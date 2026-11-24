"""
Domain resolution for symbolic getter calls (Go).

Emission lengths may still contain opaque zero-argument method calls such as
`c.out.cipher.Overhead()` or `c.out.explicitNonceLen()`. This module finds
the implementations of those methods in the analysed sources (statically
typed receiver -> exact method; interface receiver -> every implementation
with that name in the search scope, an over-approximation), summarises them
with the symbolic executor and returns the set of constant values they can
produce, each with source evidence. Delegating implementations
(`return f.aead.Overhead()`) are resolved recursively.
"""
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

import sympy as sp

from traffic.lang.go_program import GoFunc, GoPackage, GoProgram

GETTER_RE = re.compile(r"^(?P<recv>.*)\.(?P<method>[A-Za-z_][A-Za-z0-9_]*)\(\)$")


@dataclass
class DomainValue:
    value: Optional[int]
    expr: str
    evidence: List[dict] = field(default_factory=list)
    conditions: List[str] = field(default_factory=list)
    lits: list = field(default_factory=list)          # conditions as literals in the caller's namespace
    sym_expr: object = None                           # symbolic value (caller namespace) when not an integer

    def to_dict(self) -> dict:
        return {"value": self.value, "expr": self.expr, "evidence": self.evidence, "conditions": self.conditions,
                "symbolic": self.value is None and self.sym_expr is not None}


class GoDomainResolver:
    def __init__(self, program: GoProgram, executor, scope: List[GoPackage], max_depth: int = 4) -> None:
        self.program = program
        self.ex = executor
        self.scope = [p for p in scope if p is not None]
        self.max_depth = max_depth
        self.cache: Dict[str, List[DomainValue]] = {}

    def extend_scope_with_imports(self, pkg: GoPackage, depth: int = 2) -> None:
        seen = {p.import_path for p in self.scope}
        frontier = [pkg]
        for _ in range(depth):
            nxt = []
            for p in frontier:
                for ip in list(p.imports):
                    if ip in seen:
                        continue
                    seen.add(ip)
                    q = self.program.load(ip, p.origin)
                    if q is not None:
                        self.scope.append(q)
                        nxt.append(q)
            frontier = nxt

    # ------------------------------------------------------------------ rapid type analysis
    def compute_reachable_types(self, roots: List[GoPackage], depth: int = 3) -> None:
        """Collect types instantiated (composite literals / new(T)) in functions reachable from the
        root packages through package-qualified and same-package calls (bounded depth)."""
        self.instantiated: Set[tuple] = set()
        visited: Set[str] = set()
        frontier: List[GoFunc] = [fn for p in roots for fn in p.all_functions()]
        for _ in range(depth + 1):
            nxt: List[GoFunc] = []
            for fn in frontier:
                if fn.qualname in visited or fn.body is None:
                    continue
                visited.add(fn.qualname)
                stack = [fn.body]
                while stack:
                    n = stack.pop()
                    t = n.type
                    if t == "composite_literal":
                        ty = n.child_by_field_name("type")
                        if ty is not None:
                            key = self.ex.type_key(fn.file.text(ty), (fn.package, fn.file))
                            if key:
                                self.instantiated.add(key)
                    elif t == "call_expression":
                        f = n.child_by_field_name("function")
                        if f is not None and f.type == "identifier":
                            name = fn.file.text(f)
                            if name == "new":
                                args = n.child_by_field_name("arguments")
                                named = [c for c in args.children if c.is_named] if args is not None else []
                                if named:
                                    key = self.ex.type_key(fn.file.text(named[0]), (fn.package, fn.file))
                                    if key:
                                        self.instantiated.add(key)
                            elif name in fn.package.funcs:
                                nxt.append(fn.package.funcs[name])
                        elif f is not None and f.type == "selector_expression":
                            op = f.child_by_field_name("operand")
                            fld = fn.file.text(f.child_by_field_name("field"))
                            if op is not None and op.type == "identifier" and fn.file.text(op) in fn.file.imports:
                                other = self.program.load(fn.file.imports[fn.file.text(op)], fn.package.origin)
                                if other is not None and fld in other.funcs:
                                    nxt.append(other.funcs[fld])
                            else:
                                for m in fn.package.methods_by_name.get(fld, []):
                                    nxt.append(m)
                    stack.extend(n.children)
            frontier = nxt
        self.rta_functions = len(visited)

    def interface_method_set(self, typ: str, tctx, depth: int = 0) -> Optional[Set[str]]:
        if tctx is None or depth > 5:
            return None
        gt = self.program.lookup_type(tctx[0], tctx[1], typ)
        if gt is None or gt.kind != "interface":
            return None
        names = set(gt.methods)
        for emb in gt.embedded:
            sub = self.interface_method_set(emb, (gt.package, gt.file), depth + 1)
            if sub:
                names |= sub
        return names

    def type_method_names(self, pkg: GoPackage, type_name: str, depth: int = 0) -> Set[str]:
        names = {m for (t, m) in pkg.methods if t == type_name}
        gt = pkg.types.get(type_name)
        if gt is not None and gt.kind == "struct" and depth < 3:
            for emb in gt.embedded:
                sub = self.program.lookup_type(gt.package, gt.file, emb)
                if sub is not None:
                    if sub.kind == "interface":
                        names |= self.interface_method_set(emb, (gt.package, gt.file)) or set()
                    else:
                        names |= self.type_method_names(sub.package, sub.name, depth + 1)
        return names

    def rename_lit(self, lit, recv_canon: str):
        from traffic.analysis.symbolic import Atom, Lit, substitute_atom
        renamer = lambda t: t.replace("$recv", recv_canon)
        a = lit.atom
        if a.kind == "rel" and a.rel is not None:
            rm = self.ex.reg.rename_map(a.rel.free_symbols, renamer)
            rel = a.rel.xreplace(rm) if rm else a.rel
            return Lit(Atom("rel", str(rel), a.text, a.loc, rel, renamer(a.subject), a.type_text, a.type_ctx,
                            a.const_name), lit.positive)
        return Lit(substitute_atom(a, {}, renamer), lit.positive)

    def consistent(self, lits_a, lits_b) -> bool:
        return self.ex.consistent(lits_a, lits_b)

    def implementations(self, sym_name: str) -> List[GoFunc]:
        cands = self.ex.getters.get(sym_name)
        if cands and isinstance(cands[0], GoFunc):
            return list(cands)
        required: Optional[Set[str]] = None
        if cands and isinstance(cands[0], tuple):
            rtyp, rctx, _ = cands[0]
            required = self.interface_method_set(rtyp, rctx)
        m = GETTER_RE.match(sym_name)
        if not m:
            return []
        method = m.group("method")
        impls = []
        inst = getattr(self, "instantiated", None)
        for p in self.scope:
            for fn in p.methods_by_name.get(method, []):
                if not fn.params and fn.results and len(fn.results) == 1:
                    if inst is not None and (p.import_path, fn.recv_type) not in inst:
                        continue
                    if required and not required <= self.type_method_names(p, fn.recv_type):
                        continue
                    impls.append(fn)
        return impls

    def domain(self, sym_name: str, depth: int = 0, seen: Optional[Set[str]] = None) -> List[DomainValue]:
        if sym_name in self.cache:
            return self.cache[sym_name]
        seen = set(seen or ())
        if sym_name in seen or depth > self.max_depth:
            return [DomainValue(None, sym_name, [], ["recursion/depth limit"])]
        seen.add(sym_name)
        out: List[DomainValue] = []
        m = GETTER_RE.match(sym_name)
        recv_canon = m.group("recv") if m else ""
        for impl in self.implementations(sym_name):
            summ = self.ex.summarize(impl)
            ev = {"function": impl.qualname, "file": str(impl.file.path), "line": impl.start_line,
                  "provenance": impl.package.provenance()}
            for path in summ.paths:
                if path.status not in ("return", "fallthrough") or not path.returns:
                    continue
                v = path.returns[0]
                if getattr(v, "num", None) is not None:
                    expr = v.num
                elif getattr(v, "canon", "") and GETTER_RE.match(v.canon) and v.length is None and v.items is None:
                    expr = self.ex.num(v)           # delegation to another getter
                else:
                    expr = None
                conds = [l.render(lambda s: s.replace("$recv", recv_canon or "recv")) for l in path.conds]
                lits = [self.rename_lit(l, recv_canon) for l in path.conds] if recv_canon else []
                if expr is None:
                    out.append(DomainValue(None, getattr(v, "canon", "?"), [ev], conds, lits))
                    continue
                expr = sp.sympify(expr)
                if recv_canon:
                    rm = self.ex.reg.rename_map(expr.free_symbols, lambda n: n.replace("$recv", recv_canon))
                    expr = expr.xreplace(rm) if rm else expr
                if expr.is_Integer:
                    out.append(DomainValue(int(expr), str(expr), [ev], conds, lits))
                    continue
                # resolve nested getter symbols (delegation, e.g. f.aead.Overhead())
                nested = [s for s in expr.free_symbols if GETTER_RE.match(s.name)]
                if not nested or len(nested) > 2:
                    out.append(DomainValue(None, str(expr), [ev], conds, lits, sym_expr=expr))
                    continue
                combos = [({}, [], [], [])]
                for ns in nested:
                    sub_dom = self.domain(ns.name, depth + 1, seen)
                    new_combos = []
                    for binding, evs, cs, ls in combos:
                        for dv in sub_dom:
                            if dv.value is None:
                                continue
                            b = dict(binding)
                            b[ns] = sp.Integer(dv.value)
                            new_combos.append((b, evs + dv.evidence, cs + dv.conditions, ls + dv.lits))
                    combos = new_combos
                if not combos:
                    out.append(DomainValue(None, str(expr), [ev], conds, lits, sym_expr=expr))
                for binding, evs, cs, ls in combos:
                    val = expr.xreplace(binding)
                    if val.is_Integer:
                        out.append(DomainValue(int(val), str(expr), [ev] + evs, conds + cs, lits + ls))
                    else:
                        out.append(DomainValue(None, str(val), [ev] + evs, conds + cs, lits + ls, sym_expr=val))
        if not out:
            out.append(DomainValue(None, sym_name, [], ["no implementation found in analysed sources"]))
        # dedupe by (value, function)
        uniq = {}
        for dv in out:
            key = (dv.value, dv.evidence[0]["function"] if dv.evidence else dv.expr, tuple(dv.conditions))
            uniq.setdefault(key, dv)
        self.cache[sym_name] = list(uniq.values())
        return self.cache[sym_name]
