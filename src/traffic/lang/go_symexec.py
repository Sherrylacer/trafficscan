"""
Symbolic length executor for Go functions.

Executes a function body over tree-sitter ASTs, tracking:

  * integer values and slice lengths as sympy expressions,
  * path conditions (with feasibility pruning: contradictory literals, nil vs
    dynamic-type tests, type-switch compatibility through interface embedding,
    and linking of fields compared against constants of one enumeration),
  * emissions: bytes handed to a network/stream sink (net.Conn.Write ...)
    or appended to a buffer, with the path conditions in force,
  * effects on receiver fields (counters such as `c.packetsSent++`).

Calls with data parameters are inlined through cached function summaries;
the callee's `$recv` / `$pN` placeholders are renamed to the caller's
canonical expressions so that identical quantities share one symbol.
Zero-argument getters (e.g. `cipher.Overhead()`) stay symbolic; their
possible values are resolved separately (see domains.py).
"""
import re
from typing import Dict, List, Optional, Tuple

import sympy as sp

from traffic.analysis.symbolic import (
    merge_paths, Atom, BitAnd, BitOr, BitXor, Emission, Lit, PathResult, Shl, Shr, Summary, SymbolRegistry,
    TDiv, TMod, TraceStep, rename_text, substitute_atom,
)
from traffic.lang import go_knowledge as K
from traffic.lang.go_program import GoFile, GoFunc, GoPackage, GoProgram, _strip_type


# --------------------------------------------------------------------------- values
class Val:
    __slots__ = ("canon", "num", "length", "typ", "tctx", "items", "boolean", "is_nil", "const_name",
                 "const_family")

    def __init__(self, canon: str = "", num=None, length=None, typ: str = "", tctx=None, items=None,
                 boolean: Optional[Lit] = None, is_nil: bool = False, const_name: str = "",
                 const_family: str = "") -> None:
        self.canon = canon
        self.num = num
        self.length = length
        self.typ = typ
        self.tctx = tctx
        self.items = items
        self.boolean = boolean
        self.is_nil = is_nil
        self.const_name = const_name
        self.const_family = const_family

    def copy(self, **kw) -> "Val":
        v = Val(self.canon, self.num, self.length, self.typ, self.tctx, self.items, self.boolean, self.is_nil,
                self.const_name, self.const_family)
        for k, x in kw.items():
            setattr(v, k, x)
        return v


def _sym_kind(canon: str) -> str:
    if "@L" in canon:
        return "loop"
    if canon.startswith("$recv"):
        return "state"
    if canon.startswith("$p"):
        return "param"
    if canon.endswith(")"):
        return "call"
    return "opaque"


# --------------------------------------------------------------------------- state
class State:
    __slots__ = ("env", "conds", "emissions", "effects", "sets", "trace", "assumptions", "status",
                 "returns", "loops", "known", "aliases")

    def __init__(self) -> None:
        self.env: Dict[str, Val] = {}
        self.conds: List[Lit] = []
        self.emissions: List[Emission] = []
        self.effects: Dict[str, sp.Expr] = {}
        self.sets: Dict[str, Val] = {}
        self.trace: List[TraceStep] = []
        self.assumptions: List[str] = []
        self.status = "running"
        self.returns: List[Val] = []
        self.loops: List[Tuple[str, int]] = []
        self.known: Dict[sp.Symbol, sp.Expr] = {}
        self.aliases: Dict[sp.Symbol, sp.Symbol] = {}

    def fork(self) -> "State":
        s = State()
        s.env = dict(self.env)
        s.conds = list(self.conds)
        s.emissions = list(self.emissions)
        s.effects = dict(self.effects)
        s.sets = dict(self.sets)
        s.trace = list(self.trace)
        s.assumptions = list(self.assumptions)
        s.status = self.status
        s.returns = list(self.returns)
        s.loops = list(self.loops)
        s.known = dict(self.known)
        s.aliases = dict(self.aliases)
        return s


# --------------------------------------------------------------------------- executor
class GoSymExec:
    def __init__(self, program: GoProgram, registry: Optional[SymbolRegistry] = None,
                 max_paths: int = 600, max_depth: int = 7, prune_error_paths: bool = True,
                 link_enum_constants: bool = True) -> None:
        self.program = program
        self.reg = registry or SymbolRegistry()
        self.max_paths = max_paths
        self.max_depth = max_depth
        self.prune_error_paths = prune_error_paths
        self.link_enum_constants = link_enum_constants
        self.cache: Dict[str, Summary] = {}
        self.stack: List[str] = []
        self.getters: Dict[str, List[GoFunc]] = {}       # symbol name -> candidate implementations
        self.opaque_calls: Dict[str, Tuple[str, int]] = {}
        self.emitting: set = set()                       # qualnames of functions known to emit
        self.notes: List[str] = []
        self._type_class_cache: Dict[Tuple[str, str], Optional[str]] = {}
        self._fn = None
        self._pkg: Optional[GoPackage] = None
        self._file: Optional[GoFile] = None

    # ------------------------------------------------------------------ state merging
    merge_threshold = 12
    callee_path_budget = 64

    @staticmethod
    def _vkey(v):
        if v is None:
            return None
        items = tuple(GoSymExec._vkey(x) for x in v.items) if v.items is not None else None
        b = (v.boolean.atom.key, v.boolean.positive) if v.boolean is not None else None
        if v.num is None and v.length is None and items is None and b is None:
            return ("obj", v.canon, v.is_nil)
        return (v.num, v.length, items, b, v.is_nil)

    @staticmethod
    def _state_sig(st: State):
        vk = GoSymExec._vkey
        env = tuple((k, vk(v)) for k, v in sorted(st.env.items()))
        ems = tuple((e.kind, e.sink, e.length, tuple(e.loops), e.loc) for e in st.emissions)
        eff = tuple(sorted(st.effects.items()))
        sets = tuple((k, vk(v)) for k, v in sorted(st.sets.items()))
        rets = tuple(vk(v) for v in st.returns)
        return (st.status, env, ems, eff, sets, rets, tuple(st.loops))

    def merge_states(self, states: List[State]) -> List[State]:
        """Merge in-flight states whose values, emissions and effects are identical; the conditions
        that distinguish them cannot influence any length (same rule as summary-level merging)."""
        from traffic.analysis.symbolic import lit_key
        groups: Dict[object, List[State]] = {}
        order = []
        for st in states:
            sig = self._state_sig(st)
            if sig not in groups:
                groups[sig] = []
                order.append(sig)
            groups[sig].append(st)
        out = []
        for sig in order:
            g = groups[sig]
            if len(g) == 1:
                out.append(g[0])
                continue
            base = g[0].fork()
            keys = set(lit_key(l) for l in g[0].conds)
            for o in g[1:]:
                keys &= set(lit_key(l) for l in o.conds)
            base.conds = [l for l in g[0].conds if lit_key(l) in keys]
            base.known = {k: v for k, v in g[0].known.items() if all(o.known.get(k) == v for o in g[1:])}
            base.aliases = {k: v for k, v in g[0].aliases.items() if all(o.aliases.get(k) == v for o in g[1:])}
            for i, e in enumerate(base.emissions):
                ek = set(lit_key(l) for l in e.conds)
                for o in g[1:]:
                    ek &= set(lit_key(l) for l in o.emissions[i].conds)
                e_conds = [l for l in e.conds if lit_key(l) in ek]
                base.emissions[i] = Emission(e.kind, e.sink, e.sink_type, e.sink_class, e.length, e_conds, e.loc,
                                             e.chain, e.loops, e.assumptions, e.trace, e.effects)
            for o in g[1:]:
                for a_ in o.assumptions:
                    if a_ not in base.assumptions:
                        base.assumptions.append(a_)
            out.append(base)
        return out

    # ------------------------------------------------------------------ helpers
    def byte_counter_fields(self) -> set:
        """Receiver fields incremented by a data-dependent amount (cumulative byte counters)."""
        out = set()
        for summ in self.cache.values():
            for p in summ.paths:
                for k_, v_ in p.effects.items():
                    v_ = sp.sympify(v_)
                    if v_.free_symbols and any(s.name.startswith("len(") or "Write.n" in s.name
                                               for s in v_.free_symbols):
                        out.add(k_)
        return out

    def text(self, node) -> str:
        return self._file.text(node)

    def loc(self, node) -> Tuple[str, int]:
        return (str(self._file.path), node.start_point[0] + 1)

    def num(self, v: Val) -> sp.Expr:
        if v.num is not None:
            return v.num
        if v.is_nil:
            return sp.Integer(0)
        return self.reg.sym(v.canon or "?", _sym_kind(v.canon))

    def length(self, v: Val) -> sp.Expr:
        if v.length is not None:
            return v.length
        canon = v.canon or "?"
        kind = "input_len" if canon.startswith("$p") else ("loop" if "@L" in canon else "len")
        return self.reg.sym(f"len({canon})", kind, nonneg=True)

    # ------------------------------------------------------------------ types
    def type_key(self, typ: str, tctx) -> Optional[Tuple[str, str]]:
        if not typ or tctx is None:
            return None
        base, _ = _strip_type(typ)
        pkg, f = tctx
        if "." in base:
            alias, name = base.split(".", 1)
            ipath = f.imports.get(alias) if f is not None else None
            return (ipath, name) if ipath else None
        return (pkg.import_path, base)

    def type_class(self, typ: str, tctx, depth: int = 0) -> Optional[str]:
        """net | stream | buffer | None for a type expression."""
        key = self.type_key(typ, tctx)
        if key is None:
            return None
        if key in self._type_class_cache:
            return self._type_class_cache[key]
        self._type_class_cache[key] = None
        res = None
        if key in K.NET_CONN_TYPES:
            res = "net"
        elif key in K.STREAM_WRITER_TYPES:
            res = "stream"
        elif key in K.BUFFER_TYPES:
            res = "buffer"
        elif depth < 5:
            pkg, f = tctx
            gt = self.program.lookup_type(pkg, f, typ)
            if gt is not None and gt.kind == "interface":
                for emb in gt.embedded:
                    c = self.type_class(emb, (gt.package, gt.file), depth + 1)
                    if c == "net":
                        res = "net"
                        break
                    if c == "stream" and not gt.methods:
                        res = "stream"
        self._type_class_cache[key] = res
        return res

    def implements_any(self, typ: str, tctx, keys, depth: int = 0) -> bool:
        k = self.type_key(typ, tctx)
        if k is None:
            return False
        if k in keys:
            return True
        if depth > 4:
            return False
        gt = self.program.lookup_type(tctx[0], tctx[1], typ)
        if gt is None or gt.kind != "interface":
            return False
        return any(self.implements_any(e, (gt.package, gt.file), keys, depth + 1) for e in gt.embedded)

    def consistent(self, lits_a, lits_b) -> bool:
        """True if the two literal sets can hold together (same pruning rules as path exploration)."""
        st = State()
        for l in list(lits_a) + list(lits_b):
            if not self.add_lit(st, l):
                return False
        return True

    def field_type(self, v: Val, fname: str) -> Tuple[str, object]:
        if not v.typ or v.tctx is None:
            return "", None
        pkg, f = v.tctx
        gt = self.program.lookup_type(pkg, f, v.typ)
        depth = 0
        while gt is not None and depth < 4:
            if gt.kind == "struct":
                if fname in gt.fields:
                    return gt.fields[fname], (gt.package, gt.file)
                # promoted fields through embedded structs
                for emb in gt.embedded:
                    sub = self.program.lookup_type(gt.package, gt.file, emb)
                    if sub is not None and sub.kind == "struct" and fname in sub.fields:
                        return sub.fields[fname], (sub.package, sub.file)
                return "", None
            if gt.kind == "other" and gt.underlying:
                gt = self.program.lookup_type(gt.package, gt.file, gt.underlying)
                depth += 1
                continue
            return "", None
        return "", None

    def resolve_method(self, recv: Val, name: str) -> Optional[GoFunc]:
        if not recv.typ or recv.tctx is None:
            return None
        pkg, f = recv.tctx
        gt = self.program.lookup_type(pkg, f, recv.typ)
        seen = 0
        while gt is not None and seen < 4:
            seen += 1
            if gt.kind == "interface":
                return None
            m = gt.package.methods.get((gt.name, name))
            if m is not None:
                return m
            for emb in gt.embedded:
                sub = self.program.lookup_type(gt.package, gt.file, emb)
                if sub is not None and sub.kind != "interface":
                    m = sub.package.methods.get((sub.name, name))
                    if m is not None:
                        return m
            return None
        return None

    def is_interface(self, typ: str, tctx) -> bool:
        if not typ or tctx is None:
            return False
        if typ.strip() in ("any", "interface{}"):
            return True
        gt = self.program.lookup_type(tctx[0], tctx[1], typ)
        return gt is not None and gt.kind == "interface"

    # ------------------------------------------------------------------ conditions
    @staticmethod
    def refine(st: State, expr):
        if expr is None:
            return expr
        if st.aliases:
            expr = expr.xreplace(st.aliases)
        if st.known:
            expr = expr.xreplace(st.known)
        return sp.expand(expr)

    def add_lit(self, st: State, lit: Lit) -> bool:
        a = lit.atom
        if a.kind == "nil" and a.subject == "nil":
            return lit.positive
        if a.kind == "rel":
            rel = a.rel
            if st.aliases:
                rel = rel.xreplace(st.aliases)
            if st.known:
                rel = rel.xreplace(st.known)
            if rel is sp.true or rel is sp.false:
                ok = (rel is sp.true) == lit.positive
                return ok
            if rel is not a.rel:
                a = Atom("rel", str(rel), a.text, a.loc, rel, a.subject, a.type_text, a.type_ctx, a.const_name)
                lit = Lit(a, lit.positive)
            # link fields compared against constants of the same enumeration
            if self.link_enum_constants and a.const_name and isinstance(rel, sp.Eq):
                subj = [s for s in rel.free_symbols]
                if len(subj) == 1:
                    s_new = subj[0]
                    for ex in st.conds:
                        ea = ex.atom
                        if ea.kind == "rel" and ea.const_name and ea.type_text == a.type_text and \
                                isinstance(ea.rel, sp.Eq) and len(ea.rel.free_symbols) == 1:
                            s_old = next(iter(ea.rel.free_symbols))
                            if s_old != s_new:
                                st.aliases[s_new] = s_old
                                st.assumptions.append(
                                    f"linked `{s_new.name}` with `{s_old.name}`: both are compared against "
                                    f"constants of the same enumeration ({ea.const_name}, {a.const_name})")
                                return self.add_lit(st, Lit(Atom("rel", str(rel.xreplace({s_new: s_old})), a.text,
                                                                 a.loc, rel.xreplace({s_new: s_old}), a.subject,
                                                                 a.type_text, a.type_ctx, a.const_name),
                                                            lit.positive))
        for ex in st.conds:
            ea = ex.atom
            if ea.key == a.key and ea.kind == a.kind:
                return ex.positive == lit.positive
            if a.subject and ea.subject == a.subject:
                if {a.kind, ea.kind} == {"nil", "typeis"}:
                    nil_lit = lit if a.kind == "nil" else ex
                    ty_lit = ex if a.kind == "nil" else lit
                    if nil_lit.positive and ty_lit.positive:
                        return False
                if a.kind == "typeis" and ea.kind == "typeis":
                    if not self._typeis_compatible(lit, ex):
                        return False
        st.conds.append(lit)
        if a.kind == "rel" and not lit.positive and isinstance(a.rel, sp.StrictLessThan):
            lhs, rhs = a.rel.lhs, a.rel.rhs
            # not (0 < x) with x a non-negative quantity  =>  x == 0
            if lhs == 0 and isinstance(rhs, sp.Symbol) and rhs.is_nonnegative:
                st.known[rhs] = sp.Integer(0)
        if a.kind == "rel" and lit.positive and isinstance(a.rel, sp.Eq):
            lhs, rhs = a.rel.lhs, a.rel.rhs
            if isinstance(lhs, sp.Symbol) and rhs.is_number:
                st.known[lhs] = rhs
            elif isinstance(rhs, sp.Symbol) and lhs.is_number:
                st.known[rhs] = lhs
        return True

    def _embeds(self, atom_a: Atom, atom_b: Atom) -> bool:
        """True if type of atom_a implies type of atom_b (same, or interface embedding)."""
        if atom_a.type_text == atom_b.type_text and atom_a.type_ctx == atom_b.type_ctx:
            return True
        ka = self.type_key(atom_a.type_text, atom_a.type_ctx)
        kb = self.type_key(atom_b.type_text, atom_b.type_ctx)
        if ka is not None and ka == kb:
            return True
        if atom_a.type_ctx is None:
            return False
        pkg, f = atom_a.type_ctx
        gt = self.program.lookup_type(pkg, f, atom_a.type_text)
        if gt is None or gt.kind != "interface":
            return False
        for emb in gt.embedded:
            sub = Atom("typeis", "", "", type_text=emb, type_ctx=(gt.package, gt.file))
            if self._embeds(sub, atom_b):
                return True
        return False

    def _typeis_compatible(self, l1: Lit, l2: Lit) -> bool:
        a, b = l1.atom, l2.atom
        if l1.positive and l2.positive:
            return self._embeds(a, b) or self._embeds(b, a)
        if l1.positive and not l2.positive:
            return not self._embeds(a, b)
        if l2.positive and not l1.positive:
            return not self._embeds(b, a)
        return True

    # ------------------------------------------------------------------ summaries
    def summarize(self, fn: GoFunc) -> Summary:
        q = fn.qualname
        if q in self.cache:
            return self.cache[q]
        saved = (self._fn, self._pkg, self._file)
        self._fn, self._pkg, self._file = fn, fn.package, fn.file
        self.stack.append(q)
        try:
            st = State()
            ctx = (fn.package, fn.file)
            if fn.recv_name:
                rtype = ("*" if fn.recv_pointer else "") + fn.recv_type
                st.env[fn.recv_name] = Val("$recv", typ=rtype, tctx=ctx)
            for i, p in enumerate(fn.params):
                if p.name and p.name != "_":
                    st.env[p.name] = Val(f"$p{i}", typ=p.type_text, tctx=ctx)
            for r in fn.results:
                if r.name and r.name != "_":
                    st.env[r.name] = self.zero_value(r.type_text, r.name, ctx)
            body = fn.body
            finals = self.exec_block(body, [st]) if body is not None else [st]
            paths = []
            truncated = False
            for s in finals:
                if s.status in ("running", "break", "continue"):
                    s.status = "fallthrough"
                    s.returns = [s.env[r.name] for r in fn.results if r.name and r.name in s.env]
                paths.append(PathResult(s.status, s.conds, s.returns, s.emissions, s.effects, s.sets,
                                        s.trace, s.assumptions))
            if len(paths) >= self.max_paths:
                truncated = True
            paths = merge_paths(paths)
            summ = Summary(q, paths, truncated)
        finally:
            self.stack.pop()
            self._fn, self._pkg, self._file = saved
        self.cache[q] = summ
        return summ

    def zero_value(self, typ: str, name: str, ctx) -> Val:
        t = typ.strip()
        if t in K.INT_TYPE_NAMES:
            return Val(name, num=sp.Integer(0), typ=t, tctx=ctx)
        if t.startswith("[]") or t == "string":
            return Val(name, length=sp.Integer(0), typ=t, tctx=ctx)
        if t == "bool":
            return Val(name, typ=t, tctx=ctx, boolean=None)
        if t.startswith("*") or t in ("error", "any") or t.startswith("map[") or t.startswith("func") or \
                t.startswith("chan") or self.is_interface(t, ctx):
            return Val(name, typ=t, tctx=ctx, is_nil=True)
        return Val(name, typ=t, tctx=ctx)

    # ------------------------------------------------------------------ statements
    def exec_block(self, block, states: List[State]) -> List[State]:
        if block is None:
            return states
        stmts = [c for c in block.children if c.is_named and c.type not in ("comment",)]
        if block.type not in ("block", "statement_list") and block.type.endswith("statement"):
            stmts = [block]
        for stmt in stmts:
            nxt = []
            for st in states:
                if st.status != "running":
                    nxt.append(st)
                    continue
                nxt.extend(self.exec_stmt(stmt, st))
            states = nxt
            if len(states) > self.merge_threshold:
                states = self.merge_states(states)
            if len(states) > self.max_paths:
                self.notes.append(f"path limit reached in {self._fn.qualname if self._fn else '?'}")
                states = states[: self.max_paths]
        return states

    def exec_stmt(self, node, st: State) -> List[State]:
        t = node.type
        if t in ("block", "statement_list"):
            return self.exec_block(node, [st])
        if t == "short_var_declaration" or t == "assignment_statement":
            return self.exec_assign(node, st)
        if t in ("inc_statement", "dec_statement"):
            return self.exec_incdec(node, st, 1 if t == "inc_statement" else -1)
        if t == "var_declaration":
            return self.exec_var(node, st)
        if t == "if_statement":
            return self.exec_if(node, st)
        if t == "expression_switch_statement":
            return self.exec_switch(node, st)
        if t == "type_switch_statement":
            return self.exec_type_switch(node, st)
        if t == "for_statement":
            return self.exec_for(node, st)
        if t == "return_statement":
            return self.exec_return(node, st)
        if t == "expression_statement":
            inner = [c for c in node.children if c.is_named]
            if not inner:
                return [st]
            out = []
            for s, v in self.eval(inner[0], st):
                out.append(s)
            return out
        if t == "labeled_statement":
            inner = [c for c in node.children if c.is_named and c.type != "label_name"]
            return self.exec_block_list(inner, st)
        if t == "break_statement":
            st.status = "break"
            return [st]
        if t == "continue_statement":
            st.status = "continue"
            return [st]
        # defer, go, select, send, goto, fallthrough, empty, const/type decl: no length effect
        return [st]

    def exec_block_list(self, nodes, st: State) -> List[State]:
        states = [st]
        for n in nodes:
            nxt = []
            for s in states:
                nxt.extend(self.exec_stmt(n, s) if s.status == "running" else [s])
            states = nxt
        return states

    def _lhs_nodes(self, node):
        left = node.child_by_field_name("left")
        return [c for c in left.children if c.is_named] if left is not None else []

    def _rhs_nodes(self, node):
        right = node.child_by_field_name("right")
        return [c for c in right.children if c.is_named] if right is not None else []

    def exec_assign(self, node, st: State) -> List[State]:
        lhs = self._lhs_nodes(node)
        rhs = self._rhs_nodes(node)
        op_node = node.child_by_field_name("operator")
        op = self.text(op_node) if op_node is not None else ("=" if node.type == "assignment_statement" else ":=")
        out = []
        for s, vals in self.eval_seq(rhs, st):
            if len(vals) == 1 and len(lhs) > 1 and vals[0].items is not None:
                vals = list(vals[0].items)
            for i, ln in enumerate(lhs):
                if i >= len(vals):
                    break
                v = vals[i]
                if op not in ("=", ":="):
                    cur_list = self.eval(ln, s)
                    cur = cur_list[0][1] if cur_list else Val(self.text(ln))
                    v = self.arith(op[:-1], cur, v)
                self.store(ln, v, s, node, op)
            out.append(s)
        return out

    def store(self, ln, v: Val, s: State, stmt, op: str) -> None:
        t = ln.type
        if t == "identifier":
            name = self.text(ln)
            if name == "_":
                return
            old = s.env.get(name)
            nv = v.copy()
            if not nv.canon or nv.canon == "?":
                nv.canon = name
            if old is not None and not nv.typ:
                nv.typ, nv.tctx = old.typ, old.tctx
            s.env[name] = nv
            s.trace.append(TraceStep("assign", f"{name} {op} {self.text(stmt.child_by_field_name('right')) if stmt.child_by_field_name('right') else ''}", self.loc(stmt)))
            return
        if t == "selector_expression":
            res = self.eval(ln, s)
            target = res[0][1] if res else Val(self.text(ln))
            canon = target.canon
            if canon.startswith("$recv") or canon.startswith("$p"):
                # buffer append to a field: F = append(F, X...)
                if v.length is not None and op == "=" and self._is_append_to(stmt, ln):
                    added = sp.expand(v.length - self.length(target))
                    s.emissions.append(Emission("buffer", canon, target.typ or "[]byte", "buffer", added,
                                                list(s.conds), self.loc(stmt), [], list(s.loops), [],
                                                list(s.trace), dict(s.effects)))
                s.sets[canon] = v
                if op in ("+=", "-="):
                    inc = sp.expand(self.num(v) - self.num(target))
                    s.effects[canon] = s.effects.get(canon, sp.Integer(0)) + inc
            return
        # index expressions / derefs: no length effect

    def _is_append_to(self, stmt, ln) -> bool:
        rhs = self._rhs_nodes(stmt)
        if len(rhs) != 1 or rhs[0].type != "call_expression":
            return False
        fn = rhs[0].child_by_field_name("function")
        args = rhs[0].child_by_field_name("arguments")
        if fn is None or self.text(fn) != "append" or args is None:
            return False
        named = [c for c in args.children if c.is_named]
        return bool(named) and self.text(named[0]) == self.text(ln)

    def exec_incdec(self, node, st: State, delta: int) -> List[State]:
        target = [c for c in node.children if c.is_named][0]
        if target.type == "identifier":
            name = self.text(target)
            cur = st.env.get(name, Val(name))
            st.env[name] = cur.copy(num=sp.expand(self.num(cur) + delta), length=None, items=None)
        elif target.type == "selector_expression":
            res = self.eval(target, st)
            canon = res[0][1].canon if res else self.text(target)
            st.effects[canon] = st.effects.get(canon, sp.Integer(0)) + delta
            st.trace.append(TraceStep("assign", f"{self.text(target)}{'++' if delta > 0 else '--'}", self.loc(node)))
        return [st]

    def exec_var(self, node, st: State) -> List[State]:
        states = [st]
        for spec in node.children:
            if spec.type != "var_spec":
                continue
            names = [c for c in spec.children if c.type == "identifier"]
            tnode = spec.child_by_field_name("type")
            vnode = spec.child_by_field_name("value")
            nxt = []
            for s in states:
                if vnode is not None:
                    vals_nodes = [c for c in vnode.children if c.is_named]
                    for s2, vals in self.eval_seq(vals_nodes, s):
                        if len(vals) == 1 and len(names) > 1 and vals[0].items is not None:
                            vals = list(vals[0].items)
                        for i, n in enumerate(names):
                            if i < len(vals):
                                v = vals[i].copy()
                                if tnode is not None and not v.typ:
                                    v.typ, v.tctx = self.text(tnode), (self._pkg, self._file)
                                s2.env[self.text(n)] = v
                        nxt.append(s2)
                else:
                    ttext = self.text(tnode) if tnode is not None else ""
                    for n in names:
                        s.env[self.text(n)] = self.zero_value(ttext, self.text(n), (self._pkg, self._file))
                    nxt.append(s)
            states = nxt
        return states

    def _is_error_check(self, cond) -> bool:
        if cond is None or cond.type != "binary_expression":
            return False
        op = self.text(cond.child_by_field_name("operator"))
        left = cond.child_by_field_name("left")
        right = cond.child_by_field_name("right")
        if op != "!=" or right is None or self.text(right) != "nil" or left is None:
            return False
        return bool(re.match(K.ERROR_NAME_PATTERN, self.text(left).split(".")[-1]))

    def exec_if(self, node, st: State) -> List[State]:
        init = node.child_by_field_name("initializer")
        cond = node.child_by_field_name("condition")
        cons = node.child_by_field_name("consequence")
        alt = node.child_by_field_name("alternative")
        states = self.exec_stmt(init, st) if init is not None else [st]
        out = []
        for s in states:
            if s.status != "running":
                out.append(s)
                continue
            if self.prune_error_paths and self._is_error_check(cond):
                # error path: assume success (record the assumption once per path)
                if alt is not None:
                    out.extend(self.exec_stmt(alt, s))
                else:
                    out.append(s)
                continue
            t_states, f_states = self.branch(cond, s)
            for ts in t_states:
                ts.trace.append(TraceStep("branch", f"if {self.text(cond)} (taken)", self.loc(node)))
            for fs in f_states:
                fs.trace.append(TraceStep("branch", f"if {self.text(cond)} (not taken)", self.loc(node)))
            for ts in t_states:
                out.extend(self.exec_block(cons, [ts]))
            for fs in f_states:
                if alt is not None:
                    out.extend(self.exec_stmt(alt, fs))
                else:
                    out.append(fs)
        return out

    def exec_switch(self, node, st: State) -> List[State]:
        init = node.child_by_field_name("initializer")
        value = node.child_by_field_name("value")
        states = self.exec_stmt(init, st) if init is not None else [st]
        out = []
        cases = [c for c in node.children if c.type in ("expression_case", "default_case")]
        for s in states:
            if s.status != "running":
                out.append(s)
                continue
            remaining = [s]
            default = None
            for case in cases:
                if case.type == "default_case":
                    default = case
                    continue
                vals_node = case.child_by_field_name("value")
                vnodes = [c for c in vals_node.children if c.is_named] if vals_node is not None else []
                body = [c for c in case.children if c.is_named and c != vals_node]
                taken_all, next_remaining = [], []
                for r in remaining:
                    pending = [r]
                    for vn in vnodes:
                        new_pending = []
                        for p in pending:
                            tr, fa = self.branch_eq(value, vn, p) if value is not None else self.branch(vn, p)
                            taken_all.extend(tr)
                            new_pending.extend(fa)
                        pending = new_pending
                    next_remaining.extend(pending)
                for ts in taken_all:
                    ts.trace.append(TraceStep("branch", f"case {self.text(vals_node) if vals_node else ''}", self.loc(case)))
                    out.extend(self._exec_case_body(body, ts))
                remaining = next_remaining
            for r in remaining:
                if default is not None:
                    body = [c for c in default.children if c.is_named]
                    out.extend(self._exec_case_body(body, r))
                else:
                    out.append(r)
        return out

    def _exec_case_body(self, body, st: State) -> List[State]:
        res = self.exec_block_list(body, st)
        for r in res:
            if r.status == "break":
                r.status = "running"
        return res

    def exec_type_switch(self, node, st: State) -> List[State]:
        init = node.child_by_field_name("initializer")
        alias_node = node.child_by_field_name("alias")
        value = node.child_by_field_name("value")
        alias = None
        if alias_node is not None:
            names = [c for c in alias_node.children if c.type == "identifier"]
            alias = self.text(names[0]) if names else None
        states = self.exec_stmt(init, st) if init is not None else [st]
        out = []
        cases = [c for c in node.children if c.type in ("type_case", "default_case")]
        for s in states:
            if s.status != "running":
                out.append(s)
                continue
            subj_list = self.eval(value, s)
            for s0, subj in subj_list:
                remaining = [s0]
                listed: List[Atom] = []
                default = None
                for case in cases:
                    if case.type == "default_case":
                        default = case
                        continue
                    tnodes = case.children_by_field_name("type")
                    tnodes = [t for t in tnodes if t.is_named]
                    body = [c for c in case.children if c.is_named and c not in tnodes]
                    for tn in tnodes:
                        ttext = self.text(tn)
                        if ttext == "nil":
                            atom = Atom("nil", f"nil:{subj.canon}:", f"{subj.canon} == nil", self.loc(case),
                                        subject=subj.canon)
                        else:
                            atom = Atom("typeis", f"typeis:{subj.canon}:{ttext}", f"{subj.canon}.(type) == {ttext}",
                                        self.loc(case), subject=subj.canon, type_text=ttext,
                                        type_ctx=(self._pkg, self._file))
                        listed.append(atom)
                        for r in remaining:
                            ts = r.fork()
                            if self.add_lit(ts, Lit(atom, True)):
                                if alias:
                                    ts.env[alias] = subj.copy(typ=ttext if ttext != "nil" else subj.typ,
                                                              tctx=(self._pkg, self._file))
                                ts.trace.append(TraceStep("branch", f"type case {ttext}", self.loc(case)))
                                out.extend(self._exec_case_body(body, ts))
                    new_rem = []
                    for r in remaining:
                        ok = True
                        for atom in listed[-len(tnodes):] if tnodes else []:
                            if not self.add_lit(r, Lit(atom, False)):
                                ok = False
                                break
                        if ok:
                            new_rem.append(r)
                    remaining = new_rem
                for r in remaining:
                    if default is not None:
                        if alias:
                            r.env[alias] = subj.copy()
                        body = [c for c in default.children if c.is_named]
                        out.extend(self._exec_case_body(body, r))
                    else:
                        out.append(r)
        return out

    def _assigned_names(self, node, acc: set) -> None:
        t = node.type
        if t in ("assignment_statement",):
            for ln in self._lhs_nodes(node):
                if ln.type == "identifier":
                    acc.add(self.text(ln))
        elif t in ("inc_statement", "dec_statement"):
            tgt = [c for c in node.children if c.is_named]
            if tgt and tgt[0].type == "identifier":
                acc.add(self.text(tgt[0]))
        elif t == "func_literal":
            return
        for c in node.children:
            self._assigned_names(c, acc)

    def exec_for(self, node, st: State) -> List[State]:
        body = node.child_by_field_name("body")
        clause = None
        cond_expr = None
        for c in node.children:
            if c.type in ("for_clause", "range_clause"):
                clause = c
            elif c.is_named and c != body and c.type not in ("comment",):
                cond_expr = c
        line = node.start_point[0] + 1
        loop_id = (str(self._file.path), line)
        states = [st]
        if clause is not None and clause.type == "for_clause":
            init = clause.child_by_field_name("initializer")
            if init is not None:
                states = [x for s in states for x in self.exec_stmt(init, s)]
            cond_expr = clause.child_by_field_name("condition")
        assigned: set = set()
        self._assigned_names(body, assigned)
        if clause is not None and clause.type == "for_clause":
            upd = clause.child_by_field_name("update")
            if upd is not None:
                self._assigned_names(upd, assigned)
        out = []
        for s in states:
            if s.status != "running":
                out.append(s)
                continue
            pre = s.fork()
            # havoc loop-carried variables
            for name in assigned:
                if name in s.env:
                    old = s.env[name]
                    s.env[name] = Val(f"{name}@L{line}", typ=old.typ, tctx=old.tctx)
            if clause is not None and clause.type == "range_clause":
                left = clause.child_by_field_name("left")
                right = clause.child_by_field_name("right")
                rng = self.eval(right, s)[0][1] if right is not None else Val("?")
                if left is not None:
                    for i, ln in enumerate(c for c in left.children if c.is_named):
                        nm = self.text(ln)
                        if i == 0:
                            idx = self.reg.sym(f"{nm}@L{line}", "loop", nonneg=True)
                            s.env[nm] = Val(f"{nm}@L{line}", num=idx)
                        else:
                            s.env[nm] = Val(f"{nm}@L{line}", typ="")
                body_states = [s]
                s.trace.append(TraceStep("loop", f"range over {rng.canon}", self.loc(node)))
            elif cond_expr is not None:
                body_states, _ = self.branch(cond_expr, s)
                for b in body_states:
                    b.trace.append(TraceStep("loop", f"for {self.text(cond_expr)}", self.loc(node)))
            else:
                body_states = [s]
                s.trace.append(TraceStep("loop", "for { ... }", self.loc(node)))
            for b in body_states:
                b.loops = b.loops + [loop_id]
            finished = self.exec_block(body, body_states)
            # Collect emissions/effects from body paths into one post-loop state.
            post = pre
            for name in assigned:
                if name in post.env:
                    old = post.env[name]
                    post.env[name] = Val(f"{name}@L{line}.exit", typ=old.typ, tctx=old.tctx)
            seen_em = set(id(e) for e in pre.emissions)
            for f in finished:
                if f.status in ("return",):
                    f.loops = f.loops[:-1] if f.loops and f.loops[-1] == loop_id else f.loops
                    out.append(f)
                    continue
                if f.status in ("panic", "error"):
                    continue
                for e in f.emissions:
                    if id(e) not in seen_em:
                        post.emissions.append(e)
                        seen_em.add(id(e))
                for k_, v_ in f.effects.items():
                    if k_ not in post.effects:
                        post.effects[k_] = sp.Symbol(f"{k_}#loop", integer=True)
                for a_ in f.assumptions:
                    if a_ not in post.assumptions:
                        post.assumptions.append(a_)
            post.trace.append(TraceStep("loop", f"after loop at line {line}", self.loc(node)))
            post.status = "running"
            out.append(post)
        return out

    def exec_return(self, node, st: State) -> List[State]:
        exprs = [c for c in node.children if c.is_named]
        if exprs and exprs[0].type == "expression_list":
            exprs = [c for c in exprs[0].children if c.is_named]
        if not exprs:
            st.returns = [st.env[r.name] for r in self._fn.results if r.name and r.name in st.env]
            st.status = "return"
            st.trace.append(TraceStep("note", "return", self.loc(node)))
            return [st]
        out = []
        for s, vals in self.eval_seq(exprs, st):
            if len(vals) == 1 and vals[0].items is not None and len(self._fn.results) > 1:
                vals = list(vals[0].items)
            s.returns = vals
            s.status = "return"
            s.trace.append(TraceStep("note", f"return {self.text(node)[6:].strip()}", self.loc(node)))
            out.append(s)
        return out

    # ------------------------------------------------------------------ branching
    def branch(self, node, st: State) -> Tuple[List[State], List[State]]:
        t = node.type
        if t == "parenthesized_expression":
            inner = [c for c in node.children if c.is_named]
            return self.branch(inner[0], st)
        if t == "unary_expression" and self.text(node.child_by_field_name("operator")) == "!":
            tr, fa = self.branch(node.child_by_field_name("operand"), st)
            return fa, tr
        if t == "binary_expression":
            op = self.text(node.child_by_field_name("operator"))
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if op == "&&":
                lt, lf = self.branch(left, st)
                T, F = [], list(lf)
                for s in lt:
                    rt, rf = self.branch(right, s)
                    T += rt
                    F += rf
                return T, F
            if op == "||":
                lt, lf = self.branch(left, st)
                T, F = list(lt), []
                for s in lf:
                    rt, rf = self.branch(right, s)
                    T += rt
                    F += rf
                return T, F
            if op in ("==", "!=", "<", "<=", ">", ">="):
                return self.branch_cmp(left, op, right, st, node)
        if t == "true":
            return [st], []
        if t == "false":
            return [], [st]
        T, F = [], []
        for s, v in self.eval(node, st):
            if v.boolean is not None:
                lit = v.boolean
            else:
                canon = v.canon or self.text(node)
                lit = Lit(Atom("bool", f"bool:{canon}", canon, self.loc(node), subject=canon), True)
            s1, s2 = s.fork(), s
            if self.add_lit(s1, lit):
                T.append(s1)
            if self.add_lit(s2, lit.negate()):
                F.append(s2)
        return T, F

    def branch_eq(self, value_node, case_node, st: State):
        return self.branch_cmp(value_node, "==", case_node, st, case_node)

    def branch_cmp(self, left, op, right, st: State, node) -> Tuple[List[State], List[State]]:
        T, F = [], []
        if self.text(right) == "nil" or self.text(left) == "nil":
            other = left if self.text(right) == "nil" else right
            for s, v in self.eval(other, st):
                if v.is_nil:
                    (T if op == "==" else F).append(s)
                    continue
                atom = Atom("nil", f"nil:{v.canon}:", f"{v.canon} == nil", self.loc(node), subject=v.canon)
                pos = op == "=="
                s1, s2 = s.fork(), s
                if self.add_lit(s1, Lit(atom, pos)):
                    T.append(s1)
                if self.add_lit(s2, Lit(atom, not pos)):
                    F.append(s2)
            return T, F
        for s, (lv, rv) in [(s2, (vals[0], vals[1])) for s2, vals in self.eval_seq([left, right], st)]:
            a, b = self.num(lv), self.num(rv)
            const_name = rv.const_name or lv.const_name
            const_family = rv.const_family or lv.const_family
            if op == "==":
                rel, pos = sp.Eq(a, b), True
            elif op == "!=":
                rel, pos = sp.Eq(a, b), False
            elif op == "<":
                rel, pos = sp.Lt(a, b), True
            elif op == ">=":
                rel, pos = sp.Lt(a, b), False
            elif op == ">":
                rel, pos = sp.Lt(b, a), True
            else:  # <=
                rel, pos = sp.Lt(b, a), False
            if rel is sp.true or rel is sp.false:
                truth = (rel is sp.true) == pos
                (T if truth else F).append(s)
                continue
            subject = (lv.canon if rv.const_name else rv.canon) if const_name else ""
            atom = Atom("rel", str(rel), self.text(node), self.loc(node), rel, subject,
                        const_family if (op in ("==", "!=") and const_name) else "", None,
                        const_name if op in ("==", "!=") else "")
            s1, s2 = s.fork(), s
            if self.add_lit(s1, Lit(atom, pos)):
                T.append(s1)
            if self.add_lit(s2, Lit(atom, not pos)):
                F.append(s2)
        return T, F

    # ------------------------------------------------------------------ expressions
    def eval_seq(self, nodes, st: State) -> List[Tuple[State, List[Val]]]:
        acc = [(st, [])]
        for n in nodes:
            nxt = []
            for s, vals in acc:
                for s2, v in self.eval(n, s):
                    nxt.append((s2, vals + [v]))
            acc = nxt
            if len(acc) > self.max_paths:
                acc = acc[: self.max_paths]
        return acc

    def arith(self, op: str, a: Val, b: Val) -> Val:
        x, y = self.num(a), self.num(b)
        if op == "+":
            r = x + y
        elif op == "-":
            r = x - y
        elif op == "*":
            r = x * y
        elif op == "/":
            r = TDiv(x, y)
        elif op == "%":
            r = TMod(x, y)
        elif op == "<<":
            r = Shl(x, y) if not (y.is_Integer and x.is_Integer) else sp.Integer(int(x) << int(y))
            if y.is_Integer and not x.is_Integer:
                r = x * (2 ** int(y))
        elif op == ">>":
            r = Shr(x, y)
        elif op == "&":
            r = BitAnd(x, y)
        elif op == "|":
            r = BitOr(x, y)
        elif op == "^":
            r = BitXor(x, y)
        elif op == "&^":
            r = BitAnd(x, -y - 1)
        else:
            r = self.reg.sym(f"({a.canon}{op}{b.canon})", "opaque")
        return Val(f"({a.canon}{op}{b.canon})", num=sp.expand(r), typ=a.typ or b.typ, tctx=a.tctx or b.tctx)

    def eval(self, node, st: State) -> List[Tuple[State, Val]]:
        t = node.type
        if t == "int_literal":
            from traffic.lang.go_program import parse_go_int
            v = parse_go_int(self.text(node))
            return [(st, Val(self.text(node), num=sp.Integer(v) if v is not None else None))]
        if t == "rune_literal":
            from traffic.lang.go_program import parse_go_rune
            v = parse_go_rune(self.text(node))
            return [(st, Val(self.text(node), num=sp.Integer(v) if v is not None else None))]
        if t in ("interpreted_string_literal", "raw_string_literal"):
            return [(st, Val(self.text(node), length=sp.Integer(len(self.text(node)) - 2), typ="string"))]
        if t == "nil":
            return [(st, Val("nil", is_nil=True))]
        if t in ("true", "false"):
            return [(st, Val(t))]
        if t == "parenthesized_expression":
            inner = [c for c in node.children if c.is_named]
            return self.eval(inner[0], st) if inner else [(st, Val("?"))]
        if t == "identifier":
            return [(st, self.eval_ident(node, st))]
        if t == "selector_expression":
            return self.eval_selector(node, st)
        if t == "call_expression":
            return self.eval_call(node, st)
        if t == "type_conversion_expression":
            operand = node.child_by_field_name("operand")
            return [(s, v.copy(typ=self.text(node.child_by_field_name("type")), tctx=(self._pkg, self._file)))
                    for s, v in self.eval(operand, st)]
        if t == "binary_expression":
            op = self.text(node.child_by_field_name("operator"))
            if op in ("==", "!=", "<", "<=", ">", ">=", "&&", "||"):
                return self.eval_bool_value(node, st)
            out = []
            for s, vals in self.eval_seq([node.child_by_field_name("left"), node.child_by_field_name("right")], st):
                out.append((s, self.arith(op, vals[0], vals[1])))
            return out
        if t == "unary_expression":
            op = self.text(node.child_by_field_name("operator"))
            out = []
            for s, v in self.eval(node.child_by_field_name("operand"), st):
                if op == "-":
                    out.append((s, Val(f"-{v.canon}", num=-self.num(v))))
                elif op == "^":
                    out.append((s, Val(f"^{v.canon}", num=-self.num(v) - 1)))
                elif op == "!":
                    if v.boolean is not None:
                        out.append((s, Val(f"!{v.canon}", boolean=v.boolean.negate())))
                    else:
                        out.append((s, Val(f"!{v.canon}")))
                else:  # & * + <-
                    out.append((s, v))
            return out
        if t == "index_expression":
            res = []
            for s, vals in self.eval_seq([node.child_by_field_name("operand"), node.child_by_field_name("index")], st):
                res.append((s, Val(f"{vals[0].canon}[{vals[1].canon}]")))
            return res
        if t == "slice_expression":
            return self.eval_slice(node, st)
        if t == "type_assertion_expression":
            operand = node.child_by_field_name("operand")
            ttext = self.text(node.child_by_field_name("type"))
            out = []
            for s, v in self.eval(operand, st):
                atom = Atom("typeis", f"typeis:{v.canon}:{ttext}", f"{v.canon}.({ttext})", self.loc(node),
                            subject=v.canon, type_text=ttext, type_ctx=(self._pkg, self._file))
                nv = v.copy(typ=ttext, tctx=(self._pkg, self._file))
                ok = Val(f"{v.canon}.({ttext}).ok", boolean=Lit(atom, True))
                nv.items = [nv.copy(items=None), ok]
                out.append((s, nv))
            return out
        if t == "composite_literal":
            ty = node.child_by_field_name("type")
            ttext = self.text(ty) if ty is not None else ""
            body = node.child_by_field_name("body")
            n_elems = len([c for c in body.children if c.is_named]) if body is not None else 0
            length = sp.Integer(n_elems) if ttext.startswith("[") else None
            return [(st, Val(f"{ttext}{{}}", length=length, typ=ttext, tctx=(self._pkg, self._file)))]
        return [(st, Val(self.text(node)[:80]))]

    def eval_bool_value(self, node, st: State) -> List[Tuple[State, Val]]:
        # Represent a boolean expression used as a value by an opaque atom keyed by its text,
        # unless it is a simple comparison (then keep the relational atom for later branching).
        T, F = self.branch(node, st.fork())
        if len(T) == 1 and len(F) == 1 and T[0].conds and len(T[0].conds) == len(st.conds) + 1:
            lit = T[0].conds[-1]
            return [(st, Val(self.text(node), boolean=lit))]
        atom = Atom("bool", f"bool:{self.text(node)}", self.text(node), self.loc(node), subject=self.text(node))
        return [(st, Val(self.text(node), boolean=Lit(atom, True)))]

    def eval_ident(self, node, st: State) -> Val:
        name = self.text(node)
        if name in st.env:
            return st.env[name]
        if name in ("true", "false"):
            return Val(name)
        if name == "nil":
            return Val("nil", is_nil=True)
        pkg = self._pkg
        if name in pkg.consts:
            value = self.program.const_value(pkg, name)
            c = pkg.consts[name]
            fam = f"{c.file.path}:{c.node.parent.parent.start_point[0] if c.node.parent is not None and c.node.parent.parent is not None else c.line}"
            if isinstance(value, bool) or value is None or isinstance(value, str):
                v = Val(name, const_name=name, const_family=fam)
                if isinstance(value, str):
                    v.length = sp.Integer(len(value))
                return v
            st.trace.append(TraceStep("const", f"{name} = {value}", (str(c.file.path), c.line)))
            return Val(name, num=sp.Integer(int(value)), const_name=name, const_family=fam)
        if name in pkg.vars:
            f, line, ttext = pkg.vars[name]
            return Val(f"{pkg.name}.{name}", typ=ttext, tctx=(pkg, f))
        return Val(name)

    def eval_selector(self, node, st: State) -> List[Tuple[State, Val]]:
        operand = node.child_by_field_name("operand")
        fld = self.text(node.child_by_field_name("field"))
        if operand.type == "identifier":
            alias = self.text(operand)
            if alias not in st.env and alias in self._file.imports:
                other = self.program.load(self._file.imports[alias], self._pkg.origin)
                if other is not None:
                    if fld in other.consts:
                        value = self.program.const_value(other, fld)
                        c = other.consts[fld]
                        fam = f"{c.file.path}:{c.node.parent.parent.start_point[0] if c.node.parent is not None and c.node.parent.parent is not None else c.line}"
                        if isinstance(value, int) and not isinstance(value, bool):
                            st.trace.append(TraceStep("const", f"{alias}.{fld} = {value}", (str(c.file.path), c.line)))
                            return [(st, Val(f"{alias}.{fld}", num=sp.Integer(value), const_name=f"{alias}.{fld}",
                                             const_family=fam))]
                        return [(st, Val(f"{alias}.{fld}", const_name=f"{alias}.{fld}", const_family=fam))]
                    if fld in other.vars:
                        f, line, ttext = other.vars[fld]
                        return [(st, Val(f"{other.import_path}.{fld}", typ=ttext, tctx=(other, f)))]
                return [(st, Val(f"{alias}.{fld}"))]
        out = []
        for s, base in self.eval(operand, st):
            canon = f"{base.canon}.{fld}"
            ftype, fctx = self.field_type(base, fld)
            v = Val(canon, typ=ftype, tctx=fctx)
            if canon in s.sets:
                v = s.sets[canon].copy(canon=canon) if s.sets[canon].canon else s.sets[canon]
                v.typ, v.tctx = v.typ or ftype, v.tctx or fctx
            out.append((s, v))
        return out

    def eval_slice(self, node, st: State) -> List[Tuple[State, Val]]:
        operand = node.child_by_field_name("operand")
        start = node.child_by_field_name("start")
        end = node.child_by_field_name("end")
        nodes = [operand] + [x for x in (start, end) if x is not None]
        out = []
        for s, vals in self.eval_seq(nodes, st):
            base = vals[0]
            i = 1
            lo = sp.Integer(0)
            hi = self.length(base)
            if start is not None:
                lo = self.num(vals[i])
                i += 1
            if end is not None:
                hi = self.num(vals[i])
            ln = sp.expand(hi - lo)
            canon = f"{base.canon}[{self.text(start) if start else ''}:{self.text(end) if end else ''}]"
            out.append((s, Val(canon, length=ln, typ=base.typ, tctx=base.tctx)))
        return out

    # ------------------------------------------------------------------ calls
    def _args(self, node):
        args = node.child_by_field_name("arguments")
        if args is None:
            return [], False
        named = [c for c in args.children if c.is_named]
        spread = False
        res = []
        for c in named:
            if c.type == "variadic_argument":
                spread = True
                inner = [x for x in c.children if x.is_named]
                res.append(inner[0] if inner else c)
            else:
                res.append(c)
        if args.children and any(ch.type == "..." for ch in args.children):
            spread = True
        return res, spread

    def eval_call(self, node, st: State) -> List[Tuple[State, Val]]:
        fn_node = node.child_by_field_name("function")
        arg_nodes, spread = self._args(node)
        ft = fn_node.type
        if ft == "identifier":
            name = self.text(fn_node)
            if name not in st.env:
                b = self.eval_builtin(name, node, arg_nodes, spread, st)
                if b is not None:
                    return b
                if name in self._pkg.funcs:
                    return self.call_function(self._pkg.funcs[name], None, arg_nodes, st, node, spread)
                if name in self._pkg.types and len(arg_nodes) == 1:
                    return [(s, v.copy(typ=name, tctx=(self._pkg, self._file))) for s, v in self.eval(arg_nodes[0], st)]
        if ft in ("parenthesized_type", "slice_type", "array_type", "pointer_type", "qualified_type",
                  "generic_type", "map_type") and len(arg_nodes) == 1:
            return [(s, v.copy(typ=self.text(fn_node), tctx=(self._pkg, self._file))) for s, v in self.eval(arg_nodes[0], st)]
        if ft == "selector_expression":
            operand = fn_node.child_by_field_name("operand")
            mname = self.text(fn_node.child_by_field_name("field"))
            if operand.type == "identifier" and self.text(operand) not in st.env and self.text(operand) in self._file.imports:
                ipath = self._file.imports[self.text(operand)]
                if (ipath, mname) in K.RANDOM_FUNCS and arg_nodes:
                    lo_off, hi_off = K.RANDOM_FUNCS[(ipath, mname)]
                    out = []
                    for s, v in self.eval(arg_nodes[0], st):
                        bound = self.num(v)
                        name = f"{self.text(operand)}.{mname}({v.canon})@{self.loc(node)[1]}"
                        r = self.reg.sym(name, "random", nonneg=True, note=f"uniform random in [0, {bound}{hi_off:+d}]",
                                         lo=sp.Integer(lo_off), hi=bound + hi_off, origin=self.loc(node))
                        s.trace.append(TraceStep("call", f"random {self.text(node)} in [0, {bound}{hi_off:+d}]", self.loc(node)))
                        out.append((s, Val(name, num=r)))
                    return out
                if (ipath, mname) in K.RANDOM_FUNCS_EXT and len(arg_nodes) > K.RANDOM_FUNCS_EXT[(ipath, mname)][0]:
                    idx, lo_off, hi_off, tup = K.RANDOM_FUNCS_EXT[(ipath, mname)]
                    out = []
                    for s, vals in self.eval_seq(arg_nodes, st):
                        bound = self.num(vals[idx])
                        name = f"{self.text(operand)}.{mname}({vals[idx].canon})@{self.loc(node)[1]}"
                        r = self.reg.sym(name, "random", nonneg=True, note=f"uniform random in [0, {bound}{hi_off:+d}]",
                                         lo=sp.Integer(lo_off), hi=bound + hi_off, origin=self.loc(node))
                        s.trace.append(TraceStep("call", f"random {self.text(node)} in [0, {bound}{hi_off:+d}]", self.loc(node)))
                        v = Val(name, num=r)
                        out.append((s, Val("tuple", items=[v, Val(name + ".err", typ="error")]) if tup else v))
                    return out
                if (ipath, mname) in K.NUMERIC_PASSTHROUGH_FUNCS and arg_nodes:
                    idx = K.NUMERIC_PASSTHROUGH_FUNCS[(ipath, mname)]
                    return [(s, v.copy(typ=f"*{self.text(operand)}.Int")) for s, v in self.eval(arg_nodes[idx], st)]
                other = self.program.load(ipath, self._pkg.origin)
                if other is not None:
                    if mname in other.funcs:
                        return self.call_function(other.funcs[mname], None, arg_nodes, st, node, spread)
                    if mname in other.types and len(arg_nodes) == 1:
                        return [(s, v.copy(typ=f"{self.text(operand)}.{mname}", tctx=(self._pkg, self._file)))
                                for s, v in self.eval(arg_nodes[0], st)]
                return self._opaque_call(f"{self.text(operand)}.{mname}", arg_nodes, st, node)
            out = []
            for s, recv in self.eval(operand, st):
                out.extend(self.eval_method_call(recv, mname, arg_nodes, spread, s, node))
            return out
        if ft == "func_literal":
            return [(st, Val("func-literal-call"))]
        return self._opaque_call(self.text(fn_node)[:60], arg_nodes, st, node)

    def _opaque_call(self, name: str, arg_nodes, st: State, node) -> List[Tuple[State, Val]]:
        out = []
        for s, vals in self.eval_seq(arg_nodes, st):
            canon = f"{name}({','.join(v.canon for v in vals)})"
            self.opaque_calls.setdefault(canon, self.loc(node))
            out.append((s, Val(canon)))
        return out

    def eval_builtin(self, name, node, arg_nodes, spread, st: State):
        if name == "len" and arg_nodes:
            return [(s, Val(f"len({v.canon})", num=self.length(v))) for s, v in self.eval(arg_nodes[0], st)]
        if name == "cap" and arg_nodes:
            return [(s, Val(f"cap({v.canon})", num=self.reg.sym(f"cap({v.canon})", "len", nonneg=True)))
                    for s, v in self.eval(arg_nodes[0], st)]
        if name in ("min", "max") and arg_nodes:
            out = []
            for s, vals in self.eval_seq(arg_nodes, st):
                nums = [self.num(v) for v in vals]
                r = sp.Min(*nums) if name == "min" else sp.Max(*nums)
                out.append((s, Val(f"{name}(...)", num=r)))
            return out
        if name == "append" and arg_nodes:
            out = []
            for s, vals in self.eval_seq(arg_nodes, st):
                base = vals[0]
                if spread and len(vals) == 2:
                    add = self.length(vals[1])
                else:
                    add = sp.Integer(len(vals) - 1)
                out.append((s, Val(base.canon, length=sp.expand(self.length(base) + add), typ=base.typ, tctx=base.tctx)))
            return out
        if name == "make" and arg_nodes:
            ttext = self.text(arg_nodes[0])
            if len(arg_nodes) >= 2 and ttext.startswith("[]"):
                return [(s, Val(f"make({ttext})", length=self.num(v), typ=ttext, tctx=(self._pkg, self._file)))
                        for s, v in self.eval(arg_nodes[1], st)]
            return [(st, Val(f"make({ttext})", typ=ttext, tctx=(self._pkg, self._file)))]
        if name == "new" and arg_nodes:
            ttext = self.text(arg_nodes[0])
            return [(st, Val(f"new({ttext})", typ="*" + ttext, tctx=(self._pkg, self._file)))]
        if name == "panic":
            st.status = "panic"
            return [(st, Val("panic"))]
        if name in K.INT_TYPE_NAMES and len(arg_nodes) == 1:
            return [(s, v.copy(typ=name)) for s, v in self.eval(arg_nodes[0], st)]
        if name in ("string",) and len(arg_nodes) == 1:
            return [(s, v.copy(typ=name)) for s, v in self.eval(arg_nodes[0], st)]
        if name in ("copy", "print", "println", "close", "delete", "clear", "recover"):
            out = []
            for s, vals in self.eval_seq(arg_nodes, st):
                out.append((s, Val(f"{name}(...)")))
            return out
        return None

    def eval_method_call(self, recv: Val, mname: str, arg_nodes, spread, st: State, node):
        # AEAD.Seal(dst, nonce, plaintext, ad): appends len(plaintext) + Overhead()
        if mname == K.AEAD_SEAL["method"] and len(arg_nodes) == K.AEAD_SEAL["nargs"]:
            out = []
            for s, vals in self.eval_seq(arg_nodes, st):
                ovh_name = f"{recv.canon}.{K.AEAD_SEAL['overhead_method']}()"
                ovh = self.reg.sym(ovh_name, "call", nonneg=True)
                self._note_getter(ovh_name, recv, K.AEAD_SEAL["overhead_method"])
                dst = vals[K.AEAD_SEAL["dst"]]
                pt = vals[K.AEAD_SEAL["plaintext"]]
                ln = sp.expand(self.length(dst) + self.length(pt) + ovh)
                s.trace.append(TraceStep("call", f"{recv.canon}.Seal(...): len = len(dst) + len(plaintext) + Overhead()", self.loc(node)))
                out.append((s, Val(f"{recv.canon}.Seal(...)", length=ln)))
            return out
        if mname == K.HASH_SUM["method"] and len(arg_nodes) == K.HASH_SUM["nargs"] and \
                self.implements_any(recv.typ, recv.tctx, K.HASH_SUM["types"]):
            out = []
            for s, vals in self.eval_seq(arg_nodes, st):
                size_name = f"{recv.canon}.{K.HASH_SUM['size_method']}()"
                size = self.reg.sym(size_name, "call", nonneg=True)
                self._note_getter(size_name, recv, K.HASH_SUM["size_method"])
                ln = sp.expand(self.length(vals[0]) + size)
                s.trace.append(TraceStep("call", f"{recv.canon}.Sum(...): len = len(b) + Size()", self.loc(node)))
                out.append((s, Val(f"{recv.canon}.Sum(...)", length=ln)))
            return out
        if mname in K.NUMERIC_PASSTHROUGH_METHODS and not arg_nodes and recv.num is not None:
            return [(st, Val(f"{recv.canon}.{mname}()", num=recv.num))]
        if mname in K.IN_PLACE_CRYPTO:
            return [(s, Val(f"{recv.canon}.{mname}(...)")) for s, _ in self.eval_seq(arg_nodes, st)]
        tclass = self.type_class(recv.typ, recv.tctx)
        if mname in K.SINK_METHODS and tclass is not None and arg_nodes:
            out = []
            for s, vals in self.eval_seq(arg_nodes, st):
                data = vals[0]
                ln = self.refine(s, self.length(data))
                kind = "buffer" if tclass == "buffer" else "write"
                s.trace.append(TraceStep("emit", f"{recv.canon}.{mname}({data.canon}) [{recv.typ}] len={ln}", self.loc(node)))
                s.emissions.append(Emission(kind, f"{recv.canon}.{mname}", recv.typ, tclass, ln, list(s.conds),
                                            self.loc(node), [], list(s.loops), list(s.assumptions),
                                            list(s.trace), dict(s.effects)))
                n = Val(f"{recv.canon}.{mname}.n", num=ln)
                err = Val(f"{recv.canon}.{mname}.err", typ="error")
                out.append((s, Val("tuple", items=[n, err])))
            return out
        callee = self.resolve_method(recv, mname)
        if callee is None and not recv.typ and recv.canon.startswith("$recv."):
            # untyped field of the receiver: fall back to a unique same-package method of that name
            cands = self._pkg.methods_by_name.get(mname, [])
            if len(cands) == 1:
                callee = cands[0]
        if callee is not None:
            return self.call_function(callee, recv, arg_nodes, st, node, spread)
        # interface dispatch / unknown: opaque, remember getter candidates
        out = []
        for s, vals in self.eval_seq(arg_nodes, st):
            canon = f"{recv.canon}.{mname}({','.join(v.canon for v in vals)})"
            if not vals:
                self._note_getter(canon, recv, mname)
            out.append((s, Val(canon)))
        return out

    def _note_getter(self, canon: str, recv: Val, mname: str) -> None:
        if canon in self.getters:
            return
        self.getters[canon] = [(recv.typ, recv.tctx, mname)]

    def _should_inline(self, callee: GoFunc, arg_vals) -> bool:
        if callee.qualname in self.stack or len(self.stack) >= self.max_depth:
            return False
        if callee.body is None:
            return False
        results = [r.type_text for r in callee.results]
        only_error = results == ["error"] or not results
        has_slice_param = any(p.type_text.startswith("[]") or p.type_text.startswith("...") or p.type_text == "string"
                              for p in callee.params)
        if callee.params and has_slice_param:
            return True
        if callee.params and not only_error:
            return True
        size = callee.end_line - callee.start_line
        if callee.qualname in self.emitting and size <= 40:
            return True
        return False

    def call_function(self, callee: GoFunc, recv: Optional[Val], arg_nodes, st: State, node, spread=False):
        out = []
        for s, vals in self.eval_seq(arg_nodes, st):
            if not self._should_inline(callee, vals):
                canon = f"{recv.canon + '.' if recv else ''}{callee.name}({','.join(v.canon for v in vals)})"
                rtypes = [r.type_text for r in callee.results]
                if not vals and recv is not None:
                    self.getters.setdefault(canon, [callee])
                if len(rtypes) > 1:
                    items = [Val(f"{canon}#{i}", typ=rt, tctx=(callee.package, callee.file)) for i, rt in enumerate(rtypes)]
                    out.append((s, Val(canon, items=items)))
                else:
                    out.append((s, Val(canon, typ=rtypes[0] if rtypes else "", tctx=(callee.package, callee.file))))
                continue
            summ = self.summarize(callee)
            if len(summ.paths) > self.callee_path_budget:
                # too many distinct outcomes to inline usefully: keep the call opaque
                self.notes.append(f"call to {callee.qualname} kept opaque ({len(summ.paths)} paths)")
                canon = f"{recv.canon + '.' if recv else ''}{callee.name}({','.join(v.canon for v in vals)})"
                out.append((s, Val(canon)))
                continue
            out.extend(self.instantiate(summ, callee, recv, vals, s, node))
        return out

    def instantiate(self, summ: Summary, callee: GoFunc, recv: Optional[Val], vals: List[Val], st: State, node):
        mapping = {}
        direct = {}
        if recv is not None:
            mapping["$recv"] = recv.canon
        nparams = len(callee.params)
        for i, p in enumerate(callee.params):
            if p.type_text.startswith("...") and i == nparams - 1:
                # variadic: unknown number unless spread
                if i < len(vals):
                    mapping[f"$p{i}"] = vals[i].canon
                    direct[self.reg.sym(f"len($p{i})", "input_len", nonneg=True)] = self.length(vals[i])
                continue
            if i >= len(vals):
                continue
            v = vals[i]
            mapping[f"$p{i}"] = v.canon
            ptype = p.type_text.strip()
            if ptype.startswith("[]") or ptype == "string":
                direct[self.reg.sym(f"len($p{i})", "input_len", nonneg=True)] = self.length(v)
            else:
                direct[self.reg.sym(f"$p{i}", "param")] = self.num(v)

        def renamer(text: str) -> str:
            return rename_text(text, mapping)

        def subs_for(free, depth=0):
            # One simultaneous substitution: callee placeholders become caller values.
            # (Renaming after substituting would re-rename the caller's own $pN symbols.)
            subs = {}
            for sym_ in free:
                if sym_ in direct:
                    subs[sym_] = direct[sym_]
                    continue
                new = renamer(sym_.name)
                if new != sym_.name:
                    inf = self.reg.get(sym_)
                    lo, hi = inf.lo, inf.hi
                    if depth < 3 and inf.kind == "random":
                        # the range bounds are expressions over callee placeholders too
                        if lo is not None:
                            lo = lo.xreplace(subs_for(lo.free_symbols, depth + 1))
                        if hi is not None:
                            hi = sp.expand(hi.xreplace(subs_for(hi.free_symbols, depth + 1)))
                    subs[sym_] = self.reg.sym(new, inf.kind, inf.nonneg, inf.note, lo, hi, inf.origin)
                    if sym_.name in self.getters and new not in self.getters:
                        self.getters[new] = self.getters[sym_.name]
            return subs

        def inst(expr):
            if expr is None:
                return None
            subs = subs_for(expr.free_symbols)
            return expr.xreplace(subs) if subs else expr

        def inst_lit(lit: Lit) -> Lit:
            a = lit.atom
            if a.kind == "rel":
                subs = subs_for(a.rel.free_symbols)
                new_rel = a.rel.xreplace(subs) if subs else a.rel
                return Lit(Atom("rel", str(new_rel), a.text, a.loc, new_rel, renamer(a.subject), a.type_text,
                                a.type_ctx, a.const_name), lit.positive)
            return Lit(substitute_atom(a, {}, renamer), lit.positive)

        def inst_val(v: Val) -> Val:
            nv = v.copy(canon=renamer(v.canon), num=inst(v.num), length=inst(v.length))
            if v.items is not None:
                nv.items = [inst_val(x) for x in v.items]
            if v.boolean is not None:
                nv.boolean = inst_lit(v.boolean)
            # keep the caller-visible type of the receiver-derived values
            return nv

        out = []
        call_site = (callee.qualname, str(self._file.path), node.start_point[0] + 1)
        for path in summ.paths:
            if path.status not in ("return", "fallthrough"):
                continue
            s = st.fork()
            ok = True
            for lit in path.conds:
                if not self.add_lit(s, inst_lit(lit)):
                    ok = False
                    break
            if not ok:
                continue
            for e in path.emissions:
                conds = list(st.conds)
                feasible = True
                tmp = State()
                tmp.conds = list(st.conds)
                tmp.known = dict(st.known)
                tmp.aliases = dict(st.aliases)
                for lit in e.conds:
                    if not self.add_lit(tmp, inst_lit(lit)):
                        feasible = False
                        break
                if not feasible:
                    continue
                conds = tmp.conds
                eff = dict(st.effects)
                for k_, v_ in e.effects.items():
                    kk = renamer(k_)
                    eff[kk] = sp.expand(eff.get(kk, sp.Integer(0)) + inst(v_))
                etrace = list(st.trace) + [TraceStep("call", f"enter {callee.short_name}", call_site[1:])] + \
                    [TraceStep(t_.kind, renamer(t_.text), t_.loc) for t_ in e.trace]
                s.emissions.append(Emission(e.kind, renamer(e.sink), e.sink_type, e.sink_class,
                                            self.refine(tmp, inst(e.length)),
                                            conds, e.loc, [call_site] + e.chain, list(st.loops) + e.loops,
                                            list(dict.fromkeys(st.assumptions + tmp.assumptions + e.assumptions)),
                                            etrace, eff))
            for k_, v_ in path.effects.items():
                kk = renamer(k_)
                s.effects[kk] = sp.expand(s.effects.get(kk, sp.Integer(0)) + inst(v_))
            for k_, v_ in path.sets.items():
                s.sets[renamer(k_)] = inst_val(v_)
            s.trace.append(TraceStep("call", f"enter {callee.short_name}", call_site[1:]))
            for tstep in path.trace:
                s.trace.append(TraceStep(tstep.kind, renamer(tstep.text), tstep.loc))
            s.trace.append(TraceStep("call", f"return from {callee.short_name}", call_site[1:]))
            for a_ in path.assumptions:
                if a_ not in s.assumptions:
                    s.assumptions.append(renamer(a_))
            rets = [inst_val(v) for v in path.returns]
            if len(rets) == 1:
                rv = rets[0]
            elif not rets:
                rv = Val(f"{callee.name}()")
            else:
                rv = Val(f"{callee.name}(...)", items=rets)
            out.append((s, rv))
        if not out:
            # all callee paths infeasible or erroring: treat the call as opaque on this path
            out.append((st, Val(f"{callee.name}(...)")))
        return out
