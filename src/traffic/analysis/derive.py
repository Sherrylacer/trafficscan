"""
Feature derivation: turns symbolic emissions into candidate traffic features.

Language independent. Input: emissions produced by a language frontend's
symbolic executor for one entry point of one layer, the symbol registry and
a domain resolver for opaque getter symbols. Output: candidate features with

  * the derived length (value, sequence or range) at the emission unit,
  * the closed-form formula and the derivation steps with source lines,
  * the trigger conditions (path conditions rendered for humans, classified
    into input-size, configuration, protocol-state and connection-state),
  * the evidence (call chain, constants with their declarations),
  * an explicit confidence level.

Nothing here knows about specific protocols or expected values.
"""
import itertools
import re
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

import sympy as sp

from traffic.analysis.symbolic import Emission, Lit, SymbolRegistry, lit_key

INPUT_KINDS = {"input_len", "loop"}
MAX_SEQUENCE = 64


def make_pretty(recv_name: str, param_names: List[str]) -> Callable[[str], str]:
    mapping = {"$recv": recv_name or "recv"}
    for i, n in enumerate(param_names):
        mapping[f"$p{i}"] = n or f"arg{i}"

    def pretty(text: str) -> str:
        text = re.sub(r"\$(?:recv|p\d+)(?![0-9A-Za-z_])", lambda m: mapping.get(m.group(0), m.group(0)), text)
        text = re.sub(r"@L(\d+)\.exit", r"", text)
        text = re.sub(r"@L(\d+)", r"", text)
        return text

    return pretty


@dataclass
class Variant:
    emission: Emission
    length: sp.Expr
    conds: List[Lit]


@dataclass
class Feature:
    layer: str
    entry: str
    sink: str
    sink_type: str
    sink_class: str
    unit_kind: str                      # fixed | sequence | affine | range | symbolic
    formula: str
    values: List[dict]
    sequence: List[dict]
    overhead: Optional[str]
    conditions: dict
    variants: int
    domains: Dict[str, list]
    constants: List[dict]
    derivation: List[dict]
    chain: List[dict]
    emission_site: dict
    confidence: str
    assumptions: List[str]
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return dict(self.__dict__)


class FeatureDeriver:
    def __init__(self, registry: SymbolRegistry, domain_resolver=None, max_domain_combos: int = 64,
                 byte_counters=None) -> None:
        self.reg = registry
        self.domains = domain_resolver
        self.max_domain_combos = max_domain_combos
        self.byte_counters = set(byte_counters or ())

    # ------------------------------------------------------------------ helpers
    def kinds(self, expr) -> Dict[sp.Symbol, str]:
        return {s: self.reg.get(s).kind for s in expr.free_symbols}

    def counters(self, e: Emission) -> List[sp.Symbol]:
        out = []
        for s in e.length.free_symbols:
            inc = e.effects.get(s.name)
            if inc is not None and sp.sympify(inc) == 1 and self.reg.get(s).kind == "state":
                out.append(s)
        return out

    def classify_cond(self, lit: Lit, input_syms, counter_syms, pretty) -> Tuple[str, str]:
        text = lit.render(pretty)
        a = lit.atom
        syms = a.rel.free_symbols if (a.kind == "rel" and a.rel is not None) else set()
        names = {s.name for s in syms}
        if syms & set(input_syms) or any(self.reg.get(s).kind in INPUT_KINDS for s in syms):
            return "input_size", text
        if syms & set(counter_syms):
            return "connection_state", text
        subj = a.subject or a.text or ""
        if a.kind in ("typeis",):
            return "protocol_state", text
        if re.search(r"(^|\.)(config|cfg|conf|opts?|options|settings)\.", subj) or \
                any(re.search(r"(config|cfg|conf|opts?|options|settings)\.", n) for n in names):
            return "configuration", text
        if a.kind == "rel" and a.const_name:
            return "protocol_state", text
        if a.kind == "rel" and any(self.reg.get(s).kind == "state" for s in syms):
            return "connection_state", text
        return "other", text

    def resolve_domains(self, expr, skip: set) -> Tuple[Dict[str, list], List[Dict[sp.Symbol, int]], List[str]]:
        doms: Dict[str, list] = {}
        unresolved = []
        per_sym = []
        for s in sorted(expr.free_symbols, key=lambda x: x.name):
            if s in skip:
                continue
            info = self.reg.get(s)
            if info.kind == "random":
                unresolved.append(s.name)
                continue
            if self.domains is None:
                unresolved.append(s.name)
                continue
            dvs = self.domains.domain(s.name)
            doms[s.name] = [d.to_dict() for d in dvs]
            # integer values, or symbolic values (e.g. a budget getter returning `K - other.Overhead()`)
            # that may cancel against the rest of the expression
            resolved = [d for d in dvs if d.value is not None or
                        (getattr(d, "sym_expr", None) is not None and s not in sp.sympify(d.sym_expr).free_symbols)]
            if not resolved:
                unresolved.append(s.name)
                continue
            if len(resolved) < len(dvs):
                unresolved.append(s.name + " (partially)")
            per_sym.append((s, resolved))
        combos = []
        if per_sym:
            for prod in itertools.islice(itertools.product(*[v for _, v in per_sym]), self.max_domain_combos * 8):
                binding = {s: (sp.Integer(dv.value) if dv.value is not None else sp.sympify(dv.sym_expr))
                           for (s, _), dv in zip(per_sym, prod)}
                # resolve bindings that refer to other bound symbols
                for _ in range(3):
                    binding = {k: sp.expand(v.xreplace(binding)) for k, v in binding.items()}
                lits = [l for dv in prod for l in getattr(dv, "lits", [])]
                combos.append((binding, lits))
        return doms, combos, unresolved

    @staticmethod
    def cond_holds(lit: Lit, binding: Dict) -> Optional[bool]:
        a = lit.atom
        if a.kind != "rel" or a.rel is None:
            return None
        r = a.rel.xreplace(binding)
        if r is sp.true or r is sp.false:
            return (r is sp.true) == lit.positive
        return None

    def random_range(self, expr) -> Optional[Tuple[sp.Expr, sp.Expr]]:
        rnd = [s for s in expr.free_symbols if self.reg.get(s).kind == "random"]
        if not rnd:
            return None
        lo_b, hi_b = {}, {}
        for s in rnd:
            info = self.reg.get(s)
            if info.lo is None or info.hi is None:
                return None
            lo_b[s], hi_b[s] = info.lo, info.hi
        # monotone in each random symbol if coefficient sign is fixed (linear case)
        lo_v, hi_v = {}, {}
        for s in rnd:
            coeff = sp.diff(expr, s)
            if coeff.free_symbols:
                return None
            if coeff >= 0:
                lo_v[s], hi_v[s] = lo_b[s], hi_b[s]
            else:
                lo_v[s], hi_v[s] = hi_b[s], lo_b[s]
        return sp.expand(expr.xreplace(lo_v)), sp.expand(expr.xreplace(hi_v))

    # ------------------------------------------------------------------ main
    def derive(self, layer_name: str, entry_name: str, emissions: List[Emission], pretty: Callable[[str], str],
               constants_lookup: Callable[[List], List[dict]]) -> List[Feature]:
        writes = [e for e in emissions if e.kind == "write"]
        buffers = [e for e in emissions if e.kind == "buffer"]
        # group by (sink, site, length expression)
        groups: Dict[Tuple, List[Emission]] = {}
        for e in writes:
            key = (e.sink, e.loc, str(e.length))
            groups.setdefault(key, []).append(e)
        features: List[Feature] = []
        for (sink, loc, _), ems in groups.items():
            f = self._derive_group(layer_name, entry_name, ems, pretty, constants_lookup, buffers)
            if f is not None:
                features.append(f)
        return features

    def _derive_group(self, layer_name, entry_name, ems: List[Emission], pretty, constants_lookup, buffers):
        e0 = ems[0]
        L = sp.expand(e0.length)
        kinds = self.kinds(L)
        input_syms = [s for s, k in kinds.items() if k in INPUT_KINDS]
        counters = self.counters(e0)
        # common vs distinguishing conditions across variants
        common_keys = set(lit_key(l) for l in e0.conds)
        for e in ems[1:]:
            common_keys &= set(lit_key(l) for l in e.conds)
        common = [l for l in e0.conds if lit_key(l) in common_keys]
        alternatives = []
        for e in ems:
            alt = [l.render(pretty) for l in e.conds if lit_key(l) not in common_keys]
            if alt and alt not in alternatives:
                alternatives.append(alt)
        byte_syms = [s for l in common if l.atom.kind == "rel" and l.atom.rel is not None
                     for s in l.atom.rel.free_symbols if s.name in self.byte_counters]
        byte_syms = list(dict.fromkeys(byte_syms))
        cond_classes: Dict[str, List[str]] = {}
        for l in common:
            cls, text = self.classify_cond(l, input_syms, counters + byte_syms, pretty)
            cond_classes.setdefault(cls, []).append(text)
        conditions = {"all_of": cond_classes, "any_of_variants": alternatives[:12],
                      "variant_count": len(ems)}

        values: List[dict] = []
        sequence: List[dict] = []
        overhead = None
        unit_kind = "symbolic"
        notes: List[str] = []
        confidence = "static-symbolic (unresolved symbols remain)"
        domains: Dict[str, list] = {}

        # symbols to resolve through implementation domains: those in L and in the common conditions,
        # excluding input sizes, counters and cumulative byte counters
        skip = set(input_syms) | set(counters) | set(byte_syms)
        cond_syms = set()
        for l in common:
            if l.atom.kind == "rel" and l.atom.rel is not None:
                cond_syms |= {x for x in l.atom.rel.free_symbols if x not in skip and
                              self.reg.get(x).kind not in INPUT_KINDS and self.reg.get(x).kind != "state"}
        dom_expr = L + sum(cond_syms, sp.Integer(0))
        doms, raw_combos, unresolved = self.resolve_domains(dom_expr, skip)
        domains = doms
        raw_combos = raw_combos or [({}, [])]
        # keep only domain combinations consistent with the path conditions: numeric conditions are
        # evaluated under the binding; the conditions under which each implementation value arises
        # (e.g. a dynamic-type case) must be compatible with the path's conditions
        valid = []
        seen_b = set()
        for cb, lits in raw_combos:
            if not all(self.cond_holds(l, cb) is not False for l in common):
                continue
            if lits and self.domains is not None and hasattr(self.domains, "consistent") and \
                    not self.domains.consistent(common, lits):
                continue
            key = tuple(sorted((k.name, str(v)) for k, v in cb.items()))
            if key in seen_b:
                continue
            seen_b.add(key)
            valid.append(cb)
        combos = [cb for cb, _ in raw_combos]
        dropped = len(combos) - len(valid)
        if dropped:
            notes.append(f"{dropped} implementation-domain combination(s) excluded by path conditions")
        combos = valid or combos
        exact_resolution = not unresolved and all(len(d) == 1 for d in doms.values())

        if input_syms:
            if len(input_syms) == 1:
                s = input_syms[0]
                slope = sp.diff(L, s)
                rest = sp.expand(L - s)
                if slope == 1 and not any(self.reg.get(x).kind in INPUT_KINDS for x in rest.free_symbols):
                    unit_kind = "affine"
                    overhead = pretty(str(rest))
                    ov_vals = sorted({int(rest.xreplace(c)) for c in combos if rest.xreplace(c).is_Integer})
                    values = [{"overhead_bytes": v} for v in ov_vals]
                    if rest.is_Integer:
                        confidence = "static-derived"
                    elif ov_vals:
                        confidence = "static-derived (implementation-domain values)"
                    notes.append("unit length = input length + overhead (size-preserving encapsulation; "
                                 "leaks the plaintext length)")
            if unit_kind == "symbolic":
                unit_kind = "input-dependent"
                notes.append("unit length depends on application input size in a non-affine way")
        else:
            rr = self.random_range(L)
            if rr is not None:
                unit_kind = "range"
                lo, hi = rr
                lo_vals = sorted({int(lo.xreplace(c)) for c in combos if lo.xreplace(c).is_Integer})
                hi_vals = sorted({int(hi.xreplace(c)) for c in combos if hi.xreplace(c).is_Integer})
                if lo_vals and hi_vals:
                    values = [{"min": min(lo_vals), "max": max(hi_vals)}]
                    confidence = "static-derived (random range)"
                else:
                    values = [{"min": pretty(str(lo)), "max": pretty(str(hi))}]
            elif counters:
                unit_kind = "sequence"
                c = counters[0]
                cum = [sp.Integer(0) for _ in combos]
                misses = 0
                seq_symbolic = False
                for k in range(MAX_SEQUENCE):
                    vals = set()
                    for i, cb in enumerate(combos):
                        bind = dict(cb)
                        bind[c] = sp.Integer(k)
                        for bs in byte_syms:
                            bind[bs] = cum[i]
                        if any(self.cond_holds(l, bind) is False for l in common):
                            continue
                        lk = sp.expand(L.xreplace(bind))
                        if lk.is_Integer:
                            vals.add(int(lk))
                            cum[i] = cum[i] + lk
                        else:
                            seq_symbolic = True
                    if not vals:
                        misses += 1
                        if sequence and misses >= 2:
                            break
                        continue
                    misses = 0
                    lk_sym = sp.expand(L.xreplace({c: sp.Integer(k)}))
                    exact = lk_sym.is_Integer or len(vals) == 1
                    sequence.append({"index": k, "values": sorted(vals), "exact": bool(lk_sym.is_Integer),
                                     "formula": pretty(str(lk_sym))})
                if sequence:
                    first_exact = sequence[0]["exact"]
                    if first_exact and all(x["exact"] for x in sequence):
                        confidence = "static-derived"
                    elif first_exact:
                        confidence = ("static-derived (first unit independent of implementation choices; "
                                      "later units use implementation-domain values)")
                    else:
                        confidence = "static-derived (implementation-domain values)"
                    if unresolved and seq_symbolic:
                        confidence += "; some implementations unresolved"
                notes.append(f"`{pretty(c.name)}` is a per-connection counter incremented on this path; "
                             f"index k = number of earlier units built on this path")
                if byte_syms:
                    notes.append("sequence truncated where cumulative counter(s) "
                                 + ", ".join(f"`{pretty(b.name)}`" for b in byte_syms)
                                 + " reach their threshold, counting only the units of this sequence "
                                   "(other writes on the connection also count, so the real cut-over can be earlier)")
            else:
                vals = sorted({int(L.xreplace(cb)) for cb in combos if L.xreplace(cb).is_Integer})
                if vals:
                    unit_kind = "fixed"
                    values = [{"value": v} for v in vals]
                    if L.is_Integer:
                        confidence = "static-derived"
                    elif len(vals) == 1:
                        confidence = "static-derived (value independent of implementation choices)"
                    else:
                        confidence = "static-derived (implementation-domain values)"
                    # unresolved implementations only matter if they survive substitution
                    if unresolved and any(not L.xreplace(cb).is_Integer for cb in combos):
                        confidence += "; some implementations unresolved"
        # derivation steps: constants, branches, calls and assignments on the path
        steps = []
        seen = set()
        for t in e0.trace:
            if t.kind in ("const", "branch", "call", "emit", "loop") or (t.kind == "assign" and len(steps) < 400):
                key = (t.kind, t.text, t.loc)
                if key in seen:
                    continue
                seen.add(key)
                steps.append({"kind": t.kind, "text": pretty(t.text), "file": t.loc[0], "line": t.loc[1]})
        consts = constants_lookup(e0.trace)
        chain = [{"function": c[0], "file": c[1], "line": c[2]} for c in e0.chain]
        buffered = [b for b in buffers if b.loc != e0.loc]
        if buffered:
            notes.append("alternative path appends the same unit to a buffer (coalesced with other units "
                         "before reaching the sink): " + ", ".join(sorted({pretty(b.sink) for b in buffered})))
        if e0.loops:
            notes.append("emitted inside a loop: one unit per iteration (fragmentation of a larger input)")
        return Feature(
            layer=layer_name, entry=entry_name, sink=pretty(e0.sink), sink_type=e0.sink_type,
            sink_class=e0.sink_class, unit_kind=unit_kind, formula=pretty(str(L)), values=values,
            sequence=sequence, overhead=overhead, conditions=conditions, variants=len(ems),
            domains={pretty(k): v for k, v in domains.items()}, constants=consts, derivation=steps, chain=chain,
            emission_site={"file": e0.loc[0], "line": e0.loc[1]}, confidence=confidence,
            assumptions=sorted(set(a for e in ems for a in e.assumptions)), notes=notes,
        )
