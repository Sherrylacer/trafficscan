"""
Language-independent symbolic representation used by the traffic analysis.

Values are sympy expressions over *canonical symbols*: every symbol is named
by the canonical source text of the quantity it stands for (for example
``$recv.out.cipher.Overhead()``).  Because the same program quantity gets the
same symbol regardless of which function it is read in, sympy can cancel
terms across function boundaries; e.g. an overhead subtracted when computing
a payload budget and added back when the frame is built.

Path conditions are lists of literals over atoms. Atoms are relational
(sympy), opaque boolean, nil tests, or dynamic-type tests (type switches).
"""
import re
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

import sympy as sp


# --------------------------------------------------------------------------- sympy helpers
class BitAnd(sp.Function):
    @classmethod
    def eval(cls, a, b):
        if a.is_Integer and b.is_Integer:
            return sp.Integer(int(a) & int(b))
        if b.is_Integer and int(b) == 0:
            return sp.Integer(0)


class BitOr(sp.Function):
    @classmethod
    def eval(cls, a, b):
        if a.is_Integer and b.is_Integer:
            return sp.Integer(int(a) | int(b))


class BitXor(sp.Function):
    @classmethod
    def eval(cls, a, b):
        if a.is_Integer and b.is_Integer:
            return sp.Integer(int(a) ^ int(b))


class Shl(sp.Function):
    @classmethod
    def eval(cls, a, b):
        if a.is_Integer and b.is_Integer:
            return sp.Integer(int(a) << int(b))


class Shr(sp.Function):
    @classmethod
    def eval(cls, a, b):
        if a.is_Integer and b.is_Integer:
            return sp.Integer(int(a) >> int(b))


class TDiv(sp.Function):
    """Truncating integer division (Go / C semantics)."""

    @classmethod
    def eval(cls, a, b):
        if a.is_Integer and b.is_Integer and int(b) != 0:
            q = abs(int(a)) // abs(int(b))
            return sp.Integer(q if (int(a) >= 0) == (int(b) >= 0) else -q)


class TMod(sp.Function):
    """Truncating remainder (Go / C semantics)."""

    @classmethod
    def eval(cls, a, b):
        if a.is_Integer and b.is_Integer and int(b) != 0:
            r = abs(int(a)) % abs(int(b))
            return sp.Integer(r if int(a) >= 0 else -r)


SYMPY_LOCALS = {"BitAnd": BitAnd, "BitOr": BitOr, "BitXor": BitXor, "Shl": Shl, "Shr": Shr,
                "TDiv": TDiv, "TMod": TMod}


# --------------------------------------------------------------------------- symbols
@dataclass
class SymInfo:
    name: str
    kind: str            # input_len | loop | state | call | param | len | random | opaque
    nonneg: bool = False
    note: str = ""
    lo: Optional[sp.Expr] = None   # for random symbols: inclusive range
    hi: Optional[sp.Expr] = None
    origin: Optional[Tuple[str, int]] = None


class SymbolRegistry:
    def __init__(self) -> None:
        self.info: Dict[str, SymInfo] = {}
        self._syms: Dict[str, sp.Symbol] = {}

    def sym(self, name: str, kind: str = "opaque", nonneg: bool = False, note: str = "",
            lo=None, hi=None, origin=None) -> sp.Symbol:
        if name in self._syms:
            inf = self.info[name]
            if nonneg and not inf.nonneg:
                # cannot change assumptions of an existing symbol; keep metadata only
                inf.nonneg = True
            return self._syms[name]
        s = sp.Symbol(name, integer=True, nonnegative=True) if nonneg else sp.Symbol(name, integer=True)
        self._syms[name] = s
        self.info[name] = SymInfo(name, kind, nonneg, note, lo, hi, origin)
        return s

    def get(self, s: sp.Symbol) -> SymInfo:
        return self.info.get(s.name) or SymInfo(s.name, "opaque")

    def rename_map(self, expr_syms, renamer: Callable[[str], str]) -> Dict[sp.Symbol, sp.Symbol]:
        out = {}
        for s in expr_syms:
            if not isinstance(s, sp.Symbol):
                continue
            new = renamer(s.name)
            if new != s.name:
                inf = self.get(s)
                out[s] = self.sym(new, inf.kind, inf.nonneg, inf.note, inf.lo, inf.hi, inf.origin)
        return out


# --------------------------------------------------------------------------- conditions
@dataclass(frozen=True, eq=False)
class Atom:
    kind: str                      # rel | bool | nil | typeis | opaque
    key: str                       # identity
    text: str                      # source text
    loc: Tuple[str, int] = ("", 0)
    rel: object = None             # sympy relational for kind == rel
    subject: str = ""              # canonical text of tested expression (nil/typeis/rel-with-const)
    type_text: str = ""            # typeis
    type_ctx: object = None        # (package, file) to interpret type_text
    const_name: str = ""           # rel: named constant on one side (e.g. VersionTLS13)


@dataclass(frozen=True, eq=False)
class Lit:
    atom: Atom
    positive: bool

    def negate(self) -> "Lit":
        return Lit(self.atom, not self.positive)

    def render(self, pretty: Callable[[str], str] = lambda s: s) -> str:
        a = self.atom
        if a.kind == "rel" and a.const_name and isinstance(a.rel, sp.Eq):
            syms = sorted(a.rel.free_symbols, key=lambda x: x.name)
            if len(syms) == 1:
                return pretty(f"{syms[0].name} {'==' if self.positive else '!='} {a.const_name}")
        if a.kind == "rel":
            r = a.rel if self.positive else sp.Not(a.rel)
            try:
                r = sp.simplify_logic(r) if isinstance(r, sp.logic.boolalg.Boolean) and not isinstance(r, sp.core.relational.Relational) else r
            except Exception:
                pass
            return pretty(rel_str(r))
        if a.kind == "nil":
            return pretty(f"{a.subject} {'==' if self.positive else '!='} nil")
        if a.kind == "typeis":
            return pretty(f"dynamic type of {a.subject} {'is' if self.positive else 'is not'} {a.type_text}")
        return pretty(a.text if self.positive else f"!({a.text})")


def rel_str(r) -> str:
    s = str(r)
    return s.replace("Ne(", "Ne(").replace("Eq(", "Eq(")


def substitute_atom(atom: Atom, subs: Dict, renamer: Optional[Callable[[str], str]]) -> Atom:
    if atom.kind == "rel":
        new_rel = atom.rel.xreplace(subs) if subs else atom.rel
        return Atom("rel", str(new_rel), atom.text, atom.loc, new_rel,
                    renamer(atom.subject) if renamer else atom.subject, atom.type_text, atom.type_ctx,
                    atom.const_name)
    if renamer is None:
        return atom
    subj = renamer(atom.subject) if atom.subject else atom.subject
    key = atom.key
    if atom.kind in ("nil", "typeis"):
        key = f"{atom.kind}:{subj}:{atom.type_text}"
    else:
        key = renamer(atom.key)
    return Atom(atom.kind, key, atom.text, atom.loc, atom.rel, subj, atom.type_text, atom.type_ctx,
                atom.const_name)


# --------------------------------------------------------------------------- results
@dataclass
class TraceStep:
    kind: str              # const | assign | call | branch | emit | note | loop
    text: str
    loc: Tuple[str, int]


@dataclass
class Emission:
    kind: str                       # write | buffer
    sink: str                       # canonical receiver text + method, e.g. "$recv.conn.Write"
    sink_type: str                  # e.g. "net.Conn"
    sink_class: str                 # net | stream | buffer
    length: sp.Expr
    conds: List[Lit]
    loc: Tuple[str, int]
    chain: List[Tuple[str, str, int]]          # (function qualname, file, line) call sites, outermost first
    loops: List[Tuple[str, int]]               # enclosing loops (file, line)
    assumptions: List[str] = field(default_factory=list)
    trace: List["TraceStep"] = field(default_factory=list)      # derivation steps up to the emission
    effects: Dict[str, sp.Expr] = field(default_factory=dict)   # state-field increments on this path


@dataclass
class PathResult:
    status: str                     # return | panic | error | fallthrough
    conds: List[Lit]
    returns: List[object]           # Val objects
    emissions: List[Emission]
    effects: Dict[str, sp.Expr]     # receiver-field canonical -> accumulated increment
    sets: Dict[str, object]         # receiver-field canonical -> assigned Val
    trace: List[TraceStep]
    assumptions: List[str]


@dataclass
class Summary:
    func_qualname: str
    paths: List[PathResult]
    truncated: bool = False
    notes: List[str] = field(default_factory=list)


def rename_text(text: str, mapping: Dict[str, str]) -> str:
    """Replace placeholders like $recv / $p0 (word-bounded) in canonical text."""
    if not mapping:
        return text
    def rep(m):
        return mapping.get(m.group(0), m.group(0))
    return re.sub(r"\$(?:recv|p\d+)(?![0-9A-Za-z_])", rep, text)


# --------------------------------------------------------------------------- path merging
def _val_sig(v) -> str:
    if v is None:
        return "None"
    parts = []
    num = getattr(v, "num", None)
    length = getattr(v, "length", None)
    items = getattr(v, "items", None)
    boolean = getattr(v, "boolean", None)
    if num is not None:
        parts.append("n=" + str(num))
    if length is not None:
        parts.append("l=" + str(length))
    if items is not None:
        parts.append("[" + ",".join(_val_sig(x) for x in items) + "]")
    if boolean is not None:
        parts.append(("+" if boolean.positive else "-") + boolean.atom.key)
    if getattr(v, "is_nil", False):
        parts.append("nil")
    if not parts:
        # opaque value (e.g. an unevaluated getter call): identity is its canonical text
        parts.append("obj=" + str(getattr(v, "canon", "")))
    return "|".join(parts)


def _emission_sig(e: "Emission") -> str:
    return f"{e.kind}|{e.sink}|{e.length}|{e.loops}|{e.loc}"


def path_signature(p: "PathResult") -> str:
    rets = ";".join(_val_sig(v) for v in p.returns)
    ems = ";".join(_emission_sig(e) for e in p.emissions)
    eff = ";".join(f"{k}={v}" for k, v in sorted(p.effects.items()))
    sets = ";".join(f"{k}={_val_sig(v)}" for k, v in sorted(p.sets.items()))
    return f"{p.status}#{rets}#{ems}#{eff}#{sets}"


def lit_key(l: "Lit") -> Tuple[str, str, bool]:
    return (l.atom.kind, l.atom.key, l.positive)


def _intersect(lists: List[List["Lit"]]) -> List["Lit"]:
    first = lists[0]
    rest = [set(lit_key(x) for x in l) for l in lists[1:]]
    return [x for x in first if all(lit_key(x) in r for r in rest)]


def merge_paths(paths: List["PathResult"]) -> List["PathResult"]:
    """Merge paths with identical observable outcomes (returns, emissions, effects).

    Conditions that differ between merged paths cannot influence any length
    or emission and are dropped (sound for the length analysis: the merged
    path covers the disjunction of the originals).
    """
    groups: Dict[str, List["PathResult"]] = {}
    order: List[str] = []
    for p in paths:
        sig = path_signature(p)
        if sig not in groups:
            groups[sig] = []
            order.append(sig)
        groups[sig].append(p)
    out = []
    for sig in order:
        g = groups[sig]
        if len(g) == 1:
            out.append(g[0])
            continue
        base = g[0]
        conds = _intersect([p.conds for p in g])
        ems = []
        for i, e in enumerate(base.emissions):
            e_conds = _intersect([p.emissions[i].conds for p in g])
            ems.append(Emission(e.kind, e.sink, e.sink_type, e.sink_class, e.length, e_conds, e.loc, e.chain,
                                e.loops, list(dict.fromkeys(a for p in g for a in p.emissions[i].assumptions)),
                                e.trace, e.effects))
        assumptions = list(dict.fromkeys(a for p in g for a in p.assumptions))
        out.append(PathResult(base.status, conds, base.returns, ems, base.effects, base.sets, base.trace,
                              assumptions))
    return out
