"""
Layer discovery for Go programs.

A *layer* is a type that wraps a byte transport: it has a field whose type is
a network connection (net.Conn, net.PacketConn, ...) or a stream writer
(io.Writer, ...), and methods that eventually write to that field. Each layer
transforms application bytes on their way to the wire (TLS records,
WebSocket frames, AEAD chunks, mux frames, padding, ...).

For every package in scope we compute:
  * conn fields of struct types,
  * direct sink call sites (field.Write(...), param.Write(...)),
  * the closure of functions that (transitively, within the package) emit,
  * entry methods: exported emitting methods taking a byte slice.

This is purely structural; no protocol names or constants are involved.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from traffic.lang import go_knowledge as K
from traffic.lang.go_program import GoFunc, GoPackage, GoProgram, _strip_type


@dataclass
class SinkSite:
    func: GoFunc
    line: int
    text: str
    target: str          # e.g. "c.conn"
    target_type: str     # e.g. "net.Conn"
    sink_class: str      # net | stream


@dataclass
class Layer:
    package: GoPackage
    type_name: str
    conn_fields: Dict[str, Tuple[str, str]] = field(default_factory=dict)   # field -> (type, class)
    sink_sites: List[SinkSite] = field(default_factory=list)
    entries: List[GoFunc] = field(default_factory=list)
    emitting: Set[str] = field(default_factory=set)                         # qualnames

    @property
    def name(self) -> str:
        return f"{self.package.import_path}.{self.type_name}"

    def to_dict(self) -> dict:
        return {
            "layer": self.name,
            "package": self.package.import_path,
            "provenance": self.package.provenance(),
            "type": self.type_name,
            "conn_fields": {k: {"type": v[0], "class": v[1]} for k, v in self.conn_fields.items()},
            "sink_sites": [
                {"function": s.func.short_name, "file": str(s.func.file.path), "line": s.line, "call": s.text,
                 "target_type": s.target_type, "class": s.sink_class}
                for s in self.sink_sites
            ],
            "entries": [{"function": e.short_name, "file": str(e.file.path), "line": e.start_line} for e in self.entries],
        }


class GoLayerFinder:
    def __init__(self, program: GoProgram, executor) -> None:
        self.program = program
        self.ex = executor

    def _walk_calls(self, node, out: List):
        stack = [node]
        while stack:
            n = stack.pop()
            if n.type == "call_expression":
                out.append(n)
            if n.type == "func_literal":
                # closures still execute in the function's context (e.g. deferred writes)
                pass
            stack.extend(reversed(n.children))

    def _type_of_operand(self, fn: GoFunc, operand_text: str) -> Tuple[str, object]:
        """Best-effort static type of `recv.field` or a parameter name."""
        ctx = (fn.package, fn.file)
        parts = operand_text.split(".")
        if len(parts) == 1:
            for p in fn.params:
                if p.name == parts[0]:
                    return p.type_text, ctx
            return "", None
        if parts[0] == fn.recv_name and len(parts) == 2:
            gt = self.program.lookup_type(fn.package, fn.file, fn.recv_type)
            if gt is not None and gt.kind == "struct":
                if parts[1] in gt.fields:
                    return gt.fields[parts[1]], (gt.package, gt.file)
        return "", None

    def scan_package(self, pkg: GoPackage) -> List[Layer]:
        layers: Dict[str, Layer] = {}
        for tname, gt in pkg.types.items():
            if gt.kind != "struct":
                continue
            for fname, ftype in gt.fields.items():
                cls = self.ex.type_class(ftype, (pkg, gt.file))
                if cls in ("net", "stream"):
                    layers.setdefault(tname, Layer(pkg, tname)).conn_fields[fname] = (ftype, cls)
        # direct sink sites
        emitting: Set[str] = set()
        sinks_by_func: Dict[str, List[SinkSite]] = {}
        calls_by_func: Dict[str, List] = {}
        for fn in pkg.all_functions():
            if fn.body is None:
                continue
            calls: List = []
            self._walk_calls(fn.body, calls)
            calls_by_func[fn.qualname] = calls
            for c in calls:
                f = c.child_by_field_name("function")
                if f is None or f.type != "selector_expression":
                    continue
                m = fn.file.text(f.child_by_field_name("field"))
                if m not in K.SINK_METHODS:
                    continue
                operand = fn.file.text(f.child_by_field_name("operand"))
                ttext, tctx = self._type_of_operand(fn, operand)
                cls = self.ex.type_class(ttext, tctx) if ttext else None
                if cls in ("net", "stream"):
                    site = SinkSite(fn, c.start_point[0] + 1, fn.file.text(c)[:120], operand, ttext, cls)
                    sinks_by_func.setdefault(fn.qualname, []).append(site)
                    emitting.add(fn.qualname)
        # emitting closure inside the package (name-based call resolution)
        by_name: Dict[str, List[GoFunc]] = {}
        for fn in pkg.all_functions():
            by_name.setdefault(fn.name, []).append(fn)
        changed = True
        while changed:
            changed = False
            for fn in pkg.all_functions():
                if fn.qualname in emitting:
                    continue
                for c in calls_by_func.get(fn.qualname, []):
                    f = c.child_by_field_name("function")
                    if f is None:
                        continue
                    if f.type == "identifier":
                        name = fn.file.text(f)
                    elif f.type == "selector_expression":
                        name = fn.file.text(f.child_by_field_name("field"))
                    else:
                        continue
                    if any(g.qualname in emitting for g in by_name.get(name, [])):
                        emitting.add(fn.qualname)
                        changed = True
                        break
        # attach sink sites and entries to layer types
        for fn in pkg.all_functions():
            sites = sinks_by_func.get(fn.qualname, [])
            if fn.recv_type and fn.recv_type in layers:
                layers[fn.recv_type].sink_sites.extend(sites)
        for tname, layer in layers.items():
            layer.emitting = emitting
            for fn in pkg.all_functions():
                if fn.recv_type != tname or fn.qualname not in emitting:
                    continue
                if not fn.name[:1].isupper() or fn.name.startswith("Read"):
                    continue
                if any(p.type_text.startswith("[]") or p.type_text.startswith("...") for p in fn.params) or \
                        fn.name.startswith("Write") or fn.name.startswith("Send"):
                    layer.entries.append(fn)
        self.ex.emitting |= emitting
        return [l for l in layers.values() if l.sink_sites and l.entries]
