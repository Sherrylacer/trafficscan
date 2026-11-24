"""
Go frontend of the Source-to-Traffic analysis.

Orchestrates, for a Go project:
  1. dependency resolution (go.mod pinned versions + matching stdlib),
  2. loading the project packages and the packages they import directly,
  3. layer discovery (types wrapping connections) in all of them,
  4. evidence that the project actually uses each external layer
     (import sites, constructor call sites),
  5. symbolic execution of each layer's entry points and feature derivation,
  6. runtime evidence for the observability model.
"""
import os
import signal
import time
from pathlib import Path
from typing import Dict, List, Optional

from traffic.analysis.derive import FeatureDeriver, make_pretty
from traffic.analysis.observability import go_runtime_evidence, transport_semantics
from traffic.deps.go_resolver import GoDependencyResolver
from traffic.lang.go_domains import GoDomainResolver
from traffic.lang.go_layers import GoLayerFinder, Layer
from traffic.lang.go_program import BuildContext, GoPackage, GoProgram
from traffic.lang.go_symexec import GoSymExec

SKIP_DIRS = {".git", "testdata", "vendor", "node_modules", ".github"}
CRYPTO_HINTS = ("Seal(", ".Sum(", "XORKeyStream", "CryptBlocks", "encrypt", "Encrypt", "random ")


class _Timeout(Exception):
    pass


def _alarm_handler(signum, frame):
    raise _Timeout()


class GoTrafficFrontend:
    def __init__(self, project_root: str, cache_dir: str, go_version: Optional[str] = None,
                 goos: str = "linux", goarch: str = "amd64", tags: Optional[List[str]] = None,
                 offline: bool = False, entry_timeout: int = 60, include_stdlib_layers: bool = True,
                 package_filter: Optional[List[str]] = None, log=print) -> None:
        self.project_root = Path(project_root).resolve()
        self.log = log
        self.resolver = GoDependencyResolver(str(self.project_root), cache_dir, go_version, offline=offline, log=log)
        minor = int(self.resolver.go_version.split(".")[1]) if "." in self.resolver.go_version else 22
        self.build = BuildContext(goos, goarch, minor, tags)
        self.program = GoProgram(self.resolver, self.build, log=log)
        self.ex = GoSymExec(self.program)
        self.finder = GoLayerFinder(self.program, self.ex)
        self.entry_timeout = entry_timeout
        self.include_stdlib_layers = include_stdlib_layers
        self.package_filter = package_filter or []
        self.project_packages: List[GoPackage] = []
        self.stats: Dict[str, object] = {}

    # ------------------------------------------------------------------ loading
    def load_project(self) -> List[GoPackage]:
        mod = self.resolver.gomod.module
        pkgs = []
        for d, dirs, files in os.walk(self.project_root):
            dirs[:] = [x for x in dirs if x not in SKIP_DIRS and not x.startswith(".") and not x.startswith("_")]
            if not any(f.endswith(".go") for f in files):
                continue
            rel = os.path.relpath(d, self.project_root)
            ip = mod if rel == "." else f"{mod}/{rel.replace(os.sep, '/')}"
            p = self.program.load_directory(Path(d), ip, "project", mod, "")
            if p is not None:
                pkgs.append(p)
        self.project_packages = pkgs
        return pkgs

    def candidate_packages(self) -> List[GoPackage]:
        cands: Dict[str, GoPackage] = {p.import_path: p for p in self.project_packages}
        imports: Dict[str, int] = {}
        for p in self.project_packages:
            for ip, c in p.imports.items():
                imports[ip] = imports.get(ip, 0) + c
        for ip in sorted(imports):
            if ip in cands or ip == "C":
                continue
            if self.resolver.is_stdlib_path(ip) and not self.include_stdlib_layers:
                continue
            q = self.program.load(ip, "project")
            if q is not None:
                cands[ip] = q
        out = list(cands.values())
        if self.package_filter:
            out = [p for p in out if any(f in p.import_path for f in self.package_filter)]
        return out

    # ------------------------------------------------------------------ usage evidence
    def usage_evidence(self, layer: Layer) -> dict:
        pkg = layer.package
        if pkg.origin == "project":
            return {"used_by_project": True, "reason": "layer is defined in the project source", "sites": []}
        ctor_names = set()
        related_types = {layer.type_name}
        for tname, gt in pkg.types.items():
            if any(e.lstrip("*").split("[")[0] == layer.type_name for e in gt.embedded):
                related_types.add(tname)
        for fn in pkg.funcs.values():
            if any(any(t == r.type_text.lstrip("*").split("[")[0] for t in related_types) for r in fn.results):
                ctor_names.add(fn.name)
        sites = []
        for p in self.project_packages:
            for f in p.files:
                aliases = [a for a, ip in f.imports.items() if ip == pkg.import_path]
                if not aliases:
                    continue
                sites.append({"kind": "import", "file": str(f.path), "line": f.import_lines.get(pkg.import_path, 0)})
                text = f.source.decode("utf-8", "replace")
                for a in aliases:
                    for name in ctor_names:
                        needle = f"{a}.{name}("
                        start = 0
                        while True:
                            i = text.find(needle, start)
                            if i < 0:
                                break
                            line = text[:i].count("\n") + 1
                            sites.append({"kind": "constructor-call", "call": needle, "file": str(f.path), "line": line})
                            start = i + 1
        ctor_sites = [s for s in sites if s["kind"] == "constructor-call"]
        return {"used_by_project": bool(ctor_sites) or bool(sites),
                "constructs_layer": bool(ctor_sites),
                "constructors": sorted(ctor_names), "sites": sites[:40]}

    NET_CONN_METHODS = {"LocalAddr", "RemoteAddr", "SetDeadline"}

    def network_relevance(self, layer: Layer) -> str:
        """network: writes to a network connection or is itself a connection implementation;
        project: defined in the analysed project (transform of proxied traffic);
        generic: a byte-stream transform in a library unrelated to networking."""
        if any(s.sink_class == "net" for s in layer.sink_sites):
            return "network"
        methods = {m for (t, m) in layer.package.methods if t == layer.type_name}
        if self.NET_CONN_METHODS <= methods:
            return "network"
        if layer.package.origin == "project":
            return "project"
        if any(ip in ("net", "crypto/tls") or ip.startswith("net/") for ip in layer.package.imports):
            return "network"
        return "generic"

    # ------------------------------------------------------------------ analysis
    def analyse_layer(self, layer: Layer, runtime_ev: dict) -> List[dict]:
        dom = GoDomainResolver(self.program, self.ex, [layer.package])
        dom.extend_scope_with_imports(layer.package, 2)
        dom.compute_reachable_types([layer.package], 3)
        feats: List[dict] = []
        for entry in layer.entries:
            t0 = time.time()
            old = signal.signal(signal.SIGALRM, _alarm_handler)
            signal.alarm(self.entry_timeout)
            try:
                summ = self.ex.summarize(entry)
                emissions = [e for p in summ.paths for e in p.emissions]
                deriver = FeatureDeriver(self.ex.reg, dom, byte_counters=self.ex.byte_counter_fields())
                pretty = make_pretty(entry.recv_name, [p.name for p in entry.params])
                fs = deriver.derive(layer.name, entry.short_name, emissions, pretty, self._constants)
            except _Timeout:
                self.log(f"[go] timeout analysing {entry.qualname}")
                self.stats.setdefault("timeouts", []).append(entry.qualname)
                continue
            except RecursionError:
                self.stats.setdefault("errors", []).append(f"{entry.qualname}: recursion")
                continue
            except Exception as exc:  # keep going on unexpected constructs
                self.stats.setdefault("errors", []).append(f"{entry.qualname}: {exc.__class__.__name__}: {exc}")
                continue
            finally:
                signal.alarm(0)
                signal.signal(signal.SIGALRM, old)
            for f in fs:
                d = f.to_dict()
                d["provenance"] = layer.package.provenance()
                d["entry_location"] = entry.location()
                d["observability"] = transport_semantics(f.sink_class, f.sink_type, runtime_ev)
                d["flow"] = self._flow(f)
                d["analysis_seconds"] = round(time.time() - t0, 3)
                d["crypto_on_path"] = any(any(h in s["text"] for h in CRYPTO_HINTS) for s in f.derivation)
                feats.append(d)
        return feats

    @staticmethod
    def _constants(trace) -> List[dict]:
        out = {}
        for t in trace:
            if t.kind == "const":
                out[t.text] = {"definition": t.text, "file": t.loc[0], "line": t.loc[1]}
        return list(out.values())

    @staticmethod
    def _flow(f) -> List[dict]:
        flow = []
        seen = set()
        for s in f.derivation:
            if s["kind"] == "call" and s["text"].startswith("enter "):
                name = s["text"][6:]
                key = (name, s["line"])
                if key not in seen:
                    seen.add(key)
                    flow.append({"function": name, "call_site_file": s["file"], "call_site_line": s["line"]})
            elif s["kind"] == "call" and ("Seal(" in s["text"] or ".Sum(" in s["text"] or "random" in s["text"]):
                flow.append({"function": s["text"], "call_site_file": s["file"], "call_site_line": s["line"]})
            elif s["kind"] == "emit":
                flow.append({"function": "EMIT " + s["text"], "call_site_file": s["file"], "call_site_line": s["line"]})
        return flow

    def run(self) -> dict:
        t0 = time.time()
        self.log(f"[go] Go toolchain version for dependency analysis: go{self.resolver.go_version} "
                 f"({self.resolver.go_version_source})")
        self.load_project()
        self.log(f"[go] project packages: {len(self.project_packages)}")
        cands = self.candidate_packages()
        self.log(f"[go] candidate packages (project + direct imports): {len(cands)}")
        layers: List[Layer] = []
        for p in cands:
            try:
                layers.extend(self.finder.scan_package(p))
            except Exception as exc:
                self.stats.setdefault("errors", []).append(f"layer scan {p.import_path}: {exc}")
        self.log(f"[go] layers with emitting entry points: {len(layers)}")
        runtime_ev = go_runtime_evidence(self.program)
        layer_infos = []
        features: List[dict] = []
        for i, layer in enumerate(layers):
            usage = self.usage_evidence(layer)
            info = layer.to_dict()
            info["usage"] = usage
            info["network_relevance"] = self.network_relevance(layer)
            t1 = time.time()
            fs = self.analyse_layer(layer, runtime_ev)
            info["analysis_seconds"] = round(time.time() - t1, 2)
            info["feature_count"] = len(fs)
            for f in fs:
                f["network_relevance"] = info["network_relevance"]
                f["layer_used_by_project"] = usage.get("used_by_project", False)
                f["layer_constructed_by_project"] = usage.get("constructs_layer", layer.package.origin == "project")
            features.extend(fs)
            layer_infos.append(info)
            self.log(f"[go]  ({i + 1}/{len(layers)}) {layer.name}: {len(fs)} feature(s) "
                     f"[{info['analysis_seconds']}s]")
        self.stats.update({
            "seconds": round(time.time() - t0, 1),
            "packages_loaded": sum(1 for p in self.program.packages.values() if p is not None),
            "parse_errors": len(self.program.parse_errors),
            "functions_summarised": len(self.ex.cache),
            "executor_notes": sorted(set(self.ex.notes))[:50],
        })
        return {
            "language": "Go",
            "dependencies": self.resolver.summary(),
            "build_context": self.build.describe(),
            "layers": layer_infos,
            "features": features,
            "runtime_evidence": runtime_ev,
            "stats": self.stats,
        }
