"""
Go dependency resolution for the Source-to-Traffic analysis.

Given a Go project root (directory containing go.mod) this resolver maps Go
import paths to source directories:

  * packages of the project module itself,
  * third-party modules pinned in go.mod (fetched as module zips from a
    GOPROXY mirror, exactly the versions recorded in go.mod / replace),
  * the Go standard library (fetched as the official source tarball of the
    toolchain version that built the target, so that crypto/tls, net, ...
    are analysed at the right version),
  * the standard library's own vendored golang.org/x packages.

No Go toolchain is required: everything is plain HTTP + archive extraction.
Every resolution records provenance (module, version, origin URL) so the
final report can cite the exact dependency version a feature comes from.
"""
import json
import os
import shutil
import re
import time
import urllib.request
from dataclasses import dataclass, field
import zipfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from traffic.deps.archive import (
    DownloadError,
    atomic_dir,
    download,
    finalize_dir,
    safe_extract_tar,
    safe_extract_zip,
)

DEFAULT_GOPROXIES = [
    "https://proxy.golang.org",
    "https://goproxy.cn",
    "https://goproxy.io",
    "https://mirrors.aliyun.com/goproxy",
]

GO_SRC_MIRRORS = [
    "https://go.dev/dl/{f}",
    "https://dl.google.com/go/{f}",
    "https://golang.google.cn/dl/{f}",
    "https://mirrors.aliyun.com/golang/{f}",
]


@dataclass
class GoModFile:
    module: str = ""
    go_version: str = ""
    toolchain: str = ""
    requires: Dict[str, str] = field(default_factory=dict)
    indirect: Dict[str, bool] = field(default_factory=dict)
    # replace old[@ver] => new [ver]; value is (new_path, new_version or "")
    replaces: Dict[str, Tuple[str, str]] = field(default_factory=dict)


def _strip_comment(line: str) -> Tuple[str, str]:
    if "//" in line:
        idx = line.index("//")
        return line[:idx].strip(), line[idx + 2:].strip()
    return line.strip(), ""


def parse_go_mod(path: Path) -> GoModFile:
    gm = GoModFile()
    block = None
    for raw in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        line, comment = _strip_comment(raw)
        if not line:
            continue
        if block:
            if line == ")":
                block = None
                continue
            _handle_directive(gm, block, line, comment)
            continue
        m = re.match(r"^(\w+)\s*\($", line)
        if m:
            block = m.group(1)
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            _handle_directive(gm, parts[0], parts[1], comment)
    return gm


def _unquote(s: str) -> str:
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "\"`":
        return s[1:-1]
    return s


def _handle_directive(gm: GoModFile, directive: str, rest: str, comment: str) -> None:
    toks = [_unquote(t) for t in rest.split()]
    if directive == "module" and toks:
        gm.module = toks[0]
    elif directive == "go" and toks:
        gm.go_version = toks[0]
    elif directive == "toolchain" and toks:
        gm.toolchain = toks[0]
    elif directive == "require" and len(toks) >= 2:
        gm.requires[toks[0]] = toks[1]
        gm.indirect[toks[0]] = "indirect" in comment
    elif directive == "replace" and "=>" in toks:
        i = toks.index("=>")
        old = toks[:i]
        new = toks[i + 1:]
        if old and new:
            gm.replaces[old[0]] = (new[0], new[1] if len(new) > 1 else "")


def escape_module_path(p: str) -> str:
    return "".join("!" + c.lower() if c.isupper() else c for c in p)


@dataclass
class ResolvedPackage:
    import_path: str
    directory: Path
    origin: str            # "project" | "stdlib" | "module" | "local-replace"
    module: str = ""
    version: str = ""

    def to_dict(self) -> dict:
        return {
            "import_path": self.import_path,
            "directory": str(self.directory),
            "origin": self.origin,
            "module": self.module,
            "version": self.version,
        }


class GoDependencyResolver:
    def __init__(
        self,
        project_root: str,
        cache_dir: str,
        go_version: Optional[str] = None,
        goproxies: Optional[List[str]] = None,
        offline: bool = False,
        log=print,
    ) -> None:
        self.project_root = Path(project_root).resolve()
        self.cache_dir = Path(cache_dir).resolve()
        env_proxy = os.environ.get("GOPROXY", "")
        if goproxies:
            self.goproxies = goproxies
        elif env_proxy:
            self.goproxies = [p for p in env_proxy.replace("|", ",").split(",") if p.startswith("http")]
        else:
            self.goproxies = list(DEFAULT_GOPROXIES)
        self._proxies_ranked = bool(goproxies or env_proxy)
        self.offline = offline
        self.log = log
        gomod_path = self.project_root / "go.mod"
        if not gomod_path.exists():
            raise FileNotFoundError(f"go.mod not found in {self.project_root}")
        self.gomod = parse_go_mod(gomod_path)
        self.go_version, self.go_version_source = self._decide_go_version(go_version)
        self.module_dirs: Dict[Tuple[str, str], Optional[Path]] = {}
        self.module_origin: Dict[Tuple[str, str], str] = {}
        self.failures: Dict[str, str] = {}
        self._goroot_src: Optional[Path] = None
        self._goroot_failed = False

    # ------------------------------------------------------------------ Go version
    def _decide_go_version(self, explicit: Optional[str]) -> Tuple[str, str]:
        if explicit:
            return explicit.lstrip("go"), "user-specified"
        if self.gomod.toolchain:
            return self.gomod.toolchain.lstrip("go"), "go.mod toolchain directive"
        v = self.gomod.go_version
        if v.count(".") >= 2:
            return v, "go.mod go directive"
        # Only a language version (e.g. "1.27"): pick the newest patch release.
        if not self.offline:
            try:
                with urllib.request.urlopen("https://go.dev/dl/?mode=json&include=all", timeout=30) as r:
                    releases = json.load(r)
                cands = [x["version"][2:] for x in releases if x["version"].startswith("go" + v + ".")]
                cands = [c for c in cands if re.fullmatch(r"\d+\.\d+\.\d+", c)]
                if cands:
                    best = max(cands, key=lambda s: tuple(int(p) for p in s.split(".")))
                    return best, f"newest patch of go {v} (ASSUMPTION: build toolchain unknown)"
            except Exception:
                pass
        return v + ".0", f"go {v}.0 (ASSUMPTION: build toolchain unknown)"

    # ------------------------------------------------------------------ stdlib
    def goroot_src(self) -> Optional[Path]:
        if self._goroot_src is not None or self._goroot_failed:
            return self._goroot_src
        final = self.cache_dir / "go" / f"go{self.go_version}"
        src = final / "go" / "src"
        if src.exists():
            self._goroot_src = src
            return src
        if self.offline:
            self._goroot_failed = True
            self.failures["stdlib"] = "offline and Go source not cached"
            return None
        fname = f"go{self.go_version}.src.tar.gz"
        archive = self.cache_dir / "downloads" / fname
        try:
            if not archive.exists():
                self.log(f"[deps] downloading Go {self.go_version} standard library source ...")
                url = download([m.format(f=fname) for m in GO_SRC_MIRRORS], archive, timeout=600, kind="tar.gz")
                self.log(f"[deps]   fetched {url}")
            tmp = atomic_dir(final)
            safe_extract_tar(archive, tmp, member_prefix_filter=["go/src/", "go/VERSION"])
            finalize_dir(tmp, final)
            self._goroot_src = src
        except (DownloadError, OSError) as exc:
            self._goroot_failed = True
            self.failures["stdlib"] = str(exc)
            self.log(f"[deps] FAILED to obtain Go stdlib source: {exc}")
        return self._goroot_src

    # ------------------------------------------------------------------ modules
    def _rank_proxies(self) -> None:
        """Probe each GOPROXY mirror once and try reachable ones first."""
        if self._proxies_ranked:
            return
        self._proxies_ranked = True
        timings = []
        for p in self.goproxies:
            t0 = time.time()
            try:
                with urllib.request.urlopen(f"{p.rstrip('/')}/github.com/google/uuid/@v/list", timeout=5) as r:
                    r.read(64)
                timings.append((time.time() - t0, p))
            except Exception:
                timings.append((1e9, p))
        self.goproxies = [p for _, p in sorted(timings)]
        self.log(f"[deps] module proxy order: {', '.join(self.goproxies)}")

    def _module_for_import(self, import_path: str) -> Optional[Tuple[str, str]]:
        best = None
        for mod, ver in self.gomod.requires.items():
            if import_path == mod or import_path.startswith(mod + "/"):
                if best is None or len(mod) > len(best[0]):
                    best = (mod, ver)
        return best

    def module_dir(self, mod: str, ver: str) -> Optional[Path]:
        key = (mod, ver)
        if key in self.module_dirs:
            return self.module_dirs[key]
        # replace directives
        rep = self.gomod.replaces.get(f"{mod}@{ver}") or self.gomod.replaces.get(mod)
        if rep:
            new_path, new_ver = rep
            if new_path.startswith(".") or new_path.startswith("/"):
                d = (self.project_root / new_path).resolve()
                self.module_dirs[key] = d if d.exists() else None
                self.module_origin[key] = "local-replace"
                return self.module_dirs[key]
            mod_fetch, ver_fetch = new_path, new_ver or ver
        else:
            mod_fetch, ver_fetch = mod, ver
        final = self.cache_dir / "gomod" / f"{escape_module_path(mod_fetch)}@{escape_module_path(ver_fetch)}"
        if final.exists():
            self.module_dirs[key] = final
            self.module_origin[key] = "module"
            return final
        if self.offline:
            self.failures[mod] = "offline and module not cached"
            self.module_dirs[key] = None
            return None
        zname = f"{escape_module_path(ver_fetch)}.zip"
        archive = self.cache_dir / "downloads" / f"{escape_module_path(mod_fetch).replace('/', '_')}@{zname}"
        urls = [f"{p.rstrip('/')}/{escape_module_path(mod_fetch)}/@v/{zname}" for p in self.goproxies]
        try:
            if archive.exists() and not zipfile.is_zipfile(archive):
                archive.unlink()
            if not archive.exists():
                self._rank_proxies()
                urls = [f"{p.rstrip('/')}/{escape_module_path(mod_fetch)}/@v/{zname}" for p in self.goproxies]
                self.log(f"[deps] fetching module {mod_fetch}@{ver_fetch}")
                download(urls, archive, timeout=300, kind="zip")
            tmp = atomic_dir(final)
            try:
                safe_extract_zip(archive, tmp, strip_prefix=f"{mod_fetch}@{ver_fetch}/")
            except Exception:
                shutil.rmtree(tmp, ignore_errors=True)
                archive.unlink(missing_ok=True)
                raise
            finalize_dir(tmp, final)
            self.module_dirs[key] = final
            self.module_origin[key] = "module"
        except (DownloadError, OSError, Exception) as exc:
            self.failures[mod] = str(exc)
            self.log(f"[deps] FAILED module {mod}@{ver}: {exc}")
            self.module_dirs[key] = None
        return self.module_dirs[key]

    # ------------------------------------------------------------------ imports
    @staticmethod
    def is_stdlib_path(import_path: str) -> bool:
        first = import_path.split("/", 1)[0]
        return "." not in first

    def resolve(self, import_path: str, importer_origin: str = "project") -> Optional[ResolvedPackage]:
        mod = self.gomod.module
        if mod and (import_path == mod or import_path.startswith(mod + "/")):
            sub = import_path[len(mod):].lstrip("/")
            d = self.project_root / sub
            return ResolvedPackage(import_path, d, "project", mod, "") if d.is_dir() else None
        if self.is_stdlib_path(import_path):
            if import_path == "C":
                return None
            root = self.goroot_src()
            if root is None:
                return None
            d = root / import_path
            return ResolvedPackage(import_path, d, "stdlib", "std", self.go_version) if d.is_dir() else None
        if importer_origin == "stdlib":
            root = self.goroot_src()
            if root is not None:
                d = root / "vendor" / import_path
                if d.is_dir():
                    return ResolvedPackage(import_path, d, "stdlib", "std(vendor)", self.go_version)
        mv = self._module_for_import(import_path)
        if mv is None:
            self.failures.setdefault(import_path, "no module in go.mod provides this import")
            return None
        mdir = self.module_dir(*mv)
        if mdir is None:
            return None
        sub = import_path[len(mv[0]):].lstrip("/")
        d = mdir / sub
        if not d.is_dir():
            return None
        return ResolvedPackage(import_path, d, self.module_origin.get(mv, "module"), mv[0], mv[1])

    def summary(self) -> dict:
        return {
            "module": self.gomod.module,
            "go_version": self.go_version,
            "go_version_source": self.go_version_source,
            "goroot_src": str(self._goroot_src) if self._goroot_src else None,
            "modules_fetched": {
                f"{m}@{v}": (str(d) if d else None) for (m, v), d in self.module_dirs.items()
            },
            "failures": dict(self.failures),
        }
