"""
Go program model for the Source-to-Traffic analysis.

Builds a package-aware index on top of the tree-sitter Go grammar that the
original LLMSCAN parser already uses:

  * build-constraint aware file selection (GOOS/GOARCH file suffixes,
    //go:build and legacy // +build lines),
  * per-file import alias tables,
  * functions and methods (receiver type, parameters, results),
  * struct / interface type declarations (fields, embedded types),
  * package-level constants with a full Go constant-expression evaluator
    (iota, implicit repetition in const blocks, cross-package constants,
    conversions, shifts, bit operations),
  * lazy loading of dependency packages through a dependency resolver.

Every value produced here carries a source location so that derived traffic
features can cite exact evidence.
"""
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

import tree_sitter
from tree_sitter import Language

LIB_PATH = Path(__file__).resolve().parents[3] / "lib" / "build" / "my-languages.so"

KNOWN_GOOS = {
    "aix", "android", "darwin", "dragonfly", "freebsd", "hurd", "illumos", "ios", "js",
    "linux", "nacl", "netbsd", "openbsd", "plan9", "solaris", "wasip1", "windows", "zos",
}
KNOWN_GOARCH = {
    "386", "amd64", "amd64p32", "arm", "arm64", "arm64be", "armbe", "loong64", "mips",
    "mips64", "mips64le", "mips64p32", "mips64p32le", "mipsle", "ppc", "ppc64", "ppc64le",
    "riscv", "riscv64", "s390", "s390x", "sparc", "sparc64", "wasm",
}
UNIX_GOOS = {
    "aix", "android", "darwin", "dragonfly", "freebsd", "hurd", "illumos", "ios", "linux",
    "netbsd", "openbsd", "solaris",
}

_GO_LANGUAGE = None


def go_language() -> Language:
    global _GO_LANGUAGE
    if _GO_LANGUAGE is None:
        import warnings

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            _GO_LANGUAGE = Language(str(LIB_PATH), "go")
    return _GO_LANGUAGE


def make_parser() -> tree_sitter.Parser:
    p = tree_sitter.Parser()
    p.set_language(go_language())
    return p


# --------------------------------------------------------------------------- build tags
class BuildContext:
    def __init__(self, goos: str = "linux", goarch: str = "amd64", go_minor: int = 27,
                 extra_tags: Optional[List[str]] = None, cgo: bool = False) -> None:
        self.goos = goos
        self.goarch = goarch
        self.tags = {goos, goarch, "gc"}
        if goos in UNIX_GOOS:
            self.tags.add("unix")
        if goos == "android":
            self.tags.add("linux")
        if goos in ("ios",):
            self.tags.add("darwin")
        if goos == "illumos":
            self.tags.add("solaris")
        if cgo:
            self.tags.add("cgo")
        for i in range(1, go_minor + 1):
            self.tags.add(f"go1.{i}")
        for t in extra_tags or []:
            self.tags.add(t)

    def describe(self) -> dict:
        return {"goos": self.goos, "goarch": self.goarch, "tags": sorted(self.tags)}

    def file_name_ok(self, name: str) -> bool:
        if not name.endswith(".go") or name.endswith("_test.go"):
            return False
        if name.startswith("_") or name.startswith("."):
            return False
        stem = name[:-3]
        parts = stem.split("_")
        if len(parts) >= 3 and parts[-2] in KNOWN_GOOS and parts[-1] in KNOWN_GOARCH:
            return self._os_ok(parts[-2]) and parts[-1] == self.goarch
        if len(parts) >= 2:
            last = parts[-1]
            if last in KNOWN_GOOS:
                return self._os_ok(last)
            if last in KNOWN_GOARCH:
                return last == self.goarch
        return True

    def _os_ok(self, os_name: str) -> bool:
        return os_name == self.goos or (os_name == "linux" and self.goos == "android") or (
            os_name == "darwin" and self.goos == "ios")

    def constraint_ok(self, source: str) -> bool:
        header = []
        for line in source.splitlines():
            s = line.strip()
            if s.startswith("package "):
                break
            header.append(s)
        go_build = [l for l in header if l.startswith("//go:build")]
        if go_build:
            return self._eval_expr(go_build[0][len("//go:build"):].strip())
        plus = [l for l in header if l.startswith("// +build")]
        for line in plus:
            terms = line[len("// +build"):].split()
            if not any(all(self._tag(t) for t in term.split(",")) for term in terms):
                return False
        return True

    def _tag(self, t: str) -> bool:
        if t.startswith("!"):
            return not self._tag(t[1:])
        return t in self.tags

    def _eval_expr(self, expr: str) -> bool:
        tokens = re.findall(r"\(|\)|!|&&|\|\||[A-Za-z0-9_.]+", expr)
        pos = [0]

        def peek():
            return tokens[pos[0]] if pos[0] < len(tokens) else None

        def take():
            t = tokens[pos[0]]
            pos[0] += 1
            return t

        def parse_or():
            v = parse_and()
            while peek() == "||":
                take()
                r = parse_and()
                v = v or r
            return v

        def parse_and():
            v = parse_not()
            while peek() == "&&":
                take()
                r = parse_not()
                v = v and r
            return v

        def parse_not():
            if peek() == "!":
                take()
                return not parse_not()
            if peek() == "(":
                take()
                v = parse_or()
                if peek() == ")":
                    take()
                return v
            t = take() if peek() is not None else ""
            return t in self.tags

        try:
            return parse_or()
        except Exception:
            return True


# --------------------------------------------------------------------------- model
@dataclass
class GoFile:
    path: Path
    package: str
    source: bytes
    tree: tree_sitter.Tree
    imports: Dict[str, str]          # alias -> import path
    import_lines: Dict[str, int]

    def text(self, node) -> str:
        return self.source[node.start_byte:node.end_byte].decode("utf-8", "replace")

    def line(self, node) -> int:
        return node.start_point[0] + 1


@dataclass
class GoParam:
    name: str
    type_text: str


@dataclass
class GoFunc:
    name: str
    package: "GoPackage"
    file: GoFile
    node: tree_sitter.Node
    recv_name: str = ""
    recv_type: str = ""          # base type name without pointer / type params
    recv_pointer: bool = False
    params: List[GoParam] = field(default_factory=list)
    results: List[GoParam] = field(default_factory=list)
    variadic: bool = False

    @property
    def qualname(self) -> str:
        if self.recv_type:
            star = "*" if self.recv_pointer else ""
            return f"{self.package.import_path}.({star}{self.recv_type}).{self.name}"
        return f"{self.package.import_path}.{self.name}"

    @property
    def short_name(self) -> str:
        if self.recv_type:
            star = "*" if self.recv_pointer else ""
            return f"({star}{self.recv_type}).{self.name}"
        return self.name

    @property
    def start_line(self) -> int:
        return self.node.start_point[0] + 1

    @property
    def end_line(self) -> int:
        return self.node.end_point[0] + 1

    @property
    def body(self):
        return self.node.child_by_field_name("body")

    def location(self) -> dict:
        return {"file": str(self.file.path), "line": self.start_line, "end_line": self.end_line}


@dataclass
class GoConst:
    name: str
    package: "GoPackage"
    file: GoFile
    node: tree_sitter.Node            # expression node (may be repeated spec expression)
    iota: int
    type_text: str
    line: int
    _value: object = None
    _state: int = 0                   # 0 = not evaluated, 1 = in progress, 2 = done


@dataclass
class GoType:
    name: str
    package: "GoPackage"
    file: GoFile
    kind: str                         # struct | interface | other
    line: int
    fields: Dict[str, str] = field(default_factory=dict)        # struct field -> type text
    field_lines: Dict[str, int] = field(default_factory=dict)
    embedded: List[str] = field(default_factory=list)           # embedded type texts
    methods: Dict[str, str] = field(default_factory=dict)       # interface method -> signature text
    underlying: str = ""


@dataclass
class GoPackage:
    import_path: str
    directory: Path
    origin: str
    module: str = ""
    version: str = ""
    name: str = ""
    files: List[GoFile] = field(default_factory=list)
    funcs: Dict[str, GoFunc] = field(default_factory=dict)               # plain functions by name
    methods: Dict[Tuple[str, str], GoFunc] = field(default_factory=dict)  # (recv type, name)
    methods_by_name: Dict[str, List[GoFunc]] = field(default_factory=dict)
    consts: Dict[str, GoConst] = field(default_factory=dict)
    types: Dict[str, GoType] = field(default_factory=dict)
    vars: Dict[str, Tuple[GoFile, int, str]] = field(default_factory=dict)  # name -> (file, line, type text)
    imports: Dict[str, int] = field(default_factory=dict)                # import path -> count

    def all_functions(self) -> List[GoFunc]:
        return list(self.funcs.values()) + list(self.methods.values())

    def provenance(self) -> str:
        if self.origin == "stdlib":
            return f"Go standard library go{self.version}"
        if self.origin == "project":
            return "project source"
        return f"{self.module}@{self.version}"


def _strip_type(t: str) -> Tuple[str, bool]:
    t = t.strip()
    ptr = False
    while t.startswith("*"):
        ptr = True
        t = t[1:]
    if "[" in t and not t.startswith("["):
        t = t[: t.index("[")]
    return t, ptr


# --------------------------------------------------------------------------- program
class GoProgram:
    """Lazy, package-aware view of a Go project and its dependencies."""

    def __init__(self, resolver, build: Optional[BuildContext] = None, log: Callable = print) -> None:
        self.resolver = resolver
        self.build = build or BuildContext()
        self.parser = make_parser()
        self.packages: Dict[str, Optional[GoPackage]] = {}
        self.log = log
        self.parse_errors: Dict[str, int] = {}

    # ------------------------------------------------------------------ loading
    def load(self, import_path: str, importer_origin: str = "project") -> Optional[GoPackage]:
        if import_path in self.packages:
            return self.packages[import_path]
        resolved = self.resolver.resolve(import_path, importer_origin) if self.resolver else None
        if resolved is None:
            self.packages[import_path] = None
            return None
        pkg = self.load_directory(resolved.directory, import_path, resolved.origin,
                                  resolved.module, resolved.version)
        return pkg

    def load_directory(self, directory: Path, import_path: str, origin: str,
                       module: str = "", version: str = "") -> Optional[GoPackage]:
        if import_path in self.packages and self.packages[import_path] is not None:
            return self.packages[import_path]
        pkg = GoPackage(import_path, Path(directory), origin, module, version)
        try:
            names = sorted(p.name for p in Path(directory).iterdir() if p.is_file())
        except OSError:
            self.packages[import_path] = None
            return None
        for name in names:
            if not self.build.file_name_ok(name):
                continue
            path = Path(directory) / name
            try:
                src = path.read_bytes()
            except OSError:
                continue
            text = src.decode("utf-8", "replace")
            if not self.build.constraint_ok(text):
                continue
            tree = self.parser.parse(src)
            pkg_name = self._package_name(tree, src)
            if pkg_name is None or pkg_name.endswith("_test") or pkg_name == "documentation":
                continue
            if pkg.name and pkg_name != pkg.name:
                # e.g. stray "package main" generator files in a library dir
                continue
            pkg.name = pkg_name
            if tree.root_node.has_error:
                self.parse_errors[str(path)] = 1
            gofile = GoFile(path, pkg_name, src, tree, {}, {})
            pkg.files.append(gofile)
            self._index_file(pkg, gofile)
        self.packages[import_path] = pkg if pkg.files else None
        return self.packages[import_path]

    @staticmethod
    def _package_name(tree, src: bytes) -> Optional[str]:
        for child in tree.root_node.children:
            if child.type == "package_clause":
                for c in child.children:
                    if c.type == "package_identifier":
                        return src[c.start_byte:c.end_byte].decode()
        return None

    # ------------------------------------------------------------------ indexing
    def _index_file(self, pkg: GoPackage, f: GoFile) -> None:
        for node in f.tree.root_node.children:
            t = node.type
            if t == "import_declaration":
                self._index_imports(pkg, f, node)
            elif t == "function_declaration":
                fn = self._make_func(pkg, f, node, method=False)
                if fn and fn.name not in pkg.funcs:
                    pkg.funcs[fn.name] = fn
            elif t == "method_declaration":
                fn = self._make_func(pkg, f, node, method=True)
                if fn:
                    key = (fn.recv_type, fn.name)
                    if key not in pkg.methods:
                        pkg.methods[key] = fn
                        pkg.methods_by_name.setdefault(fn.name, []).append(fn)
            elif t == "const_declaration":
                self._index_consts(pkg, f, node)
            elif t == "type_declaration":
                self._index_types(pkg, f, node)
            elif t == "var_declaration":
                for spec in node.children:
                    if spec.type == "var_spec":
                        names = [c for c in spec.children if c.type == "identifier"]
                        tnode = spec.child_by_field_name("type")
                        ttext = f.text(tnode) if tnode else ""
                        if not ttext:
                            vnode = spec.child_by_field_name("value")
                            vals = [c for c in vnode.children if c.is_named] if vnode is not None else []
                            if len(vals) == 1:
                                v0 = vals[0]
                                if v0.type == "unary_expression" and f.text(v0).startswith("&"):
                                    inner = v0.child_by_field_name("operand")
                                    if inner is not None and inner.type == "composite_literal":
                                        ty = inner.child_by_field_name("type")
                                        ttext = "*" + f.text(ty) if ty is not None else ""
                                elif v0.type == "composite_literal":
                                    ty = v0.child_by_field_name("type")
                                    ttext = f.text(ty) if ty is not None else ""
                        for n in names:
                            pkg.vars[f.text(n)] = (f, f.line(n), ttext)

    def _index_imports(self, pkg: GoPackage, f: GoFile, node) -> None:
        specs = []
        for c in node.children:
            if c.type == "import_spec":
                specs.append(c)
            elif c.type == "import_spec_list":
                specs.extend(x for x in c.children if x.type == "import_spec")
        for spec in specs:
            path_node = spec.child_by_field_name("path")
            if path_node is None:
                continue
            ipath = f.text(path_node).strip('"`')
            name_node = spec.child_by_field_name("name")
            if name_node is not None:
                alias = f.text(name_node)
            else:
                alias = ipath.rsplit("/", 1)[-1]
                # conventional major-version suffix: example.com/foo/v3 -> foo
                if re.fullmatch(r"v\d+", alias) and "/" in ipath:
                    alias = ipath.rsplit("/", 2)[-2]
                alias = alias.replace("-", "_").replace(".", "_")
                if alias.startswith("go_"):
                    alias = alias[3:]
            f.imports[alias] = ipath
            f.import_lines[ipath] = f.line(spec)
            pkg.imports[ipath] = pkg.imports.get(ipath, 0) + 1

    def _params(self, f: GoFile, plist) -> Tuple[List[GoParam], bool]:
        out: List[GoParam] = []
        variadic = False
        if plist is None:
            return out, variadic
        if plist.type != "parameter_list":
            # single unnamed result type
            return [GoParam("", f.text(plist))], False
        for p in plist.children:
            if p.type not in ("parameter_declaration", "variadic_parameter_declaration"):
                continue
            tnode = p.child_by_field_name("type")
            ttext = f.text(tnode) if tnode else ""
            if p.type == "variadic_parameter_declaration":
                variadic = True
                ttext = "..." + ttext
            names = [c for c in p.children if c.type == "identifier"]
            if names:
                for n in names:
                    out.append(GoParam(f.text(n), ttext))
            else:
                out.append(GoParam("", ttext))
        return out, variadic

    def _make_func(self, pkg: GoPackage, f: GoFile, node, method: bool) -> Optional[GoFunc]:
        name_node = node.child_by_field_name("name")
        if name_node is None:
            return None
        fn = GoFunc(f.text(name_node), pkg, f, node)
        fn.params, fn.variadic = self._params(f, node.child_by_field_name("parameters"))
        fn.results, _ = self._params(f, node.child_by_field_name("result"))
        if method:
            recv = node.child_by_field_name("receiver")
            if recv is not None:
                for p in recv.children:
                    if p.type == "parameter_declaration":
                        tnode = p.child_by_field_name("type")
                        rt, ptr = _strip_type(f.text(tnode)) if tnode else ("", False)
                        fn.recv_type, fn.recv_pointer = rt, ptr
                        names = [c for c in p.children if c.type == "identifier"]
                        fn.recv_name = f.text(names[0]) if names else ""
        return fn

    def _index_consts(self, pkg: GoPackage, f: GoFile, node) -> None:
        iota = 0
        prev_values = None
        prev_type = ""
        for spec in node.children:
            if spec.type != "const_spec":
                continue
            names = [c for c in spec.children if c.type == "identifier"]
            tnode = spec.child_by_field_name("type")
            vnode = spec.child_by_field_name("value")
            if vnode is not None:
                values = [c for c in vnode.children if c.is_named]
                prev_values = values
                prev_type = f.text(tnode) if tnode else ""
            else:
                values = prev_values or []
            ttext = f.text(tnode) if tnode else (prev_type if vnode is None else "")
            for i, n in enumerate(names):
                expr = values[i] if i < len(values) else None
                cname = f.text(n)
                if cname == "_" or expr is None:
                    continue
                if cname not in pkg.consts:
                    pkg.consts[cname] = GoConst(cname, pkg, f, expr, iota, ttext, f.line(n))
            iota += 1

    def _index_types(self, pkg: GoPackage, f: GoFile, node) -> None:
        for spec in node.children:
            if spec.type not in ("type_spec", "type_alias"):
                continue
            name_node = spec.child_by_field_name("name")
            tnode = spec.child_by_field_name("type")
            if name_node is None or tnode is None:
                continue
            gt = GoType(f.text(name_node), pkg, f, "other", f.line(name_node), underlying=f.text(tnode))
            if tnode.type == "struct_type":
                gt.kind = "struct"
                for fl in tnode.children:
                    if fl.type != "field_declaration_list":
                        continue
                    for decl in fl.children:
                        if decl.type != "field_declaration":
                            continue
                        ftype = decl.child_by_field_name("type")
                        names = [c for c in decl.children if c.type == "field_identifier"]
                        if names:
                            for n in names:
                                gt.fields[f.text(n)] = f.text(ftype) if ftype else ""
                                gt.field_lines[f.text(n)] = f.line(n)
                        elif ftype is not None:
                            emb = f.text(ftype)
                            gt.embedded.append(emb)
                            base, _ = _strip_type(emb)
                            gt.fields[base.rsplit(".", 1)[-1]] = emb
                            gt.field_lines[base.rsplit(".", 1)[-1]] = f.line(ftype)
            elif tnode.type == "interface_type":
                gt.kind = "interface"
                for el in tnode.children:
                    if el.type in ("method_spec", "method_elem"):
                        mname = el.child_by_field_name("name")
                        if mname is not None:
                            gt.methods[f.text(mname)] = f.text(el)
                    elif el.type in ("constraint_elem", "type_elem", "interface_type_name",
                                     "qualified_type", "type_identifier"):
                        gt.embedded.append(f.text(el))
            if gt.name not in pkg.types:
                pkg.types[gt.name] = gt

    # ------------------------------------------------------------------ queries
    def qualified_package(self, f: GoFile, alias: str, importer: GoPackage) -> Optional[GoPackage]:
        ipath = f.imports.get(alias)
        if ipath is None:
            return None
        return self.load(ipath, importer.origin)

    def lookup_type(self, pkg: GoPackage, f: Optional[GoFile], type_text: str) -> Optional[GoType]:
        base, _ = _strip_type(type_text)
        if "." in base:
            alias, name = base.split(".", 1)
            if f is None:
                return None
            other = self.qualified_package(f, alias, pkg)
            return other.types.get(name) if other else None
        return pkg.types.get(base)

    def interface_embeds(self, pkg: GoPackage, f: Optional[GoFile], type_text: str, target: str,
                         depth: int = 0) -> bool:
        """True if interface type `type_text` (as written in f) embeds `target` (as written in f)."""
        if depth > 6:
            return False
        if _norm_type(type_text) == _norm_type(target):
            return True
        gt = self.lookup_type(pkg, f, type_text)
        if gt is None or gt.kind != "interface":
            return False
        for emb in gt.embedded:
            if _norm_type(emb) == _norm_type(target):
                return True
            if self.interface_embeds(gt.package, gt.file, emb, target, depth + 1):
                return True
        return False

    def const_value(self, pkg: GoPackage, name: str):
        c = pkg.consts.get(name)
        if c is None:
            return None
        if c._state == 2:
            return c._value
        if c._state == 1:
            return None  # cycle
        c._state = 1
        try:
            c._value = ConstEvaluator(self, pkg, c.file, c.iota).eval(c.node)
        except Exception:
            c._value = None
        c._state = 2
        return c._value

    def resolve_const_ref(self, pkg: GoPackage, f: GoFile, text: str):
        """Resolve `Name` or `alias.Name` to (value, GoConst) if it is a constant."""
        if "." in text:
            alias, name = text.split(".", 1)
            other = self.qualified_package(f, alias, pkg)
            if other is None or name not in other.consts:
                return None, None
            return self.const_value(other, name), other.consts[name]
        if text in pkg.consts:
            return self.const_value(pkg, text), pkg.consts[text]
        return None, None


def _norm_type(t: str) -> str:
    base, _ = _strip_type(t)
    return base


# --------------------------------------------------------------------------- constants
def parse_go_int(text: str) -> Optional[int]:
    t = text.replace("_", "").lower()
    try:
        if t.startswith("0x"):
            return int(t, 16)
        if t.startswith("0b"):
            return int(t, 2)
        if t.startswith("0o"):
            return int(t[2:], 8)
        if len(t) > 1 and t.startswith("0") and t.isdigit():
            return int(t, 8)
        return int(t, 10)
    except ValueError:
        return None


_ESCAPES = {"a": 7, "b": 8, "f": 12, "n": 10, "r": 13, "t": 9, "v": 11, "\\": 92, "'": 39, '"': 34}


def parse_go_rune(text: str) -> Optional[int]:
    body = text[1:-1]
    if not body:
        return None
    if body[0] != "\\":
        return ord(body[0])
    if len(body) >= 2 and body[1] in _ESCAPES:
        return _ESCAPES[body[1]]
    if body[1] == "x":
        return int(body[2:4], 16)
    if body[1] in "uU":
        return int(body[2:], 16)
    if body[1].isdigit():
        return int(body[1:4], 8)
    return None


INT_TYPES = {
    "int", "int8", "int16", "int32", "int64", "uint", "uint8", "uint16", "uint32", "uint64",
    "uintptr", "byte", "rune",
}


class ConstEvaluator:
    """Evaluates Go constant expressions to Python ints/bools/strings (None if unknown)."""

    def __init__(self, program: GoProgram, pkg: GoPackage, f: GoFile, iota: int) -> None:
        self.program = program
        self.pkg = pkg
        self.f = f
        self.iota = iota

    def eval(self, node):
        t = node.type
        f = self.f
        if t == "int_literal":
            return parse_go_int(f.text(node))
        if t == "rune_literal":
            return parse_go_rune(f.text(node))
        if t in ("interpreted_string_literal", "raw_string_literal"):
            return f.text(node)[1:-1]
        if t == "iota":
            return self.iota
        if t == "true":
            return True
        if t == "false":
            return False
        if t == "parenthesized_expression":
            inner = [c for c in node.children if c.is_named]
            return self.eval(inner[0]) if inner else None
        if t == "identifier":
            name = f.text(node)
            if name in self.pkg.consts:
                return self.program.const_value(self.pkg, name)
            return None
        if t == "selector_expression":
            operand = node.child_by_field_name("operand")
            fld = node.child_by_field_name("field")
            if operand is not None and operand.type == "identifier" and fld is not None:
                other = self.program.qualified_package(f, f.text(operand), self.pkg)
                if other is not None:
                    return self.program.const_value(other, f.text(fld))
            return None
        if t == "unary_expression":
            op = f.text(node.child_by_field_name("operator"))
            v = self.eval(node.child_by_field_name("operand"))
            if v is None:
                return None
            if op == "-":
                return -v
            if op == "+":
                return v
            if op == "^" and isinstance(v, int):
                return ~v
            if op == "!" and isinstance(v, bool):
                return not v
            return None
        if t == "binary_expression":
            op = f.text(node.child_by_field_name("operator"))
            a = self.eval(node.child_by_field_name("left"))
            b = self.eval(node.child_by_field_name("right"))
            if a is None or b is None:
                return None
            return apply_binop(op, a, b)
        if t in ("call_expression", "type_conversion_expression"):
            fn = node.child_by_field_name("function") or node.child_by_field_name("type")
            args = node.child_by_field_name("arguments")
            argv = [c for c in args.children if c.is_named] if args is not None else []
            if t == "type_conversion_expression":
                argv = [node.child_by_field_name("operand")]
            fname = f.text(fn) if fn is not None else ""
            if fname == "len" and argv:
                v = self.eval(argv[0])
                return len(v) if isinstance(v, str) else None
            if len(argv) == 1:
                base = fname.rsplit(".", 1)[-1]
                is_type = base in INT_TYPES or base in self.pkg.types or "." in fname or base in ("string", "float64", "float32")
                if is_type:
                    v = self.eval(argv[0])
                    return v
            return None
        return None


def apply_binop(op: str, a, b):
    try:
        if op == "+":
            return a + b
        if op == "-":
            return a - b
        if op == "*":
            return a * b
        if op == "/":
            if isinstance(a, int) and isinstance(b, int):
                q = abs(a) // abs(b)
                return q if (a >= 0) == (b >= 0) else -q
            return a / b
        if op == "%":
            if isinstance(a, int) and isinstance(b, int):
                r = abs(a) % abs(b)
                return r if a >= 0 else -r
            return None
        if op == "<<":
            return a << b
        if op == ">>":
            return a >> b
        if op == "&":
            return a & b
        if op == "|":
            return a | b
        if op == "^":
            return a ^ b
        if op == "&^":
            return a & ~b
        if op == "==":
            return a == b
        if op == "!=":
            return a != b
        if op == "<":
            return a < b
        if op == "<=":
            return a <= b
        if op == ">":
            return a > b
        if op == ">=":
            return a >= b
        if op == "&&":
            return bool(a) and bool(b)
        if op == "||":
            return bool(a) or bool(b)
    except Exception:
        return None
    return None
