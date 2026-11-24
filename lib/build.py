import os

from tree_sitter import Language, Parser
from pathlib import Path

cwd = Path(__file__).resolve().parent.absolute()

# clone tree-sitter if necessary
if not (cwd / "vendor/tree-sitter-c/grammar.js").exists():
    os.system(
        f'git clone https://github.com/tree-sitter/tree-sitter-c.git {cwd / "vendor/tree-sitter-c"}'
    )

if not (cwd / "vendor/tree-sitter-cpp/grammar.js").exists():
    os.system(
        f'git clone https://github.com/tree-sitter/tree-sitter-cpp.git {cwd / "vendor/tree-sitter-cpp"}'
    )

if not (cwd / "vendor/tree-sitter-java/grammar.js").exists():
    os.system(
        f'git clone https://github.com/tree-sitter/tree-sitter-java.git {cwd / "vendor/tree-sitter-java"}'
    )

if not (cwd / "vendor/tree-sitter-python/grammar.js").exists():
    os.system(
        f'git clone https://github.com/tree-sitter/tree-sitter-python.git {cwd / "vendor/tree-sitter-python"}'
    )

if not (cwd / "vendor/tree-sitter-go/grammar.js").exists():
    # Pinned: py-tree-sitter<0.22 can only load grammars generated with ABI <= 14.
    # tree-sitter-go v0.21.0 is ABI 14 and supports generics.
    os.system(
        f'git clone --depth 1 --branch v0.21.0 https://github.com/tree-sitter/tree-sitter-go.git {cwd / "vendor/tree-sitter-go"}'
    )

GRAMMARS = [
    cwd / "vendor/tree-sitter-c",
    cwd / "vendor/tree-sitter-cpp",
    cwd / "vendor/tree-sitter-java",
    cwd / "vendor/tree-sitter-python",
    cwd / "vendor/tree-sitter-go",
]
OUTPUT = cwd / "build/my-languages.so"


def build_with_compiler() -> None:
    """Fallback: compile and link the grammars directly.

    Recent setuptools releases on macOS link without -shared, which makes
    Language.build_library fail with an undefined `_main`. Building the
    shared object by hand is equivalent.
    """
    import subprocess
    import tempfile

    objs = []
    with tempfile.TemporaryDirectory() as tmp:
        for g in GRAMMARS:
            src = g / "src"
            for f in sorted(src.iterdir()):
                if f.suffix not in (".c", ".cc"):
                    continue
                obj = Path(tmp) / f"{g.name}-{f.stem}.o"
                compiler = "c++" if f.suffix == ".cc" else "cc"
                std = ["-std=c++14"] if f.suffix == ".cc" else ["-std=c11"]
                subprocess.check_call(
                    [compiler, "-c", "-fPIC", "-O2", *std, "-I", str(src), str(f), "-o", str(obj)]
                )
                objs.append(str(obj))
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        subprocess.check_call(["c++", "-shared", *objs, "-o", str(OUTPUT)])


try:
    Language.build_library(
        # Store the library in the `build` directory
        str(OUTPUT),
        # Include one or more languages
        [str(g) for g in GRAMMARS],
    )
except Exception as exc:  # noqa: BLE001
    print(f"Language.build_library failed ({exc.__class__.__name__}); compiling directly")
    build_with_compiler()
print(f"built {OUTPUT}")
