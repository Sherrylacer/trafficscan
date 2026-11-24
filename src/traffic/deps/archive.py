"""
Safe download / extraction helpers used by dependency resolvers.

Downloaded archives are untrusted data: every member path is checked so that
nothing can be written outside the destination directory (zip-slip / tar
path traversal), symlinks and device files inside tarballs are skipped, and
nothing that is extracted is ever executed by LLMSCAN.
"""
import os
import shutil
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path
from typing import List, Optional


class DownloadError(RuntimeError):
    pass


def _looks_valid(path: Path, kind: str) -> bool:
    try:
        with open(path, "rb") as fh:
            head = fh.read(4)
    except OSError:
        return False
    if kind == "zip":
        return head.startswith(b"PK") and zipfile.is_zipfile(path)
    if kind == "tar.gz":
        return head.startswith(b"\x1f\x8b")
    return len(head) > 0


def download(urls: List[str], dest_file: Path, timeout: int = 120, kind: str = "") -> str:
    """Download the first URL that succeeds (and whose content has the expected archive
    signature) into dest_file. Returns the URL used."""
    dest_file.parent.mkdir(parents=True, exist_ok=True)
    errors = []
    for url in urls:
        tmp = dest_file.with_suffix(dest_file.suffix + ".part")
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "LLMSCAN-trafficscan"})
            with urllib.request.urlopen(req, timeout=timeout) as resp, open(tmp, "wb") as out:
                shutil.copyfileobj(resp, out, length=1 << 20)
            if kind and not _looks_valid(tmp, kind):
                raise DownloadError("response is not a valid " + kind)
            tmp.replace(dest_file)
            return url
        except Exception as exc:  # network errors are expected (mirrors, offline)
            errors.append(f"{url}: {exc}")
            if tmp.exists():
                tmp.unlink()
    raise DownloadError("; ".join(errors))


def _inside(base: Path, target: Path) -> bool:
    try:
        target.resolve().relative_to(base.resolve())
        return True
    except ValueError:
        return False


def safe_extract_zip(archive: Path, dest: Path, strip_prefix: Optional[str] = None) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive) as zf:
        for info in zf.infolist():
            name = info.filename
            if strip_prefix is not None:
                if not name.startswith(strip_prefix):
                    continue
                name = name[len(strip_prefix):]
            if not name or name.endswith("/"):
                continue
            target = dest / name
            if not _inside(dest, target):
                raise DownloadError(f"unsafe path in archive: {info.filename}")
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, open(target, "wb") as out:
                shutil.copyfileobj(src, out)


def safe_extract_tar(archive: Path, dest: Path, member_prefix_filter: Optional[List[str]] = None) -> None:
    """Extract regular files (and dirs) only. Optionally keep only members under given prefixes."""
    dest.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive, "r:*") as tf:
        for member in tf:
            if not (member.isreg() or member.isdir()):
                continue
            if member_prefix_filter and not any(member.name.startswith(p) for p in member_prefix_filter):
                continue
            target = dest / member.name
            if not _inside(dest, target):
                raise DownloadError(f"unsafe path in archive: {member.name}")
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            src = tf.extractfile(member)
            if src is None:
                continue
            with src, open(target, "wb") as out:
                shutil.copyfileobj(src, out)


def atomic_dir(final_dir: Path) -> Path:
    """Create a temporary sibling directory to extract into; caller renames it to final_dir."""
    final_dir.parent.mkdir(parents=True, exist_ok=True)
    return Path(tempfile.mkdtemp(prefix=final_dir.name + ".", dir=str(final_dir.parent)))


def finalize_dir(tmp_dir: Path, final_dir: Path) -> None:
    if final_dir.exists():
        shutil.rmtree(tmp_dir, ignore_errors=True)
        return
    os.replace(tmp_dir, final_dir)
