"""Read exactly the allowlisted product files from real build output."""

from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path

from . import allowlist
from .errors import ReleaseError
from .manifestcheck import validate_manifest

MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024

REMOTE_ATTRIBUTE = re.compile(r"""(?is)\b(?:src|href)\s*=\s*["']\s*(?:https?:)?//""")
REMOTE_IMPORT = re.compile(r"""(?is)@import\s+(?:url\(\s*)?["']?\s*(?:https?:)?//""")
LOCAL_SCRIPT = re.compile(r"""(?is)<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']""")
SOURCE_MAP = re.compile(r"(?i)sourcemappingurl\s*=")
EVAL = re.compile(r"(?<![A-Za-z0-9_$])eval\s*\(")
NEW_FUNCTION = re.compile(r"\bnew\s+Function\s*\(")


def _fail(message: str) -> None:
    raise ReleaseError(message)


def read_regular_file(path: Path, label: str, limit: int = MAX_FILE_BYTES) -> bytes:
    """Read a small regular file without following symlinks."""
    try:
        before = path.lstat()
    except OSError:
        _fail(f"{label} is missing")
    if stat.S_ISLNK(before.st_mode):
        _fail(f"{label} is a symlink")
    if not stat.S_ISREG(before.st_mode):
        _fail(f"{label} is not a regular file")
    if before.st_size > limit:
        _fail(f"{label} exceeds the size limit")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        _fail(f"{label} cannot be opened safely")
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
            or opened.st_size > limit
        ):
            _fail(f"{label} changed while being read")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            data = handle.read(limit + 1)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(data) > limit:
        _fail(f"{label} exceeds the size limit")
    return data


def scan_public_bundle(files: dict[str, bytes]) -> None:
    """Refuse source maps, remote assets, dynamic code and non-public bytes."""
    for name, data in files.items():
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            _fail(f"{name} is not UTF-8 public product source")
        if SOURCE_MAP.search(text):
            _fail(f"{name} references a source map")
        if name.endswith((".html", ".css")):
            if REMOTE_ATTRIBUTE.search(text) or REMOTE_IMPORT.search(text):
                _fail(f"{name} references a remote asset")
        if name.endswith(".html"):
            allowed_scripts = allowlist.BASE_FILES + allowlist.PRODUCT_EXTRA_FILES["safari"]
            for source in LOCAL_SCRIPT.findall(text):
                if source not in allowed_scripts:
                    _fail(f"{name} references a non-allowlisted script")
        if name.endswith(".js"):
            if EVAL.search(text):
                _fail(f"{name} contains dynamic eval")
            if NEW_FUNCTION.search(text):
                _fail(f"{name} contains dynamic Function construction")


def read_bundle(build_dir: Path, product: str, version: str) -> dict[str, bytes]:
    """Read the generated directory; anything outside the allowlist refuses."""
    entries = allowlist.entries_for(product)
    try:
        directory = Path(build_dir).lstat()
    except OSError:
        _fail("build output directory is missing")
    if stat.S_ISLNK(directory.st_mode) or not stat.S_ISDIR(directory.st_mode):
        _fail("build output directory is not a trusted directory")
    try:
        names = {entry.name for entry in Path(build_dir).iterdir()}
    except OSError:
        _fail("build output directory cannot be listed")
    if names != set(entries):
        _fail("build output does not match the exact product allowlist")

    files: dict[str, bytes] = {}
    total = 0
    for name in entries:
        files[name] = read_regular_file(Path(build_dir) / name, f"build output {name}")
        total += len(files[name])
        if total > MAX_TOTAL_BYTES:
            _fail("build output exceeds the bundle size limit")
    try:
        manifest = json.loads(files[allowlist.MANIFEST_FILE].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        _fail("generated manifest is not valid UTF-8 JSON")
    validate_manifest(manifest, product, version)
    scan_public_bundle(files)
    return files
