"""Run the real browser-extension build with an explicit argv list."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from . import allowlist, source
from .errors import ReleaseError

BUILD_DIRECTORY = "browser-extension"
BUILD_SCRIPT = "build.js"
TIMEOUT_SECONDS = 120


def _path() -> str:
    return os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin")


def check_build_paths(root: Path, product: str) -> Path:
    """Refuse a symlinked or non-directory build path before writing anything."""
    if product not in allowlist.PRODUCTS:
        raise ReleaseError("unsupported product")
    extension = Path(root).resolve() / BUILD_DIRECTORY
    if extension.is_symlink() or not extension.is_dir():
        raise ReleaseError("extension source directory is not a real directory")
    for path in (extension / "dist", extension / "dist" / product):
        if path.is_symlink():
            raise ReleaseError("build output path is a symlink")
        if path.exists() and not path.is_dir():
            raise ReleaseError("build output path is not a directory")
    return extension / "dist" / product


def verify_build_paths(root: Path, product: str) -> Path:
    """Re-check the build path after node ran and confirm it stayed inside."""
    output = check_build_paths(root, product)
    if not output.is_dir():
        raise ReleaseError("build output directory is missing")
    expected = Path(root).resolve() / BUILD_DIRECTORY / "dist" / product
    if Path(os.path.realpath(output)) != expected:
        raise ReleaseError("build output path escapes the extension directory")
    return output


def run_build(root: Path, product: str) -> None:
    """Invoke `node build.js <product>`; no shell, stdin, profile or credentials."""
    if product not in allowlist.PRODUCTS:
        raise ReleaseError("unsupported product")
    # A committed symlink keeps the worktree clean, so the status check cannot
    # see it. Refuse a non-blob mode for every build input before node reads it.
    source.require_regular_source_blobs(root)
    command = ["node", BUILD_SCRIPT, product]
    environment = {"PATH": _path(), "LC_ALL": "C"}
    try:
        completed = subprocess.run(
            command,
            cwd=(Path(root) / BUILD_DIRECTORY).resolve(),
            shell=False,
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=TIMEOUT_SECONDS,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise ReleaseError("node build.js could not be run") from None
    if completed.returncode != 0:
        raise ReleaseError("node build.js failed")
