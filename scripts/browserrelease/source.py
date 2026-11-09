"""Resolve the 40-hex source commit and refuse an unpinned source tree."""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

from . import allowlist
from .errors import ReleaseError

COMMIT = re.compile(r"[0-9a-f]{40}")
BUILD_SCRIPT_RELATIVE = "browser-extension/build.js"
VERSION_METADATA_RELATIVE = "browser-extension/release-version.json"
# Committed regular blobs only. A committed symlink is mode 120000 and passes
# `git status`, so the worktree-clean check alone cannot see it.
REGULAR_BLOB_MODES = frozenset({"100644", "100755"})
EXTENSION_TREE = "browser-extension"


def _path() -> str:
    return os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin")


def _git(root: Path, args: list[str], timeout: int = 60):
    environment = {
        "PATH": _path(),
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_NOSYSTEM": "1",
        "LC_ALL": "C",
    }
    try:
        return subprocess.run(
            ["git", *args],
            cwd=Path(root),
            shell=False,
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise ReleaseError("source tree state could not be verified") from None


def _source_inputs() -> tuple[str, ...]:
    """Return every committed file the build reads, relative to the repo root."""
    names = [
        *allowlist.BASE_FILES,
        *allowlist.PRODUCT_EXTRA_FILES["safari"],
    ]
    inputs = [BUILD_SCRIPT_RELATIVE, VERSION_METADATA_RELATIVE]
    inputs.extend(f"{EXTENSION_TREE}/{name}" for name in names)
    return tuple(dict.fromkeys(inputs))


def require_clean_source(root: Path) -> None:
    """Refuse unless the whole repository is committed and nothing untracked.

    `git status --porcelain --untracked-files=all` reports every tracked change
    and every untracked path, including the version metadata, build script,
    static product files and this release module. Ignored build output such as
    `browser-extension/dist` is not a source input. Neither the status output
    nor any file content is ever printed: only this fixed refusal is exposed.
    """
    completed = _git(root, ["status", "--porcelain", "--untracked-files=all"])
    if completed.returncode != 0:
        raise ReleaseError("source tree state could not be verified")
    if completed.stdout.strip():
        raise ReleaseError(
            "source tree has uncommitted or untracked changes; "
            "refusing to pin a commit"
        )


def require_regular_source_blobs(root: Path) -> None:
    """Refuse unless every input is a committed regular blob at HEAD.

    The worktree can be clean while a committed symlink (mode 120000) still
    points a product file, the version document or the build script at a file
    outside the repository. Only committed blob modes 100644/100755 are pinned;
    gitlinks and anything else are refused. The refusal never prints a path.
    """
    completed = _git(
        root, ["ls-tree", "-r", "-z", "HEAD", "--", EXTENSION_TREE]
    )
    if completed.returncode != 0:
        raise ReleaseError("source tree state could not be verified")
    modes: dict[str, tuple[str, str]] = {}
    for record in completed.stdout.split(b"\x00"):
        if not record:
            continue
        metadata, separator, raw_path = record.partition(b"\t")
        if not separator:
            raise ReleaseError("source tree state could not be verified")
        parts = metadata.split(b" ")
        if len(parts) != 3:
            raise ReleaseError("source tree state could not be verified")
        modes[raw_path.decode("utf-8", "replace")] = (
            parts[0].decode("ascii", "replace"),
            parts[1].decode("ascii", "replace"),
        )
    for relative in _source_inputs():
        entry = modes.get(relative)
        if entry is None:
            raise ReleaseError("a required source input is not committed")
        mode, kind = entry
        if kind != "blob" or mode not in REGULAR_BLOB_MODES:
            raise ReleaseError(
                "a required source input is not a committed regular file"
            )


def source_commit(root: Path) -> str:
    """Return HEAD of a clean worktree; never guess or synthesize a commit."""
    require_clean_source(root)
    require_regular_source_blobs(root)
    completed = _git(root, ["rev-parse", "--verify", "HEAD"])
    output = completed.stdout.decode("ascii", "replace").strip()
    if completed.returncode != 0 or not COMMIT.fullmatch(output):
        raise ReleaseError("source commit is not a resolved 40-hex commit")
    return output
