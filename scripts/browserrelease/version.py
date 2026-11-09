"""Single central browser-extension version document with strict validation."""

from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path

from .errors import ReleaseError

METADATA_RELATIVE = "browser-extension/release-version.json"
ALLOWED_MEMBERS = frozenset({"version"})
MAX_METADATA_BYTES = 512
MAX_COMPONENTS = 4
MAX_COMPONENT = 65535
COMPONENT = re.compile(r"(?:0|[1-9][0-9]{0,4})")


def validate_version(value: object) -> str:
    """Validate a browser-compatible version: 1-4 decimal uint16 components.

    Leading zeros are refused because store tooling treats them ambiguously,
    and every component must fit an unsigned 16-bit integer. This function
    never rewrites or "bumps" the version; it only accepts or refuses.
    """
    if not isinstance(value, str) or not value:
        raise ReleaseError("release version must be a non-empty string")
    parts = value.split(".")
    if not 1 <= len(parts) <= MAX_COMPONENTS:
        raise ReleaseError("release version must have 1-4 dot-separated components")
    for part in parts:
        if not COMPONENT.fullmatch(part):
            raise ReleaseError(
                "release version components must be decimal without leading zeros"
            )
        if int(part) > MAX_COMPONENT:
            raise ReleaseError("release version components must be 0-65535")
    return value


def metadata_bytes(root: Path) -> bytes:
    """Read the central version document as bytes, refusing unsafe files."""
    path = Path(root) / METADATA_RELATIVE
    try:
        info = path.lstat()
    except OSError:
        raise ReleaseError("release version metadata is missing") from None
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ReleaseError("release version metadata is not a regular file")
    if info.st_size > MAX_METADATA_BYTES:
        raise ReleaseError("release version metadata is too large")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise ReleaseError("release version metadata cannot be opened") from None
    try:
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            opened = os.fstat(handle.fileno())
            if not stat.S_ISREG(opened.st_mode):
                raise ReleaseError("release version metadata is not a regular file")
            if opened.st_size > MAX_METADATA_BYTES:
                raise ReleaseError("release version metadata is too large")
            data = handle.read(MAX_METADATA_BYTES + 1)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(data) > MAX_METADATA_BYTES:
        raise ReleaseError("release version metadata is too large")
    return data


def load_release_version(root: Path) -> str:
    """Return the single central version; unknown members fail closed."""
    try:
        document = json.loads(metadata_bytes(root).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ReleaseError("release version metadata is not valid UTF-8 JSON") from None
    if not isinstance(document, dict):
        raise ReleaseError("release version metadata must be a JSON object")
    if set(document) != ALLOWED_MEMBERS:
        raise ReleaseError("release version metadata has unsupported members")
    return validate_version(document["version"])
