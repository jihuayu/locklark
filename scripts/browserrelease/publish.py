"""Per-name, no-overwrite publication of a ZIP/receipt pair.

This is deliberately not pair-atomic. Each name is created by linking a
fsynced private temporary file into place, so an existing file is never
replaced. A crash between the two links can leave the ZIP without its receipt;
`browserrelease.reuse` completes that state only when the ZIP matches the
current preparation byte for byte, and otherwise refuses.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from .errors import ReleaseError

FILE_MODE = 0o644


class PublicationRace(Exception):
    """Another writer created the target name first; the caller re-checks."""


def write_private_temp(directory: Path, name: str, data: bytes) -> Path:
    """Write data to a fresh 0600 temporary file and fsync it."""
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{name}.", suffix=".tmp", dir=directory
    )
    path = Path(temporary)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(path, FILE_MODE)
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    return path


def link_nonreplace(temporary: Path, final: Path) -> None:
    """Create the final name only if it does not already exist."""
    try:
        os.link(temporary, final)
    except FileExistsError:
        raise PublicationRace() from None
    except OSError:
        raise ReleaseError("output artifact could not be published atomically") from None


def fsync_directory(directory: Path) -> None:
    descriptor = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def publish_one(output_dir: Path, name: str, payload: bytes) -> None:
    """Link one payload into place without ever replacing an existing name."""
    output_dir = Path(output_dir)
    temporary = write_private_temp(output_dir, name, payload)
    try:
        link_nonreplace(temporary, output_dir / name)
        fsync_directory(output_dir)
    finally:
        temporary.unlink(missing_ok=True)


def publish_new(
    output_dir: Path,
    artifact_name: str,
    artifact_bytes: bytes,
    receipt_name: str,
    receipt_payload: bytes,
) -> None:
    """Publish the ZIP first and the receipt last (not pair-atomic)."""
    publish_one(output_dir, artifact_name, artifact_bytes)
    publish_one(output_dir, receipt_name, receipt_payload)
