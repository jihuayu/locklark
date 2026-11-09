"""Deterministic ZIP construction: stored entries, fixed time, fixed mode."""

from __future__ import annotations

import io
import stat
import zipfile

from .errors import ReleaseError

ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
ZIP_FILE_MODE = 0o644
ZIP_FORMAT = "ZIP_STORED"
ZIP_TIMESTAMP_TEXT = "1980-01-01T00:00:00Z"
ZIP_MODE_TEXT = "0644"


def zip_info(name: str) -> zipfile.ZipInfo:
    """Return one fixed ZIP entry header for a product file name."""
    info = zipfile.ZipInfo(name, ZIP_TIMESTAMP)
    info.compress_type = zipfile.ZIP_STORED
    info.create_system = 3
    info.create_version = 20
    info.extract_version = 20
    info.external_attr = (stat.S_IFREG | ZIP_FILE_MODE) << 16
    info.internal_attr = 0
    info.flag_bits = 0
    info.extra = b""
    info.comment = b""
    return info


def build_zip(entries: tuple[str, ...], files: dict[str, bytes]) -> bytes:
    """Build the archive in the fixed entry order of the product allowlist."""
    if set(entries) != set(files) or len(entries) != len(files):
        raise ReleaseError("archive entries and product files do not match")
    buffer = io.BytesIO()
    with zipfile.ZipFile(
        buffer, "w", compression=zipfile.ZIP_STORED, allowZip64=False
    ) as archive:
        for name in entries:
            archive.writestr(zip_info(name), files[name])
    return buffer.getvalue()
