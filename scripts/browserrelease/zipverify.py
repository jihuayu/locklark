"""Verify a preparation ZIP without extracting any archive member."""

from __future__ import annotations

import io
import stat
import struct
import zipfile

from . import allowlist, zipbuild
from .errors import ReleaseError

MAX_ENTRIES = 64
MAX_ENTRY_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024

LOCAL_SIGNATURE = b"PK\x03\x04"
CENTRAL_SIGNATURE = b"PK\x01\x02"
END_SIGNATURE = b"PK\x05\x06"
END_RECORD_BYTES = 22
LOCAL_HEADER_BYTES = 30
CENTRAL_HEADER_BYTES = 46
DATA_DESCRIPTOR_FLAG = 0x8


def _fail(message: str) -> None:
    raise ReleaseError(message)


def _check_name(name: str, allowed: set[str]) -> None:
    if not isinstance(name, str) or not name:
        _fail("archive entry has an empty name")
    if name.startswith("/") or "\\" in name:
        _fail("archive entry has an absolute or backslash path")
    if any(character < " " or character == "\x7f" for character in name):
        _fail("archive entry name contains control characters")
    parts = name.split("/")
    if any(part in ("", ".", "..") for part in parts):
        _fail("archive entry has an unsafe path segment")
    if len(parts) != 1:
        _fail("archive entry is not a flat product file")
    if name.startswith("."):
        _fail("archive entry is hidden")
    if name not in allowed:
        _fail("archive entry is outside the product allowlist")


def verify_zip(data: bytes, product: str) -> dict[str, bytes]:
    """Return verified member bytes; reject anything but the exact allowlist."""
    entries = allowlist.entries_for(product)
    allowed = set(entries)
    if not isinstance(data, (bytes, bytearray)) or not data:
        _fail("archive is empty")
    if len(data) > MAX_TOTAL_BYTES:
        _fail("archive exceeds the ZIP size budget")
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        _fail("archive is not a readable ZIP")
    infos = archive.infolist()
    if len(infos) > MAX_ENTRIES:
        _fail("archive has too many entries")
    names = [info.filename for info in infos]
    if len(set(names)) != len(names):
        _fail("archive has duplicate entries")
    for info in infos:
        # Python truncates a raw NUL-terminated name; compare against the
        # original bytes-derived name so a hidden suffix cannot be smuggled in.
        if getattr(info, "orig_filename", info.filename) != info.filename:
            _fail("archive entry name is not the exact stored name")
        if "\x00" in info.filename:
            _fail("archive entry name contains a NUL byte")
        _check_name(info.filename, allowed)
    if tuple(names) != entries:
        _fail("archive entries do not match the exact ordered allowlist")
    if archive.comment:
        _fail("archive carries an unexpected comment")

    files: dict[str, bytes] = {}
    total = 0
    for info in infos:
        if info.is_dir() or info.filename.endswith("/"):
            _fail("archive contains a directory entry")
        if info.flag_bits & 0x1:
            _fail("archive entry is encrypted")
        if info.compress_type != zipfile.ZIP_STORED:
            _fail("archive entry is not stored deterministically")
        if info.date_time != zipbuild.ZIP_TIMESTAMP:
            _fail("archive entry timestamp is not fixed")
        if info.extra or info.comment:
            _fail("archive entry carries unexpected extra metadata")
        mode = info.external_attr >> 16
        if not stat.S_ISREG(mode) or stat.S_IMODE(mode) != zipbuild.ZIP_FILE_MODE:
            _fail("archive entry is not a fixed-mode regular file")
        if info.file_size > MAX_ENTRY_BYTES:
            _fail("archive entry exceeds the per-file size budget")
        if info.flag_bits & 0x8:
            _fail("archive entry uses a data descriptor")
        if info.compress_size != info.file_size:
            _fail("archive entry has a non-identity compression ratio")
        try:
            payload = archive.read(info)
        except (zipfile.BadZipFile, RuntimeError, OSError, EOFError):
            _fail("archive entry cannot be read safely")
        if len(payload) != info.file_size:
            _fail("archive entry size does not match its header")
        total += len(payload)
        if total > MAX_TOTAL_BYTES:
            _fail("archive exceeds the uncompressed size budget")
        files[info.filename] = payload
    _check_raw_layout(data, entries)
    return files


def _decode_raw_name(raw_name: bytes, label: str) -> str:
    if b"\x00" in raw_name:
        _fail(f"archive {label} entry name contains a NUL byte")
    try:
        return raw_name.decode("ascii")
    except UnicodeDecodeError:
        _fail(f"archive {label} entry name is not the expected ASCII name")


def _check_raw_layout(data: bytes, entries: tuple[str, ...]) -> None:
    """Require a gap-free deterministic local/central/EOCD byte layout.

    The stdlib reader locates the central directory through the EOCD offset, so
    bytes smuggled between the last local payload and the central directory (or
    hidden local/central extra fields) are invisible to it. Walk every raw
    record and refuse a prefix, interstitial gap, duplicate local entry, extra
    local metadata, mismatched local/central header, or trailing byte. Never
    strip or normalize bytes.
    """
    try:
        _verify_raw_records(data, entries)
    except (struct.error, IndexError, ValueError):
        _fail("archive raw record layout is malformed")


def _verify_raw_records(data: bytes, entries: tuple[str, ...]) -> None:
    if len(data) < END_RECORD_BYTES:
        _fail("archive is missing its end record")
    eocd = len(data) - END_RECORD_BYTES
    if data[eocd : eocd + 4] != END_SIGNATURE:
        _fail("archive has hidden bytes after the end record")
    (
        entries_this_disk,
        entries_total,
        central_size,
        central_offset,
        comment_length,
    ) = struct.unpack_from("<HHIIH", data, eocd + 8)
    if comment_length != 0:
        _fail("archive end record carries a comment")
    if entries_this_disk != len(entries) or entries_total != len(entries):
        _fail("archive end record entry count is not the exact allowlist")
    if central_offset > eocd:
        _fail("archive central directory offset is out of range")
    if central_size != eocd - central_offset:
        _fail("archive central directory size does not match its records")

    central = _read_central_directory(data, entries, central_offset, eocd)
    _read_local_entries(data, entries, central, central_offset)


def _read_central_directory(
    data: bytes, entries: tuple[str, ...], start: int, eocd: int
) -> list[tuple[int, int, int, int, int, int, int, int]]:
    central: list[tuple[int, int, int, int, int, int, int, int]] = []
    position = start
    for expected in entries:
        if data[position : position + 4] != CENTRAL_SIGNATURE:
            _fail("archive central directory is not contiguous")
        (
            _signature,
            _version_made,
            _version_needed,
            flags,
            method,
            mod_time,
            mod_date,
            crc,
            compressed,
            uncompressed,
            name_length,
            extra_length,
            record_comment,
            _disk_start,
            _internal,
            _external,
            local_offset,
        ) = struct.unpack_from("<4sHHHHHHIIIHHHHHII", data, position)
        raw_name = data[
            position + CENTRAL_HEADER_BYTES : position + CENTRAL_HEADER_BYTES + name_length
        ]
        if _decode_raw_name(raw_name, "central") != expected:
            _fail("archive central entry name differs from the allowlist")
        if extra_length != 0 or record_comment != 0:
            _fail("archive central entry carries unexpected extra metadata")
        central.append(
            (flags, method, mod_time, mod_date, crc, compressed, uncompressed, local_offset)
        )
        position += CENTRAL_HEADER_BYTES + name_length + extra_length + record_comment
        if position > eocd:
            _fail("archive central directory record is truncated")
    if position != eocd:
        _fail("archive central directory is followed by hidden bytes")
    return central


def _read_local_entries(
    data: bytes,
    entries: tuple[str, ...],
    central: list[tuple[int, int, int, int, int, int, int, int]],
    start_dir: int,
) -> None:
    position = 0
    for index, expected in enumerate(entries):
        if data[position : position + 4] != LOCAL_SIGNATURE:
            _fail("archive local entries are not contiguous from the first byte")
        (
            _signature,
            _version_needed,
            flags,
            method,
            mod_time,
            mod_date,
            crc,
            compressed,
            uncompressed,
            name_length,
            extra_length,
        ) = struct.unpack_from("<4sHHHHHIIIHH", data, position)
        raw_name = data[
            position + LOCAL_HEADER_BYTES : position + LOCAL_HEADER_BYTES + name_length
        ]
        if _decode_raw_name(raw_name, "local") != expected:
            _fail("archive local entry name differs from its central name")
        if extra_length != 0:
            _fail("archive local entry carries unexpected extra metadata")
        if flags & DATA_DESCRIPTOR_FLAG:
            _fail("archive local entry uses a data descriptor")
        if (flags, method, mod_time, mod_date, crc, compressed, uncompressed, position) != (
            central[index]
        ):
            _fail("archive local entry header differs from its central record")
        position += LOCAL_HEADER_BYTES + name_length + extra_length + compressed
        if position > start_dir:
            _fail("archive local entry overlaps the central directory")
    if position != start_dir:
        _fail("archive local entries are followed by hidden bytes")
