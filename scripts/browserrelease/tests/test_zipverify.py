"""Structural verifier tests: no extraction, no traversal, exact allowlist.

Also covers the raw byte layout: a strict, gap-free deterministic archive where
the local headers, central directory and EOCD are contiguous and every local
header field matches its central record. Bytes hidden in an interstitial gap or
a local extra field must be refused, never stripped.
"""

from __future__ import annotations

import hashlib
import json
import stat
import struct
import tempfile
import unittest
import zlib
from pathlib import Path
import zipfile

from browserrelease import (
    allowlist,
    package,
    receipt as receipt_module,
    zipverify,
)
from browserrelease.errors import ReleaseError
from browserrelease.tests import support

PRODUCT = "chromium"

HIDDEN_GAP = b"UNLISTED-HIDDEN-BYTES\x00payload"
LOCAL_EXTRA = b"UNLISTED-LOCAL-EXTRA\x00payload"


def _central_offset(data: bytes) -> int:
    return struct.unpack_from("<I", data, len(data) - 22 + 16)[0]


def _local_offsets(data: bytes) -> list[int]:
    limit = _central_offset(data)
    offsets: list[int] = []
    position = 0
    while position < limit:
        if data[position : position + 4] != b"PK\x03\x04":
            raise AssertionError("fixture local header is malformed")
        name_length = struct.unpack_from("<H", data, position + 26)[0]
        extra_length = struct.unpack_from("<H", data, position + 28)[0]
        compressed = struct.unpack_from("<I", data, position + 18)[0]
        offsets.append(position)
        position += 30 + name_length + extra_length + compressed
    if position != limit:
        raise AssertionError("fixture local region is not contiguous")
    return offsets


def _insert_bytes(data: bytes, offset: int, blob: bytes) -> bytes:
    """Insert blob at offset and move the EOCD central-directory offset."""
    central_offset = _central_offset(data)
    if offset > central_offset:
        raise AssertionError("fixture insertion is past the central directory")
    body = data[:offset] + blob + data[offset:]
    updated = bytearray(body)
    struct.pack_into("<I", updated, len(updated) - 22 + 16, central_offset + len(blob))
    return bytes(updated)


def _local_record(name: bytes, data: bytes) -> bytes:
    crc = zlib.crc32(data) & 0xFFFFFFFF
    return (
        struct.pack(
            "<IHHHHHIIIHH",
            0x04034B50,
            20,
            0,
            0,
            0,
            0x21,
            crc,
            len(data),
            len(data),
            len(name),
            0,
        )
        + name
        + data
    )


class ZipVerifyTests(unittest.TestCase):
    def accept(self, members, product=PRODUCT, **kwargs):
        return zipverify.verify_zip(support.crafted_zip(members, **kwargs), product)

    def refuse(self, members, product=PRODUCT, **kwargs):
        with self.assertRaises(ReleaseError):
            zipverify.verify_zip(
                support.crafted_zip(members, **kwargs), product
            )

    def test_accepts_the_exact_allowlist(self):
        entries = allowlist.entries_for(PRODUCT)
        files = self.accept(support.members_for(PRODUCT))
        self.assertEqual(tuple(files), entries)

    def test_accepts_the_safari_helper_allowlist(self):
        files = self.accept(support.members_for("safari"), "safari")
        self.assertIn("safari-native-port.js", files)
        self.assertEqual(len(files), 12)
        self.assertNotIn("safari-native-port.js", allowlist.entries_for(PRODUCT))

    def test_refuses_extra_missing_or_reordered_entries(self):
        members = support.members_for(PRODUCT)
        self.refuse(members + [("notes.txt", b"x", 0)])
        self.refuse(members[:-1])
        self.refuse([members[1], members[0], *members[2:]])
        self.refuse([*members, members[0]])

    def test_refuses_unsafe_entry_names(self):
        members = support.members_for(PRODUCT)
        for name in (
            "/manifest.json",
            "..\\manifest.json",
            "../manifest.json",
            "sub/manifest.json",
            "manifest.json/",
            ".manifest.json",
            "manif\\x01est.json",
            "",
        ):
            with self.subTest(name=name):
                self.refuse([(name, b"x", 0), *members[1:]])

    def test_refuses_symlink_and_non_regular_entries(self):
        members = support.members_for(PRODUCT)
        self.refuse([(members[0][0], b"x", stat.S_IFLNK | 0o777), *members[1:]])
        self.refuse([(members[0][0], b"x", 0o755), *members[1:]])
        self.refuse([(members[0][0], b"x", 0o600), *members[1:]])

    def test_refuses_non_stored_compression(self):
        self.refuse(
            support.members_for(PRODUCT), compression=zipfile.ZIP_DEFLATED
        )

    def test_refuses_archive_comment(self):
        self.refuse(support.members_for(PRODUCT), comment=b"built elsewhere")

    def test_refuses_too_many_entries(self):
        self.refuse([(f"file{index}.js", b"x", 0) for index in range(65)])

    def test_accepts_a_seventeen_mib_archive_without_giant_repo_files(self):
        entries = allowlist.entries_for(PRODUCT)
        members = [
            (entries[0], b"\0" * (15 * 1024 * 1024), 0),
            (entries[1], b"\0" * (3 * 1024 * 1024), 0),
            *[(name, b"x", 0) for name in entries[2:]],
        ]
        files = self.accept(members)
        self.assertGreater(
            sum(len(payload) for payload in files.values()), 16 * 1024 * 1024
        )

    def test_refuses_raw_nul_names_in_central_or_local_headers(self):
        entries = allowlist.entries_for(PRODUCT)
        good = [(name.encode(), name.encode(), b"x") for name in entries]
        files = zipverify.verify_zip(support.raw_zip(good), PRODUCT)
        self.assertEqual(tuple(files), entries)
        central_nul = [
            (name.encode(), name.encode() + b"\x00", b"x")
            if index == 0
            else (name.encode(), name.encode(), b"x")
            for index, name in enumerate(entries)
        ]
        with self.assertRaises(ReleaseError):
            zipverify.verify_zip(support.raw_zip(central_nul), PRODUCT)
        local_nul = [
            (name.encode() + b"\x00", name.encode(), b"x")
            if index == 0
            else (name.encode(), name.encode(), b"x")
            for index, name in enumerate(entries)
        ]
        with self.assertRaises(ReleaseError):
            zipverify.verify_zip(support.raw_zip(local_nul), PRODUCT)

    def test_refuses_oversized_entries_and_garbage(self):
        members = support.members_for(PRODUCT)
        oversized = (members[0][0], b"\0" * (16 * 1024 * 1024 + 1), 0)
        self.refuse([oversized, *members[1:]])
        for payload in (b"", b"not a zip", b"PK\x03\x04truncated"):
            with self.subTest(payload=payload[:8]):
                with self.assertRaises(ReleaseError):
                    zipverify.verify_zip(payload, PRODUCT)


class RawLayoutTests(unittest.TestCase):
    def setUp(self):
        self.entries = allowlist.entries_for(PRODUCT)
        self.clean = support.raw_zip(
            [(name.encode(), name.encode(), b"x") for name in self.entries]
        )
        # The unmodified raw archive is the control: it must still be accepted.
        self.assertEqual(tuple(zipverify.verify_zip(self.clean, PRODUCT)), self.entries)

    def refuses(self, data: bytes) -> None:
        with self.assertRaises(ReleaseError):
            zipverify.verify_zip(data, PRODUCT)

    def test_refuses_interstitial_gap_between_local_payload_and_central(self):
        self.assertEqual(len(HIDDEN_GAP), 29)
        tampered = _insert_bytes(self.clean, _central_offset(self.clean), HIDDEN_GAP)
        # The canary really is in the bytes; it is refused, not stripped.
        self.assertIn(HIDDEN_GAP, tampered)
        self.refuses(tampered)

    def test_refuses_prefix_before_the_first_local_header(self):
        self.refuses(b"PREFIX-CANARY" + self.clean)

    def test_refuses_hidden_duplicate_local_entry_before_central(self):
        hidden = _local_record(b".hidden", b"hidden-payload")
        tampered = _insert_bytes(self.clean, _central_offset(self.clean), hidden)
        self.assertIn(b".hidden", tampered)
        self.refuses(tampered)

    def test_refuses_local_extra_field_when_central_extra_is_empty(self):
        self.assertEqual(len(LOCAL_EXTRA), 28)
        offsets = _local_offsets(self.clean)
        last = offsets[-1]
        name_length = struct.unpack_from("<H", self.clean, last + 26)[0]
        tampered = bytearray(
            _insert_bytes(self.clean, last + 30 + name_length, LOCAL_EXTRA)
        )
        # The local header keeps its offset; only its extra-field length changes.
        struct.pack_into("<H", tampered, last + 28, len(LOCAL_EXTRA))
        self.assertIn(LOCAL_EXTRA, tampered)
        self.refuses(bytes(tampered))

    def test_refuses_trailing_bytes_after_the_end_record(self):
        self.refuses(self.clean + b"TRAILER")

    def test_refuses_local_header_field_that_differs_from_central(self):
        offsets = _local_offsets(self.clean)
        tampered = bytearray(self.clean)
        crc = struct.unpack_from("<I", tampered, offsets[0] + 14)[0]
        struct.pack_into("<I", tampered, offsets[0] + 14, crc ^ 0xFFFFFFFF)
        self.refuses(bytes(tampered))


class FullPackageLayoutTests(unittest.TestCase):
    """A fully receipted package must still refuse a byte-level layout gap."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.root = support.make_root(self.base)
        self.target = str(self.base / "out")
        package.prepare(PRODUCT, self.target, root=self.root)
        self.zip_path = (
            Path(self.target) / receipt_module.artifact_names(PRODUCT)[0]
        )
        self.receipt_path = (
            Path(self.target) / receipt_module.artifact_names(PRODUCT)[1]
        )
        self.clean = self.zip_path.read_bytes()
        zipverify.verify_zip(self.clean, PRODUCT)
        self.assertEqual(
            package.verify(PRODUCT, self.target, root=self.root)["status"],
            "verified",
        )

    def publish_tampered(self, tampered: bytes) -> None:
        receipt = json.loads(self.receipt_path.read_text(encoding="utf-8"))
        receipt["artifact"]["size"] = len(tampered)
        receipt["artifact"]["sha256"] = hashlib.sha256(tampered).hexdigest()
        self.zip_path.write_bytes(tampered)
        self.receipt_path.write_text(json.dumps(receipt), encoding="utf-8")

    def test_full_verify_refuses_interstitial_gap_with_updated_receipt(self):
        tampered = _insert_bytes(self.clean, _central_offset(self.clean), HIDDEN_GAP)
        self.assertIn(HIDDEN_GAP, tampered)
        self.publish_tampered(tampered)
        with self.assertRaises(ReleaseError):
            package.verify(PRODUCT, self.target, root=self.root)

    def test_full_verify_refuses_local_extra_with_updated_receipt(self):
        offsets = _local_offsets(self.clean)
        last = offsets[-1]
        name_length = struct.unpack_from("<H", self.clean, last + 26)[0]
        tampered = bytearray(
            _insert_bytes(self.clean, last + 30 + name_length, LOCAL_EXTRA)
        )
        struct.pack_into("<H", tampered, last + 28, len(LOCAL_EXTRA))
        self.assertIn(LOCAL_EXTRA, tampered)
        self.publish_tampered(bytes(tampered))
        with self.assertRaises(ReleaseError):
            package.verify(PRODUCT, self.target, root=self.root)


if __name__ == "__main__":
    unittest.main()
