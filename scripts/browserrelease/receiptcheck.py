"""Verify a receipt against the ZIP bytes and every bundled file digest."""

from __future__ import annotations

import json
import re
from pathlib import Path

from . import allowlist, receipt as receipt_module, zipbuild, zipverify
from .bundle import read_regular_file
from .errors import ReleaseError
from .manifestcheck import validate_manifest
from .version import validate_version

COMMIT = re.compile(r"[0-9a-f]{40}")
SHA256 = re.compile(r"[0-9a-f]{64}")
MAX_RECEIPT_BYTES = 1024 * 1024
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024


def _fail(message: str) -> None:
    raise ReleaseError(message)


def _hex(value, label: str) -> str:
    if not isinstance(value, str) or not SHA256.fullmatch(value):
        _fail(f"{label} is not a lowercase SHA256 digest")
    return value


def verify_receipt(
    receipt: object,
    files: dict[str, bytes],
    zip_bytes: bytes,
    product: str,
    version: str | None = None,
) -> None:
    """Check the receipt is a self-consistent unsigned preparation record."""
    if not isinstance(receipt, dict):
        _fail("receipt is not an object")
    if receipt.get("schema") != receipt_module.SCHEMA:
        _fail("receipt schema is not recognized")
    if receipt.get("tool") != receipt_module.TOOL_PATH:
        _fail("receipt was produced by a different tool")
    if receipt.get("product") != product:
        _fail("receipt product does not match the requested product")
    if receipt.get("unsigned") is not True or receipt.get("signed") is not False:
        _fail("receipt must describe an unsigned preparation")
    receipt_version = validate_version(receipt.get("version"))
    if version is not None and receipt_version != version:
        _fail("receipt version does not match the central release version")
    if receipt.get("identity") != allowlist.identity_for(product):
        _fail("receipt browser identity does not match the fixed identity")
    commit = receipt.get("source_commit")
    if not isinstance(commit, str) or not COMMIT.fullmatch(commit):
        _fail("receipt source commit is not a 40-hex commit")

    artifact = receipt.get("artifact")
    if not isinstance(artifact, dict):
        _fail("receipt artifact metadata is missing")
    if artifact.get("name") != receipt_module.artifact_names(product)[0]:
        _fail("receipt artifact name does not match the product")
    if artifact.get("format") != zipbuild.ZIP_FORMAT:
        _fail("receipt artifact format is not the deterministic stored ZIP")
    if artifact.get("entry_timestamp") != zipbuild.ZIP_TIMESTAMP_TEXT:
        _fail("receipt entry timestamp is not the fixed timestamp")
    if artifact.get("entry_mode") != zipbuild.ZIP_MODE_TEXT:
        _fail("receipt entry mode is not the fixed mode")
    if artifact.get("size") != len(zip_bytes):
        _fail("receipt artifact size does not match the ZIP")
    if _hex(artifact.get("sha256"), "receipt artifact digest") != receipt_module.sha256_hex(
        zip_bytes
    ):
        _fail("receipt artifact digest does not match the ZIP")

    entries = receipt.get("entries")
    if not isinstance(entries, list) or len(entries) != len(allowlist.entries_for(product)):
        _fail("receipt entry list does not match the product allowlist")
    for expected_name, entry in zip(allowlist.entries_for(product), entries):
        if not isinstance(entry, dict) or entry.get("name") != expected_name:
            _fail("receipt entry names do not match the product allowlist in order")
        if entry.get("size") != len(files[expected_name]):
            _fail(f"receipt entry size does not match {expected_name}")
        if _hex(entry.get("sha256"), f"receipt entry digest for {expected_name}") != (
            receipt_module.sha256_hex(files[expected_name])
        ):
            _fail(f"receipt entry digest does not match {expected_name}")

    manifest = json.loads(files[allowlist.MANIFEST_FILE].decode("utf-8"))
    validate_manifest(manifest, product, receipt_version)
    recorded = receipt.get("manifest")
    if not isinstance(recorded, dict):
        _fail("receipt manifest summary is missing")
    if recorded.get("version") != manifest["version"]:
        _fail("receipt manifest version does not match the bundled manifest")
    if recorded.get("permissions") != sorted(manifest["permissions"]):
        _fail("receipt manifest permissions do not match the bundled manifest")
    if recorded.get("host_permissions") != manifest["host_permissions"]:
        _fail("receipt host permissions do not match the bundled manifest")
    for key in ("generator", "version_metadata"):
        block = receipt.get(key)
        if not isinstance(block, dict) or not isinstance(block.get("path"), str):
            _fail(f"receipt {key} metadata is missing")
        _hex(block.get("sha256"), f"receipt {key} digest")


def verify_prepared_pair(
    output_dir: Path, product: str, version: str | None = None
) -> tuple[dict[str, bytes], bytes, dict, bytes]:
    """Load and verify one existing ZIP/receipt pair from an output directory."""
    zip_name, receipt_name = receipt_module.artifact_names(product)
    zip_path = Path(output_dir) / zip_name
    receipt_path = Path(output_dir) / receipt_name
    for path in (zip_path, receipt_path):
        if path.is_symlink() or not path.is_file():
            _fail("existing output artifact is not a regular file")
    raw_receipt = read_regular_file(receipt_path, "existing receipt")
    if len(raw_receipt) > MAX_RECEIPT_BYTES:
        _fail("existing receipt exceeds the size limit")
    try:
        parsed = json.loads(raw_receipt.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        _fail("existing receipt is not valid UTF-8 JSON")
    zip_bytes = read_regular_file(
        zip_path, "existing artifact", MAX_ARCHIVE_BYTES
    )
    files = zipverify.verify_zip(zip_bytes, product)
    verify_receipt(parsed, files, zip_bytes, product, version)
    return files, zip_bytes, parsed, raw_receipt
