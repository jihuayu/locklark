"""Offline verification of a detached public Ed25519 release attestation.

The verifier reads a small public JSON document, a public key supplied
explicitly by the owner, and the fixed package/receipt names for one product.
It never signs, never reads a private key, never uploads, never contacts a
network, and never writes or replaces an existing file.

A reason to verify an attestation is *pinned-key authenticity*, which is
different from the unsigned preparation receipt's self-consistency check.
The pinned key is only as trustworthy as the out-of-band channel that supplied
it; this module makes no claim that any particular key belongs to the owner.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import sys
from pathlib import Path

from . import allowlist, ed25519, receipt as receipt_module
from .bundle import read_regular_file
from .errors import ReleaseError
from .receiptcheck import verify_prepared_pair
from .version import validate_version

SCHEMA = "locklark-browser-release-attestation/v1"
DOMAIN = SCHEMA
REPO = "jihuayu/locklark"
MAX_ATTESTATION_BYTES = 64 * 1024
MAX_PUBLIC_KEY_BYTES = 128
FIELDS = (
    "schema",
    "repo",
    "product",
    "version",
    "source_commit",
    "artifact_sha256",
    "receipt_sha256",
    "signature",
)
_PAYLOAD_FIELDS = FIELDS[:-1]
_FOLDED_FIELDS = frozenset(field.casefold() for field in FIELDS)
_SHA256 = re.compile(r"[0-9a-f]{64}")
_COMMIT = re.compile(r"[0-9a-f]{40}")
_SIGNATURE = re.compile(r"[0-9a-f]{128}")
_PUBLIC_KEY_HEX = re.compile(rb"[0-9a-f]{64}")


def _fail(message: str) -> None:
    raise ReleaseError(message)


def _reject_constant(_value: str):
    _fail("attestation contains a non-JSON numeric constant")


def _object_pairs(pairs):
    """Refuse duplicate keys and case-only aliases at every object level."""
    result: dict[str, object] = {}
    seen: set[str] = set()
    for key, value in pairs:
        if not isinstance(key, str):
            _fail("attestation contains a non-string field name")
        folded = key.casefold()
        if folded in seen:
            _fail("attestation has a duplicate or case-aliased field")
        seen.add(folded)
        result[key] = value
    return result


def parse_attestation(data: bytes) -> dict[str, str]:
    """Parse and validate one strict v1 public attestation document."""
    if not isinstance(data, (bytes, bytearray)) or not data:
        _fail("attestation is empty")
    if len(data) > MAX_ATTESTATION_BYTES:
        _fail("attestation exceeds the size limit")
    if bytes(data).startswith(b"\xef\xbb\xbf"):
        _fail("attestation must not carry a UTF-8 byte-order mark")
    try:
        text = bytes(data).decode("utf-8")
    except UnicodeDecodeError:
        _fail("attestation is not valid UTF-8 JSON")
    try:
        document = json.loads(
            text,
            object_pairs_hook=_object_pairs,
            parse_constant=_reject_constant,
        )
    except json.JSONDecodeError:
        _fail("attestation is not valid JSON")
    if not isinstance(document, dict):
        _fail("attestation is not a JSON object")

    for key in document:
        if key in FIELDS:
            continue
        if key.casefold() in _FOLDED_FIELDS:
            _fail("attestation field name is not the exact lowercase name")
        _fail("attestation contains an unknown field")
    missing = set(FIELDS) - set(document)
    if missing:
        _fail("attestation is missing a required field")
    for field in FIELDS:
        if not isinstance(document[field], str):
            _fail(f"attestation field {field} must be a string")

    if document["schema"] != SCHEMA:
        _fail("attestation schema is not recognized")
    if document["repo"] != REPO:
        _fail("attestation repository is not the fixed repository")
    if document["product"] not in allowlist.PRODUCTS:
        _fail("attestation product is not supported")
    validate_version(document["version"])
    if not _COMMIT.fullmatch(document["source_commit"]):
        _fail("attestation source commit is not a 40-hex commit")
    if not _SHA256.fullmatch(document["artifact_sha256"]):
        _fail("attestation artifact digest is not a lowercase SHA256 digest")
    if not _SHA256.fullmatch(document["receipt_sha256"]):
        _fail("attestation receipt digest is not a lowercase SHA256 digest")
    if not _SIGNATURE.fullmatch(document["signature"]):
        _fail("attestation signature is not a lowercase 64-byte Ed25519 value")
    return {field: document[field] for field in FIELDS}


def canonical_bytes(payload: dict[str, str]) -> bytes:
    """Return the exact domain-separated bytes covered by the signature.

    The format is ASCII, one field per line, with a final newline:

        locklark-browser-release-attestation/v1
        repo=jihuayu/locklark
        product=chromium
        version=0.1.0
        source_commit=<40 lowercase hex>
        artifact_sha256=<64 lowercase hex>
        receipt_sha256=<64 lowercase hex>

    The signature field itself is not part of the signed bytes. Values are
    validated before this function is used by the verifier, so they contain no
    newline or non-ASCII bytes.
    """
    try:
        values = [payload[field] for field in _PAYLOAD_FIELDS]
    except KeyError:
        _fail("attestation canonical fields are missing")
    if not all(isinstance(value, str) for value in values):
        _fail("attestation canonical fields must be strings")
    lines = [DOMAIN]
    lines.extend(
        f"{field}={payload[field]}" for field in _PAYLOAD_FIELDS if field != "schema"
    )
    try:
        return ("\n".join(lines) + "\n").encode("ascii")
    except UnicodeEncodeError:
        _fail("attestation canonical fields must be ASCII")


def load_attestation(path: str | Path) -> dict[str, str]:
    """Read a strict, size-bounded attestation without following symlinks."""
    return parse_attestation(
        read_regular_file(Path(path), "publisher attestation", MAX_ATTESTATION_BYTES)
    )


def load_public_key(path: str | Path) -> bytes:
    """Read the owner-supplied pinned key: exactly 64 lowercase hex digits.

    One optional trailing LF is accepted for ordinary text-file convenience.
    The key is never read from the attestation, receipt, manifest, or output
    directory, so an attacker cannot substitute a key with the package.

    The decoded bytes must also be a usable Ed25519 public key: canonical
    encoding, on the curve, in the prime-order subgroup, and not small order.
    libsodium performs that check; a zero key, the identity point, a
    small-order point, a non-canonical encoding, or an off-curve encoding is
    refused before any signature is examined.
    """
    data = read_regular_file(Path(path), "owner public key", MAX_PUBLIC_KEY_BYTES)
    if data.endswith(b"\n"):
        data = data[:-1]
    if len(data) != 64 or not _PUBLIC_KEY_HEX.fullmatch(data):
        _fail("owner public key must be exactly 64 lowercase hex characters")
    key = bytes.fromhex(data.decode("ascii"))
    ed25519.require_usable_public_key(key)
    return key


def _require_output_directory(path: str | Path) -> Path:
    target = Path(path)
    try:
        info = target.lstat()
    except OSError:
        _fail("--output directory is missing")
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        _fail("--output is not a trusted directory")
    return target


def verify_attestation(
    product: str,
    output_dir: str | Path,
    attestation_path: str | Path,
    public_key_path: str | Path,
) -> dict:
    """Verify a detached attestation and bind it to the existing artifact pair.

    The package and receipt names are derived only from ``product`` and
    ``output_dir``. No package path, receipt path, or public key may be
    supplied by the attestation document. The output is read only.
    """
    if product not in allowlist.PRODUCTS:
        _fail("unsupported product")
    attestation = load_attestation(attestation_path)
    if attestation["product"] != product:
        _fail("attestation product does not match the requested product")
    public_key = load_public_key(public_key_path)
    if not ed25519.verify(
        public_key,
        bytes.fromhex(attestation["signature"]),
        canonical_bytes(attestation),
    ):
        _fail("attestation signature does not match the pinned public key")

    target = _require_output_directory(output_dir)
    _, zip_bytes, receipt, raw_receipt = verify_prepared_pair(target, product)
    if receipt_module.sha256_hex(raw_receipt) != attestation["receipt_sha256"]:
        _fail("attestation receipt digest does not match the receipt file")
    if receipt_module.sha256_hex(zip_bytes) != attestation["artifact_sha256"]:
        _fail("attestation artifact digest does not match the ZIP")
    if receipt.get("version") != attestation["version"]:
        _fail("attestation version does not match the receipt")
    if receipt.get("source_commit") != attestation["source_commit"]:
        _fail("attestation source commit does not match the receipt")
    return {
        "product": product,
        "version": attestation["version"],
        "source_commit": attestation["source_commit"],
        "artifact_sha256": attestation["artifact_sha256"],
        "receipt_sha256": attestation["receipt_sha256"],
        "public_key_sha256": hashlib.sha256(public_key).hexdigest(),
        "status": "pinned-key-signature-match",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Verify an offline detached Ed25519 publisher attestation against "
            "the fixed package/receipt names for one product. This never signs, "
            "uploads, contacts a network, or trusts a key from the same manifest."
        )
    )
    parser.add_argument("--product", required=True, choices=allowlist.PRODUCTS)
    parser.add_argument(
        "--output",
        required=True,
        help="absolute directory containing the fixed ZIP and receipt names",
    )
    parser.add_argument(
        "--attestation",
        required=True,
        help="explicit public attestation JSON file (at most 64 KiB)",
    )
    parser.add_argument(
        "--public-key",
        required=True,
        help="explicit owner public-key file: 64 lowercase hex characters",
    )
    args = parser.parse_args(argv)
    if not Path(args.output).is_absolute():
        print("FAIL: --output must be an absolute path", file=sys.stderr)
        return 1
    try:
        summary = verify_attestation(
            args.product, args.output, args.attestation, args.public_key
        )
    except ReleaseError as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    print(
        "PASS: attestation signature matches the explicitly supplied pinned "
        "public key"
    )
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
