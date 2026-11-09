"""Offline publisher attestation tests with in-memory throwaway keys."""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from browserrelease import (
    allowlist,
    attestation,
    ed25519,
    policy,
    receipt as receipt_module,
    zipbuild,
)
from browserrelease.errors import ReleaseError

COMMIT = "a" * 40
VERSION = "0.1.0"
SEED = bytes.fromhex("11" * 32)
OTHER_SEED = bytes.fromhex("22" * 32)

# Exact weak-key reproduction reported by the independent reviewer.
#
# Public identity point encoding: 01 followed by 31 zero bytes. With
# ``cryptography`` 50.0.0 / OpenSSL, signature R = the basepoint encoding
# (58 followed by 31 bytes 66) and S = little-endian 1 verifies *any* message
# without any private key. No blacklist of this one value may be the only
# defense; the verifier requires a canonical prime-subgroup non-small-order
# point from libsodium instead.
FORGED_IDENTITY_PUBLIC_KEY = bytes.fromhex("01" + "00" * 31)
FORGED_IDENTITY_SIGNATURE = bytes.fromhex(
    "58" + "66" * 31 + "01" + "00" * 31
)

# Ed25519 prime-subgroup order L, little-endian.
GROUP_ORDER = bytes.fromhex(
    "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010"
)

# Encodings that libsodium must reject as public keys or as signature R:
# small order, non-canonical (>= p), and off-curve. Each entry is a name and
# 64 lowercase hex characters.
BAD_POINTS = (
    ("zero", "00" * 32),
    ("identity", "01" + "00" * 31),
    ("identity-sign-bit", "01" + "00" * 30 + "80"),
    ("order-2", "ec" + "ff" * 30 + "7f"),
    ("order-4", "00" * 31 + "80"),
    ("order-8-a", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
    ("order-8-b", "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
    ("order-8-c", "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85"),
    ("noncanonical-identity", "ee" + "ff" * 30 + "7f"),
    ("noncanonical-near-p", "ed" + "ff" * 30 + "7f"),
    ("noncanonical-order-2", "ec" + "ff" * 30 + "ff"),
    ("offcurve-y2", "02" + "00" * 31),
    ("offcurve-y3", "03" + "00" * 31),
    ("offcurve-all-ff", "ff" * 32),
)


def _private_key(seed: bytes) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(seed)


def _public_key(seed: bytes) -> bytes:
    return _private_key(seed).public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    )


def _sign(seed: bytes, message: bytes) -> bytes:
    return _private_key(seed).sign(message)


def _manifest(product: str, version: str) -> dict:
    commands = {
        "_execute_action": (
            {"description": policy.EXPECTED_ACTION_COMMAND["description"]}
            if product == "firefox"
            else policy.EXPECTED_ACTION_COMMAND
        ),
        **policy.EXPECTED_COMMON_COMMANDS,
    }
    manifest = {
        "manifest_version": 3,
        "name": policy.EXPECTED_NAME,
        "version": version,
        "description": policy.EXPECTED_DESCRIPTION,
        "permissions": sorted(policy.EXPECTED_PERMISSIONS[product]),
        "host_permissions": policy.EXPECTED_HOST_PERMISSIONS,
        "content_scripts": policy.EXPECTED_CONTENT_SCRIPTS,
        "action": policy.EXPECTED_ACTION,
        "options_ui": policy.EXPECTED_OPTIONS,
        "commands": commands,
        "content_security_policy": policy.EXPECTED_CSP,
        "background": policy.EXPECTED_BACKGROUND[product],
    }
    if product == "chromium":
        manifest["key"] = allowlist.CHROMIUM_KEY
        manifest["minimum_chrome_version"] = allowlist.CHROMIUM_MIN_VERSION
    elif product == "firefox":
        manifest["browser_specific_settings"] = {
            "gecko": {
                "id": allowlist.FIREFOX_ID,
                "strict_min_version": allowlist.FIREFOX_MIN_VERSION,
                "data_collection_permissions": {"required": ["none"]},
            }
        }
    return manifest


def _make_pair(
    output: Path, product: str = "chromium", version: str = VERSION, commit: str = COMMIT
) -> dict:
    output.mkdir()
    entries = allowlist.entries_for(product)
    files = {name: f"fixture {name}\n".encode("utf-8") for name in entries}
    manifest = _manifest(product, version)
    files["manifest.json"] = (
        json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    zip_bytes = zipbuild.build_zip(entries, files)
    artifact_name = receipt_module.artifact_names(product)[0]
    receipt = {
        "schema": receipt_module.SCHEMA,
        "tool": receipt_module.TOOL_PATH,
        "product": product,
        "unsigned": True,
        "signed": False,
        "version": version,
        "identity": allowlist.identity_for(product),
        "source_commit": commit,
        "artifact": {
            "name": artifact_name,
            "format": zipbuild.ZIP_FORMAT,
            "entry_timestamp": zipbuild.ZIP_TIMESTAMP_TEXT,
            "entry_mode": zipbuild.ZIP_MODE_TEXT,
            "size": len(zip_bytes),
            "sha256": receipt_module.sha256_hex(zip_bytes),
        },
        "manifest": {
            "name": manifest["name"],
            "version": manifest["version"],
            "manifest_version": manifest["manifest_version"],
            "permissions": sorted(manifest["permissions"]),
            "host_permissions": manifest["host_permissions"],
        },
        "entries": [
            {
                "name": name,
                "size": len(files[name]),
                "sha256": receipt_module.sha256_hex(files[name]),
            }
            for name in entries
        ],
        "generator": {
            "path": receipt_module.BUILD_SCRIPT_RELATIVE,
            "sha256": receipt_module.sha256_hex(b"fixture build script"),
        },
        "version_metadata": {
            "path": receipt_module.VERSION_METADATA_RELATIVE,
            "sha256": receipt_module.sha256_hex(b"fixture version metadata"),
        },
    }
    receipt_bytes = receipt_module.receipt_bytes(receipt)
    (output / artifact_name).write_bytes(zip_bytes)
    (output / receipt_module.artifact_names(product)[1]).write_bytes(receipt_bytes)
    return {
        "product": product,
        "version": version,
        "commit": commit,
        "zip_bytes": zip_bytes,
        "receipt_bytes": receipt_bytes,
        "artifact_name": artifact_name,
    }


def _payload(pair: dict) -> dict:
    return {
        "schema": attestation.SCHEMA,
        "repo": attestation.REPO,
        "product": pair["product"],
        "version": pair["version"],
        "source_commit": pair["commit"],
        "artifact_sha256": receipt_module.sha256_hex(pair["zip_bytes"]),
        "receipt_sha256": receipt_module.sha256_hex(pair["receipt_bytes"]),
    }


def _write_attestation(
    path: Path, payload: dict, seed: bytes = SEED, extra: dict | None = None
) -> dict:
    signature = _sign(seed, attestation.canonical_bytes(payload)).hex()
    document = {**payload, "signature": signature}
    if extra:
        document.update(extra)
    path.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return document


class AttestationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.output = self.base / "out"
        self.pair = _make_pair(self.output)
        self.payload = _payload(self.pair)
        self.key_path = self.base / "owner.pub"
        self.key_path.write_text(_public_key(SEED).hex() + "\n", encoding="ascii")
        self.attestation_path = self.base / "attestation.json"
        _write_attestation(self.attestation_path, self.payload)

    def verify(self, product: str = "chromium"):
        return attestation.verify_attestation(
            product, self.output, self.attestation_path, self.key_path
        )

    def assert_refused(self, product: str = "chromium", message: str | None = None):
        with self.assertRaises(ReleaseError) as raised:
            self.verify(product)
        if message:
            self.assertIn(message, str(raised.exception))
        return raised.exception

    def test_rejects_duplicate_and_case_alias_fields(self):
        document = json.loads(self.attestation_path.read_text(encoding="utf-8"))
        encoded = json.dumps(document)
        duplicate = encoded[:-1] + ',"repo":"jihuayu/locklark"}'
        self.attestation_path.write_text(duplicate, encoding="utf-8")
        self.assert_refused(message="duplicate")

        aliased = encoded.replace('"product"', '"Product"', 1)
        self.attestation_path.write_text(aliased, encoding="utf-8")
        self.assert_refused(message="lowercase")

    def test_rejects_unknown_and_missing_fields(self):
        _write_attestation(
            self.attestation_path, self.payload, extra={"public_key": "00" * 32}
        )
        self.assert_refused(message="unknown field")

        _write_attestation(self.attestation_path, self.payload)
        document = json.loads(self.attestation_path.read_text(encoding="utf-8"))
        document.pop("receipt_sha256")
        self.attestation_path.write_text(json.dumps(document), encoding="utf-8")
        self.assert_refused(message="missing")

    def test_rejects_invalid_schema_repository_and_product(self):
        for field, value, message in (
            ("schema", "locklark-browser-release-attestation/v2", "schema"),
            ("repo", "someone/else", "repository"),
            ("product", "edge", "product"),
        ):
            with self.subTest(field=field):
                payload = dict(self.payload)
                payload[field] = value
                _write_attestation(self.attestation_path, payload)
                self.assert_refused(message=message)

    def test_rejects_invalid_hash_commit_and_version_values(self):
        cases = (
            ("artifact_sha256", "A" * 64, "artifact digest"),
            ("artifact_sha256", "0" * 63, "artifact digest"),
            ("receipt_sha256", "g" * 64, "receipt digest"),
            ("source_commit", "a" * 39, "source commit"),
            ("source_commit", "A" * 40, "source commit"),
            ("version", "01.0", "version"),
            ("version", "1.2.3.4.5", "version"),
            ("version", "65536", "version"),
        )
        for field, value, message in cases:
            with self.subTest(field=field, value=value):
                payload = dict(self.payload)
                payload[field] = value
                _write_attestation(self.attestation_path, payload)
                self.assert_refused(message=message)

    def test_rejects_uppercase_signature(self):
        document = json.loads(self.attestation_path.read_text(encoding="utf-8"))
        document["signature"] = document["signature"].upper()
        self.attestation_path.write_text(json.dumps(document), encoding="utf-8")
        self.assert_refused(message="signature")

    def test_rejects_malformed_json_and_non_object(self):
        for text in ("{", "[]", '"text"', "null", '{"schema": NaN}'):
            with self.subTest(text=text):
                self.attestation_path.write_text(text, encoding="utf-8")
                self.assert_refused()

    def test_rejects_oversize_attestation_and_public_key(self):
        self.attestation_path.write_bytes(b"{" + b" " * attestation.MAX_ATTESTATION_BYTES)
        self.assert_refused(message="size")
        self.key_path.write_bytes(b"0" * (attestation.MAX_PUBLIC_KEY_BYTES + 1))
        self.assert_refused(message="size")

    def test_rejects_symlinked_inputs(self):
        real_attestation = self.base / "real-attestation.json"
        real_attestation.write_bytes(self.attestation_path.read_bytes())
        self.attestation_path.unlink()
        os.symlink(real_attestation, self.attestation_path)
        self.assert_refused(message="symlink")

        self.attestation_path.unlink()
        _write_attestation(self.attestation_path, self.payload)
        real_key = self.base / "real-owner.pub"
        real_key.write_bytes(self.key_path.read_bytes())
        self.key_path.unlink()
        os.symlink(real_key, self.key_path)
        self.assert_refused(message="symlink")

    def test_rejects_nonregular_inputs(self):
        self.attestation_path.unlink()
        self.attestation_path.mkdir()
        self.assert_refused(message="regular file")

    def test_rejects_symlinked_package_and_receipt(self):
        artifact = self.output / self.pair["artifact_name"]
        real_artifact = self.base / "real.zip"
        real_artifact.write_bytes(artifact.read_bytes())
        artifact.unlink()
        os.symlink(real_artifact, artifact)
        self.assert_refused()

        artifact.unlink()
        artifact.write_bytes(self.pair["zip_bytes"])
        receipt_name = receipt_module.artifact_names("chromium")[1]
        receipt = self.output / receipt_name
        real_receipt = self.base / "real.receipt.json"
        real_receipt.write_bytes(receipt.read_bytes())
        receipt.unlink()
        os.symlink(real_receipt, receipt)
        self.assert_refused()

    def test_rejects_tampered_package_bytes(self):
        artifact = self.output / self.pair["artifact_name"]
        tampered = bytearray(self.pair["zip_bytes"])
        tampered[len(tampered) // 2] ^= 0xFF
        artifact.write_bytes(bytes(tampered))
        self.assert_refused()

    def test_rejects_tampered_receipt_bytes(self):
        receipt_name = receipt_module.artifact_names("chromium")[1]
        receipt_path = self.output / receipt_name
        receipt_path.write_bytes(self.pair["receipt_bytes"] + b"\n")
        self.assert_refused(message="receipt digest")

    def test_rejects_tampered_receipt_semantics(self):
        receipt_name = receipt_module.artifact_names("chromium")[1]
        receipt_path = self.output / receipt_name
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        receipt["entries"][0]["sha256"] = "0" * 64
        receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
        self.assert_refused()

    def test_rejects_tampered_signature(self):
        document = json.loads(self.attestation_path.read_text(encoding="utf-8"))
        signature = document["signature"]
        document["signature"] = ("0" if signature[0] != "0" else "1") + signature[1:]
        self.attestation_path.write_text(json.dumps(document), encoding="utf-8")
        self.assert_refused(message="signature")

    def test_rejects_unknown_signer(self):
        _write_attestation(self.attestation_path, self.payload, seed=OTHER_SEED)
        self.assert_refused(message="signature")

    def test_rejects_mismatched_output_product(self):
        self.assert_refused(product="firefox")

        output = self.base / "firefox-out"
        pair = _make_pair(output, product="firefox")
        payload = _payload(pair)
        path = self.base / "firefox-attestation.json"
        _write_attestation(path, payload)
        with self.assertRaises(ReleaseError):
            attestation.verify_attestation(
                "firefox", self.output, path, self.key_path
            )

    def test_rejects_mismatched_source_commit_version_and_digests(self):
        cases = (
            ("source_commit", "b" * 40, "source commit"),
            ("version", "0.2.0", "version"),
            ("artifact_sha256", "0" * 64, "artifact digest"),
            ("receipt_sha256", "0" * 64, "receipt digest"),
        )
        for field, value, message in cases:
            with self.subTest(field=field):
                payload = dict(self.payload)
                payload[field] = value
                _write_attestation(self.attestation_path, payload)
                self.assert_refused(message=message)

    def test_rejects_malformed_public_key_file(self):
        for payload in (
            b"",
            b"0" * 63,
            b"0" * 65,
            b"G" * 64,
            ("0" * 64).upper().encode("ascii"),
            ("0" * 64).encode("ascii") + b"\r\n",
        ):
            with self.subTest(payload=payload[:8]):
                self.key_path.write_bytes(payload)
                self.assert_refused(message="public key")

    def test_rejects_relative_output_path_in_cli(self):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            result = attestation.main(
                [
                    "--product",
                    "chromium",
                    "--output",
                    "relative/out",
                    "--attestation",
                    str(self.attestation_path),
                    "--public-key",
                    str(self.key_path),
                ]
            )
        self.assertEqual(result, 1)
        self.assertIn("absolute", stderr.getvalue())

    def test_cli_success_is_read_only_and_failure_is_fixed(self):
        artifact = self.output / self.pair["artifact_name"]
        receipt = self.output / receipt_module.artifact_names("chromium")[1]
        before = {
            "zip": artifact.read_bytes(),
            "receipt": receipt.read_bytes(),
            "attestation": self.attestation_path.read_bytes(),
            "key": self.key_path.read_bytes(),
        }
        stdout = io.StringIO()
        stderr = io.StringIO()
        argv = [
            "--product",
            "chromium",
            "--output",
            str(self.output),
            "--attestation",
            str(self.attestation_path),
            "--public-key",
            str(self.key_path),
        ]
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            self.assertEqual(attestation.main(argv), 0)
        self.assertIn("PASS", stdout.getvalue())
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(
            before,
            {
                "zip": artifact.read_bytes(),
                "receipt": receipt.read_bytes(),
                "attestation": self.attestation_path.read_bytes(),
                "key": self.key_path.read_bytes(),
            },
        )

        document = json.loads(self.attestation_path.read_text(encoding="utf-8"))
        document["signature"] = "0" * 128
        self.attestation_path.write_text(json.dumps(document), encoding="utf-8")
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            self.assertEqual(attestation.main(argv), 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("FAIL", stderr.getvalue())

    def test_canonical_bytes_are_domain_separated_and_field_ordered(self):
        encoded = attestation.canonical_bytes(self.payload)
        self.assertTrue(encoded.startswith(b"locklark-browser-release-attestation/v1\n"))
        self.assertEqual(encoded.count(b"\n"), 7)
        self.assertIn(b"repo=jihuayu/locklark\n", encoded)
        self.assertNotIn(b"signature=", encoded)
        changed = dict(self.payload)
        changed["version"] = "0.2.0"
        self.assertNotEqual(encoded, attestation.canonical_bytes(changed))

    def test_rfc8032_test_vector_one(self):
        public_key = bytes.fromhex(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        )
        signature = bytes.fromhex(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555"
            "fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        )
        self.assertTrue(ed25519.verify(public_key, signature, b""))
        self.assertFalse(ed25519.verify(public_key, signature, b"x"))
        self.assertFalse(ed25519.verify(public_key, signature[:-1], b""))

    def test_missing_verifier_dependency_fails_closed(self):
        original_public = ed25519.Ed25519PublicKey
        original_invalid = ed25519.InvalidSignature
        try:
            ed25519.Ed25519PublicKey = None
            ed25519.InvalidSignature = None
            with self.assertRaises(ReleaseError) as raised:
                ed25519.verify(b"\x00" * 32, b"\x00" * 64, b"")
            self.assertEqual(str(raised.exception), ed25519.DEPENDENCY_ERROR)
            self.assert_refused(message=ed25519.DEPENDENCY_ERROR)
        finally:
            ed25519.Ed25519PublicKey = original_public
            ed25519.InvalidSignature = original_invalid

    def test_all_products_verify(self):
        for product in allowlist.PRODUCTS:
            with self.subTest(product=product):
                output = self.base / f"out-{product}"
                pair = _make_pair(output, product=product)
                payload = _payload(pair)
                path = self.base / f"{product}.attestation.json"
                _write_attestation(path, payload)
                summary = attestation.verify_attestation(
                    product, output, path, self.key_path
                )
                self.assertEqual(summary["product"], product)
                self.assertEqual(summary["status"], "pinned-key-signature-match")


class PointValidationTests(unittest.TestCase):
    """Weak-key regressions: canonical prime-subgroup point gate (libsodium).

    Every key and signature below is a throwaway in-memory fixture. Success
    means the verifier refuses, never that an owner identity was proven.
    """

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.output = self.base / "out"
        self.pair = _make_pair(self.output)
        self.payload = _payload(self.pair)
        self.key_path = self.base / "owner.pub"
        self.key_path.write_text(_public_key(SEED).hex() + "\n", encoding="ascii")
        self.attestation_path = self.base / "attestation.json"
        _write_attestation(self.attestation_path, self.payload)

    def verify(self):
        return attestation.verify_attestation(
            "chromium", self.output, self.attestation_path, self.key_path
        )

    def assert_refused_key(self, expected: str = ed25519.PUBLIC_KEY_ERROR):
        with self.assertRaises(ReleaseError) as raised:
            self.verify()
        self.assertEqual(str(raised.exception), expected)
        return raised.exception

    def test_libsodium_rejects_small_order_noncanonical_and_offcurve_points(self):
        for name, encoded in BAD_POINTS:
            with self.subTest(name=name):
                raw = bytes.fromhex(encoded)
                self.assertEqual(len(raw), 32)
                self.assertFalse(
                    ed25519.crypto_core_ed25519_is_valid_point(raw),
                    f"libsodium accepted the {name} fixture",
                )
                self.assertFalse(ed25519.public_key_is_usable(raw))

    def test_libsodium_accepts_honest_generated_and_rfc_points(self):
        generated = Ed25519PrivateKey.generate()
        generated_public = generated.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )
        self.assertTrue(ed25519.public_key_is_usable(generated_public))
        self.assertTrue(ed25519.public_key_is_usable(_public_key(SEED)))
        for public_key, signature, _message in _rfc8032_vectors():
            self.assertTrue(ed25519.public_key_is_usable(public_key))
            self.assertTrue(ed25519.public_key_is_usable(signature[:32]))

    def test_forged_identity_key_never_verifies_any_message_at_the_wrapper(self):
        for message in (
            b"",
            b"x",
            attestation.canonical_bytes(self.payload),
            b"arbitrary attacker chosen payload",
        ):
            with self.subTest(message=message[:12]):
                self.assertFalse(
                    ed25519.verify(
                        FORGED_IDENTITY_PUBLIC_KEY,
                        FORGED_IDENTITY_SIGNATURE,
                        message,
                    ),
                    "the forged identity key must never verify",
                )
        self.assertFalse(ed25519.public_key_is_usable(FORGED_IDENTITY_PUBLIC_KEY))
        with self.assertRaises(ReleaseError) as raised:
            ed25519.require_usable_public_key(FORGED_IDENTITY_PUBLIC_KEY)
        self.assertEqual(str(raised.exception), ed25519.PUBLIC_KEY_ERROR)

    def test_backend_alone_accepts_the_forged_identity_key(self):
        """Records why the point gate exists; skips if the backend is fixed."""
        message = attestation.canonical_bytes(self.payload)
        try:
            Ed25519PublicKey.from_public_bytes(FORGED_IDENTITY_PUBLIC_KEY).verify(
                FORGED_IDENTITY_SIGNATURE, message
            )
        except Exception:  # pragma: no cover - depends on the OpenSSL build
            self.skipTest(
                "pinned cryptography/OpenSSL no longer accepts the forged "
                "identity key; the libsodium gate remains required"
            )
        # The backend accepted a signature made without any private key. The
        # verifier must refuse it anyway, which is exactly what this asserts.
        self.assertFalse(
            ed25519.verify(
                FORGED_IDENTITY_PUBLIC_KEY, FORGED_IDENTITY_SIGNATURE, message
            )
        )

    def test_forged_identity_key_is_refused_end_to_end(self):
        self.key_path.write_text(
            FORGED_IDENTITY_PUBLIC_KEY.hex() + "\n", encoding="ascii"
        )
        # The forged signature is message-independent, so it is also valid for
        # this real synthetic package/receipt payload under the identity key.
        self.attestation_path.write_text(
            json.dumps(
                {**self.payload, "signature": FORGED_IDENTITY_SIGNATURE.hex()},
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        error = self.assert_refused_key()
        self.assertNotIn("pinned-key-signature-match", str(error))
        self.assertNotIn("PASS", str(error))

    def test_forged_identity_key_never_passes_the_cli(self):
        self.key_path.write_text(
            FORGED_IDENTITY_PUBLIC_KEY.hex() + "\n", encoding="ascii"
        )
        self.attestation_path.write_text(
            json.dumps(
                {**self.payload, "signature": FORGED_IDENTITY_SIGNATURE.hex()},
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            result = attestation.main(
                [
                    "--product",
                    "chromium",
                    "--output",
                    str(self.output),
                    "--attestation",
                    str(self.attestation_path),
                    "--public-key",
                    str(self.key_path),
                ]
            )
        self.assertEqual(result, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertNotIn("pinned-key-signature-match", stdout.getvalue())
        self.assertIn("FAIL", stderr.getvalue())
        self.assertIn(ed25519.PUBLIC_KEY_ERROR, stderr.getvalue())

    def test_every_bad_public_key_is_refused_before_the_signature(self):
        for name, encoded in BAD_POINTS:
            with self.subTest(name=name):
                self.key_path.write_text(encoded + "\n", encoding="ascii")
                self.assert_refused_key()

    def test_bad_public_key_with_matching_forged_signature_is_refused(self):
        for name, encoded in BAD_POINTS:
            with self.subTest(name=name):
                self.key_path.write_text(encoded + "\n", encoding="ascii")
                self.attestation_path.write_text(
                    json.dumps(
                        {
                            **self.payload,
                            "signature": FORGED_IDENTITY_SIGNATURE.hex(),
                        },
                        indent=2,
                        sort_keys=True,
                    )
                    + "\n",
                    encoding="utf-8",
                )
                self.assert_refused_key()

    def test_strict_r_point_is_required(self):
        public_key = _public_key(SEED)
        message = attestation.canonical_bytes(self.payload)
        honest = _sign(SEED, message)
        self.assertTrue(ed25519.verify(public_key, honest, message))

        # Honest key, forged R = basepoint encoding and S = 1.
        self.assertFalse(ed25519.verify(public_key, FORGED_IDENTITY_SIGNATURE, message))
        for name, encoded in BAD_POINTS:
            with self.subTest(name=name):
                self.assertFalse(
                    ed25519.verify(public_key, bytes.fromhex(encoded) + honest[32:], message)
                )

        # End to end: the same bad R inside a syntactically valid attestation.
        for name, encoded in BAD_POINTS:
            with self.subTest(end_to_end=name):
                self.attestation_path.write_text(
                    json.dumps(
                        {
                            **self.payload,
                            "signature": (bytes.fromhex(encoded) + honest[32:]).hex(),
                        },
                        indent=2,
                        sort_keys=True,
                    )
                    + "\n",
                    encoding="utf-8",
                )
                with self.assertRaises(ReleaseError) as raised:
                    self.verify()
                self.assertIn("signature does not match", str(raised.exception))

    def test_noncanonical_s_scalar_is_refused(self):
        public_key = _public_key(SEED)
        message = attestation.canonical_bytes(self.payload)
        honest = _sign(SEED, message)
        order = int.from_bytes(GROUP_ORDER, "little")
        for name, scalar in (
            ("order", GROUP_ORDER),
            ("order-plus-one", (order + 1).to_bytes(32, "little")),
            ("all-ff", b"\xff" * 32),
            ("zero", b"\x00" * 32),
        ):
            with self.subTest(name=name):
                self.assertFalse(
                    ed25519.verify(public_key, honest[:32] + scalar, message)
                )

    def test_generated_independent_signer_verifies_end_to_end(self):
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )
        self.key_path.write_text(public_key.hex() + "\n", encoding="ascii")
        signature = private_key.sign(attestation.canonical_bytes(self.payload))
        self.attestation_path.write_text(
            json.dumps(
                {**self.payload, "signature": signature.hex()},
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        summary = self.verify()
        self.assertEqual(summary["status"], "pinned-key-signature-match")
        self.assertEqual(
            summary["public_key_sha256"], hashlib.sha256(public_key).hexdigest()
        )

        # The same generated signer over another message must not verify.
        other = private_key.sign(b"another payload")
        self.attestation_path.write_text(
            json.dumps(
                {**self.payload, "signature": other.hex()},
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        with self.assertRaises(ReleaseError):
            self.verify()

    def test_rfc8032_vectors_two_and_three(self):
        for public_key, signature, message in _rfc8032_vectors():
            with self.subTest(message=message.hex()):
                self.assertTrue(ed25519.verify(public_key, signature, message))
                self.assertFalse(ed25519.verify(public_key, signature, message + b"\x00"))
                self.assertFalse(
                    ed25519.verify(
                        public_key,
                        signature[:32] + signature[32:],
                        message + b" ",
                    )
                )

    def test_missing_pynacl_fails_closed(self):
        original = ed25519.crypto_core_ed25519_is_valid_point
        good_key = _public_key(SEED)
        good_signature = _sign(SEED, attestation.canonical_bytes(self.payload))
        try:
            ed25519.crypto_core_ed25519_is_valid_point = None
            with self.assertRaises(ReleaseError) as raised:
                ed25519.verify(
                    good_key, good_signature, attestation.canonical_bytes(self.payload)
                )
            self.assertEqual(str(raised.exception), ed25519.DEPENDENCY_ERROR)
            with self.assertRaises(ReleaseError) as raised:
                ed25519.require_usable_public_key(good_key)
            self.assertEqual(str(raised.exception), ed25519.DEPENDENCY_ERROR)
            with self.assertRaises(ReleaseError) as raised:
                attestation.load_public_key(self.key_path)
            self.assertEqual(str(raised.exception), ed25519.DEPENDENCY_ERROR)
            self.assert_refused_key(ed25519.DEPENDENCY_ERROR)

            # A forged identity key must not slip through either.
            self.key_path.write_text(
                FORGED_IDENTITY_PUBLIC_KEY.hex() + "\n", encoding="ascii"
            )
            self.assert_refused_key(ed25519.DEPENDENCY_ERROR)
        finally:
            ed25519.crypto_core_ed25519_is_valid_point = original


def _rfc8032_vectors():
    """RFC 8032 section 7.1 test vectors 1-3 (public key, signature, message)."""
    return (
        (
            bytes.fromhex(
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
            ),
            bytes.fromhex(
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555"
                "fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
            ),
            b"",
        ),
        (
            bytes.fromhex(
                "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
            ),
            bytes.fromhex(
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
                "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
            ),
            bytes.fromhex("72"),
        ),
        (
            bytes.fromhex(
                "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"
            ),
            bytes.fromhex(
                "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
                "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
            ),
            bytes.fromhex("af82"),
        ),
    )


if __name__ == "__main__":
    unittest.main()
