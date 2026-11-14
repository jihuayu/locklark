#!/usr/bin/env python3
"""Focused contracts for verify_desktop_release.py.

The fixtures are synthetic bytes signed by a temporary Ed25519 key. They
exercise the real digest, size, and OpenSSL signature checks in the verifier;
they do not build, sign, or publish a real Locklark release, and they are not
evidence that production artifacts have the identity checked here.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "verify_desktop_release.py"
VERSION = "1.2.3"
PLATFORM_ARCHIVE = {
    "windows-amd64": f"locklark-{VERSION}-windows-amd64.tar.gz",
    "darwin-universal": f"locklark-{VERSION}-darwin-universal.tar.gz",
}


def openssl(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["openssl", *args],
        capture_output=True,
        check=True,
    )


class SyntheticRelease:
    """A temporary release directory and the Ed25519 key used to sign it."""

    def __init__(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="locklark-release-test-"))
        os.chmod(self.root, 0o700)
        self.key = self.root / "key.pem"
        self.public_der = self.root / "public.der"
        openssl("genpkey", "-algorithm", "ED25519", "-out", str(self.key))
        os.chmod(self.key, 0o600)
        openssl(
            "pkey",
            "-in",
            str(self.key),
            "-pubout",
            "-outform",
            "DER",
            "-out",
            str(self.public_der),
        )
        os.chmod(self.public_der, 0o600)
        der = self.public_der.read_bytes()
        if len(der) != 44:
            raise AssertionError(f"unexpected Ed25519 public DER length: {len(der)}")
        self.public_key = base64.b64encode(der[-32:]).decode("ascii")

    def close(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def assets(self) -> Path:
        path = Path(tempfile.mkdtemp(prefix="assets-", dir=self.root))
        os.chmod(path, 0o700)
        return path

    def sign(self, payload: bytes) -> str:
        with tempfile.TemporaryDirectory(prefix="sign-", dir=self.root) as raw:
            work = Path(raw)
            digest = work / "digest.bin"
            signature = work / "signature.bin"
            digest.write_bytes(hashlib.sha256(payload).digest())
            openssl(
                "pkeyutl",
                "-sign",
                "-inkey",
                str(self.key),
                "-rawin",
                "-in",
                str(digest),
                "-out",
                str(signature),
            )
            return base64.b64encode(signature.read_bytes()).decode("ascii")

    def add_asset(self, assets: Path, name: str, payload: bytes) -> None:
        (assets / name).write_bytes(payload)

    def write_manifest(
        self,
        assets: Path,
        platform: str,
        payload: bytes,
        *,
        archive_name: str | None = None,
        version: str = VERSION,
        notes: str = "Synthetic release notes.",
        deltas: list[dict] | None = None,
    ) -> dict:
        name = archive_name or PLATFORM_ARCHIVE[platform]
        manifest = {
            "version": version,
            "notes": notes,
            "url": f"https://example.invalid/releases/download/v{version}/{name}",
            "size": len(payload),
            "signature": self.sign(payload),
        }
        if deltas is not None:
            manifest["deltas"] = deltas
        (assets / f"update-{platform}.json").write_text(
            json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
        )
        return manifest

    def add_installer_assets(self, assets: Path, version: str = VERSION) -> None:
        self.add_asset(assets, f"locklark-setup-{version}-amd64.exe", b"setup")
        self.add_asset(assets, f"locklark-{version}.dmg", b"dmg")
        self.add_asset(assets, "install.ps1", b"install ps1")
        self.add_asset(assets, "install.sh", b"install sh")

    def run(self, assets: Path, *, version: str = VERSION) -> subprocess.CompletedProcess:
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--assets",
                str(assets),
                "--version",
                version,
                "--public-key",
                self.public_key,
            ],
            capture_output=True,
            text=True,
        )


def parse_checksums(path: Path) -> dict[str, str]:
    checksums: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        digest, name = line.split("  ", 1)
        checksums[name] = digest
    return checksums


@unittest.skipUnless(shutil.which("openssl"), "openssl is required by the verifier")
class VerifyDesktopReleaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.release = SyntheticRelease()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.release.close()

    def assert_rejected(
        self, result: subprocess.CompletedProcess, assets: Path
    ) -> None:
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("release verification failed:", result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertFalse((assets / "SHA256SUMS").exists())

    def test_00_signed_digest_smoke(self) -> None:
        payload = b"synthetic signed bytes for the verifier smoke"
        signature = base64.b64decode(self.release.sign(payload))
        self.assertEqual(len(signature), 64)
        with tempfile.TemporaryDirectory(prefix="smoke-", dir=self.release.root) as raw:
            work = Path(raw)
            digest = work / "digest.bin"
            signature_path = work / "signature.bin"
            digest.write_bytes(hashlib.sha256(payload).digest())
            signature_path.write_bytes(signature)
            openssl(
                "pkeyutl",
                "-verify",
                "-pubin",
                "-inkey",
                str(self.release.public_der),
                "-keyform",
                "DER",
                "-rawin",
                "-in",
                str(digest),
                "-sigfile",
                str(signature_path),
            )
            digest.write_bytes(hashlib.sha256(payload + b"!").digest())
            tampered = subprocess.run(
                [
                    "openssl",
                    "pkeyutl",
                    "-verify",
                    "-pubin",
                    "-inkey",
                    str(self.release.public_der),
                    "-keyform",
                    "DER",
                    "-rawin",
                    "-in",
                    str(digest),
                    "-sigfile",
                    str(signature_path),
                ],
                capture_output=True,
            )
            self.assertNotEqual(tampered.returncode, 0)

    def test_valid_release_binds_both_platform_archives(self) -> None:
        assets = self.release.assets()
        windows = b"windows archive payload\n"
        darwin = b"darwin archive payload\n"
        self.release.add_asset(assets, PLATFORM_ARCHIVE["windows-amd64"], windows)
        self.release.add_asset(assets, PLATFORM_ARCHIVE["darwin-universal"], darwin)
        self.release.add_installer_assets(assets)
        self.release.write_manifest(assets, "windows-amd64", windows)
        self.release.write_manifest(assets, "darwin-universal", darwin)

        result = self.release.run(assets)
        self.assertEqual(result.returncode, 0, result.stderr)
        checksums = parse_checksums(assets / "SHA256SUMS")
        self.assertEqual(
            set(checksums),
            {
                *PLATFORM_ARCHIVE.values(),
                f"locklark-setup-{VERSION}-amd64.exe",
                f"locklark-{VERSION}.dmg",
                "install.ps1",
                "install.sh",
            },
        )
        self.assertEqual(
            checksums[PLATFORM_ARCHIVE["windows-amd64"]],
            hashlib.sha256(windows).hexdigest(),
        )
        self.assertEqual(
            checksums[PLATFORM_ARCHIVE["darwin-universal"]],
            hashlib.sha256(darwin).hexdigest(),
        )

    def test_darwin_manifest_cannot_reuse_windows_archive(self) -> None:
        assets = self.release.assets()
        windows = b"windows archive only\n"
        self.release.add_asset(assets, PLATFORM_ARCHIVE["windows-amd64"], windows)
        self.release.add_installer_assets(assets)
        self.release.write_manifest(assets, "windows-amd64", windows)
        self.release.write_manifest(
            assets,
            "darwin-universal",
            windows,
            archive_name=PLATFORM_ARCHIVE["windows-amd64"],
        )

        result = self.release.run(assets)
        self.assert_rejected(result, assets)
        self.assertIn("darwin-universal archive", result.stderr)
        self.assertIn(PLATFORM_ARCHIVE["darwin-universal"], result.stderr)

    def test_windows_manifest_cannot_reuse_darwin_archive(self) -> None:
        assets = self.release.assets()
        darwin = b"darwin archive only\n"
        self.release.add_asset(assets, PLATFORM_ARCHIVE["darwin-universal"], darwin)
        self.release.add_installer_assets(assets)
        self.release.write_manifest(
            assets,
            "windows-amd64",
            darwin,
            archive_name=PLATFORM_ARCHIVE["darwin-universal"],
        )
        self.release.write_manifest(assets, "darwin-universal", darwin)

        result = self.release.run(assets)
        self.assert_rejected(result, assets)
        self.assertIn("windows-amd64 archive", result.stderr)
        self.assertIn(PLATFORM_ARCHIVE["windows-amd64"], result.stderr)

    def test_wrong_version_archive_name_is_rejected(self) -> None:
        assets = self.release.assets()
        payload = b"wrong version payload\n"
        wrong_name = "locklark-1.0.0-windows-amd64.tar.gz"
        darwin = b"darwin archive payload\n"
        self.release.add_asset(assets, wrong_name, payload)
        self.release.add_asset(assets, PLATFORM_ARCHIVE["darwin-universal"], darwin)
        self.release.add_installer_assets(assets)
        self.release.write_manifest(
            assets, "windows-amd64", payload, archive_name=wrong_name
        )
        self.release.write_manifest(assets, "darwin-universal", darwin)

        result = self.release.run(assets)
        self.assert_rejected(result, assets)
        self.assertIn("windows-amd64 archive", result.stderr)
        self.assertIn(PLATFORM_ARCHIVE["windows-amd64"], result.stderr)

    def test_wrong_architecture_archive_name_is_rejected(self) -> None:
        assets = self.release.assets()
        windows = b"windows archive payload\n"
        wrong_name = f"locklark-{VERSION}-darwin-arm64.tar.gz"
        payload = b"darwin arm64 payload\n"
        self.release.add_asset(assets, PLATFORM_ARCHIVE["windows-amd64"], windows)
        self.release.add_asset(assets, wrong_name, payload)
        self.release.add_installer_assets(assets)
        self.release.write_manifest(assets, "windows-amd64", windows)
        self.release.write_manifest(
            assets, "darwin-universal", payload, archive_name=wrong_name
        )

        result = self.release.run(assets)
        self.assert_rejected(result, assets)
        self.assertIn("darwin-universal archive", result.stderr)
        self.assertIn(PLATFORM_ARCHIVE["darwin-universal"], result.stderr)

    def test_cross_platform_delta_is_rejected(self) -> None:
        assets = self.release.assets()
        windows = b"windows archive payload\n"
        darwin = b"darwin archive payload\n"
        delta = b"delta payload made for darwin\n"
        delta_name = f"locklark-1.1.0-to-{VERSION}-darwin-universal.delta"
        self.release.add_asset(assets, PLATFORM_ARCHIVE["windows-amd64"], windows)
        self.release.add_asset(assets, PLATFORM_ARCHIVE["darwin-universal"], darwin)
        self.release.add_asset(assets, delta_name, delta)
        self.release.add_installer_assets(assets)
        self.release.write_manifest(
            assets,
            "windows-amd64",
            windows,
            deltas=[
                {
                    "from": "1.1.0",
                    "url": f"https://example.invalid/releases/download/v{VERSION}/{delta_name}",
                    "size": len(delta),
                    "signature": self.release.sign(delta),
                }
            ],
        )
        self.release.write_manifest(assets, "darwin-universal", darwin)

        result = self.release.run(assets)
        self.assert_rejected(result, assets)
        self.assertIn("windows-amd64 delta from 1.1.0", result.stderr)
        self.assertIn(f"locklark-1.1.0-to-{VERSION}-windows-amd64.delta", result.stderr)

    def test_malformed_manifest_fields_are_rejected(self) -> None:
        def bool_size(assets: Path, manifest: dict) -> None:
            manifest["size"] = True

        def bad_deltas(assets: Path, manifest: dict) -> None:
            manifest["deltas"] = {"from": "1.1.0"}

        def bad_url(assets: Path, manifest: dict) -> None:
            manifest["url"] = "http://[::1"

        for mutate in (bool_size, bad_deltas, bad_url):
            with self.subTest(mutate=mutate.__name__):
                assets = self.release.assets()
                payload = b"x"
                self.release.add_asset(
                    assets, PLATFORM_ARCHIVE["windows-amd64"], payload
                )
                darwin = b"darwin archive payload\n"
                self.release.add_asset(
                    assets, PLATFORM_ARCHIVE["darwin-universal"], darwin
                )
                self.release.add_installer_assets(assets)
                manifest = self.release.write_manifest(
                    assets, "windows-amd64", payload
                )
                mutate(assets, manifest)
                (assets / "update-windows-amd64.json").write_text(
                    json.dumps(manifest) + "\n", encoding="utf-8"
                )
                self.release.write_manifest(assets, "darwin-universal", darwin)

                self.assert_rejected(self.release.run(assets), assets)

    def test_duplicate_manifest_key_is_rejected(self) -> None:
        assets = self.release.assets()
        payload = b"windows archive payload\n"
        darwin = b"darwin archive payload\n"
        self.release.add_asset(assets, PLATFORM_ARCHIVE["windows-amd64"], payload)
        self.release.add_asset(assets, PLATFORM_ARCHIVE["darwin-universal"], darwin)
        self.release.add_installer_assets(assets)
        self.release.write_manifest(assets, "windows-amd64", payload)
        self.release.write_manifest(assets, "darwin-universal", darwin)
        manifest_path = assets / "update-windows-amd64.json"
        manifest_path.write_text(
            manifest_path.read_text(encoding="utf-8").replace(
                '"notes":', '"notes": "duplicate",\n  "notes":', 1
            ),
            encoding="utf-8",
        )

        result = self.release.run(assets)
        self.assert_rejected(result, assets)
        self.assertIn("duplicate JSON key", result.stderr)

    def test_actual_bytes_size_and_signature_stay_failclosed(self) -> None:
        def tampered_payload(assets: Path, manifest: dict) -> None:
            path = assets / PLATFORM_ARCHIVE["windows-amd64"]
            path.write_bytes(b"X" * len(path.read_bytes()))

        def wrong_size(assets: Path, manifest: dict) -> None:
            manifest["size"] += 1
            (assets / "update-windows-amd64.json").write_text(
                json.dumps(manifest) + "\n", encoding="utf-8"
            )

        def short_signature(assets: Path, manifest: dict) -> None:
            manifest["signature"] = base64.b64encode(b"short").decode("ascii")
            (assets / "update-windows-amd64.json").write_text(
                json.dumps(manifest) + "\n", encoding="utf-8"
            )

        for mutate in (tampered_payload, wrong_size, short_signature):
            with self.subTest(mutate=mutate.__name__):
                assets = self.release.assets()
                payload = b"windows archive payload\n"
                darwin = b"darwin archive payload\n"
                self.release.add_asset(
                    assets, PLATFORM_ARCHIVE["windows-amd64"], payload
                )
                self.release.add_asset(
                    assets, PLATFORM_ARCHIVE["darwin-universal"], darwin
                )
                self.release.add_installer_assets(assets)
                manifest = self.release.write_manifest(
                    assets, "windows-amd64", payload
                )
                self.release.write_manifest(assets, "darwin-universal", darwin)
                mutate(assets, manifest)

                self.assert_rejected(self.release.run(assets), assets)


if __name__ == "__main__":
    unittest.main()
