#!/usr/bin/env python3
"""Focused contracts for verify_desktop_release.py.

The archives hold minimal real Go PE/Mach-O fixtures signed by a temporary
Ed25519 key. They exercise the verifier's real digest, size, OpenSSL, PE,
Mach-O, Go build-info and tar checks; they do not build, sign, or publish a
real Locklark release, and they are not evidence that production artifacts
have the identity checked here.
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import io
import json
import os
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "verify_desktop_release.py"
VERSION = "1.2.3"
OLD_VERSION = "1.0.0"
IDENTIFIER = "app.locklark.desktop"
WINDOWS_EXECUTABLE = "Locklark.exe"
DARWIN_EXECUTABLE = "Locklark.app/Contents/MacOS/Locklark"
DARWIN_INFO_PLIST = "Locklark.app/Contents/Info.plist"
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


class GoFixtures:
    """Minimal real Go PE and universal Mach-O fixtures, compiled once."""

    def __init__(self, root: Path) -> None:
        self.root = root / "go-fixtures"
        self.root.mkdir(mode=0o700)
        self.module = self.root / "module"
        (self.module / "cmd" / "fixture").mkdir(parents=True, mode=0o700)
        (self.module / "go.mod").write_text(
            "module github.com/egoist/mygo\n\ngo 1.27.3\n", encoding="utf-8"
        )
        (self.module / "mygo.go").write_text(
            """package mygo

var packageVersion = "unset"
var packageIdentifier = "unset"

//go:noinline
func Metadata() (string, string) { return packageVersion, packageIdentifier }
""",
            encoding="utf-8",
        )
        (self.module / "cmd" / "fixture" / "main.go").write_text(
            """package main

import (
	"fmt"

	"github.com/egoist/mygo"
)

func main() {
	version, identifier := mygo.Metadata()
	fmt.Println(version, identifier)
}
""",
            encoding="utf-8",
        )
        self.cache: dict[tuple[str, str, str, str], bytes] = {}
        self.environment = os.environ.copy()
        self.environment.update(
            {
                "GOWORK": "off",
                "GOENV": "off",
                "GOTOOLCHAIN": "local",
                "CGO_ENABLED": "0",
            }
        )

    def _build(
        self, goos: str, goarch: str, version: str, identifier: str = IDENTIFIER
    ) -> bytes:
        key = (goos, goarch, version, identifier)
        if key in self.cache:
            return self.cache[key]
        output = self.root / f"{goos}-{goarch}-{version}-{identifier}"
        ldflags = (
            "-s -w "
            f"-X github.com/egoist/mygo.packageVersion={version} "
            f"-X github.com/egoist/mygo.packageIdentifier={identifier}"
        )
        if goos == "windows":
            ldflags += " -H=windowsgui"
        environment = dict(self.environment, GOOS=goos, GOARCH=goarch)
        result = subprocess.run(
            [
                "go",
                "build",
                "-mod=readonly",
                "-trimpath",
                "-ldflags",
                ldflags,
                "-o",
                str(output),
                "./cmd/fixture",
            ],
            cwd=self.module,
            env=environment,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise AssertionError(
                f"cannot build Go fixture {goos}/{goarch}/{version}: {result.stderr}"
            )
        os.chmod(output, 0o600)
        data = output.read_bytes()
        self.cache[key] = data
        return data

    def windows(self, version: str = VERSION, identifier: str = IDENTIFIER) -> bytes:
        return self._build("windows", "amd64", version, identifier)

    def darwin_slice(self, arch: str, version: str = VERSION) -> bytes:
        return self._build("darwin", arch, version)

    def universal(
        self,
        version: str = VERSION,
        *,
        arches: tuple[str, ...] = ("arm64", "amd64"),
        versions: dict[str, str] | None = None,
    ) -> bytes:
        cpu = {"arm64": 0x0100000C, "amd64": 0x01000007}
        sub = {"arm64": 0, "amd64": 3}
        slices = [
            (
                cpu[arch],
                sub[arch],
                self.darwin_slice(
                    arch, versions[arch] if versions is not None else version
                ),
            )
            for arch in arches
        ]
        align = 14
        offset = 1 << align
        header = struct.pack(">II", 0xCAFEBABE, len(slices))
        bodies: list[tuple[int, bytes]] = []
        for cpu_type, cpu_subtype, data in slices:
            header += struct.pack(
                ">IIIII", cpu_type, cpu_subtype, offset, len(data), align
            )
            bodies.append((offset, data))
            offset += (len(data) + (1 << align) - 1) & ~((1 << align) - 1)
        out = bytearray(header)
        for start, data in bodies:
            out.extend(b"\0" * (start - len(out)))
            out.extend(data)
        return bytes(out)

    @staticmethod
    def plist(
        version: str = VERSION, identifier: str = IDENTIFIER
    ) -> bytes:
        return (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<plist version="1.0"><dict>'
            f"<key>CFBundleIdentifier</key><string>{identifier}</string>"
            f"<key>CFBundleShortVersionString</key><string>{version}</string>"
            f"<key>CFBundleVersion</key><string>{version}</string>"
            "</dict></plist>\n"
        ).encode()

    @staticmethod
    def tar_gz(entries: list[dict]) -> bytes:
        buffer = io.BytesIO()
        with tarfile.open(
            fileobj=buffer, mode="w:gz", format=tarfile.PAX_FORMAT
        ) as archive:
            for entry in entries:
                info = tarfile.TarInfo(entry["name"])
                info.mode = entry.get("mode", 0o644)
                if entry.get("type") == "symlink":
                    info.type = tarfile.SYMTYPE
                    info.linkname = entry["linkname"]
                    archive.addfile(info)
                    continue
                data = entry["data"]
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        return buffer.getvalue()

    @staticmethod
    def oversized_tar_gz(name: str, declared_size: int) -> bytes:
        buffer = io.BytesIO()
        with gzip.GzipFile(fileobj=buffer, mode="wb") as compressed:
            info = tarfile.TarInfo(name)
            info.size = declared_size
            info.mode = 0o755
            compressed.write(info.tobuf(format=tarfile.GNU_FORMAT))
            compressed.write(b"\0" * 1024)
        return buffer.getvalue()

    def windows_archive(
        self,
        version: str = VERSION,
        *,
        executable: bytes | None = None,
        identifier: str = IDENTIFIER,
        entries: list[dict] | None = None,
    ) -> bytes:
        if entries is None:
            executable = executable or self.windows(version, identifier)
            entries = [
                {"name": WINDOWS_EXECUTABLE, "data": executable, "mode": 0o755}
            ]
        return self.tar_gz(entries)

    def darwin_archive(
        self,
        version: str = VERSION,
        *,
        executable: bytes | None = None,
        plist: bytes | None = None,
        entries: list[dict] | None = None,
    ) -> bytes:
        if entries is None:
            executable = executable or self.universal(version)
            plist = plist if plist is not None else self.plist(version)
            entries = [
                {"name": DARWIN_EXECUTABLE, "data": executable, "mode": 0o755},
                {"name": DARWIN_INFO_PLIST, "data": plist, "mode": 0o644},
                {
                    "name": "Locklark.app/Contents/PkgInfo",
                    "data": b"APPL????",
                    "mode": 0o644,
                },
            ]
        return self.tar_gz(entries)


def parse_checksums(path: Path) -> dict[str, str]:
    checksums: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        digest, name = line.split("  ", 1)
        checksums[name] = digest
    return checksums


@unittest.skipUnless(
    shutil.which("openssl") and shutil.which("go"),
    "openssl and Go are required by the verifier",
)
class VerifyDesktopReleaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.release = SyntheticRelease()
        try:
            cls.go = GoFixtures(cls.release.root)
            cls.windows_archive = cls.go.windows_archive()
            cls.darwin_archive = cls.go.darwin_archive()
            cls.old_windows_archive = cls.go.windows_archive(OLD_VERSION)
            cls.prerelease_windows_archive = cls.go.windows_archive(
                VERSION + "-rc1"
            )
            cls.old_darwin_archive = cls.go.darwin_archive(OLD_VERSION)
        except BaseException:
            cls.release.close()
            raise

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
        windows = self.windows_archive
        darwin = self.darwin_archive
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

    def test_same_windows_bytes_under_both_archive_names_is_rejected(self) -> None:
        assets = self.release.assets()
        shared = self.windows_archive
        self.release.add_asset(assets, PLATFORM_ARCHIVE["windows-amd64"], shared)
        self.release.add_asset(assets, PLATFORM_ARCHIVE["darwin-universal"], shared)
        self.release.add_installer_assets(assets)
        self.release.write_manifest(assets, "windows-amd64", shared)
        self.release.write_manifest(assets, "darwin-universal", shared)

        result = self.release.run(assets)
        self.assert_rejected(result, assets)
        self.assertIn("darwin-universal archive content identity", result.stderr)
        self.assertIn(DARWIN_EXECUTABLE, result.stderr)

    def test_cross_platform_executables_inside_archives_are_rejected(self) -> None:
        cases = {
            "windows-pe-in-darwin": (
                self.windows_archive,
                self.go.darwin_archive(executable=self.go.windows()),
            ),
            "darwin-macho-in-windows": (
                self.go.windows_archive(executable=self.go.universal()),
                self.darwin_archive,
            ),
        }
        for name, (windows, darwin) in cases.items():
            with self.subTest(case=name):
                assets = self.release.assets()
                self.release.add_asset(
                    assets, PLATFORM_ARCHIVE["windows-amd64"], windows
                )
                self.release.add_asset(
                    assets, PLATFORM_ARCHIVE["darwin-universal"], darwin
                )
                self.release.add_installer_assets(assets)
                self.release.write_manifest(assets, "windows-amd64", windows)
                self.release.write_manifest(assets, "darwin-universal", darwin)

                result = self.release.run(assets)
                self.assert_rejected(result, assets)
                self.assertIn("content identity does not verify", result.stderr)

    def test_old_windows_bytes_renamed_current_are_rejected(self) -> None:
        archives = {
            "old": self.old_windows_archive,
            "prerelease": self.prerelease_windows_archive,
        }
        for name, windows in archives.items():
            with self.subTest(case=name):
                assets = self.release.assets()
                darwin = self.darwin_archive
                self.release.add_asset(
                    assets, PLATFORM_ARCHIVE["windows-amd64"], windows
                )
                self.release.add_asset(
                    assets, PLATFORM_ARCHIVE["darwin-universal"], darwin
                )
                self.release.add_installer_assets(assets)
                self.release.write_manifest(assets, "windows-amd64", windows)
                self.release.write_manifest(assets, "darwin-universal", darwin)

                result = self.release.run(assets)
                self.assert_rejected(result, assets)
                self.assertIn(
                    "does not embed an exact Go string for version", result.stderr
                )
                self.assertIn(VERSION, result.stderr)

    def test_old_darwin_bytes_renamed_current_are_rejected(self) -> None:
        assets = self.release.assets()
        windows = self.windows_archive
        darwin = self.old_darwin_archive
        self.release.add_asset(assets, PLATFORM_ARCHIVE["windows-amd64"], windows)
        self.release.add_asset(assets, PLATFORM_ARCHIVE["darwin-universal"], darwin)
        self.release.add_installer_assets(assets)
        self.release.write_manifest(assets, "windows-amd64", windows)
        self.release.write_manifest(assets, "darwin-universal", darwin)

        result = self.release.run(assets)
        self.assert_rejected(result, assets)
        self.assertIn("CFBundleShortVersionString", result.stderr)
        self.assertIn(VERSION, result.stderr)

    def test_darwin_archive_must_have_both_arch_slices(self) -> None:
        assets = self.release.assets()
        windows = self.windows_archive
        executable = self.go.universal(arches=("arm64",))
        darwin = self.go.darwin_archive(executable=executable)
        self.release.add_asset(assets, PLATFORM_ARCHIVE["windows-amd64"], windows)
        self.release.add_asset(assets, PLATFORM_ARCHIVE["darwin-universal"], darwin)
        self.release.add_installer_assets(assets)
        self.release.write_manifest(assets, "windows-amd64", windows)
        self.release.write_manifest(assets, "darwin-universal", darwin)

        result = self.release.run(assets)
        self.assert_rejected(result, assets)
        self.assertIn("want arm64 and amd64", result.stderr)

    def test_both_darwin_slices_must_match_current_version(self) -> None:
        assets = self.release.assets()
        windows = self.windows_archive
        executable = self.go.universal(
            versions={"arm64": VERSION, "amd64": OLD_VERSION}
        )
        darwin = self.go.darwin_archive(executable=executable)
        self.release.add_asset(assets, PLATFORM_ARCHIVE["windows-amd64"], windows)
        self.release.add_asset(assets, PLATFORM_ARCHIVE["darwin-universal"], darwin)
        self.release.add_installer_assets(assets)
        self.release.write_manifest(assets, "windows-amd64", windows)
        self.release.write_manifest(assets, "darwin-universal", darwin)

        result = self.release.run(assets)
        self.assert_rejected(result, assets)
        self.assertIn(
            "macOS amd64 slice does not embed an exact Go string for version",
            result.stderr,
        )

    def test_wrong_identifier_is_rejected(self) -> None:
        wrong = "x" + IDENTIFIER
        with self.subTest(kind="windows-binary"):
            assets = self.release.assets()
            windows = self.go.windows_archive(identifier=wrong)
            darwin = self.darwin_archive
            self.release.add_asset(
                assets, PLATFORM_ARCHIVE["windows-amd64"], windows
            )
            self.release.add_asset(
                assets, PLATFORM_ARCHIVE["darwin-universal"], darwin
            )
            self.release.add_installer_assets(assets)
            self.release.write_manifest(assets, "windows-amd64", windows)
            self.release.write_manifest(assets, "darwin-universal", darwin)

            result = self.release.run(assets)
            self.assert_rejected(result, assets)
            self.assertIn(
                "does not embed an exact Go string for identifier", result.stderr
            )

        with self.subTest(kind="darwin-plist"):
            assets = self.release.assets()
            windows = self.windows_archive
            darwin = self.go.darwin_archive(
                plist=self.go.plist(VERSION, identifier=wrong)
            )
            self.release.add_asset(
                assets, PLATFORM_ARCHIVE["windows-amd64"], windows
            )
            self.release.add_asset(
                assets, PLATFORM_ARCHIVE["darwin-universal"], darwin
            )
            self.release.add_installer_assets(assets)
            self.release.write_manifest(assets, "windows-amd64", windows)
            self.release.write_manifest(assets, "darwin-universal", darwin)

            result = self.release.run(assets)
            self.assert_rejected(result, assets)
            self.assertIn("CFBundleIdentifier", result.stderr)

    def test_darwin_manifest_cannot_reuse_windows_archive(self) -> None:
        assets = self.release.assets()
        windows = self.windows_archive
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
        darwin = self.darwin_archive
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
        payload = self.windows_archive
        wrong_name = "locklark-1.0.0-windows-amd64.tar.gz"
        darwin = self.darwin_archive
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
        windows = self.windows_archive
        wrong_name = f"locklark-{VERSION}-darwin-arm64.tar.gz"
        payload = self.darwin_archive
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
        windows = self.windows_archive
        darwin = self.darwin_archive
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
                payload = self.windows_archive
                self.release.add_asset(
                    assets, PLATFORM_ARCHIVE["windows-amd64"], payload
                )
                darwin = self.darwin_archive
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
        payload = self.windows_archive
        darwin = self.darwin_archive
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

    def test_malformed_archive_content_is_rejected(self) -> None:
        executable = self.go.windows()
        cases = {
            "duplicate": [
                {"name": WINDOWS_EXECUTABLE, "data": executable, "mode": 0o755},
                {"name": WINDOWS_EXECUTABLE, "data": executable, "mode": 0o755},
            ],
            "traversal": [
                {"name": "../Locklark.exe", "data": executable, "mode": 0o755}
            ],
            "link-escape": [
                {
                    "name": WINDOWS_EXECUTABLE,
                    "type": "symlink",
                    "linkname": "../../outside",
                }
            ],
            "file-child": [
                {"name": WINDOWS_EXECUTABLE, "data": executable, "mode": 0o755},
                {
                    "name": WINDOWS_EXECUTABLE + "/child",
                    "data": b"child",
                    "mode": 0o644,
                },
            ],
        }
        archives = {
            name: self.go.windows_archive(entries=entries)
            for name, entries in cases.items()
        }
        archives["oversized"] = self.go.oversized_tar_gz(
            WINDOWS_EXECUTABLE, (512 << 20) + 1
        )
        for name, windows in archives.items():
            with self.subTest(case=name):
                assets = self.release.assets()
                darwin = self.darwin_archive
                self.release.add_asset(
                    assets, PLATFORM_ARCHIVE["windows-amd64"], windows
                )
                self.release.add_asset(
                    assets, PLATFORM_ARCHIVE["darwin-universal"], darwin
                )
                self.release.add_installer_assets(assets)
                self.release.write_manifest(assets, "windows-amd64", windows)
                self.release.write_manifest(assets, "darwin-universal", darwin)

                result = self.release.run(assets)
                self.assert_rejected(result, assets)
                self.assertIn("windows-amd64 archive content identity", result.stderr)

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
                payload = self.windows_archive
                darwin = self.darwin_archive
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
