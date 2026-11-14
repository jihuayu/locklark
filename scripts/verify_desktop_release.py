#!/usr/bin/env python3
"""Verify a Locklark desktop draft release and rebuild SHA256SUMS.

The release workflow runs this after the Windows and macOS jobs upload to
the same draft. It checks that each MyGo update manifest names the exact
archive for its platform and version, verifies the manifest's Ed25519
signature, rejects unexpected assets, and writes a complete SHA256SUMS.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import subprocess
import sys
import tempfile
import urllib.parse
from pathlib import Path


# mygo.config.ts sets slug=locklark and the release workflow builds the two
# targets below. MyGo names update archives "<slug>-<version>-<target>.tar.gz"
# and deltas "<slug>-<from>-to-<version>-<target>.delta" (see
# cmd/mygo/updates.go in github.com/egoist/mygo v0.7.4). The manifest URL is
# checked against this exact name so a valid archive signed for one target
# cannot stand in for another, or for another version.
APP_SLUG = "locklark"
PLATFORMS = ("windows-amd64", "darwin-universal")
CHECKSUMS = "SHA256SUMS"
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")


def fail(message: str) -> None:
    raise SystemExit(f"release verification failed: {message}")


def expected_archive_name(version: str, platform: str) -> str:
    return f"{APP_SLUG}-{version}-{platform}.tar.gz"


def expected_delta_name(version: str, platform: str, previous: str) -> str:
    return f"{APP_SLUG}-{previous}-to-{version}-{platform}.delta"


def unique_object(pairs: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def read_manifest(path: Path) -> dict:
    try:
        data = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=unique_object
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        fail(f"cannot read {path.name}: {exc}")
    if not isinstance(data, dict):
        fail(f"{path.name} is not a JSON object")
    return data


def asset_name(url: object, label: str) -> str:
    if not isinstance(url, str) or not url:
        fail(f"{label} has no URL")
    try:
        parsed = urllib.parse.urlparse(url)
    except ValueError as exc:
        fail(f"{label} has an invalid asset URL: {exc}")
    name = urllib.parse.unquote(parsed.path.rsplit("/", 1)[-1])
    if not name or "/" in name or "\\" in name or "\x00" in name:
        fail(f"{label} has an invalid asset URL: {url}")
    return name


def sha256(path: Path) -> bytes:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.digest()


def verify_signature(public_key: bytes, digest: bytes, signature: bytes, label: str) -> None:
    with tempfile.TemporaryDirectory(prefix="locklark-release-verify-") as raw_dir:
        directory = Path(raw_dir)
        key_path = directory / "update-public.der"
        digest_path = directory / "digest.bin"
        signature_path = directory / "signature.bin"
        key_path.write_bytes(ED25519_SPKI_PREFIX + public_key)
        digest_path.write_bytes(digest)
        signature_path.write_bytes(signature)
        try:
            result = subprocess.run(
                [
                    "openssl",
                    "pkeyutl",
                    "-verify",
                    "-pubin",
                    "-inkey",
                    str(key_path),
                    "-keyform",
                    "DER",
                    "-rawin",
                    "-in",
                    str(digest_path),
                    "-sigfile",
                    str(signature_path),
                ],
                capture_output=True,
                text=True,
            )
        except FileNotFoundError:
            fail("openssl is required to verify update signatures")
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        fail(f"{label} signature does not verify: {detail}")


def validate_signed_asset(
    assets: Path,
    public_key: bytes,
    *,
    label: str,
    url: object,
    size: object,
    signature: object,
    expected_name: str,
) -> str:
    name = asset_name(url, label)
    if name != expected_name:
        fail(f"{label} names {name}, want {expected_name}")
    path = assets / name
    if not path.is_file():
        fail(f"{label} names a missing asset: {name}")
    if isinstance(size, bool) or not isinstance(size, int) or size <= 0:
        fail(f"{label} has an invalid size")
    actual_size = path.stat().st_size
    if actual_size != size:
        fail(f"{name} has {actual_size} bytes, but {label} says {size}")
    if not isinstance(signature, str):
        fail(f"{label} has no signature")
    try:
        raw_signature = base64.b64decode(signature, validate=True)
    except ValueError as exc:
        fail(f"{label} has an invalid base64 signature: {exc}")
    if len(raw_signature) != 64:
        fail(f"{label} signature has {len(raw_signature)} bytes, want 64")
    verify_signature(public_key, sha256(path), raw_signature, label)
    return name


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--assets", required=True, type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--public-key", required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    assets = args.assets.resolve()
    if not assets.is_dir():
        fail(f"{assets} is not a directory")
    try:
        public_key = base64.b64decode(args.public_key.strip(), validate=True)
    except ValueError as exc:
        fail(f"invalid updates.publicKey: {exc}")
    if len(public_key) != 32:
        fail(f"updates.publicKey has {len(public_key)} bytes, want 32")

    expected: set[str] = set()
    signed_assets: set[str] = set()
    for platform in PLATFORMS:
        manifest_name = f"update-{platform}.json"
        manifest_path = assets / manifest_name
        if not manifest_path.is_file():
            fail(f"missing {manifest_name}")
        manifest = read_manifest(manifest_path)
        manifest_version = manifest.get("version")
        if not isinstance(manifest_version, str) or manifest_version != args.version:
            fail(
                f"{manifest_name} is version {manifest_version!r}, "
                f"want {args.version!r}"
            )
        if not isinstance(manifest.get("notes"), str) or not manifest["notes"].strip():
            fail(f"{manifest_name} has no release notes")
        signed_assets.add(
            validate_signed_asset(
                assets,
                public_key,
                label=f"{platform} archive",
                url=manifest.get("url"),
                size=manifest.get("size"),
                signature=manifest.get("signature"),
                expected_name=expected_archive_name(args.version, platform),
            )
        )
        deltas = manifest.get("deltas", [])
        if not isinstance(deltas, list):
            fail(f"{manifest_name} has an invalid deltas list")
        for index, delta in enumerate(deltas):
            if (
                not isinstance(delta, dict)
                or not isinstance(delta.get("from"), str)
                or not delta["from"]
            ):
                fail(f"{manifest_name} delta {index} is invalid")
            signed_assets.add(
                validate_signed_asset(
                    assets,
                    public_key,
                    label=f"{platform} delta from {delta['from']}",
                    url=delta.get("url"),
                    size=delta.get("size"),
                    signature=delta.get("signature"),
                    expected_name=expected_delta_name(
                        args.version, platform, delta["from"]
                    ),
                )
            )
        expected.add(manifest_name)

    version = args.version
    required = {
        f"locklark-setup-{version}-amd64.exe",
        f"locklark-{version}.dmg",
        "install.ps1",
        "install.sh",
    }
    required.update(expected_archive_name(version, platform) for platform in PLATFORMS)
    expected.update(required)
    expected.update(signed_assets)

    actual = {path.name for path in assets.iterdir() if path.is_file()}
    missing = sorted(expected - actual)
    if missing:
        fail("missing required assets: " + ", ".join(missing))
    unexpected = sorted(actual - expected - {CHECKSUMS})
    if unexpected:
        fail("unexpected release assets: " + ", ".join(unexpected))

    checksummed = sorted(signed_assets | required)
    lines = [f"{sha256(assets / name).hex()}  {name}\n" for name in checksummed]
    (assets / CHECKSUMS).write_text("".join(lines), encoding="utf-8", newline="\n")
    print(
        f"verified {len(PLATFORMS)} signed update manifests, "
        f"{len(signed_assets)} signed archives/deltas, and {len(checksummed)} checksummed assets"
    )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
