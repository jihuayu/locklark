"""Build the deterministic public preparation receipt (never a signature)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from . import allowlist, zipbuild
from .bundle import read_regular_file
from .version import metadata_bytes

SCHEMA = "locklark-browser-extension-unsigned-receipt/v2"
TOOL_PATH = "scripts/browserrelease"
BUILD_SCRIPT_RELATIVE = "browser-extension/build.js"
VERSION_METADATA_RELATIVE = "browser-extension/release-version.json"


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def artifact_names(product: str) -> tuple[str, str]:
    return (
        f"locklark-browser-extension-{product}-unsigned.zip",
        f"locklark-browser-extension-{product}-unsigned.receipt.json",
    )


def build_receipt(
    root: Path,
    product: str,
    version: str,
    source_commit: str,
    files: dict[str, bytes],
    zip_bytes: bytes,
) -> dict:
    """Assemble the canonical receipt; no time, path, host or env values."""
    manifest = json.loads(files[allowlist.MANIFEST_FILE].decode("utf-8"))
    artifact_name = artifact_names(product)[0]
    return {
        "schema": SCHEMA,
        "tool": TOOL_PATH,
        "product": product,
        "unsigned": True,
        "signed": False,
        "version": version,
        "identity": allowlist.identity_for(product),
        "source_commit": source_commit,
        "artifact": {
            "name": artifact_name,
            "format": zipbuild.ZIP_FORMAT,
            "entry_timestamp": zipbuild.ZIP_TIMESTAMP_TEXT,
            "entry_mode": zipbuild.ZIP_MODE_TEXT,
            "size": len(zip_bytes),
            "sha256": sha256_hex(zip_bytes),
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
                "sha256": sha256_hex(files[name]),
            }
            for name in allowlist.entries_for(product)
        ],
        "generator": {
            "path": BUILD_SCRIPT_RELATIVE,
            "sha256": sha256_hex(
                read_regular_file(Path(root) / BUILD_SCRIPT_RELATIVE, "build script")
            ),
            "command": ["node", "build.js", product],
            "cwd": "browser-extension",
        },
        "version_metadata": {
            "path": VERSION_METADATA_RELATIVE,
            "sha256": sha256_hex(metadata_bytes(root)),
        },
    }


def receipt_bytes(receipt: dict) -> bytes:
    """Serialize canonically: sorted keys, ASCII, stable trailing newline."""
    return (
        json.dumps(receipt, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    ).encode("utf-8")
