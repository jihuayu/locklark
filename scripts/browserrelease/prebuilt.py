"""Strictly consume a real browserrelease v2 pair plus its unpacked build."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from . import allowlist, bundle, receipt as receipt_module, source, zipbuild
from .errors import ReleaseError
from .receiptcheck import verify_prepared_pair
from .version import load_release_version, metadata_bytes

ROOT = Path(__file__).resolve().parents[2]
ERROR = "prebuilt browser extension input rejected"


def _fail() -> None:
    raise ReleaseError(ERROR)


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _verify(product: str, prepared_dir: Path, dist_dir: Path, root: Path) -> dict:
    if product not in allowlist.PRODUCTS:
        _fail()
    root = Path(root)
    version = load_release_version(root)
    head = source.source_commit(root)
    files, zip_bytes, prepared, _ = verify_prepared_pair(
        Path(prepared_dir), product, version
    )
    if prepared.get("source_commit") != head:
        _fail()
    generator = prepared.get("generator")
    if not isinstance(generator, dict) or generator != {
        "path": receipt_module.BUILD_SCRIPT_RELATIVE,
        "sha256": _digest(
            bundle.read_regular_file(
                root / receipt_module.BUILD_SCRIPT_RELATIVE, "build script"
            )
        ),
        "command": ["node", "build.js", product],
        "cwd": "browser-extension",
    }:
        _fail()
    version_metadata = prepared.get("version_metadata")
    if not isinstance(version_metadata, dict) or version_metadata != {
        "path": receipt_module.VERSION_METADATA_RELATIVE,
        "sha256": _digest(metadata_bytes(root)),
    }:
        _fail()
    rebuilt = bundle.read_bundle(Path(dist_dir), product, version)
    if rebuilt != files:
        _fail()
    if zipbuild.build_zip(allowlist.entries_for(product), rebuilt) != zip_bytes:
        _fail()
    # The receipt and ZIP can agree while the committed build inputs drifted.
    # Compare every copied static source byte, including Safari's helper.
    for name in allowlist.entries_for(product):
        if name == allowlist.MANIFEST_FILE:
            continue
        source_bytes = bundle.read_regular_file(
            root / "browser-extension" / name, "extension source"
        )
        if source_bytes != rebuilt[name]:
            _fail()
    return {
        "product": product,
        "version": version,
        "source_commit": head,
        "identity": allowlist.identity_for(product),
        "entries": len(rebuilt),
        "zip_sha256": _digest(zip_bytes),
    }


def verify_prebuilt(product: str, prepared_dir: Path, dist_dir: Path, root: Path = ROOT) -> dict:
    """Return fixed metadata only after every strict consumer check passes."""
    try:
        return _verify(product, prepared_dir, dist_dir, root)
    except ReleaseError:
        raise ReleaseError(ERROR) from None
    except Exception:
        raise ReleaseError(ERROR) from None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify a real browserrelease pair against its unpacked dist."
    )
    parser.add_argument("--product", required=True, choices=allowlist.PRODUCTS)
    parser.add_argument("--prepared-dir", required=True)
    parser.add_argument("--dist", required=True)
    parser.add_argument("--root", default=str(ROOT))
    args = parser.parse_args(argv)
    try:
        summary = verify_prebuilt(
            args.product, Path(args.prepared_dir), Path(args.dist), Path(args.root)
        )
    except ReleaseError as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    print("PASS: verified prebuilt browser extension")
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
