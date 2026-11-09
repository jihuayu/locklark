"""Prepare and verify deterministic unsigned browser-extension ZIPs."""

from __future__ import annotations

from pathlib import Path

from . import allowlist, build, output, receipt as receipt_module, reuse, source
from .bundle import read_bundle
from .errors import ReleaseError
from .receipt import build_receipt, receipt_bytes
from .receiptcheck import verify_prepared_pair
from .version import load_release_version
from .zipbuild import build_zip

ROOT = Path(__file__).resolve().parents[2]


def _summary(product: str, version: str, status: str, receipt: dict) -> dict:
    return {
        "product": product,
        "version": version,
        "identity": allowlist.identity_for(product),
        "source_commit": receipt["source_commit"],
        "artifact": receipt["artifact"]["name"],
        "receipt": receipt_module.artifact_names(product)[1],
        "sha256": receipt["artifact"]["sha256"],
        "size": receipt["artifact"]["size"],
        "entries": [entry["name"] for entry in receipt["entries"]],
        "unsigned": True,
        "status": status,
    }


def prepare(
    product: str,
    target: str,
    root: Path = ROOT,
    runner=build.run_build,
) -> dict:
    """Build the real output, package it deterministically and publish safely."""
    if product not in allowlist.PRODUCTS:
        raise ReleaseError("unsupported product")
    root = Path(root)
    version = load_release_version(root)
    source.require_clean_source(root)
    output_dir = output.resolve_output(root, target)
    output.prepare_output_dir(output_dir)
    output.check_unrelated(output_dir)
    output.validate_existing_pairs(output_dir, version, product)
    build.check_build_paths(root, product)
    runner(root, product)
    build.verify_build_paths(root, product)
    files = read_bundle(
        root / build.BUILD_DIRECTORY / "dist" / product, product, version
    )
    zip_bytes = build_zip(allowlist.entries_for(product), files)
    if len(zip_bytes) > reuse.MAX_ARCHIVE_BYTES:
        raise ReleaseError("prepared archive exceeds the ZIP size budget")
    commit = source.source_commit(root)
    receipt = build_receipt(root, product, version, commit, files, zip_bytes)
    status = reuse.publish_or_reuse(
        output_dir, product, version, zip_bytes, receipt_bytes(receipt)
    )
    return _summary(product, version, status, receipt)


def verify(product: str, target: str, root: Path = ROOT) -> dict:
    """Verify an existing pair against the receipt and the fixed policy."""
    if product not in allowlist.PRODUCTS:
        raise ReleaseError("unsupported product")
    version = load_release_version(root)
    output_dir = output.resolve_output(root, target)
    if not output_dir.is_dir():
        raise ReleaseError("--output directory is missing")
    _, _, receipt, _ = verify_prepared_pair(output_dir, product, version)
    return _summary(product, version, "verified", receipt)
