"""Reuse, complete or refuse an output directory without overwriting it."""

from __future__ import annotations

from pathlib import Path

from . import publish, receipt as receipt_module, zipverify
from .bundle import read_regular_file
from .errors import ReleaseError
from .receiptcheck import verify_prepared_pair

MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_ATTEMPTS = 3


def publish_or_reuse(
    output_dir: Path,
    product: str,
    version: str,
    zip_bytes: bytes,
    payload: bytes,
) -> str:
    """Return "prepared", "completed" or "existing"; never overwrite a name.

    - complete pair: re-verified against its receipt; identical bytes are
      reused, anything else refuses;
    - ZIP without receipt (crash orphan): completed only when the owner file is
      a regular, non-symlink ZIP whose bytes equal the current preparation;
      a tampered or unrelated orphan is left untouched and refused;
    - receipt without ZIP: refused, because the ZIP cannot be reconstructed
      without replacing an owner-visible artifact;
    - nothing present: both names are created with non-replacing links.
    """
    if len(zip_bytes) > MAX_ARCHIVE_BYTES:
        raise ReleaseError("prepared archive exceeds the ZIP size budget")
    zip_name, receipt_name = receipt_module.artifact_names(product)
    zip_path = Path(output_dir) / zip_name
    receipt_path = Path(output_dir) / receipt_name
    for _ in range(MAX_ATTEMPTS):
        for path in (zip_path, receipt_path):
            if path.is_symlink():
                raise ReleaseError("existing output artifact is a symlink")
            if path.exists() and not path.is_file():
                raise ReleaseError("existing output artifact is not a regular file")
        zip_exists = zip_path.exists()
        receipt_exists = receipt_path.exists()
        if zip_exists and receipt_exists:
            _, existing_zip, _, existing_payload = verify_prepared_pair(
                output_dir, product, version
            )
            if existing_zip == zip_bytes and existing_payload == payload:
                return "existing"
            raise ReleaseError(
                "existing output differs from the current preparation; "
                "refusing to overwrite"
            )
        if receipt_exists and not zip_exists:
            raise ReleaseError(
                "existing output has a receipt without its ZIP; "
                "owner recovery is required and nothing was overwritten"
            )
        if zip_exists:
            orphan = read_regular_file(
                zip_path, "existing orphan artifact", MAX_ARCHIVE_BYTES
            )
            if orphan != zip_bytes:
                raise ReleaseError(
                    "orphan ZIP does not match the current preparation; "
                    "refusing to overwrite it"
                )
            zipverify.verify_zip(orphan, product)
            try:
                publish.publish_one(output_dir, receipt_name, payload)
            except publish.PublicationRace:
                continue
            return "completed"
        try:
            publish.publish_new(output_dir, zip_name, zip_bytes, receipt_name, payload)
        except publish.PublicationRace:
            continue
        return "prepared"
    raise ReleaseError("output publication raced repeatedly; refusing")
