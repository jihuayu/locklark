"""Output directory safety for preparation publication."""

from __future__ import annotations

from pathlib import Path

from . import allowlist
from . import receipt as receipt_module
from .errors import ReleaseError
from .receiptcheck import verify_prepared_pair

EXTENSION_RELATIVE = "browser-extension"


def _fail(message: str) -> None:
    raise ReleaseError(message)


def _inside(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def known_names() -> set[str]:
    names: set[str] = set()
    for product in allowlist.PRODUCTS:
        names.update(receipt_module.artifact_names(product))
    return names


def resolve_output(root: Path, raw: str) -> Path:
    """Validate the explicit output directory; never infer one."""
    if not raw:
        _fail("an explicit --output directory is required")
    target = Path(raw)
    if not target.is_absolute():
        _fail("--output must be an absolute path")
    if target.name in ("", ".", ".."):
        _fail("--output must name a directory")
    root = Path(root).resolve()
    extension = (root / EXTENSION_RELATIVE).resolve()
    resolved = target.resolve(strict=False)
    for candidate in (target, resolved):
        if candidate == extension or _inside(candidate, extension):
            _fail("--output must be outside the browser-extension source/build tree")
        if candidate == root or candidate in root.parents:
            _fail("--output must not be the repository root or its ancestor")
    parent = target.parent
    if not parent.is_dir() or parent.is_symlink():
        _fail("--output parent must exist and not be a symlink")
    if target.exists() or target.is_symlink():
        if target.is_symlink():
            _fail("--output is a symlink")
        if not target.is_dir():
            _fail("--output exists and is not a directory")
    return target


def prepare_output_dir(target: Path) -> Path:
    """Create the output directory with a private mode when it is absent."""
    if not target.exists():
        try:
            target.mkdir(mode=0o700)
        except OSError:
            _fail("--output directory could not be created")
    return target


def check_unrelated(output_dir: Path) -> None:
    """Refuse an output directory holding anything but preparation artifacts."""
    try:
        names = {entry.name for entry in Path(output_dir).iterdir()}
    except OSError:
        _fail("--output directory cannot be listed")
    if names - known_names():
        _fail("--output contains unrelated files; refusing to overwrite")


def validate_existing_pairs(
    output_dir: Path, version: str, target_product: str
) -> None:
    """Verify every other product pair, and refuse any incomplete one.

    The target product is excluded because `reuse.publish_or_reuse` owns that
    decision: it can safely complete a matching crash-orphan ZIP and refuses
    every other target state.
    """
    for product in allowlist.PRODUCTS:
        if product == target_product:
            continue
        zip_name, receipt_name = receipt_module.artifact_names(product)
        zip_path = Path(output_dir) / zip_name
        receipt_path = Path(output_dir) / receipt_name
        has_zip = zip_path.exists() or zip_path.is_symlink()
        has_receipt = receipt_path.exists() or receipt_path.is_symlink()
        if not has_zip and not has_receipt:
            continue
        for path in (zip_path, receipt_path):
            if path.is_symlink():
                _fail("existing output artifact is a symlink")
            if path.exists() and not path.is_file():
                _fail("existing output artifact is not a regular file")
        if has_zip != has_receipt:
            _fail("existing output has an incomplete preparation")
        verify_prepared_pair(output_dir, product, version)
