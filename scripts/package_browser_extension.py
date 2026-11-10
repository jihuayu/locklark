#!/usr/bin/env python3
"""Build reproducible, unsigned preparation ZIPs for the Locklark extension.

This tool intentionally has no signing, publishing, network, credential, or
environment-discovery path. It runs the existing Node build with an argv list
(no shell), accepts only the extension's explicit product allowlist, validates
the generated manifest and its fixed browser identity, and writes deterministic
store ZIPs plus public SHA256 receipt metadata.

The produced ZIP is preparation evidence, not a signed Chrome Web Store, Edge
Addons, or Firefox AMO release.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXTENSION_DIR = ROOT / "browser-extension"
BUILD_SCRIPT = EXTENSION_DIR / "build.js"

PRODUCTS = ("chromium", "firefox")
PRODUCT_FILES = (
    "core.js",
    "content.js",
    "webauthn.js",
    "background.js",
    "popup.html",
    "popup.css",
    "popup.js",
    "options.html",
    "options.css",
    "options.js",
)
MANIFEST_FILE = "manifest.json"
ZIP_ENTRIES = (MANIFEST_FILE,) + PRODUCT_FILES

EXPECTED_NAME = "Locklark"
EXPECTED_VERSION = "0.1.0"
EXPECTED_DESCRIPTION = (
    "Passwords, automatic sign-in and passkeys with your native Locklark vault"
)
EXPECTED_HOST_PERMISSIONS = ["https://*/*"]
CHROMIUM_KEY = (
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1GcZFP4Yh8F3N5LELUw5UYy132r9"
    "ZQOdPGMR9yzJXc5KjBRCfPZm7ao/cAEkUeTcu3Pek/aBz+GCe0ntWBXIDlt7Z7q4rW7xtnI"
    "H7h01KVBoR5yh3sgF+89QEpF3KxOYMBIzh5fvpJ5KJzzDv4S/6jhYuernWOg7F6t38cZ1mT"
    "3+yvEecWa5z+Zuw3hDX8QWNdJGNp+809SOy+SiDYsv8kQ5ETf7cDrcREgzfFHj10J8AQlhE"
    "8yG5c89INXGy5HN45j2lwSdF+CoLf2l74Wm6QHDYQJCmgIrUZ9/wyMIIZdBwd+9c2MgsWV5"
    "YmHXRkje94JpCP/r9+ge6oLW93XnSwIDAQAB"
)
CHROMIUM_ID = "geldnhjapnackobgknocomedmjgphnpe"
FIREFOX_ID = "browser@locklark.local"
FIREFOX_MIN_VERSION = "153.0"
CHROMIUM_MIN_VERSION = "120"
EXPECTED_PERMISSIONS = {
    "chromium": frozenset(
        {
            "activeTab",
            "scripting",
            "nativeMessaging",
            "storage",
            "contextMenus",
            "idle",
            "notifications",
        }
    ),
    "firefox": frozenset(
        {
            "activeTab",
            "scripting",
            "nativeMessaging",
            "storage",
            "idle",
            "notifications",
        }
    ),
}
EXPECTED_CONTENT_SCRIPTS = [
    {
        "matches": ["https://*/*"],
        "js": ["core.js", "content.js"],
        "run_at": "document_start",
        "all_frames": True,
    },
    {
        "matches": ["https://*/*"],
        "js": ["webauthn.js"],
        "run_at": "document_start",
        "all_frames": False,
        "world": "MAIN",
    },
]
EXPECTED_CSP = {
    "extension_pages": "script-src 'self'; object-src 'none'",
}
EXPECTED_ACTION = {"default_popup": "popup.html"}
EXPECTED_OPTIONS = {"page": "options.html", "open_in_tab": True}
EXPECTED_COMMON_COMMANDS = {
    "autofill": {
        "suggested_key": {"default": "Ctrl+Shift+L", "mac": "Command+Shift+L"},
        "description": "填充当前页面登录或打开候选",
    },
    "lock": {
        "suggested_key": {"default": "Ctrl+Shift+U", "mac": "Command+Shift+U"},
        "description": "立即锁定 Locklark",
    },
}
EXPECTED_ACTION_COMMAND = {
    "suggested_key": {"default": "Ctrl+Shift+Y", "mac": "Command+Shift+Y"},
    "description": "打开 Locklark 弹窗",
}
COMMON_TOP_LEVEL = {
    "manifest_version",
    "name",
    "version",
    "description",
    "permissions",
    "host_permissions",
    "content_scripts",
    "action",
    "options_ui",
    "commands",
    "content_security_policy",
}
EXPECTED_TOP_LEVEL = {
    "chromium": COMMON_TOP_LEVEL
    | {"key", "minimum_chrome_version", "background"},
    "firefox": COMMON_TOP_LEVEL
    | {"background", "browser_specific_settings"},
}

ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
ZIP_FILE_MODE = 0o644
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_BUNDLE_BYTES = 32 * 1024 * 1024
MAX_RECEIPT_BYTES = 1024 * 1024
RECEIPT_SCHEMA = "locklark-browser-extension-unsigned-receipt/v1"
TOOL_NAME = "scripts/package_browser_extension.py"

REMOTE_ATTRIBUTE = re.compile(
    r"""(?is)\b(?:src|href)\s*=\s*["']\s*(?:https?:)?//"""
)
REMOTE_IMPORT = re.compile(
    r"""(?is)@import\s+(?:url\(\s*)?["']?\s*(?:https?:)?//"""
)
LOCAL_SCRIPT = re.compile(r"""(?is)<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']""")


class PackagingError(Exception):
    """Fixed, public-safe packaging refusal."""


def _fail(message: str) -> None:
    raise PackagingError(message)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _chrome_id_from_key(key: str) -> str:
    try:
        der = base64.b64decode(key, validate=True)
    except (ValueError, TypeError):
        _fail("Chromium manifest key is not valid base64")
    digest = hashlib.sha256(der).hexdigest()[:32]
    return "".join(chr(ord("a") + int(character, 16)) for character in digest)


def _exact(actual, expected, label: str) -> None:
    if actual != expected:
        _fail(f"{label} does not match the allowed release identity")


def _keys(manifest: dict, expected: set[str]) -> None:
    if not isinstance(manifest, dict):
        _fail("manifest is not an object")
    if set(manifest) != expected:
        _fail("manifest contains unsupported top-level fields")


def validate_manifest(manifest: object, product: str) -> dict:
    """Validate the generated manifest against the fixed product contract."""
    if product not in PRODUCTS:
        _fail("unsupported product")
    if not isinstance(manifest, dict):
        _fail("manifest is not an object")
    _keys(manifest, EXPECTED_TOP_LEVEL[product])

    if type(manifest["manifest_version"]) is not int or manifest["manifest_version"] != 3:
        _fail("manifest_version must be 3")
    _exact(manifest["name"], EXPECTED_NAME, "extension name")
    _exact(manifest["version"], EXPECTED_VERSION, "extension version")
    _exact(manifest["description"], EXPECTED_DESCRIPTION, "extension description")

    permissions = manifest["permissions"]
    if (
        not isinstance(permissions, list)
        or not all(isinstance(item, str) for item in permissions)
        or len(permissions) != len(set(permissions))
        or set(permissions) != EXPECTED_PERMISSIONS[product]
    ):
        _fail("manifest permissions do not match the allowed product set")
    _exact(manifest["host_permissions"], EXPECTED_HOST_PERMISSIONS, "host permissions")
    _exact(
        manifest["content_scripts"],
        EXPECTED_CONTENT_SCRIPTS,
        "content-script world/frame policy",
    )
    _exact(manifest["action"], EXPECTED_ACTION, "action")
    _exact(manifest["options_ui"], EXPECTED_OPTIONS, "options_ui")
    _exact(manifest["content_security_policy"], EXPECTED_CSP, "content security policy")

    commands = manifest["commands"]
    if not isinstance(commands, dict):
        _fail("commands is not an object")
    if product == "chromium":
        _exact(
            commands,
            {"_execute_action": EXPECTED_ACTION_COMMAND, **EXPECTED_COMMON_COMMANDS},
            "commands",
        )
        _exact(manifest["key"], CHROMIUM_KEY, "Chromium public key")
        if _chrome_id_from_key(manifest["key"]) != CHROMIUM_ID:
            _fail("Chromium extension ID does not match the fixed public key")
        _exact(
            manifest["minimum_chrome_version"],
            CHROMIUM_MIN_VERSION,
            "minimum Chrome version",
        )
        _exact(
            manifest["background"],
            {"service_worker": "background.js"},
            "Chromium background",
        )
    else:
        _exact(
            commands,
            {"_execute_action": {"description": EXPECTED_ACTION_COMMAND["description"]},
             **EXPECTED_COMMON_COMMANDS},
            "commands",
        )
        _exact(
            manifest["background"],
            {"scripts": ["core.js", "background.js"]},
            "Firefox background",
        )
        _exact(
            manifest["browser_specific_settings"],
            {
                "gecko": {
                    "id": FIREFOX_ID,
                    "strict_min_version": FIREFOX_MIN_VERSION,
                    "data_collection_permissions": {"required": ["none"]},
                }
            },
            "Firefox browser identity",
        )
    return manifest


def _read_regular_file(path: Path, label: str) -> bytes:
    try:
        before = path.lstat()
    except OSError:
        _fail(f"{label} is missing")
    if stat.S_ISLNK(before.st_mode):
        _fail(f"{label} is a symlink")
    if not stat.S_ISREG(before.st_mode):
        _fail(f"{label} is not a regular file")
    if before.st_size > MAX_FILE_BYTES:
        _fail(f"{label} exceeds the size limit")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        _fail(f"{label} cannot be opened safely")
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
            or opened.st_size > MAX_FILE_BYTES
        ):
            _fail(f"{label} changed while being read")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            data = handle.read(MAX_FILE_BYTES + 1)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(data) > MAX_FILE_BYTES:
        _fail(f"{label} exceeds the size limit")
    return data


def _scan_public_bundle(files: dict[str, bytes]) -> None:
    for name, data in files.items():
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            _fail(f"{name} is not UTF-8 public product source")
        lowered = text.lower()
        if "sourcemappingurl" in lowered:
            _fail(f"{name} references a source map")
        if name.endswith((".html", ".css")):
            if REMOTE_ATTRIBUTE.search(text) or REMOTE_IMPORT.search(text):
                _fail(f"{name} references a remote asset")
        if name.endswith(".html"):
            for source in LOCAL_SCRIPT.findall(text):
                if source not in PRODUCT_FILES:
                    _fail(f"{name} references a non-allowlisted script")
        if name.endswith(".js"):
            if re.search(r"(?<![A-Za-z0-9_$])eval\s*\(", text):
                _fail(f"{name} contains dynamic eval")
            if re.search(r"\bnew\s+Function\s*\(", text):
                _fail(f"{name} contains dynamic Function construction")


def read_bundle(build_dir: Path, product: str) -> dict[str, bytes]:
    """Read exactly the allowlisted product files and generated manifest."""
    try:
        directory = build_dir.lstat()
    except OSError:
        _fail("build output directory is missing")
    if stat.S_ISLNK(directory.st_mode) or not stat.S_ISDIR(directory.st_mode):
        _fail("build output directory is not a trusted directory")
    try:
        names = {entry.name for entry in build_dir.iterdir()}
    except OSError:
        _fail("build output directory cannot be listed")
    if names != set(ZIP_ENTRIES):
        _fail("build output contains files outside the submission allowlist")

    files: dict[str, bytes] = {}
    total = 0
    for name in ZIP_ENTRIES:
        files[name] = _read_regular_file(build_dir / name, f"build output {name}")
        total += len(files[name])
        if total > MAX_BUNDLE_BYTES:
            _fail("build output exceeds the bundle size limit")
    try:
        manifest = json.loads(files[MANIFEST_FILE].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        _fail("generated manifest is not valid UTF-8 JSON")
    validate_manifest(manifest, product)
    _scan_public_bundle(files)
    return files


def _inside(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _output_target(raw: str) -> Path:
    if not raw:
        _fail("an explicit --output directory is required")
    target = Path(raw)
    if not target.is_absolute():
        _fail("--output must be an absolute path")
    if target.name in ("", ".", ".."):
        _fail("--output must name a directory")
    resolved = target.resolve(strict=False)
    extension = EXTENSION_DIR.resolve()
    root = ROOT.resolve()
    for candidate in (target, resolved):
        if candidate == extension or _inside(candidate, extension):
            _fail("--output must be outside the browser-extension source/build tree")
        if candidate == root or candidate in root.parents:
            _fail("--output must not be the repository root or its ancestor")
    return target


def _check_prior_receipt(
    output: Path, product: str, zip_name: str, receipt_name: str
) -> None:
    zip_path = output / zip_name
    receipt_path = output / receipt_name
    if zip_path.is_symlink() or receipt_path.is_symlink():
        _fail("existing output artifact is a symlink")
    if not zip_path.is_file() or not receipt_path.is_file():
        _fail("existing output contains only part of a previous preparation")
    raw = _read_regular_file(receipt_path, "existing receipt")
    if len(raw) > MAX_RECEIPT_BYTES:
        _fail("existing receipt exceeds the size limit")
    try:
        receipt = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        _fail("existing receipt is not valid JSON")
    if (
        not isinstance(receipt, dict)
        or receipt.get("schema") != RECEIPT_SCHEMA
        or receipt.get("tool") != TOOL_NAME
        or receipt.get("product") != product
        or not isinstance(receipt.get("artifact"), dict)
        or receipt["artifact"].get("name") != zip_name
        or not isinstance(receipt["artifact"].get("sha256"), str)
        or not re.fullmatch(r"[0-9a-f]{64}", receipt["artifact"]["sha256"])
    ):
        _fail("existing receipt is not a recognized preparation")
    digest = hashlib.sha256()
    size = 0
    try:
        with zip_path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
                size += len(chunk)
    except OSError:
        _fail("existing preparation ZIP cannot be read")
    if digest.hexdigest() != receipt["artifact"]["sha256"]:
        _fail("existing preparation ZIP does not match its receipt")
    if receipt["artifact"].get("size") != size:
        _fail("existing preparation ZIP size does not match its receipt")


def _artifact_names(product: str) -> tuple[str, str]:
    return (
        f"locklark-browser-extension-{product}-unsigned.zip",
        f"locklark-browser-extension-{product}-unsigned.receipt.json",
    )


def prepare_output(raw: str, product: str) -> Path:
    output = _output_target(raw)
    extension = EXTENSION_DIR.resolve()
    if output == extension or _inside(output.resolve(strict=False), extension):
        _fail("--output must be outside the browser-extension source/build tree")
    if output.exists():
        if output.is_symlink():
            _fail("--output is a symlink")
        if not output.is_dir():
            _fail("--output exists and is not a directory")
        entries = {entry.name for entry in output.iterdir()}
        if entries:
            allowed = set()
            for candidate in PRODUCTS:
                allowed.update(_artifact_names(candidate))
            if entries - allowed:
                _fail("--output contains unrelated files; refusing to overwrite")
            for candidate in PRODUCTS:
                names = set(_artifact_names(candidate))
                present = entries & names
                if present and present != names:
                    _fail("existing output contains only part of a previous preparation")
                if present:
                    _check_prior_receipt(output, candidate, *_artifact_names(candidate))
    else:
        parent = output.parent
        if not parent.is_dir() or parent.is_symlink():
            _fail("--output parent must exist and not be a symlink")
        try:
            output.mkdir(mode=0o700)
        except OSError:
            _fail("--output directory could not be created")
    return output


def _preflight_source() -> None:
    if EXTENSION_DIR.is_symlink() or not EXTENSION_DIR.is_dir():
        _fail("resolved browser-extension directory is not trusted")
    _read_regular_file(BUILD_SCRIPT, "browser-extension/build.js")
    for name in PRODUCT_FILES:
        _read_regular_file(EXTENSION_DIR / name, f"browser-extension/{name}")
    dist = EXTENSION_DIR / "dist"
    if dist.exists():
        if dist.is_symlink() or not dist.is_dir():
            _fail("browser-extension/dist is not a trusted build directory")
        for product in PRODUCTS:
            mode_dir = dist / product
            if not mode_dir.exists():
                continue
            if mode_dir.is_symlink() or not mode_dir.is_dir():
                _fail("browser-extension/dist product path is not trusted")
            for entry in mode_dir.iterdir():
                if entry.is_symlink():
                    _fail("browser-extension/dist contains a symlink")


def _run_build(product: str) -> None:
    command = ["node", "build.js", product]
    try:
        completed = subprocess.run(
            command,
            cwd=EXTENSION_DIR.resolve(),
            shell=False,
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired):
        _fail("node build.js could not be run")
    if completed.returncode != 0:
        _fail("node build.js failed")


def _zip_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, ZIP_TIMESTAMP)
    info.compress_type = zipfile.ZIP_STORED
    info.create_system = 3
    info.create_version = 20
    info.extract_version = 20
    info.external_attr = (stat.S_IFREG | ZIP_FILE_MODE) << 16
    info.internal_attr = 0
    info.flag_bits = 0
    info.extra = b""
    info.comment = b""
    return info


def build_zip(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED, allowZip64=False) as archive:
        for name in ZIP_ENTRIES:
            archive.writestr(_zip_info(name), files[name])
    return buffer.getvalue()


def _receipt(
    product: str,
    files: dict[str, bytes],
    zip_bytes: bytes,
    artifact_name: str,
) -> dict:
    manifest = json.loads(files[MANIFEST_FILE])
    identity = (
        f"chrome-extension://{CHROMIUM_ID}/"
        if product == "chromium"
        else FIREFOX_ID
    )
    return {
        "schema": RECEIPT_SCHEMA,
        "tool": TOOL_NAME,
        "product": product,
        "unsigned": True,
        "signed": False,
        "artifact": {
            "name": artifact_name,
            "sha256": _sha256(zip_bytes),
            "size": len(zip_bytes),
            "format": "ZIP_STORED",
            "entry_timestamp": "1980-01-01T00:00:00Z",
            "entry_mode": "0644",
        },
        "manifest": {
            "name": manifest["name"],
            "version": manifest["version"],
            "manifest_version": manifest["manifest_version"],
            "permissions": sorted(manifest["permissions"]),
            "host_permissions": manifest["host_permissions"],
            "identity": identity,
            "minimum_chrome_version": manifest.get("minimum_chrome_version"),
            "strict_min_version": (
                manifest.get("browser_specific_settings", {})
                .get("gecko", {})
                .get("strict_min_version")
            ),
        },
        "generator": {
            "path": "browser-extension/build.js",
            "sha256": _sha256(_read_regular_file(BUILD_SCRIPT, "browser-extension/build.js")),
            "command": ["node", "build.js", product],
            "cwd": "browser-extension",
        },
        "entries": [
            {"name": name, "sha256": _sha256(files[name]), "size": len(files[name])}
            for name in ZIP_ENTRIES
        ],
    }


def _atomic_write(path: Path, data: bytes) -> None:
    if path.is_symlink():
        _fail(f"{path.name} is a symlink")
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o644)
        if path.is_symlink():
            _fail(f"{path.name} is a symlink")
        os.replace(temporary, path)
        temporary = ""
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass


def package(product: str, output: str) -> dict:
    if product not in PRODUCTS:
        _fail("unsupported product")
    output_dir = prepare_output(output, product)
    _preflight_source()
    _run_build(product)
    files = read_bundle(EXTENSION_DIR / "dist" / product, product)
    zip_bytes = build_zip(files)
    artifact_name = f"locklark-browser-extension-{product}-unsigned.zip"
    receipt_name = f"locklark-browser-extension-{product}-unsigned.receipt.json"
    receipt = _receipt(product, files, zip_bytes, artifact_name)
    receipt_bytes = (
        json.dumps(receipt, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    ).encode("utf-8")
    _atomic_write(output_dir / artifact_name, zip_bytes)
    _atomic_write(output_dir / receipt_name, receipt_bytes)
    return {
        "product": product,
        "artifact": artifact_name,
        "receipt": receipt_name,
        "sha256": receipt["artifact"]["sha256"],
        "size": receipt["artifact"]["size"],
        "entries": [entry["name"] for entry in receipt["entries"]],
        "unsigned": True,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Prepare deterministic unsigned browser-extension submission ZIPs "
            "and public receipts. This does not sign or publish anything."
        )
    )
    parser.add_argument("--product", required=True, choices=PRODUCTS)
    parser.add_argument("--output", required=True, help="existing parent; absolute directory")
    args = parser.parse_args(argv)
    try:
        summary = package(args.product, args.output)
    except PackagingError as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    print("PASS: prepared unsigned release artifact")
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
