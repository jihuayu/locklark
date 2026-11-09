"""Validate one generated manifest against the fixed public product contract."""

from __future__ import annotations

import base64
import hashlib

from . import allowlist, policy
from .errors import ReleaseError


def _fail(message: str) -> None:
    raise ReleaseError(message)


def _exact(actual, expected, label: str) -> None:
    if actual != expected:
        _fail(f"{label} does not match the allowed release identity")


def chrome_id_from_key(key: str) -> str:
    try:
        der = base64.b64decode(key, validate=True)
    except (ValueError, TypeError):
        _fail("Chromium manifest key is not valid base64")
    digest = hashlib.sha256(der).hexdigest()[:32]
    return "".join(chr(ord("a") + int(character, 16)) for character in digest)


def validate_manifest(manifest: object, product: str, version: str) -> dict:
    """Accept only the fixed product identity, permissions and version."""
    if product not in allowlist.PRODUCTS:
        _fail("unsupported product")
    if not isinstance(manifest, dict):
        _fail("manifest is not an object")
    forbidden = set(manifest) & allowlist.FORBIDDEN_TOP_LEVEL
    if forbidden:
        _fail("manifest contains a forbidden capability surface")
    if set(manifest) != policy.EXPECTED_TOP_LEVEL[product]:
        _fail("manifest contains unsupported top-level fields")

    if type(manifest["manifest_version"]) is not int or manifest["manifest_version"] != 3:
        _fail("manifest_version must be 3")
    _exact(manifest["name"], policy.EXPECTED_NAME, "extension name")
    # The manifest must carry the single central version unchanged.
    _exact(manifest["version"], version, "extension version")
    _exact(manifest["description"], policy.EXPECTED_DESCRIPTION, "extension description")

    permissions = manifest["permissions"]
    if (
        not isinstance(permissions, list)
        or not all(isinstance(item, str) for item in permissions)
        or len(permissions) != len(set(permissions))
        or set(permissions) & allowlist.FORBIDDEN_PERMISSIONS
        or set(permissions) != policy.EXPECTED_PERMISSIONS[product]
    ):
        _fail("manifest permissions do not match the allowed product set")
    _exact(
        manifest["host_permissions"],
        policy.EXPECTED_HOST_PERMISSIONS,
        "host permissions",
    )
    _exact(
        manifest["content_scripts"],
        policy.EXPECTED_CONTENT_SCRIPTS,
        "content-script world/frame policy",
    )
    _exact(manifest["action"], policy.EXPECTED_ACTION, "action")
    _exact(manifest["options_ui"], policy.EXPECTED_OPTIONS, "options_ui")
    _exact(
        manifest["content_security_policy"],
        policy.EXPECTED_CSP,
        "content security policy",
    )

    commands = manifest["commands"]
    if not isinstance(commands, dict):
        _fail("commands is not an object")
    if product == "firefox":
        _exact(
            commands,
            {
                "_execute_action": {
                    "description": policy.EXPECTED_ACTION_COMMAND["description"]
                },
                **policy.EXPECTED_COMMON_COMMANDS,
            },
            "commands",
        )
    else:
        _exact(
            commands,
            {
                "_execute_action": policy.EXPECTED_ACTION_COMMAND,
                **policy.EXPECTED_COMMON_COMMANDS,
            },
            "commands",
        )
    _exact(manifest["background"], policy.EXPECTED_BACKGROUND[product], "background")

    if product == "chromium":
        _exact(manifest["key"], allowlist.CHROMIUM_KEY, "Chromium public key")
        if chrome_id_from_key(manifest["key"]) != allowlist.CHROMIUM_ID:
            _fail("Chromium extension ID does not match the fixed public key")
        _exact(
            manifest["minimum_chrome_version"],
            allowlist.CHROMIUM_MIN_VERSION,
            "minimum Chrome version",
        )
    elif product == "firefox":
        _exact(
            manifest["browser_specific_settings"],
            {
                "gecko": {
                    "id": allowlist.FIREFOX_ID,
                    "strict_min_version": allowlist.FIREFOX_MIN_VERSION,
                    "data_collection_permissions": {"required": ["none"]},
                }
            },
            "Firefox browser identity",
        )
    else:
        # Safari must stay free of Chromium keys and Gecko settings: identity is
        # the containing app's bundle identifier, not manifest metadata.
        if "key" in manifest or "browser_specific_settings" in manifest:
            _fail("Safari manifest must not carry Chromium or Gecko identity")
    return manifest
