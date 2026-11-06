"""Shared physical acceptance configuration; never echo rejected input."""
import re


def validate_test_bundle_base(value):
    if not isinstance(value, str) or len(value) > 200 or not re.fullmatch(r"(?:[A-Za-z][A-Za-z0-9-]*\.){2,}locklark\.acceptance", value, flags=re.ASCII):
        raise ValueError("physical acceptance requires an explicit test-only bundle base")
    return value


def validate_runner_bundle(value):
    suffix = ".uitests.xctrunner"
    if not isinstance(value, str) or not value.endswith(suffix):
        raise ValueError("physical acceptance requires the exact test runner bundle")
    return validate_test_bundle_base(value[:-len(suffix)])


def validate_device_id(value):
    patterns = [r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{16}", r"[0-9A-Fa-f]{40}", r"[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}"]
    if not isinstance(value, str) or not any(re.fullmatch(pattern, value, flags=re.ASCII) for pattern in patterns):
        raise ValueError("physical acceptance requires an exact device identifier")
    return value


def validate_team_id(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Z0-9]{10}", value, flags=re.ASCII):
        raise ValueError("physical acceptance requires a configured signing team")
    return value


def require_fresh_test_apps(payload, base):
    validate_test_bundle_base(base)
    apps = payload.get("result", {}).get("apps") if isinstance(payload, dict) else None
    if not isinstance(apps, list):
        raise ValueError("device application inventory is unavailable")
    for app in apps:
        if not isinstance(app, dict) or not isinstance(app.get("bundleIdentifier"), str):
            raise ValueError("device application inventory is unavailable")
        identifier = app["bundleIdentifier"]
        if identifier == base or identifier.startswith(base + "."):
            raise ValueError("test application already exists; choose a fresh explicit test bundle")
