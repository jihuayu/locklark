"""Fixed expected manifest contract per product (public reviewable facts)."""

from __future__ import annotations

EXPECTED_NAME = "Locklark"
EXPECTED_DESCRIPTION = (
    "Passwords, automatic sign-in and passkeys with your native Locklark vault"
)
EXPECTED_HOST_PERMISSIONS = ["https://*/*"]
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
EXPECTED_CSP = {"extension_pages": "script-src 'self'; object-src 'none'"}
EXPECTED_ACTION = {"default_popup": "popup.html"}
EXPECTED_OPTIONS = {"page": "options.html", "open_in_tab": True}
EXPECTED_ACTION_COMMAND = {
    "suggested_key": {"default": "Ctrl+Shift+Y", "mac": "Command+Shift+Y"},
    "description": "打开 Locklark 弹窗",
}
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
_NATIVE_PERMISSIONS = frozenset(
    {"activeTab", "scripting", "nativeMessaging", "storage"}
)
EXPECTED_PERMISSIONS = {
    "chromium": _NATIVE_PERMISSIONS | {"contextMenus", "idle", "notifications"},
    "firefox": _NATIVE_PERMISSIONS | {"idle", "notifications"},
    "safari": _NATIVE_PERMISSIONS,
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
    "chromium": COMMON_TOP_LEVEL | {"key", "minimum_chrome_version", "background"},
    "firefox": COMMON_TOP_LEVEL | {"background", "browser_specific_settings"},
    "safari": COMMON_TOP_LEVEL | {"background"},
}
EXPECTED_BACKGROUND = {
    "chromium": {"service_worker": "background.js"},
    "firefox": {"scripts": ["core.js", "background.js"]},
    "safari": {"scripts": ["safari-native-port.js", "core.js", "background.js"]},
}
