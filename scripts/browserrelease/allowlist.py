"""Exact per-product submission allowlist and fixed public browser identities."""

from __future__ import annotations

BASE_FILES = (
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

# Safari is the only product with an extra shipped helper: the containing app's
# native-port shim loaded before core.js/background.js. Chromium and Firefox
# keep the ten product files above plus the generated manifest.
PRODUCT_EXTRA_FILES = {
    "chromium": (),
    "firefox": (),
    "safari": ("safari-native-port.js",),
}
PRODUCTS = ("chromium", "firefox", "safari")

CHROMIUM_ID = "geldnhjapnackobgknocomedmjgphnpe"
FIREFOX_ID = "browser@locklark.local"
SAFARI_ID = "org.locklark.browser.safari.Extension"

IDENTITIES = {
    "chromium": f"chrome-extension://{CHROMIUM_ID}/",
    "firefox": FIREFOX_ID,
    "safari": SAFARI_ID,
}

CHROMIUM_KEY = (
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1GcZFP4Yh8F3N5LELUw5UYy132r9"
    "ZQOdPGMR9yzJXc5KjBRCfPZm7ao/cAEkUeTcu3Pek/aBz+GCe0ntWBXIDlt7Z7q4rW7xtnI"
    "H7h01KVBoR5yh3sgF+89QEpF3KxOYMBIzh5fvpJ5KJzzDv4S/6jhYuernWOg7F6t38cZ1mT"
    "3+yvEecWa5z+Zuw3hDX8QWNdJGNp+809SOy+SiDYsv8kQ5ETf7cDrcREgzfFHj10J8AQlhE"
    "8yG5c89INXGy5HN45j2lwSdF+CoLf2l74Wm6QHDYQJCmgIrUZ9/wyMIIZdBwd+9c2MgsWV5"
    "YmHXRkje94JpCP/r9+ge6oLW93XnSwIDAQAB"
)
CHROMIUM_MIN_VERSION = "120"
FIREFOX_MIN_VERSION = "153.0"

# Capabilities that must never appear in a preparation package: clipboard read,
# SSO/identity/oauth surfaces, and the broad host/network APIs the product does
# not need. The exact expected permission set already refuses these, but naming
# them makes the refusal explainable.
FORBIDDEN_PERMISSIONS = frozenset(
    {
        "bookmarks",
        "browsingData",
        "clipboardRead",
        "clipboardWrite",
        "contentSettings",
        "cookies",
        "debugger",
        "declarativeNetRequest",
        "downloads",
        "history",
        "identity",
        "management",
        "offscreen",
        "proxy",
        "tabs",
        "unlimitedStorage",
        "webNavigation",
        "webRequest",
    }
)
FORBIDDEN_TOP_LEVEL = frozenset(
    {"externally_connectable", "oauth2", "oauth_config", "sso", "identity"}
)


def entries_for(product: str) -> tuple[str, ...]:
    """Return the exact, ordered entry allowlist for one product."""
    if product not in PRODUCT_EXTRA_FILES:
        raise KeyError("unsupported product")
    return (MANIFEST_FILE,) + BASE_FILES + PRODUCT_EXTRA_FILES[product]


def identity_for(product: str) -> str:
    """Return the fixed native-host allowlisted identity for one product."""
    if product not in IDENTITIES:
        raise KeyError("unsupported product")
    return IDENTITIES[product]
