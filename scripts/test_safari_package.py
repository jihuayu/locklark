#!/usr/bin/env python3
"""Packaging checks for the explicit Safari build.

These checks are deliberately static/package-level. They run on any host with
Node and Python, but they do not compile Swift, sign entitlements, install a
Safari extension or talk to a real Safari browser. Those remain CI/platform
steps and must not be inferred from this file.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXTENSION = ROOT / "browser-extension"
DIST = EXTENSION / "dist"
SAFARI = ROOT / "safari"

EXPECTED_FILES = {
    "manifest.json",
    "background.js",
    "core.js",
    "content.js",
    "webauthn.js",
    "safari-native-port.js",
    "popup.html",
    "popup.css",
    "popup.js",
    "options.html",
    "options.css",
    "options.js",
}

FROZEN_MANIFEST_SHA256 = {
    "chromium": "861ee5ba8f7c3dba5f24ba906ab0edc056e0b546ee1ec9f9387a2d31c4a27472",
    "firefox": "b9220f9cf622d1f478a5e6f57e49b28308a130e5753780579079ae1c568401c4",
}

APPLE_SOURCE = (
    "https://developer.apple.com/documentation/safariservices/"
    "messaging-between-the-app-and-javascript-in-a-safari-web-extension"
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_manifest(mode: str) -> dict:
    return json.loads((DIST / mode / "manifest.json").read_text("utf-8"))


def referenced_resources(manifest: dict) -> list[str]:
    refs: list[str] = []
    refs.extend(manifest.get("background", {}).get("scripts", []))
    if "service_worker" in manifest.get("background", {}):
        refs.append(manifest["background"]["service_worker"])
    for script in manifest.get("content_scripts", []):
        refs.extend(script.get("js", []))
        refs.extend(script.get("css", []))
    action = manifest.get("action") or {}
    if action.get("default_popup"):
        refs.append(action["default_popup"])
    options = manifest.get("options_ui") or {}
    if options.get("page"):
        refs.append(options["page"])
    return refs


def assert_safe_resource_name(name: str) -> None:
    if not isinstance(name, str) or not name:
        raise AssertionError(f"invalid resource name: {name!r}")
    if (
        "/" in name
        or "\\" in name
        or name.startswith(".")
        or ".." in name.split(".")
        or os.path.isabs(name)
    ):
        raise AssertionError(f"unsafe/resource traversal name: {name!r}")


def verify_safari_dist() -> None:
    safari_dir = DIST / "safari"
    if not safari_dir.is_dir():
        raise AssertionError("dist/safari missing; run node build.js safari")
    names = {entry.name for entry in safari_dir.iterdir() if entry.is_file()}
    if names != EXPECTED_FILES:
        raise AssertionError(
            f"Safari resource whitelist mismatch: missing={sorted(EXPECTED_FILES - names)} "
            f"extra={sorted(names - EXPECTED_FILES)}"
        )
    for entry in safari_dir.iterdir():
        if entry.is_symlink():
            raise AssertionError(f"symlink not allowed in Safari package: {entry.name}")

    manifest = json.loads((safari_dir / "manifest.json").read_text("utf-8"))
    if manifest.get("manifest_version") != 3:
        raise AssertionError("Safari manifest must be MV3")
    expected_permissions = ["activeTab", "scripting", "nativeMessaging", "storage"]
    if manifest.get("permissions") != expected_permissions:
        raise AssertionError(f"unexpected Safari permissions: {manifest.get('permissions')}")
    forbidden_permissions = {
        "clipboardRead",
        "clipboardWrite",
        "contextMenus",
        "tabs",
        "management",
        "debugger",
        "nativeMessagingRead",
    }
    if forbidden_permissions & set(manifest.get("permissions", [])):
        raise AssertionError("Safari package has a forbidden permission")
    if manifest.get("host_permissions") != ["https://*/*"]:
        raise AssertionError("Safari host permission must stay HTTPS-only")
    for forbidden in (
        "key",
        "minimum_chrome_version",
        "browser_specific_settings",
        "externally_connectable",
        "optional_permissions",
        "optional_host_permissions",
        "web_accessible_resources",
        "content_security_policy_pages",
    ):
        if forbidden in manifest:
            raise AssertionError(f"Safari manifest must not contain {forbidden}")
    if manifest.get("content_security_policy") != {
        "extension_pages": "script-src 'self'; object-src 'none'"
    }:
        raise AssertionError("Safari CSP changed")
    background = manifest.get("background") or {}
    scripts = background.get("scripts") or []
    if background.get("service_worker"):
        raise AssertionError("Safari package uses background.scripts, not service_worker")
    if scripts != ["safari-native-port.js", "core.js", "background.js"]:
        raise AssertionError(f"unexpected Safari background order: {scripts}")
    if scripts.index("safari-native-port.js") >= scripts.index("background.js"):
        raise AssertionError("Safari shim must load before background.js")
    for content_script in manifest.get("content_scripts", []):
        if "safari-native-port.js" in content_script.get("js", []):
            raise AssertionError("native shim must never run in a content/MAIN world")
        if content_script.get("world") not in (None, "MAIN"):
            raise AssertionError("unexpected content-script world")

    for reference in referenced_resources(manifest):
        assert_safe_resource_name(reference)
        if not (safari_dir / reference).is_file():
            raise AssertionError(f"manifest references missing resource: {reference}")

    chromium = json.loads((DIST / "chromium" / "manifest.json").read_text("utf-8"))
    if manifest["content_scripts"] != chromium["content_scripts"]:
        raise AssertionError("Safari content-script policy drifted from Chromium")
    for key in ("action", "options_ui", "commands", "description", "name", "version"):
        if manifest.get(key) != chromium.get(key):
            raise AssertionError(f"Safari manifest field drifted: {key}")


def run(node_args: list[str]) -> None:
    subprocess.run(
        ["node", str(EXTENSION / "build.js"), *node_args],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


class SafariPackagingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not shutil.which("node"):
            raise unittest.SkipTest("node unavailable")
        shutil.rmtree(DIST, ignore_errors=True)
        run([])
        if (DIST / "safari").exists():
            raise AssertionError("Safari must not be part of the default build")
        run(["safari"])

    def test_safari_resource_whitelist_and_manifest(self) -> None:
        verify_safari_dist()

    def test_existing_chrome_and_firefox_manifests_are_byte_identical(self) -> None:
        for mode, expected in FROZEN_MANIFEST_SHA256.items():
            actual = sha256(DIST / mode / "manifest.json")
            self.assertEqual(actual, expected, f"{mode} manifest bytes changed")
            self.assertEqual(
                {entry.name for entry in (DIST / mode).iterdir()},
                EXPECTED_FILES - {"safari-native-port.js"},
            )

    def test_safari_shim_is_only_in_background_bundle(self) -> None:
        manifest = load_manifest("safari")
        self.assertIn("safari-native-port.js", manifest["background"]["scripts"])
        for content in manifest["content_scripts"]:
            self.assertNotIn("safari-native-port.js", content["js"])
        src = (EXTENSION / "safari-native-port.js").read_text("utf-8")
        self.assertIn("isSafariRuntime", src)
        self.assertIn("safari-web-extension://", src)
        self.assertIn('if (name !== NATIVE_HOST_NAME) throw Error("unknown native host")', src)
        self.assertNotIn("chrome.runtime.connectNative =", src)
        self.assertNotIn("globalThis.chrome =", src)
        self.assertNotIn("MutationObserver", src)

    def test_fixed_safari_identities(self) -> None:
        project = (SAFARI / "project.yml").read_text("utf-8")
        identity = (SAFARI / "Shared/Sources/SignedIdentity.swift").read_text("utf-8")
        for value in (
            "org.locklark.browser.safari",
            "org.locklark.browser.safari.Extension",
            "group.org.locklark.browser.safari",
            'MACOSX_DEPLOYMENT_TARGET: "13.0"',
            "type: application",
            "type: app-extension",
            "com.apple.Safari.web-extension",
        ):
            target = identity if value.startswith("org.locklark") or value.startswith("group.") else project
            if value == "com.apple.Safari.web-extension":
                target = (SAFARI / "LocklarkSafariExtension/Info.plist").read_text("utf-8")
            self.assertIn(value, target)
        self.assertIn("fixedContainingAppBundleID", identity)
        self.assertIn("fixedExtensionBundleID", identity)
        self.assertIn("fixedAppGroupID", identity)
        self.assertNotIn("platform: iOS", project)
        self.assertIn("embed: true", project)
        self.assertIn("Embed fixed native helper", project)

    def test_entitlements_and_placeholders_fail_closed(self) -> None:
        for name, target in (
            ("LocklarkSafari.entitlements", "LocklarkSafari"),
            ("LocklarkSafariExtension.entitlements", "LocklarkSafariExtension"),
        ):
            text = (SAFARI / target / name).read_text("utf-8")
            self.assertIn("com.apple.security.app-sandbox", text)
            self.assertIn("com.apple.security.application-groups", text)
            self.assertIn("$(LOCKLARK_APP_GROUP_ID)", text)
            self.assertNotIn("group.REPLACE", text)
        identity = (SAFARI / "Shared/Sources/SignedIdentity.swift").read_text("utf-8")
        for marker in ("REPLACE", "CHANGEME", "PLACEHOLDER", "TEAMID", "UNSIGNED"):
            self.assertIn(marker, identity)
        for plist in (
            SAFARI / "LocklarkSafari/Info.plist",
            SAFARI / "LocklarkSafariExtension/Info.plist",
        ):
            text = plist.read_text("utf-8")
            self.assertIn("$(LOCKLARK_TEAM_ID)", text)
            self.assertIn("$(LOCKLARK_APP_GROUP_ID)", text)
            self.assertNotIn("<string>ABCDE12345</string>", text)

    def test_extension_never_launches_processes_or_logs_raw_requests(self) -> None:
        sources = "\n".join(
            path.read_text("utf-8")
            for path in sorted((SAFARI / "LocklarkSafariExtension/Sources").glob("*.swift"))
        )
        for forbidden in (
            "Process(",
            "NSTask",
            "posix_spawn",
            "system(",
            "popen(",
            "execv",
            "NSLog",
            "os_log",
            "print(",
            "logger.",
        ):
            self.assertNotIn(forbidden, sources)
        handler = (SAFARI / "LocklarkSafariExtension/Sources/SafariWebExtensionHandler.swift").read_text("utf-8")
        self.assertIn("SFExtensionMessageKey", handler)
        self.assertIn("SFExtensionProfileKey", handler)
        self.assertIn("NSExtensionRequestHandling", handler)
        self.assertNotIn("userInfo?[\"message\"]", handler)

    def test_app_launches_only_fixed_embedded_helper(self) -> None:
        sources = "\n".join(
            path.read_text("utf-8")
            for path in sorted((SAFARI / "LocklarkSafari/Sources").glob("*.swift"))
        )
        limits = (SAFARI / "Shared/Sources/RelayLimits.swift").read_text("utf-8")
        self.assertIn('helperName = "locklark-browser-safari"', limits)
        self.assertIn("RelayLimits.helperName", sources)
        self.assertIn('fixedArguments = ["--safari-browser"]', sources)
        self.assertIn("Process()", sources)
        self.assertNotIn("CommandLine.arguments", sources)
        self.assertNotIn("/bin/sh", sources)
        self.assertNotIn("/bin/bash", sources)
        self.assertNotIn("ProcessInfo.processInfo.environment", sources)
        for forbidden in ("execv", "posix_spawn", "system(", "popen("):
            self.assertNotIn(forbidden, sources)

    def test_peer_policy_requires_team_and_exact_extension_bundle(self) -> None:
        peer = (SAFARI / "Shared/Sources/PeerPolicy.swift").read_text("utf-8")
        verifier = (SAFARI / "LocklarkSafari/Sources/PeerVerifier.swift").read_text("utf-8")
        self.assertIn("peer.uid == expectedUID", peer)
        self.assertIn("teamID == expectedTeamID", peer)
        self.assertIn("bundleID == expectedExtensionBundleID", peer)
        self.assertIn("signatureValid", peer)
        self.assertIn("SecCodeCheckValidity", verifier)
        self.assertIn("SecRequirementCreateWithString", verifier)
        self.assertIn("kSecCodeInfoTeamIdentifier", verifier)
        self.assertIn("getpeereid", (SAFARI / "Shared/Sources/SocketSupport.swift").read_text("utf-8"))
        self.assertNotIn("SecTrustEvaluate", verifier)
        self.assertNotIn("disable", verifier.lower())

    def test_bounded_envelope_token_profile_and_frames(self) -> None:
        envelope = (SAFARI / "Shared/Sources/RelayEnvelope.swift").read_text("utf-8")
        limits = (SAFARI / "Shared/Sources/RelayLimits.swift").read_text("utf-8")
        self.assertIn("maxFrameBytes = 256 * 1024", limits)
        self.assertIn("maxFramesPerPoll = 64", limits)
        self.assertIn("maxQueuedFrames = 64", limits)
        self.assertIn("maxConnections = 8", limits)
        self.assertIn("sessionTTL", limits)
        self.assertIn("isValidToken", envelope)
        self.assertIn("isValidProfileKey", envelope)
        self.assertIn("Set(object.keys) == Set([\"v\", \"op\", \"token\", \"frame\"])", envelope)
        self.assertIn("static func failure", envelope)
        failure = envelope.split("public static func failure", 1)[1].split("}", 1)[0]
        self.assertNotIn("frames", failure)
        self.assertNotIn("error", failure)

    def test_no_fake_replies_when_helper_missing(self) -> None:
        helper = (SAFARI / "LocklarkSafari/Sources/HelperSession.swift").read_text("utf-8")
        relay = (SAFARI / "LocklarkSafariExtension/Sources/ExtensionRelay.swift").read_text("utf-8")
        self.assertIn("throw RelayError.unavailable", helper)
        self.assertIn("RelayReply.failure(token: request.token)", relay)
        self.assertNotIn("RelayReply.success(token: request.token, frames: [", relay)
        self.assertNotIn("approved", relay.lower())

    def test_build_script_requires_signed_inputs_and_guards_unsigned_mode(self) -> None:
        script = (SAFARI / "scripts/build_safari.sh").read_text("utf-8")
        self.assertIn("LOCKLARK_TEAM_ID", script)
        self.assertIn("LOCKLARK_APP_GROUP_ID", script)
        self.assertIn("UNSIGNEDCI0", script)
        self.assertIn("unsigned CI compile only", script)
        self.assertIn("CODE_SIGNING_ALLOWED=NO", script)
        self.assertIn("CODE_SIGNING_REQUIRED=NO", script)
        self.assertIn('if [[ "$UNSIGNED" == "1" ]]; then', script)
        self.assertIn("not an installed/signed Safari package", script)
        self.assertIn("codesign -dv", script)
        self.assertNotIn("disable signature", script.lower())
        self.assertNotIn("--deep", script)

    def test_docs_include_apple_source_and_limitations(self) -> None:
        docs = (ROOT / "docs/safari-extension.md").read_text("utf-8")
        self.assertIn(APPLE_SOURCE, docs)
        self.assertIn("sendNativeMessage", docs)
        self.assertIn("connectNative", docs)
        self.assertIn("not", docs.lower())
        self.assertIn("unsigned", docs.lower())


def main() -> int:
    if "--verify-dist" in sys.argv:
        try:
            verify_safari_dist()
        except AssertionError as error:
            print(f"Safari dist verification failed: {error}", file=sys.stderr)
            return 1
        print("Safari dist verification passed")
        return 0
    unittest.main(argv=[sys.argv[0]])


if __name__ == "__main__":
    raise SystemExit(main())
