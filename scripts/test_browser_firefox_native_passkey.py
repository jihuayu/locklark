"""Controller checks for the external Firefox Passkey acceptance.

No browser is started here: these checks pin the opt-in gate, the native label
contract shared with the existing XTest driver, the absence of privileged
extension/CDP shortcuts, and the independent relying-party verifier itself.
"""
import ast
import pathlib
import subprocess
import unittest

SCRIPTS = pathlib.Path(__file__).resolve().parent
FIREFOX = SCRIPTS / "browser_firefox_native_acceptance.mjs"
PASSKEY = SCRIPTS / "browser_firefox_passkey_acceptance.mjs"


def node(*args):
    return subprocess.run(
        ["node", *args], cwd=SCRIPTS, capture_output=True, text=True, timeout=120
    )


class FirefoxPasskeyContract(unittest.TestCase):
    def test_scripts_parse(self):
        for script in (FIREFOX, PASSKEY):
            result = node("--check", script.name)
            self.assertEqual(result.returncode, 0, script.name)

    def test_gate_is_opt_in_and_keeps_default_flow(self):
        text = FIREFOX.read_text(encoding="utf-8")
        gate = 'if (process.env.LOCKLARK_TEST_FIREFOX_PASSKEY === "1") {'
        self.assertIn(gate, text)
        start = text.index(gate)
        block = text[start : text.index("\n    }\n", start)]
        self.assertIn("acceptFirefoxPasskey({", block)
        # Default acceptance still has to run its pre-existing phases.
        self.assertIn("await acceptBrowserSave(acceptanceDriver);", text)
        self.assertIn("await acceptBrowserOTP(acceptanceDriver);", text)

    def test_only_mode_is_opt_in_and_scoped(self):
        text = FIREFOX.read_text(encoding="utf-8")
        gate = 'process.env.LOCKLARK_TEST_FIREFOX_PASSKEY_ONLY === "1"'
        self.assertIn(gate, text)
        self.assertIn(
            'process.env.LOCKLARK_TEST_FIREFOX_PASSKEY_ONLY !== "1" ||', text
        )
        self.assertIn('scope: "passkey-only"', text)
        self.assertIn('legacyFillSaveOtp: "not-run"', text)
        # Legacy phases must stay inside an explicit non-passkey-only guard.
        self.assertIn("if (!passkeyOnly) {", text)
        legacy = text[text.index("if (!passkeyOnly) {") :]
        self.assertIn("await acceptBrowserSave(acceptanceDriver);", legacy)
        self.assertIn("await acceptBrowserOTP(acceptanceDriver);", legacy)
        # The passkey-only run must still pair through the real native host.
        self.assertIn('popupClick("#connect")', text)
        self.assertIn("确认连接此扩展", text)

    def test_failure_diagnostics_use_fixed_codes_only(self):
        helper = PASSKEY.read_text(encoding="utf-8")
        for phase in (
            "firefox-passkey-create:page-request",
            "firefox-passkey-create:inline",
            "firefox-passkey-create:native-factors",
            "firefox-passkey-create:result",
            "firefox-passkey-create:rp-verify",
            "firefox-passkey-get:inline",
            "firefox-passkey-get:rp-verify",
        ):
            self.assertIn(phase, helper)
        self.assertIn('"PasskeyFailure:inline-unavailable:" + label', helper)
        self.assertIn("safeName(created.error)", helper)
        self.assertIn("safeName(signed.error)", helper)
        self.assertNotIn('+ created.error)', helper)
        self.assertNotIn('+ signed.error)', helper)
        # The probe must offer an out-of-process fallback, not one assumption.
        self.assertIn("CHROME_VIEWPORT_SOURCE", helper)
        self.assertIn("bidi-locate", helper)
        native = FIREFOX.read_text(encoding="utf-8")
        self.assertIn("browsingContext.locateNodes", native)
        self.assertIn("Failure class: ", native)
        self.assertIn("/^PasskeyFailure:[a-z-]+(:[^:]{0,40})?$/", native)

    def test_no_privileged_extension_or_cdp_shortcut(self):
        text = PASSKEY.read_text(encoding="utf-8")
        for forbidden in (
            "runtime.sendMessage",
            "browser.runtime",
            "browser.extension",
            "newCDPSession",
            "DOM.getDocument",
            "executeScript",
            "sendNativeMessage",
        ):
            self.assertNotIn(forbidden, text)
        # The closed shadow tree is only observed; every click is real XTest.
        self.assertIn("openOrClosedShadowRoot", text)
        self.assertIn("clickScreen", text)
        self.assertIn("mozInnerScreenX", text)

    def test_native_passkey_label_matches_driver_allowlist(self):
        source = (SCRIPTS / "browser_native_x11.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        labels = None
        for node in tree.body:
            if isinstance(node, ast.Assign) and any(
                getattr(target, "id", "") == "CONTROL_LABELS" for target in node.targets
            ):
                labels = ast.literal_eval(node.value)
        self.assertIsInstance(labels, tuple)
        passkey = PASSKEY.read_text(encoding="utf-8")
        for label in (
            "验证主密码",
            "验证 Secret Key",
            "创建新登录并保存 Passkey",
            "登录：login.locklark.test · passkey-test · passkey-test",
        ):
            self.assertIn(label, labels, label)
            self.assertIn(label, passkey, label)


class FirefoxPasskeyVerifier(unittest.TestCase):
    def test_independent_registration_and_assertion(self):
        result = node("browser_firefox_passkey_acceptance.mjs", "--self-check")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(
            "independent relying-party registration and assertion verification passed",
            result.stdout,
        )
        # The self-check must not print private fixture material.
        for marker in ("synthetic-", "Password=", "Secret="):
            self.assertNotIn(marker, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
