"""Controller checks for the external Firefox Passkey acceptance.

No browser is started here: these checks pin the opt-in gate, the native label
contract shared with the existing XTest driver, the absence of privileged
extension/CDP shortcuts, the independent relying-party verifier itself, and the
two-realm popup selection that decides where the single physical click lands.
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


# The driver talks to two different Firefox realms and they must not be merged:
#   * rdpEvaluate executes in the add-on background page, which owns
#     browser.extension/browser.runtime but has no chrome XUL popup elements;
#   * evaluate(..., chrome) executes in the browser chrome window, which owns
#     the XUL <browser> hosts and currentURI but has no WebExtension APIs.
# This harness runs the real driver helpers against two separate mock realms and
# fails loudly if either helper reaches into the other realm.
POPUP_HARNESS = r"""
const fs = require("node:fs");
const vm = require("node:vm");
const assert = require("node:assert/strict");
const source = fs.readFileSync("browser_firefox_native_acceptance.mjs", "utf8");
const start = source.indexOf('let popupExpectedURL = "";');
const end = source.indexOf("\nasync function popupKeyboard", start);
assert(start >= 0 && end > start, "popup selection helpers missing");

const OWNED = "moz-extension://owned-uuid/popup.html";
function control(rect = {x:10, y:20, width:100, height:30}) {
 return {disabled:false, scrollIntoView: () => {}, getBoundingClientRect: () => ({...rect}), contains: () => false};
}
function popupWindow(options = {}) {
 const target = control(options.controlRect);
 const document = {
  visibilityState: options.visibility ?? "visible",
  hidden: options.hidden === true,
  querySelector: (selector) => selector === "#refresh" ? target : null,
  elementFromPoint: () => target,
 };
 return {
  closed: options.closed === true,
  document,
  innerWidth: options.width ?? 320,
  innerHeight: options.height ?? 480,
  location: {href: options.href ?? OWNED},
  getComputedStyle: () => ({display:"block", visibility:"visible"}),
 };
}
function hostFor(options = {}) {
 const rect = options.rect ?? {x:100, y:200, width:320, height:480};
 return {
  style: options.style ?? {display:"block", visibility:"visible"},
  getAttribute: (name) => name === "hidden" && options.hidden === true ? "true" :
   name === "collapsed" && options.collapsed === true ? "true" : null,
  getBoundingClientRect: () => ({...rect}),
  currentURI: {spec: options.spec ?? OWNED},
  browsingContext: {id: options.id ?? "ctx-1"},
 };
}
function realm(extra) {
 return Object.assign({JSON, Error, String, Math, Array, Promise, Object}, extra);
}
async function drive(views, hosts, owned = OWNED) {
 const clicks = [];
 const backgroundDocument = {};
 Object.defineProperty(backgroundDocument, "querySelector", {get() {
  throw Error("background realm must not touch the chrome document");
 }});
 Object.defineProperty(backgroundDocument, "querySelectorAll", {get() {
  throw Error("background realm must not touch the chrome document");
 }});
 const background = realm({
  browser: {
   extension: {getViews: () => views},
   runtime: {getURL: (path) => path === "popup.html" ? owned : "moz-extension://owned-uuid/" + path},
  },
  document: backgroundDocument,
 });
 const chrome = realm({
  document: {
   querySelectorAll: (selector) => selector === "browser.webextension-popup-browser" ? hosts : [],
  },
  window: {screenX: 50, screenY: 60},
  getComputedStyle: (element) => element.style || {display:"block", visibility:"visible"},
 });
 Object.defineProperty(chrome, "browser", {get() {
  throw Error("chrome realm must not touch WebExtension APIs");
 }});
 const sandbox = realm({
  env: {},
  context: async () => {},
  execFileSync: (binary, args) => clicks.push({binary, args}),
  rdpEvaluate: async (text) => JSON.parse(vm.runInNewContext(text, background)),
  evaluate: (script, args = []) =>
   vm.runInNewContext("(function(){" + script + "})", chrome)(...args),
  eventually: async (check, message) => {
   for (let attempt = 0; attempt < 6; attempt++) {
    try { if (await check()) return; } catch {}
   }
   throw Error(message);
  },
 });
 vm.runInNewContext(
  source.slice(start, end) + "\nglobalThis.popupClick=popupClick;", sandbox
 );
 try {
  await sandbox.popupClick("#refresh");
  return {clicks, error: null};
 } catch (error) {
  return {clicks, error: String(error.message)};
 }
}
function clicked(result, x, y) {
 assert.equal(result.error, null, "unexpected refusal: " + result.error);
 assert.equal(result.clicks.length, 1, "exactly one physical click");
 assert.equal(result.clicks[0].binary, "python3");
 assert.deepEqual(Array.from(result.clicks[0].args.slice(-2)), [String(x), String(y)]);
}
function refused(result, pattern) {
 assert.ok(result.error, "expected a refusal");
 assert.match(result.error, pattern);
 assert.equal(result.clicks.length, 0, "refusal must not send an XTest click");
}
(async () => {
/*SCENARIOS*/
 console.log("popup selection scenarios passed");
})().catch((error) => { console.error(error.message); process.exitCode = 1; });
"""


class FirefoxPasskeyContract(unittest.TestCase):
    def _popup_selection(self, scenarios):
        result = node("-e", POPUP_HARNESS.replace("/*SCENARIOS*/", scenarios))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_popup_selection_uses_the_single_visible_view_and_host(self):
        self._popup_selection(
            r"""
 const staleSize = popupWindow({width:0, controlRect:{x:300,y:300,width:100,height:30}});
 const visible = popupWindow();
 const staleHost = hostFor({rect:{x:0,y:0,width:0,height:0}, id:"stale"});
 clicked(await drive([staleSize, visible], [staleHost, hostFor({id:"ctx-1"})]), 210, 295);
 const hiddenView = popupWindow({hidden:true, controlRect:{x:300,y:300,width:100,height:30}});
 clicked(await drive([hiddenView, visible], [hostFor({id:"ctx-1"})]), 210, 295);
 const collapsedHost = hostFor({rect:{x:400,y:400,width:320,height:480}, collapsed:true, id:"stale"});
 const hiddenHost = hostFor({rect:{x:0,y:0,width:320,height:480}, hidden:true, id:"stale"});
 clicked(await drive([visible], [collapsedHost, hiddenHost, hostFor({id:"ctx-1"})]), 210, 295);
"""
        )

    def test_popup_selection_refuses_without_a_visible_view(self):
        self._popup_selection(
            r"""
 const zeroWidth = popupWindow({width:0, controlRect:{x:300,y:300,width:100,height:30}});
 refused(await drive([zeroWidth], [hostFor({id:"ctx-1"})]), /not uniquely visible/);
 const hiddenView = popupWindow({visibility:"hidden"});
 refused(await drive([hiddenView], [hostFor({id:"ctx-1"})]), /not uniquely visible/);
 const foreignView = popupWindow({href:"moz-extension://other-uuid/popup.html"});
 refused(
  await drive([foreignView], [hostFor({spec:"moz-extension://other-uuid/popup.html"})]),
  /not uniquely visible/
 );
"""
        )

    def test_popup_selection_refuses_two_visible_views(self):
        self._popup_selection(
            r"""
 const first = popupWindow({controlRect:{x:10,y:20,width:100,height:30}});
 const second = popupWindow({controlRect:{x:40,y:50,width:100,height:30}});
 refused(
  await drive(
   [first, second],
   [hostFor({id:"ctx-1"}), hostFor({rect:{x:300,y:300,width:320,height:480}, id:"ctx-2"})]
  ),
  /not uniquely visible/
 );
"""
        )

    def test_popup_selection_refuses_mismatched_host_url_or_identity(self):
        self._popup_selection(
            r"""
 const visible = popupWindow();
 refused(
  await drive([visible], [hostFor({spec:"moz-extension://other-uuid/popup.html"})]),
  /target not stable/
 );
 refused(
  await drive(
   [visible],
   [hostFor({id:"ctx-1"}), hostFor({rect:{x:300,y:300,width:320,height:480}, id:"ctx-2"})]
  ),
  /target not stable/
 );
 const owned = "moz-extension://second-check-uuid/popup.html";
 clicked(await drive([popupWindow({href:owned})], [hostFor({spec:owned})], owned), 210, 295);
"""
        )

    def test_scripts_parse(self):
        for script in (FIREFOX, PASSKEY):
            result = node("--check", script.name)
            self.assertEqual(result.returncode, 0, script.name)

    def test_popup_pointer_uses_post_scroll_origin_and_hit_testing(self):
        script = r"""
const fs = require("node:fs");
const vm = require("node:vm");
const assert = require("node:assert/strict");
const source = fs.readFileSync("browser_firefox_native_acceptance.mjs", "utf8");
const start = source.indexOf("async function popupClick(selector) {");
const end = source.indexOf("\nasync function popupKeyboard", start);
assert(start >= 0 && end > start);
async function scenario(hit) {
 let origin = {x:100,y:200};
 const clicks = [];
 const sandbox = {
  env:{},
  popupContext: async () => ({...origin}),
  popupEvaluate: async text => {
   if(text.includes("scrollIntoView")) {
    origin = {x:900,y:800};
    return text.includes("return {x:r.x") ? {x:10,y:20} : true;
   }
   return hit ? {x:10,y:20} : null;
  },
  eventually: async (check, message) => {
   for(let n=0;n<4;n++) if(await check()) return;
   throw Error(message);
  },
  execFileSync: (binary,args) => clicks.push({binary,args}),
 };
 vm.runInNewContext(source.slice(start,end)+"\nglobalThis.click = popupClick;", sandbox);
 if(hit) {
  await sandbox.click("#refresh");
  assert.equal(clicks.length,1);
  assert.equal(clicks[0].binary,"python3");
  assert.deepEqual(Array.from(clicks[0].args.slice(-2)),["910","820"]);
 } else {
  await assert.rejects(sandbox.click("#refresh"),/target not stable/);
  assert.equal(clicks.length,0);
 }
}
(async()=>{await scenario(true);await scenario(false)})().catch(e=>{console.error(e.message);process.exitCode=1});
"""
        result = node("-e", script)
        self.assertEqual(result.returncode, 0, result.stderr)

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
