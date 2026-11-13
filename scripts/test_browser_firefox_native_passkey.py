"""Controller checks for the external Firefox Passkey acceptance.

No browser is started here: these checks pin the opt-in gate, the native label
contract shared with the existing XTest driver, the absence of privileged
extension/CDP shortcuts, the independent relying-party verifier itself, and the
two-realm popup selection that decides where the single physical click lands.
"""
import ast
import pathlib
import re
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

    def test_conditional_sibling_focus_order_around_single_click(self):
        # The native snapshot raises and focuses the app X window and the XTest
        # inline click is bare, so the driver must refocus the browser page after
        # the last snapshot and before exactly one physical selection. Native
        # factor entry then stops the mock with a sentinel, so no signature has
        # to be fabricated and no approval is granted here.
        script = r"""
const assert = require("node:assert/strict");
(async () => {
 const { acceptConditionalSibling } = await import("./browser_conditional_passkey_acceptance.mjs");
 const origin = "https://login.locklark.test";
 const first = { id: "first-sibling-public-id" };
 const second = { id: "second-sibling-id-public" };
 const events = [];
 const sentinel = new Error("sentinel:native-factors");
 const hooks = {
  origin,
  fixture: { Password: "synthetic-password", Secret: "synthetic-secret" },
  first, second,
  phase: (value) => { events.push({ event: "phase", phase: value }); },
  navigate: async (url) => { events.push({ event: "navigate", url }); },
  pageEval: async (fn) => {
   events.push({ event: "page", fn: fn.name || "capability" });
   if (fn.name === "readConditional")
    return { result: null, error: null, metadataExposed: false, lightDOMChoices: 0 };
   return true;
  },
  clickDocument: async (selector) => { events.push({ event: "document-click", selector }); },
  inlinePresent: async (label) => {
   events.push({ event: "inline-probe", label });
   return label !== "Synthetic user · passkey-test";
  },
  inlineClick: async (label) => { events.push({ event: "inline-click", label }); },
  focusPage: async () => { events.push({ event: "browser-focus" }); },
  eventually: async (check, message) => {
   for (let attempt = 0; attempt < 20; attempt++) if (await check()) return;
   throw Error(message);
  },
  input: (actions, native = true, options = {}) => {
   if (options.inspect === true) {
    events.push({ event: "native-inspect" });
    return { controls: {} };
   }
   if (native === false) {
    events.push({ event: "browser-focus" });
    return {};
   }
   events.push({ event: "native-factors", actions });
   throw sentinel;
  },
  observe: () => ({ snapshot_digest: "synthetic-digest" }),
 };
 let failure = null;
 try {
  await acceptConditionalSibling(hooks);
 } catch (error) {
  failure = error;
 }
 assert.equal(failure, sentinel, "selection did not reach native factor entry");
 const indexes = (name) => events
  .map((entry, index) => [entry.event, index])
  .filter(([event]) => event === name)
  .map(([, index]) => index);
 const hint = (id) => id.slice(0, 6) + "…" + id.slice(-4);
 const clicks = events.filter((entry) => entry.event === "inline-click");
 assert.equal(clicks.length, 1, "exactly one physical sibling selection");
 assert.equal(clicks[0].label, "Synthetic user · passkey-test · " + hint(second.id));
 const click = indexes("inline-click")[0];
 const inspection = indexes("native-inspect").pop();
 const focus = indexes("browser-focus").pop();
 const factors = indexes("native-factors")[0];
 assert.ok(indexes("native-inspect").length >= 2, "native snapshots preceded selection");
 assert.ok(inspection < focus, "browser focus must follow the last native snapshot");
 assert.ok(focus < click, "browser focus must precede the physical selection");
 assert.ok(click < factors, "native factor entry must follow the physical selection");
 const between = events.slice(focus + 1, click).map((entry) => entry.event);
 assert.deepEqual([...new Set(between)], ["inline-probe"],
  "no native access between refocus and the single click: " + between.join(","));
 assert.ok(events.slice(0, click).every((entry) => entry.event !== "native-factors"),
  "no native factor entry before the selection");
 const actions = events[factors].actions;
 assert.deepEqual(actions.slice(0, 5), [
  { wait_label: "验证主密码" }, { click_label: "验证主密码" },
  { text: "synthetic-password" }, { click_label: "验证 Secret Key" }, { text: "synthetic-secret" },
 ]);
 assert.equal(actions.length, 6);
 assert.match(actions[5].click_label,
  /^登录：login\.locklark\.test · login\.locklark\.test · passkey-test · passkey-test · 凭据 /);
 console.log("conditional sibling driver order scenarios passed");
})().catch((error) => { console.error(error.message); process.exitCode = 1; });
"""
        result = node("-e", script)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("conditional sibling driver order scenarios passed", result.stdout)

    def test_failure_diagnostics_stay_on_public_controls(self):
        text = FIREFOX.read_text(encoding="utf-8")
        # Debugging must never enumerate processes, their arguments or their
        # environments; only the existing public native control snapshot stays.
        for forbidden in ("/proc", "cmdline", "readdirSync", "/environ"):
            self.assertNotIn(forbidden, text)
        self.assertNotIn("Native accessibility environment", text)
        self.assertNotIn("NO_AT_BRIDGE", text)
        reads = re.findall(r'os\.environ\[[^\]]*\]', text)
        self.assertEqual(reads, ['os.environ["DISPLAY"]'] * 2)
        # The public snapshot keeps fixed labels and boolean states only.
        self.assertIn('"Native control state: "', text)
        for label in ("验证主密码", "验证 Secret Key", "批准本次填充", "拒绝本次填充"):
            self.assertIn('"' + label + '"', text)
        for state in (
            "present: control?.present === true",
            "enabled: control?.enabled === true",
            "showing: control?.showing === true",
        ):
            self.assertIn(state, text)

    def test_diagnostic_labels_cover_quick_pair_and_passkey_removals(self):
        text = FIREFOX.read_text(encoding="utf-8")
        # Exactly three additions to the fixed diagnostic list, all also
        # allowlisted by the shared X11 driver.
        start = text.index("const labels = [")
        labels = re.findall(
            r'^\s+"([^"]+)",$', text[start : text.index("];", start)], re.MULTILINE
        )
        for label in ("连接并启用快捷填充", "批准删除 Passkey", "拒绝删除 Passkey"):
            self.assertEqual(labels.count(label), 1, label)
            self.assertIn('"' + label + '"', text[start:])
        source = (SCRIPTS / "browser_native_x11.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        allowlist = None
        for node in tree.body:
            if isinstance(node, ast.Assign) and any(
                getattr(target, "id", "") == "CONTROL_LABELS" for target in node.targets
            ):
                allowlist = ast.literal_eval(node.value)
        self.assertIsInstance(allowlist, tuple)
        for label in ("连接并启用快捷填充", "批准删除 Passkey", "拒绝删除 Passkey"):
            self.assertIn(label, allowlist, label)

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
        ):
            self.assertIn(label, labels, label)
            self.assertIn(label, passkey, label)
        # Dynamic labels include the public credential ID hint and are matched
        # by full equality in the driver; the grammar stays narrow.
        self.assertIn("PASSKEY_CHOICE_LABEL", source)
        self.assertIn("control_label_allowed", source)
        self.assertIn("passkeyChoiceLabel", passkey)
        self.assertIn("凭据 ", (SCRIPTS / "browser_passkey_management_acceptance.mjs").read_text(encoding="utf-8"))
        self.assertNotIn('"登录：" + rp', passkey)


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
