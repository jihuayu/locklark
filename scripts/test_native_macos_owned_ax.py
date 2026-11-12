"""Focused tests for the macOS owned-PID AX discovery path.

No real OS, GUI, TCC, prompt, AX call or window enumeration: ``QuartzApi`` runs
over an in-memory ApplicationServices fake whose CoreGraphics window inventory
is POISONED (any ``CGWindowList*`` touch is a hard failure, on every call). The
opaque AXUIElement is the window identity: no AXWindowNumber, no private
attribute, no synthetic int id.

Scoped (owned PID) discovery, re-observation, controls, focus, hit test and
activation must stay inside that process's AX windows, proven by AS.GetPid
before any title/frame read. The unscoped int-id path and the public
four-boolean status stay unchanged.
"""
import ctypes
import json
import os
import sys
import unittest
import unittest.mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import browser_native_macos as macos
import native_acceptance_contract as contract

TITLE = "Locklark · 本地金库"
OTHER_TITLE = "Locklark · 另一个窗口"
OWNED_PID = 4242
OTHER_PID = 4243
EXE = "/opt/locklark/locklark-desktop"
NO_VALUE = -25212
WINDOW_FRAME = {"x": 313, "y": 75, "width": 1102, "height": 822}
CONTROL_FRAME = {"x": 400, "y": 500, "width": 80, "height": 30}
LABEL = "解锁"
FORBIDDEN = ("AXWindowNumber", "AXValue", "AXSelectedText", "AXLabel")


class Node:
    """One opaque fake AXUIElement (identity is Python object identity)."""

    def __init__(self, **attributes):
        self.attributes = attributes


class Point:
    def __init__(self, frame):
        self.x, self.y = frame["x"], frame["y"]


class Size:
    def __init__(self, frame):
        self.width, self.height = frame["width"], frame["height"]


def owned_window(title=TITLE, pid=OWNED_PID):
    """One AXWindow with its single label control, using real AX names."""
    control = Node(AXRole="AXButton", AXDescription=LABEL, AXEnabled=True,
                   AXHidden=False, AXPosition=Point(CONTROL_FRAME),
                   AXSize=Size(CONTROL_FRAME), _pid=pid)
    window = Node(AXRole="AXWindow", AXTitle=title, AXDescription="", _pid=pid,
                  AXChildren=[control], AXPosition=Point(WINDOW_FRAME),
                  AXSize=Size(WINDOW_FRAME))
    control.attributes["AXParent"] = window
    return window, control


class FakeFrameworks:
    """ApplicationServices fake + a poisoned CoreGraphics inventory."""

    kAXWindowsAttribute = "AXWindows"
    kAXErrorNoValue = NO_VALUE
    kAXValueCGPointType = 1
    kAXValueCGSizeType = 2
    NSApplicationActivateIgnoringOtherApps = 2
    kCGWindowListOptionOnScreenOnly = 1
    kCGWindowListExcludeDesktopElements = 16
    kCGNullWindowID = 0

    def __init__(self, windows, focused=None, front_pid=OWNED_PID, hit=None,
                 getpid=None):
        self.windows = list(windows)
        self.focused = focused
        self.front_pid = front_pid
        self.hit = hit
        self.getpid = getpid
        self.requests = []
        self.activations = []
        self.applications = {}

    def __getattr__(self, name):
        # EVERY CoreGraphics window-list entry point is a hard failure.
        if name.startswith("CGWindowList"):
            raise AssertionError("CoreGraphics window inventory touched: " + name)
        raise AttributeError(name)

    # -- ApplicationServices ----------------------------------------------
    def AXIsProcessTrusted(self):
        return True

    def AXUIElementCreateApplication(self, pid):
        self.requests.append(("application", pid))
        app = self.applications.get(pid)
        if app is None:
            app = self.applications[pid] = Node(_application=pid)
        return app

    def AXUIElementGetPid(self, element, out):
        self.requests.append(("getpid", element))
        if self.getpid is not None:
            return self.getpid(element)
        return (0, element.attributes["_pid"])

    def AXUIElementCopyAttributeValue(self, element, name, out):
        self.requests.append(("copy", element, name))
        if name in FORBIDDEN:
            raise AssertionError("forbidden attribute requested: " + name)
        application = element.attributes.get("_application")
        if application is not None:
            if name == "AXWindows":
                return (0, [w for w in self.windows
                            if w.attributes["_pid"] == application])
            if name == "AXFocusedWindow":
                return (0, self.focused) if self.focused is not None else (NO_VALUE, None)
            return (NO_VALUE, None)
        value = element.attributes.get(name)
        return (NO_VALUE, None) if value is None else (0, value)

    def AXUIElementCopyElementAtPosition(self, application, x, y, out):
        self.requests.append(("at", application, x, y))
        return (0, self.hit)

    def AXValueGetValue(self, value, kind, out):
        return (True, value)

    def CFEqual(self, left, right):
        return left is right

    def process(self, pid):
        return (EXE, True)

    # -- AppKit (activation + frontmost) ----------------------------------
    @property
    def NSRunningApplication(self):
        return _NSRunningApplication(self)

    @property
    def NSWorkspace(self):
        return _NSWorkspace(self)

    def CGWindowListCopyWindowInfo(self, options, identifier):
        # Only reached on the UNSCOPED path of the one negative test below:
        # it must be provably the CG inventory, and it still refuses.
        raise AssertionError("CoreGraphics window inventory touched")

    # -- call-log views ----------------------------------------------------
    def names(self):
        return [request[2] for request in self.requests if request[0] == "copy"]


class _NSRunningApplication:
    def __init__(self, frameworks):
        self.frameworks = frameworks

    def runningApplicationWithProcessIdentifier_(self, pid):
        return _Running(self.frameworks, pid)


class _Running:
    def __init__(self, frameworks, pid):
        self.frameworks, self.pid = frameworks, pid

    def activateWithOptions_(self, options):
        self.frameworks.activations.append(self.pid)
        return True


class _NSWorkspace:
    def __init__(self, frameworks):
        self.frameworks = frameworks

    def sharedWorkspace(self):
        return self

    def frontmostApplication(self):
        pid = self.frameworks.front_pid
        return None if pid is None else _Front(pid)


class _Front:
    def __init__(self, pid):
        self.pid = pid

    def processIdentifier(self):
        return self.pid


class _Libproc:
    def proc_pidpath(self, pid, buffer, size):
        buffer.value = EXE.encode()
        return len(EXE)

    def proc_pidinfo(self, pid, flavor, arg, info, size):
        buffer = ctypes.cast(info, ctypes.POINTER(ctypes.c_char * size)).contents
        bsd = macos.BSDInfo.from_buffer(buffer)
        bsd.pbi_pid, bsd.pbi_uid = pid, os.getuid()
        return size


def api_for(frameworks):
    api = macos.QuartzApi.__new__(macos.QuartzApi)
    api.ax = frameworks
    api.quartz = frameworks
    api.appkit = frameworks
    api.libproc = _Libproc()
    return api


def scoped(windows, owned_pid=OWNED_PID, **kwargs):
    """A scoped API that already discovered its one owned window."""
    frameworks = FakeFrameworks(windows, **kwargs)
    api = api_for(frameworks)
    api.scope_to_owned_pid(owned_pid)
    return api, frameworks


class ScopedDiscoveryTests(unittest.TestCase):
    def test_owned_discovery_returns_the_opaque_handle_and_global_bounds(self):
        window, _ = owned_window()
        api, frameworks = scoped([window])
        windows, unique = api.owned_discovery(TITLE)
        self.assertTrue(unique)
        self.assertIs(windows[0]["id"], window)
        self.assertEqual(windows[0]["pid"], OWNED_PID)
        self.assertEqual(windows[0]["bounds"], WINDOW_FRAME)
        self.assertEqual(windows[0]["executable"], EXE)
        for name in FORBIDDEN:
            self.assertNotIn(name, frameworks.names())

    def test_every_owned_pid_is_proven_before_title_or_frame(self):
        window, _ = owned_window()
        api, frameworks = scoped([window])
        api.owned_discovery(TITLE)
        # The FIRST GetPid of the owned window precedes its first AXTitle read.
        getpid = next(index for index, request in enumerate(frameworks.requests)
                      if request[0] == "getpid" and request[1] is window)
        title = next(index for index, request in enumerate(frameworks.requests)
                     if request[0] == "copy" and request[1] is window
                     and request[2] == "AXTitle")
        self.assertLess(getpid, title)

    def test_no_owned_window_is_not_ready(self):
        api, _ = scoped([])
        self.assertEqual(api.owned_discovery(TITLE), ([], False))

    def test_multiple_owned_windows_are_ambiguous(self):
        first, _ = owned_window()
        second, _ = owned_window(title=OTHER_TITLE)
        api, frameworks = scoped([first, second])
        self.assertEqual(api.owned_discovery(TITLE), ([], False))
        # Ambiguity never reads a title of any owned window.
        self.assertNotIn("AXTitle", frameworks.names())

    def test_title_mismatch_is_not_ready(self):
        window, _ = owned_window(title=OTHER_TITLE)
        api, _ = scoped([window])
        self.assertEqual(api.owned_discovery(TITLE), ([], False))

    def test_foreign_window_never_satisfies_the_owned_pid(self):
        window, _ = owned_window(pid=OTHER_PID)
        api, _ = scoped([window])
        self.assertEqual(api.owned_discovery(TITLE), ([], False))

    def test_malformed_and_missing_pid_refused(self):
        api, _ = scoped([])
        for pid in (0, -1, True, 4242.0, "4242", None):
            with self.subTest(pid=pid):
                with self.assertRaises(contract.ContractError) as error:
                    api.scope_to_owned_pid(pid)
                self.assertEqual(error.exception.code, "a11y-query")

    def test_getpid_error_or_wrong_pid_fails_closed(self):
        window, _ = owned_window()
        for answer in (OSError("private"), (0, OTHER_PID), (-25204, OWNED_PID),
                       (0, True), (0, None), None):
            with self.subTest(answer=answer):
                def getpid(element, answer=answer):
                    if isinstance(answer, Exception):
                        raise answer
                    return answer

                api, _ = scoped([window], getpid=getpid)
                with self.assertRaises(contract.ContractError) as error:
                    api.owned_discovery(TITLE)
                self.assertEqual(error.exception.code, "a11y-query")

    def test_unreadable_frame_fails_closed(self):
        window, _ = owned_window()
        del window.attributes["AXPosition"]
        api, _ = scoped([window])
        with self.assertRaises(contract.ContractError) as error:
            api.owned_discovery(TITLE)
        self.assertEqual(error.exception.code, "a11y-query")


class ScopedReobserveTests(unittest.TestCase):
    def discovered(self, **kwargs):
        window, control = owned_window()
        api, frameworks = scoped([window], **kwargs)
        api.owned_discovery(TITLE)
        return api, frameworks, window, control

    def test_reobserve_the_same_handle_never_enumerates_or_uses_cg(self):
        api, frameworks, window, _ = self.discovered()
        before = len(frameworks.requests)
        raw = api.owned_window(window)
        self.assertIs(raw["id"], window)
        after = frameworks.requests[before:]
        # No AXWindows enumeration at all: the retained handle is re-proven.
        self.assertNotIn("AXWindows", [request[2] for request in after if request[0] == "copy"])
        self.assertIn(("getpid", window), after)

    def test_foreign_handle_and_same_looking_clone_are_refused(self):
        api, _, _, _ = self.discovered()
        other, _ = owned_window(title=OTHER_TITLE)
        clone, _ = owned_window()
        self.assertIsNone(api.owned_window(other))
        self.assertIsNone(api.owned_window(clone))

    def test_handle_whose_pid_changed_is_refused(self):
        window, _ = owned_window()
        api, frameworks = scoped([window], getpid=lambda element: (0, OTHER_PID))
        api._owned_scope_pid = OWNED_PID  # scope set directly; GetPid is foreign
        api._owned_handles.add(window)
        self.assertIsNone(api.owned_window(window))

    def test_identity_equal_uses_real_cf_equal_semantics(self):
        api, _, window, _ = self.discovered()
        clone, _ = owned_window()
        self.assertIs(api.identity_equal(window, window), True)
        self.assertIs(api.identity_equal(window, clone), False)


class ScopedFocusAndActivationTests(unittest.TestCase):
    def discovered(self, window, focused, front_pid=OWNED_PID):
        """Scope + discover with ``window`` as BOTH the only owned window and focus."""
        if focused == "window":
            focused = window
        api, frameworks = scoped([window], focused=focused, front_pid=front_pid)
        api.owned_discovery(TITLE)
        return api, frameworks

    def test_owned_ax_focused_window_proves_focus(self):
        window, _ = owned_window()
        api, _ = self.discovered(window, "window")
        chosen = {"id": window, "pid": OWNED_PID}
        state = api.focus_state(chosen)
        self.assertIs(state["window"], window)
        self.assertTrue(api.focus_identity(chosen, state))

    def test_foreign_focus_handle_is_refused(self):
        window, _ = owned_window()
        foreign, _ = owned_window(title=OTHER_TITLE)
        api, _ = self.discovered(window, foreign)
        chosen = {"id": window, "pid": OWNED_PID}
        self.assertIsNone(api.focus_state(chosen)["window"])
        self.assertFalse(api.focus_identity(chosen, {"pid": OWNED_PID, "window": foreign}))

    def test_same_pid_alone_never_proves_focus(self):
        window, _ = owned_window()
        api, _ = self.discovered(window, None)
        chosen = {"id": window, "pid": OWNED_PID}
        self.assertIsNone(api.focus_state(chosen)["window"])

    def test_scoped_activation_proves_the_owned_window(self):
        window, _ = owned_window()
        api, frameworks = self.discovered(window, "window")
        self.assertTrue(api.activate_owned({"id": window, "pid": OWNED_PID}))
        self.assertEqual(frameworks.activations, [OWNED_PID])

    def test_scoped_activation_without_focus_fails_closed(self):
        window, _ = owned_window()
        api, _ = self.discovered(window, None)
        with self.assertRaises(contract.ContractError) as error:
            api.activate_owned({"id": window, "pid": OWNED_PID})
        self.assertEqual(error.exception.code, "focus-lost")


class ScopedHitTests(unittest.TestCase):
    def test_hit_test_uses_the_retained_owned_handle(self):
        window, control = owned_window()
        api, frameworks = scoped([window], hit=control)
        api.owned_discovery(TITLE)
        self.assertTrue(api.hit_test_control({"id": window, "pid": OWNED_PID},
                                             LABEL, dict(CONTROL_FRAME), 440, 515))
        self.assertNotIn("AXWindowNumber", frameworks.names())

    def test_hit_test_foreign_handle_refused(self):
        window, control = owned_window()
        api, frameworks = scoped([window], hit=control)
        foreign, _ = owned_window(title=OTHER_TITLE)
        api.owned_discovery(TITLE)
        with self.assertRaises(contract.ContractError):
            api.hit_test_control({"id": foreign, "pid": OWNED_PID},
                                 LABEL, dict(CONTROL_FRAME), 440, 515)


class ScopedContractFlowTests(unittest.TestCase):
    """The real contract over MacAdapter, scoped, with CG inventory poisoned."""

    def test_inspect_receipts_the_opaque_handle_as_no_window_number(self):
        window, control = owned_window()
        api, frameworks = scoped([window], focused=window, front_pid=OWNED_PID)
        adapter = macos.MacAdapter(api=api)
        release = adapter.scope_owned_process(OWNED_PID)
        plan = contract.parse_request(json.dumps(
            {"title": TITLE, "executable": EXE, "actions": [], "inspect": True}).encode())
        try:
            with unittest.mock.patch.object(contract, "monotonic", return_value=0):
                result = contract.execute(plan, adapter)
        finally:
            release()
        self.assertIsNone(result["window"])
        self.assertEqual(result["pid"], OWNED_PID)
        self.assertEqual(result["x"], WINDOW_FRAME["x"])
        self.assertEqual(set(result["status"]), set(contract.STATUS_FIELDS))
        self.assertTrue(all(type(value) is bool for value in result["status"].values()))
        # The opaque handle never reaches the serialized result.
        payload = json.dumps(result)
        self.assertNotIn("Node", payload)
        self.assertEqual(api.owned_pid_scope(), None)


class UnscopedPathTests(unittest.TestCase):
    def test_unscoped_api_has_no_owned_scope(self):
        api = api_for(FakeFrameworks([]))
        self.assertIsNone(api.owned_pid_scope())
        with self.assertRaises(contract.ContractError) as error:
            api.owned_discovery(TITLE)
        self.assertEqual(error.exception.code, "a11y-query")

    def test_status_contract_unchanged(self):
        api = api_for(FakeFrameworks([]))
        self.assertEqual(api.read_status({}, {}), macos._empty_status())
        self.assertEqual(set(api.read_status({}, {})), set(contract.STATUS_FIELDS))

    def test_adapter_unscoped_uses_the_unchanged_cg_path(self):
        frameworks = FakeFrameworks([])
        adapter = macos.MacAdapter(api=api_for(frameworks))
        # Poisoned CG inventory proves the unscoped path is the CG one.
        with self.assertRaises(AssertionError):
            adapter.list_windows()


if __name__ == "__main__":
    unittest.main()
