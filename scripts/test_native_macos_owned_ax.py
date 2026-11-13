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
import io
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
    """One fake AXUIElement backed by a plain attribute dict."""

    def __init__(self, **attributes):
        self.attributes = attributes


class OpaqueHandle:
    """An AXUIElement stand-in that is UNHASHABLE and NOT weak-referenceable.

    A real native element need satisfy neither property, so the retained
    handle must never depend on hashing, weak references or Python ``id``.
    """

    __slots__ = ("node",)
    __hash__ = None

    def __init__(self, node):
        self.node = node


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
    kCGWindowLayer = "layer"
    kCGWindowOwnerPID = "pid"
    kCGWindowNumber = "number"
    kCGWindowBounds = "bounds"
    kCGWindowName = "name"

    def __init__(self, windows, focused=None, front_pid=OWNED_PID, hit=None,
                 getpid=None, cg_windows=None):
        self.windows = list(windows)
        # None keeps the CoreGraphics inventory POISONED (the default);
        # a list opts the UNSCOPED path into a working CG inventory.
        self.cg_windows = None if cg_windows is None else list(cg_windows)
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
        return (0, self._node(element).attributes["_pid"])

    def AXUIElementCopyAttributeValue(self, element, name, out):
        self.requests.append(("copy", element, name))
        if name in FORBIDDEN:
            raise AssertionError("forbidden attribute requested: " + name)
        element = self._node(element)
        application = element.attributes.get("_application")
        if application is not None:
            if name == "AXWindows":
                return (0, [w for w in self.windows
                            if self._node(w).attributes["_pid"] == application])
            if name == "AXFocusedWindow":
                return (0, self.focused) if self.focused is not None else (NO_VALUE, None)
            # The application root reports AXApplication exactly as in the C API.
            return (0, "AXApplication") if name == "AXRole" else (NO_VALUE, None)
        value = element.attributes.get(name)
        return (NO_VALUE, None) if value is None else (0, value)

    @staticmethod
    def _node(element):
        return element.node if isinstance(element, OpaqueHandle) else element

    def AXUIElementCopyElementAtPosition(self, application, x, y, out):
        self.requests.append(("at", application, x, y))
        return (0, self.hit)

    # One active display covering every test rectangle. These are the CG
    # DISPLAY queries, never the CG window inventory (which stays poisoned).
    def CGGetActiveDisplayList(self, limit, displays, count):
        self.requests.append(("display_list",))
        return (0, [("display", 0)], 1)

    def CGDisplayBounds(self, display):
        self.requests.append(("display_bounds",))
        return ((0, 0), (4000, 3000))

    # Inert CG EVENT stubs (physical input, never the window inventory).
    kCGHIDEventTap = 0
    kCGEventMouseMoved = 5
    kCGEventLeftMouseDown = 1
    kCGEventLeftMouseUp = 2

    def CGEventCreateMouseEvent(self, source, kind, point, button):
        return ("mouse", kind, tuple(point))

    def CGEventPost(self, tap, event):
        self.requests.append(("post", event))

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
        self.requests.append(("cg_list",))
        if self.cg_windows is None:
            # The default: ANY CoreGraphics inventory touch is a hard failure.
            raise AssertionError("CoreGraphics window inventory touched")
        return [dict(entry) for entry in self.cg_windows]

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

    def processIdentifier(self):
        return self.pid

    def isFinishedLaunching(self):
        return True

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

    def test_multiple_owned_windows_are_ambiguous_at_discovery(self):
        first, _ = owned_window()
        second, _ = owned_window(title=OTHER_TITLE)
        api, frameworks = scoped([first, second])
        with self.assertRaises(contract.ContractError) as error:
            api.owned_discovery(TITLE)
        self.assertEqual(error.exception.code, "window-ambiguous")
        # Every PID is proven, but ambiguity never reads any window title.
        self.assertNotIn("AXTitle", frameworks.names())
        self.assertEqual(len([r for r in frameworks.requests if r[0] == "getpid"]),
                         len(api.owned_windows(OWNED_PID)))

    def test_initial_wrong_title_is_not_ready_and_never_adopted(self):
        # Initial discovery polls: a not-yet-correct title is not-ready, not a
        # hard failure, and the wrong window is never accepted or retained.
        window, _ = owned_window(title=OTHER_TITLE)
        api, _ = scoped([window])
        self.assertEqual(api.owned_discovery(TITLE), ([], False))
        self.assertIsNone(api._retained_handle())

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

    def test_reobserve_re_enumerates_only_the_owned_windows(self):
        api, frameworks, window, _ = self.discovered()
        before = len(frameworks.requests)
        raw = api.owned_window(window)
        self.assertIs(raw["id"], window)
        after = frameworks.requests[before:]
        # It MUST re-enumerate the owned PID's AXWindows (no CG, no shortcut)...
        self.assertIn("AXWindows", [r[2] for r in after if r[0] == "copy"])
        # ...prove the PID before any title/frame, then match the handle.
        kinds = [r[0] if r[0] != "copy" else r[2] for r in after]
        self.assertLess(kinds.index("getpid"), kinds.index("AXTitle"))
        self.assertIn(("getpid", window), after)

    def test_foreign_handle_and_same_looking_clone_are_refused(self):
        api, _, window, _ = self.discovered()
        other, _ = owned_window(title=OTHER_TITLE)
        clone, _ = owned_window()
        for foreign in (other, clone, None):
            with self.subTest(foreign=foreign):
                with self.assertRaises(contract.ContractError) as error:
                    api.owned_window(foreign)
                self.assertEqual(error.exception.code, "window-changed")

    def test_handle_whose_pid_changed_is_refused(self):
        window, _ = owned_window()
        api, frameworks = scoped([window], getpid=lambda element: (0, OTHER_PID))
        api.scope_to_owned_pid(OWNED_PID)
        api._owned_handles.append(window)  # retained, but GetPid now answers foreign
        with self.assertRaises(contract.ContractError) as error:
            api.owned_window(window)
        self.assertEqual(error.exception.code, "a11y-query")

    def test_identity_equal_uses_real_cf_equal_semantics(self):
        api, _, window, _ = self.discovered()
        clone, _ = owned_window()
        self.assertIs(api.identity_equal(window, window), True)
        self.assertIs(api.identity_equal(window, clone), False)


class PostDiscoveryChangeTests(unittest.TestCase):
    """A change AFTER discovery must refuse before any input, on every path."""

    def discovered(self):
        window, control = owned_window()
        api, frameworks = scoped([window], focused=window, hit=control)
        api.owned_discovery(TITLE)
        return api, frameworks, window

    def paths(self, api, window):
        """Every scoped path that could authorise input, as callables."""
        chosen = {"id": window, "pid": OWNED_PID}
        return {
            "read_window": lambda: api.owned_window(window),
            "controls": lambda: api.owned_element_controls(window),
            "focus_state": lambda: api.focus_state(chosen),
            "focus_identity": lambda: api.focus_identity(
                chosen, {"pid": OWNED_PID, "window": window}),
            "hit_test": lambda: api.hit_test_control(
                chosen, LABEL, dict(CONTROL_FRAME), 440, 515),
            "activate": lambda: api.activate_owned(chosen),
        }

    @staticmethod
    def assert_not_authorised(test, call):
        """A path refuses or reports no window identity; never authorises."""
        try:
            result = call()
        except contract.ContractError:
            return
        if type(result) is dict:
            test.assertIsNone(result.get("window"))
        elif result is not None:
            test.assertIs(result, False)

    def test_second_owned_window_after_discovery_refuses_everywhere(self):
        api, frameworks, window = self.discovered()
        frameworks.windows.append(owned_window(title=OTHER_TITLE)[0])
        for name, call in self.paths(api, window).items():
            with self.subTest(path=name):
                self.assert_not_authorised(self, call)
        self.assertEqual(frameworks.activations, [])
        self.assertFalse([r for r in frameworks.requests if r[0] == "at"])

    def test_title_change_after_discovery_refuses_everywhere(self):
        api, frameworks, window = self.discovered()
        window.attributes["AXTitle"] = "Locklark · 改了标题"
        for name, call in self.paths(api, window).items():
            with self.subTest(path=name):
                self.assert_not_authorised(self, call)
        self.assertEqual(frameworks.activations, [])
        self.assertFalse([r for r in frameworks.requests if r[0] == "at"])

    def test_window_disappearing_after_discovery(self):
        api, frameworks, window = self.discovered()
        frameworks.windows.clear()
        self.assertIsNone(api.owned_window(window))
        with self.assertRaises(contract.ContractError):
            api.owned_element_controls(window)

    def test_replaced_handle_after_discovery_is_refused(self):
        api, frameworks, window = self.discovered()
        replacement, _ = owned_window()
        frameworks.windows[:] = [replacement]
        with self.assertRaises(contract.ContractError) as error:
            api.owned_window(window)
        self.assertEqual(error.exception.code, "window-changed")


class RetainedHandleTests(unittest.TestCase):
    def test_unhashable_and_non_weakref_handle_is_retained_and_proven(self):
        window, _ = owned_window()
        handle = OpaqueHandle(window)
        import weakref
        with self.assertRaises(TypeError):
            weakref.ref(handle)
        with self.assertRaises(TypeError):
            hash(handle)
        frameworks = FakeFrameworks([handle])
        api = api_for(frameworks)
        api.scope_to_owned_pid(OWNED_PID)
        windows, unique = api.owned_discovery(TITLE)
        self.assertTrue(unique)
        self.assertIs(windows[0]["id"], handle)
        # Re-observation re-enumerates and matches by CFEqual, not by hash.
        self.assertIs(api.owned_window(handle)["id"], handle)
        self.assertTrue(api.owned_element_controls(handle))

    def test_retained_list_is_strong_and_bounded(self):
        window, _ = owned_window()
        api, _ = scoped([window])
        api.owned_discovery(TITLE)
        self.assertEqual(len(api._owned_handles), 1)
        self.assertIs(api._owned_handles[0], window)
        self.assertNotIsInstance(api._owned_handles, (set, frozenset))

    def test_release_clears_title_and_retained_handles(self):
        window, _ = owned_window()
        api, _ = scoped([window])
        api.owned_discovery(TITLE)
        self.assertEqual(api.owned_scope_title(), TITLE)
        self.assertEqual(len(api._owned_handles), 1)
        api.unscope_owned_pid()
        self.assertIsNone(api.owned_pid_scope())
        self.assertIsNone(api.owned_scope_title())
        self.assertIsNone(api._owned_handles)
        with self.assertRaises(contract.ContractError):
            api.owned_window(window)

    def test_scope_title_cannot_be_repointed(self):
        window, _ = owned_window()
        api, _ = scoped([window])
        api.owned_discovery(TITLE)
        with self.assertRaises(contract.ContractError) as error:
            api.set_owned_scope_title(OTHER_TITLE)
        self.assertEqual(error.exception.code, "window-changed")


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
        plan = contract.parse_request(json.dumps(
            {"title": TITLE, "executable": EXE, "actions": [], "inspect": True,
             "owned_pid": OWNED_PID}).encode())
        with unittest.mock.patch.object(contract, "monotonic", return_value=0):
            result = contract.execute(plan, adapter)
        self.assertIsNone(result["window"])
        self.assertEqual(result["pid"], OWNED_PID)
        self.assertEqual(result["x"], WINDOW_FRAME["x"])
        self.assertEqual(set(result["status"]), set(contract.STATUS_FIELDS))
        self.assertTrue(all(type(value) is bool for value in result["status"].values()))
        # The opaque handle never reaches the serialized result.
        payload = json.dumps(result)
        self.assertNotIn("Node", payload)
        # execute() leaves release to run_stdin (the request boundary)...
        self.assertEqual(api.owned_pid_scope(), OWNED_PID)
        for release in plan["releases"]:
            release()
        # ...and releasing clears every scoped artifact.
        self.assertIsNone(api.owned_pid_scope())
        self.assertIsNone(api.owned_scope_title())
        self.assertIsNone(api._retained_handle())


class RealEntryPointTests(unittest.TestCase):
    """The REAL nativesmain/run_stdin over a scoped driver, CG fully poisoned."""

    def entry(self, api, request, clock=None):
        """Run ``browser_native_macos.main`` once, returning (code, result, err)."""
        stdout, stderr = io.StringIO(), io.StringIO()
        clock = clock or _Clock()
        # main() builds MacAdapter() itself; the REAL class is used, only its
        # api is injected (a class-level patch keeps MacAdapter._native_title).
        with unittest.mock.patch.object(
                macos.MacAdapter, "__init__",
                lambda self, *args, **kwargs: setattr(self, "api", api)), \
                unittest.mock.patch.object(contract, "monotonic", clock.monotonic), \
                unittest.mock.patch.object(contract, "sleep", clock.sleep):
            code = macos.main(io.BytesIO(request), stdout, stderr)
        return code, stdout.getvalue(), stderr.getvalue()

    def scoped_api(self):
        window, control = owned_window()
        api, frameworks = scoped([window], focused=window, front_pid=OWNED_PID,
                                 hit=control)
        return api, frameworks, window

    def test_real_main_scoped_inspect_has_null_window_and_cleans_up(self):
        api, frameworks, window = self.scoped_api()
        request = json.dumps({"title": TITLE, "executable": EXE, "owned_pid": OWNED_PID,
                              "actions": [{"click_label": LABEL}],
                              "inspect": True}).encode()
        code, out, err = self.entry(api, request)
        self.assertEqual((code, err), (0, ""))
        result = json.loads(out)
        self.assertIsNone(result["window"])                  # opaque handle
        self.assertIsNone(result["clicks"][0]["window"])     # null receipt
        self.assertEqual(result["pid"], OWNED_PID)
        self.assertEqual(set(result["status"]), set(contract.STATUS_FIELDS))
        self.assertTrue(all(type(v) is bool for v in result["status"].values()))
        # The scope never outlives the request.
        self.assertIsNone(api.owned_pid_scope())
        self.assertIsNone(api.owned_scope_title())
        self.assertIsNone(api._retained_handle())
        self.assertNotIn("CGWindowList", " ".join(r[0] for r in frameworks.requests))

    def test_real_main_scoped_absence_never_uses_cg(self):
        api, frameworks, window = self.scoped_api()
        request = json.dumps({"title": TITLE, "executable": EXE, "owned_pid": OWNED_PID,
                              "wait_absent": True}).encode()
        clock = _Clock()
        code, out, err = self.entry(api, request, clock)
        # The exact-title window IS present: the bounded wait refuses at the
        # unchanged deadline as window-changed, never as "absent", and never
        # through CoreGraphics.
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("code=window-changed", err)
        self.assertGreaterEqual(clock.now, contract.CONTROL_TIMEOUT)
        self.assertIsNone(api.owned_pid_scope())

    def test_real_main_scoped_absence_reports_absent_for_other_title(self):
        window, _ = owned_window(title=OTHER_TITLE)
        api, frameworks = scoped([window])
        request = json.dumps({"title": TITLE, "executable": EXE, "owned_pid": OWNED_PID,
                              "wait_absent": True}).encode()
        code, out, err = self.entry(api, request)
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(json.loads(out), {"absent": True})

    def test_malformed_pid_title_or_executable_refused_before_any_ax(self):
        cases = (
            {"title": TITLE, "executable": EXE, "owned_pid": 0},
            {"title": TITLE, "executable": EXE, "owned_pid": -5},
            {"title": TITLE, "executable": EXE, "owned_pid": True},
            {"title": TITLE, "executable": EXE, "owned_pid": 4242.0},
            {"title": TITLE, "executable": EXE, "owned_pid": "4242"},
            {"title": TITLE, "executable": EXE, "owned_pid": None},
            {"executable": EXE, "owned_pid": OWNED_PID},
            {"title": TITLE, "owned_pid": OWNED_PID},
            {"title_prefix": "Locklark", "executable": EXE, "owned_pid": OWNED_PID},
            {"title": TITLE, "executable": "relative/path", "owned_pid": OWNED_PID},
        )
        for document in cases:
            with self.subTest(keys=sorted(document)):
                window, _ = owned_window()
                frameworks = FakeFrameworks([window])   # NEVER pre-scoped
                api = api_for(frameworks)
                code, out, err = self.entry(api, json.dumps(document).encode())
                self.assertEqual(code, 1)
                self.assertEqual(out, "")
                # NOTHING reached ApplicationServices or CoreGraphics.
                self.assertEqual(frameworks.requests, [])
                self.assertEqual(api.owned_pid_scope(), None)

    def test_scope_released_when_execution_raises_after_installing_it(self):
        # The REAL execute() installs the scope, then the discovery hook blows
        # up mid-request: the finally must still release it.
        window, _ = owned_window()
        api = api_for(FakeFrameworks([window]))
        adapter = macos.MacAdapter(api=api)

        def explode(title):
            raise RuntimeError("private mid-request failure")

        api.owned_discovery = explode
        request = json.dumps({"title": TITLE, "executable": EXE, "owned_pid": OWNED_PID,
                              "actions": [{"click_label": LABEL}]}).encode()
        stdout, stderr = io.StringIO(), io.StringIO()
        with unittest.mock.patch.object(
                macos.MacAdapter, "__init__",
                lambda self, *a, **k: setattr(self, "api", api)):
            code = macos.main(io.BytesIO(request), stdout, stderr)
        self.assertEqual(code, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("code=unexpected", stderr.getvalue())
        # The scope was installed and is gone now that the request ended.
        self.assertIsNone(api.owned_pid_scope())
        self.assertIsNone(api.owned_scope_title())
        self.assertIsNone(api._retained_handle())
        self.assertEqual(api._owned_handles, None)

        # Prove the release really ran by running the same request again: a
        # leaked scope would make the second scope call see a stale title.
        api.owned_discovery = lambda title: ([], False)
        stdout = io.StringIO()
        with unittest.mock.patch.object(
                macos.MacAdapter, "__init__",
                lambda self, *a, **k: setattr(self, "api", api)), \
                unittest.mock.patch.object(contract, "monotonic", _Clock().monotonic), \
                unittest.mock.patch.object(contract, "sleep", _Clock().sleep):
            macos.main(io.BytesIO(request), stdout, io.StringIO())
        self.assertIsNone(api.owned_pid_scope())

    def test_unscoped_real_main_still_uses_the_cg_path(self):
        api = api_for(FakeFrameworks([]))
        request = json.dumps({"title": TITLE, "executable": EXE, "actions": []}).encode()
        code, out, err = self.entry(api, request)
        # Unscoped macOS keeps its CG inventory path; here it is poisoned.
        self.assertIn("unexpected", err)


class AbsenceRegressionTests(unittest.TestCase):
    """UNSCOPED absence keeps the CG path; SCOPED absence never falls back."""

    @staticmethod
    def cg_window(title=TITLE, pid=OTHER_PID, number=0x300001):
        return {"layer": 0, "pid": pid, "number": number,
                "bounds": {"X": 10, "Y": 20, "Width": 800, "Height": 600},
                "name": title}

    def entry(self, api, request, clock=None):
        stdout, stderr = io.StringIO(), io.StringIO()
        clock = clock or _Clock()
        with unittest.mock.patch.object(
                macos.MacAdapter, "__init__",
                lambda self, *a, **k: setattr(self, "api", api)), \
                unittest.mock.patch.object(contract, "monotonic", clock.monotonic), \
                unittest.mock.patch.object(contract, "sleep", clock.sleep):
            code = macos.main(io.BytesIO(request), stdout, stderr)
        return code, stdout.getvalue(), stderr.getvalue(), clock

    def test_unscoped_absence_still_uses_the_normal_cg_path(self):
        # A NON-owned PID's CG window carries the exact title: unscoped absence
        # must still SEE it (present) and refuse window-changed at the deadline.
        frameworks = FakeFrameworks([], cg_windows=[self.cg_window()])
        api = api_for(frameworks)
        request = json.dumps({"title": TITLE, "executable": EXE,
                              "wait_absent": True}).encode()
        code, out, err, clock = self.entry(api, request, _Clock())
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("code=window-changed", err)
        # It really went through the CG inventory, never the owned hook.
        self.assertIn(("cg_list",), frameworks.requests)
        self.assertGreaterEqual(clock.now, contract.CONTROL_TIMEOUT)

    def test_unscoped_absence_reports_absent_from_the_cg_path(self):
        frameworks = FakeFrameworks([], cg_windows=[self.cg_window(title=OTHER_TITLE)])
        api = api_for(frameworks)
        request = json.dumps({"title": TITLE, "executable": EXE,
                              "wait_absent": True}).encode()
        code, out, err, clock = self.entry(api, request)
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(json.loads(out), {"absent": True})
        self.assertIn(("cg_list",), frameworks.requests)
        self.assertEqual(clock.sleeps, [])

    def test_unscoped_absence_never_calls_the_owned_hook(self):
        # Even on a SCOPED-CAPABLE adapter object, an unscoped plan uses the
        # CG path: the owned hook is not consulted merely because it exists.
        frameworks = FakeFrameworks([], cg_windows=[self.cg_window()])

        class ScopedCapable(macos.MacAdapter):
            """Has owned absence (via the API) but is NOT scoped here."""

            def scope_owned_process(self, pid):
                raise AssertionError("unscoped request must not be scoped")

        api = api_for(frameworks)
        adapter = ScopedCapable(api=api)
        self.assertIsNone(api.owned_pid_scope())
        calls = []
        original = macos.MacAdapter.owned_absence

        def spy(self, plan):
            calls.append(plan.get("owned_pid"))
            return original(self, plan)

        plan = contract.parse_request(json.dumps(
            {"title": TITLE, "executable": EXE, "wait_absent": True}).encode())
        self.assertTrue(callable(getattr(adapter, "owned_absence", None)))
        self.assertIsNone(plan["owned_pid"])
        with unittest.mock.patch.object(macos.MacAdapter, "owned_absence", spy), \
                unittest.mock.patch.object(contract, "monotonic", _Clock().monotonic), \
                unittest.mock.patch.object(contract, "sleep", _Clock().sleep):
            with self.assertRaises(contract.ContractError):
                contract.execute(plan, adapter)
        self.assertEqual(calls, [])
        self.assertIn(("cg_list",), frameworks.requests)

    def test_scoped_absence_never_falls_back_to_cg(self):
        # The owned hook blows up: the request refuses and NEVER touches CG.
        window, _ = owned_window(title=TITLE)
        frameworks = FakeFrameworks([window])
        api = api_for(frameworks)
        api.owned_absence = lambda plan: (_ for _ in ()).throw(RuntimeError("private"))
        request = json.dumps({"title": TITLE, "executable": EXE,
                              "owned_pid": OWNED_PID, "wait_absent": True}).encode()
        code, out, err, clock = self.entry(api, request)
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertNotIn(("cg_list",), frameworks.requests)
        self.assertIsNone(api.owned_pid_scope())

    def test_scoped_absence_without_the_hook_refuses_not_cg(self):
        window, _ = owned_window()
        frameworks = FakeFrameworks([window])

        class NoOwnedHook(macos.MacAdapter):
            """A scoped-capable adapter that simply has no owned absence hook."""

            owned_absence = None

        api = api_for(frameworks)
        api.owned_absence = None
        adapter = NoOwnedHook(api=api)
        plan = contract.parse_request(json.dumps(
            {"title": TITLE, "executable": EXE, "owned_pid": OWNED_PID,
             "wait_absent": True}).encode())
        with unittest.mock.patch.object(contract, "monotonic", _Clock().monotonic), \
                unittest.mock.patch.object(contract, "sleep", _Clock().sleep):
            with self.assertRaises(contract.ContractError) as error:
                contract.execute(plan, adapter)
        self.assertEqual(error.exception.code, "a11y-query")
        self.assertNotIn(("cg_list",), frameworks.requests)
        for release in plan["releases"]:
            release()

    def test_scoped_absence_matches_the_canonical_executable_path(self):
        # The owned window's executable is the canonical absolute path; a
        # non-normalised but equivalent request path must still match.
        window, _ = owned_window()
        api, frameworks = scoped([window])
        variant = "/opt/locklark/./locklark-desktop"
        request = json.dumps({"title": TITLE, "executable": variant,
                              "owned_pid": OWNED_PID, "wait_absent": True}).encode()
        code, out, err, clock = self.entry(api, request, _Clock())
        # Present via the canonical comparison -> deadline refusal, not absent.
        self.assertEqual(code, 1)
        self.assertIn("code=window-changed", err)
        self.assertGreaterEqual(clock.now, contract.CONTROL_TIMEOUT)
        self.assertNotIn(("cg_list",), frameworks.requests)

    def test_scoped_absence_reports_absent_for_a_different_executable(self):
        window, _ = owned_window()
        api, frameworks = scoped([window])
        request = json.dumps({"title": TITLE, "executable": "/opt/other/app",
                              "owned_pid": OWNED_PID, "wait_absent": True}).encode()
        code, out, err, clock = self.entry(api, request, _Clock())
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(json.loads(out), {"absent": True})
        self.assertNotIn(("cg_list",), frameworks.requests)

    def test_activation_only_path_never_touches_cg(self):
        frameworks = FakeFrameworks([])
        api = api_for(frameworks)
        request = json.dumps({"activate_pid": OWNED_PID, "executable": EXE}).encode()
        code, out, err, clock = self.entry(api, request)
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(json.loads(out), {"activated": True})
        self.assertEqual(frameworks.activations, [OWNED_PID])
        self.assertNotIn(("cg_list",), frameworks.requests)


class _Clock:
    """Deterministic monotonic/sleep for the real discovery deadline loop."""

    def __init__(self):
        self.now = 0.0
        self.sleeps = []

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


class OwnedDiscoveryContractTests(unittest.TestCase):
    """The REAL contract discovery loop over owned-AX fakes."""

    def run_plan(self, api, clock, actions=None, inspect=False):
        """The REAL path: parse an owned_pid request, then execute it."""
        adapter = macos.MacAdapter(api=api)
        request = json.dumps({"title": TITLE, "executable": EXE,
                              "owned_pid": OWNED_PID,
                              "actions": list(actions or ()), "inspect": inspect}).encode()
        plan = contract.parse_request(request)
        with unittest.mock.patch.object(contract, "monotonic", clock.monotonic), \
                unittest.mock.patch.object(contract, "sleep", clock.sleep):
            return contract.execute(plan, adapter)

    def test_wrong_title_polls_until_exact_title_before_the_deadline(self):
        window, _ = owned_window(title=OTHER_TITLE)
        api, frameworks = scoped([window])
        clock = _Clock()
        # The owned window is renamed to the EXACT fixture title only after
        # five not-ready polls - still well before DISCOVER_TIMEOUT.
        original_discovery = api.owned_discovery

        def discovery(title):
            result = original_discovery(title)
            if len(clock.sleeps) == 5:
                window.attributes["AXTitle"] = TITLE
            return result

        api.owned_discovery = discovery
        result = self.run_plan(api, clock)
        self.assertIsNone(result["window"])       # opaque handle: no window number
        self.assertEqual(result["pid"], OWNED_PID)
        self.assertEqual(result["x"], WINDOW_FRAME["x"])
        # Exactly the unchanged poll interval was slept, under the deadline.
        self.assertEqual(set(clock.sleeps), {contract.POLL})
        self.assertLess(clock.now, contract.DISCOVER_TIMEOUT)

    def test_wrong_title_is_never_accepted_and_times_out_at_the_deadline(self):
        window, _ = owned_window(title=OTHER_TITLE)
        api, frameworks = scoped([window])
        clock = _Clock()
        with self.assertRaises(contract.ContractError) as error:
            self.run_plan(api, clock)
        self.assertEqual(error.exception.code, "window-timeout")
        # The deadline is the unchanged DISCOVER_TIMEOUT, not an early refusal.
        self.assertGreaterEqual(clock.now, contract.DISCOVER_TIMEOUT)
        self.assertLess(clock.now, contract.DISCOVER_TIMEOUT + contract.POLL)
        # The wrong-title window was never accepted, adopted or used.
        self.assertIsNone(api._retained_handle())
        self.assertFalse([r for r in frameworks.requests if r[0] == "at"])

    def test_title_change_after_binding_still_refuses_immediately(self):
        window, control = owned_window()
        api, frameworks = scoped([window], focused=window, hit=control)
        clock = _Clock()
        adapter = macos.MacAdapter(api=api)
        release = adapter.scope_owned_process(OWNED_PID)
        plan = {"title": TITLE, "title_prefix": None, "executable": EXE,
                "actions": ({"click_label": LABEL},), "inspect": False,
                "wait_absent": False, "preserve_focus": False,
                "activation": None, "owned_pid": None}
        try:
            with unittest.mock.patch.object(contract, "monotonic", clock.monotonic), \
                    unittest.mock.patch.object(contract, "sleep", clock.sleep):
                adapter.observe_plan(plan)
                budget = contract.Budget()
                bound = contract.find_window(plan, adapter, budget)
                self.assertIs(bound["id"], window)
                self.assertIs(api._retained_handle(), window)
                # The title changes only AFTER the window was accepted.
                window.attributes["AXTitle"] = OTHER_TITLE
                for name, path in (
                        ("reobserve", lambda: contract.reobserve_window(
                            plan, adapter, bound, budget)),
                        ("authorize", lambda: contract.authorize(
                            plan, adapter, bound, budget, LABEL))):
                    with self.subTest(path=name):
                        with self.assertRaises(contract.ContractError) as error:
                            path()
                        self.assertEqual(error.exception.code, "window-changed")
        finally:
            release()
        # The refusal was immediate: no poll after binding, no input attempted.
        self.assertEqual(clock.sleeps, [])
        self.assertEqual([r for r in frameworks.requests if r[0] == "at"], [])

    def test_ambiguity_and_foreign_pid_still_refuse(self):
        first, _ = owned_window()
        second, _ = owned_window(title=OTHER_TITLE)
        api, _ = scoped([first, second])
        with self.assertRaises(contract.ContractError) as error:
            self.run_plan(api, _Clock())
        self.assertEqual(error.exception.code, "window-ambiguous")

        foreign, _ = owned_window(pid=OTHER_PID)
        api, _ = scoped([foreign])
        with self.assertRaises(contract.ContractError) as error:
            self.run_plan(api, _Clock())
        self.assertEqual(error.exception.code, "window-timeout")


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
