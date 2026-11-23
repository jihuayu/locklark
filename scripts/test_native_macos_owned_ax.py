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

TITLE = "Passme · 本地金库"
OTHER_TITLE = "Passme · 另一个窗口"
OWNED_PID = 4242
OTHER_PID = 4243
EXE = "/opt/passme/passme-desktop"
NO_VALUE = -25212
WINDOW_FRAME = {"x": 313, "y": 75, "width": 1102, "height": 822}
CONTROL_FRAME = {"x": 400, "y": 500, "width": 80, "height": 30}
LABEL = "解锁"
FORBIDDEN = ("AXWindowNumber", "AXValue", "AXSelectedText", "AXLabel")


# Markers for ``FakeFrameworks.front_answer`` (see ``_Front``).
CALLABLE = object()
MISSING = object()


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
                 getpid=None, cg_windows=None, front_answer=CALLABLE):
        self.windows = list(windows)
        # None keeps the CoreGraphics inventory POISONED (the default);
        # a list opts the UNSCOPED path into a working CG inventory.
        self.cg_windows = None if cg_windows is None else list(cg_windows)
        self.focused = focused
        self.front_pid = front_pid
        # ``front_answer`` chooses how the fresh frontmost app exposes its
        # ``processIdentifier``: ``CALLABLE`` keeps the real method; anything
        # else is installed (or the attribute removed) before any lookup.
        self.front_answer = front_answer
        self.hit = hit
        self.getpid = getpid
        self.requests = []
        self.activations = []
        self.capability_calls = 0
        self.applications = {}

    def __getattr__(self, name):
        # EVERY CoreGraphics window-list entry point is a hard failure.
        if name.startswith("CGWindowList"):
            raise AssertionError("CoreGraphics window inventory touched: " + name)
        raise AttributeError(name)

    # -- ApplicationServices ----------------------------------------------
    def AXIsProcessTrusted(self):
        self.capability_calls += 1
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
        if pid is None:
            return None
        return _Front(pid, self.frameworks.front_answer)


def _real_process_identifier(front):
    """The fake frontmost app's real bound method: its PID."""
    return front.pid


class _Front:
    """A fresh frontmost app answering ``processIdentifier`` as requested.

    The answer is installed when the object is built, BEFORE any lookup, so
    the method under test never observes a class-level state. ``CALLABLE``
    keeps the real bound method; ``MISSING`` removes the attribute entirely;
    any other answer (``_raises`` included) is the installed attribute.
    """

    processIdentifier = _real_process_identifier

    def __init__(self, pid, answer=CALLABLE):
        _Front.processIdentifier = _real_process_identifier
        self.pid = pid
        if answer is CALLABLE:
            return
        if answer is MISSING:
            del _Front.processIdentifier
        else:
            _Front.processIdentifier = answer


class _Libproc:
    """Controllable libproc answers; no process or kernel call is made."""

    def __init__(self, path=EXE, uid=None, start_sec=1700000000,
                 start_usec=123, pid=None, path_result=None, info_size=None,
                 error=None):
        self.path = path
        self.uid = os.geteuid() if uid is None else uid
        self.start_sec = start_sec
        self.start_usec = start_usec
        self.pid = pid
        self.path_result = path_result
        self.info_size = info_size
        self.error = error
        self.calls = []

    def proc_pidpath(self, pid, buffer, size):
        self.calls.append(("path", pid))
        if self.error is not None:
            raise self.error
        if self.path_result is not None:
            return self.path_result
        buffer.value = self.path.encode()
        return len(self.path)

    def proc_pidinfo(self, pid, flavor, arg, info, size):
        self.calls.append(("info", pid))
        if self.error is not None:
            raise self.error
        buffer = ctypes.cast(info, ctypes.POINTER(ctypes.c_char * size)).contents
        bsd = macos.BSDInfo.from_buffer(buffer)
        bsd.pbi_pid, bsd.pbi_uid = pid if self.pid is None else self.pid, self.uid
        bsd.pbi_start_tvsec, bsd.pbi_start_tvusec = self.start_sec, self.start_usec
        return size if self.info_size is None else self.info_size




def api_for(frameworks, libproc=None):
    api = macos.QuartzApi.__new__(macos.QuartzApi)
    api.ax = frameworks
    api.quartz = frameworks
    api.appkit = frameworks
    api.libproc = _Libproc() if libproc is None else libproc
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
        window.attributes["AXTitle"] = "Passme · 改了标题"
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


def _raises():
    raise RuntimeError("native lookup failed")


class IntSubclass(int):
    """An ``int`` subclass: equal to the PID but not the exact built-in type."""


# how a fresh frontmost app answers: (FakeFrameworks.front_answer, same answer
# installed on the app that focus_state sees AFTER activate_owned's activation)
FRONT_ANSWERS = {
    "missing": (MISSING, MISSING),
    "non_callable": ("4242", "4242"),
    "raising": (_raises, _raises),
    "string": ("4242", "4242"),
    "float": (4242.0, 4242.0),
    "bool_true": (True, True),
    "bool_false": (False, False),
    "int_subclass": (IntSubclass(OWNED_PID), IntSubclass(OWNED_PID)),
    "zero": (0, 0),
    "negative": (-1, -1),
    "different_pid": (OTHER_PID, OTHER_PID),
}

_MALFORMED = ("missing", "non_callable", "raising", "string", "float",
              "bool_true", "bool_false", "int_subclass", "zero", "negative")


class FrontmostPIDTests(unittest.TestCase):
    """foreground_pid accepts ONLY a callable exact-int positive PID."""

    def test_real_callable_exact_int_pid_is_accepted(self):
        for front_pid in (OWNED_PID, OTHER_PID):
            with self.subTest(front_pid=front_pid):
                api, _ = scoped([owned_window()[0]], front_pid=front_pid)
                self.assertIs(type(api.foreground_pid()), int)
                self.assertEqual(api.foreground_pid(), front_pid)

    def test_malformed_answers_are_no_pid(self):
        for name in _MALFORMED:
            with self.subTest(answer=name):
                window, _ = owned_window()
                api, _ = scoped([window], front_pid=OWNED_PID,
                                front_answer=FRONT_ANSWERS[name][0])
                api.owned_discovery(TITLE)
                self.assertIsNone(api.foreground_pid())
                state = api.focus_state({"id": window, "pid": OWNED_PID})
                self.assertIsNone(state["window"])
                self.assertIsNone(state["pid"])

    def test_no_frontmost_application_is_no_pid(self):
        window, _ = owned_window()
        api, _ = scoped([window], front_pid=None)
        self.assertIsNone(api.foreground_pid())

    def test_different_pid_never_satisfies_the_owned_focus(self):
        window, _ = owned_window()
        api, _ = scoped([window], focused=window, front_pid=OTHER_PID)
        api.owned_discovery(TITLE)
        self.assertEqual(api.foreground_pid(), OTHER_PID)
        state = api.focus_state({"id": window, "pid": OWNED_PID})
        self.assertEqual(state["pid"], OTHER_PID)
        self.assertIsNone(state["window"])

    def test_real_focused_window_still_proves_focus_with_exact_pid(self):
        window, _ = owned_window()
        api, _ = scoped([window], focused=window, front_pid=OWNED_PID)
        api.owned_discovery(TITLE)
        state = api.focus_state({"id": window, "pid": OWNED_PID})
        self.assertIs(state["window"], window)
        self.assertIs(api.focus_identity({"id": window, "pid": OWNED_PID}, state), True)

    def test_unscoped_real_focused_window_still_proves_focus(self):
        # The same exact AXFocusedWindow/CFEqual guard with NO owned scope: an
        # exact frontmost PID proves focus, and a different PID is refused by
        # that existing guard (no new unscoped semantics).
        for name, expected in (("callable", True), ("different_pid", False),
                               ("string", False), ("missing", False),
                               ("bool_true", False)):
            with self.subTest(answer=name):
                window, _ = owned_window()
                answer, _ = FRONT_ANSWERS.get(name, (CALLABLE, CALLABLE))
                frameworks = FakeFrameworks([window], focused=window,
                                            front_pid=OWNED_PID, cg_windows=[],
                                            front_answer=answer)
                api = api_for(frameworks)
                self.assertIsNone(api.owned_pid_scope())
                chosen = {"id": window, "pid": OWNED_PID, "title": TITLE,
                          "bounds": dict(WINDOW_FRAME)}
                state = api.focus_state(chosen)
                if expected:
                    self.assertIs(state["window"], window)
                    self.assertEqual(state["pid"], OWNED_PID)
                else:
                    self.assertIsNone(state["window"])


class ActivateOwnedFrontPIDTests(unittest.TestCase):
    """activate_owned's final frontmost check uses the same strict PID."""

    def discovered(self, front_pid=OWNED_PID):
        window, _ = owned_window()
        api, frameworks = scoped([window], focused=window, front_pid=front_pid)
        api.owned_discovery(TITLE)
        return api, frameworks, window

    @staticmethod
    def flip_after_focus(api, final):
        """The app focus_state sees is correct; only the final read differs."""
        real = api.focus_state
        calls = []

        def focus_state(chosen):
            state = real(chosen)
            api.appkit.front_answer = final
            calls.append(state)
            return state

        api.focus_state = focus_state
        return calls

    def test_real_owned_front_pid_activates_once(self):
        api, frameworks, window = self.discovered()
        self.assertIs(api.activate_owned({"id": window, "pid": OWNED_PID}), True)
        self.assertEqual(frameworks.activations, [OWNED_PID])

    def test_malformed_final_answers_refuse_focus_lost(self):
        for name in _MALFORMED:
            with self.subTest(answer=name):
                api, frameworks, window = self.discovered()
                calls = self.flip_after_focus(api, FRONT_ANSWERS[name][1])
                with self.assertRaises(contract.ContractError) as error:
                    api.activate_owned({"id": window, "pid": OWNED_PID})
                self.assertEqual(error.exception.code, "focus-lost")
                self.assertEqual(len(calls), 1)
                self.assertIs(calls[0]["window"], window)
                # The pre-activation proofs held; exactly one activation ran.
                self.assertEqual(frameworks.activations, [OWNED_PID])

    def test_different_pid_answer_refuses_focus_lost(self):
        api, frameworks, window = self.discovered()
        self.flip_after_focus(api, FRONT_ANSWERS["different_pid"][1])
        with self.assertRaises(contract.ContractError) as error:
            api.activate_owned({"id": window, "pid": OWNED_PID})
        self.assertEqual(error.exception.code, "focus-lost")
        self.assertEqual(frameworks.activations, [OWNED_PID])

    def test_different_pid_from_the_start_refuses_focus_lost(self):
        api, frameworks, window = self.discovered(front_pid=OTHER_PID)
        self.assertEqual(api.foreground_pid(), OTHER_PID)
        with self.assertRaises(contract.ContractError) as error:
            api.activate_owned({"id": window, "pid": OWNED_PID})
        self.assertEqual(error.exception.code, "focus-lost")
        # The pre-activation owned-handle proof passes and exactly one
        # activation is attempted; the final different-PID guard refuses.
        self.assertEqual(frameworks.activations, [OWNED_PID])


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
            {"title_prefix": "Passme", "executable": EXE, "owned_pid": OWNED_PID},
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
        variant = "/opt/passme/./passme-desktop"
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


class OwnedGenerationTests(unittest.TestCase):
    """Real process_generation over a fake libproc; no adapter stand-in."""

    class Fatal(BaseException):
        pass

    def generation(self, **overrides):
        value = {"pid": OWNED_PID, "executable": EXE, "euid": os.geteuid(),
                 "start_sec": 1700000000, "start_usec": 123}
        value.update(overrides)
        return value

    def api(self, windows=None, **libproc):
        frameworks = FakeFrameworks([] if windows is None else windows)
        api = api_for(frameworks, libproc=_Libproc(**libproc))
        api.scope_to_owned_pid(OWNED_PID)
        return api, frameworks

    def test_process_generation_reads_the_actual_libproc_identity(self):
        api, _ = self.api()
        self.assertEqual(api.process_generation(OWNED_PID), self.generation())

    def test_process_generation_is_none_for_malformed_or_raising_libproc(self):
        for libproc in ({"info_size": 0}, {"pid": OTHER_PID},
                        {"path_result": 0}, {"path": "", "path_result": 1},
                        {"start_sec": 0},
                        {"start_usec": 1000000}, {"error": self.Fatal()}):
            with self.subTest(libproc=libproc):
                api, _ = self.api(**libproc)
                self.assertIsNone(api.process_generation(OWNED_PID))

    def test_malformed_stale_and_wrong_euid_are_refused_before_any_ax(self):
        window, _ = owned_window()
        for altered in ({"start_usec": 124}, {"euid": os.geteuid() + 1}):
            with self.subTest(altered=altered):
                api, frameworks = self.api([window])
                with self.assertRaises(contract.ContractError) as error:
                    api.set_owned_generation(self.generation(**altered))
                self.assertEqual(error.exception.code, "process-untrusted")
                self.assertEqual(frameworks.requests, [])
        malformed = (None, {}, {**self.generation(), "extra": 1},
                     {**self.generation(), "pid": OTHER_PID},
                     {**self.generation(), "euid": True},
                     {**self.generation(), "start_sec": 0},
                     {**self.generation(), "start_usec": 1000000},
                     {**self.generation(), "executable": "relative"})
        for value in malformed:
            with self.subTest(value=value):
                api, frameworks = self.api([window])
                with self.assertRaises(contract.ContractError) as error:
                    api.set_owned_generation(value)
                self.assertEqual(error.exception.code, "process-untrusted")
                self.assertEqual(frameworks.requests, [])

    def test_bound_generation_is_rechecked_before_owned_ax(self):
        window, _ = owned_window()
        api, frameworks = self.api([window])
        api.set_owned_generation(self.generation())
        self.assertTrue(api._owned_generation_ok())
        api.libproc.start_usec += 1
        with self.assertRaises(contract.ContractError) as error:
            api.owned_windows(OWNED_PID)
        self.assertEqual(error.exception.code, "process-untrusted")
        self.assertEqual(frameworks.requests, [])

    def test_foreign_euid_matching_actual_generation_is_refused_before_capability(self):
        foreign = os.geteuid() + 1
        window, _ = owned_window()
        frameworks = FakeFrameworks([window])
        adapter = macos.MacAdapter(api=api_for(frameworks, libproc=_Libproc(uid=foreign)))
        plan = contract.parse_request(json.dumps({
            "title": TITLE, "executable": EXE, "owned_pid": OWNED_PID,
            "owned_generation": self.generation(euid=foreign), "actions": [],
        }))
        with self.assertRaises(contract.ContractError) as error:
            contract.execute(plan, adapter)
        self.assertEqual(error.exception.code, "process-untrusted")
        self.assertEqual(frameworks.capability_calls, 0)
        self.assertEqual(frameworks.requests, [])
        self.assertEqual(frameworks.activations, [])

    def test_generation_euid_check_fails_closed_on_base_exception(self):
        window, _ = owned_window()
        api, frameworks = self.api([window])
        generation = self.generation()
        with unittest.mock.patch.object(macos.os, "geteuid", side_effect=self.Fatal()):
            with self.assertRaises(contract.ContractError) as error:
                api.set_owned_generation(generation)
        self.assertEqual(error.exception.code, "process-untrusted")
        self.assertEqual(frameworks.requests, [])
        self.assertEqual(frameworks.capability_calls, 0)

    def test_owned_windows_accepts_the_bound_live_generation(self):
        window, _ = owned_window()
        api, _ = self.api([window])
        api.set_owned_generation(self.generation())
        self.assertEqual(api.owned_windows(OWNED_PID), [window])

    def test_activation_generation_is_proved_before_the_single_activation(self):
        api, frameworks = self.api([owned_window()[0]])
        self.assertIs(api.activate_process(OWNED_PID, EXE, self.generation()), True)
        self.assertEqual(frameworks.activations, [OWNED_PID])

    def test_activation_foreign_euid_matching_actual_never_activates(self):
        foreign = os.geteuid() + 1
        api, frameworks = self.api([owned_window()[0]], uid=foreign)
        with self.assertRaises(contract.ContractError) as error:
            api.activate_process(OWNED_PID, EXE, self.generation(euid=foreign))
        self.assertEqual(error.exception.code, "process-untrusted")
        self.assertEqual(frameworks.activations, [])
        self.assertEqual(frameworks.capability_calls, 0)
        self.assertEqual(frameworks.requests, [])

    def test_activation_provided_generation_euid_is_rejected_with_process_trust(self):
        # Isolate the provided-generation boundary: process() is forced to
        # report trust while the actual libproc generation still carries a
        # foreign effective UID and the request mirrors it exactly.
        foreign = os.geteuid() + 1
        api, frameworks = self.api([owned_window()[0]], uid=foreign)
        api.process = lambda pid: (EXE, True)
        with self.assertRaises(contract.ContractError) as error:
            api.activate_process(OWNED_PID, EXE, self.generation(euid=foreign))
        self.assertEqual(error.exception.code, "process-untrusted")
        self.assertEqual(frameworks.activations, [])
        self.assertEqual(frameworks.capability_calls, 0)
        self.assertEqual(frameworks.requests, [])

    def test_stale_wrong_euid_and_malformed_activation_never_activates(self):
        for value in (self.generation(start_usec=124),
                      self.generation(euid=os.geteuid() + 1),
                      {}, {**self.generation(), "pid": OTHER_PID},
                      {**self.generation(), "euid": True}):
            with self.subTest(value=value):
                api, frameworks = self.api([owned_window()[0]])
                with self.assertRaises(contract.ContractError) as error:
                    api.activate_process(OWNED_PID, EXE, value)
                self.assertEqual(error.exception.code, "process-untrusted")
                self.assertEqual(frameworks.activations, [])

    def test_process_trust_uses_the_effective_uid_not_the_real_uid(self):
        api, _ = self.api()
        real, effective = 1000, 501
        with unittest.mock.patch.object(macos.os, "getuid", return_value=real), \
                unittest.mock.patch.object(macos.os, "geteuid", return_value=effective):
            api.process_uid = lambda pid: real
            self.assertFalse(api.process(OWNED_PID)[1])
            api.process_uid = lambda pid: effective
            self.assertTrue(api.process(OWNED_PID)[1])


class OwnedGenerationGuardTests(unittest.TestCase):
    """Guard timing around every scoped owned AX touch; fake libproc only."""

    class Fatal(BaseException):
        pass

    def generation(self, **overrides):
        value = {"pid": OWNED_PID, "executable": EXE, "euid": os.geteuid(),
                 "start_sec": 1700000000, "start_usec": 123}
        value.update(overrides)
        return value

    def api(self, windows=None, **kwargs):
        frameworks = FakeFrameworks([] if windows is None else windows, **kwargs)
        api = api_for(frameworks)
        api.scope_to_owned_pid(OWNED_PID)
        return api, frameworks

    def bound(self, windows=None, **kwargs):
        api, frameworks = self.api(windows, **kwargs)
        api.set_owned_generation(self.generation())
        return api, frameworks

    def guarded_cases(self, window):
        return (
            ("attribute", lambda api: api.attribute(window, "AXTitle")),
            ("ax-value-read", lambda api: api._ax_value_read(window, "AXRole")),
            ("owned-windows", lambda api: api.owned_windows(OWNED_PID)),
            ("prove-owned-element",
             lambda api: api._prove_owned_element(window, OWNED_PID)),
            ("prove-window-role", lambda api: api._prove_ax_window_role(window)),
            ("enumerate", lambda api: api._enumerate_owned_window(TITLE, None)),
            ("records", lambda api: api.owned_window_records()),
            ("proven-pid", lambda api: api._proven_pid(window)),
            ("element-at", lambda api: api._element_at({"pid": OWNED_PID}, 1, 1)),
            ("same-element", lambda api: api._same_element(window, window)),
            ("geometry",
             lambda api: api._geometry(window, "AXPosition",
                                       api.ax.kAXValueCGPointType, "x", "y")),
            ("focus-state",
             lambda api: api.focus_state({"id": window, "pid": OWNED_PID})),
            ("owned-root-at",
             lambda api: api._owned_root_at(
                 {"id": window, "pid": OWNED_PID}, OWNED_PID, 1, 1)),
        )

    def test_pre_stale_refuses_every_guarded_method_before_any_ax(self):
        window, _ = owned_window()
        for name, invoke in self.guarded_cases(window):
            with self.subTest(name=name):
                api, frameworks = self.bound([window])
                api.libproc.start_usec += 1
                with self.assertRaises(contract.ContractError) as error:
                    invoke(api)
                self.assertEqual(error.exception.code, "process-untrusted")
                self.assertEqual(frameworks.requests, [])

    def test_valid_generation_checks_before_and_after_every_guarded_method(self):
        window, _ = owned_window()
        for name, invoke in self.guarded_cases(window):
            with self.subTest(name=name):
                api, frameworks = self.bound([window])
                api.owned_discovery(TITLE)
                api.libproc.calls = []
                invoke(api)
                self.assertGreaterEqual(len(api.libproc.calls), 4)

    def test_attribute_checks_before_and_after_native_copy(self):
        window, _ = owned_window()
        api, frameworks = self.bound([window])
        at_native = []
        original = frameworks.AXUIElementCopyAttributeValue

        def copy(element, name, out):
            at_native.append(len(api.libproc.calls))
            return original(element, name, out)

        frameworks.AXUIElementCopyAttributeValue = copy
        api.libproc.calls = []
        self.assertEqual(api.attribute(window, "AXTitle"), TITLE)
        self.assertEqual(at_native, [2])
        self.assertEqual(len(api.libproc.calls), 4)

    def test_proven_pid_checks_before_and_after_native_getpid(self):
        window, _ = owned_window()
        api, frameworks = self.bound([window])
        at_native = []

        def getpid(element, out):
            at_native.append(len(api.libproc.calls))
            return (0, OWNED_PID)

        frameworks.AXUIElementGetPid = getpid
        api.libproc.calls = []
        self.assertEqual(api._proven_pid(window), OWNED_PID)
        self.assertEqual(at_native, [2])
        self.assertEqual(len(api.libproc.calls), 4)

    def test_element_at_checks_before_and_after_native_hit(self):
        window, _ = owned_window()
        api, frameworks = self.bound([window])
        at_native = []

        def hit(application, x, y, out):
            at_native.append(len(api.libproc.calls))
            return (0, None)

        frameworks.AXUIElementCopyElementAtPosition = hit
        api.libproc.calls = []
        self.assertIsNone(api._element_at({"pid": OWNED_PID}, 1, 1))
        self.assertEqual(at_native, [2])
        self.assertEqual(len(api.libproc.calls), 4)

    def test_midcall_stale_after_first_getpid_stops_before_next_element(self):
        first, _ = owned_window()
        second, _ = owned_window(title=OTHER_TITLE)
        api, frameworks = self.bound([first, second])
        getpid_calls = []

        def changed_getpid(element, out):
            getpid_calls.append(element)
            if len(getpid_calls) == 1:
                api.libproc.start_usec += 1
            return (0, OWNED_PID)

        frameworks.AXUIElementGetPid = changed_getpid
        with self.assertRaises(contract.ContractError) as error:
            api.owned_windows(OWNED_PID)
        self.assertEqual(error.exception.code, "process-untrusted")
        self.assertEqual(len(getpid_calls), 1)
        self.assertNotIn("AXRole", frameworks.names())

    def test_midcall_stale_inside_proven_pid_runs_postcheck(self):
        window, _ = owned_window()
        api, frameworks = self.bound([window])
        getpid_calls = []

        def changed_getpid(element, out):
            getpid_calls.append(element)
            api.libproc.start_usec += 1
            return (0, OWNED_PID)

        frameworks.AXUIElementGetPid = changed_getpid
        with self.assertRaises(contract.ContractError) as error:
            api._proven_pid(window)
        self.assertEqual(error.exception.code, "process-untrusted")
        self.assertEqual(len(getpid_calls), 1)

    def test_same_element_midchange_after_cf_equal_runs_postcheck(self):
        window, _ = owned_window()
        api, frameworks = self.bound([window])
        equal_calls = []
        original = frameworks.CFEqual

        def changed_equal(left, right):
            equal_calls.append(1)
            api.libproc.start_usec += 1
            return original(left, right)

        frameworks.CFEqual = changed_equal
        with self.assertRaises(contract.ContractError) as error:
            api._same_element(window, window)
        self.assertEqual(error.exception.code, "process-untrusted")
        self.assertEqual(len(equal_calls), 1)

    def test_identity_equal_preserves_process_untrusted(self):
        window, _ = owned_window()
        api, _ = self.bound([window])
        api.libproc.start_usec += 1
        with self.assertRaises(contract.ContractError) as error:
            api.identity_equal(window, window)
        self.assertEqual(error.exception.code, "process-untrusted")

    def test_focus_state_pre_stale_never_asks_frontmost(self):
        window, _ = owned_window()
        api, frameworks = self.bound([window])
        api.libproc.start_usec += 1
        calls = []
        api.foreground_pid = lambda: calls.append(1) or OWNED_PID
        with self.assertRaises(contract.ContractError) as error:
            api.focus_state({"id": window, "pid": OWNED_PID})
        self.assertEqual(error.exception.code, "process-untrusted")
        self.assertEqual(calls, [])
        self.assertEqual(frameworks.requests, [])

    def test_geometry_pre_stale_never_reads_axvalue(self):
        window, _ = owned_window()
        api, frameworks = self.bound([window])
        api.libproc.start_usec += 1
        calls = []
        frameworks.AXValueGetValue = (
            lambda value, kind, out: calls.append(1) or (True, value))
        with self.assertRaises(contract.ContractError) as error:
            api._geometry(window, "AXPosition",
                         frameworks.kAXValueCGPointType, "x", "y")
        self.assertEqual(error.exception.code, "process-untrusted")
        self.assertEqual(calls, [])
        self.assertEqual(frameworks.requests, [])

    def test_application_midchange_refuses_before_axwindows(self):
        window, _ = owned_window()
        api, frameworks = self.bound([window])
        original = frameworks.AXUIElementCreateApplication

        def create(pid):
            answer = original(pid)
            api.libproc.start_usec += 1
            return answer

        frameworks.AXUIElementCreateApplication = create
        with self.assertRaises(contract.ContractError) as error:
            api.owned_windows(OWNED_PID)
        self.assertEqual(error.exception.code, "process-untrusted")
        self.assertNotIn("AXWindows", frameworks.names())

    def test_application_midchange_in_owned_root_refuses_before_hit(self):
        window, _ = owned_window()
        api, frameworks = self.bound([window])
        api.owned_discovery(TITLE)
        frameworks.requests = []
        original = frameworks.AXUIElementCreateApplication
        calls = []

        def create(pid):
            answer = original(pid)
            calls.append(1)
            if len(calls) == 2:
                api.libproc.start_usec += 1
            return answer

        frameworks.AXUIElementCreateApplication = create
        with self.assertRaises(contract.ContractError) as error:
            api._owned_root_at({"id": window, "pid": OWNED_PID}, OWNED_PID, 1, 1)
        self.assertEqual(error.exception.code, "process-untrusted")
        self.assertNotIn("at", [request[0] for request in frameworks.requests])

    def test_role_midchange_refuses_before_parent_read(self):
        window, _ = owned_window()
        api, frameworks = self.bound([window])
        api.owned_discovery(TITLE)
        frameworks.requests = []
        hit_node = Node(AXRole="AXButton")
        original_copy = frameworks.AXUIElementCopyAttributeValue

        def hit(application, x, y, out):
            frameworks.requests.append(("at", application, x, y))
            return (0, hit_node)

        def copy(element, name, out):
            if element is hit_node and name == "AXRole":
                frameworks.requests.append(("copy", element, name))
                api.libproc.start_usec += 1
                return (0, "AXButton")
            return original_copy(element, name, out)

        frameworks.AXUIElementCopyElementAtPosition = hit
        frameworks.AXUIElementCopyAttributeValue = copy
        with self.assertRaises(contract.ContractError) as error:
            api._owned_root_at({"id": window, "pid": OWNED_PID}, OWNED_PID, 1, 1)
        self.assertEqual(error.exception.code, "process-untrusted")
        role_reads = [request for request in frameworks.requests
                      if request[0] == "copy" and request[1] is hit_node
                      and request[2] == "AXRole"]
        parent_reads = [request for request in frameworks.requests
                        if request[0] == "copy" and request[1] is hit_node
                        and request[2] == "AXParent"]
        self.assertEqual(len(role_reads), 1)
        self.assertEqual(parent_reads, [])


        window, _ = owned_window()
        api, frameworks = self.bound([window])
        api.libproc.start_usec += 1
        calls = []
        api.activate = lambda pid: calls.append(pid) or True
        with self.assertRaises(contract.ContractError) as error:
            api.activate_owned({"id": window, "pid": OWNED_PID})
        self.assertEqual(error.exception.code, "process-untrusted")
        self.assertEqual(calls, [])
        self.assertEqual(frameworks.activations, [])
        self.assertEqual(frameworks.requests, [])

    def test_activate_owned_valid_generation_activates_once(self):
        window, _ = owned_window()
        api, frameworks = self.bound([window], focused=window)
        self.assertTrue(api.owned_discovery(TITLE)[1])
        self.assertTrue(api.activate_owned({"id": window, "pid": OWNED_PID}))
        self.assertEqual(frameworks.activations, [OWNED_PID])

    def test_owned_root_at_midchange_after_hit_never_reads_axrole(self):
        window, _ = owned_window()
        api, frameworks = self.bound([window])
        api.owned_discovery(TITLE)
        frameworks.requests = []
        hits = []

        def hit(application, x, y, out):
            hits.append(1)
            frameworks.requests.append(("at", application, x, y))
            api.libproc.start_usec += 1
            return (0, window)

        frameworks.AXUIElementCopyElementAtPosition = hit
        with self.assertRaises(contract.ContractError) as error:
            api._owned_root_at({"id": window, "pid": OWNED_PID}, OWNED_PID, 1, 1)
        self.assertEqual(error.exception.code, "process-untrusted")
        self.assertEqual(len(hits), 1)
        self.assertEqual(frameworks.requests[-1][0], "at")

    def test_foreign_uid_after_binding_refuses_before_native(self):
        window, _ = owned_window()
        api, frameworks = self.bound([window])
        api.libproc.uid = os.geteuid() + 1
        with self.assertRaises(contract.ContractError) as error:
            api.owned_window_records()
        self.assertEqual(error.exception.code, "process-untrusted")
        self.assertEqual(frameworks.requests, [])

    def test_base_exception_before_native_refuses_with_zero_ax(self):
        window, _ = owned_window()
        api, frameworks = self.bound([window])
        api.libproc.error = self.Fatal()
        with self.assertRaises(contract.ContractError) as error:
            api.attribute(window, "AXTitle")
        self.assertEqual(error.exception.code, "process-untrusted")
        self.assertEqual(frameworks.requests, [])

    def test_base_exception_after_native_runs_postcheck(self):
        window, _ = owned_window()
        api, frameworks = self.bound([window])
        native = []
        original = frameworks.AXUIElementCopyAttributeValue

        def copy(element, name, out):
            native.append(name)
            api.libproc.error = self.Fatal()
            return original(element, name, out)

        frameworks.AXUIElementCopyAttributeValue = copy
        with self.assertRaises(contract.ContractError) as error:
            api.attribute(window, "AXTitle")
        self.assertEqual(error.exception.code, "process-untrusted")
        self.assertEqual(len(native), 1)

    def test_missing_generation_keeps_legacy_scoped_path_without_guard_reads(self):
        window, _ = owned_window()
        api, frameworks = self.api([window])
        calls = []
        api.process_generation = lambda pid: calls.append(pid) or self.generation()
        self.assertTrue(api.owned_discovery(TITLE)[1])
        self.assertEqual(len(api.owned_window_records()), 1)
        self.assertEqual(api.attribute(window, "AXTitle"), TITLE)
        self.assertEqual(calls, [])


class StatusGenerationPropagationTests(unittest.TestCase):
    """Optional status must not swallow the terminal generation refusal."""

    def controls(self):
        value = {label: {"present": True, "showing": True, "enabled": True}
                 for label in macos.LOCKED_CONTROLS}
        value[macos.LOCKED_VIEW_ABSENT] = {
            "present": False, "showing": False, "enabled": False}
        return value

    def locked_window(self):
        window, first = owned_window()
        controls = [first]
        for label in macos.LOCKED_CONTROLS:
            if label == LABEL:
                continue
            node = Node(AXRole="AXButton", AXDescription=label, AXEnabled=True,
                        AXHidden=False, AXPosition=Point(CONTROL_FRAME),
                        AXSize=Size(CONTROL_FRAME), _pid=OWNED_PID)
            node.attributes["AXParent"] = window
            controls.append(node)
        window.attributes["AXChildren"] = controls
        return window

    def setup(self, locked=False):
        window = self.locked_window() if locked else owned_window()[0]
        frameworks = FakeFrameworks([window], focused=window, front_pid=OWNED_PID)
        api = api_for(frameworks)
        api.scope_to_owned_pid(OWNED_PID)
        generation = api.process_generation(OWNED_PID)
        api.set_owned_generation(generation)
        windows, _ = api.owned_discovery(TITLE)
        return api, frameworks, windows[0], generation

    def status_hook(self, api, frameworks, mutation):
        active = []
        original_walk = api._status_walk

        def walk(window, controls):
            active.append(1)
            try:
                return original_walk(window, controls)
            finally:
                active.pop()

        api._status_walk = walk
        original_copy = frameworks.AXUIElementCopyAttributeValue

        def copy(element, name, out):
            if active and name == "AXRole":
                mutation(api, frameworks)
            return original_copy(element, name, out)

        frameworks.AXUIElementCopyAttributeValue = copy

    @staticmethod
    def stale(api, frameworks):
        api.libproc.start_usec += 1

    @staticmethod
    def ordinary_failure(api, frameworks):
        raise OSError("synthetic status query failure")

    def test_status_propagates_process_untrusted(self):
        api, frameworks, window, _ = self.setup()
        self.status_hook(api, frameworks, self.stale)
        with self.assertRaises(contract.ContractError) as error:
            api.status(window, self.controls())
        self.assertEqual(error.exception.code, "process-untrusted")

        api, frameworks, window, _ = self.setup()
        self.status_hook(api, frameworks, self.stale)
        adapter = macos.MacAdapter(api=api)
        with self.assertRaises(contract.ContractError) as error:
            adapter.read_status(window, self.controls())
        self.assertEqual(error.exception.code, "process-untrusted")

    def test_ordinary_status_failure_stays_all_false(self):
        api, frameworks, window, _ = self.setup()
        self.status_hook(api, frameworks, self.ordinary_failure)
        status = api.status(window, self.controls())
        self.assertEqual(status, macos._empty_status())

        api, frameworks, window, _ = self.setup()
        self.status_hook(api, frameworks, self.ordinary_failure)
        adapter = macos.MacAdapter(api=api)
        self.assertEqual(adapter.read_status(window, self.controls()),
                         macos._empty_status())

    def inspect_request(self, generation):
        return json.dumps({
            "title": TITLE, "executable": EXE, "owned_pid": OWNED_PID,
            "owned_generation": generation, "actions": [], "inspect": True,
        }).encode()

    def test_inspect_status_change_fails_request_without_success(self):
        api, frameworks, window, generation = self.setup(locked=True)
        self.status_hook(api, frameworks, self.stale)
        stdout, stderr = io.StringIO(), io.StringIO()
        status = contract.run_stdin(
            macos.MacAdapter(api=api), "macos",
            stdin=io.BytesIO(self.inspect_request(generation)),
            stdout=stdout, stderr=stderr)
        self.assertEqual(status, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("code=process-untrusted", stderr.getvalue())
        self.assertIn("action=snapshot", stderr.getvalue())

    def test_inspect_ordinary_status_failure_is_all_false_success(self):
        api, frameworks, window, generation = self.setup(locked=True)
        self.status_hook(api, frameworks, self.ordinary_failure)
        stdout, stderr = io.StringIO(), io.StringIO()
        status = contract.run_stdin(
            macos.MacAdapter(api=api), "macos",
            stdin=io.BytesIO(self.inspect_request(generation)),
            stdout=stdout, stderr=stderr)
        self.assertEqual(status, 0)
        self.assertEqual(stderr.getvalue(), "")
        result = json.loads(stdout.getvalue())
        self.assertEqual(result["status"], macos._empty_status())



if __name__ == "__main__":
    unittest.main()
