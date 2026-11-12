"""Focused behavior tests for owned-process window discovery and readiness.

No real OS, GUI, TCC, prompt, window inventory or input: ``QuartzApi`` runs
over an in-memory ApplicationServices/CoreGraphics fake whose CoreGraphics
inventory is POISONED (any ``CGWindowList*`` touch is a hard failure), so every
test here proves discovery never falls back to the global CG window inventory.

Covered end-to-end through the normal driver entry point
(``browser_native_macos.main`` -> ``native_acceptance_contract.run_stdin``):
the scoped normal discovery/readiness path, wrong/foreign PID, ambiguous owned
windows, title-failure refusals (the exact fixture title is never waived), and
the unchanged original direct status-hook regression.
"""
import ctypes
import io
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import browser_native_macos as macos
import native_acceptance_contract as contract

TITLE = "Locklark · 本地金库"
OWNED_PID = 4242
OTHER_PID = 4243
WINDOW_NUMBER = 0x200003
EXE = "/opt/locklark/locklark-desktop"
FRAME = {"x": 313, "y": 75, "width": 1102, "height": 822}
NO_VALUE = -25212


class AxWindow:
    """One opaque fake AXUIElement with only public AX attributes."""

    def __init__(self, owner=OWNED_PID, title=TITLE, number=WINDOW_NUMBER,
                 frame=None):
        self.owner, self.title, self.number = owner, title, number
        self.position = frame or FRAME
        self.size = FRAME
        self.attributes = {"AXTitle": title, "AXWindowNumber": number}


class FakeFrameworks:
    """ApplicationServices + CoreGraphics stand-in with a poisoned CG inventory."""

    kAXWindowsAttribute = "AXWindows"
    kAXErrorNoValue = NO_VALUE
    kAXValueCGPointType = 1
    kAXValueCGSizeType = 2
    kCGWindowListOptionOnScreenOnly = 1
    kCGWindowListExcludeDesktopElements = 16
    kCGNullWindowID = 0
    kCGWindowLayer = "layer"
    kCGWindowOwnerPID = "pid"
    kCGWindowNumber = "number"
    kCGWindowBounds = "bounds"
    kCGWindowName = "name"

    def __init__(self, windows, eager=None):
        self.windows = list(windows)
        self.eager = None if eager is None else list(eager)
        self.release_requested = 0
        self.scoped_pid = None
        self.requests = []

    # -- CoreGraphics: every inventory entry point is poisoned -------------
    def __getattr__(self, name):
        if name.startswith("CGWindowList"):
            raise AssertionError("CoreGraphics window inventory touched: " + name)
        raise AttributeError(name)

    # -- ApplicationServices ----------------------------------------------
    def AXIsProcessTrusted(self):
        # Query only: the fake claims the existing trusted capability.
        return True

    def AXUIElementCreateApplication(self, pid):
        self.requests.append(("create", pid))
        self._eager = self.eager
        return ("application", pid)

    def AXUIElementGetPid(self, element, out):
        if out is _MISSING:
            raise TypeError("AXUIElementGetPid() missing required out argument")
        self.requests.append(("getpid", element))
        return (0, element.owner)

    def AXUIElementCopyAttributeValue(self, element, name, out):
        self.requests.append(("copy", element, name))
        if isinstance(element, tuple) and element[0] == "application":
            # Readiness: the owned PID's AXWindows, bounded by this fake.
            listed = [w for w in self.windows if w.owner == element[1]]
            if not listed and self._eager:
                # The owned process creates its window during readiness.
                self.windows.extend(self._eager)
                self._eager = None
                listed = [w for w in self.windows if w.owner == element[1]]
            return (0, listed)
        if name == "AXRole":
            return (0, "AXWindow")
        if name == "AXChildren":
            return (0, [])
        if name == macos.AX_WINDOW_NUMBER:
            return (0, element.number)
        if name == "AXTitle":
            return (0, element.title) if element.title is not None else (NO_VALUE, None)
        if name == "AXDescription":
            return (NO_VALUE, None)
        if name == "AXPosition":
            return (0, _Point(element.position))
        if name == "AXSize":
            return (0, _Size(element.size))
        raise AssertionError("unexpected attribute read: " + name)

    def AXValueGetValue(self, value, kind, out):
        return (True, value)

    # -- process identity (public metadata only) ---------------------------
    def process(self, pid):
        return (EXE, True)

    def foreground_pid(self):
        return OWNED_PID

    def scope_to_owned_process(self, pid):
        self.scoped_pid = pid

    def unscope_owned_process(self):
        self.scoped_pid = None
        self.release_requested += 1

    # -- call log views ----------------------------------------------------
    def names(self):
        return [request[0] for request in self.requests]

    def attributes(self):
        return [request[2] for request in self.requests if request[0] == "copy"]


class _Point:
    def __init__(self, value):
        self.x, self.y = value["x"], value["y"]


class _Size:
    def __init__(self, value):
        self.width, self.height = value["width"], value["height"]


_MISSING = object()


def driver(frameworks, request, monkey_clock=None):
    """Run the REAL macOS driver entry point once with fake frameworks."""
    api = macos.QuartzApi.__new__(macos.QuartzApi)
    api.ax = frameworks
    api.quartz = frameworks
    api.appkit = frameworks
    api.libproc = _NoLibproc()
    adapter = macos.MacAdapter(api=api)
    if monkey_clock is not None:
        restore = contract.monotonic
        contract.monotonic = monkey_clock
    else:
        restore = None
    out, err = io.StringIO(), io.StringIO()
    try:
        code = contract.run_stdin(adapter, macos.PLATFORM,
                                  io.BytesIO(request), out, err)
    finally:
        if restore is not None:
            contract.monotonic = restore
    return code, out.getvalue().encode(), err.getvalue(), api


class _NoLibproc:
    """proc_pidpath answers the canonical executable for the owned PID."""

    def proc_pidpath(self, pid, buffer, size):
        if pid != OWNED_PID:
            return 0
        buffer.value = EXE.encode()
        return len(EXE)

    def proc_pidinfo(self, pid, flavor, arg, info, size):
        if pid != OWNED_PID:
            return 0
        # Fill the caller's real struct through the ctypes pointer it passed.
        buffer = ctypes.cast(info, ctypes.POINTER(ctypes.c_char * size)).contents
        bsd = macos.BSDInfo.from_buffer(buffer)
        bsd.pbi_pid, bsd.pbi_uid = OWNED_PID, os.getuid()
        return size


def discovery_request(**overrides):
    document = {"title": TITLE, "executable": EXE, "actions": [],
                "inspect": False, "owned_pid": OWNED_PID}
    document.update(overrides)
    return json.dumps(document).encode()


def refusal_code(code, err):
    """The fixed refusal code from one driver run, or None when it succeeded."""
    if code == 0:
        return None
    match = contract.FAILURE_LINE.match(err) if hasattr(contract, "FAILURE_LINE") else None
    line = err.strip()
    for name in contract.ERROR_MESSAGES:
        if "code=" + name + " " in line:
            return name
    return "unrecognized"


class OwnedDiscoveryTests(unittest.TestCase):
    def test_scoped_discovery_reads_no_cg_inventory(self):
        frameworks = FakeFrameworks([AxWindow()])
        code, out, err, api = driver(frameworks, discovery_request(inspect=True))
        self.assertEqual((code, err), (0, ""))
        result = json.loads(out)
        self.assertEqual(result["window"], hex(WINDOW_NUMBER))
        self.assertEqual(result["pid"], OWNED_PID)
        self.assertEqual(result["x"], FRAME["x"])
        self.assertEqual(result["y"], FRAME["y"])
        # Only the owned window's public metadata was read, never AXValue.
        attributes = frameworks.attributes()
        self.assertEqual(attributes[0], "AXWindows")
        self.assertIn(macos.AX_WINDOW_NUMBER, attributes)
        self.assertIn("AXPosition", attributes)
        self.assertIn("AXSize", attributes)
        for forbidden in ("AXValue", "AXSelectedText", "AXLabel"):
            self.assertNotIn(forbidden, attributes)
        self.assertNotIn("AXSelectedText", frameworks.attributes())
        # The scope is per-request: installed for discovery, then released.
        self.assertIsNone(api.owned_process_scope())

    def test_unscoped_normal_request_still_refuses_over_poisoned_cg(self):
        # Without owned_pid the platform keeps its CG path; here it is poisoned,
        # so the run refuses and no CG data reaches discovery. This proves the
        # scoped tests above never took that path implicitly.
        frameworks = FakeFrameworks([AxWindow()])
        payload = json.loads(discovery_request())
        payload.pop("owned_pid")
        code, out, err, api = driver(frameworks, json.dumps(payload).encode())
        self.assertEqual(code, 1)
        self.assertEqual(out, b"")
        self.assertIsNone(api.owned_process_scope())
        self.assertEqual(frameworks.requests, [])

    def test_readiness_waits_for_the_owned_window(self):
        frameworks = FakeFrameworks([], eager=[AxWindow()])
        code, out, err, _ = driver(frameworks, discovery_request(inspect=True))
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(json.loads(out)["window"], hex(WINDOW_NUMBER))

    def test_wrong_pid_never_binds_another_process_window(self):
        # The owned PID's app has no windows; another process has one.
        frameworks = FakeFrameworks([AxWindow(owner=OTHER_PID)])
        clock = [0.0]

        def monotonic():
            clock[0] += 10.0
            return clock[0]

        code, out, err, api = driver(frameworks,
                                     discovery_request(inspect=True, owned_pid=OTHER_PID),
                                     monkey_clock=monotonic)
        # The foreign window is not owned: readiness times out, never binds it.
        self.assertEqual(refusal_code(code, err), "window-timeout")
        self.assertEqual(out, b"")
        self.assertIsNone(api.owned_process_scope())

    def test_ambiguous_owned_windows_are_refused(self):
        frameworks = FakeFrameworks([AxWindow(), AxWindow(number=WINDOW_NUMBER + 1)])
        clock = [0.0]

        def monotonic():
            clock[0] += 10.0
            return clock[0]

        code, out, err, _ = driver(frameworks, discovery_request(inspect=True),
                                   monkey_clock=monotonic)
        self.assertEqual(refusal_code(code, err), "window-timeout")
        self.assertEqual(out, b"")
        # Ambiguity never reads a title/number/frame of any owned window.
        self.assertEqual(set(frameworks.attributes()), {"AXWindows"})

    def test_title_mismatch_is_never_waived(self):
        frameworks = FakeFrameworks([AxWindow(title="Locklark · 别的窗口")])
        clock = [0.0]

        def monotonic():
            clock[0] += 10.0
            return clock[0]

        code, out, err, _ = driver(frameworks, discovery_request(inspect=True),
                                   monkey_clock=monotonic)
        self.assertEqual(refusal_code(code, err), "window-timeout")
        self.assertEqual(out, b"")

    def test_exact_title_is_required_by_the_schema_too(self):
        # A missing title or executable alongside owned_pid is rejected before
        # any AX call: the exact fixture title is structurally mandatory.
        for document in ({"title": TITLE, "owned_pid": OWNED_PID},
                         {"executable": EXE, "owned_pid": OWNED_PID},
                         {"title": TITLE, "title_prefix": "Locklark",
                          "executable": EXE, "owned_pid": OWNED_PID}):
            with self.subTest(keys=sorted(document)):
                frameworks = FakeFrameworks([AxWindow()])
                code, out, err, _ = driver(frameworks,
                                           json.dumps(document).encode())
                self.assertNotEqual(code, 0)
                self.assertEqual(frameworks.requests, [])
                self.assertEqual(frameworks.scoped_pid, None)

    def test_malformed_owned_pid_is_rejected_before_any_ax_call(self):
        for pid in (0, -1, True, 4242.0, "4242", None):
            with self.subTest(pid=pid):
                frameworks = FakeFrameworks([AxWindow()])
                code, out, err, _ = driver(frameworks,
                                           discovery_request(owned_pid=pid))
                self.assertNotEqual(code, 0)
                self.assertEqual(frameworks.requests, [])

def _api(frameworks):
    api = macos.QuartzApi.__new__(macos.QuartzApi)
    api.ax = frameworks
    api.quartz = frameworks
    api.appkit = frameworks
    api.libproc = _NoLibproc()
    return api


class OriginalStatusRegressionTests(unittest.TestCase):
    """The original direct status hook is untouched by owned discovery."""

    def test_unscoped_status_entry_point_is_unchanged(self):
        frameworks = FakeFrameworks([AxWindow()])
        api = _api(frameworks)
        self.assertTrue(callable(api.status))
        self.assertTrue(callable(api.read_status))
        # No scope has been installed, so normal discovery (not owned) applies.
        self.assertIsNone(api.owned_process_scope())


if __name__ == "__main__":
    unittest.main()
