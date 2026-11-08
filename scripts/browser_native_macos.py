"""External macOS ApplicationServices/CoreGraphics input agent for acceptance.

Ordinary external input only: public AX role/title/enabled/hidden/frame and
public window metadata, then ONE physical CGEventPost batch. It never reads an
accessibility value, never performs an accessibility action (no press or
invoke), never touches the clipboard and never injects an approval.

Accessibility trust is required and started by the human in System Settings >
Privacy & Security > Accessibility. `AXIsProcessTrusted()` is only queried; this
module NEVER prompts for or grants TCC permission -- an untrusted process gets
the fixed capability failure. Screen Recording is not requested: window titles
come from AX once Accessibility is trusted (CGWindowName is only used when the
OS already exposes it).

PyObjC is imported lazily, so this module imports and unit-tests on Linux.
"""
import ctypes
import os

import native_acceptance_contract as contract

PLATFORM = "macos"
MAX_NODES = 4096
MAX_DEPTH = 12

ROLE_MAP = {"AXButton": "push button", "AXTextField": "entry",
            "AXTextArea": "entry", "AXStaticText": "text"}

SECURE_PROCESSES = frozenset({"securityagent", "coreautha", "coreauthd", "loginwindow"})

KEYCODES = {
    "Control_L": 0x3B, "Control_R": 0x3E, "Shift_L": 0x38, "Shift_R": 0x3C,
    "Alt_L": 0x3A, "Alt_R": 0x3D, "Super_L": 0x37, "Super_R": 0x36,
    "Escape": 0x35, "Tab": 0x30, "Return": 0x24, "space": 0x31,
    "Delete": 0x33, "BackSpace": 0x33, "Home": 0x73, "End": 0x77,
    "Prior": 0x74, "Next": 0x79, "Up": 0x7E, "Down": 0x7D, "Left": 0x7B, "Right": 0x7C,
    "a": 0x00, "s": 0x01, "d": 0x02, "f": 0x03, "h": 0x04, "g": 0x05, "z": 0x06,
    "x": 0x07, "c": 0x08, "v": 0x09, "b": 0x0B, "q": 0x0C, "w": 0x0D, "e": 0x0E,
    "r": 0x0F, "y": 0x10, "t": 0x11, "1": 0x12, "2": 0x13, "3": 0x14, "4": 0x15,
    "6": 0x16, "5": 0x17, "9": 0x19, "7": 0x1A, "8": 0x1C, "0": 0x1D, "o": 0x1F,
    "u": 0x20, "i": 0x22, "p": 0x23, "l": 0x25, "j": 0x26, "k": 0x28, "n": 0x2D,
    "m": 0x2E, ".": 0x2F, ",": 0x2B, "/": 0x2C, ";": 0x29, "-": 0x1B, "=": 0x18,
}
FLAGS = {"Control_L": 0x00040000, "Control_R": 0x00040000, "Shift_L": 0x00020000,
         "Shift_R": 0x00020000, "Alt_L": 0x00080000, "Alt_R": 0x00080000,
         "Super_L": 0x00100000, "Super_R": 0x00100000}

PROC_PIDTBSDINFO = 3


class BSDInfo(ctypes.Structure):
    _fields_ = [("pbi_flags", ctypes.c_uint32), ("pbi_status", ctypes.c_uint32),
                ("pbi_xstatus", ctypes.c_uint32), ("pbi_pid", ctypes.c_uint32),
                ("pbi_ppid", ctypes.c_uint32), ("pbi_uid", ctypes.c_uint32),
                ("pbi_gid", ctypes.c_uint32), ("pbi_ruid", ctypes.c_uint32),
                ("pbi_rgid", ctypes.c_uint32), ("pbi_svuid", ctypes.c_uint32),
                ("pbi_svgid", ctypes.c_uint32), ("rfu_1", ctypes.c_uint32),
                ("pbi_comm", ctypes.c_char * 16), ("pbi_name", ctypes.c_char * 32)]


class AxValueUnavailable(Exception):
    """AX returned no usable geometry; the caller must fail closed."""


class QuartzApi:
    """Real ApplicationServices / CoreGraphics access; created only on macOS."""

    def __init__(self, quartz=None, appkit=None):
        if quartz is None or appkit is None:
            import AppKit  # noqa: F401  (PyObjC, imported on demand)
            import Quartz
            quartz, appkit = Quartz, AppKit
        self.quartz, self.appkit = quartz, appkit
        self.libproc = ctypes.CDLL(None)

    # -- capability ---------------------------------------------------------
    def capability(self):
        """Query-only trust check. Never prompts, never grants, never retries."""
        if not bool(self.quartz.AXIsProcessTrusted()):
            raise contract.ContractError("capability-unavailable")

    # -- read-only AX helpers ----------------------------------------------
    def attribute(self, element, name):
        result = self.quartz.AXUIElementCopyAttributeValue(element, name, None)
        if isinstance(result, tuple) and len(result) == 2:
            code, value = result
        else:
            code, value = 0, result
        if code != 0 or value is None:
            return None
        return value

    def _geometry(self, element, name, value_type, first, second):
        value = self.attribute(element, name)
        if value is None:
            return None
        try:
            result = self.quartz.AXValueGetValue(value, value_type, None)
        except Exception:
            raise AxValueUnavailable()
        if not isinstance(result, tuple) or len(result) != 2 or not result[0]:
            raise AxValueUnavailable()
        payload = result[1]
        try:
            return int(getattr(payload, first)), int(getattr(payload, second))
        except Exception:
            try:
                return int(payload[0]), int(payload[1])
            except Exception:
                raise AxValueUnavailable()

    def frame(self, element):
        """AX frame in global display coordinates, or AxValueUnavailable."""
        position = self._geometry(element, "AXPosition", self.quartz.kAXValueCGPointType, "x", "y")
        size = self._geometry(element, "AXSize", self.quartz.kAXValueCGSizeType, "width", "height")
        if position is None or size is None:
            raise AxValueUnavailable()
        return {"x": int(position[0]), "y": int(position[1]),
                "width": int(size[0]), "height": int(size[1])}

    def application(self, pid):
        return self.quartz.AXUIElementCreateApplication(pid)

    def windows(self, pid):
        element = self.application(pid)
        if element is None:
            return []
        value = self.attribute(element, self.quartz.kAXWindowsAttribute)
        return list(value) if value else []

    def title(self, element):
        for name in ("AXTitle", "AXDescription"):
            value = self.attribute(element, name)
            if type(value) is str and value:
                return value
        return ""

    # -- widget walk --------------------------------------------------------
    def controls(self, pid, title):
        """Bounded AX walk of the titled window; public fields only."""
        target = None
        for window in self.windows(pid):
            if self.title(window) == title:
                target = window
                break
        if target is None:
            raise contract.ContractError("a11y-query")
        found, nodes = [], [0]

        def walk(element, depth):
            nodes[0] += 1
            if nodes[0] > MAX_NODES:
                raise contract.ContractError("a11y-overrun")
            if depth > MAX_DEPTH:
                raise contract.ContractError("a11y-tree-limit")
            role = ROLE_MAP.get(self.attribute(element, "AXRole"))
            if role is not None:
                name = self.title(element)
                if name in contract.KNOWN_SYNTHETIC_LABELS:
                    try:
                        bounds = self.frame(element)
                    except AxValueUnavailable:
                        bounds = None
                    if bounds is not None:
                        enabled = self.attribute(element, "AXEnabled")
                        hidden = self.attribute(element, "AXHidden")
                        found.append({"role": role, "name": name,
                                      "enabled": enabled is not False,
                                      "visible": hidden is not True,
                                      "bounds": bounds})
            children = self.attribute(element, "AXChildren")
            for child in children or []:
                walk(child, depth + 1)

        walk(target, 0)
        return found

    # -- process identity ---------------------------------------------------
    def process_uid(self, pid):
        info = BSDInfo()
        try:
            size = self.libproc.proc_pidinfo(int(pid), PROC_PIDTBSDINFO, 0,
                                             ctypes.byref(info), ctypes.sizeof(info))
        except Exception:
            return None
        return int(info.pbi_uid) if size == ctypes.sizeof(info) else None

    def process(self, pid):
        """Read-only pid -> executable path lookup; same-user trust only."""
        buffer = ctypes.create_string_buffer(4096)
        try:
            length = self.libproc.proc_pidpath(int(pid), buffer, 4096)
        except Exception:
            return "", False
        if length <= 0:
            return "", False
        path = buffer.value.decode("utf-8", "replace")
        try:
            file_uid = os.stat(path).st_uid
        except OSError:
            return "", False
        uid = self.process_uid(pid)
        trusted = uid == os.getuid() if uid is not None else file_uid == os.getuid()
        return path, trusted

    # -- windows ------------------------------------------------------------
    def list_windows(self):
        quartz = self.quartz
        options = quartz.kCGWindowListOptionOnScreenOnly | quartz.kCGWindowListExcludeDesktopElements
        entries = quartz.CGWindowListCopyWindowInfo(options, quartz.kCGNullWindowID) or []
        if len(entries) > contract.MAX_WINDOWS:
            raise contract.ContractError("window-overrun")
        title_cache, windows = {}, []
        for entry in entries:
            try:
                if int(entry.get(quartz.kCGWindowLayer, 1)) != 0:
                    continue
                pid = int(entry.get(quartz.kCGWindowOwnerPID, 0))
                identifier = int(entry.get(quartz.kCGWindowNumber, 0))
                bounds = entry.get(quartz.kCGWindowBounds) or {}
                rect = {"x": int(bounds.get("X", 0)), "y": int(bounds.get("Y", 0)),
                        "width": int(bounds.get("Width", 0)), "height": int(bounds.get("Height", 0))}
            except (TypeError, ValueError):
                continue
            if pid <= 0 or identifier <= 0:
                continue
            if pid not in title_cache:
                title_cache[pid] = self._ax_title(pid)
            path, trusted = self.process(pid)
            name = path.rsplit("/", 1)[-1].lower()
            windows.append({
                "id": identifier, "pid": pid,
                "title": entry.get(quartz.kCGWindowName) or title_cache[pid],
                "executable": path, "trusted": trusted,
                "visible": True,
                "onscreen": rect["width"] > 0 and rect["height"] > 0,
                "secure": name in SECURE_PROCESSES,
                "bounds": rect, "client": dict(rect),
            })
        return windows

    def _ax_title(self, pid):
        for window in self.windows(pid):
            title = self.title(window)
            if title:
                return title
        return ""

    # -- foreground / input -------------------------------------------------
    def foreground_pid(self):
        workspace = self.appkit.NSWorkspace.sharedWorkspace()
        front = workspace.frontmostApplication()
        return int(front.processIdentifier()) if front is not None else None

    def activate(self, pid):
        running = self.appkit.NSRunningApplication.runningApplicationWithProcessIdentifier_(int(pid))
        if running is None:
            return False
        return bool(running.activateWithOptions_(1))

    def click(self, x, y):
        quartz, point = self.quartz, (float(x), float(y))
        events = [quartz.CGEventCreateMouseEvent(None, quartz.kCGEventMouseMoved, point, 0),
                  quartz.CGEventCreateMouseEvent(None, quartz.kCGEventLeftMouseDown, point, 0),
                  quartz.CGEventCreateMouseEvent(None, quartz.kCGEventLeftMouseUp, point, 0)]
        for event in events:
            if event is None:
                raise contract.ContractError("input-failed")
            quartz.CGEventPost(quartz.kCGHIDEventTap, event)
        return {"move": True, "down": True, "up": True}

    def type_text(self, text):
        if not text or len(text) > contract.MAX_TEXT or any(ord(c) < 32 or ord(c) > 126 for c in text):
            raise contract.ContractError("input-charset")
        quartz = self.quartz
        for char in text:
            for down in (True, False):
                event = quartz.CGEventCreateKeyboardEvent(None, 0, down)
                if event is None:
                    raise contract.ContractError("input-failed")
                try:
                    quartz.CGEventKeyboardSetUnicodeString(event, len(char), char)
                except Exception:
                    raise contract.ContractError("input-unsupported")
                quartz.CGEventPost(quartz.kCGHIDEventTap, event)
        return {"move": True, "down": True, "up": True}

    def press_chord(self, parts):
        quartz = self.quartz
        codes, flags = [], 0
        for part in parts:
            code = KEYCODES.get(part)
            if code is None:
                raise contract.ContractError("input-unsupported")
            codes.append(code)
            flags |= FLAGS.get(part, 0)
        events = [quartz.CGEventCreateKeyboardEvent(None, code, True) for code in codes]
        events += [quartz.CGEventCreateKeyboardEvent(None, code, False) for code in reversed(codes)]
        for event in events:
            if event is None:
                raise contract.ContractError("input-failed")
            if flags:
                quartz.CGEventSetFlags(event, flags)
            quartz.CGEventPost(quartz.kCGHIDEventTap, event)
        return {"move": True, "down": True, "up": True}


class MacAdapter:
    """Contract adapter. Focus is never stolen while preserve_focus is asked."""

    platform = PLATFORM
    supports_activation = True

    def __init__(self, api=None, uia=None):
        self.api = QuartzApi() if api is None else api
        del uia  # AX access lives in the injected api object

    def check_capability(self):
        self.api.capability()

    def list_windows(self):
        return [self._normalise(raw) for raw in self.api.list_windows()]

    def _normalise(self, raw):
        def rect(value):
            return {key: (value or {}).get(key) for key in ("x", "y", "width", "height")}

        return {
            "id": raw.get("id"), "pid": raw.get("pid"),
            "title": raw.get("title") or "", "executable": raw.get("executable") or "",
            "trusted": raw.get("trusted") is True,
            "visible": raw.get("visible") is True,
            "onscreen": raw.get("onscreen") is not False,
            "secure": raw.get("secure") is True,
            "bounds": rect(raw.get("bounds")), "client": rect(raw.get("client")),
        }

    def read_window(self, identifier):
        for raw in self.api.list_windows():
            if raw.get("id") == identifier:
                return self._normalise(raw)
        return None

    def read_controls(self, window):
        controls = self.api.controls(window["pid"], window["title"])
        if not isinstance(controls, list) or len(controls) > contract.MAX_CONTROLS:
            raise contract.ContractError("a11y-overrun")
        for control in controls:
            if type(control) is not dict or set(control) != set(contract.WIDGET_FIELDS):
                raise contract.ContractError("a11y-query")
        return controls

    def focus_state(self):
        return {"pid": self.api.foreground_pid()}

    def activate(self, window):
        if not self.api.activate(window["pid"]):
            raise contract.ContractError("focus-lost")

    def click(self, x, y):
        return self.api.click(x, y)

    def type_text(self, text):
        return self.api.type_text(text)

    def press_chord(self, parts):
        return self.api.press_chord(parts)


def main(stdin=None, stdout=None, stderr=None):
    import sys

    stdout = sys.stdout if stdout is None else stdout
    stderr = sys.stderr if stderr is None else stderr
    try:
        adapter = MacAdapter()
    except Exception:
        stderr.write(contract.failure_line(contract.ContractError("capability-unavailable"),
                                           "setup", -1, PLATFORM) + "\n")
        return 1
    return contract.run_stdin(adapter, PLATFORM, stdin, stdout, stderr)


if __name__ == "__main__":
    import sys

    sys.exit(main())
