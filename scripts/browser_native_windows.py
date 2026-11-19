"""External Windows Win32 + UI Automation input agent for native acceptance.

Ordinary external input only: public window metadata, public UIA name/role/
enabled/visible/bounds, then ONE physical SendInput batch. No product hook, no
accessibility value, text or invoke pattern, no text-setting call, never an
automatic approval. The
process refuses on the secure desktop (logon UI / Windows Hello) because those
surfaces must be completed by the human at the console.

Everything (ctypes Win32 signatures, comtypes UIA) is created lazily so this
module imports and unit-tests on Linux without any Windows library present.
"""
import ctypes
import ctypes.wintypes as wt
import math

import native_acceptance_contract as contract

PLATFORM = "windows"
MAX_ELEMENTS = 4096
MAX_HIT_ELEMENTS = 64

# Control-type ids from the public UIA documentation, mapped onto the roles the
# shared contract accepts. Anything else is ignored (never inspected further).
UIA_ROLES = {
    50000: "push button",   # Button
    50004: "entry",         # Edit
    50020: "text",          # Text
    50030: "text",          # Document
    50025: "button",        # Custom
}

# Surfaces that can never be approved by this driver: the human must act.
SECURE_PROCESSES = frozenset({"logonui.exe", "consent.exe", "credentialuibroker.exe"})
SECURE_CLASSES = frozenset({"Credential Dialog Xaml Host", "Credential Dialog Host",
                            "LogonUI", "Windows.UI.Core.CoreWindow"})

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
TOKEN_QUERY = 0x0008
TokenUser = 1
DESKTOP_READOBJECTS = 0x0001
UOI_NAME = 2
MOUSEEVENTF_MOVE = 0x0001
MOUSEEVENTF_ABSOLUTE = 0x8000
MOUSEEVENTF_VIRTUALDESK = 0x4000
MOUSEEVENTF_LEFTDOWN = 0x0002
MOUSEEVENTF_LEFTUP = 0x0004
INPUT_MOUSE = 0
INPUT_KEYBOARD = 1
KEYEVENTF_KEYUP = 0x0002
KEYEVENTF_UNICODE = 0x0004
GA_ROOT = 2
VK_SHIFT = 0x10
SM_XVIRTUALSCREEN, SM_YVIRTUALSCREEN, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN = 76, 77, 78, 79

VK = {
    "Control_L": 0x11, "Control_R": 0xA3, "Shift_L": 0x10, "Shift_R": 0xA1,
    "Alt_L": 0x12, "Alt_R": 0xA5, "Super_L": 0x5B, "Super_R": 0x5C,
    "Escape": 0x1B, "Tab": 0x09, "Return": 0x0D, "space": 0x20,
    "BackSpace": 0x08, "Delete": 0x2E, "Home": 0x24, "End": 0x23,
    "Prior": 0x21, "Next": 0x22, "Up": 0x26, "Down": 0x28, "Left": 0x25, "Right": 0x27,
}


class MOUSEINPUT(ctypes.Structure):
    _fields_ = [("dx", wt.LONG), ("dy", wt.LONG), ("mouseData", wt.DWORD),
                ("dwFlags", wt.DWORD), ("time", wt.DWORD), ("dwExtraInfo", ctypes.c_void_p)]


class KEYBDINPUT(ctypes.Structure):
    _fields_ = [("wVk", wt.WORD), ("wScan", wt.WORD), ("dwFlags", wt.DWORD),
                ("time", wt.DWORD), ("dwExtraInfo", ctypes.c_void_p)]


class _INPUTUNION(ctypes.Union):
    _fields_ = [("mi", MOUSEINPUT), ("ki", KEYBDINPUT)]


class INPUT(ctypes.Structure):
    _fields_ = [("type", wt.DWORD), ("union", _INPUTUNION)]


def load_uia():
    """Create the real UIA automation object through comtypes, lazily."""
    import comtypes.client  # noqa: F401  (Windows-only, imported on demand)

    module = comtypes.client.GetModule("UIAutomationCore.dll")
    automation = comtypes.client.CreateObject(
        "{ff48dba4-60ef-4201-aa87-54103eef594e}", interface=module.IUIAutomation)
    return UiaReader(module, automation)


class UiaReader:
    """Read name/role/enabled/offscreen/bounds only; never a value or text."""

    def __init__(self, module, automation):
        self.module = module
        self.automation = automation

    def _descendants(self, handle):
        """Bounded walk returning (native element, public record) rows."""
        element = self.automation.ElementFromHandle(handle)
        if element is None:
            raise contract.ContractError("a11y-unavailable")
        found = element.FindAll(self.module.TreeScope_Descendants,
                                self.automation.CreateTrueCondition())
        count = found.Length if found is not None else 0
        if count > MAX_ELEMENTS:
            raise contract.ContractError("a11y-overrun")
        rows = []
        for index in range(count):
            node = found.GetElement(index)
            if node is None:
                continue
            role = UIA_ROLES.get(node.CurrentControlType)
            if role is None:
                continue
            rect = node.CurrentBoundingRectangle
            rows.append((node, {
                "role": role,
                "name": node.CurrentName,
                "enabled": bool(node.CurrentIsEnabled),
                "visible": not bool(node.CurrentIsOffscreen),
                "bounds": {"x": int(rect.left), "y": int(rect.top),
                           "width": int(rect.right - rect.left),
                           "height": int(rect.bottom - rect.top)},
            }))
        return rows

    def controls(self, handle):
        """Bounded walk returning public metadata for at most MAX_ELEMENTS nodes."""
        return [record for _, record in self._descendants(handle)]

    def _selected(self, handle, label, rect):
        """Re-parse the CURRENT bound window for the unique selected control.

        The same role/name rule the contract used is applied to a fresh parse,
        and the freshly observed rectangle must equal the authorising one
        exactly: a control that moved or resized between the two reads is never
        clicked.  Zero matches and several matches both refuse.
        """
        rows = [(node, record) for node, record in self._descendants(handle)
                if record.get("name") == label and record.get("role") in contract.CONTROL_ROLES]
        if len(rows) > 1:
            raise contract.ContractError("control-ambiguous", {"matches": len(rows)})
        if not rows:
            raise contract.ContractError("control-missing")
        node, record = rows[0]
        bounds = record.get("bounds") or {}
        if not contract.rect_positive(rect) or any(bounds.get(key) != rect.get(key)
                                                   for key in ("x", "y", "width", "height")):
            raise contract.ContractError("control-hit")
        return node

    def _point(self, x, y):
        """Build the UIA ``POINT`` value from the generated COM structure.

        ``IUIAutomation::ElementFromPoint`` takes the IDL ``POINT`` structure,
        which comtypes generates from UIAutomationCore.dll.  Only a generated
        structure whose layout is exactly two 32-bit signed members ``x``/``y``
        is used; if the module exposes no such type the reader refuses instead
        of guessing a call shape.
        """
        point_type = getattr(self.module, "tagPOINT", None)
        if point_type is None:
            point_type = getattr(self.module, "POINT", None)
        fields = getattr(point_type, "_fields_", None)
        if (not isinstance(point_type, type) or not issubclass(point_type, ctypes.Structure)
                or not fields or [name for name, _ in fields] != ["x", "y"]
                or any(ctypes.sizeof(field) != 4 for _, field in fields)):
            raise contract.ContractError("a11y-unavailable")
        return point_type(screen_int(x), screen_int(y))

    def _element_at(self, x, y):
        """ElementFromPoint at the click point; failures never look like a hit."""
        point = self._point(x, y)
        try:
            return self.automation.ElementFromPoint(point)
        except contract.ContractError:
            raise
        except Exception:
            raise contract.ContractError("a11y-query")

    def _same(self, left, right):
        """``IUIAutomation.CompareElements``: the only native identity test.

        The IDL return value is ``[out, retval] BOOL *``, so comtypes hands back
        the plain C ``BOOL``: the Python integer 1 for TRUE and 0 for FALSE.  A
        match is therefore only the literal ``True`` or the integer 1; every
        other value (0, 2, -1, a truthy object) is not a proven match.  Element
        names, control types and rectangles are never compared instead, and a
        failing COM query refuses.
        """
        if left is None or right is None:
            return False
        try:
            matched = self.automation.CompareElements(left, right)
        except contract.ContractError:
            raise
        except Exception:
            raise contract.ContractError("a11y-query")
        return matched is True or (type(matched) is int and matched == 1)

    def _hit_reaches(self, element, target):
        """Walk parents from the hit element; True only for the selected one.

        ``RawViewWalker.GetParentElement`` is bounded to MAX_HIT_ELEMENTS
        elements (at most 63 parent steps).  A repeated element (cycle), an
        exhausted chain, an overrun, a missing walker and any failed query
        refuse or answer False; nothing is ever inferred from silence.
        """
        walker = getattr(self.automation, "RawViewWalker", None)
        if walker is None:
            raise contract.ContractError("a11y-unavailable")
        node, seen = element, []
        for _ in range(MAX_HIT_ELEMENTS):
            if node is None:
                return False
            if any(self._same(node, prior) for prior in seen):
                raise contract.ContractError("a11y-query")
            seen.append(node)
            if self._same(node, target):
                return True
            try:
                node = walker.GetParentElement(node)
            except contract.ContractError:
                raise
            except Exception:
                raise contract.ContractError("a11y-query")
        return False

    def hit_test_control(self, handle, label, rect, x, y):
        """True only when the element under the point IS the selected control.

        The selected label is re-resolved in the CURRENT bound window (unique
        role/name match, rectangle exactly equal to the authorising one), then
        ``ElementFromPoint`` plus the bounded raw-view parent walk must reach
        that exact element through ``CompareElements``.  A same-root sibling or
        a transparent overlay covering the control never reaches it, so the
        click is refused instead of being aimed at the overlay.
        """
        target = self._selected(handle, label, rect)
        return self._hit_reaches(self._element_at(x, y), target)


def screen_int(value):
    """An integral screen coordinate as a plain int, or ``control-offscreen``.

    The contract may carry fractional macOS geometry, but Win32 ``POINT`` and
    the ctypes input structures accept integers only: an integral int/float is
    converted here, explicitly and before the call, and a fractional or
    non-finite point is never silently truncated into a different location.
    """
    if type(value) is float and math.isfinite(value) and value == int(value):
        value = int(value)
    elif isinstance(value, int) and type(value) is not bool:
        value = int.__int__(value)  # a genuine int subclass, never an override
    else:
        raise contract.ContractError("control-offscreen")
    if not -2 ** 31 <= value < 2 ** 31:
        raise contract.ContractError("control-offscreen")
    return value


class Win32Api:
    """Thin, read-mostly Win32 surface. Only read-only queries before input."""

    def __init__(self):
        self.user32 = ctypes.WinDLL("user32", use_last_error=True)
        self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
        self._signatures()

    def _signatures(self):
        u, k, a = self.user32, self.kernel32, self.advapi32
        u.EnumWindows.argtypes = [ctypes.c_void_p, wt.LPARAM]
        u.EnumWindows.restype = wt.BOOL
        u.WindowFromPoint.argtypes = [wt.POINT]
        u.WindowFromPoint.restype = wt.HWND
        u.GetAncestor.argtypes = [wt.HWND, wt.UINT]
        u.GetAncestor.restype = wt.HWND
        u.VkKeyScanW.argtypes = [ctypes.c_wchar]
        u.VkKeyScanW.restype = ctypes.c_short
        u.GetWindowThreadProcessId.argtypes = [wt.HWND, ctypes.POINTER(wt.DWORD)]
        u.GetWindowThreadProcessId.restype = wt.DWORD
        u.GetWindowTextLengthW.argtypes = [wt.HWND]
        u.GetWindowTextW.argtypes = [wt.HWND, wt.LPWSTR, ctypes.c_int]
        u.GetClassNameW.argtypes = [wt.HWND, wt.LPWSTR, ctypes.c_int]
        u.IsWindowVisible.argtypes = [wt.HWND]
        u.GetClientRect.argtypes = [wt.HWND, ctypes.POINTER(wt.RECT)]
        u.GetWindowRect.argtypes = [wt.HWND, ctypes.POINTER(wt.RECT)]
        u.ClientToScreen.argtypes = [wt.HWND, ctypes.POINTER(wt.POINT)]
        u.GetForegroundWindow.restype = wt.HWND
        u.SetForegroundWindow.argtypes = [wt.HWND]
        u.SendInput.argtypes = [wt.UINT, ctypes.POINTER(INPUT), ctypes.c_int]
        u.SendInput.restype = wt.UINT
        u.GetSystemMetrics.argtypes = [ctypes.c_int]
        u.OpenInputDesktop.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
        u.OpenInputDesktop.restype = wt.HANDLE
        u.GetUserObjectInformationW.argtypes = [wt.HANDLE, ctypes.c_int, ctypes.c_void_p, wt.DWORD, ctypes.POINTER(wt.DWORD)]
        u.CloseDesktop.argtypes = [wt.HANDLE]
        k.GetCurrentProcess.argtypes = []
        k.GetCurrentProcess.restype = wt.HANDLE
        k.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
        k.OpenProcess.restype = wt.HANDLE
        k.CloseHandle.argtypes = [wt.HANDLE]
        k.QueryFullProcessImageNameW.argtypes = [wt.HANDLE, wt.DWORD, wt.LPWSTR, ctypes.POINTER(wt.DWORD)]
        a.OpenProcessToken.argtypes = [wt.HANDLE, wt.DWORD, ctypes.POINTER(wt.HANDLE)]
        a.GetTokenInformation.argtypes = [wt.HANDLE, ctypes.c_int, ctypes.c_void_p, wt.DWORD, ctypes.POINTER(wt.DWORD)]
        a.EqualSid.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

    def _text(self, function, hwnd, size=contract.MAX_TITLE):
        buffer = ctypes.create_unicode_buffer(size + 1)
        if function(hwnd, buffer, size + 1) <= 0:
            return ""
        return buffer.value

    def _sid_pair(self, source_handle):
        handle = wt.HANDLE()
        if not self.advapi32.OpenProcessToken(source_handle, TOKEN_QUERY, ctypes.byref(handle)):
            return None
        try:
            buffer = ctypes.create_string_buffer(1024)
            needed = wt.DWORD(0)
            if not self.advapi32.GetTokenInformation(handle, TokenUser, buffer, 1024, ctypes.byref(needed)):
                return None
            return buffer, ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0]
        finally:
            self.kernel32.CloseHandle(handle)

    def same_user(self, process_handle):
        mine = self._sid_pair(self.kernel32.GetCurrentProcess())
        theirs = self._sid_pair(process_handle)
        if not mine or not theirs or not mine[1] or not theirs[1]:
            return False
        return bool(self.advapi32.EqualSid(mine[1], theirs[1]))

    def process_image(self, pid):
        """Read-only path + same-user trust; never opens a writable handle."""
        handle = self.kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            return "", False
        try:
            buffer = ctypes.create_unicode_buffer(32768)
            size = wt.DWORD(32768)
            if not self.kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
                return "", False
            return buffer.value, self.same_user(handle)
        finally:
            self.kernel32.CloseHandle(handle)

    def _describe(self, hwnd):
        pid = wt.DWORD(0)
        self.user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        if not pid.value:
            return None
        title = self._text(self.user32.GetWindowTextW, hwnd)
        if not title:
            return None
        window_class = self._text(self.user32.GetClassNameW, hwnd, 256)
        executable, trusted = self.process_image(pid.value)
        bounds_rect, client_rect, origin = wt.RECT(), wt.RECT(), wt.POINT(0, 0)
        if not self.user32.GetWindowRect(hwnd, ctypes.byref(bounds_rect)):
            return None
        self.user32.GetClientRect(hwnd, ctypes.byref(client_rect))
        self.user32.ClientToScreen(hwnd, ctypes.byref(origin))
        screen = (self.user32.GetSystemMetrics(SM_XVIRTUALSCREEN), self.user32.GetSystemMetrics(SM_YVIRTUALSCREEN),
                  self.user32.GetSystemMetrics(SM_CXVIRTUALSCREEN), self.user32.GetSystemMetrics(SM_CYVIRTUALSCREEN))
        left, top = bounds_rect.left, bounds_rect.top
        right, bottom = bounds_rect.right, bounds_rect.bottom
        onscreen = (right > screen[0] and bottom > screen[1] and
                    left < screen[0] + screen[2] and top < screen[1] + screen[3])
        name = executable.replace("\\", "/").rsplit("/", 1)[-1].lower()
        return {
            "id": int(hwnd),
            "pid": int(pid.value),
            "title": title,
            "executable": executable,
            "trusted": trusted,
            "visible": bool(self.user32.IsWindowVisible(hwnd)),
            "onscreen": onscreen,
            "secure": window_class in SECURE_CLASSES or name in SECURE_PROCESSES,
            "bounds": {"x": left, "y": top, "width": max(0, right - left), "height": max(0, bottom - top)},
            "client": {"x": origin.x, "y": origin.y,
                       "width": max(0, client_rect.right - client_rect.left),
                       "height": max(0, client_rect.bottom - client_rect.top)},
        }

    def list_windows(self):
        """Exactly bounded enumeration: >MAX_WINDOWS top-level windows refuses.

        The overflow is recorded even when the matching target was already in
        the first MAX_WINDOWS handles, so enumeration is never truncated into a
        false "unique" answer.
        """
        handles = []
        overflow = []

        @ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)
        def collect(hwnd, _param):
            if len(handles) >= contract.MAX_WINDOWS:
                overflow.append(1)
                return False
            handles.append(hwnd)
            return True

        enumerated = self.user32.EnumWindows(collect, 0)
        if overflow:
            raise contract.ContractError("window-overrun", {"windows": len(handles)})
        if not enumerated:
            # Enumeration stopped before the end without our own overflow stop:
            # the handle list is a partial view and is never returned.
            raise contract.ContractError("window-query", {"windows": len(handles)})
        windows = []
        for hwnd in handles:
            described = self._describe(hwnd)
            if described is not None:
                windows.append(described)
        return windows

    def input_desktop_secure(self):
        """True only when the input desktop is provably NOT the user default.

        A failed ``OpenInputDesktop``/``GetUserObjectInformationW`` leaves the
        desktop identity unknown; "could not ask" is never reported as "not
        secure", because that would authorise input to an unnamed surface.  The
        fixed ``capability-unavailable`` refusal is raised instead.
        """
        desktop = self.user32.OpenInputDesktop(0, False, DESKTOP_READOBJECTS)
        if not desktop:
            raise contract.ContractError("capability-unavailable")
        try:
            buffer = ctypes.create_unicode_buffer(256)
            needed = wt.DWORD(0)
            if not self.user32.GetUserObjectInformationW(desktop, UOI_NAME, buffer,
                                                        ctypes.sizeof(buffer), ctypes.byref(needed)):
                raise contract.ContractError("capability-unavailable")
            return buffer.value != "Default"
        finally:
            self.user32.CloseDesktop(desktop)

    def foreground_pid(self):
        hwnd = self.user32.GetForegroundWindow()
        if not hwnd:
            return None
        pid = wt.DWORD(0)
        self.user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        return int(pid.value) or None

    def focus_state(self, window=None):
        """Foreground HWND and its PID; the contract compares the HWND itself."""
        del window
        hwnd = self.user32.GetForegroundWindow()
        if not hwnd:
            return {"pid": None, "window": None}
        pid = wt.DWORD(0)
        self.user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        return {"pid": int(pid.value) or None, "window": int(hwnd)}

    def root_at(self, identifier, x, y):
        """Top-level window owning screen point (x, y), via WindowFromPoint."""
        try:  # Win32 POINT takes integers only; conversion precedes the call
            point = wt.POINT(screen_int(x), screen_int(y))
        except contract.ContractError:  # fractional/non-finite: never a hit
            return False
        hwnd = self.user32.WindowFromPoint(point)
        if not hwnd:
            return False
        root = self.user32.GetAncestor(hwnd, GA_ROOT) or hwnd
        return int(root) == int(identifier)

    def screen_bounds(self):
        return {
            "x": self.user32.GetSystemMetrics(SM_XVIRTUALSCREEN),
            "y": self.user32.GetSystemMetrics(SM_YVIRTUALSCREEN),
            "width": max(0, self.user32.GetSystemMetrics(SM_CXVIRTUALSCREEN)),
            "height": max(0, self.user32.GetSystemMetrics(SM_CYVIRTUALSCREEN)),
        }

    def activate(self, hwnd):
        return bool(self.user32.SetForegroundWindow(hwnd))

    def _send(self, events):
        """One batch; anything short of the whole batch refuses, never retried.

        SendInput reports how many of the LEADING events it inserted.  Zero
        means nothing reached the queue (``input-failed``).  A short non-zero
        count means a prefix may already be delivered: the whole batch cannot
        be resent without duplicating that prefix, and no "repair" key/button
        release is injected either, so the fixed ``input-unknown`` refusal is
        raised and the driver stops with delivery unprovable.
        """
        if not events:
            raise contract.ContractError("input-failed")
        array = (INPUT * len(events))(*events)
        sent = self.user32.SendInput(len(events), array, ctypes.sizeof(INPUT))
        if type(sent) is not int or sent < 0 or sent > len(events):
            raise contract.ContractError("input-unknown", {"sent": -1})
        if sent != len(events):
            raise contract.ContractError("input-unknown" if sent else "input-failed",
                                         {"sent": sent})
        return {"move": True, "down": True, "up": True}

    def _mouse(self, flags, x=0, y=0):
        event = INPUT(type=INPUT_MOUSE)
        event.union.mi = MOUSEINPUT(x, y, 0, flags, 0, None)
        return event

    def click(self, x, y):
        # MOUSEINPUT is a 32-bit integer structure: validate and convert the
        # coordinates to integers before the screen is read or any Win32 input
        # structure is built.
        x = screen_int(x)
        y = screen_int(y)
        screen = self.screen_bounds()
        if (screen["width"] <= 0 or screen["height"] <= 0 or
                not (screen["x"] <= x < screen["x"] + screen["width"] and
                     screen["y"] <= y < screen["y"] + screen["height"])):
            raise contract.ContractError("control-offscreen")
        ax = int((x - screen["x"]) * 65535 / screen["width"])
        ay = int((y - screen["y"]) * 65535 / screen["height"])
        if not (0 <= ax <= 65535 and 0 <= ay <= 65535):
            raise contract.ContractError("control-offscreen")
        flags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK
        return self._send([self._mouse(flags, ax, ay), self._mouse(MOUSEEVENTF_LEFTDOWN),
                           self._mouse(MOUSEEVENTF_LEFTUP)])

    def _key(self, vk, down):
        event = INPUT(type=INPUT_KEYBOARD)
        event.union.ki = KEYBDINPUT(vk, 0, 0 if down else KEYEVENTF_KEYUP, 0, None)
        return event

    def _virtual_key(self, part):
        """Map one chord part; Ctrl/Alt (AltGr) layout states are refused.

        VkKeyScanW's high byte reports Shift/Ctrl/Alt state the character needs
        on the active layout.  Shift is honoured explicitly; a character that
        needs Ctrl, Alt or AltGr is refused as unsupported instead of being
        typed as the wrong character.
        """
        if len(part) == 1:
            scan = self.user32.VkKeyScanW(part)
            if type(scan) is not int or scan == -1:
                raise contract.ContractError("input-unsupported")
            modifiers = (scan >> 8) & 0xFF
            if modifiers & 0x06:
                raise contract.ContractError("input-unsupported")
            return scan & 0xFF, bool(modifiers & 0x01)
        if part in VK:
            return VK[part], False
        raise contract.ContractError("input-unsupported")

    def _unicode(self, code, down):
        flags = KEYEVENTF_UNICODE | (0 if down else KEYEVENTF_KEYUP)
        event = INPUT(type=INPUT_KEYBOARD)
        event.union.ki = KEYBDINPUT(0, code, flags, 0, None)
        return event

    def type_text(self, text):
        """One physical UNICODE batch; layout and modifiers are irrelevant."""
        if (type(text) is not str or not text or len(text) > contract.MAX_TEXT or
                any(ord(c) < 32 or ord(c) > 126 for c in text)):
            raise contract.ContractError("input-charset")
        events = []
        for char in text:
            code = ord(char)
            events.append(self._unicode(code, True))
            events.append(self._unicode(code, False))
        return self._send(events)

    def press_chord(self, parts):
        codes, implicit_shift = [], False
        for part in parts:
            code, needs_shift = self._virtual_key(part)
            codes.append(code)
            implicit_shift = implicit_shift or needs_shift
        shift = implicit_shift and "Shift_L" not in parts and "Shift_R" not in parts
        events = [self._key(VK_SHIFT, True)] if shift else []
        events += [self._key(code, True) for code in codes]
        events += [self._key(code, False) for code in reversed(codes)]
        if shift:
            events.append(self._key(VK_SHIFT, False))
        return self._send(events)


class WindowsAdapter:
    """Contract adapter: public metadata in, one physical input batch out."""

    platform = PLATFORM
    supports_activation = True
    exact_focus = True
    input_evidence = "accepted"

    def __init__(self, api=None, uia=None):
        self.api = Win32Api() if api is None else api
        self._uia = uia

    @property
    def uia(self):
        if self._uia is None:
            try:
                self._uia = load_uia()
            except contract.ContractError:
                raise
            except Exception:
                raise contract.ContractError("a11y-unavailable")
        return self._uia

    def check_capability(self):
        if self.api.input_desktop_secure():
            raise contract.ContractError("secure-desktop")

    def _normalise(self, raw):
        geometry = ("x", "y", "width", "height")

        def rect(value):
            return {key: (value or {}).get(key) for key in geometry}

        return {
            "id": raw.get("id"),
            "pid": raw.get("pid"),
            "title": raw.get("title") or "",
            "executable": raw.get("executable") or "",
            "trusted": raw.get("trusted") is True,
            "visible": raw.get("visible") is True,
            "onscreen": raw.get("onscreen") is not False,
            "secure": raw.get("secure") is True,
            "bounds": rect(raw.get("bounds")),
            "client": rect(raw.get("client")),
        }

    def list_windows(self):
        return [self._normalise(raw) for raw in self.api.list_windows()]

    def read_window(self, identifier):
        for raw in self.api.list_windows():
            if raw.get("id") == identifier:
                return self._normalise(raw)
        return None

    def read_controls(self, window):
        controls = self.uia.controls(window["id"])
        if not isinstance(controls, list) or len(controls) > contract.MAX_CONTROLS:
            raise contract.ContractError("a11y-overrun")
        for control in controls:
            if type(control) is not dict or set(control) != set(contract.WIDGET_FIELDS):
                raise contract.ContractError("a11y-query")
        return controls

    def focus_state(self, window=None):
        """Exact foreground window only: same PID on another HWND never counts."""
        return self.api.focus_state(window)

    def screen_bounds(self):
        return self.api.screen_bounds()

    def hit_test(self, window, x, y):
        """The click point must resolve to the selected top-level window root."""
        return self.api.root_at(window["id"], x, y)

    def hit_test_control(self, window, label, rect, x, y):
        """Strict identity re-check for the uniquely selected UIA control."""
        return self.uia.hit_test_control(window["id"], label, dict(rect), x, y) is True

    def activate(self, window):
        self.api.activate(window["id"])

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
        adapter = WindowsAdapter()
    except Exception:
        stderr.write(contract.failure_line(contract.ContractError("a11y-unavailable"),
                                           "setup", -1, PLATFORM) + "\n")
        return 1
    return contract.run_stdin(adapter, PLATFORM, stdin, stdout, stderr)


if __name__ == "__main__":
    import sys

    sys.exit(main())
