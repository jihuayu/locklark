"""External macOS ApplicationServices/CoreGraphics input agent for acceptance.

Ordinary external input only: public AX role/title/enabled/hidden/frame and
public window metadata, then ONE physical CGEventPost batch. It never reads an
accessibility value, never performs an accessibility action (no press or
invoke), never touches the clipboard and never injects an approval.

A separate activation-only request names one exact (pid, executable): the
adapter proves that live pid/path/uid with the process identity helpers and
makes exactly one NSRunningApplication activation. It lists no window, reads
no title/control and emits no input.

Accessibility trust is required and started by the human in System Settings >
Privacy & Security > Accessibility. `AXIsProcessTrusted()` is only queried; this
module NEVER prompts for or grants TCC permission -- an untrusted process gets
the fixed capability failure. Screen Recording is not requested: window titles
come from AX once Accessibility is trusted (CGWindowName is only used when the
OS already exposes it).

Two PyObjC frameworks are imported separately and lazily: every AX
(accessibility) call and constant belongs to ApplicationServices/HIServices
(``self.ax``), and only CoreGraphics window/display/event work belongs to
Quartz (``self.quartz``). CoreGraphics is never used as an AX stand-in at
runtime, so a missing ApplicationServices import fails closed instead of
silently reading the wrong framework. Everything imports and unit-tests on
Linux.

AX window identity: same PID, exactly one AX window with exactly the CG title,
and an exact frame or the single measured one-pixel border inset with the same
centre (``AX_CG_BORDER_INSET``). No generic tolerance and no private API.
"""
import ctypes
import math
import os

import native_acceptance_contract as contract

PLATFORM = "macos"
MAX_NODES = 4096
MAX_DEPTH = 12
MAX_HIT_PARENTS = 64
MAX_DISPLAYS = 32

ROLE_MAP = {"AXButton": "push button", "AXTextField": "entry",
            "AXTextArea": "entry"}

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

# The one measured AX<->CG window border relation. A real owned app reported
# CGWindow bounds {313, 75, 1102, 822} and AXWindow frame {314, 76, 1100, 820}:
# the AX frame is exactly 1 point inside every CG edge with the identical
# centre. Public AX exposes no window number (AXAttributeConstants.h has no
# AXWindowNumber) and NSWindow.windowNumber is not the window-server number, so
# the exact title plus this canonical relation is the identity. It is one fixed
# relation, never a +/-1 tolerance: a larger, smaller, partial or off-centre
# difference never matches.
AX_CG_BORDER_INSET = 1
RECT_KEYS = ("x", "y", "width", "height")
# The one fixed set of fractional positions of every exact control rectangle
# tried for a labelled click, in row-major order. The exact centre is always
# first (MacAdapter.click_candidates), so adding the 50% column and row leaves
# at most nine points, all strictly inside the authorising rectangle.
CLICK_FRACTIONS = (0.2, 0.5, 0.8)


def _frame_relation(frame, bounds):
    """'exact' or 'border-inset' for this AX frame/CG bounds pair, else None.

    Both rectangles must be valid positive integer geometry. 'exact' requires
    all four values to be equal. 'border-inset' requires the AX frame to be
    exactly AX_CG_BORDER_INSET inside each CG edge and to share the same centre;
    since both widths (and heights) differ by an even number, that centre is
    whole. Anything else, including any other delta, has no relation.
    """
    if not contract.rect_positive(frame) or not contract.rect_positive(bounds):
        return None
    if all(frame[key] == bounds[key] for key in RECT_KEYS):
        return "exact"
    inset = AX_CG_BORDER_INSET
    if (frame["x"] == bounds["x"] + inset and frame["y"] == bounds["y"] + inset and
            frame["width"] == bounds["width"] - 2 * inset and
            frame["height"] == bounds["height"] - 2 * inset):
        outer = (2 * bounds["x"] + bounds["width"], 2 * bounds["y"] + bounds["height"])
        inner = (2 * frame["x"] + frame["width"], 2 * frame["y"] + frame["height"])
        if inner == outer:
            return "border-inset"
    return None


class BSDInfo(ctypes.Structure):
    """Complete struct proc_bsdinfo: pbi_uid is the real process UID."""

    _fields_ = [("pbi_flags", ctypes.c_uint32), ("pbi_status", ctypes.c_uint32),
                ("pbi_xstatus", ctypes.c_uint32), ("pbi_pid", ctypes.c_uint32),
                ("pbi_ppid", ctypes.c_uint32), ("pbi_uid", ctypes.c_uint32),
                ("pbi_gid", ctypes.c_uint32), ("pbi_ruid", ctypes.c_uint32),
                ("pbi_rgid", ctypes.c_uint32), ("pbi_svuid", ctypes.c_uint32),
                ("pbi_svgid", ctypes.c_uint32), ("rfu_1", ctypes.c_uint32),
                ("pbi_comm", ctypes.c_char * 16), ("pbi_name", ctypes.c_char * 32),
                ("pbi_nfiles", ctypes.c_uint32), ("pbi_pgid", ctypes.c_uint32),
                ("pbi_pjobc", ctypes.c_uint32), ("e_tdev", ctypes.c_uint32),
                ("e_tpgid", ctypes.c_uint32), ("pbi_nice", ctypes.c_int32),
                ("pbi_start_tvsec", ctypes.c_uint64), ("pbi_start_tvusec", ctypes.c_uint64)]


class AxValueUnavailable(Exception):
    """AX returned no usable geometry; the caller must fail closed."""


def _exact_int(value):
    """A plain built-in ``int``, or None for bool, non-integer or hostile values.

    AX geometry is tested with ``type(...) is int`` so a float, a bool or an
    ``int`` subclass with overridden arithmetic can never satisfy the frame
    relation; ``int.__int__`` normalises a genuine ``int`` subclass to plain
    ``int`` without dispatching to an override.
    """
    if type(value) is int:
        return value
    if isinstance(value, int):
        return int.__int__(value)
    return None


def _geometry_int(value):
    """A finite built-in float or a plain int from AXValue, else refuse.

    AXValueGetValue reports CGFloat coordinates as floats.  A genuine, finite
    built-in float is preserved exactly, fractional or not, so a fractional
    macOS control bound is never truncated into a near match; an integral float
    such as 314.0 is still normalised to the same pixel as 314.  ``bool``, NaN,
    infinities, strings and every float subclass (a hostile ``__float__`` is
    never dispatched) are refused.
    """
    if type(value) is float:
        if not math.isfinite(value):
            raise AxValueUnavailable()
        return int(value) if value == int(value) else value
    if type(value) is not int:
        raise AxValueUnavailable()
    return value


def _native_text(value):
    """Exact built-in ``str`` copy of a string-compatible value, else "".

    PyObjC surfaces Quartz/AX NSString titles as ``objc.pyobjc_unicode``, a
    ``str`` subclass that compares equal to the expected title but fails the
    shared contract's ``type(title) is str`` check. Only genuine string
    instances are copied into an exact ``str`` via ``str.__str__`` (which never
    dispatches to a subclass override); every other value keeps a safe empty
    string and arbitrary ``str()`` is never called.
    """
    if isinstance(value, str):
        return str.__str__(value)
    return ""


class QuartzApi:
    """Real ApplicationServices (AX) + CoreGraphics (Quartz) access on macOS.

    ``self.ax`` carries ApplicationServices/HIServices only: the AX trust
    query, AX element creation/copy calls, AX attribute names and AXValue
    types. ``self.quartz`` carries CoreGraphics only: window list, display
    list, event creation/posting. A real run imports both frameworks
    separately and never falls back from one to the other; the single
    exception is an explicitly injected combined fake object, used for tests.
    """

    def __init__(self, quartz=None, appkit=None, ax=None):
        injected = quartz is not None
        if quartz is None or appkit is None:
            import AppKit  # noqa: F401  (PyObjC, imported on demand)
            import Quartz
            quartz = Quartz if quartz is None else quartz
            appkit = AppKit if appkit is None else appkit
        if ax is not None:
            self.ax = ax
        elif injected:
            # Explicit fallback ONLY for a caller-injected (fake) object that
            # stands in for both frameworks; a real run never takes this path.
            self.ax = quartz
        else:
            import ApplicationServices  # noqa: F401  (PyObjC HIServices)
            self.ax = ApplicationServices
        self.quartz, self.appkit = quartz, appkit
        self.libproc = ctypes.CDLL(None)
        self._declare_libproc()

    def _declare_libproc(self):
        """Declare prototypes once; symbols absent off Darwin stay undeclared."""
        declarations = (
            ("proc_pidinfo", [ctypes.c_int, ctypes.c_int, ctypes.c_uint64,
                              ctypes.c_void_p, ctypes.c_int], ctypes.c_int),
            ("proc_pidpath", [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32],
             ctypes.c_int),
        )
        for name, argtypes, restype in declarations:
            try:
                function = getattr(self.libproc, name)
            except (AttributeError, OSError):
                continue
            function.argtypes = argtypes
            function.restype = restype

    # -- capability ---------------------------------------------------------
    def capability(self):
        """Query-only trust check. Never prompts, never grants, never retries."""
        if not bool(self.ax.AXIsProcessTrusted()):
            raise contract.ContractError("capability-unavailable")

    # -- read-only AX helpers ----------------------------------------------
    def attribute(self, element, name):
        result = self.ax.AXUIElementCopyAttributeValue(element, name, None)
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
            result = self.ax.AXValueGetValue(value, value_type, None)
        except Exception:
            raise AxValueUnavailable()
        if not isinstance(result, tuple) or len(result) != 2 or not result[0]:
            raise AxValueUnavailable()
        payload = result[1]
        try:
            pair = (getattr(payload, first), getattr(payload, second))
        except Exception:
            try:
                pair = (payload[0], payload[1])
            except Exception:
                raise AxValueUnavailable()
        return _geometry_int(pair[0]), _geometry_int(pair[1])

    def frame(self, element):
        """AX frame in global display coordinates, or AxValueUnavailable.

        Coordinates are returned exactly as parsed (int or finite float), never
        truncated: a fractional control bound must stay fractional all the way
        to the centre calculation.
        """
        position = self._geometry(element, "AXPosition", self.ax.kAXValueCGPointType, "x", "y")
        size = self._geometry(element, "AXSize", self.ax.kAXValueCGSizeType, "width", "height")
        if position is None or size is None:
            raise AxValueUnavailable()
        return {"x": position[0], "y": position[1],
                "width": size[0], "height": size[1]}

    def application(self, pid):
        return self.ax.AXUIElementCreateApplication(pid)

    def windows(self, pid):
        element = self.application(pid)
        if element is None:
            return []
        value = self.attribute(element, self.ax.kAXWindowsAttribute)
        return list(value) if value else []

    def title(self, element):
        """Exact built-in ``str`` AX title/description; never a native subclass.

        A native string-compatible value is copied to exact ``str`` before it
        is returned so the ``list_windows`` AX fallback reaches MacAdapter
        already type-exact. Anything else is dropped, not coerced.
        """
        for name in ("AXTitle", "AXDescription"):
            text = _native_text(self.attribute(element, name))
            if text:
                return text
        return ""

    # -- widget walk --------------------------------------------------------
    def _relation(self, element, window):
        """Frame relation of this AX window to the CG window, or None.

        The title must be exactly the CG title and the frame exactly equal or
        the one canonical ``AX_CG_BORDER_INSET`` border inset of ``_frame_relation``;
        unreadable geometry has no relation.
        """
        if _native_text(self.title(element)) != _native_text(window.get("title")):
            return None
        try:
            frame = self.frame(element)
        except AxValueUnavailable:
            return None
        return _frame_relation(frame, window.get("bounds"))

    def _identity_matches(self, element, window):
        """True only for the UNIQUE exact-title AX window this CGWindow binds.

        The observed focused/hit AX element is resolved through
        ``window_element`` first, so a duplicated same-title AX window refuses
        ``window-ambiguous`` here exactly as it does for a control read, and the
        exact frame or canonical inset relation stays mandatory.  The element
        must then be the very same AXUIElement as that unique selection under
        ``CFEqual`` (``_same_element``): a twin window with the same title and
        frame that merely looks identical is never accepted.  ``window_element``
        uses ``_relation`` directly, so this never recurses.
        """
        selected = self.window_element(window)
        return self._same_element(element, selected)

    def window_element(self, window):
        """Bind the UNIQUE AX window to this exact CGWindow identity.

        First the same-PID AX window list must hold exactly ONE window whose
        title is exactly the CG title; zero refuses ``a11y-query`` and several
        refuse ``window-ambiguous`` before any frame is compared, so a
        same-title duplicate can never be resolved by frame.  That unique
        window then has to satisfy the exact frame or the canonical one-pixel
        border-inset relation; anything else refuses ``a11y-query``.  The first
        window sharing a title is never used.
        """
        title = _native_text(window.get("title"))
        titled = [element for element in self.windows(window["pid"])
                  if _native_text(self.title(element)) == title]
        if len(titled) > 1:
            raise contract.ContractError("window-ambiguous", {"ax": len(titled)})
        if not titled:
            raise contract.ContractError("a11y-query")
        if self._relation(titled[0], window) is None:
            raise contract.ContractError("a11y-query")
        return titled[0]

    def _control(self, element, role, name):
        """Public fields only; missing or non-boolean AX state fails closed."""
        try:
            bounds = self.frame(element)
        except AxValueUnavailable:
            raise contract.ContractError("control-geometry")
        enabled = self.attribute(element, "AXEnabled")
        hidden = self.attribute(element, "AXHidden")
        if type(enabled) is not bool or type(hidden) is not bool:
            raise contract.ContractError("a11y-unavailable", {"attribute": 1})
        if not contract.rect_positive(bounds):
            raise contract.ContractError("control-geometry")
        return {"role": role, "name": name, "enabled": enabled,
                "visible": not hidden, "bounds": bounds}

    def _labeled(self, window):
        """Bounded AX walk of the exactly bound window: (element, public record)."""
        target = self.window_element(window)
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
                    found.append((element, self._control(element, role, name)))
            children = self.attribute(element, "AXChildren")
            for child in children or []:
                walk(child, depth + 1)

        walk(target, 0)
        return found

    def controls(self, window):
        """Bounded AX walk of the exactly bound target window; public fields."""
        return [record for _, record in self._labeled(window)]

    def _selected(self, window, label, rect):
        """Re-resolve the unique selected control and its native AX element.

        The CURRENT bound AX window is queried again with the same role/name
        rules, and the fresh frame must equal the authorising rectangle
        exactly, so a control that moved or was rebuilt is never clicked.  Zero
        or several label matches refuse.
        """
        rows = [(element, record) for element, record in self._labeled(window)
                if record.get("name") == label and record.get("role") in contract.CONTROL_ROLES]
        if len(rows) > 1:
            raise contract.ContractError("control-ambiguous", {"matches": len(rows)})
        if not rows:
            raise contract.ContractError("control-missing")
        element, record = rows[0]
        bounds = record.get("bounds") or {}
        if not contract.rect_positive(rect) or any(bounds.get(key) != rect.get(key)
                                                   for key in ("x", "y", "width", "height")):
            raise contract.ContractError("control-hit")
        return element

    def _cf_equal(self):
        """CFEqual for native AX elements; absent means refuse, never guess.

        An ``AXUIElement`` is a CFType, so CFEqual is the identity test the AX
        API defines for it.  Python object identity and any name/role/frame
        comparison are never used as a substitute, and neither framework is
        used as a fallback for the other: an injected test object may carry
        CFEqual, otherwise the real CoreFoundation module is imported lazily.
        """
        for source in (self.ax, self.quartz):
            function = getattr(source, "CFEqual", None)
            if callable(function):
                return function
        try:
            import CoreFoundation
            function = CoreFoundation.CFEqual
        except Exception:
            raise contract.ContractError("a11y-unavailable")
        if not callable(function):
            raise contract.ContractError("a11y-unavailable")
        return function

    def _same_element(self, left, right):
        """Native CFEqual identity of two AX elements; never a value compare.

        ``CFEqual`` answers a CoreFoundation ``Boolean``, which PyObjC surfaces
        as a Python bool (an integer 1 is accepted for the same C value).  Every
        other answer - including a name, role or frame that happens to match -
        is not equality.
        """
        if left is None or right is None:
            return False
        equal = self._cf_equal()
        try:
            verdict = equal(left, right)
        except contract.ContractError:
            raise
        except Exception:
            raise contract.ContractError("a11y-query")
        return verdict is True or (type(verdict) is int and verdict == 1)

    def _element_at(self, window, x, y):
        """AX element under the point; a failed query refuses, never a hit."""
        application = self.application(window["pid"])
        if application is None:
            return None
        try:
            result = self.ax.AXUIElementCopyElementAtPosition(
                application, float(x), float(y), None)
        except contract.ContractError:
            raise
        except Exception:
            raise contract.ContractError("a11y-query")
        if isinstance(result, tuple) and len(result) == 2:
            code, element = result
        else:
            code, element = 0, result
        if code != 0:
            raise contract.ContractError("a11y-query")
        return element

    def _reaches(self, element, target):
        """Walk AXParent from the hit element; True only for the selection.

        Every comparison is CFEqual against the ACTUAL selected AX element.  The
        walk is bounded to MAX_HIT_PARENTS steps, stops at the first AXWindow
        (a control never contains one, so the selection was not under the
        point - the window ancestor is never accepted as a substitute), and
        refuses on a repeated element, an exhausted chain or a failed query.
        """
        node, seen = element, []
        for _ in range(MAX_HIT_PARENTS):
            if node is None:
                return False
            if any(self._same_element(node, prior) for prior in seen):
                raise contract.ContractError("a11y-query")
            seen.append(node)
            if self._same_element(node, target):
                return True
            if self.attribute(node, "AXRole") == "AXWindow":
                return False
            try:
                node = self.attribute(node, "AXParent")
            except contract.ContractError:
                raise
            except Exception:
                raise contract.ContractError("a11y-query")
        return False

    def hit_test_control(self, window, label, rect, x, y):
        """True only when the element under the point IS the selected control.

        The selected label is re-resolved in the CURRENT bound AX window under
        the same role/name/exact-frame rules, then the element at the point must
        reach that exact native AXUIElement through bounded AXParent steps and
        CFEqual.  A same-frame sibling or a transparent overlay above the
        control never reaches it, so no click is aimed at the overlay.
        """
        return self._reaches(self._element_at(window, x, y), self._selected(window, label, rect))

    # -- process identity ---------------------------------------------------
    def process_uid(self, pid):
        """True process uid from proc_pidinfo(PROC_PIDTBSDINFO), else None."""
        info = BSDInfo()
        try:
            size = self.libproc.proc_pidinfo(int(pid), PROC_PIDTBSDINFO, 0,
                                             ctypes.byref(info), ctypes.sizeof(info))
        except Exception:
            return None
        if size != ctypes.sizeof(info) or int(info.pbi_pid) != int(pid):
            return None
        if int(info.pbi_uid) < 0:
            return None
        return int(info.pbi_uid)

    def process(self, pid):
        """Read-only pid -> path plus SAME PROCESS uid; unknown uid is untrusted.

        The executable file owner is never used as a process-identity guess:
        when proc_pidinfo cannot prove the process uid, the window is untrusted
        and every request against it is refused.
        """
        buffer = ctypes.create_string_buffer(4096)
        try:
            length = self.libproc.proc_pidpath(int(pid), buffer, 4096)
        except Exception:
            return "", False
        if length <= 0:
            return "", False
        path = buffer.value.decode("utf-8", "replace")
        uid = self.process_uid(pid)
        if uid is None or uid != os.getuid():
            return path, False
        return path, True

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

    # -- display ------------------------------------------------------------
    def point_visible(self, window, x, y):
        """True only inside one real active display rectangle.

        ``CGGetActiveDisplayList`` + ``CGDisplayBounds`` need no Screen
        Recording permission and cannot prompt.  Membership is tested display by
        display: the union of display rectangles is not the screen, so a gap
        between two displays is not clickable.  An unreadable or empty display
        list fails closed.
        """
        del window
        quartz = self.quartz
        try:
            result = quartz.CGGetActiveDisplayList(MAX_DISPLAYS, None, None)
        except Exception:
            return False
        if not isinstance(result, tuple) or len(result) != 3:
            return False
        error, displays, count = result
        if error or displays is None:
            return False
        # A count that is bool, non-integer, out of range or longer than the
        # returned list means the query result is not trustworthy.
        if type(count) is not int or not 1 <= count <= MAX_DISPLAYS:
            return False
        try:
            active = list(displays)
        except Exception:
            return False
        if len(active) < count:
            return False
        for display in active[:count]:
            try:
                bounds = quartz.CGDisplayBounds(display)
                origin, size = bounds[0], bounds[1]
                left, top = float(origin[0]), float(origin[1])
                width, height = float(size[0]), float(size[1])
            except Exception:
                return False
            if not all(math.isfinite(value) for value in (left, top, width, height)):
                return False
            if width <= 0 or height <= 0:
                continue
            if left <= x < left + width and top <= y < top + height:
                return True
        return False

    # -- foreground / input -------------------------------------------------
    def foreground_pid(self):
        workspace = self.appkit.NSWorkspace.sharedWorkspace()
        front = workspace.frontmostApplication()
        return int(front.processIdentifier()) if front is not None else None

    def focus_state(self, window=None):
        """AXFocusedWindow must be the unique exact window; AXMainWindow only adds.

        A frontmost PID is never enough and AXMainWindow is never a fallback:
        when AXFocusedWindow is missing, a same-title duplicate exists or the
        focused element is not the unique selected AXUIElement (CFEqual), no
        window identity is reported and the shared contract refuses input
        before any control read. When the OS also exposes AXMainWindow it is
        only an additional consistency check under the same identity.
        """
        front = self.foreground_pid()
        if window is None or type(front) is not int or front != window["pid"]:
            return {"pid": front, "window": None}
        application = self.application(window["pid"])
        focused = self.attribute(application, "AXFocusedWindow")
        if focused is None or not self._identity_matches(focused, window):
            return {"pid": front, "window": None}
        main = self.attribute(application, "AXMainWindow")
        if main is not None and not self._identity_matches(main, window):
            return {"pid": front, "window": None}
        return {"pid": front, "window": window["id"]}

    def root_at(self, window, x, y):
        """The AXWindow above the point must BE the unique bound AX window.

        The ancestor must satisfy the same uniqueness and ``CFEqual`` identity
        as ``_identity_matches``; a duplicate same-title window refuses here
        too, and any failure fails closed with no hit.
        """
        application = self.application(window["pid"])
        if application is None:
            return False
        result = self.ax.AXUIElementCopyElementAtPosition(
            application, float(x), float(y), None)
        if isinstance(result, tuple) and len(result) == 2:
            code, element = result
        else:
            code, element = 0, result
        if code != 0 or element is None:
            return False
        for _ in range(MAX_DEPTH + 1):
            if self.attribute(element, "AXRole") == "AXWindow":
                return self._identity_matches(element, window)
            element = self.attribute(element, "AXParent")
            if element is None:
                return False
        return False

    def activate(self, pid):
        running = self.appkit.NSRunningApplication.runningApplicationWithProcessIdentifier_(int(pid))
        if running is None:
            return False
        # The named AppKit option, never a literal: NSApplicationActivateAllWindows
        # is 1 and must not be what foregrounding an application asks for.
        return bool(running.activateWithOptions_(
            self.appkit.NSApplicationActivateIgnoringOtherApps))

    def activate_process(self, pid, executable):
        """Identity-proofed, once-only activation of ONE already-known pid.

        Only ``process(pid)`` (proc_pidpath + proc_pidinfo pid/uid) is read:
        no window is listed, no AX element is created and no title, control or
        foreground content is queried. The path must equal the requested
        canonical executable exactly and the live uid must be ours. The
        activation hook supplied by the adapter is then called exactly once
        and its verdict is returned verbatim; nothing here retries.
        """
        if type(pid) is not int or pid <= 1:
            raise contract.ContractError("activation-invalid")
        path, trusted = self.process(pid)
        if not path:
            raise contract.ContractError("activation-failed")
        if not contract.same_executable(executable, path, PLATFORM):
            raise contract.ContractError("process-untrusted")
        if trusted is not True:
            raise contract.ContractError("process-untrusted")
        return self.activate(pid)

    def _post(self, events):
        """Post an already complete, already validated event list exactly once.

        ``CGEventPost`` returns void: a returned call means POSTED, never
        accepted, and nothing here can observe what the application did.  If a
        post raises after an earlier event was delivered, the events are never
        rebuilt or re-posted (that would duplicate a prefix); the fixed
        ``input-unknown`` refusal reports delivery as unprovable instead.
        """
        for index, event in enumerate(events):
            try:
                self.quartz.CGEventPost(self.quartz.kCGHIDEventTap, event)
            except Exception:
                raise contract.ContractError("input-unknown", {"posted": index})
        return {"move": True, "down": True, "up": True}

    def click(self, x, y):
        """Build and validate move/down/up first; a failure posts nothing.

        The point is passed to Quartz exactly as the contract authorised it: a
        fractional coordinate keeps its fraction and is never int-cast, while a
        bool or a non-numeric value is refused instead of being coerced.
        """
        if any(type(value) not in (int, float) or not math.isfinite(value)
               for value in (x, y)):
            raise contract.ContractError("input-failed")
        quartz, point = self.quartz, (x, y)
        events = [quartz.CGEventCreateMouseEvent(None, quartz.kCGEventMouseMoved, point, 0),
                  quartz.CGEventCreateMouseEvent(None, quartz.kCGEventLeftMouseDown, point, 0),
                  quartz.CGEventCreateMouseEvent(None, quartz.kCGEventLeftMouseUp, point, 0)]
        if any(event is None for event in events):
            raise contract.ContractError("input-failed")
        return self._post(events)

    def type_text(self, text):
        """Build every unicode event first: no orphan key-down is ever posted."""
        if not text or len(text) > contract.MAX_TEXT or any(ord(c) < 32 or ord(c) > 126 for c in text):
            raise contract.ContractError("input-charset")
        quartz, events = self.quartz, []
        for char in text:
            for down in (True, False):
                event = quartz.CGEventCreateKeyboardEvent(None, 0, down)
                if event is None:
                    raise contract.ContractError("input-failed")
                try:
                    quartz.CGEventKeyboardSetUnicodeString(event, len(char), char)
                except Exception:
                    raise contract.ContractError("input-unsupported")
                events.append(event)
        return self._post(events)

    def press_chord(self, parts):
        """Build the chord and set its flags before the first post."""
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
        if any(event is None for event in events):
            raise contract.ContractError("input-failed")
        if flags:
            try:
                for event in events:
                    quartz.CGEventSetFlags(event, flags)
            except Exception:
                raise contract.ContractError("input-unsupported")
        return self._post(events)


class MacAdapter:
    """Contract adapter. Focus is never stolen while preserve_focus is asked."""

    platform = PLATFORM
    supports_activation = True
    exact_focus = True
    input_evidence = "posted"

    def __init__(self, api=None, uia=None):
        self.api = QuartzApi() if api is None else api
        del uia  # AX access lives in the injected api object

    def check_capability(self):
        self.api.capability()

    def list_windows(self):
        return [self._normalise(raw) for raw in self.api.list_windows()]

    @staticmethod
    def _native_title(value):
        """Exact built-in ``str`` title, or "" for anything not string-compatible."""
        return _native_text(value)

    def _normalise(self, raw):
        def text(value):
            return MacAdapter._native_title(value)

        def rect(value):
            return {key: (value or {}).get(key) for key in ("x", "y", "width", "height")}

        return {
            "id": raw.get("id"), "pid": raw.get("pid"),
            "title": text(raw.get("title")), "executable": text(raw.get("executable")),
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
        controls = self.api.controls(window)
        if not isinstance(controls, list) or len(controls) > contract.MAX_CONTROLS:
            raise contract.ContractError("a11y-overrun")
        for control in controls:
            if type(control) is not dict or set(control) != set(contract.WIDGET_FIELDS):
                raise contract.ContractError("a11y-query")
        return controls

    def focus_state(self, window=None):
        return self.api.focus_state(window)

    def hit_test(self, window, x, y):
        """Topmost AX element at the point must be inside the selected window."""
        return self.api.root_at(window, x, y)

    def hit_test_control(self, window, label, rect, x, y):
        """Strict identity re-check for the uniquely selected AX control."""
        return self.api.hit_test_control(window, label, dict(rect), x, y) is True

    @staticmethod
    def click_candidates(rect):
        """The fixed exact-point list inside one validated control rectangle.

        The exact centre comes first: the historical integer centre for
        purely integer geometry (unchanged from Windows/X11), otherwise the
        true fractional centre.  It is followed by the points at
        ``CLICK_FRACTIONS`` (20%, 50% and 80%) of the rectangle's width and
        height, in row-major order and deduplicated against the centre, so the
        list is at most ``MAX_CLICK_CANDIDATES`` (9) long.  Every point is
        built from the exact rectangle values (never a tolerance and never an
        offset outward), so it stays strictly inside the selected control.
        Nothing is read from AX here: the caller validates shape, types and
        rect membership.  Integer-resolved macOS geometry keeps the same
        historical integer centre FIRST (bit-for-bit the Windows/X11 point);
        the 3x3 fractional grid is still offered after it so a covered centre
        can fall back to an exact in-bounds point.  Windows/X11 never call
        this hook at all and keep the single centre.
        """
        if type(rect) is not dict:
            raise contract.ContractError("control-hit")
        values = [rect.get(key) for key in RECT_KEYS]
        if not all(type(value) in (int, float) and math.isfinite(value) for value in values):
            raise contract.ContractError("control-hit")
        x, y, width, height = values
        if all(type(value) is int for value in values):
            first = (x + width // 2, y + height // 2)
        else:
            first = (x + width / 2, y + height / 2)
        points = [first]
        for fy in CLICK_FRACTIONS:
            for fx in CLICK_FRACTIONS:
                point = (x + width * fx, y + height * fy)
                if point not in points:
                    points.append(point)
        return [{"x": point[0], "y": point[1]}
                for point in points[:contract.MAX_CLICK_CANDIDATES]]

    def point_visible(self, window, x, y):
        """Point must lie inside one active display; unknown fails closed."""
        return self.api.point_visible(window, x, y)

    def activate(self, window):
        if not self.api.activate(window["pid"]):
            raise contract.ContractError("focus-lost")

    def activate_process(self, pid, executable):
        """Activation-only mode: strict literal True, never a truthy value."""
        if self.api.activate_process(pid, executable) is not True:
            raise contract.ContractError("activation-failed")
        return True

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
