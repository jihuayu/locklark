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
import inspect
import math
import os
import time

import native_acceptance_contract as contract

PLATFORM = "macos"
MAX_NODES = 4096
MAX_DEPTH = 12
MAX_HIT_PARENTS = 64
MAX_DISPLAYS = 32
MAX_AX_WINDOWS = 1024

# Optional read-only inspect diagnostic. The four booleans are the whole
# public result; the fixed status texts below are compared internally and are
# never returned, formatted into an exception, logged or written as a
# diagnostic. The lock-view proof uses only the already-built controls snapshot.
STATUS_FIELDS = contract.STATUS_FIELDS
STATUS_TEXT = (
    ("generic_unlock_error", "操作未完成。请检查输入、文件权限和当前版本后重试。"),
    ("secret_key_format_error", "Secret Key 格式不正确"),
    ("processing", "处理中…"),
)
LOCKED_CONTROLS = ("金库文件", "主密码", "Secret Key", "解锁")
LOCKED_VIEW_ABSENT = "新建登录"

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
# The AXUIElementCopyElementAtPosition status documented for "There is no
# accessibility object at the specified position", and the AXUIElementCopyAttributeValue
# status for an attribute that has no value.  Both are read from
# ``ApplicationServices.kAXErrorNoValue`` through ``self.ax`` at the call site
# (never a bare -25212); kAXErrorSuccess == 0 needs no lookup.  The expected
# value guards against a substituted or absent constant.
AX_ERROR_NO_VALUE_EXPECTED = -25212
# Activation-only readiness for ONE already-known pid. NSRunningApplication
# registration and finished launching legitimately lag the process itself (the
# owned da850 diagnosis saw the app absent at t0 and launch-finished by 0.26 s),
# so the identity proof is re-read and registration/readiness is polled inside
# this one short bound before the single activation. A dead process or a
# mismatched path/uid never waits; an absent or not-yet-launched application
# waits only within the bound and then refuses.
ACTIVATE_READY_TIMEOUT = 2.0
ACTIVATE_READY_POLL = 0.02


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


def _a11y_query():
    """The one fixed refusal for an unknown accessibility/display query."""
    return contract.ContractError("a11y-query")


def diagnostic_of(error):
    """The fixed ``{operation, attribute, error}`` of our own status refusal.

    ``QuartzApi.status`` builds the FIRST failed status-walk query as our own
    ``a11y-query`` ``ContractError`` whose guard holds only the fixed triple;
    it is never raised, but recorded in that call's result. This is the single
    sanitizer (``contract.ax_diagnostic``) of it, shared by the adapter hook.
    Any other error yields None.
    """
    if type(error) is not contract.ContractError or error.code != "a11y-query":
        return None
    return contract.ax_diagnostic(error)


def _status_query(attribute, error=None):
    """The fixed status-walk refusal of one attribute (diagnostic only).

    ``attribute`` is one of the allowlisted AX names the walk reads, and
    ``error`` is the raw AXError (an exact built-in int when one was returned,
    else None); the contract's ``ax_diagnostic`` decides what may be reported.
    """
    return contract.ContractError(
        "a11y-query", {"operation": "status-walk", "attribute": attribute, "error": error})


def _ax_status(ax):
    """``(kAXErrorNoValue, kAXErrorSuccess)`` read through the AX framework, or None.

    ``kAXErrorNoValue`` comes from ``ax.kAXErrorNoValue`` (a plain Python int in
    PyObjC) and must be exactly the documented -25212, so a missing or
    substituted constant can never turn another status into a classification;
    kAXErrorSuccess is the exact built-in ``int`` 0.
    """
    try:
        no_value = ax.kAXErrorNoValue
    except Exception:
        return None
    if type(no_value) is not int or no_value != AX_ERROR_NO_VALUE_EXPECTED:
        return None
    return no_value, 0


def _exact_status(code):
    """True only for an exact built-in ``int`` status (never ``bool``/subclass)."""
    return type(code) is int


def _ax_result(result):
    """Decode one documented AX ``(AXError, value)`` answer, or None.

    The real PyObjC contract for an out-argument call (AXUIElementCopyAttributeValue,
    AXUIElementGetPid) is a two-tuple whose first item is the exact built-in
    ``int`` AXError. Exact 0 means success and returns ``(code, value)`` with
    the value verbatim (nil or not, left for the caller to validate); any other
    exact built-in code returns ``(code, value)`` too, so the caller decides
    what a nonzero status means. ``False``, a bool, a float, a string, a
    non-tuple or a tuple of another length is a malformed answer (None), never
    a success.
    """
    if not isinstance(result, tuple):
        return None
    # Read the two items through the base ``tuple`` protocol, never through an
    # overridable ``len``/``__iter__``: a hostile tuple subclass can raise
    # there, and its exception text must never surface. A tuple of any other
    # length answers None for the missing item exactly like a shape refusal.
    try:
        code = tuple.__getitem__(result, 0)
        value = tuple.__getitem__(result, 1)
        size = tuple.__len__(result)
    except Exception:
        return None
    if size != 2 or not _exact_status(code):
        return None
    return code, value


def _sequence(value):
    """A readable ordered collection, or None.

    PyObjC may return a native ``NSArray``/``CFArray`` instead of a builtin
    list, which is a legitimate documented form and is read as an indexable,
    sized sequence; anything that cannot be read that way is unusable and
    refuses rather than being treated as an empty result.
    """
    if type(value) in (list, tuple):
        return value
    try:
        size = len(value)
        if size < 0:
            return None
        value[0:0]
    except Exception:
        return None
    return value


def _empty_status():
    """The fixed all-false four-boolean diagnostic; never carries AX text."""
    return {field: False for field in STATUS_FIELDS}


# The status walk distinguishes a documented missing value from a failed query.
# Only these attributes may legitimately answer kAXErrorNoValue: a static text
# without an AXDescription (the AX spelling of NSAccessibilityElement
# accessibilityLabel) has no label, and a leaf has no children. AXRole must be
# present, so its own no-value status is a failed query. A container that
# exposes no AXChildren is an empty container, never a refused query: the
# locked view is proved from the controls snapshot, and AppKit commonly omits
# the empty AXChildren attribute, which must not turn the whole diagnostic off.
_STATUS_NO_VALUE = object()
_STATUS_NO_VALUE_ATTRIBUTES = frozenset(("AXDescription", "AXChildren"))
# The built-in AXError kAXErrorAttributeUnsupported (-25205) is also accepted
# for AXDescription only: a static text whose accessibility label is simply not
# exposed answers unsupported rather than no-value, and is read as an absent
# label.  Any other AXDescription error still refuses, and AXRole/AXChildren
# never accept it.
AX_ERROR_ATTRIBUTE_UNSUPPORTED_EXPECTED = -25205
_STATUS_UNSUPPORTED_ATTRIBUTES = frozenset(("AXDescription",))
# Marker for "the proved locked-view walk completed"; never an exception.
_NO_FAILURE = object()


def _status_shape(value):
    """The exact four-built-in-bool status object, else the all-false one."""
    empty = _empty_status()
    if type(value) is not dict or set(value) != set(STATUS_FIELDS):
        return empty
    if any(type(value[field]) is not bool for field in STATUS_FIELDS):
        return empty
    return {field: value[field] for field in STATUS_FIELDS}


def _call_arity(reader):
    """True when ``reader(window, controls, call)`` is its documented signature.

    The per-call result is passed only to a ``read_status``/``status`` hook that
    declares a third positional slot (or takes ``*args``); a two-argument hook
    is called exactly as before.
    """
    try:
        parameters = inspect.signature(reader).parameters.values()
    except Exception:
        return False
    positional = 0
    for parameter in parameters:
        if parameter.kind is parameter.VAR_POSITIONAL:
            return True
        if parameter.kind in (parameter.POSITIONAL_ONLY, parameter.POSITIONAL_OR_KEYWORD):
            positional += 1
    return positional >= 3


def _locked_view(controls):
    """True only for the exact already-read locked controls snapshot.

    This reads the existing safe ``{present, enabled, showing}`` mapping and
    never touches AX. ``present`` AND ``showing`` must both be the exact
    built-in ``True`` for all four locked controls, and ``present`` must be the
    exact built-in ``False`` for the new-login control; ``enabled`` is
    deliberately ignored (a busy control may be disabled while the locked view
    still holds). Any missing/malformed record proves nothing and refuses.
    """
    if type(controls) is not dict:
        return False
    for label in LOCKED_CONTROLS:
        record = controls.get(label)
        if type(record) is not dict:
            return False
        if record.get("present") is not True or record.get("showing") is not True:
            return False
    record = controls.get(LOCKED_VIEW_ABSENT)
    return type(record) is dict and record.get("present") is False


def _ax_value(ax, element, name, status=None):
    """One raw AX attribute read: the value, or ``None`` for a missing value.

    Only the documented ``(AXError, value)`` status tuple is unpacked, and its
    status must be an exact built-in ``int``: kAXErrorSuccess (0) returns the
    value verbatim (nil or not) for the caller to validate, and
    ``ApplicationServices.kAXErrorNoValue`` means the attribute has no value (a
    nil result).  Every other status - including ``False``, which equals 0 but
    is not a status - is an unknown query, as is a raised call or a malformed
    result.  A missing ``kAXErrorNoValue`` constant refuses rather than guessing.
    """
    if status is None:
        status = _ax_status(ax)
        if status is None:
            raise _a11y_query()
    try:
        result = ax.AXUIElementCopyAttributeValue(element, name, None)
    except contract.ContractError:
        raise
    except Exception:
        raise _a11y_query()
    if isinstance(result, tuple):
        if len(result) != 2:
            raise _a11y_query()
        code = result[0]
        if not _exact_status(code):
            raise _a11y_query()
        if code == status[1]:
            return result[1]
        if code == status[0]:
            return None
        raise _a11y_query()
    return result


def _display_query(quartz):
    """The active-display triple; an exception or malformed shape refuses."""
    try:
        result = quartz.CGGetActiveDisplayList(MAX_DISPLAYS, None, None)
    except Exception:
        raise _a11y_query()
    if type(result) is not tuple:
        raise _a11y_query()
    if len(result) != 3:
        raise _a11y_query()
    return result


def _display_list(displays, count):
    """The first ``count`` returned displays; an unusable sequence refuses."""
    active = _sequence(displays)
    if active is None:
        raise _a11y_query()
    if len(active) < count:
        raise _a11y_query()
    try:
        return [active[index] for index in range(count)]
    except Exception:
        raise _a11y_query()


def _display_rect(quartz, display):
    """One display's (left, top, width, height) floats; malformed refuses."""
    try:
        bounds = _sequence(quartz.CGDisplayBounds(display))
        if bounds is None:
            raise ValueError("unreadable bounds")
        origin = _sequence(bounds[0])
        size = _sequence(bounds[1])
        if origin is None or size is None:
            raise ValueError("unreadable origin/size")
        left = float(origin[0])
        top = float(origin[1])
        width = float(size[0])
        height = float(size[1])
    except Exception:
        raise _a11y_query()
    if not math.isfinite(left):
        raise _a11y_query()
    if not math.isfinite(top):
        raise _a11y_query()
    if not math.isfinite(width):
        raise _a11y_query()
    if not math.isfinite(height):
        raise _a11y_query()
    return left, top, width, height


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

    def _status_attribute(self, element, name):
        """Strict status-walk AX read: success, documented no-value, or refuse.

        The generic ``attribute()`` helper above intentionally collapses every
        nonzero status (and ``False``) to ``None``, so it cannot tell an absent
        attribute from a failed query and is never used here. This reader
        requires the documented ``(AXError, value)`` tuple with an exact
        built-in ``int`` status; exact 0 is success, and the only accepted
        missing-value status is the validated ``self.ax.kAXErrorNoValue``. Only
        AXDescription/AXChildren may answer no-value (safe absent label / leaf);
        every other status - including ``False``, a malformed tuple, a raised
        call, a success carrying ``None``, or no-value on AXRole - refuses.
        AXDescription may also answer the built-in kAXErrorAttributeUnsupported
        (-25205), which is likewise read as an absent label; AXRole and
        AXChildren do not accept it and every other status still refuses.
        The raw ``(AXError, value)`` answer is the exact one ``_ax_value_read``
        returns for one ``AXUIElementCopyAttributeValue`` call.

        The documented ``kAXErrorNoValue`` constant is validated HERE, locally,
        before any attribute is read: a missing or substituted constant refuses
        with the sanitized refusal (no recorded error) and provably touches no
        AX attribute at all.
        """
        status = _ax_status(self.ax)
        if status is None:
            raise _status_query(name)
        code, value = self._ax_value_read(element, name)
        if code == status[1]:
            if value is None:
                raise _status_query(name, code)
            return value
        if code == status[0] and name in _STATUS_NO_VALUE_ATTRIBUTES:
            return _STATUS_NO_VALUE
        if (code == AX_ERROR_ATTRIBUTE_UNSUPPORTED_EXPECTED
                and name in _STATUS_UNSUPPORTED_ATTRIBUTES):
            return _STATUS_NO_VALUE
        raise _status_query(name, code)

    def _ax_value_read(self, element, name):
        """One raw ``(AXError, value)`` from AXUIElementCopyAttributeValue, or refuse.

        Requires the documented PyObjC out-argument tuple with an exact built-in
        ``int`` status; a raised call, a ``False`` status or any other shape is
        the fixed sanitized ``a11y-query`` refusal naming ``name``. The value is
        returned verbatim (including nil) for the caller to classify.
        """
        try:
            result = self.ax.AXUIElementCopyAttributeValue(element, name, None)
        except contract.ContractError:
            raise
        except Exception:
            raise _status_query(name)
        decoded = _ax_result(result)
        if decoded is None:
            raise _status_query(name)
        return decoded

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

    def owned_windows(self, pid):
        """The opaque AX window handles of exactly this explicit owned PID.

        AXWindows is obtained ONLY from
        ``ApplicationServices.AXUIElementCreateApplication(pid)`` for the one
        caller-supplied positive owned PID, through the documented PyObjC
        out-argument contract. Every listed element must then prove, in this
        exact order and BEFORE any handle leaves this method:

        1. ownership: ``AXUIElementGetPid(element, None)`` answers the
           ``(AXError, pid)`` tuple with exact status 0 and an exact built-in
           ``int`` pid equal to the requested PID;
        2. role: ``AXUIElementCopyAttributeValue(element, "AXRole", None)``
           answers a strict ``(AXError, value)`` tuple with exact status 0 whose
           value is exactly ``"AXWindow"`` (an empty string copied to an exact
           built-in ``str``). A genuine native list has been observed to carry
           the application root (whose role is ``"AXApplication"``), so no
           non-window role is ever returned, skipped or re-labelled.

        Only the opaque AX handles are returned, in AX order and bounded by
        ``MAX_AX_WINDOWS``. Nothing else is read here: no CoreGraphics window
        inventory and no AX title, bounds, control, value or text attribute.
        Any malformed PID, creation/list/GetPid/role shape, nonzero status,
        mismatched PID, wrong or non-string role, or raised native call fails
        closed with the existing sanitized ``a11y-query`` refusal - never a
        stringified exception or a payload.
        """
        if not _exact_status(pid) or pid <= 0:
            raise _a11y_query()
        try:
            application = self.ax.AXUIElementCreateApplication(pid)
        except Exception:
            raise _a11y_query()
        if application is None:
            raise _a11y_query()
        # Every AXWindows answer is classified here as a bare ``a11y-query``:
        # the status-walk guard of ``_ax_value_read`` is never passed through.
        try:
            answer = self.ax.AXUIElementCopyAttributeValue(application, "AXWindows", None)
        except Exception:
            raise _a11y_query()
        decoded = _ax_result(answer)
        if decoded is None or decoded[0] != 0:
            raise _a11y_query()
        listed = _sequence(decoded[1])
        if listed is None or isinstance(listed, (str, bytes, bytearray)):
            raise _a11y_query()
        try:
            count = len(listed)
        except Exception:
            raise _a11y_query()
        if count > MAX_AX_WINDOWS:
            raise contract.ContractError("a11y-overrun")
        handles = []
        for index in range(count):
            try:
                element = listed[index]
            except Exception:
                raise _a11y_query()
            if element is None:
                raise _a11y_query()
            try:
                answer = self.ax.AXUIElementGetPid(element, None)
            except Exception:
                raise _a11y_query()
            decoded = _ax_result(answer)
            if decoded is None or decoded[0] != 0:
                raise _a11y_query()
            owner = decoded[1]
            if not _exact_status(owner) or owner != pid:
                raise _a11y_query()
            # Ownership is proven first; only then is the role read, and only
            # an exact success carrying exactly AXWindow may join the handles.
            try:
                answer = self.ax.AXUIElementCopyAttributeValue(element, "AXRole", None)
            except Exception:
                raise _a11y_query()
            decoded = _ax_result(answer)
            if decoded is None or decoded[0] != 0:
                raise _a11y_query()
            if _native_text(decoded[1]) != "AXWindow":
                raise _a11y_query()
            handles.append(element)
        return handles

    # -- owned-PID AX path (no CoreGraphics window inventory) ----------------
    def scope_to_owned_pid(self, pid):
        """Scope discovery to ONE explicit positive owned PID.

        The PID must be an exact built-in positive ``int``; a malformed PID
        refuses ``a11y-query`` now. The scope is per-instance and removed by
        ``unscope_owned_pid``; there is no module/global registry.
        """
        if not _exact_status(pid) or pid <= 0:
            raise _a11y_query()
        self._owned_scope_pid = pid
        self._owned_scope_title = None
        # Strong, bounded, per-instance list (not a set: a native AXUIElement
        # need not be hashable, weak-referenceable or stable under Python
        # ``id``). Membership is CFEqual only, never hash/identity.
        self._owned_handles = []

    def unscope_owned_pid(self):
        """Drop the scope AND every retained handle; the CG path applies again."""
        self._owned_scope_pid, self._owned_scope_title = None, None
        self._owned_handles = None

    def owned_pid_scope(self):
        """The validated scoped PID, or None for the unscoped CG path."""
        pid = getattr(self, "_owned_scope_pid", None)
        return pid if _exact_status(pid) and pid > 0 else None

    def owned_discovery(self, title):
        """``([], False)`` while absent, ``([window], True)`` once unique.

        Enumerates ONLY the scoped PID's AX windows, probes GetPid for EVERY
        window before any other attribute, then requires exactly one window
        that IS the retained handle (CFEqual) and carries exactly ``title``.
        The first discovery adopts that handle; nothing else is retained.
        """
        if type(title) is not str or not title:
            raise _a11y_query()
        scope_title = getattr(self, "_owned_scope_title", None)
        if scope_title is not None and scope_title != title:
            # The title is fixed for the whole scope; a later request for a
            # different title must never re-point at a later-owned window.
            raise contract.ContractError("window-changed")
        self._owned_scope_title = title
        expect = self._retained_handle()
        raw = self._enumerate_owned_window(title, expect)
        if raw is None:
            return [], False
        self._adopt_handle(raw["id"])
        return [raw], True

    def _enumerate_owned_window(self, title, expect):
        """Re-enumerate ONLY the owned AX windows and prove the ONE window.

        Shared by discovery, re-observation, controls, hit tests, focus and
        activation, so every one of them refuses on a second owned window or a
        title change AFTER discovery. Order is mandatory: every listed window
        is proven with GetPid FIRST, then the list must hold exactly one, then
        that window must equal the requested retained handle under CFEqual and
        carry exactly the requested title, and only then are its frame and
        process identity read.

        Returns the public record, or None when this observation is simply not
        ready: the owned process has no window yet, OR (only for the INITIAL
        discovery, ``expect is None``) its single window does not carry the
        exact requested title yet. The caller then keeps polling within the
        original discovery deadline instead of treating a not-yet-renamed
        window as a hard failure. Once a window was accepted (``expect`` is
        bound), a title change is an immediate ``window-changed`` refusal.
        """
        pid = self.owned_pid_scope()
        if pid is None:
            raise _a11y_query()
        if type(title) is not str or not title:
            raise _a11y_query()
        elements = self.owned_windows(pid)
        if not elements:
            return None
        if len(elements) != 1:
            # A second owned window is ambiguous: never the first one.
            raise contract.ContractError("window-ambiguous", {"ax": len(elements)})
        element = elements[0]
        if self._proven_pid(element) != pid:
            raise _a11y_query()
        if expect is not None and not self._same_element(element, expect):
            raise contract.ContractError("window-changed")
        name = self.title(element)
        if not name or name != title:
            if expect is None:
                # Initial discovery: a wrong title is not-ready, never an
                # accepted (or wrong) window, and never a hard refusal.
                return None
            raise contract.ContractError("window-changed")
        try:
            bounds = self.frame(element)
        except AxValueUnavailable:
            raise _a11y_query()
        if not contract.rect_positive(bounds):
            raise _a11y_query()
        path, trusted = self.process(pid)
        return {
            "id": element, "pid": pid, "title": name,
            "executable": path, "trusted": trusted,
            "visible": True, "onscreen": True,
            "secure": path.rsplit("/", 1)[-1].lower() in SECURE_PROCESSES,
            "bounds": dict(bounds), "client": dict(bounds),
        }

    def owned_window_records(self):
        """Public records of EVERY owned AX window (scoped; no CG inventory).

        Discovery and absence both observe through here. Every listed window is
        proven with GetPid BEFORE its title or frame is read, and a window that
        does not belong to the scoped PID refuses (never "absent").
        """
        pid = self.owned_pid_scope()
        if pid is None:
            raise _a11y_query()
        records = []
        for element in self.owned_windows(pid):
            if self._proven_pid(element) != pid:
                raise _a11y_query()
            name = self.title(element)
            if not name:
                continue
            try:
                bounds = self.frame(element)
            except AxValueUnavailable:
                raise _a11y_query()
            if not contract.rect_positive(bounds):
                raise _a11y_query()
            path, trusted = self.process(pid)
            records.append({
                "id": element, "pid": pid, "title": name,
                "executable": path, "trusted": trusted,
                "visible": True, "onscreen": True,
                "secure": path.rsplit("/", 1)[-1].lower() in SECURE_PROCESSES,
                "bounds": dict(bounds), "client": dict(bounds),
            })
        return records

    def set_owned_scope_title(self, title):
        """Fix the exact requested title for this scope (validated plain text)."""
        if self.owned_pid_scope() is None or type(title) is not str or not title \
                or len(title) > contract.MAX_TITLE:
            raise _a11y_query()
        current = self.owned_scope_title()
        if current is not None and current != title:
            raise contract.ContractError("window-changed")
        self._owned_scope_title = title

    def owned_scope_title(self):
        """The exact title this scope was discovered with, or None."""
        title = getattr(self, "_owned_scope_title", None)
        return title if type(title) is str and title else None

    def _retained_handles(self):
        handles = getattr(self, "_owned_handles", None)
        return handles if type(handles) is list else None

    def _retained_handle(self):
        """The ONE retained handle, or None when this request holds none."""
        handles = self._retained_handles()
        if not handles:
            return None
        return handles[0]

    def _adopt_handle(self, element):
        """Retain this request's single handle (bounded; release clears it)."""
        handles = self._retained_handles()
        if handles is None:
            raise _a11y_query()
        if len(handles) >= MAX_AX_WINDOWS:
            raise contract.ContractError("a11y-overrun")
        if not handles:
            handles.append(element)

    def _holds_handle(self, element):
        """True when ``element`` IS the request's retained handle (CFEqual)."""
        handle = self._retained_handle()
        if handle is None or element is None:
            return False
        return self._same_element(handle, element)

    def _proven_pid(self, element):
        """The proven owner PID of one AX element (fail closed)."""
        try:
            answer = self.ax.AXUIElementGetPid(element, None)
        except Exception:
            raise _a11y_query()
        decoded = _ax_result(answer)
        if decoded is None or decoded[0] != 0:
            raise _a11y_query()
        owner = decoded[1]
        if not _exact_status(owner) or owner <= 0:
            raise _a11y_query()
        return owner

    def _current_owned_window(self, element, title=None):
        """Re-enumerate and prove THIS request's retained owned window.

        Returns the fresh public record, or None when the window is gone. A
        foreign/mismatched handle, a second owned window or a title change
        refuses (``window-ambiguous``/``window-changed``/``a11y-query``)
        before anything else about it is read.
        """
        if not self._holds_handle(element):
            raise contract.ContractError("window-changed")
        expected = self.owned_scope_title()
        if expected is None:
            raise _a11y_query()
        if title is not None and title != expected:
            raise contract.ContractError("window-changed")
        return self._enumerate_owned_window(expected, element)

    def owned_window(self, element):
        """Re-observe the retained owned AX window by re-enumerating its PID."""
        return self._current_owned_window(element)

    def owned_element_controls(self, element):
        """Controls of the retained owned AX window, re-proven first."""
        raw = self._current_owned_window(element)
        if raw is None:
            raise contract.ContractError("window-changed")
        return self._labeled(None, element)

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

    def _labeled(self, window, target=None):
        """Bounded AX walk of the exactly bound window: (element, public record).

        With an explicit retained owned AX ``target`` that element is walked
        directly (it was already proven to belong to the scoped PID); without
        one the CG window is bound exactly as before.
        """
        if target is None:
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

    def _status_matches(self, target):
        """Bounded static-text AXDescription comparison for the proved locked view.

        Only AXRole, AXChildren and AXDescription are read here (and never
        AXValue or AXSelectedText), through the strict status-only reader: a
        failed query refuses, a documented AXDescription no-value (or the
        built-in kAXErrorAttributeUnsupported) is a safe absent label, and a
        documented AXChildren no-value is a leaf (an
        element without children, never a read failure). The AX
        spelling matches the local SDK, where
        NSAccessibilityElement.accessibilityLabel is AXDescription (MyGo 0.7.4
        writes static-text labels with setAccessibilityLabel:). Every label is
        compared internally with the fixed STATUS_TEXT strings; an unknown or
        empty label is discarded and no text is retained, returned or formatted
        anywhere. The existing MAX_NODES/MAX_DEPTH bounds still refuse rather
        than truncate, and the caller converts every query/shape refusal to the
        fixed all-false object.
        """
        found = {field: False for field, _ in STATUS_TEXT}
        nodes = [0]

        def walk(element, depth):
            nodes[0] += 1
            if nodes[0] > MAX_NODES:
                raise contract.ContractError("a11y-overrun")
            if depth > MAX_DEPTH:
                raise contract.ContractError("a11y-tree-limit")
            raw_role = self._status_attribute(element, "AXRole")
            if raw_role is _STATUS_NO_VALUE or not isinstance(raw_role, str):
                raise _status_query("AXRole")
            role = _native_text(raw_role)
            if not role:
                raise _status_query("AXRole")
            if role == "AXStaticText":
                raw_label = self._status_attribute(element, "AXDescription")
                if raw_label is not _STATUS_NO_VALUE:
                    if not isinstance(raw_label, str):
                        raise _status_query("AXDescription")
                    label = _native_text(raw_label)
                    for field, text in STATUS_TEXT:
                        if label == text:
                            found[field] = True
            raw_children = self._status_attribute(element, "AXChildren")
            if raw_children is _STATUS_NO_VALUE:
                return
            children = _sequence(raw_children)
            if children is None or isinstance(children, (str, bytes, bytearray)):
                raise _status_query("AXChildren")
            for child in children:
                if child is None:
                    raise _status_query("AXChildren")
                walk(child, depth + 1)

        walk(target, 0)
        return found

    def status(self, window, controls, call=None):
        """Optional locked-view status diagnostic: exactly four booleans.

        The existing controls snapshot is proved locked first, before any AX
        binding or label read. Only then is the exact already-bound AX window
        walked and its AXDescription values compared internally. This method
        NEVER raises: a false/incomplete proof, an unavailable binding, any
        query/shape error and any traversal overrun all return the same
        all-false object, so this diagnostic can never fail the caller.

        The FIRST failed query carries only the fixed diagnostic triple of our
        own ``a11y-query`` refusal. It is delivered ONLY through the explicit
        per-call ``call`` result (``record``), never raised and never kept in
        module or instance state, so no diagnostic outlives the call that
        produced it. Without a ``call`` the failure is simply all-false.
        """
        status, diagnostic = self._status_walk(window, controls)
        if diagnostic is not None and call is not None:
            report = getattr(call, "report", None) or getattr(call, "record", None)
            if callable(report):
                report(diagnostic)
        return status

    def read_status(self, window, controls, call=None):
        """Expose the non-raising status diagnostic under the adapter spelling."""
        return self.status(window, controls, call)

    def _status_walk(self, window, controls):
        """``(fixed four-boolean status, sanitized diagnostic or None)``.

        Never raises. Every failure of the proof, binding, walk or traversal is
        converted to the all-false status; the diagnostic is the already
        allowlisted ``{operation, attribute, error}`` of the FIRST status-walk
        query refusal (None for any other error), handed back for exactly this
        call and never raised or stored.
        """
        refusal = _NO_FAILURE
        try:
            if type(controls) is not dict or not _locked_view(controls):
                return _empty_status(), None
            target = self.window_element(window)
            found = self._status_matches(target)
        except Exception as failure:
            refusal = failure
        if refusal is not _NO_FAILURE:
            try:
                return _empty_status(), diagnostic_of(refusal)
            except Exception:
                return _empty_status(), None
        result = _empty_status()
        result["available"] = True
        for field, _ in STATUS_TEXT:
            result[field] = found[field]
        return result, None

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

    def identity_equal(self, first, second):
        """Trusted handle equality for the contract: native CFEqual, exact bool.

        An unusable query or an answer that is neither the PyObjC bool nor the
        CoreFoundation integer Boolean refuses ``window-changed``; it is never
        silently reported as "different".
        """
        try:
            if self._same_element(first, second):
                return True
            if self._same_element(second, first):
                return True
        except contract.ContractError:
            raise contract.ContractError("window-changed")
        return False

    def focus_identity(self, window, state):
        """Prove focus with the OWNED AXFocusedWindow of the scoped PID.

        Only when exact focus is expected: the frontmost PID is the window's,
        the retained handle is one of ours, and that handle IS the application's
        AXFocusedWindow under CFEqual. A same-PID different window refuses.
        """
        pid = self.owned_pid_scope()
        handle = window.get("id") if type(window) is dict else None
        if pid is None or handle is None or not self._holds_handle(handle):
            return False
        if window.get("pid") != pid or state.get("pid") != pid:
            return False
        if state.get("window") is not handle:
            return False
        try:
            # Re-enumerate the owned windows FIRST: a second window or a title
            # change after discovery must refuse, never authorise input.
            if self._current_owned_window(handle) is None:
                return False
        except contract.ContractError as error:
            if error.code in ("window-changed", "window-ambiguous"):
                return False
            raise
        try:
            application = self.application(pid)
            if application is None:
                return False
            focused = self.attribute(application, "AXFocusedWindow")
            if focused is None:
                return False
            return self._same_element(focused, handle)
        except contract.ContractError:
            raise
        except Exception:
            raise contract.ContractError("a11y-query")

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

        When scoped to an owned PID the selected control is re-resolved in the
        SAME retained owned AX handle (never by enumerating again), so the
        point can only authorise a control of this owned window.
        """
        identity = window.get("id") if type(window) is dict else None
        if self.owned_pid_scope() is not None:
            selected = self._owned_selected(window, identity, label, rect)
            return self._reaches(self._element_at(window, x, y), selected)
        return self._reaches(self._element_at(window, x, y), self._selected(window, label, rect))

    def _owned_selected(self, window, element, label, rect):
        """The selected control of ONE retained owned AX handle; else refuse."""
        if element is None or self._current_owned_window(element) is None:
            raise contract.ContractError("a11y-query")
        rows = [(row, record) for row, record in self._labeled(window, element)
                if record.get("name") == label and record.get("role") in contract.CONTROL_ROLES]
        if len(rows) > 1:
            raise contract.ContractError("control-ambiguous", {"matches": len(rows)})
        if not rows:
            raise contract.ContractError("control-missing")
        row, record = rows[0]
        bounds = record.get("bounds") or {}
        if not contract.rect_positive(rect) or any(bounds.get(key) != rect.get(key)
                                                   for key in ("x", "y", "width", "height")):
            raise contract.ContractError("control-hit")
        return row

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
        between two displays is not clickable.  ``False`` means the query
        SUCCEEDED and proved the point outside every active display; a raised
        API exception, a CoreGraphics error, an empty or malformed display list,
        an unusable count or unreadable/undisplayable bounds is an unknown query
        state and refuses the fixed ``a11y-query`` instead of a skippable miss.
        """
        del window
        result = _display_query(self.quartz)
        error = result[0]
        displays = result[1]
        count = result[2]
        # The status must be the exact built-in int 0: ``False`` equals 0 but is
        # a malformed CoreGraphics status, never a success.
        if not _exact_status(error) or error != 0:
            raise _a11y_query()
        if displays is None:
            raise _a11y_query()
        if type(count) is not int:
            raise _a11y_query()
        if count < 1:
            raise _a11y_query()
        if count > MAX_DISPLAYS:
            raise _a11y_query()
        rects = [_display_rect(self.quartz, display)
                 for display in _display_list(displays, count)]
        for left, top, width, height in rects:
            # A zero/negative-area member is not a usable display rather than
            # a member that silently contains nothing.
            if width <= 0 or height <= 0:
                raise _a11y_query()
        for left, top, width, height in rects:
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
        if self.owned_pid_scope() is not None:
            return self._owned_focus_state(front, window)
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
        too.  A succeeded query with no element, a chain that ends before any
        AXWindow or a bound AXWindow under another window are a legitimate
        ``False`` miss.  An unavailable application, a raised AX query, any
        other non-zero status, a malformed result (a status that is not an
        exact built-in int, including ``False``) or a bounded walk that never
        reaches an AXWindow is an unknown query state and refuses the fixed
        ``a11y-query``; it never looks like a skippable candidate miss.

        ``ApplicationServices.kAXErrorNoValue`` is the documented status for
        "There is no accessibility object at the specified position": the
        query SUCCEEDED and the point holds no AX object, so it is a miss.
        The same named status on an attribute read means AXRole is unknown
        (refused, as above) and AXParent is absent (the chain ends before the
        selected AXWindow - a valid ``False`` hit).  The AXRole string is
        normalized to an exact built-in ``str`` before validation, so a native
        ``objc.pyobjc_unicode`` role is read exactly while an empty or
        non-string role still refuses.

        When scoped to an owned PID the AXWindow ancestor must BE the retained
        owned handle (CFEqual) with the same proven PID; no title/frame is
        matched and no CoreGraphics inventory is consulted.
        """
        scoped_pid = self.owned_pid_scope()
        if scoped_pid is not None:
            return self._owned_root_at(window, scoped_pid, x, y)
        status = _ax_status(self.ax)
        if status is None:
            raise contract.ContractError("a11y-query")
        try:
            application = self.application(window["pid"])
            available = application is not None
        except Exception:
            available = False
        if not available:
            raise contract.ContractError("a11y-query")
        try:
            result = self.ax.AXUIElementCopyElementAtPosition(
                application, float(x), float(y), None)
        except contract.ContractError:
            raise
        except Exception:
            raise contract.ContractError("a11y-query")
        if isinstance(result, tuple) and len(result) == 2:
            code, element = result
            if not _exact_status(code):
                raise contract.ContractError("a11y-query")
        elif type(result) is tuple:
            raise contract.ContractError("a11y-query")
        else:
            # A native out-parameter may surface as the bare element.
            code, element = status[1], result
        if code == status[0]:
            return False
        if code != status[1]:
            raise contract.ContractError("a11y-query")
        if element is None:
            return False
        # A nil AXParent is a successful "no parent": the chain ends before
        # any AXWindow and the point has no window root (a legitimate miss).
        # A raised read or an unreadable role/parent payload is an unknown
        # query and refuses; a walk that never ends refuses too.
        for _ in range(MAX_DEPTH + 1):
            role = _native_text(_ax_value(self.ax, element, "AXRole", status))
            if not role:
                raise contract.ContractError("a11y-query")
            if role == "AXWindow":
                return self._identity_matches(element, window)
            parent = _ax_value(self.ax, element, "AXParent", status)
            if parent is None:
                return False
            element = parent
        raise contract.ContractError("a11y-query")

    def _owned_focus_state(self, front, window):
        """Scoped focus: the retained handle must be AXFocusedWindow (CFEqual)."""
        pid = self.owned_pid_scope()
        handle = window.get("id") if type(window) is dict else None
        if front != pid or window.get("pid") != pid or handle is None:
            return {"pid": front, "window": None}
        try:
            if self._current_owned_window(handle) is None:
                return {"pid": front, "window": None}
        except contract.ContractError as error:
            if error.code != "window-changed":
                raise
            return {"pid": front, "window": None}
        try:
            application = self.application(pid)
            focused = self.attribute(application, "AXFocusedWindow") if application is not None else None
            if focused is None or not self._same_element(focused, handle):
                return {"pid": front, "window": None}
            main = self.attribute(application, "AXMainWindow")
            if main is not None and not self._same_element(main, handle):
                return {"pid": front, "window": None}
            return {"pid": front, "window": handle}
        except contract.ContractError:
            raise
        except Exception:
            raise contract.ContractError("a11y-query")

    def _owned_root_at(self, window, pid, x, y):
        """Scoped window-root hit test over the retained owned AX handle."""
        handle = window.get("id") if type(window) is dict else None
        if handle is None or self._current_owned_window(handle) is None:
            raise contract.ContractError("a11y-query")
        if window.get("pid") != pid:
            raise contract.ContractError("a11y-query")
        status = _ax_status(self.ax)
        if status is None:
            raise contract.ContractError("a11y-query")
        try:
            application = self.application(pid)
        except Exception:
            raise contract.ContractError("a11y-query")
        if application is None:
            raise contract.ContractError("a11y-query")
        try:
            result = self.ax.AXUIElementCopyElementAtPosition(
                application, float(x), float(y), None)
        except contract.ContractError:
            raise
        except Exception:
            raise contract.ContractError("a11y-query")
        decoded = None
        if isinstance(result, tuple) and len(result) == 2:
            decoded = result
        elif type(result) is tuple:
            raise contract.ContractError("a11y-query")
        else:
            decoded = (status[1], result)
        code, element = decoded
        if not _exact_status(code):
            raise contract.ContractError("a11y-query")
        if code == status[0]:
            return False
        if code != status[1]:
            raise contract.ContractError("a11y-query")
        if element is None:
            return False
        for _ in range(MAX_DEPTH + 1):
            role = _native_text(_ax_value(self.ax, element, "AXRole", status))
            if not role:
                raise contract.ContractError("a11y-query")
            if role == "AXWindow":
                if self._proven_pid(element) != pid:
                    raise contract.ContractError("a11y-query")
                return self._same_element(element, handle)
            parent = _ax_value(self.ax, element, "AXParent", status)
            if parent is None:
                return False
            element = parent
        raise contract.ContractError("a11y-query")

    def activate_owned(self, window):
        """Activate the owned process, then prove its owned window is focused.

        The retained handle must still be the application's AXFocusedWindow
        (CFEqual) and the frontmost process must be the owned PID; a same-PID
        different window never authorises input.
        """
        pid = self.owned_pid_scope()
        handle = window.get("id") if type(window) is dict else None
        if pid is None or handle is None or window.get("pid") != pid:
            raise contract.ContractError("focus-lost")
        # Re-enumerate and prove the owned window BEFORE any activation.
        try:
            if self._current_owned_window(handle) is None:
                raise contract.ContractError("focus-lost")
        except contract.ContractError as error:
            if error.code not in ("focus-lost", "window-changed", "window-ambiguous"):
                raise
            raise contract.ContractError("focus-lost")
        if not self.activate(pid):
            raise contract.ContractError("focus-lost")
        state = self.focus_state(window)
        if self.focus_identity(window, state) is not True:
            raise contract.ContractError("focus-lost")
        app = self.appkit.NSWorkspace.sharedWorkspace().frontmostApplication()
        if app is None or int(app.processIdentifier()) != pid:
            raise contract.ContractError("focus-lost")
        return True

    def activate(self, pid):
        running = self.appkit.NSRunningApplication.runningApplicationWithProcessIdentifier_(int(pid))
        if running is None:
            return False
        # The named AppKit option, never a literal: NSApplicationActivateAllWindows
        # is 1 and must not be what foregrounding an application asks for.
        return bool(running.activateWithOptions_(
            self.appkit.NSApplicationActivateIgnoringOtherApps))

    def _activation_identity(self, pid, executable):
        """Re-read ONE pid's live path/uid and prove it is the exact request.

        Only ``process(pid)`` (proc_pidpath + proc_pidinfo pid/uid) is read. A
        dead or unreadable process refuses ``activation-failed``; a path that
        is not the exact requested canonical executable, or a uid that is not
        provably ours, refuses ``process-untrusted``. Both are final: the
        caller never waits or retries after them.
        """
        path, trusted = self.process(pid)
        if not path:
            raise contract.ContractError("activation-failed")
        if not contract.same_executable(executable, path, PLATFORM):
            raise contract.ContractError("process-untrusted")
        if trusted is not True:
            raise contract.ContractError("process-untrusted")

    def activation_ready(self, pid):
        """Read-only readiness of THIS pid's NSRunningApplication, or raise.

        Returns ``False`` only while the application is not yet registered
        (``None``) or registered and not yet finished launching; that is the
        sole state the caller may wait on. Returns ``True`` only when the
        registered object reports the requested pid through a callable
        ``processIdentifier()`` returning an exact built-in ``int`` equal to
        ``pid`` (a missing/non-callable/string/float/bool/``int`` subclass
        answer is refused, never coerced) and ``isFinishedLaunching()`` answers
        the built-in ``True``. A missing/raising AppKit API, an object for a
        different pid, or any other answer refuses ``activation-failed`` at
        once - it is never readiness and never a wait.
        """
        try:
            lookup = self.appkit.NSRunningApplication.runningApplicationWithProcessIdentifier_
            running = lookup(int(pid))
        except Exception:
            raise contract.ContractError("activation-failed")
        if running is None:
            return False
        if running is True or running is False:
            raise contract.ContractError("activation-failed")
        try:
            identifier = running.processIdentifier
            reported = identifier() if callable(identifier) else None
            finished = running.isFinishedLaunching()
        except Exception:
            raise contract.ContractError("activation-failed")
        if type(reported) is not int or reported != pid:
            raise contract.ContractError("activation-failed")
        if finished is True:
            return True
        if finished is False:
            return False
        raise contract.ContractError("activation-failed")

    def activate_process(self, pid, executable):
        """Identity-proofed, bounded-readiness, once-only activation of ONE known pid.

        Only ``process(pid)`` (proc_pidpath + proc_pidinfo pid/uid) and this
        pid's own ``NSRunningApplication`` registration/isFinishedLaunching are
        read: no window is listed, no AX element is created and no title,
        control or foreground content is queried. The identity (exact
        executable, our uid, live process) must hold BEFORE the readiness wait
        (re-read on every poll, so a process that dies or is replaced while
        waiting refuses) and is re-read once more after readiness and BEFORE
        the single activation. An absent or not-yet-finished application may
        only WAIT inside ``ACTIVATE_READY_TIMEOUT``; on expiry the request
        refuses. A missing or unusable AppKit readiness API is refused at once,
        without waiting. Exactly one OS activation is then attempted and its
        verdict returned verbatim; nothing retries after an activation call or
        a refusal.
        """
        if type(pid) is not int or pid <= 1:
            raise contract.ContractError("activation-invalid")
        deadline = time.monotonic() + ACTIVATE_READY_TIMEOUT
        while True:
            self._activation_identity(pid, executable)
            ready = self.activation_ready(pid)
            if ready is True:
                break
            # Only a definite "not yet registered / not yet finished" may wait;
            # an unusable API already raised, and a passed deadline refuses
            # without ever calling activation.
            if time.monotonic() < deadline:
                time.sleep(max(0.0, min(ACTIVATE_READY_POLL, deadline - time.monotonic())))
                continue
            raise contract.ContractError("activation-failed")
        self._activation_identity(pid, executable)
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

    def _scoped(self):
        reader = getattr(self.api, "owned_pid_scope", None)
        return callable(reader) and reader() is not None

    def observe_plan(self, plan):
        """Hand the exact requested title to a scoped API before discovery.

        The title lives on the API's per-request scope (cleared on release), so
        every later re-enumeration proves the same exact title. Unscoped
        adapters keep no title at all.
        """
        if not self._scoped():
            return
        title = plan.get("title") if type(plan) is dict else None
        setter = getattr(self.api, "set_owned_scope_title", None)
        if not callable(setter) or type(title) is not str:
            raise contract.ContractError("a11y-query")
        setter(title)

    def scope_owned_process(self, pid):
        """Scope discovery to one owned PID; the returned release drops it.

        Releasing also clears the retained handle(s) and the exact scope title,
        so nothing about this request survives it.
        """
        setter = getattr(self.api, "scope_to_owned_pid", None)
        clearer = getattr(self.api, "unscope_owned_pid", None)
        if not callable(setter) or not callable(clearer):
            raise contract.ContractError("a11y-query")
        setter(pid)
        return clearer

    def identity_equal(self, first, second):
        """Trusted opaque handle equality for the contract (native CFEqual)."""
        equal = getattr(self.api, "identity_equal", None)
        if not callable(equal):
            raise contract.ContractError("window-changed")
        return equal(first, second)

    def focus_identity(self, window, state):
        """Opaque focus proof against the owned AXFocusedWindow."""
        prove = getattr(self.api, "focus_identity", None)
        if not callable(prove):
            return False
        return prove(window, state)

    def list_windows(self):
        """Scoped: the owned PID's AX windows only (never the CG inventory).

        Discovery goes through ``owned_discovery`` so the exact-title match is
        enforced and the single accepted handle is adopted for later proofs.
        """
        if self._scoped():
            title = self.api.owned_scope_title()
            if type(title) is not str:
                raise contract.ContractError("a11y-query")
            windows, unique = self.api.owned_discovery(title)
            return [] if not unique else [self._normalise(raw) for raw in windows]
        return [self._normalise(raw) for raw in self.api.list_windows()]

    def owned_process_windows(self):
        """Public records of ONLY the owned PID's AX windows (absence seam).

        Every observed window is proven with GetPid before its title/frame.
        This never consults the CoreGraphics inventory.
        """
        reader = getattr(self.api, "owned_window_records", None)
        if not callable(reader):
            raise contract.ContractError("a11y-query")
        return reader()

    def owned_absence(self, plan):
        """Scoped absence state: is ANY owned AX window exactly ``plan``'s?

        Returns ``{"present": bool}``. An absence request has no discovery, so
        the plan's exact title (already validated by the contract and never
        waived) fixes the scope title here. An observation that cannot be
        proven refuses ``a11y-query`` instead of guessing "absent".
        """
        title = plan.get("title") if type(plan) is dict else None
        if type(title) is not str:
            raise contract.ContractError("a11y-query")
        setter = getattr(self.api, "set_owned_scope_title", None)
        if not callable(setter):
            raise contract.ContractError("a11y-query")
        setter(title)
        expected = self.api.owned_scope_title()
        if title != expected:
            raise contract.ContractError("a11y-query")
        platform = self.platform
        requested = plan.get("executable")
        windows = self.owned_process_windows()
        matches = [window for window in windows
                   if window.get("title") == expected
                   and window.get("pid") == self.api.owned_pid_scope()
                   and (requested is None
                        # The SAME canonical executable contract as unscoped
                        # absence, never a raw string equality.
                        or contract.same_executable(
                            requested, window.get("executable"), platform))]
        # The fixed absence semantics stay identical: present means the exact
        # unique window; the identity observed is the owned AX handle.
        return {"present": bool(matches),
                "pid": self.api.owned_pid_scope(),
                "id": matches[0]["id"] if matches else None}

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
        """Scoped: re-observe the SAME retained owned AX handle, never the CG list."""
        if self._scoped():
            reader = getattr(self.api, "owned_window", None)
            if not callable(reader):
                raise contract.ContractError("a11y-query")
            raw = reader(identifier)
            return None if raw is None else self._normalise(raw)
        for raw in self.api.list_windows():
            if raw.get("id") == identifier:
                return self._normalise(raw)
        return None

    def read_controls(self, window):
        if self._scoped():
            reader = getattr(self.api, "owned_element_controls", None)
            if not callable(reader):
                raise contract.ContractError("a11y-query")
            records = reader(window.get("id"))
            controls = [record for _, record in records]
        else:
            controls = self.api.controls(window)
        if not isinstance(controls, list) or len(controls) > contract.MAX_CONTROLS:
            raise contract.ContractError("a11y-overrun")
        for control in controls:
            if type(control) is not dict or set(control) != set(contract.WIDGET_FIELDS):
                raise contract.ContractError("a11y-query")
        return controls

    def read_status(self, window, controls, call=None):
        """Optional macOS-only inspect diagnostic; always exactly four bools.

        The proof, binding and AX reads belong to the platform API. This reader
        NEVER raises: any missing or malformed hook answer, and any exception
        a hook still raises, is converted to the fixed all-false object, so the
        optional diagnostic never changes the existing controls snapshot.

        The platform hook receives the explicit per-call ``call`` result only
        when its signature accepts a third argument (``QuartzApi`` does, and
        records its sanitized refusal there); a two-argument hook is called
        exactly as before and still never raises. A hook that raises its own
        sanitized ``a11y-query`` refusal instead of recording it has that
        refusal placed in this call's ``call``, never re-raised.
        """
        for name in ("read_status", "status", "inspect_status"):
            try:
                reader = getattr(self.api, name, None)
            except Exception:
                continue
            if not callable(reader):
                continue
            try:
                if _call_arity(reader):
                    result = reader(window, controls, call)
                else:
                    result = reader(window, controls)
            except Exception as error:
                diagnostic = diagnostic_of(error)
                report = (getattr(call, "report", None)
                          or getattr(call, "record", None))
                if diagnostic is not None and callable(report):
                    report(diagnostic)
                return _empty_status()
            return _status_shape(result)
        return _empty_status()

    def focus_state(self, window=None):
        return self.api.focus_state(window)

    def activate_owned(self, window):
        """Scoped activation: owned process, then its owned AX window focused."""
        activator = getattr(self.api, "activate_owned", None)
        if not callable(activator):
            raise contract.ContractError("focus-lost")
        activator(window)

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
        """Point must lie inside one active display; unknown fails closed.

        Only a successful ``True`` (inside an active display) or a successful
        ``False`` (outside every active display) is a query verdict.  A raised
        error, a non-boolean answer or any other value is an unknown query
        state and refuses ``a11y-query``; it is never reported as a miss.
        """
        try:
            verdict = self.api.point_visible(window, x, y)
        except contract.ContractError:
            raise
        except Exception:
            raise contract.ContractError("a11y-query")
        if verdict is not True and verdict is not False:
            raise contract.ContractError("a11y-query")
        return verdict

    def activate(self, window):
        if self._scoped():
            return self.activate_owned(window)
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
