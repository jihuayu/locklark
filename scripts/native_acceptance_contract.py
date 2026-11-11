"""Shared pure-stdlib contract for external native-window acceptance drivers.

One JSON request arrives on stdin; one JSON result is written to stdout. Every
failure is a single fixed-format line on stderr carrying a fixed error code.
Requests are never echoed, control values/field text/clipboard are never read,
and raw exceptions never reach output or argv.

The platform drivers (browser_native_windows.py, browser_native_macos.py) are
ordinary external input agents: they observe public window/accessibility
metadata, then emit ONE physical pointer/keyboard batch through the OS input
queue. They never use product hooks, accessibility value/invoke patterns or
approval injection. A disjoint request form carries no title and no action: it
only asks the adapter to activate ONE exact (pid, executable) process after its
own identity proof, and observes no window and emits no input.

Importing this module must not initialise X11, COM, UIA or AppKit. Only the
existing X11 driver's literal label tuple is imported; that module defines
constants and classes at import time and opens a display only inside main().
"""
import json
import math
import os
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

# The allowlisted synthetic labels are the SAME literal tuple the existing X11
# driver uses. Importing that module does not open a display or load libX11.
from browser_native_x11 import CONTROL_LABELS as X11_CONTROL_LABELS  # noqa: E402

KNOWN_SYNTHETIC_LABELS = tuple(label for label in X11_CONTROL_LABELS if type(label) is str and label)
_LABELS = frozenset(KNOWN_SYNTHETIC_LABELS)

# Public control roles accepted by the existing X11 driver; reused verbatim so
# every platform agrees on what an ordinary input control is.
CONTROL_ROLES = frozenset({"push button", "button", "text", "password text", "entry"})

# Only these five fields may ever be read from a platform widget. Value, text,
# clipboard and invoke accessors are deliberately absent from the protocol.
WIDGET_FIELDS = ("role", "name", "enabled", "visible", "bounds")

PLATFORMS = ("linux", "windows", "macos", "unknown")
ACTIONS = ("setup", "discover", "reference", "label-click", "label-wait",
           "text-entry", "key", "pointer", "snapshot", "absence", "activate")

MAX_REQUEST_BYTES = 65536
MAX_ACTIONS = 64
MAX_TITLE = 512
MAX_EXECUTABLE = 4096
MAX_TEXT = 256
MAX_CHORD_PARTS = 4
MAX_WINDOWS = 512
MAX_CONTROLS = 4096
MAX_OBSERVATIONS = 240
CLICK_LIMIT = 100000
DISCOVER_TIMEOUT = 5.0
CONTROL_TIMEOUT = 10.0
POLL = 0.05

REQUEST_KEYS = frozenset({"title", "title_prefix", "executable", "actions",
                          "inspect", "wait_absent", "preserve_focus"})
ACTION_KEYS = frozenset({"click_label", "wait_label", "click", "text", "key"})
ABSENCE_KEYS = frozenset({"title", "executable", "actions", "wait_absent"})
# Activation-only form: exact {pid, executable} and nothing else. It is disjoint
# from every normal request above and authorises no observation or input.
ACTIVATION_KEYS = frozenset({"activate_pid", "executable"})

# Fixed code -> fixed message. Nothing here is ever formatted with request data.
ERROR_MESSAGES = {
    "a11y-child-limit": "Native accessibility child limit",
    "a11y-overrun": "Native accessibility query overran its budget",
    "a11y-query": "Native accessibility query failed",
    "a11y-tree-limit": "Native accessibility tree limit",
    "a11y-unavailable": "Native accessibility unavailable",
    "absence-invalid": "Exact native-window absence request required",
    "activation-invalid": "Exact native-process activation request required",
    "activation-failed": "Native process activation not proved",
    "activation-unsupported": "Native window activation unsupported",
    "action-invalid": "Native acceptance action invalid",
    "action-unsupported": "Native acceptance action unsupported",
    "capability-unavailable": "Native accessibility permission is not trusted",
    "control-ambiguous": "Native acceptance control must be unique",
    "control-disabled": "Native acceptance control is disabled",
    "control-geometry": "Native acceptance control geometry unavailable",
    "control-hidden": "Native acceptance control is not visible",
    "control-hit": "Native acceptance click target identity not confirmed",
    "control-missing": "Native acceptance control not ready",
    "control-offscreen": "Native acceptance control is off screen",
    "control-overrun": "Native accessibility control budget exceeded",
    "control-ready-timeout": "Native acceptance control not ready",
    "executable-invalid": "Native acceptance executable path invalid",
    "focus-lost": "Native acceptance foreground focus not verified",
    "input-charset": "Acceptance input must be ASCII",
    "input-failed": "Native acceptance input failed",
    "input-unknown": "Native acceptance input outcome unknown",
    "input-unsupported": "Acceptance shortcut unavailable",
    "label-not-allowed": "Native acceptance label is not allowlisted",
    "observe-overrun": "Native acceptance observation budget exceeded",
    "platform-unsupported": "Native acceptance platform unsupported",
    "preserve-focus-lost": "Native acceptance focus was not preserved",
    "preserve-focus-unsupported": "Native acceptance preserve-focus unsupported",
    "process-ambiguous": "Native acceptance process identity ambiguous",
    "process-untrusted": "Native acceptance process identity untrusted",
    "request-duplicate-key": "Native acceptance request key duplicated",
    "request-invalid": "Native acceptance request invalid",
    "request-oversize": "Native acceptance request too large",
    "request-unknown-key": "Native acceptance request key unknown",
    "secure-desktop": "Native acceptance secure desktop cannot be approved",
    "title-invalid": "Native acceptance window title invalid",
    "unexpected": "Native acceptance input failed",
    "window-ambiguous": "Native acceptance window must be unique",
    "window-changed": "Native acceptance window changed",
    "window-geometry": "Native acceptance window geometry unavailable",
    "window-hidden": "Native acceptance window not viewable",
    "window-offscreen": "Native acceptance window is off screen",
    "window-overrun": "Native acceptance window budget exceeded",
    "window-query": "Native window query failed",
    "window-timeout": "Native acceptance window unavailable",
}
ERROR_CODES = frozenset(ERROR_MESSAGES)


class ContractError(RuntimeError):
    """A refusal carrying one fixed code; the message is never formatted."""

    def __init__(self, code, guard=None):
        if code not in ERROR_MESSAGES:
            code = "unexpected"
        super().__init__(ERROR_MESSAGES[code])
        self.code = code
        self.guard = dict(guard) if isinstance(guard, dict) else {}


def code_of(error):
    """Only our own ContractError codes survive; anything else is 'unexpected'."""
    if type(error) is ContractError:
        return error.code
    return "unexpected"


def failure_line(error, action="setup", index=-1, platform="unknown"):
    """Fixed-format refusal line; contains no request value and no exception."""
    action = action if action in ACTIONS else "setup"
    platform = platform if platform in PLATFORMS else "unknown"
    index = index if type(index) is int and 0 <= index < MAX_ACTIONS else -1
    return "Native acceptance input failed [code=%s action=%s index=%d platform=%s]" % (
        code_of(error), action, index, platform)

# ---------------------------------------------------------------- validation --

_PRINTABLE = re.compile(r"^[^\x00-\x1f\x7f]+$")
_LABEL_KEY = re.compile(r"^[A-Za-z0-9_]{1,32}$")


def _plain_text(value, limit):
    if type(value) is not str or not value or len(value) > limit:
        return False
    return bool(_PRINTABLE.match(value))


def _absolute_path(value):
    if not _plain_text(value, MAX_EXECUTABLE):
        return False
    if re.match(r"^[A-Za-z]:[\\/]", value):
        return True
    return value.startswith("/") and "//" not in value


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ContractError("request-duplicate-key")
        result[key] = value
    return result


def _size(value):
    try:
        return len(value)
    except TypeError:
        return 0


def _action(index, value):
    if type(value) is not dict or not value or len(value) > len(ACTION_KEYS):
        raise ContractError("action-invalid", {"index": index, "size": _size(value)})
    if [key for key in value if key not in ACTION_KEYS]:
        raise ContractError("request-unknown-key", {"index": index})
    if ("click_label" in value) + ("wait_label" in value) > 1:
        raise ContractError("action-invalid", {"index": index, "size": _size(value)})
    if ("text" in value) + ("key" in value) > 1:
        raise ContractError("action-invalid", {"index": index, "size": _size(value)})
    action = {}
    if "click_label" in value or "wait_label" in value:
        name = "click_label" if "click_label" in value else "wait_label"
        label = value[name]
        if type(label) is not str or label not in _LABELS:
            raise ContractError("label-not-allowed", {"index": index})
        action[name] = label
    if "text" in value:
        text = value["text"]
        if type(text) is not str or not text or len(text) > MAX_TEXT:
            raise ContractError("action-invalid", {"index": index, "size": 0})
        if any(ord(char) < 32 or ord(char) > 126 for char in text):
            raise ContractError("input-charset", {"index": index})
        action["text"] = text
    if "key" in value:
        raw = value["key"]
        parts = raw.split("+") if type(raw) is str else []
        if not 1 <= len(parts) <= MAX_CHORD_PARTS or not all(_LABEL_KEY.match(part or "") for part in parts):
            raise ContractError("input-unsupported", {"index": index})
        action["key"] = tuple(parts)
    if "click" in value:
        point = value["click"]
        if (type(point) is not list or len(point) != 2 or
                not all(type(item) is int and -CLICK_LIMIT <= item <= CLICK_LIMIT for item in point)):
            raise ContractError("action-invalid", {"index": index, "size": 0})
        action["click"] = (point[0], point[1])
    if not action:
        raise ContractError("action-invalid", {"index": index, "size": 0})
    return action


def _activation_plan(document):
    """Exactly {activate_pid: positive plain int, executable: absolute path}."""
    if set(document) != ACTIVATION_KEYS:
        raise ContractError("activation-invalid")
    pid = document["activate_pid"]
    if type(pid) is not int or pid <= 0:
        raise ContractError("activation-invalid")
    if not _absolute_path(document["executable"]):
        raise ContractError("executable-invalid")
    return {"activation": {"pid": pid, "executable": document["executable"]},
            "title": None, "title_prefix": None, "executable": None, "actions": (),
            "inspect": False, "wait_absent": False, "preserve_focus": False}


def parse_request(raw):
    """Strictly validate one bounded request document; return a normalised plan."""
    if type(raw) is str:
        raw = raw.encode("utf-8", "strict")
    if type(raw) is not bytes:
        raise ContractError("request-invalid")
    if len(raw) > MAX_REQUEST_BYTES:
        raise ContractError("request-oversize", {"bytes": len(raw)})
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
    except ContractError:
        raise
    except Exception:
        raise ContractError("request-invalid")
    if type(document) is not dict:
        raise ContractError("request-invalid")
    if "activate_pid" in document:
        return _activation_plan(document)
    if [key for key in document if key not in REQUEST_KEYS]:
        raise ContractError("request-unknown-key")
    plan = {
        "title": None, "title_prefix": None, "executable": None, "actions": [],
        "inspect": False, "wait_absent": False, "preserve_focus": False,
    }
    for name, limit in (("title", MAX_TITLE), ("title_prefix", MAX_TITLE)):
        if name in document:
            if not _plain_text(document[name], limit):
                raise ContractError("title-invalid", {"field": name})
            plan[name] = document[name]
    if (plan["title"] is None) == (plan["title_prefix"] is None):
        raise ContractError("title-invalid", {"field": "title"})
    if "executable" in document:
        if not _absolute_path(document["executable"]):
            raise ContractError("executable-invalid")
        plan["executable"] = document["executable"]
    for flag in ("inspect", "wait_absent", "preserve_focus"):
        if flag in document:
            if type(document[flag]) is not bool:
                raise ContractError("request-invalid", {"field": flag})
            plan[flag] = document[flag]
    actions = document.get("actions", [])
    if type(actions) is not list or len(actions) > MAX_ACTIONS:
        raise ContractError("action-invalid", {"index": -1, "size": _size(actions)})
    plan["actions"] = tuple(_action(index, value) for index, value in enumerate(actions))
    if plan["wait_absent"]:
        if (set(document) - ABSENCE_KEYS or plan["title"] is None or
                plan["executable"] is None or plan["actions"] or plan["inspect"]):
            raise ContractError("absence-invalid")
    elif plan["preserve_focus"] and plan["title_prefix"] is None:
        raise ContractError("request-invalid", {"field": "preserve_focus"})
    return plan

# --------------------------------------------------------------- observation --

import time  # noqa: E402  (kept late so tests can patch the aliases below)

monotonic = time.monotonic
sleep = time.sleep

ACK_KEYS = ("move", "down", "up")
EVIDENCE_KINDS = ("accepted", "posted")


def evidence_kind(adapter):
    """Only two truthful input claims exist; neither proves product effect.

    ``accepted`` = the Windows input API reported the whole batch queued.
    ``posted`` = macOS created the event objects and the void post call
    returned.  Product effect is verified separately by the real flow.
    """
    kind = getattr(adapter, "input_evidence", None)
    if type(kind) is str and kind in EVIDENCE_KINDS:
        return kind
    raise ContractError("input-unsupported")
PROVISIONAL = frozenset({"control-missing", "control-disabled", "control-hidden"})


class Budget:
    """Hard observation limits; exceeding one refuses before any input."""

    LIMITS = (("windows", MAX_WINDOWS, "window-overrun"),
              ("controls", MAX_CONTROLS, "control-overrun"),
              ("observations", MAX_OBSERVATIONS, "observe-overrun"))

    def __init__(self):
        self.counts = {"windows": 0, "controls": 0, "observations": 0}
        # Distinct (pid, window id) identities observed so far in this request.
        self.identities = set()

    def charge(self, kind, amount=1, code="observe-overrun"):
        self.counts["observations"] += 1
        for name, limit, overrun in self.LIMITS:
            if name == kind:
                self.counts[name] += amount
                if self.counts[name] > limit:
                    raise ContractError(overrun, dict(self.counts))
        if self.counts["observations"] > MAX_OBSERVATIONS:
            raise ContractError("observe-overrun", dict(self.counts))
        del code

    def charge_windows(self, windows):
        """Charge one window snapshot against both hard window limits.

        Each individual snapshot is bounded by MAX_WINDOWS.  Separately, the
        distinct (pid, window id) identities observed across the request are
        bounded by MAX_WINDOWS, but an identity already observed is not
        counted again: fast polling of a stable desktop must not exhaust the
        shared cap before the discovery timeout.  The ``windows`` count is the
        larger of the current snapshot size and the distinct identity total,
        so a genuinely churning set of windows still refuses.
        """
        size = _size(windows)
        if size > MAX_WINDOWS:
            raise ContractError("window-overrun", {"windows": size})
        self.counts["observations"] += 1
        for window in windows:
            pid = window.get("pid") if type(window) is dict else None
            identifier = window.get("id") if type(window) is dict else None
            self.identities.add((pid, identifier))
        self.counts["windows"] = max(size, len(self.identities))
        if self.counts["windows"] > MAX_WINDOWS:
            raise ContractError("window-overrun", dict(self.counts))
        if self.counts["observations"] > MAX_OBSERVATIONS:
            raise ContractError("observe-overrun", dict(self.counts))


def canonical_path(value, platform="linux"):
    if type(value) is not str or not value:
        return ""
    path = value.replace("\\", "/") if platform == "windows" else value
    path = os.path.normpath(path)
    return path.lower() if platform == "windows" else path


def same_executable(requested, observed, platform="linux"):
    left, right = canonical_path(requested, platform), canonical_path(observed, platform)
    if not left or not right:
        return False
    return left == right


def geometry_value(value):
    """The plain int or finite built-in float this coordinate denotes, else None.

    A plain ``int`` is kept as is.  A genuine built-in ``float`` must be finite;
    it is preserved exactly so a fractional macOS (CGFloat) coordinate is never
    truncated into a near match.  The built-in type check is exact: ``bool``,
    every ``int``/``float`` subclass (whose comparison, addition or conversion
    overrides could run later in ``rect_within`` or the click paths), strings
    and non-numeric values are not geometry, and no method on them is called.
    """
    kind = type(value)
    if kind is int:
        return value
    if kind is float:
        return value if math.isfinite(value) else None
    return None


def _geometry(rect):
    """The four geometry values of a rectangle dict, else None."""
    if type(rect) is not dict:
        return None
    return tuple(geometry_value(rect.get(key)) for key in ("x", "y", "width", "height"))


def rect_positive(rect):
    """True only for a rectangle of four plain ints/finite floats with positive extents."""
    values = _geometry(rect)
    if values is None or not all(type(value) in (int, float) for value in values):
        return False
    return values[2] > 0 and values[3] > 0


def integer_rect(rect):
    """The same rectangle as exact plain ``int`` values, else None.

    Used only to hand geometry to APIs that require integers.  Every field must
    be an exact built-in ``int`` or an integral finite built-in ``float``; a
    fractional float is REFUSED (None) and is never truncated into a near match.
    """
    values = _geometry(rect)
    if values is None or not all(type(value) in (int, float) for value in values):
        return None
    if values[2] <= 0 or values[3] <= 0:
        return None
    result = {}
    for key, value in zip(("x", "y", "width", "height"), values):
        if type(value) is float:
            if not value.is_integer():
                return None
            value = int(value)
        result[key] = value
    return result


def rect_within(inner, outer):
    if not rect_positive(inner) or not rect_positive(outer):
        return False
    return (inner["x"] >= outer["x"] and inner["y"] >= outer["y"] and
            inner["x"] + inner["width"] <= outer["x"] + outer["width"] and
            inner["y"] + inner["height"] <= outer["y"] + outer["height"])


def title_matches(plan, window):
    title = window.get("title") if type(window) is dict else None
    if type(title) is not str:
        return False
    if plan["title"] is not None:
        return title == plan["title"]
    return title.startswith(plan["title_prefix"])


def check_window(plan, window, platform="linux"):
    """Validate one observed window against the request and platform truth."""
    if type(window) is not dict:
        raise ContractError("window-timeout")
    if type(window.get("pid")) is not int or window["pid"] <= 0:
        raise ContractError("process-ambiguous")
    if window.get("secure") is True:
        raise ContractError("secure-desktop")
    if window.get("visible") is not True:
        raise ContractError("window-hidden")
    if not rect_positive(window.get("bounds")):
        raise ContractError("window-geometry")
    if window.get("onscreen") is False:
        raise ContractError("window-offscreen")
    if window.get("trusted") is False:
        raise ContractError("process-untrusted")
    if plan["executable"] is not None and not same_executable(plan["executable"], window.get("executable"), platform):
        raise ContractError("process-untrusted")
    return window


def window_candidate(plan, window, platform="linux"):
    """A title match that also belongs to the requested executable, when given."""
    if not title_matches(plan, window):
        return False
    if plan["executable"] is None:
        return True
    return same_executable(plan["executable"], window.get("executable"), platform)


def find_window(plan, adapter, budget):
    """Bounded discovery of exactly one visible, on-screen, canonical window."""
    deadline = monotonic() + DISCOVER_TIMEOUT
    while True:
        windows = adapter.list_windows()
        budget.charge_windows(windows)
        matches = [window for window in windows
                   if window_candidate(plan, window, adapter.platform)]
        if len(matches) > 1:
            raise ContractError("window-ambiguous", {"matches": len(matches)})
        if matches:
            window = check_window(plan, matches[0], adapter.platform)
            if monotonic() > deadline:
                raise ContractError("window-timeout")
            return window
        if monotonic() >= deadline:
            raise ContractError("window-timeout")
        sleep(POLL)


def reobserve_window(plan, adapter, window, budget):
    budget.charge("observations")
    fresh = adapter.read_window(window["id"])
    if type(fresh) is not dict:
        raise ContractError("window-changed")
    check_window(plan, fresh, adapter.platform)
    if fresh["id"] != window["id"] or fresh["pid"] != window["pid"]:
        raise ContractError("window-changed")
    return fresh


def read_controls(adapter, window, budget):
    controls = adapter.read_controls(window)
    budget.charge("controls", _size(controls))
    if type(controls) is not list:
        raise ContractError("a11y-query")
    for control in controls:
        if type(control) is not dict or set(control) - set(WIDGET_FIELDS):
            raise ContractError("a11y-query")
    return controls


def select_control(adapter, window, label, budget):
    """Exactly one enabled, visible, on-window control with an allowlisted label."""
    if label not in _LABELS:
        raise ContractError("label-not-allowed")
    controls = read_controls(adapter, window, budget)
    hits = [c for c in controls if c.get("name") == label and c.get("role") in CONTROL_ROLES]
    if len(hits) > 1:
        raise ContractError("control-ambiguous", {"matches": len(hits)})
    if not hits:
        raise ContractError("control-missing")
    control = hits[0]
    if control.get("enabled") is not True:
        raise ContractError("control-disabled")
    if control.get("visible") is not True:
        raise ContractError("control-hidden")
    rect = control.get("bounds")
    # The authorising rectangle carries only plain ints or finite built-in
    # floats (rect_positive is exact-type), whose values feed the click-point
    # arithmetic and the receipt.
    if not rect_positive(rect):
        raise ContractError("control-geometry")
    frame = window.get("client") if rect_positive(window.get("client")) else window.get("bounds")
    if not rect_within(rect, frame):
        raise ContractError("control-offscreen")
    return rect


def await_control(plan, adapter, window, label, budget):
    """Bounded readiness wait; only absence/disabled/hidden is re-observed."""
    deadline = monotonic() + CONTROL_TIMEOUT
    while True:
        try:
            rect = select_control(adapter, window, label, budget)
        except ContractError as error:
            if error.code not in PROVISIONAL:
                raise
            if monotonic() >= deadline:
                raise ContractError("control-ready-timeout")
            sleep(POLL)
            continue
        if monotonic() > deadline:
            # A snapshot that lands after the deadline can never authorise input.
            raise ContractError("control-ready-timeout")
        return rect


# ------------------------------------------------------------------- focus ----

def focus_matches(adapter, window, budget):
    """Foreground must be the EXACT selected window, never just its process.

    Platforms that can name a foreground window (Windows HWND, macOS bound AX
    window) set ``exact_focus = True`` and must report the same window id as
    the selected top-level window.  A process-level pid match alone never
    authorises input, so a second window of the same process is refused.
    """
    budget.charge("observations")
    exact = getattr(adapter, "exact_focus", False) is True
    state = adapter.focus_state(window) if exact else adapter.focus_state()
    if type(state) is not dict:
        return False
    pid = state.get("pid")
    if type(pid) is not int or pid <= 0 or pid != window["pid"]:
        return False
    if not exact:
        return True
    identifier = state.get("window")
    return type(identifier) is int and identifier > 0 and identifier == window["id"]


def screen_bounds(adapter):
    """Observed virtual-screen rectangle, or None when the adapter has none."""
    reader = getattr(adapter, "screen_bounds", None)
    if reader is None:
        return None
    rect = reader()
    return rect if rect_positive(rect) else None


def check_point(adapter, window, x, y):
    """Refuse any point outside the virtual screen or the selected window."""
    screen = screen_bounds(adapter)
    if screen is not None and not (screen["x"] <= x < screen["x"] + screen["width"] and
                                   screen["y"] <= y < screen["y"] + screen["height"]):
        raise ContractError("control-offscreen")
    frame = window.get("client") if rect_positive(window.get("client")) else window.get("bounds")
    if not rect_positive(frame):
        raise ContractError("window-geometry")
    if not (frame["x"] <= x < frame["x"] + frame["width"] and
            frame["y"] <= y < frame["y"] + frame["height"]):
        raise ContractError("control-offscreen")
    hit = getattr(adapter, "hit_test", None)
    if hit is not None and hit(window, x, y) is not True:
        raise ContractError("control-offscreen")
    visible = getattr(adapter, "point_visible", None)
    if visible is not None and visible(window, x, y) is not True:
        # A hidden display, an unreadable display list or any non-True verdict
        # fails closed: permission to inject is never inferred from silence.
        raise ContractError("control-offscreen")
    return x, y


def confirm_control_hit(adapter, window, label, rect, x, y):
    """Refuse unless the point provably resolves to THIS selected control.

    ``check_point`` only proves the point is inside the selected top-level
    window, so a same-root sibling widget or a transparent overlay drawn above
    the control still passes it.  The adapter's ``hit_test_control`` must
    re-resolve the selected label inside the CURRENT bound window under the
    same role/name rules, compare the current rectangle with the authorising
    one and confirm that the element actually under the point is that control
    or one of its descendants.

    Only the literal ``True`` authorises the click.  An adapter that does not
    implement the hook is refused rather than trusted by omission, and every
    other verdict, exception or changed rectangle fails closed before input.
    """
    probe = getattr(adapter, "hit_test_control", None)
    if probe is None:
        raise ContractError("control-hit")
    try:
        verdict = probe(window, label, dict(rect), x, y)
    except ContractError:
        raise
    except Exception:
        raise ContractError("a11y-query")
    if verdict is not True:
        raise ContractError("control-hit")
    return x, y


def ensure_focus(plan, adapter, window, budget):
    """Single activation attempt, then re-observed foreground verification."""
    if focus_matches(adapter, window, budget):
        return True
    if plan["preserve_focus"]:
        raise ContractError("preserve-focus-lost")
    if getattr(adapter, "supports_activation", False) is not True:
        raise ContractError("activation-unsupported")
    adapter.activate(window)
    if not focus_matches(adapter, window, budget):
        raise ContractError("focus-lost")
    return True


def authorize(plan, adapter, window, budget, label=None):
    """Re-observe window, control rect and foreground immediately before input.

    Every observation is read-only.  Exactly one physical input batch is
    emitted afterwards; no authorisation click is ever retried.
    """
    fresh = reobserve_window(plan, adapter, window, budget)
    rect = select_control(adapter, fresh, label, budget) if label is not None else None
    if not focus_matches(adapter, fresh, budget):
        raise ContractError("focus-lost")
    return fresh, rect


# ------------------------------------------------------------------ results ---

def _window_record(window, plan):
    """Safe window evidence only: no request title, prefix or text."""
    del plan
    identifier = window.get("id")
    if type(identifier) is not int or identifier <= 0:
        raise ContractError("window-changed")
    return {
        "window": hex(identifier),
        "pid": window["pid"],
        "x": window["bounds"]["x"],
        "y": window["bounds"]["y"],
        "width": window["bounds"]["width"],
        "height": window["bounds"]["height"],
    }




def _clicked(rect, x, y):
    """The point as handed to the click call, or None unless it is inside.

    Integer adapters (Windows, X11) only ever produce ints here and keep them.
    A macOS fractional point must be reported exactly as it was passed to
    Quartz, so geometry values are preserved and never int-cast; a point that
    is not a finite number inside the freshly observed rectangle cannot be
    proved to be the one the adapter received and is refused.
    """
    if rect_positive(rect):
        for key, value in (("x", x), ("y", y)):
            if type(value) not in (int, float):
                return None
            inside = rect[key] <= value < rect[key] + rect["width" if key == "x" else "height"]
            if not inside:
                return None
    elif type(x) is not int or type(y) is not int:
        return None
    return x, y


def click_record(window, label, x, y, ack, kind="accepted", rect=None):
    point = _clicked(rect, x, y)
    if point is None:
        raise ContractError("control-hit")
    return {
        "label": label if label in _LABELS else "pointer",
        "window": hex(window["id"]) if type(window.get("id")) is int else "0x0",
        "x": point[0],
        "y": point[1],
        "before": {"focus_matches_target": True},
        "evidence": kind if kind in EVIDENCE_KINDS else "posted",
        "ack": {key: (type(ack) is dict and ack.get(key) is True) for key in ACK_KEYS},
    }


def snapshot(adapter, window, budget):
    controls = read_controls(adapter, window, budget)
    result = {}
    for label in KNOWN_SYNTHETIC_LABELS:
        hits = [c for c in controls if c.get("name") == label and c.get("role") in CONTROL_ROLES]
        result[label] = {
            "present": len(hits) == 1,
            "enabled": len(hits) == 1 and hits[0].get("enabled") is True,
            "showing": len(hits) == 1 and hits[0].get("visible") is True,
        }
    return result


# ----------------------------------------------------------------- absence ----

def await_absent(plan, adapter, budget):
    deadline = monotonic() + CONTROL_TIMEOUT
    while True:
        windows = adapter.list_windows()
        budget.charge_windows(windows)
        if not [w for w in windows
                if title_matches(plan, w) and same_executable(plan["executable"], w.get("executable"), adapter.platform)]:
            return {"absent": True}
        if monotonic() >= deadline:
            raise ContractError("window-changed", {"present": 1})
        sleep(POLL)


# -------------------------------------------------------------- activation ----

# The only result an activation-only request can produce. It claims nothing
# about windows, focus, foreground content or product effect.
ACTIVATION_RESULT = {"activated": True}
FAILURE_CONTEXT = {"action": "setup", "index": -1}


def execute_activation(plan, adapter):
    """One identity-proved NSRunningApplication activation; no observation.

    The adapter's ``activate_process(pid, executable)`` must itself prove the
    exact pid/executable/uid identity and perform exactly one OS activation.
    It returns the literal ``True`` only after that one call reported success.
    Any other verdict, a raised error or a missing hook fails closed; nothing
    is retried, no window is listed and no input is emitted.
    """
    FAILURE_CONTEXT["action"], FAILURE_CONTEXT["index"] = "activate", -1
    request = plan["activation"]
    hook = getattr(adapter, "activate_process", None)
    if hook is None or getattr(adapter, "supports_activation", False) is not True:
        raise ContractError("activation-unsupported")
    try:
        verdict = hook(request["pid"], request["executable"])
    except ContractError:
        raise
    except Exception:
        raise ContractError("activation-failed")
    if verdict is not True:
        raise ContractError("activation-failed")
    return dict(ACTIVATION_RESULT)


# ----------------------------------------------------------------- execute ----

def _center(rect):
    """Exact geometric centre of a validated control rectangle.

    With only integer geometry this is the historical floor centre, unchanged.
    A fractional macOS control bound is centred by true division: neither the
    origin nor the half-extent is floored or truncated, so the point stays the
    actual geometric centre of the control.
    """
    if all(type(rect[key]) is int for key in ("x", "y", "width", "height")):
        return rect["x"] + rect["width"] // 2, rect["y"] + rect["height"] // 2
    return rect["x"] + rect["width"] / 2, rect["y"] + rect["height"] / 2


def _offset_click(fresh, point):
    frame = fresh.get("client") if rect_positive(fresh.get("client")) else fresh["bounds"]
    x, y = frame["x"] + point[0], frame["y"] + point[1]
    if not (frame["x"] <= x < frame["x"] + frame["width"] and
            frame["y"] <= y < frame["y"] + frame["height"]):
        raise ContractError("control-offscreen")
    return x, y


def execute(plan, adapter):
    """Run one validated plan against a platform adapter and return safe JSON."""
    budget = Budget()
    check = getattr(adapter, "check_capability", None)
    if plan.get("activation") is not None:
        # Activation-only: no capability prompt and no accessibility query.
        return execute_activation(plan, adapter)
    if check is not None:
        check()
    if plan["wait_absent"]:
        FAILURE_CONTEXT["action"] = "absence"
        return await_absent(plan, adapter, budget)
    FAILURE_CONTEXT["action"] = "discover"
    window = find_window(plan, adapter, budget)
    clicks = []
    for index, action in enumerate(plan["actions"]):
        FAILURE_CONTEXT["index"] = index
        FAILURE_CONTEXT["action"] = (
            "label-click" if "click_label" in action else
            "label-wait" if "wait_label" in action else
            "text-entry" if "text" in action else
            "key" if "key" in action else "pointer")
        if "click_label" in action:
            ensure_focus(plan, adapter, window, budget)
            fresh, rect = authorize(plan, adapter, window, budget, action["click_label"])
            x, y = check_point(adapter, fresh, *_center(rect))
            # The window-root hit test above cannot see a sibling or
            # transparent overlay: re-prove that the point resolves to the
            # uniquely selected control itself before the single click.
            confirm_control_hit(adapter, fresh, action["click_label"], rect, x, y)
            kind = evidence_kind(adapter)
            ack = adapter.click(x, y)  # exactly one physical batch
            clicks.append(click_record(fresh, action["click_label"], x, y,
                                       ack, kind, rect))
            window = fresh
        elif "click" in action:
            ensure_focus(plan, adapter, window, budget)
            fresh, _ = authorize(plan, adapter, window, budget)
            point = _offset_click(fresh, action["click"])
            x, y = check_point(adapter, fresh, point[0], point[1])
            frame = fresh.get("client") if rect_positive(fresh.get("client")) else fresh["bounds"]
            kind = evidence_kind(adapter)
            ack = adapter.click(x, y)
            clicks.append(click_record(fresh, "pointer", x, y, ack, kind, frame))
            window = fresh
        elif "wait_label" in action:
            await_control(plan, adapter, window, action["wait_label"], budget)
        elif "text" in action or "key" in action:
            ensure_focus(plan, adapter, window, budget)
            fresh, _ = authorize(plan, adapter, window, budget)
            if "text" in action:
                adapter.type_text(action["text"])
            else:
                adapter.press_chord(action["key"])
            window = fresh
        else:
            raise ContractError("action-invalid", {"index": index})
    result = _window_record(window, plan)
    result["clicks"] = clicks
    if plan["inspect"]:
        FAILURE_CONTEXT["action"] = "snapshot"
        result["controls"] = snapshot(adapter, window, budget)
    return result


def run_stdin(adapter, platform, stdin=None, stdout=None, stderr=None):
    """Read one request, execute it, and emit either safe JSON or one fixed line."""
    stdin = sys.stdin.buffer if stdin is None else stdin
    stdout = sys.stdout if stdout is None else stdout
    stderr = sys.stderr if stderr is None else stderr
    FAILURE_CONTEXT["action"], FAILURE_CONTEXT["index"] = "setup", -1
    try:
        result = execute(parse_request(stdin.read(MAX_REQUEST_BYTES + 1)), adapter)
    except ContractError as error:
        stderr.write(failure_line(error, FAILURE_CONTEXT["action"],
                                  FAILURE_CONTEXT["index"], platform) + "\n")
        return 1
    except Exception:
        stderr.write(failure_line(ContractError("unexpected"), FAILURE_CONTEXT["action"],
                                  FAILURE_CONTEXT["index"], platform) + "\n")
        return 1
    stdout.write(json.dumps(result) + "\n")
    return 0
