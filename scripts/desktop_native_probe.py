"""Narrow external display/clipboard observer for disposable desktop acceptance.

Only the two explicitly authorized display labels may expose text internally.
No editable field, seed, window dump, or observed value is returned. Clipboard
uses the caller's isolated X display; this process also models a later owner.
All communication is a private pipe and errors use fixed classifications.
"""
import ctypes as C
import json
import os
import select
import stat
import sys
import time

from browser_native_x11 import AccessibilityQueryUnavailable, NativeControls, failure_reason as native_failure_reason


DISPLAY_LABELS = ("已授权显示的字段", "已授权显示的验证码")
PROBE_REASONS = frozenset((
    "display-request", "display-group-required", "display-static-text-required",
    "display-text-interface", "display-single-text-required", "display-window",
    "display-ambiguous", "display-process", "probe-operation", "a11y-query", "unexpected",
    "clipboard-response-timeout", "clipboard-response-invalid",
    "a11y-tree-limit", "a11y-child-limit", "a11y-window-ambiguous",
))
ERROR_CLASSES = {
    RuntimeError:"runtime", TypeError:"type", ValueError:"value", KeyError:"key",
    AttributeError:"attribute", OverflowError:"overflow", OSError:"os",
    UnicodeDecodeError:"unicode", C.ArgumentError:"ffi-argument",
    AccessibilityQueryUnavailable:"a11y-query",
}
TRACE_FUNCTIONS = {
    "probe":frozenset(("main", "inspect_display", "inspect_display_once", "window", "field", "read_group", "authorized_text", "received", "compare", "pump", "__init__")),
    "native":frozenset(("checked", "string", "walk", "__init__")),
}


def safe_diagnostic(value):
    if not isinstance(value, dict):
        return {}
    result = {"error_class":value.get("error_class") if value.get("error_class") in ERROR_CLASSES.values() else "unexpected"}
    result["locations"] = []
    for location in value.get("locations", [])[:8] if isinstance(value.get("locations"), list) else []:
        if not isinstance(location, dict):
            continue
        function, line = location.get("function"), location.get("line")
        if (type(function) is str and function in {module+"."+name for module, names in TRACE_FUNCTIONS.items() for name in names}
                and type(line) is int and 1 <= line <= 10000):
            result["locations"].append({"function":function, "line":line})
    if isinstance(value.get("guard"), dict):
        result["guard"] = {key:count for key,count in value["guard"].items()
                           if key in ("depth", "visited", "remaining", "children") and type(count) is int and -(2**31) <= count < 2**31}
    return result


def error_diagnostic(error):
    # Only fixed class/function aliases and numeric locations/counts. Never
    # inspect args, format an exception, retain locals, or return source paths.
    value = {"error_class":ERROR_CLASSES.get(type(error), "unexpected"), "locations":[]}
    trace = error.__traceback__
    source_root = os.path.dirname(os.path.abspath(__file__))
    files = {os.path.join(source_root,"desktop_native_probe.py"):"probe", os.path.join(source_root,"browser_native_x11.py"):"native"}
    while trace is not None:
        code = trace.tb_frame.f_code
        module = files.get(os.path.abspath(code.co_filename))
        if module and code.co_name in TRACE_FUNCTIONS[module]:
            value["locations"].append({"function":module+"."+code.co_name, "line":trace.tb_lineno})
        trace = trace.tb_next
    value["locations"] = value["locations"][-8:]
    if type(error) is RuntimeError and isinstance(getattr(error,"native_guard",None), dict):
        value["guard"] = error.native_guard
    return safe_diagnostic(value)


def failure_reason(error):
    if type(error) is AccessibilityQueryUnavailable:
        return "a11y-query"
    if type(error) is RuntimeError and len(error.args) == 1 and type(error.args[0]) is str:
        if error.args[0] in PROBE_REASONS:
            return error.args[0]
        reason = native_failure_reason(error)
        if reason in ("a11y-tree-limit", "a11y-child-limit", "a11y-window-ambiguous"):
            return reason
    return "unexpected"


class DisplayReader(NativeControls):
    def __init__(self, pid):
        super().__init__("Locklark · 本地金库", pid)
        pointer, error = C.c_void_p, C.POINTER(C.c_void_p)
        self.at.atspi_accessible_get_text_iface.argtypes = [pointer]
        self.at.atspi_accessible_get_text_iface.restype = pointer
        self.at.atspi_text_get_text.argtypes = [pointer, C.c_int, C.c_int, error]
        self.at.atspi_text_get_text.restype = pointer

    def inspect_display(self, label, expected):
        # This is observation only. Never repeat a product action, prepare a
        # new value, extend a lease, or retry a structural/authorization error.
        deadline = time.monotonic() + 0.5
        attempts = 0
        while True:
            attempts += 1
            try:
                result = self.inspect_display_once(label, expected)
                return {**result, "read_attempts": attempts}
            except AccessibilityQueryUnavailable:
                now = time.monotonic()
                if now >= deadline:
                    raise
                time.sleep(min(0.02, deadline - now))
                if time.monotonic() >= deadline:
                    raise

    def inspect_display_once(self, label, expected):
        if label not in DISPLAY_LABELS or not isinstance(expected, list):
            raise RuntimeError("display-request")
        for _ in range(100):
            if not self.gl.g_main_context_iteration(None, 0):
                break
        windows = []
        groups = []

        def window(node, depth):
            if (self.string(self.at.atspi_accessible_get_name, node) == self.title
                    and self.checked(self.at.atspi_accessible_get_process_id, node) == self.pid):
                windows.append(self.go.g_object_ref(node))
                return False
            return depth < 2

        def field(node, _depth):
            if self.string(self.at.atspi_accessible_get_name, node) != label:
                return True
            groups.append(self.go.g_object_ref(node))
            return False

        def read_group(node):
            role = self.string(self.at.atspi_accessible_get_role_name, node)
            if role not in ("panel", "grouping", "group"):
                raise RuntimeError("display-group-required")
            texts = []

            def authorized_text(child, depth):
                if depth == 0:
                    return True
                role = self.string(self.at.atspi_accessible_get_role_name, child)
                if role != "label":
                    # Never enter an editable control, password field or an
                    # unrelated nested widget, even within this public group.
                    raise RuntimeError("display-static-text-required")
                interface = self.at.atspi_accessible_get_text_iface(child)
                if not interface:
                    raise RuntimeError("display-text-interface")
                try:
                    value = self.checked(self.at.atspi_text_get_text, interface, 0, -1)
                    try:
                        texts.append(C.string_at(value).decode("utf-8") if value else "")
                    finally:
                        if value:
                            self.gl.g_free(value)
                finally:
                    self.go.g_object_unref(interface)
                return False

            self.walk(node, authorized_text)
            if len(texts) != 1:
                raise RuntimeError("display-single-text-required")
            return {"present": True, "empty": texts[0] == "", "matches": [texts[0] == item for item in expected]}

        try:
            self.walk(self.desktop, window)
            if len(windows) != 1:
                raise RuntimeError("display-window")
            self.walk(windows[0], field)
            if len(groups) > 1:
                raise RuntimeError("display-ambiguous")
            if groups:
                return read_group(groups[0])
            return {"present": False, "empty": True, "matches": [False for _ in expected]}
        finally:
            for node in groups:
                self.go.g_object_unref(node)
            for node in windows:
                self.go.g_object_unref(node)


class Clipboard:
    text_received_type = C.CFUNCTYPE(None, C.c_void_p, C.c_void_p, C.c_void_p)

    def __init__(self):
        self.gtk = C.CDLL("libgtk-3.so.0")
        self.gdk = C.CDLL("libgdk-3.so.0")
        self.gl = C.CDLL("libglib-2.0.so.0")
        pointer = C.c_void_p
        self.gtk.gtk_init_check.argtypes = [pointer, pointer]
        self.gtk.gtk_init_check.restype = C.c_int
        self.gdk.gdk_atom_intern_static_string.argtypes = [C.c_char_p]
        self.gdk.gdk_atom_intern_static_string.restype = pointer
        self.gtk.gtk_clipboard_get.argtypes = [pointer]
        self.gtk.gtk_clipboard_get.restype = pointer
        self.gtk.gtk_clipboard_request_text.argtypes = [pointer, self.text_received_type, pointer]
        self.gtk.gtk_clipboard_set_text.argtypes = [pointer, C.c_char_p, C.c_int]
        self.gtk.gtk_clipboard_clear.argtypes = [pointer]
        self.gtk.gtk_events_pending.restype = C.c_int
        self.gtk.gtk_main_iteration_do.argtypes = [C.c_int]
        self.gl.g_free.argtypes = [pointer]
        if not self.gtk.gtk_init_check(None, None):
            raise RuntimeError("clipboard-display")
        self.clipboard = self.gtk.gtk_clipboard_get(self.gdk.gdk_atom_intern_static_string(b"CLIPBOARD"))
        self.sequence = 0
        self.pending = {}
        # GTK may invoke a callback after an operation times out. Keep this C
        # function pointer alive for the entire worker. user_data is a unique
        # integer token, never a borrowed pointer to a stack/Python object.
        self.text_received = self.text_received_type(self.received)

    def pump(self):
        for _ in range(100):
            if not self.gtk.gtk_events_pending():
                break
            self.gtk.gtk_main_iteration_do(0)

    def compare(self, expected):
        self.sequence += 1
        token = self.sequence
        request = {"expected": expected, "deadline": time.monotonic() + 1, "result": None}
        self.pending[token] = request
        try:
            self.gtk.gtk_clipboard_request_text(self.clipboard, self.text_received, token)
            while request["result"] is None:
                self.pump()
                if time.monotonic() >= request["deadline"]:
                    raise RuntimeError("clipboard-response-timeout")
                if request["result"] is None:
                    time.sleep(0.005)
            result = request["result"]
            if "error" in result:
                raise RuntimeError(result["error"])
            return result
        finally:
            # A late callback finds no active token and does not read its
            # text pointer, respond to a later command, or expose any value.
            del self.pending[token]

    def received(self, _clipboard, text, user_data):
        token = int(user_data or 0)
        request = self.pending.get(token)
        if request is None:
            return
        try:
            if time.monotonic() >= request["deadline"]:
                request["result"] = {"error": "clipboard-response-timeout"}
                return
            # GTK owns this NUL-terminated text only during this callback.
            # Compute booleans privately and never retain or return the text.
            value = C.string_at(text).decode("utf-8") if text else ""
            request["result"] = {"empty": value == "", "matches": [value == item for item in request["expected"]]}
        except Exception:
            # A Python exception escaping a ctypes callback would print its
            # message. Invalid data receives a fixed failure instead.
            request["result"] = {"error": "clipboard-response-invalid"}


def main():
    if not stat.S_ISFIFO(os.fstat(sys.stdout.fileno()).st_mode):
        raise RuntimeError("private-pipe")
    clipboard, display = Clipboard(), None
    print('{"ready":true}', flush=True)
    while True:
        clipboard.pump()
        if not select.select([sys.stdin], [], [], 0.02)[0]:
            continue
        line = sys.stdin.readline()
        if not line:
            return
        try:
            request = json.loads(line)
            if request.get("op") == "clipboard":
                result = clipboard.compare(request.get("expected", []))
            elif request.get("op") == "own-clipboard":
                value = request["marker"].encode("utf-8")
                clipboard.gtk.gtk_clipboard_set_text(clipboard.clipboard, value, len(value))
                result = {"owned": True}
            elif request.get("op") == "display":
                pid = request["pid"]
                if (not isinstance(pid, int) or pid <= 0
                        or os.readlink("/proc/" + str(pid) + "/exe") != os.path.realpath(request["executable"])):
                    raise RuntimeError("display-process")
                if display is None or display.pid != pid:
                    display = DisplayReader(pid)
                result = display.inspect_display(request["label"], request.get("expected", []))
            else:
                raise RuntimeError("probe-operation")
            print(json.dumps({"ok": True, **result}), flush=True)
        except Exception as error:
            # No exception or command body can reach stdout/stderr.
            print(json.dumps({"ok":False, "reason":failure_reason(error), "diagnostic":error_diagnostic(error)}), flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("Desktop external probe unavailable", file=sys.stderr)
        sys.exit(1)
