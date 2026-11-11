"""External XTest driver for synthetic native-window acceptance; no app hooks.

Reads one JSON request from stdin. Values are never echoed. Requires DISPLAY,
libX11 and libXtst. Native controls use their real AT-SPI labels, state and
geometry. Legacy coordinates are relative to the requested real X window.
"""
import ctypes as C
import json
import os
import re
import sys
import time


CONTROL_LABELS = (
    "连接并启用快捷填充", "验证主密码", "验证 Secret Key", "创建新登录并保存 Passkey",
    "取消 / 使用其他验证器", "确认连接（每次敏感操作需批准）",
    "登录：login.locklark.test · passkey-test · passkey-test",
    "登录：login.locklark.test · passkey-other · passkey-other",
    "登录：login.locklark.test · signal-one · signal-one",
    "登录：login.locklark.test · signal-two · signal-two",
    "确认应用这些更新", "取消（不做任何更改）", "取消尚未提交的更新",
    "金库文件", "主密码", "Secret Key", "解锁", "确认连接此扩展",
    "拒绝连接", "批准本次填充", "拒绝本次填充", "立即锁定",
    "批准本次附件操作",
    "批准本次操作", "拒绝本次操作",
    "批准本次字段披露", "拒绝本次字段披露",
    "批准删除 Passkey", "拒绝删除 Passkey",
    "批准填充验证码", "拒绝填充验证码",
    "批准本次敏感字段填充", "拒绝本次敏感字段填充",
    "批准本次跨源银行卡填充", "拒绝本次跨源银行卡填充",
    "新登录标题", "批准保存登录", "拒绝保存登录", "批准更新登录", "拒绝更新登录",
    "快捷搜索", "快捷搜索标题", "搜索活动登录", "关闭快捷搜索",
    "选择登录：Daily OTP login", "选择登录：Daily other login", "选择登录：Daily provider login",
    "搜索标题", "搜索 / 刷新", "新建登录", "登录标题", "新登录用户名", "新登录密码", "保存登录",
    "网站（可选）", "密码长度（22–256）", "生成强密码并保存",
    "重新生成本地密码", "确认生成并替换", "取消重新生成",
    "显示备注", "复制备注", "编辑备注", "备注正文（可见多行）", "保存备注", "取消编辑备注",
    "Notes imported login · active", "Notes imported login · archived", "Notes imported login · trashed",
    "归档条目", "移入回收站", "恢复条目",
    "显示密码", "复制密码", "立即隐藏", "显示验证码", "复制验证码", "隐藏验证码",
    "金库", "安全设置", "归档", "回收站", "全部",
    "Daily generated login · active", "Daily manual login · active",
    "Daily OTP login · active", "Daily other login · active",
    "Daily provider login · active", "停用系统快捷解锁",
    "Daily archived login · archived", "Daily trashed login · trashed",
)

# Exact grammar of the reviewed multi-credential choice labels. The account
# list is closed; the credential hint is eight public Base64URL characters and
# an ellipsis. Labels are still matched by full equality, never by substring.
PASSKEY_CHOICE_LABEL = re.compile(
    r"^(?:登录|保存到)：login\.locklark\.test · login\.locklark\.test · "
    r"(?:passkey-test|passkey-other|signal-one|signal-two) · "
    r"(?:passkey-test|passkey-other|signal-one|signal-two)"
    r"(?: · 凭据 [A-Za-z0-9_-]{8}…)?"
    r"(?:（已有 [0-9]+ 个 Passkey）)?"
    r"(?: · 升级加密格式，旧客户端将拒绝该金库)?$"
)


def control_label_allowed(label):
    return label in CONTROL_LABELS or (
        type(label) is str and PASSKEY_CHOICE_LABEL.fullmatch(label) is not None
    )


FAILURE_CONTEXT = {"action": "setup", "index": -1, "x_codes":[]}
FAILURE_REASONS = {
    "Native accessibility unavailable": "a11y-unavailable",
    "Native accessibility query failed": "a11y-query",
    "Native accessibility tree limit": "a11y-tree-limit",
    "Native accessibility child limit": "a11y-child-limit",
    "Native accessibility window must be unique": "a11y-window-ambiguous",
    "Native acceptance label is not allowlisted": "label-not-allowed",
    "Native acceptance control must be unique": "control-ambiguous",
    "Native acceptance control not ready": "control-ready-timeout",
    "X display unavailable": "x-display",
    "Exact native-window absence request required": "absence-request",
    "Native acceptance X query failed": "x-query",
    "Previous native acceptance window did not close": "window-close-timeout",
    "Native acceptance window must be unique": "window-ambiguous",
    "Native acceptance window unavailable": "window-timeout",
    "Native acceptance window not viewable": "window-viewable-timeout",
    "Native acceptance window attributes unavailable": "window-attributes",
    "Native acceptance window geometry unavailable": "window-geometry",
    "Native acceptance X target unavailable": "x-target",
    "Acceptance input must be ASCII": "input-charset",
    "Acceptance keyboard mapping unavailable": "keyboard-mapping",
    "Acceptance shortcut unavailable": "shortcut-mapping",
    "Native acceptance X input failed": "x-input",
}


class AccessibilityQueryUnavailable(RuntimeError):
    """A read-only AT-SPI query could not inspect the current tree."""


def failure_reason(error):
    # Only compare our literal RuntimeError messages; never format an arbitrary
    # exception, JSON input, command or editable control value.
    if type(error) is AccessibilityQueryUnavailable:
        return "a11y-query"
    if type(error) is RuntimeError and len(error.args) == 1 and type(error.args[0]) is str:
        return FAILURE_REASONS.get(error.args[0], "unexpected")
    return "unexpected"


def safe_click_record(value):
    """Only public labels, geometry, XIDs and input acknowledgement flags."""
    if not isinstance(value, dict):
        return {}
    result = {"label":value.get("label") if control_label_allowed(value.get("label")) else "pointer"}
    for key in ("target",):
        if type(value.get(key)) is str and re.fullmatch(r"0x[0-9a-f]+",value[key]):
            result[key] = value[key]
    for key in ("x","y"):
        if type(value.get(key)) is int:
            result[key] = value[key]
    for phase in ("before","after"):
        state = value.get(phase)
        if not isinstance(state,dict):
            continue
        result[phase] = {key:state[key] for key in ("x","y","button_mask") if type(state.get(key)) is int}
        if type(state.get("focus")) is str and re.fullmatch(r"0x[0-9a-f]+",state["focus"]):
            result[phase]["focus"] = state["focus"]
        result[phase]["pointer_available"] = state.get("pointer_available") is True
    if isinstance(value.get("x_test"),dict):
        result["x_test"] = {key:value["x_test"].get(key) is True for key in ("motion","down","up")}
    return result


def wait_window_viewable(read_map_state, deadline):
    """Observe one already selected XID within the original find deadline."""
    while time.monotonic() < deadline:
        state = read_map_state()
        now = time.monotonic()
        if now >= deadline:
            break
        if state is None:
            raise RuntimeError("Native acceptance window attributes unavailable")
        if state == 2:  # Xlib IsViewable, not merely an existing/unmapped XID.
            return
        remaining = deadline-now
        if remaining > 0:
            time.sleep(min(0.05,remaining))
    raise RuntimeError("Native acceptance window not viewable")


def check_x_target_errors(errors,target):
    if any(code != 3 or resource == target for code,resource in errors):
        raise RuntimeError("Native acceptance X target unavailable")


class NativeControls:
    """Read public OS accessibility metadata only; never read field values."""

    def __init__(self, title, pid=None):
        self.title = title
        self.pid = pid
        self.at = C.CDLL("libatspi.so.0")
        self.gl = C.CDLL("libglib-2.0.so.0")
        self.go = C.CDLL("libgobject-2.0.so.0")
        pointer, error = C.c_void_p, C.POINTER(C.c_void_p)

        class Rect(C.Structure):
            _fields_ = [(field, C.c_int) for field in ("x", "y", "width", "height")]

        self.at.atspi_init.restype = C.c_int
        self.at.atspi_set_timeout.argtypes = [C.c_int, C.c_int]
        self.at.atspi_get_desktop.argtypes = [C.c_int]
        self.at.atspi_get_desktop.restype = pointer
        self.at.atspi_accessible_get_child_count.argtypes = [pointer, error]
        self.at.atspi_accessible_get_child_count.restype = C.c_int
        self.at.atspi_accessible_get_child_at_index.argtypes = [pointer, C.c_int, error]
        self.at.atspi_accessible_get_child_at_index.restype = pointer
        self.at.atspi_accessible_get_process_id.argtypes = [pointer, error]
        self.at.atspi_accessible_get_process_id.restype = C.c_uint
        for method in ("get_name", "get_role_name"):
            function = getattr(self.at, "atspi_accessible_" + method)
            function.argtypes, function.restype = [pointer, error], pointer
        self.at.atspi_accessible_get_state_set.argtypes = [pointer]
        self.at.atspi_accessible_get_state_set.restype = pointer
        self.at.atspi_state_set_contains.argtypes = [pointer, C.c_int]
        self.at.atspi_state_set_contains.restype = C.c_int
        self.at.atspi_accessible_get_component_iface.argtypes = [pointer]
        self.at.atspi_accessible_get_component_iface.restype = pointer
        self.at.atspi_component_get_extents.argtypes = [pointer, C.c_int, error]
        self.at.atspi_component_get_extents.restype = C.POINTER(Rect)
        self.at.atspi_rect_free.argtypes = [C.POINTER(Rect)]
        self.gl.g_free.argtypes = [pointer]
        self.gl.g_error_free.argtypes = [pointer]
        self.gl.g_main_context_iteration.argtypes = [pointer, C.c_int]
        self.gl.g_main_context_iteration.restype = C.c_int
        self.go.g_object_ref.argtypes = [pointer]
        self.go.g_object_ref.restype = pointer
        self.go.g_object_unref.argtypes = [pointer]
        if self.at.atspi_init() != 0:
            raise RuntimeError("Native accessibility unavailable")
        self.at.atspi_set_timeout(300, 1000)
        self.desktop = self.at.atspi_get_desktop(0)

    def checked(self, function, *args):
        error = C.c_void_p()
        result = function(*args, C.byref(error))
        if error:
            self.gl.g_error_free(error)
            raise AccessibilityQueryUnavailable("Native accessibility query failed")
        return result

    def string(self, function, node):
        value = self.checked(function, node)
        if not value:
            return ""
        try:
            return C.string_at(value).decode("utf-8", errors="replace")
        finally:
            self.gl.g_free(value)

    def walk(self, node, visit, depth=0, budget=None):
        budget = [512] if budget is None else budget
        if depth > 12 or budget[0] <= 0:
            error = RuntimeError("Native accessibility tree limit")
            error.native_guard = {"depth":depth, "visited":512-budget[0], "remaining":budget[0]}
            raise error
        budget[0] -= 1
        if visit(node, depth) is False:
            return
        count = self.checked(self.at.atspi_accessible_get_child_count, node)
        # AT-SPI documents exactly -1 as an exception, not a child count.
        # Abort this snapshot; callers may re-observe it within their existing
        # read-only deadline. Never skip the node or return partial controls.
        if count == -1:
            raise AccessibilityQueryUnavailable("Native accessibility query failed")
        if count < 0 or count > 256:
            error = RuntimeError("Native accessibility child limit")
            error.native_guard = {"depth":depth, "visited":512-budget[0], "remaining":budget[0], "children":count}
            raise error
        for index in range(count):
            child = self.checked(self.at.atspi_accessible_get_child_at_index, node, index)
            if not child:
                continue
            try:
                self.walk(child, visit, depth + 1, budget)
            finally:
                self.go.g_object_unref(child)

    def snapshot(self):
        for _ in range(100):
            if not self.gl.g_main_context_iteration(None, 0):
                break
        windows = []

        def window(node, depth):
            if self.string(self.at.atspi_accessible_get_name, node) == self.title and (
                self.pid is None or self.checked(self.at.atspi_accessible_get_process_id, node) == self.pid
            ):
                windows.append(self.go.g_object_ref(node))
                return False
            return depth < 2

        try:
            self.walk(self.desktop, window)
        except BaseException:
            # Window discovery can retain references before a later child
            # query fails. Release those references on every exceptional exit.
            for node in windows:
                self.go.g_object_unref(node)
            raise
        if not windows:
            return {}
        if len(windows) != 1:
            for node in windows:
                self.go.g_object_unref(node)
            raise RuntimeError("Native accessibility window must be unique")
        controls = {}

        def control(node, _depth):
            label = self.string(self.at.atspi_accessible_get_name, node)
            if not control_label_allowed(label):
                return True
            role = self.string(self.at.atspi_accessible_get_role_name, node)
            if role not in ("push button", "button", "text", "password text", "entry"):
                return True
            state = self.at.atspi_accessible_get_state_set(node)
            if not state:
                return True
            try:
                # Public AT-SPI state enum: ENABLED=8, SENSITIVE=24,
                # SHOWING=25, VISIBLE=30. No editable-text/value API is used.
                enabled = all(self.at.atspi_state_set_contains(state, n) for n in (8, 24))
                showing = all(self.at.atspi_state_set_contains(state, n) for n in (25, 30))
            finally:
                self.go.g_object_unref(state)
            component = self.at.atspi_accessible_get_component_iface(node)
            if not component:
                return True
            try:
                rect = self.checked(self.at.atspi_component_get_extents, component, 0)
                if not rect:
                    return True
                try:
                    bounds = {k: getattr(rect.contents, k) for k in ("x", "y", "width", "height")}
                finally:
                    self.at.atspi_rect_free(rect)
            finally:
                self.go.g_object_unref(component)
            controls.setdefault(label, []).append({"enabled": bool(enabled), "showing": bool(showing), **bounds})
            return True

        try:
            self.walk(windows[0], control)
        finally:
            self.go.g_object_unref(windows[0])
        return controls

    def ready(self, label):
        if not control_label_allowed(label):
            raise RuntimeError("Native acceptance label is not allowlisted")
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                controls = self.snapshot().get(label, [])
            except AccessibilityQueryUnavailable:
                # No action has been emitted. Re-observe a transient tree
                # transition only within the existing, unchanged deadline.
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                time.sleep(min(0.05, remaining))
                continue
            if time.monotonic() >= deadline:
                break
            if len(controls) > 1:
                raise RuntimeError("Native acceptance control must be unique")
            if controls:
                control = controls[0]
                if control["enabled"] and control["showing"] and control["width"] > 0 and control["height"] > 0:
                    return control
            remaining = deadline - time.monotonic()
            if remaining > 0:
                time.sleep(min(0.05, remaining))
        raise RuntimeError("Native acceptance control not ready")


def main():
    request = json.load(sys.stdin)
    x = C.CDLL("libX11.so.6")
    xt = C.CDLL("libXtst.so.6")
    pointer, window = C.c_void_p, C.c_ulong

    class XError(C.Structure):
        _fields_ = [
            ("type", C.c_int), ("display", pointer),
            ("resource", C.c_ulong), ("serial", C.c_ulong),
            ("code", C.c_ubyte), ("request", C.c_ubyte), ("minor", C.c_ubyte),
        ]

    class Attributes(C.Structure):
        _fields_ = [(name,C.c_int) for name in ("x","y","width","height","border_width","depth")]+[
            ("visual",pointer),("root",window),("class",C.c_int),("bit_gravity",C.c_int),
            ("win_gravity",C.c_int),("backing_store",C.c_int),("backing_planes",C.c_ulong),
            ("backing_pixel",C.c_ulong),("save_under",C.c_int),("colormap",C.c_ulong),
            ("map_installed",C.c_int),("map_state",C.c_int),("all_event_masks",C.c_long),
            ("your_event_mask",C.c_long),("do_not_propagate_mask",C.c_long),
            ("override_redirect",C.c_int),("screen",pointer)]

    errors = []
    error_handler_type = C.CFUNCTYPE(C.c_int, pointer, C.POINTER(XError))

    @error_handler_type
    def error_handler(_display, event):
        errors.append((event.contents.code, event.contents.resource))
        if event.contents.code not in FAILURE_CONTEXT["x_codes"]:
            FAILURE_CONTEXT["x_codes"].append(int(event.contents.code))
        return 0

    x.XSetErrorHandler.argtypes = [error_handler_type]
    x.XSetErrorHandler(error_handler)
    x.XSync.argtypes = [pointer, C.c_int]
    x.XOpenDisplay.argtypes = [C.c_char_p]
    x.XOpenDisplay.restype = pointer
    x.XDefaultRootWindow.argtypes = [pointer]
    x.XDefaultRootWindow.restype = window
    x.XQueryTree.argtypes = [pointer, window, C.POINTER(window), C.POINTER(window), C.POINTER(C.POINTER(window)), C.POINTER(C.c_uint)]
    x.XFetchName.argtypes = [pointer, window, C.POINTER(C.c_char_p)]
    x.XInternAtom.argtypes = [pointer, C.c_char_p, C.c_int]
    x.XInternAtom.restype = C.c_ulong
    x.XGetWindowProperty.argtypes = [pointer, window, C.c_ulong, C.c_long, C.c_long, C.c_int, C.c_ulong, C.POINTER(C.c_ulong), C.POINTER(C.c_int), C.POINTER(C.c_ulong), C.POINTER(C.c_ulong), C.POINTER(pointer)]
    x.XFree.argtypes = [pointer]
    x.XRaiseWindow.argtypes = [pointer, window]
    x.XSetInputFocus.argtypes = [pointer, window, C.c_int, C.c_ulong]
    x.XGetWindowAttributes.argtypes = [pointer,window,C.POINTER(Attributes)]
    x.XGetWindowAttributes.restype = C.c_int
    x.XGetInputFocus.argtypes = [pointer, C.POINTER(window), C.POINTER(C.c_int)]
    x.XQueryPointer.argtypes = [pointer, window, C.POINTER(window), C.POINTER(window), C.POINTER(C.c_int), C.POINTER(C.c_int), C.POINTER(C.c_int), C.POINTER(C.c_int), C.POINTER(C.c_uint)]
    x.XTranslateCoordinates.argtypes = [pointer, window, window, C.c_int, C.c_int, C.POINTER(C.c_int), C.POINTER(C.c_int), C.POINTER(window)]
    x.XStringToKeysym.argtypes = [C.c_char_p]
    x.XStringToKeysym.restype = C.c_ulong
    x.XKeysymToKeycode.argtypes = [pointer, C.c_ulong]
    x.XKeysymToKeycode.restype = C.c_uint
    x.XKeycodeToKeysym.argtypes = [pointer, C.c_uint, C.c_int]
    x.XKeycodeToKeysym.restype = C.c_ulong
    x.XFlush.argtypes = [pointer]
    x.XCloseDisplay.argtypes = [pointer]
    xt.XTestFakeKeyEvent.argtypes = [pointer, C.c_uint, C.c_int, C.c_ulong]
    xt.XTestFakeMotionEvent.argtypes = [pointer, C.c_int, C.c_int, C.c_int, C.c_ulong]
    xt.XTestFakeButtonEvent.argtypes = [pointer, C.c_uint, C.c_int, C.c_ulong]
    xt.XTestFakeMotionEvent.restype = C.c_int
    xt.XTestFakeButtonEvent.restype = C.c_int
    display = x.XOpenDisplay(os.environ.get("DISPLAY", "").encode())
    if not display:
        raise RuntimeError("X display unavailable")
    root = x.XDefaultRootWindow(display)
    name_atom = x.XInternAtom(display, b"_NET_WM_NAME", 0)
    utf8_atom = x.XInternAtom(display, b"UTF8_STRING", 0)
    pid_atom = x.XInternAtom(display, b"_NET_WM_PID", 0)

    def window_pid(candidate):
        actual, count, remaining = C.c_ulong(), C.c_ulong(), C.c_ulong()
        fmt, data = C.c_int(), pointer()
        status = x.XGetWindowProperty(display,candidate,pid_atom,0,1,0,6,C.byref(actual),C.byref(fmt),C.byref(count),C.byref(remaining),C.byref(data))
        if status != 0 or not data:
            return None
        try:
            if actual.value == 6 and fmt.value == 32 and count.value == 1:
                return C.cast(data,C.POINTER(C.c_ulong))[0]
        finally:
            x.XFree(data)
        return None

    def expected_process(candidate):
        if not request.get("executable"):
            return True
        pid=window_pid(candidate)
        try:
            return pid is not None and os.readlink("/proc/"+str(pid)+"/exe") == os.path.realpath(request["executable"])
        except OSError:
            return False

    def window_title(candidate):
        actual, count, remaining = C.c_ulong(), C.c_ulong(), C.c_ulong()
        fmt, data = C.c_int(), pointer()
        status = x.XGetWindowProperty(display, candidate, name_atom, 0, 1024, 0, utf8_atom, C.byref(actual), C.byref(fmt), C.byref(count), C.byref(remaining), C.byref(data))
        if status == 0 and data:
            try:
                if actual.value == utf8_atom and fmt.value == 8:
                    return C.string_at(data, count.value).decode("utf-8", errors="replace")
            finally:
                x.XFree(data)
        name = C.c_char_p()
        if x.XFetchName(display, candidate, C.byref(name)) and name.value:
            title = name.value.decode("utf-8", errors="replace")
            x.XFree(name)
            return title
        return ""

    def children(parent):
        root_return, parent_return, count = window(), window(), C.c_uint()
        result = C.POINTER(window)()
        if not x.XQueryTree(display, parent, C.byref(root_return), C.byref(parent_return), C.byref(result), C.byref(count)):
            return []
        found = [result[i] for i in range(count.value)]
        if result:
            x.XFree(result)
        return found

    def find(parent, depth=0):
        if depth > 3:
            return []
        matches=[]
        for candidate in children(parent):
            title = window_title(candidate)
            if (request.get("title") == title or (request.get("title_prefix") and title.startswith(request["title_prefix"]))) and expected_process(candidate):
                matches.append(candidate)
            matches.extend(find(candidate, depth+1))
        return matches

    if request.get("wait_absent"):
        if not request.get("title") or not request.get("executable") or request.get("actions"):
            raise RuntimeError("Exact native-window absence request required")
        for _ in range(200):
            if not find(root):
                x.XSync(display, 0)
                if any(code != 3 for code, _resource in errors):
                    raise RuntimeError("Native acceptance X query failed")
                x.XCloseDisplay(display)
                print(json.dumps({"absent": True}))
                return
            time.sleep(0.05)
        raise RuntimeError("Previous native acceptance window did not close")

    target = None
    discovery_deadline = time.monotonic()+5
    while time.monotonic() < discovery_deadline:
        matches=find(root)
        if len(matches)>1:
            raise RuntimeError("Native acceptance window must be unique")
        if matches:
            target=matches[0]
            break
        time.sleep(0.05)
    if not target:
        raise RuntimeError("Native acceptance window unavailable")

    def selected_map_state():
        attributes = Attributes()
        if not x.XGetWindowAttributes(display,target,C.byref(attributes)):
            return None
        return attributes.map_state

    wait_window_viewable(selected_map_state,discovery_deadline)
    # An extension popup owns keyboard focus through its own transient window.
    # Refocusing the browser's main X window closes that popup. The Firefox
    # adapter checks the actual focused input before requesting this mode.
    if request.get("preserve_focus") is not True or not request.get("title_prefix"):
        x.XRaiseWindow(display, target)
        x.XSetInputFocus(display, target, 1, 0)
    px, py, child = C.c_int(), C.c_int(), window()
    if not x.XTranslateCoordinates(display, target, root, 0, 0, C.byref(px), C.byref(py), C.byref(child)):
        raise RuntimeError("Native acceptance window geometry unavailable")
    x.XSync(display, 0)
    # Popup destruction during read-only tree traversal is normal. Other X
    # errors, or destruction of our selected target, must still fail closed.
    check_x_target_errors(errors,target)
    errors.clear()

    def key(code, down):
        xt.XTestFakeKeyEvent(display, code, int(down), 0)

    def named(name):
        return x.XKeysymToKeycode(display, x.XStringToKeysym(name.encode("ascii")))

    def input_state():
        focus, revert = window(), C.c_int()
        x.XGetInputFocus(display,C.byref(focus),C.byref(revert))
        qr,qc,rx,ry,wx,wy,mask = window(),window(),C.c_int(),C.c_int(),C.c_int(),C.c_int(),C.c_uint()
        available = x.XQueryPointer(display,root,C.byref(qr),C.byref(qc),C.byref(rx),C.byref(ry),C.byref(wx),C.byref(wy),C.byref(mask))
        return {"focus":hex(focus.value),"x":rx.value,"y":ry.value,"button_mask":mask.value,"pointer_available":bool(available)}

    clicks = []

    def click(cx,cy,label):
        before = input_state()
        # Preserve the existing single motion/down/up batch and zero duration.
        # These are acknowledgements, not evidence of an App handler result.
        motion = xt.XTestFakeMotionEvent(display,-1,cx,cy,0)
        down = xt.XTestFakeButtonEvent(display,1,1,0)
        up = xt.XTestFakeButtonEvent(display,1,0,0)
        clicks.append({"target":hex(target),"label":label,"x":cx,"y":cy,"before":before,
                       "x_test":{"motion":bool(motion),"down":bool(down),"up":bool(up)}})

    native = None
    if request.get("inspect") or any("click_label" in a or "wait_label" in a for a in request.get("actions", [])):
        native = NativeControls(request["title"],window_pid(target) if request.get("executable") else None)
    for index, action in enumerate(request.get("actions", [])):
        previous_clicks = len(clicks)
        FAILURE_CONTEXT["index"] = index
        FAILURE_CONTEXT["action"] = (
            "label-click" if "click_label" in action else
            "label-wait" if "wait_label" in action else
            "text-entry" if "text" in action else
            "key" if "key" in action else "pointer"
        )
        if "click_label" in action or "wait_label" in action:
            control = native.ready(action.get("click_label", action.get("wait_label")))
            if "click_label" in action:
                click(control["x"] + control["width"] // 2,control["y"] + control["height"] // 2,action["click_label"])
        if "click" in action:
            dx, dy = action["click"]
            click(px.value+dx,py.value+dy,"pointer")
        if "text" in action:
            shift = named("Shift_L")
            for char in action["text"]:
                symbol = ord(char)
                if symbol < 32 or symbol > 126:
                    raise RuntimeError("Acceptance input must be ASCII")
                code = x.XKeysymToKeycode(display, symbol)
                if not code:
                    raise RuntimeError("Acceptance keyboard mapping unavailable")
                shifted = x.XKeycodeToKeysym(display, code, 0) != symbol
                if shifted:
                    key(shift, True)
                key(code, True)
                key(code, False)
                if shifted:
                    key(shift, False)
        if "key" in action:
            parts = action["key"].split("+")
            codes = [named(part) for part in parts]
            if not all(codes):
                raise RuntimeError("Acceptance shortcut unavailable")
            for code in codes:
                key(code, True)
            for code in reversed(codes):
                key(code, False)
        x.XFlush(display)
        time.sleep(0.15)
        x.XSync(display, 0)
        if errors:
            raise RuntimeError("Native acceptance X input failed")
        for emitted in clicks[previous_clicks:]:
            emitted["after"] = input_state()
    result = {"window": target, "x": px.value, "y": py.value,"clicks":[safe_click_record(click) for click in clicks]}
    if request.get("inspect"):
        FAILURE_CONTEXT["action"] = "snapshot"
        snapshot = native.snapshot()
        inspected = set(CONTROL_LABELS)
        inspected.update(label for label in snapshot if control_label_allowed(label))
        result["controls"] = {
            label: {
                "present": len(snapshot.get(label, [])) == 1,
                "enabled": len(snapshot.get(label, [])) == 1 and snapshot[label][0]["enabled"],
                "showing": len(snapshot.get(label, [])) == 1 and snapshot[label][0]["showing"],
            }
            for label in inspected
        }
    print(json.dumps(result))
    x.XCloseDisplay(display)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print("Native acceptance input failed [" + failure_reason(error) +
              " action=" + FAILURE_CONTEXT["action"] +
              " index=" + str(FAILURE_CONTEXT["index"]) + "]"+
              (" x_codes="+",".join(map(str,FAILURE_CONTEXT["x_codes"])) if FAILURE_CONTEXT["x_codes"] else ""), file=sys.stderr)
        sys.exit(1)
