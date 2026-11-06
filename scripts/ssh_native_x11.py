"""Owned XTest/AT-SPI SSH acceptance driver; no product API or approval hook.

Normal control input delegates to the existing XTest driver. The two observer
operations read only explicit public SSH metadata or an explicitly copied
canonical public key/endpoint, and return them solely through a private pipe.
"""
import ctypes as C
import json
import os
import re
import stat
import sys
import time

import browser_native_x11 as native
from desktop_native_probe import Clipboard

LABELS = (
    "SSH 密钥", "SSH 密钥标题", "生成 Ed25519 密钥", "选择未加密 OpenSSH 私钥…",
    "确认导入未加密 Ed25519 私钥", "刷新 SSH 密钥", "复制 SSH 公钥", "开启本地 SSH agent",
    "复制 SSH_AUTH_SOCK 端点", "停止本地 SSH agent", "仅批准本次 SSH 签名", "拒绝本次 SSH 签名",
    "停止 agent 并拒绝本次", "活动 SSH 密钥", "已归档 SSH 密钥", "SSH 回收站", "全部 SSH 密钥",
    "归档 SSH 密钥", "取消归档 SSH 密钥", "将 SSH 密钥移入回收站", "恢复 SSH 密钥",
    "选择 SSH 密钥：Owned generated SSH", "选择 SSH 密钥：Owned imported SSH",
    "打开", "打开(_O)", "Open", "取消", "Cancel", "选择", "Select",
)
native.CONTROL_LABELS = (*native.CONTROL_LABELS, *LABELS)
PUBLIC_PREFIXES = ("本机来源：", "密钥：", "密钥 ID：", "精确修订：", "公钥指纹：", "算法：",
                   "签名数据：", "载荷 SHA256：", "请求 ID：", "连接 ID：", "批准期限：")
SAFE_TARGET = "none"


class PickerWindowQueryUnavailable(RuntimeError):
    pass


def failure_diagnostic(error):
    context = native.FAILURE_CONTEXT
    action = context.get("action")
    index = context.get("index")
    result = {"target": SAFE_TARGET if SAFE_TARGET in ("app", "picker", "none") else "none",
              "action": action if action in ("setup", "label-click", "label-wait", "text-entry", "key", "pointer", "snapshot") else "unknown",
              "index": index if type(index) is int and -1 <= index <= 100 else -1, "guard": {}}
    guard = getattr(error, "native_guard", None) if type(error) is RuntimeError else None
    if type(guard) is dict:
        result["guard"] = {key: value for key, value in guard.items() if key in ("depth", "visited", "remaining", "children")
                           and type(value) is int and -(2**31) <= value < 2**31}
    return result


class PublicClipboard(Clipboard):
    def received(self, _clipboard, text, user_data):
        request = self.pending.get(int(user_data or 0))
        if request is None:
            return
        try:
            if time.monotonic() >= request["deadline"]:
                request["result"] = {"error": "clipboard-response-timeout"}
                return
            value = C.string_at(text).decode("ascii") if text else ""
            if not (re.fullmatch(r"ssh-ed25519 [A-Za-z0-9+/]{68}={0,2}\n?", value)
                    or re.fullmatch(r"/[A-Za-z0-9_./-]{1,180}/agent\.sock", value)):
                request["result"] = {"error": "clipboard-response-invalid"}
                return
            request["result"] = {"value": value}
        except Exception:
            request["result"] = {"error": "clipboard-response-invalid"}


def approval(request, reader=None):
    pid = request["pid"]
    if (type(pid) is not int or pid <= 0
            or os.readlink("/proc/" + str(pid) + "/exe") != os.path.realpath(request["executable"])):
        raise RuntimeError()
    reader = reader or native.NativeControls(request["title"], pid)
    for _ in range(100):
        if not reader.gl.g_main_context_iteration(None, 0):
            break
    windows, values = [], []

    def window(node, depth):
        if (reader.string(reader.at.atspi_accessible_get_name, node) == reader.title
                and reader.checked(reader.at.atspi_accessible_get_process_id, node) == pid):
            windows.append(reader.go.g_object_ref(node))
            return False
        return depth < 2

    def label(node, _depth):
        # Never call a text/value interface or enter an editable control.
        role = reader.string(reader.at.atspi_accessible_get_role_name, node)
        if role in ("text", "password text", "entry"):
            return False
        if role == "label":
            value = reader.string(reader.at.atspi_accessible_get_name, node)
            if value in ("批准本次 SSH 签名？", "目的地未验证") or value.startswith(PUBLIC_PREFIXES):
                if len(value) > 2048:
                    raise RuntimeError()
                values.append(value)
        return True

    try:
        reader.walk(reader.desktop, window)
        if len(windows) != 1:
            raise RuntimeError()
        reader.walk(windows[0], label)
        return {"values": values}
    finally:
        for node in windows:
            reader.go.g_object_unref(node)


def picker_observation(request):
    """Inspect the stable location entry before submitting it once."""
    return picker_observation_once(request)


def picker_window_present(request):
    """Read only X11 window identity; never walk a closing AT-SPI tree."""
    if (request.get("title") != "选择未加密 OpenSSH Ed25519 私钥" or type(request.get("pid")) is not int
            or request["pid"] <= 0 or os.readlink("/proc/" + str(request["pid"]) + "/exe") != os.path.realpath(request["executable"])):
        raise RuntimeError()
    x = C.CDLL("libX11.so.6")
    pointer, window = C.c_void_p, C.c_ulong
    class XError(C.Structure):
        _fields_ = [("type", C.c_int), ("display", pointer), ("resource", C.c_ulong), ("serial", C.c_ulong),
                    ("code", C.c_ubyte), ("request", C.c_ubyte), ("minor", C.c_ubyte)]
    handler_type = C.CFUNCTYPE(C.c_int, pointer, C.POINTER(XError))
    errors = []
    @handler_type
    def error_handler(_display, event):
        errors.append(int(event.contents.code))
        return 0
    x.XSetErrorHandler.argtypes, x.XSetErrorHandler.restype = [pointer], pointer
    previous = x.XSetErrorHandler(C.cast(error_handler, pointer))
    x.XOpenDisplay.argtypes, x.XOpenDisplay.restype = [C.c_char_p], pointer
    x.XCloseDisplay.argtypes = [pointer]
    x.XDefaultRootWindow.argtypes, x.XDefaultRootWindow.restype = [pointer], window
    x.XInternAtom.argtypes, x.XInternAtom.restype = [pointer, C.c_char_p, C.c_int], C.c_ulong
    x.XQueryTree.argtypes = [pointer, window, C.POINTER(window), C.POINTER(window), C.POINTER(C.POINTER(window)), C.POINTER(C.c_uint)]
    x.XGetWindowProperty.argtypes = [pointer, window, C.c_ulong, C.c_long, C.c_long, C.c_int, C.c_ulong,
                                   C.POINTER(C.c_ulong), C.POINTER(C.c_int), C.POINTER(C.c_ulong), C.POINTER(C.c_ulong), C.POINTER(pointer)]
    x.XFree.argtypes, x.XSync.argtypes = [pointer], [pointer, C.c_int]
    display = None
    try:
        display = x.XOpenDisplay(os.environ.get("DISPLAY", "").encode())
        if not display:
            raise PickerWindowQueryUnavailable()
        pid_atom = x.XInternAtom(display, b"_NET_WM_PID", 0)
        name_atom = x.XInternAtom(display, b"_NET_WM_NAME", 0)
        utf8_atom = x.XInternAtom(display, b"UTF8_STRING", 0)
        def property_value(candidate, atom, kind):
            actual, count, remaining, fmt, data = C.c_ulong(), C.c_ulong(), C.c_ulong(), C.c_int(), pointer()
            status = x.XGetWindowProperty(display, candidate, atom, 0, 512, 0, kind, C.byref(actual), C.byref(fmt),
                                          C.byref(count), C.byref(remaining), C.byref(data))
            try:
                if status != 0:
                    raise PickerWindowQueryUnavailable()
                if not data or actual.value != kind:
                    return None
                if kind == 6 and fmt.value == 32 and count.value == 1:
                    return C.cast(data, C.POINTER(C.c_ulong))[0]
                if kind == utf8_atom and fmt.value == 8 and remaining.value == 0:
                    return C.string_at(data, count.value).decode("utf-8")
                return None
            finally:
                if data:
                    x.XFree(data)
        matches, visited = [], [0]
        def walk(parent, depth):
            if depth > 3:
                return
            root_out, parent_out, children, count = window(), window(), C.POINTER(window)(), C.c_uint()
            if not x.XQueryTree(display, parent, C.byref(root_out), C.byref(parent_out), C.byref(children), C.byref(count)):
                raise PickerWindowQueryUnavailable()
            try:
                if visited[0] + count.value > 4096:
                    raise RuntimeError("Native acceptance X query failed")
                candidates = [children[index] for index in range(count.value)]
            finally:
                if children:
                    x.XFree(children)
            visited[0] += len(candidates)
            for candidate in candidates:
                if property_value(candidate, pid_atom, 6) == request["pid"]:
                    if property_value(candidate, name_atom, utf8_atom) == request["title"]:
                        matches.append(candidate)
                walk(candidate, depth + 1)
        walk(x.XDefaultRootWindow(display), 0)
        x.XSync(display, 0)
        if errors:
            raise PickerWindowQueryUnavailable()
        if len(matches) > 1:
            raise RuntimeError("Native acceptance window must be unique")
        if os.readlink("/proc/" + str(request["pid"]) + "/exe") != os.path.realpath(request["executable"]):
            raise RuntimeError()
        return bool(matches)
    finally:
        if display:
            x.XCloseDisplay(display)
        x.XSetErrorHandler(previous)


def wait_picker_closed(request):
    deadline = request.get("observation_deadline")
    if type(deadline) not in (int, float) or not time.monotonic() < deadline <= time.monotonic() + 10:
        raise RuntimeError()
    while True:
        try:
            present = picker_window_present(request)
        except PickerWindowQueryUnavailable:
            present = None  # An unsuccessful query is never evidence of absence.
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError("Previous native acceptance window did not close")
        if present is False:
            return {"absent": True}
        time.sleep(min(0.02, remaining))


def picker_reader(request):
    if request.get("title") != "选择未加密 OpenSSH Ed25519 私钥":
        raise RuntimeError()
    reader = native.NativeControls(request["title"], request["pid"])
    if os.readlink("/proc/" + str(request["pid"]) + "/exe") != os.path.realpath(request["executable"]):
        raise RuntimeError()
    reader.at.atspi_accessible_get_text_iface.argtypes = [C.c_void_p]
    reader.at.atspi_accessible_get_text_iface.restype = C.c_void_p
    reader.at.atspi_text_get_text.argtypes = [C.c_void_p, C.c_int, C.c_int, C.POINTER(C.c_void_p)]
    reader.at.atspi_text_get_text.restype = C.c_void_p
    return reader


def picker_observation_once(request, reader=None):
    reader = reader or picker_reader(request)
    for _ in range(100):
        if not reader.gl.g_main_context_iteration(None, 0):
            break
    windows, counts = [], {"present": False, "path_match": 0, "entries": 0}

    def find(node, depth):
        if (reader.string(reader.at.atspi_accessible_get_name, node) == reader.title
                and reader.checked(reader.at.atspi_accessible_get_process_id, node) == request["pid"]):
            windows.append(reader.go.g_object_ref(node))
            return False
        return depth < 2

    def observe(node, _depth):
        role = reader.string(reader.at.atspi_accessible_get_role_name, node)
        if role in ("text", "entry"):
            counts["entries"] += 1
            interface = reader.at.atspi_accessible_get_text_iface(node)
            if interface:
                try:
                    value = reader.checked(reader.at.atspi_text_get_text, interface, 0, -1)
                    try:
                        counts["path_match"] += bool(value) and C.string_at(value).decode() == request["expected_path"]
                    finally:
                        if value:
                            reader.gl.g_free(value)
                finally:
                    reader.go.g_object_unref(interface)
            return False
        return True
    try:
        reader.walk(reader.desktop, find)
        if not windows:
            return counts
        if len(windows) != 1:
            raise RuntimeError()
        counts["present"] = True
        reader.walk(windows[0], observe)
        return counts
    finally:
        for node in windows:
            reader.go.g_object_unref(node)


def approval_observer():
    """One warm read-only AT-SPI connection; input protocol has no actions."""
    global SAFE_TARGET
    if not stat.S_ISFIFO(os.fstat(sys.stdout.fileno()).st_mode):
        raise RuntimeError()
    line = sys.stdin.readline(4097)
    if len(line) > 4096:
        raise RuntimeError()
    request = json.loads(line)
    if (set(request) != {"title", "pid", "executable"} or request["title"] != "Locklark · 本地金库"
            or type(request["pid"]) is not int or request["pid"] <= 0
            or os.readlink("/proc/" + str(request["pid"]) + "/exe") != os.path.realpath(request["executable"])):
        raise RuntimeError()
    SAFE_TARGET = "app"
    reader = native.NativeControls(request["title"], request["pid"])
    print('{"ready":true}', flush=True)
    while True:
        line = sys.stdin.readline(129)
        if not line:
            return
        if line != "observe\n":
            raise RuntimeError()
        native.FAILURE_CONTEXT.update(action="snapshot", index=-1)
        print(json.dumps({"present": bool(approval(request, reader)["values"])}), flush=True)


def main():
    global SAFE_TARGET
    if not stat.S_ISFIFO(os.fstat(sys.stdout.fileno()).st_mode):
        raise RuntimeError()
    request = json.load(sys.stdin)
    SAFE_TARGET = "app" if request.get("title") == "Locklark · 本地金库" else "picker" if request.get("title") == "选择未加密 OpenSSH Ed25519 私钥" else "none"
    if request.get("observe"):
        native.FAILURE_CONTEXT.update(action="snapshot", index=-1)
    if request.get("observe") == "clipboard":
        print(json.dumps(PublicClipboard().compare([])))
    elif request.get("observe") == "approval":
        print(json.dumps(approval(request)))
    elif request.get("observe") == "picker":
        print(json.dumps(picker_observation(request)))
    elif request.get("observe") == "picker-closed":
        print(json.dumps(wait_picker_closed(request)))
    else:
        # Reuse only normal OS input; an in-memory stream avoids logging the
        # request or passing text-entry values as command arguments.
        import io
        sys.stdin = io.StringIO(json.dumps(request))
        native.main()


if __name__ == "__main__":
    try:
        if sys.argv[1:] == ["--approval-observer"]:
            approval_observer()
        elif sys.argv[1:]:
            raise RuntimeError()
        else:
            main()
    except Exception as error:
        reason = "x-query" if type(error) is PickerWindowQueryUnavailable else native.failure_reason(error)
        print("SSH native driver failed [" + reason + "]", file=sys.stderr)
        print("SSH_NATIVE_DIAGNOSTIC " + json.dumps(failure_diagnostic(error), sort_keys=True), file=sys.stderr)
        raise SystemExit(1)
