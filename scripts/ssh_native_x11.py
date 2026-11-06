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


def approval(request):
    pid = request["pid"]
    if (type(pid) is not int or pid <= 0
            or os.readlink("/proc/" + str(pid) + "/exe") != os.path.realpath(request["executable"])):
        raise RuntimeError()
    reader = native.NativeControls(request["title"], pid)
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
    if request.get("title") != "选择未加密 OpenSSH Ed25519 私钥":
        raise RuntimeError()
    reader = native.NativeControls(request["title"], request["pid"])
    if os.readlink("/proc/" + str(request["pid"]) + "/exe") != os.path.realpath(request["executable"]):
        raise RuntimeError()
    reader.at.atspi_accessible_get_text_iface.argtypes = [C.c_void_p]
    reader.at.atspi_accessible_get_text_iface.restype = C.c_void_p
    reader.at.atspi_text_get_text.argtypes = [C.c_void_p, C.c_int, C.c_int, C.POINTER(C.c_void_p)]
    reader.at.atspi_text_get_text.restype = C.c_void_p
    windows, counts = [], {"present": False, "path_match": 0, "name_match": 0, "selected_name_match": 0, "entries": 0}

    def find(node, depth):
        if (reader.string(reader.at.atspi_accessible_get_name, node) == reader.title
                and reader.checked(reader.at.atspi_accessible_get_process_id, node) == request["pid"]):
            windows.append(reader.go.g_object_ref(node))
            return False
        return depth < 2

    def observe(node, _depth):
        role = reader.string(reader.at.atspi_accessible_get_role_name, node)
        name = reader.string(reader.at.atspi_accessible_get_name, node)
        counts["name_match"] += name == pathlib_basename(request["expected_path"])
        if name == pathlib_basename(request["expected_path"]):
            state = reader.at.atspi_accessible_get_state_set(node)
            if state:
                try:
                    counts["selected_name_match"] += bool(reader.at.atspi_state_set_contains(state, 23))
                finally:
                    reader.go.g_object_unref(state)
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


def pathlib_basename(path):
    return os.path.basename(path)


def main():
    if not stat.S_ISFIFO(os.fstat(sys.stdout.fileno()).st_mode):
        raise RuntimeError()
    request = json.load(sys.stdin)
    if request.get("observe") == "clipboard":
        print(json.dumps(PublicClipboard().compare([])))
    elif request.get("observe") == "approval":
        print(json.dumps(approval(request)))
    elif request.get("observe") == "picker":
        print(json.dumps(picker_observation(request)))
    else:
        # Reuse only normal OS input; an in-memory stream avoids logging the
        # request or passing text-entry values as command arguments.
        import io
        sys.stdin = io.StringIO(json.dumps(request))
        native.main()


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print("SSH native driver failed [" + native.failure_reason(error) + "]", file=sys.stderr)
        raise SystemExit(1)
