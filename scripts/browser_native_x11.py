"""External XTest driver for synthetic native-window acceptance; no app hooks.

Reads one JSON request from stdin. Values are never echoed. Requires DISPLAY,
libX11 and libXtst. Native controls use their real AT-SPI labels, state and
geometry. Legacy coordinates are relative to the requested real X window.
The only pointer input is the purpose-bound `chooser_action`
{"select_folder": true}, derived from the measured chooser geometry.
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
    "Chooser ownership request required": "chooser-request",
    "Chooser owner window unavailable": "chooser-owner",
    "Chooser owner window must be unique": "chooser-owner-ambiguous",
    "Chooser must be a WM transient of the owner": "chooser-leader",
    "Chooser must share the owner client leader": "chooser-leader",
    "Chooser must belong to the owner browser process": "chooser-process",
    "X window query refused": "x-query",
    "Chooser folder action request required": "folder-action-request",
    "Chooser must keep the requested title": "folder-title",
    "Chooser must keep the measured geometry": "folder-geometry",
    "Chooser folder point is not inside the chooser": "folder-point",
    "Chooser folder pointer is not at the measured point": "folder-pointer",
    "Chooser folder input failed": "folder-input",
}


# Fixed, request-carried attribution contract. Everything is ASCII: the
# chooser title prefix, the exact --user-data-dir switch and the executable.
OWNER_FIELDS = ("owner_title_prefix", "chooser_title_prefix", "user_data_dir", "executable")
# The actual X property type is part of every proof: a 32-bit value of the
# wrong type is not a WINDOW id and not a process id.
PROPERTY_TYPES = {
    "WM_TRANSIENT_FOR": "WINDOW",
    "WM_CLIENT_LEADER": "WINDOW",
    "_NET_WM_PID": "CARDINAL",
}
PROPERTY_LIMIT = 256
PID_LIMIT = 4194304
TREE_BUDGET = 4096
PARENT_DEPTH = 8
PROC_LINK_MAX = 4096
CMDLINE_MAX = PROC_LINK_MAX * 4
PROBE_KEYS = frozenset(OWNER_FIELDS) | {"actions", "ownership_probe", "preserve_focus"}
INPUT_KEYS = frozenset(OWNER_FIELDS) | {
    "actions", "owner", "owner_pid", "preserve_focus", "title", "title_prefix",
}
# One purpose-bound folder action, separate from the keyboard/coordinate input
# shape. The chooser title must equal this exact literal and the chooser must
# keep the measured client size; the point is always derived from that geometry.
FOLDER_ACTION = {"select_folder": True}
FOLDER_ACTION_KEYS = frozenset(OWNER_FIELDS) | {"chooser_action", "owner", "owner_pid"}
EDGE_CHOOSER_TITLE = "Select the extension directory."
FOLDER_CHOOSER_SIZE = (1124, 822)
FOLDER_POINT_OFFSETS = (("width", -62), ("height", -69))


def parse_folder_action_request(request):
    """Exact purpose-bound `{"select_folder": true}` chooser request, or None.

    The request is never the keyboard/coordinate shape: there is no `actions`,
    no caller title, no `title_prefix`, no focus or geometry value and no
    click coordinate. The chooser title is the fixed literal and the optional
    caller PID is bound exactly as in the owner input shape. Only the fixed
    attribution values are returned; values are never printed.
    """
    if type(request) is not dict or set(request) - FOLDER_ACTION_KEYS:
        return None
    action = request.get("chooser_action")
    # Strict identity: the value must be the JSON boolean true, not 1 or "true".
    if request.get("owner") is not True or type(action) is not dict or \
            set(action) != set(FOLDER_ACTION) or action.get("select_folder") is not True:
        return None
    if not all(key in request for key in OWNER_FIELDS):
        return None
    if request.get("chooser_title_prefix") != EDGE_CHOOSER_TITLE:
        return None
    validated_pid = None
    if "owner_pid" in request:
        supplied = request["owner_pid"]
        if type(supplied) is not int or not 1 < supplied <= PID_LIMIT:
            return None
        validated_pid = supplied
    if ascii_line(request["owner_title_prefix"]) is None or \
            ascii_path(request["user_data_dir"]) is None or \
            ascii_path(request["executable"]) is None:
        return None
    normalized = {key: request[key] for key in OWNER_FIELDS}
    normalized["caller_pid"] = validated_pid
    normalized["probe"] = False
    return normalized


def folder_point(width, height):
    """The only permitted point, (width-62, height-69), or None.

    Valid only for the exact measured 1124x822 chooser client geometry and
    only when the derived point is strictly inside that geometry.
    """
    if type(width) is not int or type(height) is not int or \
            (width, height) != FOLDER_CHOOSER_SIZE:
        return None
    offsets = dict(FOLDER_POINT_OFFSETS)
    x, y = width + offsets["width"], height + offsets["height"]
    if 0 < x < width and 0 < y < height:
        return x, y
    return None


def chooser_geometry(attributes):
    """(width, height) of one real mapped, non-override-redirect window.

    None for a missing attribute record, an unmapped or override-redirect
    window, or a non-positive client size. The exact measured size is enforced
    only by folder_point, so this helper never widens the permitted point.
    """
    if attributes is None or attributes.map_state != 2 or attributes.override_redirect:
        return None
    if type(attributes.width) is not int or type(attributes.height) is not int:
        return None
    if attributes.width <= 0 or attributes.height <= 0:
        return None
    return attributes.width, attributes.height


def folder_output(click_count):
    """Fixed folder-action output: no window, title, path, PID or coordinate."""
    if type(click_count) is not int or click_count not in (0, 1):
        return None
    return {"chooser_action": "select_folder", "clicks": click_count}


def x_property(x, display, candidate, atom, expected_type):
    """One real XGetWindowProperty read with Xlib's own argument handling.

    Returns ("ok", values) for an un-truncated 32-bit property of exactly
    `expected_type` (the WINDOW or CARDINAL atom), ("missing", []) for an
    absent property and ("malformed", []) for a wrong type, wrong format, a
    truncated value or anything else. The data pointer is always released
    through the loaded Xlib XFree.
    """
    if type(atom) is not int or atom <= 0 or type(expected_type) is not int or expected_type <= 0:
        return "malformed", []
    actual, count, remaining = C.c_ulong(), C.c_ulong(), C.c_ulong()
    fmt, data = C.c_int(), C.c_void_p()
    try:
        status = x.XGetWindowProperty(display, candidate, atom, 0, PROPERTY_LIMIT, 0, 0,
                                      C.byref(actual), C.byref(fmt), C.byref(count),
                                      C.byref(remaining), C.byref(data))
    except Exception:
        return "malformed", []
    if status != 0:
        return "malformed", []
    if not data.value:
        return "missing", []
    try:
        # Xlib returns None for an absent type; only FORMAT 32, the exact
        # requested actual type, an exact count and no trailing values count.
        if fmt.value != 32 or remaining.value or count.value > 4:
            return "malformed", []
        if int(actual.value) != expected_type:
            return "malformed", []
        return "ok", [int(C.cast(data, C.POINTER(C.c_ulong))[index])
                      for index in range(count.value)]
    finally:
        x.XFree(data)


def property_record(x, display, candidate, name):
    """One fixed property read as a status/values record, or malformed."""
    actual = PROPERTY_TYPES.get(name)
    if actual is None:
        return {"status": "malformed"}
    try:
        atom = x.XInternAtom(display, name.encode("ascii"), 0)
        expected = x.XInternAtom(display, actual.encode("ascii"), 0)
    except Exception:
        return {"status": "malformed"}
    status, values = x_property(x, display, candidate, atom, expected)
    return {"status": status, "values": values} if status == "ok" else {"status": status}


def assert_chooser_text(text):
    """The X key path is printable-ASCII only; refuse before any input."""
    if type(text) is not str or any(ord(char) < 32 or ord(char) > 126 for char in text):
        raise RuntimeError("Acceptance input must be ASCII")
    return text


def ascii_text(value):
    """One non-empty printable-ASCII token without whitespace, or None."""
    if type(value) is not str or not value:
        return None
    if any(ord(char) < 33 or ord(char) > 126 for char in value):
        return None
    return value


def ascii_line(value):
    """One non-empty printable-ASCII line (spaces allowed), or None."""
    if type(value) is not str or not value:
        return None
    if any(ord(char) < 32 or ord(char) > 126 for char in value):
        return None
    return value


def ascii_path(value):
    """One absolute printable-ASCII path without trailing slash, or None."""
    if ascii_line(value) is None or not value.startswith("/") or value == "/":
        return None
    if value.endswith("/") and len(value) > 1:
        return None
    return value


def title_matches(title, prefix):
    """Fixed, non-empty title prefix match; control/None input never matches."""
    return (type(title) is str and title != "" and ascii_line(prefix) is not None
            and not any(ord(char) < 32 for char in title)
            and title.startswith(prefix))


def query_children(x, display, parent):
    """Actual Xlib XQueryTree of one window; every child in tree order.

    XQueryTree returns Status and fills the child array, released through the
    loaded XFree. A refused query stops the probe instead of being read as an
    empty tree.
    """
    if type(parent) is not int or parent <= 0:
        raise RuntimeError("X window query refused")
    root_return, parent_return, count = C.c_ulong(), C.c_ulong(), C.c_uint()
    result = C.POINTER(C.c_ulong)()
    ok = x.XQueryTree(display, parent, C.byref(root_return), C.byref(parent_return),
                      C.byref(result), C.byref(count))
    if not ok:
        raise RuntimeError("X window query refused")
    try:
        if count.value > TREE_BUDGET or (count.value and not result):
            raise RuntimeError("X window query refused")
        return [int(result[index]) for index in range(count.value)]
    finally:
        if result:
            x.XFree(result)


def distinct_transients(x, display, candidate):
    """Distinct WM_TRANSIENT_FOR parents of the candidate, or None if malformed."""
    try:
        atom = x.XInternAtom(display, b"WM_TRANSIENT_FOR", 0)
        window_type = x.XInternAtom(display, b"WINDOW", 0)
    except Exception:
        return None
    status, values = x_property(x, display, candidate, atom, window_type)
    if status != "ok" or not 1 <= len(values) <= 4:
        return None
    return sorted(set(values))


def parse_owner_request(request):
    """Exact fixed attribution contract of the native chooser mode.

    Two shapes exist. `ownership_probe: true` is the zero-action probe: the
    driver derives the owner PID from the unique real owner window and returns
    only the fixed ownership class. `owner: true` is the input shape: the
    driver derives the owner PID from the same unique real owner window, then
    checks the exact executable image, the single exact private
    --user-data-dir switch and the chooser attribution before any input. An
    optional caller PID is validated and must equal the derived PID exactly.
    Only the chooser title, the title prefix of the real Edge manager window,
    the requester's exact private --user-data-dir and the Edge executable are
    accepted. None of these values is ever printed.
    """
    if type(request) is not dict:
        return None
    probe = request.get("ownership_probe")
    input_mode = request.get("owner")
    if probe is not None and probe is not True:
        return None
    if input_mode is not None and input_mode is not True:
        return None
    if (probe is True) == (input_mode is True):
        return None
    # The purpose-bound folder action has its own closed schema.
    if "chooser_action" in request:
        return None
    if probe is True:
        if set(request) - PROBE_KEYS:
            return None
        if request.get("actions") not in (None, []):
            return None
        if "owner_pid" in request:
            return None
        if request.get("preserve_focus", True) is not True:
            return None
        if not all(key in request for key in OWNER_FIELDS):
            return None
        normalized = {key: request[key] for key in OWNER_FIELDS}
        normalized["probe"] = True
    else:
        if set(request) - INPUT_KEYS:
            return None
        if request.get("title_prefix") != request.get("title"):
            return None
        if ascii_line(request.get("title")) is None:
            return None
        if request.get("preserve_focus") is not True:
            return None
        # The owner PID is derived from the unique real manager window, exactly
        # as in the zero-action probe. A caller-supplied PID is optional; when
        # present it must be a well-formed value and equal the derived one.
        validated_pid = None
        if "owner_pid" in request:
            supplied = request["owner_pid"]
            if type(supplied) is not int or not 1 < supplied <= PID_LIMIT:
                return None
            validated_pid = supplied
        actions = request.get("actions")
        if type(actions) is not list or not actions:
            return None
        if not all(key in request for key in OWNER_FIELDS):
            return None
        for action in actions:
            if type(action) is not dict:
                return None
            if "key" in action:
                parts = action["key"].split("+") if type(action["key"]) is str else []
                if not 1 <= len(parts) <= 2 or not all(ascii_text(part) for part in parts):
                    return None
            if set(action) - {"text", "key"} or not {"key", "text"} & set(action):
                return None
            if "text" in action:
                try:
                    assert_chooser_text(action["text"])
                except RuntimeError:
                    return None
        normalized = {key: request[key] for key in OWNER_FIELDS}
        normalized["caller_pid"] = validated_pid
        normalized["probe"] = False
    if ascii_line(normalized["owner_title_prefix"]) is None or \
            ascii_line(normalized["chooser_title_prefix"]) is None:
        return None
    if ascii_path(normalized["user_data_dir"]) is None or \
            ascii_path(normalized["executable"]) is None:
        return None
    return normalized


def derived_owner_pid(owner, owner_pid):
    """The unique manager window's own PID, bound again to an optional request.

    `owner_pid` is the _NET_WM_PID of the single viewable manager window whose
    title carries the owner prefix, exactly as the zero-action probe reads it.
    An input request may also carry a caller PID; it must be a well-formed
    value (parse_owner_request) and equal the derived PID. The derived value is
    returned only when the binding holds, else None. Values are never printed.
    """
    if type(owner) is not dict or type(owner_pid) is not int or not 1 < owner_pid <= PID_LIMIT:
        return None
    caller = owner.get("caller_pid")
    if owner.get("probe") is True:
        return owner_pid
    if owner.get("probe") is not False:
        return None
    if caller is not None and (type(caller) is not int or caller != owner_pid):
        return None
    return owner_pid


def safe_owner_record(result):
    """Only the fixed ownership class and relation type; never raw values."""
    if type(result) is not dict:
        return None
    if result.get("owned") is False and result.get("relation") == "none":
        return {"owned": False, "relation": "none"}
    relation = result.get("relation")
    if result.get("owned") is True and relation in ("transient-leader", "process-parent"):
        return {"owned": True, "relation": relation}
    return None


def probe_output(record):
    """Zero-action probe output: only the fixed ownership class, nothing else."""
    safe = safe_owner_record(record)
    return None if safe is None else {"ownership": safe}


def window_chain_ok(owner, owners, transients):
    """One owner X window with exactly one chooser WM_TRANSIENT_FOR target.

    owner: (window, pid, pid_viewable) for the real manager window.
    owners: every viewable window whose title starts with the owner prefix.
    transients: every distinct WM_TRANSIENT_FOR parent of the chooser
    candidate. A malformed, zero, duplicate or ambiguous value refuses. The
    terminal may be the owner window itself: that is the normal parent link
    and the detailed WM_TRANSIENT_FOR/WM_CLIENT_LEADER proof follows.
    """
    if type(owner) is not tuple or len(owner) != 3:
        return False
    window, pid, viewable = owner
    if type(window) is not int or window <= 0 or not 1 < pid <= PID_LIMIT or viewable is not True:
        return False
    if type(owners) is not list or owners.count(window) != 1 or len(owners) != 1:
        return False
    if type(transients) is not list or len(transients) != 1 or \
            type(transients[0]) is not int:
        return False
    # Exactly one terminal WM_TRANSIENT_FOR target; the caller proves it is
    # the owner's own client window through the WM chain.
    return transients[0] != 0


def read_proc_link(pid, name):
    """Read one /proc/<pid>/ link only; a missing or unreadable link is None."""
    if type(pid) is not int or not 1 < pid <= PID_LIMIT:
        return None
    try:
        value = os.readlink("/proc/" + str(pid) + "/" + name)
    except OSError:
        return None
    return value if value and len(value) <= PROC_LINK_MAX else None


def owner_process_matches(pid, owner):
    """Exact requested executable image and exact requester profile switch.

    /proc/<pid>/exe must resolve (realpath) to the requested executable image
    and /proc/<pid>/cmdline must carry the exact --user-data-dir=<profile>
    token exactly once. A truncated command line, a missing terminator or a
    duplicate switch is refused. Values are compared, never returned.
    """
    if type(pid) is not int or not 1 < pid <= PID_LIMIT or type(owner) is not dict:
        return None
    executable = owner.get("executable")
    profile = owner.get("user_data_dir")
    if ascii_path(executable) is None or ascii_path(profile) is None:
        return None
    actual = read_proc_link(pid, "exe")
    if actual is None:
        return None
    try:
        if os.path.realpath(actual) != os.path.realpath(executable):
            return None
    except (OSError, ValueError):
        return None
    try:
        with open("/proc/" + str(pid) + "/cmdline", "rb") as cmdline:
            data = cmdline.read(CMDLINE_MAX + 1)
    except OSError:
        return None
    # /proc/<pid>/cmdline is NUL terminated. A full read, a missing final NUL
    # or an empty command line means truncation or a race: refuse it.
    if not data or len(data) > CMDLINE_MAX or not data.endswith(b"\0"):
        return None
    switch = b"--user-data-dir=" + os.fsencode(profile)
    # Only the one exact requester switch counts; duplicate or truncated
    # profile switches are refused.
    return pid if data.split(b"\0").count(switch) == 1 else None


def chooser_pid_relation(owner_pid, chooser_pid):
    """Bounded, actual OS parent chain back to the exact verified Edge PID.

    Only /proc/<pid>/stat parent ids are followed; the chain stops at the
    owner. The exact owner PID itself is a direct match. It is never a
    same-uid or executable-basename guess.
    """
    def parent(pid):
        try:
            with open("/proc/" + str(pid) + "/stat", "rb") as stat:
                fields = stat.read(PROC_LINK_MAX).rsplit(b")", 1)
        except UnicodeDecodeError:
            return None
        except Exception:
            return None
        if len(fields) != 2:
            return None
        parts = fields[1].split()
        # After the command name: state ppid ...
        if len(parts) < 2:
            return None
        return int(parts[1])

    if type(owner_pid) is not int or type(chooser_pid) is not int:
        return False
    if not 1 < owner_pid <= PID_LIMIT or not 1 < chooser_pid <= PID_LIMIT:
        return False
    if chooser_pid == owner_pid:
        return True
    pid = chooser_pid
    for _ in range(PARENT_DEPTH):
        try:
            pid = parent(pid)
        except (OSError, IndexError, ValueError):
            return False
        if pid is None:
            return False
        if pid == owner_pid:
            return True
        if pid <= 1:
            return False
    return False


def _single_int(values):
    if type(values) is not list or len(values) != 1:
        return None
    value = values[0]
    return value if type(value) is int and 0 <= value <= 0xFFFFFFFF else None


def _unique(values):
    if type(values) is not list or not values or any(type(value) is not int for value in values):
        return False
    return len(set(values)) == 1


def _ok_values(record):
    """Values of an actual, type-checked property record, else None."""
    if type(record) is not dict or record.get("status") != "ok":
        return None
    return record.get("values")


def property_single_int(record):
    """One 32-bit value of a status/values record; never the record itself."""
    return _single_int(_ok_values(record))


def check_chooser_relations(prop, expected_client, owner_pid):
    """Fail-closed ownership proof for the one chooser candidate.

    prop(name, window) returns {"status": "ok", "values": [...]} from the
    actual, type-checked XGetWindowProperty, {"status": "missing"} when the
    property is absent or {"status": "malformed"} otherwise (including a
    WINDOW property whose actual type is not WINDOW). The chooser is owned
    only when it is a WM transient of the owner's sole viewable client window
    and shares its WM_CLIENT_LEADER; both ends must carry the verified owner
    _NET_WM_PID. Returns a fixed failure message or None when owned.
    """
    if type(owner_pid) is not int or not 1 < owner_pid <= PID_LIMIT:
        return "Chooser owner window unavailable"
    expected_client = expected_client if type(expected_client) is int else None
    client_pid = property_single_int(prop("_NET_WM_PID", expected_client)) \
        if expected_client else None
    if expected_client is None or client_pid != owner_pid:
        return "Chooser must belong to the owner browser process"
    client_leader = property_single_int(prop("WM_CLIENT_LEADER", expected_client))
    if not client_leader:
        return "Chooser must share the owner client leader"
    transient = prop("WM_TRANSIENT_FOR", None)
    transient_values = _ok_values(transient)
    if transient_values is None or not _unique(transient_values):
        return "Chooser must be a WM transient of the owner"
    if transient_values != [expected_client]:
        return "Chooser must be a WM transient of the owner"
    # Exactly the client's leader: one WINDOW value, equal, and non-zero.
    leader_values = _ok_values(prop("WM_CLIENT_LEADER", None))
    if _single_int(leader_values) != client_leader:
        return "Chooser must share the owner client leader"
    return None


def prove_chooser_ownership(mode, prop, owner_pid, client, candidate_pid, parent_relation):
    """Choose exactly one proof mode; no physical action happens here.

    mode "wm": WM_TRANSIENT_FOR/WM_CLIENT_LEADER chain from the candidate to
    the sole owner client window `client`, whose _NET_WM_PID must be
    `owner_pid`. mode "process": actual bounded OS parent chain from the
    candidate's _NET_WM_PID to the exact owner PID. The caller has already
    verified the owner's executable and exact --user-data-dir. Returns a fixed
    safe record, or a fixed failure message as the second element.
    """
    if mode == "wm":
        if type(client) is not int or client <= 0:
            return None, "Chooser client window of the owner is unavailable"
        reason = check_chooser_relations(prop, client, owner_pid)
        return (None, reason) if reason else ({"owned": True, "relation": "transient-leader"}, None)
    if mode == "process":
        if type(owner_pid) is not int or type(candidate_pid) is not int or candidate_pid <= 0:
            return None, "Chooser must belong to the owner browser process"
        record = prop("_NET_WM_PID", None)
        pid = property_single_int(record)
        if pid is None or pid != candidate_pid:
            return None, "Chooser must belong to the owner browser process"
        if parent_relation(owner_pid, pid) is not True:
            return None, "Chooser must belong to the owner browser process"
        return {"owned": True, "relation": "process-parent"}, None
    return None, "Chooser ownership request required"


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

    def window_property(candidate, name):
        """One real, actual-type-checked X property read as a record."""
        return property_record(x, display, candidate, name)

    def attributes_of(candidate):
        attributes = Attributes()
        if not x.XGetWindowAttributes(display, candidate, C.byref(attributes)):
            return None
        return attributes

    def normal_viewable(window):
        attributes = attributes_of(window)
        return attributes is not None and attributes.map_state == 2 and not attributes.override_redirect

    def children(parent):
        return query_children(x, display, parent)

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

    def collect_titles(prefix, parent=root, depth=0):
        """Bounded title-prefix traversal with no executable filter.

        Used only by the owner/probe contract so a GTK helper dialog is
        discoverable before attribution; every candidate is still proven
        through the real WM chain or the bounded /proc parent chain before
        any input.
        """
        if depth > 3:
            return []
        found = []
        for candidate in children(parent):
            if title_matches(window_title(candidate), prefix):
                found.append(candidate)
            found.extend(collect_titles(prefix, candidate, depth + 1))
        return found

    # The folder action has its own closed request parser; it is never routed
    # through the keyboard/coordinate owner input shape.
    folder_mode = "chooser_action" in request
    owner = None
    if folder_mode or request.get("owner") or request.get("ownership_probe"):
        owner = parse_folder_action_request(request) if folder_mode \
            else parse_owner_request(request)
        if owner is None or request.get("wait_absent") or request.get("inspect"):
            raise RuntimeError("Chooser folder action request required" if folder_mode
                               else "Chooser ownership request required")

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
        if owner is not None:
            # Fixed chooser title prefix only; the exact Edge executable filter
            # is deliberately not applied before the ownership proof.
            matches = [candidate for candidate in collect_titles(owner["chooser_title_prefix"])
                       if normal_viewable(candidate)]
        else:
            matches=find(root)
        if len(matches)>1:
            raise RuntimeError("Native acceptance window must be unique")
        if matches:
            target=matches[0]
            break
        time.sleep(0.05)
    if not target:
        raise RuntimeError("Native acceptance window unavailable")

    ownership = None
    if owner is not None:
        # Fixed attribution only: one real manager window of this private
        # profile, its exact verified process and the chooser ownership proof.
        # Every request field, every owner fact and the chooser proof are
        # checked before the first physical input; failures stay fixed classes.
        prior_errors = list(errors)
        errors.clear()
        try:
            if not title_matches(window_title(target), owner["chooser_title_prefix"]):
                raise RuntimeError("Native acceptance window unavailable")
            manager = [candidate for candidate in collect_titles(owner["owner_title_prefix"])
                       if normal_viewable(candidate)]
            if len(manager) != 1:
                raise RuntimeError("Chooser owner window must be unique" if manager
                                   else "Chooser owner window unavailable")
            owner_window = manager[0]
            owner_pid = property_single_int(window_property(owner_window, "_NET_WM_PID"))
            if type(owner_pid) is not int or not 1 < owner_pid <= PID_LIMIT:
                raise RuntimeError("Chooser owner window unavailable")
            # The owner PID is bound by the unique real manager window itself in
            # both shapes. A caller-supplied input PID must equal it exactly;
            # it is never trusted on its own.
            if derived_owner_pid(owner, owner_pid) != owner_pid:
                raise RuntimeError("Chooser owner window unavailable")
            # Exact real executable image and exactly one exact private profile
            # switch; a duplicate profile switch is never a second match.
            if owner_process_matches(owner_pid, owner) != owner_pid:
                raise RuntimeError("Chooser owner window unavailable")
            # None selects the chooser; the owner window is used for
            # the owner-side _NET_WM_PID/WM_CLIENT_LEADER reads.
            chooser_props = lambda name, candidate: window_property(
                target if candidate is None else candidate, name)
            chooser_parents = distinct_transients(x, display, target)
            record, reason = None, None
            # WM_TRANSIENT_FOR/WM_CLIENT_LEADER chain first; the unique owner
            # window is the only valid transient terminal, so a separate helper
            # cannot substitute itself. Then the bounded, actual /proc parent
            # chain back to the exact verified PID. Edge may omit
            # WM_CLIENT_LEADER on the owner window; the process proof then
            # accepts the exact same PID or a real bounded parent chain.
            if window_chain_ok((owner_window, owner_pid, True), manager, chooser_parents):
                record, reason = prove_chooser_ownership(
                    "wm", chooser_props, owner_pid, owner_window, window_pid(target), None)
            if record is None:
                record, reason = prove_chooser_ownership(
                    "process", chooser_props, owner_pid, None, window_pid(target),
                    chooser_pid_relation)
            # Re-prove the owner process identity immediately before trusting
            # the relation result.
            if record is None or owner_process_matches(owner_pid, owner) != owner_pid:
                raise RuntimeError(reason or "Chooser owner window unavailable")
            ownership = safe_owner_record(record)
            if ownership is None or any(code != 3 for code, _resource in errors) or \
                    any(code != 3 for code, _resource in prior_errors):
                raise RuntimeError("Native acceptance X query failed")
            if owner["probe"]:
                # Zero-action probe: only the fixed ownership class is ever
                # emitted, and it returns before focus/geometry/XTest.
                output = probe_output(record)
                if output is None:
                    raise RuntimeError("Chooser owner window unavailable")
                print(json.dumps(output))
                x.XCloseDisplay(display)
                return
        finally:
            errors.clear()

    def find_chooser():
        """The same unique chooser: exact title, bounded tree, re-read title.

        Returns its (width, height) only when it is mapped, not
        override-redirect and exactly the measured client size.
        """
        if window_title(target) != EDGE_CHOOSER_TITLE:
            raise RuntimeError("Chooser must keep the requested title")
        same = [candidate for candidate in collect_titles(EDGE_CHOOSER_TITLE)
                if normal_viewable(candidate)]
        if same != [target]:
            raise RuntimeError("Native acceptance window must be unique" if same
                               else "Native acceptance window unavailable")
        if window_title(target) != EDGE_CHOOSER_TITLE:
            raise RuntimeError("Chooser must keep the requested title")
        geometry = chooser_geometry(attributes_of(target))
        if geometry is None or folder_point(*geometry) is None:
            raise RuntimeError("Chooser must keep the measured geometry")
        return geometry

    def prove_folder_owner(owner_record):
        """Owner window, PID, executable and profile, re-read before the click."""
        current = [candidate for candidate in collect_titles(owner["owner_title_prefix"])
                   if normal_viewable(candidate)]
        if current != [owner_window]:
            raise RuntimeError("Chooser owner window must be unique" if current
                               else "Chooser owner window unavailable")
        owner_now = property_single_int(window_property(owner_window, "_NET_WM_PID"))
        if type(owner_now) is not int or owner_now != owner_pid:
            raise RuntimeError("Chooser owner window unavailable")
        if derived_owner_pid(owner_record, owner_now) != owner_now:
            raise RuntimeError("Chooser owner window unavailable")
        if owner_process_matches(owner_now, owner_record) != owner_now:
            raise RuntimeError("Chooser owner window unavailable")
        if window_pid(target) != owner_now:
            raise RuntimeError("Chooser must belong to the owner browser process")

    def read_only(step, failure="Chooser folder input failed"):
        """One read-only Xlib step; a refused or erroring query refuses input."""
        errors.clear()
        try:
            value = step()
        except RuntimeError:
            raise
        except Exception:
            raise RuntimeError(failure)
        x.XSync(display, 0)
        if errors:
            raise RuntimeError(failure)
        return value

    def click_folder(owner_record):
        # Every check below runs before the request batch that queues the
        # click. Chooser and owner proofs alternate so state must stay
        # identical across them, ending with the owner re-read immediately
        # before the single XTest button down/up pair.
        geometry = read_only(find_chooser, "Native acceptance X query failed")
        read_only(lambda: prove_folder_owner(owner_record), "Native acceptance X query failed")
        if read_only(find_chooser, "Native acceptance X query failed") != geometry:
            raise RuntimeError("Chooser must keep the measured geometry")
        point = folder_point(*geometry)
        if point is None:
            raise RuntimeError("Chooser folder point is not inside the chooser")
        read_only(lambda: prove_folder_owner(owner_record), "Native acceptance X query failed")
        # Last identity/geometry re-read immediately before the click.
        if read_only(find_chooser, "Native acceptance X query failed") != geometry:
            raise RuntimeError("Chooser must keep the measured geometry")
        # The click lands at the one derived point only when the chooser's root
        # origin plus that point is exactly the current pointer position. No
        # motion is emitted; the pointer stays where the reviewed probe left it.
        px, py, child = C.c_int(), C.c_int(), window()
        if not x.XTranslateCoordinates(display, target, root, 0, 0, C.byref(px),
                                       C.byref(py), C.byref(child)):
            raise RuntimeError("Chooser must keep the measured geometry")
        qroot, qchild = window(), window()
        rx, ry, wx, wy, mask = C.c_int(), C.c_int(), C.c_int(), C.c_int(), C.c_uint()
        if not x.XQueryPointer(display, root, C.byref(qroot), C.byref(qchild),
                               C.byref(rx), C.byref(ry), C.byref(wx), C.byref(wy),
                               C.byref(mask)):
            raise RuntimeError("Chooser folder pointer is not at the measured point")
        if (rx.value, ry.value) != (px.value + point[0], py.value + point[1]):
            raise RuntimeError("Chooser folder pointer is not at the measured point")
        x.XSync(display, 0)
        if errors:
            raise RuntimeError("Native acceptance X query failed")
        down = xt.XTestFakeButtonEvent(display, 1, 1, 0)
        up = xt.XTestFakeButtonEvent(display, 1, 0, 0)
        if not down or not up:
            raise RuntimeError("Chooser folder input failed")
        x.XFlush(display)
        x.XSync(display, 0)
        if errors:
            raise RuntimeError("Chooser folder input failed")

    if folder_mode:
        if owner is None:
            raise RuntimeError("Chooser folder action request required")
        errors.clear()
        FAILURE_CONTEXT["index"] = 0
        FAILURE_CONTEXT["action"] = "folder-action"
        click_folder(owner)
        print(json.dumps(folder_output(1)))
        x.XCloseDisplay(display)
        return

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
    actions = request.get("actions", [])
    if type(actions) is not list or not all(type(action) is dict for action in actions):
        raise RuntimeError("Native acceptance X query failed")
    # Every typed value is validated before the first physical input, so a
    # refused directory can never arrive after a shortcut was emitted.
    for action in actions:
        if "text" in action and (type(action["text"]) is not str or
                                 any(ord(char) < 32 or ord(char) > 126 for char in action["text"])):
            raise RuntimeError("Acceptance input must be ASCII")
    for index, action in enumerate(actions):
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
            if type(action["text"]) is not str:
                raise RuntimeError("Acceptance input must be ASCII")
            assert_chooser_text(action["text"])
            shift = named("Shift_L")
            for char in action["text"]:
                symbol = ord(char)
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
    if ownership is not None:
        # Probe mode: only the fixed ownership class and relation type; no
        # window, title, path, command line, PID or arbitrary property.
        result = {"ownership": ownership, "clicks": len(clicks)}
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
