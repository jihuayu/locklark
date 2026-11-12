"""Platform seam tests with fakes and spies: no real OS, GUI, TCC or input.

They prove the adapters only read the five public widget fields, only emit one
physical batch per action, verify foreground focus before input, refuse
ambiguity/untrusted/secure surfaces, and never prompt for OS permission.
"""
import ctypes
import io
import json
import os
import subprocess
import sys
import types
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import browser_native_macos as macos
import browser_native_windows as windows
import native_acceptance_contract as contract
import native_acceptance_driver as driver

LABEL = "确认连接此扩展"
TITLE = "Locklark · 浏览器原生确认"
# The exact Python int PyObjC's ApplicationServices exports as kAXErrorNoValue
# (documented: no accessibility object at the specified position).
NO_VALUE = -25212
EXE = "C:/Program Files/Locklark test/browser.exe" if os.name == "nt" else "/opt/locklark/test-browser"
WINDOW_RAW = {
    "id": 0x200003, "pid": 4242, "title": TITLE, "executable": EXE, "trusted": True,
    "visible": True, "onscreen": True, "secure": False,
    "bounds": {"x": 100, "y": 100, "width": 800, "height": 600},
    "client": {"x": 110, "y": 140, "width": 780, "height": 560},
}
CONTROL = {"role": "push button", "name": LABEL, "enabled": True, "visible": True,
           "bounds": {"x": 200, "y": 300, "width": 80, "height": 30}}


def document(**overrides):
    value = {"title": TITLE, "executable": EXE, "actions": [{"click_label": LABEL}]}
    value.update(overrides)
    return json.dumps({key: item for key, item in value.items() if item is not None})


class FakeWin32:
    """Records the platform calls a real Win32Api would make."""

    def __init__(self, windows_list=None, focus=4242, secure=False,
                 focus_window=None, root=True):
        self.windows_list = [dict(WINDOW_RAW)] if windows_list is None else windows_list
        self.focus = focus
        self.focus_window = WINDOW_RAW["id"] if focus_window is None else focus_window
        self.secure = secure
        self.root = root
        self.activations = 0
        self.clicks = []
        self.typed = []
        self.chords = []

    def list_windows(self):
        return [dict(item) for item in self.windows_list]

    def input_desktop_secure(self):
        return self.secure

    def foreground_pid(self):
        return self.focus

    def focus_state(self, window=None):
        return {"pid": self.focus, "window": self.focus_window}

    def screen_bounds(self):
        return {"x": 0, "y": 0, "width": 1920, "height": 1080}

    def root_at(self, identifier, x, y):
        return self.root

    def activate(self, identifier):
        self.activations += 1
        return True

    def click(self, x, y):
        self.clicks.append((x, y))
        return {"move": True, "down": True, "up": True}

    def type_text(self, text):
        self.typed.append(text)
        return {"move": True, "down": True, "up": True}

    def press_chord(self, parts):
        self.chords.append(tuple(parts))
        return {"move": True, "down": True, "up": True}


class FakeUia:
    def __init__(self, controls=None, control_hit=True):
        self._controls = [dict(CONTROL)] if controls is None else controls
        self.control_hit = control_hit
        self.hit_calls = []
        self.reads = 0

    def controls(self, handle):
        self.reads += 1
        return [dict(item) for item in self._controls]

    def hit_test_control(self, handle, label, rect, x, y):
        self.hit_calls.append((handle, label, dict(rect), x, y))
        return self.control_hit


def execute(adapter, payload):
    plan = contract.parse_request(payload)
    with patch.object(contract, "monotonic", return_value=0), patch.object(contract, "sleep"):
        return contract.execute(plan, adapter)


class WindowsAdapterTests(unittest.TestCase):
    def test_public_metadata_then_one_physical_click(self):
        api, uia = FakeWin32(), FakeUia()
        adapter = windows.WindowsAdapter(api=api, uia=uia)
        result = execute(adapter, document())
        self.assertEqual(api.clicks, [(240, 315)])
        self.assertEqual(result["clicks"][0]["label"], LABEL)
        self.assertEqual(result["window"], "0x200003")
        self.assertEqual(api.activations, 0)  # already foreground: never activated

    def test_refuses_untrusted_secure_and_ambiguous_windows(self):
        cases = (([dict(WINDOW_RAW, trusted=False)], "process-untrusted"),
                 ([dict(WINDOW_RAW, secure=True)], "secure-desktop"),
                 ([dict(WINDOW_RAW), dict(WINDOW_RAW, id=7)], "window-ambiguous"),
                 ([dict(WINDOW_RAW, visible=False)], "window-hidden"))
        for windows_list, code in cases:
            with self.subTest(code=code):
                api = FakeWin32(windows_list=windows_list)
                adapter = windows.WindowsAdapter(api=api, uia=FakeUia())
                with self.assertRaises(contract.ContractError) as error:
                    execute(adapter, document())
                self.assertEqual(error.exception.code, code)
                self.assertEqual(api.clicks, [])

    def test_same_title_window_of_another_executable_is_not_a_candidate(self):
        # Executable-scoped discovery filters the other executable's window
        # before check_window, so discovery finds no candidate and times out.
        # The helper freezes monotonic time, so a zero timeout keeps the
        # first empty poll deterministic instead of exhausting the budget.
        api, uia = FakeWin32(windows_list=[dict(WINDOW_RAW,
                                                executable="/opt/other/browser")]), FakeUia()
        adapter = windows.WindowsAdapter(api=api, uia=uia)
        with patch.object(contract, "DISCOVER_TIMEOUT", 0):
            with self.assertRaises(contract.ContractError) as error:
                execute(adapter, document())
        self.assertEqual(error.exception.code, "window-timeout")
        self.assertEqual(api.clicks, [])
        self.assertEqual(uia.reads, 0)
        self.assertEqual(uia.hit_calls, [])
        self.assertEqual(api.activations, 0)

    def test_secure_desktop_refused_before_any_observation(self):
        api = FakeWin32(secure=True)
        adapter = windows.WindowsAdapter(api=api, uia=FakeUia())
        self.assertEqual(api.clicks, [])
        adapter.api.windows_list = None  # list_windows must not be reached
        with self.assertRaises(contract.ContractError) as error:
            adapter.check_capability()
        self.assertEqual(error.exception.code, "secure-desktop")

    def test_extra_widget_field_is_rejected_unread(self):
        control = dict(CONTROL, value="synthetic-private-canary-value")
        adapter = windows.WindowsAdapter(api=FakeWin32(), uia=FakeUia([control]))
        with self.assertRaises(contract.ContractError) as error:
            execute(adapter, document())
        self.assertEqual(error.exception.code, "a11y-query")

    def test_focus_mismatch_activates_once_then_refuses(self):
        api = FakeWin32(focus=999)
        adapter = windows.WindowsAdapter(api=api, uia=FakeUia())
        with self.assertRaises(contract.ContractError) as error:
            execute(adapter, document())
        self.assertEqual(error.exception.code, "focus-lost")
        self.assertEqual(api.activations, 1)
        self.assertEqual(api.clicks, [])

    def test_text_and_chord_delegate_once(self):
        api = FakeWin32()
        adapter = windows.WindowsAdapter(api=api, uia=FakeUia())
        execute(adapter, document(actions=[{"text": "abc"}, {"key": "Control_L+a"}]))
        self.assertEqual(api.typed, ["abc"])
        self.assertEqual(api.chords, [("Control_L", "a")])


    def test_same_pid_other_hwnd_refused(self):
        api = FakeWin32(focus_window=0x200004)
        adapter = windows.WindowsAdapter(api=api, uia=FakeUia())
        with self.assertRaises(contract.ContractError) as error:
            execute(adapter, document())
        self.assertEqual(error.exception.code, "focus-lost")
        self.assertEqual(api.activations, 1)
        self.assertEqual(api.clicks, [])

    def test_click_point_must_resolve_to_the_selected_hwnd(self):
        api = FakeWin32(root=False)
        adapter = windows.WindowsAdapter(api=api, uia=FakeUia())
        with self.assertRaises(contract.ContractError) as error:
            execute(adapter, document(actions=[{"click": [10, 20]}]))
        self.assertEqual(error.exception.code, "control-offscreen")
        self.assertEqual(api.clicks, [])

    def test_success_click_is_accepted_evidence_without_title(self):
        result = execute(windows.WindowsAdapter(api=FakeWin32(), uia=FakeUia()), document())
        self.assertEqual(result["clicks"][0]["evidence"], "accepted")
        self.assertNotIn("title", result)

    def test_overlay_at_the_control_centre_refuses_without_any_click(self):
        api, uia = FakeWin32(root=True), FakeUia(control_hit=False)
        adapter = windows.WindowsAdapter(api=api, uia=uia)
        with self.assertRaises(contract.ContractError) as error:
            execute(adapter, document())
        self.assertEqual(error.exception.code, "control-hit")
        self.assertEqual(api.clicks, [])
        self.assertEqual(uia.hit_calls,
                         [(WINDOW_RAW["id"], LABEL, dict(CONTROL["bounds"]), 240, 315)])

    def test_adapter_hit_verdict_is_strictly_boolean(self):
        for verdict, expected in ((True, True), (1, False), (-1, False), (None, False)):
            with self.subTest(verdict=verdict):
                adapter = windows.WindowsAdapter(api=FakeWin32(), uia=FakeUia(control_hit=verdict))
                self.assertEqual(
                    adapter.hit_test_control(dict(WINDOW_RAW), LABEL, dict(CONTROL["bounds"]), 240, 315),
                    expected)


class StrictWidget:
    """Exposes only the five public UIA members; anything else is a failure."""

    def __init__(self, control_type=50000, name=LABEL, enabled=True, offscreen=False):
        self.CurrentControlType = control_type
        self.CurrentName = name
        self.CurrentIsEnabled = enabled
        self.CurrentIsOffscreen = offscreen
        self.CurrentBoundingRectangle = types.SimpleNamespace(left=200, top=300, right=280, bottom=330)

    def __getattr__(self, name):
        raise AssertionError("forbidden UI Automation member requested: " + name)


class FakeCollection:
    def __init__(self, nodes):
        self.nodes = nodes
        self.Length = len(nodes)

    def GetElement(self, index):
        return self.nodes[index]


class FakeAutomation:
    def __init__(self, nodes):
        self.nodes = nodes
        self.handles = []

    def ElementFromHandle(self, handle):
        self.handles.append(handle)
        return self

    def CreateTrueCondition(self):
        return object()

    def FindAll(self, scope, condition):
        return FakeCollection(self.nodes)


class UiaReaderTests(unittest.TestCase):
    def test_reads_only_the_five_public_members(self):
        module = types.SimpleNamespace(TreeScope_Descendants=4)
        automation = FakeAutomation([StrictWidget(), StrictWidget(50020, "text node"),
                                     StrictWidget(50099, "ignored control type")])
        reader = windows.UiaReader(module, automation)
        controls = reader.controls(0x200003)
        self.assertEqual(len(controls), 2)  # unknown control type is not inspected
        for control in controls:
            self.assertEqual(set(control), set(contract.WIDGET_FIELDS))
        self.assertEqual(controls[0]["bounds"], {"x": 200, "y": 300, "width": 80, "height": 30})

    def test_element_budget_is_bounded(self):
        class Huge(FakeAutomation):
            def FindAll(self, scope, condition):
                collection = FakeCollection([])
                collection.Length = windows.MAX_ELEMENTS + 1
                return collection

        reader = windows.UiaReader(types.SimpleNamespace(TreeScope_Descendants=4), Huge([]))
        with self.assertRaises(contract.ContractError) as error:
            reader.controls(1)
        self.assertEqual(error.exception.code, "a11y-overrun")


class _Point(ctypes.Structure):
    """Stand-in for the comtypes-generated UIAutomation ``tagPOINT``."""

    _fields_ = [("x", ctypes.c_int32), ("y", ctypes.c_int32)]


def widget(name=LABEL, left=200, top=300, right=280, bottom=330):
    node = StrictWidget(name=name)
    node.CurrentBoundingRectangle = types.SimpleNamespace(left=left, top=top, right=right, bottom=bottom)
    return node


class Node(object):
    """Opaque element in the fake tree: only its native identity matters."""


class HitAutomation(FakeAutomation):
    """Fake UIA tree: ElementFromPoint, CompareElements, raw-view parents."""

    def __init__(self, nodes, hit=None, parents=None, compare=None):
        FakeAutomation.__init__(self, nodes)
        self.hit = hit
        self.parents = {} if parents is None else parents
        self.compare = compare
        self.points = []

    @property
    def RawViewWalker(self):
        return self

    def ElementFromPoint(self, point):
        self.points.append((point.x, point.y))
        return self.hit

    def CompareElements(self, left, right):
        return left is right if self.compare is None else self.compare(left, right)

    def GetParentElement(self, element):
        return self.parents.get(element)


class UiaControlIdentityTests(unittest.TestCase):
    """UIA hit identity: the point must reach the ACTUAL selected element."""

    MODULE = types.SimpleNamespace(TreeScope_Descendants=4, tagPOINT=_Point)
    RECT = {"x": 200, "y": 300, "width": 80, "height": 30}

    def reader(self, automation, module=None):
        return windows.UiaReader(self.MODULE if module is None else module, automation)

    def verdict(self, automation):
        return self.reader(automation).hit_test_control(1, LABEL, self.RECT, 240, 315)

    def refusal(self, automation, code, rect=None):
        with self.assertRaises(contract.ContractError) as error:
            self.reader(automation).hit_test_control(1, LABEL, self.RECT if rect is None else rect,
                                                     240, 315)
        self.assertEqual(error.exception.code, code)

    def test_selected_control_and_a_legitimate_child_accept(self):
        target, child = widget(), Node()
        for hit, parents in ((target, {}), (child, {child: target})):
            with self.subTest(hit=hit):
                automation = HitAutomation([target], hit=hit, parents=parents)
                self.assertTrue(self.verdict(automation))
                self.assertEqual(automation.points, [(240, 315)])

    def test_same_root_sibling_or_overlay_at_the_centre_refuses(self):
        target, root = widget(), widget(name="window")
        sibling, overlay = widget(name="解锁"), Node()
        other_root = widget(name="overlay window")
        cases = ((sibling, {sibling: root}), (overlay, {overlay: root}),
                 (overlay, {}), (overlay, {overlay: other_root}))
        for hit, parents in cases:
            with self.subTest(parents=len(parents)):
                self.assertFalse(self.verdict(HitAutomation([target], hit=hit, parents=parents)))

    def test_rect_change_duplicate_and_unknown_label_refuse(self):
        target = widget()
        changed = {"x": 201, "y": 300, "width": 80, "height": 30}
        self.refusal(HitAutomation([target], hit=target), "control-hit", changed)
        self.refusal(HitAutomation([target], hit=target), "control-hit",
                     {"x": 200, "y": 300, "width": 0, "height": 30})
        self.refusal(HitAutomation([widget(), widget()], hit=target), "control-ambiguous")
        self.refusal(HitAutomation([widget(name="解锁")], hit=target), "control-missing")

    def test_cycle_parent_limit_and_query_failures_refuse(self):
        target = widget()
        first, second = widget(name="a"), widget(name="b")
        self.refusal(HitAutomation([target], hit=first,
                                   parents={first: second, second: first}), "a11y-query")

        chain, parents = [Node() for _ in range(windows.MAX_HIT_ELEMENTS + 5)], {}
        for index, node in enumerate(chain[:-1]):
            parents[node] = chain[index + 1]
        self.assertFalse(self.verdict(HitAutomation([target], hit=chain[0], parents=parents)))

        class BrokenCompare(HitAutomation):
            def CompareElements(self, left, right):
                raise OSError("comparison query failed")

        class BrokenWalker(HitAutomation):
            def GetParentElement(self, element):
                raise OSError("walker query failed")

        class BrokenPoint(HitAutomation):
            def ElementFromPoint(self, point):
                raise OSError("point query failed")

        class NoWalker(HitAutomation):
            RawViewWalker = None

        self.refusal(BrokenCompare([target], hit=target), "a11y-query")
        self.refusal(BrokenWalker([target], hit=Node()), "a11y-query")
        self.refusal(BrokenPoint([target], hit=target), "a11y-query")
        self.refusal(NoWalker([target], hit=target), "a11y-unavailable")
        self.assertFalse(self.verdict(HitAutomation([target], hit=None)))

    def test_generated_point_schema_and_native_bool_truth_are_strict(self):
        target = widget()

        class Wide(ctypes.Structure):
            _fields_ = [("x", ctypes.c_int64), ("y", ctypes.c_int64)]

        for module in (types.SimpleNamespace(TreeScope_Descendants=4),
                       types.SimpleNamespace(TreeScope_Descendants=4, tagPOINT=types.SimpleNamespace),
                       types.SimpleNamespace(TreeScope_Descendants=4, tagPOINT=Wide)):
            with self.subTest(module=module):
                with self.assertRaises(contract.ContractError) as error:
                    self.reader(HitAutomation([target], hit=target), module).hit_test_control(
                        1, LABEL, self.RECT, 240, 315)
                self.assertEqual(error.exception.code, "a11y-unavailable")

        # IUIAutomation.CompareElements returns BOOL*, which comtypes surfaces
        # as the integer 1 for TRUE: that is a real match, nothing else is.
        for verdict, accepted in ((True, True), (1, True), (0, False), (2, False),
                                  (-1, False), ("yes", False)):
            with self.subTest(verdict=verdict):
                automation = HitAutomation([target], hit=target,
                                           compare=lambda left, right, v=verdict: v)
                self.assertEqual(
                    self.reader(automation).hit_test_control(1, LABEL, self.RECT, 240, 315),
                    accepted)


class Win32InputBuildingTests(unittest.TestCase):
    """The real ctypes event builders, driven by a recording SendInput spy."""

    def api(self, vk=0x41, metrics=None):
        metrics = {76: 0, 77: 0, 78: 1920, 79: 1080} if metrics is None else metrics

        class User32:
            def __init__(self):
                self.batches = []

            def SendInput(self, count, array, size):
                self.batches.append([array[index] for index in range(count)])
                return count

            def VkKeyScanW(self, code):
                return vk if isinstance(code, str) and len(code) == 1 and ord(code) < 128 else -1

            def GetSystemMetrics(self, name):
                return metrics[name]

        api = windows.Win32Api.__new__(windows.Win32Api)
        api.user32 = User32()
        api.kernel32, api.advapi32 = types.SimpleNamespace(), types.SimpleNamespace()
        return api

    def test_chord_is_one_batch_with_modifier_first_and_released_last(self):
        api = self.api()
        api.press_chord(("Control_L", "a"))
        self.assertEqual(len(api.user32.batches), 1)
        batch = api.user32.batches[0]
        self.assertEqual(len(batch), 4)
        self.assertEqual(batch[0].union.ki.wVk, 0x11)
        self.assertEqual(batch[1].union.ki.wVk, 0x41)
        self.assertEqual(batch[-1].union.ki.wVk, 0x11)
        self.assertEqual(batch[-1].union.ki.dwFlags, windows.KEYEVENTF_KEYUP)

    def test_click_is_one_batch_of_move_down_up(self):
        api = self.api()
        api.click(500, 400)
        self.assertEqual(len(api.user32.batches), 1)
        batch = api.user32.batches[0]
        self.assertEqual(len(batch), 3)
        self.assertEqual(batch[0].union.mi.dwFlags,
                         windows.MOUSEEVENTF_MOVE | windows.MOUSEEVENTF_ABSOLUTE | windows.MOUSEEVENTF_VIRTUALDESK)
        self.assertEqual(batch[1].union.mi.dwFlags, windows.MOUSEEVENTF_LEFTDOWN)
        self.assertEqual(batch[2].union.mi.dwFlags, windows.MOUSEEVENTF_LEFTUP)

    def test_click_normalises_virtual_screen_origin_and_extent(self):
        api = self.api(metrics={76: 100, 77: 200, 78: 1000, 79: 800})
        api.click(350, 400)
        move = api.user32.batches[0][0].union.mi
        self.assertEqual((move.dx, move.dy), (16383, 16383))

    def test_click_outside_virtual_screen_refused(self):
        api = self.api()
        for point in ((-1, 10), (1920, 10), (10, -1), (10, 1080)):
            with self.subTest(point=point):
                with self.assertRaises(contract.ContractError) as error:
                    api.click(*point)
                self.assertEqual(error.exception.code, "control-offscreen")
        self.assertEqual(api.user32.batches, [])

    def test_ascii_text_is_one_unicode_batch_of_two_events_per_char(self):
        api = self.api()
        api.type_text("Aa1!")
        self.assertEqual(len(api.user32.batches), 1)
        batch = api.user32.batches[0]
        self.assertEqual(len(batch), 8)
        for index, char in enumerate("Aa1!"):
            down, up = batch[index * 2], batch[index * 2 + 1]
            self.assertEqual((down.union.ki.wVk, down.union.ki.wScan, down.union.ki.dwFlags),
                             (0, ord(char), windows.KEYEVENTF_UNICODE))
            self.assertEqual((up.union.ki.wScan, up.union.ki.dwFlags),
                             (ord(char), windows.KEYEVENTF_UNICODE | windows.KEYEVENTF_KEYUP))

    def test_zero_sendinput_count_refused(self):
        class EmptyUser32(object):
            def SendInput(self, count, array, size):
                return 0

        api = windows.Win32Api.__new__(windows.Win32Api)
        api.user32 = EmptyUser32()
        with self.assertRaises(contract.ContractError) as error:
            api.type_text("a")
        self.assertEqual(error.exception.code, "input-failed")

    def test_partial_sendinput_prefix_is_unknown_and_never_resent(self):
        class ShortUser32(object):
            def __init__(self):
                self.calls = 0

            def SendInput(self, count, array, size):
                self.calls += 1
                return count - 1

        api = windows.Win32Api.__new__(windows.Win32Api)
        api.user32 = ShortUser32()
        with self.assertRaises(contract.ContractError) as error:
            api.type_text("a")
        self.assertEqual(error.exception.code, "input-unknown")
        self.assertEqual(api.user32.calls, 1)  # the whole batch is never resent

    def test_more_than_512_top_level_windows_refused(self):
        class User32(object):
            def EnumWindows(self, callback, param):
                for handle in range(1, contract.MAX_WINDOWS + 2):
                    if not callback(handle, 0):
                        break
                return 1

        api = windows.Win32Api.__new__(windows.Win32Api)
        api.user32 = User32()
        callback_type = getattr(windows.ctypes, "WINFUNCTYPE", windows.ctypes.CFUNCTYPE)
        with patch.object(windows.ctypes, "WINFUNCTYPE", callback_type, create=True):
            with self.assertRaises(contract.ContractError) as error:
                api.list_windows()
        self.assertEqual(error.exception.code, "window-overrun")

    def test_unknown_key_and_non_ascii_text_refused(self):
        api = self.api()
        with self.assertRaises(contract.ContractError) as error:
            api.press_chord(("NotAKey",))
        self.assertEqual(error.exception.code, "input-unsupported")
        for text in ("naïve", "", "a" * (contract.MAX_TEXT + 1)):
            with self.subTest(text=text[:8]):
                with self.assertRaises(contract.ContractError) as error:
                    api.type_text(text)
                self.assertEqual(error.exception.code, "input-charset")
        self.assertEqual(api.user32.batches, [])


class FakeDll:
    """Fake Win32 DLL that refuses symbols which belong to another DLL."""

    def __init__(self, forbidden=()):
        object.__setattr__(self, "forbidden", frozenset(forbidden))
        object.__setattr__(self, "declared", {})
        object.__setattr__(self, "accessed", [])

    def __getattr__(self, name):
        if name in self.forbidden:
            raise AssertionError("wrong DLL asked for symbol: " + name)
        self.accessed.append(name)
        return FakeFunction(self, name)


class FakeFunction:
    def __init__(self, owner, name):
        object.__setattr__(self, "_owner", owner)
        object.__setattr__(self, "_name", name)

    def __setattr__(self, key, value):
        if key in ("argtypes", "restype"):
            self._owner.declared.setdefault(self._name, set()).add(key)
        object.__setattr__(self, key, value)


def bare_win32():
    return windows.Win32Api.__new__(windows.Win32Api)


def patched_winfunctype():
    return patch.object(windows.ctypes, "WINFUNCTYPE", windows.ctypes.CFUNCTYPE, create=True)


class Win32DllOwnershipTests(unittest.TestCase):
    """GetCurrentProcess belongs to kernel32; user32 must never be asked for it."""

    def test_signatures_declare_get_current_process_on_kernel32_only(self):
        api = bare_win32()
        api.user32 = FakeDll(forbidden=("GetCurrentProcess",))
        api.kernel32, api.advapi32 = FakeDll(), FakeDll()
        api._signatures()
        self.assertEqual(api.kernel32.declared["GetCurrentProcess"], {"argtypes", "restype"})
        self.assertNotIn("GetCurrentProcess", api.user32.declared)
        self.assertNotIn("GetCurrentProcess", api.user32.accessed)

    def test_same_user_reads_the_pseudo_handle_from_kernel32(self):
        api = bare_win32()
        api.user32 = FakeDll(forbidden=("GetCurrentProcess",))
        api.kernel32 = types.SimpleNamespace(GetCurrentProcess=lambda: 0x1234)
        api.advapi32 = types.SimpleNamespace(EqualSid=lambda left, right: True)
        seen = []

        def sid_pair(handle):
            seen.append(handle)
            return (b"token", handle)

        api._sid_pair = sid_pair
        self.assertTrue(api.same_user(0x9999))
        self.assertEqual(seen, [0x1234, 0x9999])


class FakeDesktopUser32:
    """Fake OpenInputDesktop/GetUserObjectInformationW surface."""

    def __init__(self, handle=0x44, info=True, name="Default"):
        self.handle, self.info, self.name = handle, info, name
        self.opened = self.closed = self.queried = 0

    def OpenInputDesktop(self, flags, inherit, access):
        self.opened += 1
        return self.handle

    def GetUserObjectInformationW(self, handle, index, buffer, size, needed):
        self.queried += 1
        if not self.info:
            return 0
        buffer.value = self.name
        return 1

    def CloseDesktop(self, handle):
        self.closed += 1


class Win32SecureDesktopTests(unittest.TestCase):
    """An unknown input desktop fails closed; it never means "not secure"."""

    def api(self, **options):
        api = bare_win32()
        api.user32 = FakeDesktopUser32(**options)
        return api

    def test_unknown_desktop_identity_is_the_fixed_capability_refusal(self):
        for options in ({"handle": 0}, {"info": False}):
            with self.subTest(options=options):
                with self.assertRaises(contract.ContractError) as error:
                    self.api(**options).input_desktop_secure()
                self.assertEqual(error.exception.code, "capability-unavailable")

    def test_open_failure_never_queries_and_never_reports_not_secure(self):
        api = self.api(handle=0)
        with self.assertRaises(contract.ContractError):
            api.input_desktop_secure()
        self.assertEqual((api.user32.queried, api.user32.closed), (0, 0))

    def test_query_failure_still_closes_the_handle(self):
        api = self.api(info=False)
        with self.assertRaises(contract.ContractError):
            api.input_desktop_secure()
        self.assertEqual(api.user32.closed, 1)

    def test_named_default_and_non_default_desktops(self):
        self.assertFalse(self.api().input_desktop_secure())
        self.assertTrue(self.api(name="Winlogon").input_desktop_secure())

    def test_adapter_refuses_before_any_observation_when_the_desktop_is_unknown(self):
        class UnknownDesktop(FakeWin32):
            def input_desktop_secure(self):
                raise contract.ContractError("capability-unavailable")

        adapter = windows.WindowsAdapter(api=UnknownDesktop(), uia=FakeUia())
        with self.assertRaises(contract.ContractError) as error:
            adapter.check_capability()
        self.assertEqual(error.exception.code, "capability-unavailable")


class Win32EnumerationTests(unittest.TestCase):
    """A failed EnumWindows is a refusal, never a short "unique" window list."""

    def test_false_enumeration_is_a_window_query_refusal(self):
        class User32(object):
            def EnumWindows(self, callback, param):
                for handle in (1, 2):
                    if not callback(handle, 0):
                        break
                return 0  # FALSE without our own overflow stop

        api = bare_win32()
        api.user32 = User32()
        api._describe = lambda hwnd: (_ for _ in ()).throw(AssertionError("partial list used"))
        with patched_winfunctype():
            with self.assertRaises(contract.ContractError) as error:
                api.list_windows()
        self.assertEqual(error.exception.code, "window-query")

    def test_true_enumeration_returns_the_bounded_list(self):
        class User32(object):
            def EnumWindows(self, callback, param):
                callback(7, 0)
                return 1

        api = bare_win32()
        api.user32 = User32()
        api._describe = lambda hwnd: {"id": hwnd}
        with patched_winfunctype():
            self.assertEqual(api.list_windows(), [{"id": 7}])

    def test_overflow_keeps_its_own_window_overrun_refusal(self):
        class User32(object):
            def EnumWindows(self, callback, param):
                for handle in range(1, contract.MAX_WINDOWS + 2):
                    if not callback(handle, 0):
                        break
                return 1

        api = bare_win32()
        api.user32 = User32()
        with patched_winfunctype():
            with self.assertRaises(contract.ContractError) as error:
                api.list_windows()
        self.assertEqual(error.exception.code, "window-overrun")


class StrictQuartz:
    """Only AXIsProcessTrusted exists; any other symbol is a hard failure."""

    def __init__(self, trusted=True):
        self.trusted = trusted

    def AXIsProcessTrusted(self):
        return self.trusted

    def __getattr__(self, name):
        raise AssertionError("forbidden ApplicationServices symbol: " + name)


class FakeMacApi:
    def __init__(self, windows_list=None, controls=None, focus=4242, trusted=True, secure=False,
                 focus_window=None, root=True, visible=True, control_hit=True):
        self.windows_list = [dict(WINDOW_RAW, secure=secure)] if windows_list is None else windows_list
        self._controls = [dict(CONTROL)] if controls is None else controls
        self.control_hit = control_hit
        self.hit_calls = []
        self.focus = focus
        self.focus_window = WINDOW_RAW["id"] if focus_window is None else focus_window
        self.root = root
        self.visible = visible
        self.display_bounds = [(0, 0, 3840, 2160)]
        self.display_error = None
        self.display_queries = 0
        self.trusted = trusted
        self.activations = 0
        self.clicks = []
        self.typed = []
        self.chords = []
        # Activation-only surface: exactly one pre-verified identity.
    def capability(self):
        if not self.trusted:
            raise contract.ContractError("capability-unavailable")

    def list_windows(self):
        return [dict(item) for item in self.windows_list]

    def controls(self, window):
        return [dict(item) for item in self._controls]

    def foreground_pid(self):
        return self.focus

    def focus_state(self, window=None):
        return {"pid": self.focus, "window": self.focus_window}

    def root_at(self, window, x, y):
        return self.root

    def hit_test_control(self, window, label, rect, x, y):
        self.hit_calls.append((window["id"], label, dict(rect), x, y))
        return self.control_hit

    def point_visible(self, window, x, y):
        # Real QuartzApi.point_visible: membership only, with a replaceable
        # ``display_bounds`` so tests can move the active display.
        self.display_queries = getattr(self, "display_queries", 0) + 1
        if self.display_error is not None:
            raise self.display_error
        return any(left <= x < left + width and top <= y < top + height
                   for left, top, width, height in self.display_bounds)

    def activate(self, pid):
        self.activations += 1
        return True

    def click(self, x, y):
        self.clicks.append((x, y))
        return {"move": True, "down": True, "up": True}

    def type_text(self, text):
        self.typed.append(text)
        return {"move": True, "down": True, "up": True}

    def press_chord(self, parts):
        self.chords.append(tuple(parts))
        return {"move": True, "down": True, "up": True}


class FakeRunningApplication:
    def __init__(self, verdict=True):
        self.verdict = verdict
        self.options = []

    def activateWithOptions_(self, options):
        self.options.append(options)
        if isinstance(self.verdict, Exception):
            raise self.verdict
        return self.verdict


class FakeWorkspaceAppKit:
    """Strict AppKit stand-in: only the one NSRunningApplication lookup and the
    one exported activation option exist; every other symbol is an error."""

    # Deliberately not the SDK integer: only the named export may be used.
    NSApplicationActivateIgnoringOtherApps = object()

    def __init__(self, running=None):
        self.running = running
        self.lookups = []
        self.our_appkit = self

        class NSRunningApplication(object):
            pass

        @staticmethod
        def by_pid(pid):
            self.lookups.append(pid)
            return self.running

        NSRunningApplication.runningApplicationWithProcessIdentifier_ = by_pid
        self.NSRunningApplication = NSRunningApplication

    def __getattr__(self, name):
        raise AssertionError("activation touched AppKit symbol " + name)


def activation_api(path="/opt/locklark/locklark-desktop", uid=None, running=None):
    """QuartzApi with ONLY process identity and one AppKit activation bound.

    Any other attribute (windows, AX elements, titles, controls, foreground,
    event posting) fails the test if the activation-only path touches it.
    """
    uid = os.getuid() if uid is None else uid
    api = macos.QuartzApi.__new__(macos.QuartzApi)
    api.process = lambda pid: (path, uid == os.getuid())
    api.appkit = FakeWorkspaceAppKit(running)
    return api


def assert_named_activation_options(test, api, running):
    """The one activation received the exact exported AppKit option object."""
    option = api.appkit.NSApplicationActivateIgnoringOtherApps
    test.assertEqual(len(running.options), 1)
    test.assertIs(running.options[0], option)


class MacActivationOnlyTests(unittest.TestCase):
    PID = 4242
    EXE = "/opt/locklark/locklark-desktop"

    def run_driver(self, api):
        """Real MacAdapter + driver dispatch on an injected activation-only API."""
        raw = json.dumps({"activate_pid": self.PID, "executable": self.EXE}).encode()
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(macos.MacAdapter, "__init__",
                          lambda self, *a, **k: setattr(self, "api", api)):
            status = driver.main(argv=["--platform", "macos"], stdin=io.BytesIO(raw),
                                 stdout=stdout, stderr=stderr)
        return status, stdout.getvalue(), stderr.getvalue()

    def test_success_is_one_fixed_result_after_exactly_one_activation(self):
        running = FakeRunningApplication(True)
        api = activation_api(running=running)
        self.assertEqual(self.run_driver(api), (0, '{"activated": true}\n', ""))
        self.assertEqual(api.appkit.lookups, [self.PID])
        assert_named_activation_options(self, api, running)

    def test_trusted_real_api_path_checks_pid_path_and_uid_before_one_activation(self):
        requested = macos.QuartzApi.activate_process
        api = macos.QuartzApi.__new__(macos.QuartzApi)
        running = FakeRunningApplication(True)
        api.appkit = FakeWorkspaceAppKit(running)
        looked_up = []

        def process(pid):
            looked_up.append(pid)
            return self.EXE, True

        api.process = process
        self.assertIs(requested(api, self.PID, self.EXE), True)
        self.assertEqual(looked_up, [self.PID])
        self.assertEqual(api.appkit.lookups, [self.PID])
        assert_named_activation_options(self, api, running)

    def test_identity_refusals_never_activate(self):
        # (process() answer, expected refusal). "" means the pid is absent.
        cases = (
            (("/opt/locklark/other-desktop", True), "process-untrusted"),
            ((self.EXE + "-copy", True), "process-untrusted"),
            (("", False), "activation-failed"),
            ((self.EXE, False), "process-untrusted"),
        )
        for answer, code in cases:
            with self.subTest(answer=answer), \
                    patch.object(macos.os, "stat", side_effect=AssertionError("file owner used")):
                running = FakeRunningApplication(True)
                api = activation_api(running=running)
                api.process = lambda pid, answer=answer: answer
                status, stdout, stderr = self.run_driver(api)
                self.assertEqual((status, stdout), (1, ""))
                self.assertIn("code=%s action=activate" % code, stderr)
                self.assertEqual(api.appkit.lookups, [])
                self.assertEqual(running.options, [])

    def test_absent_application_or_failed_activation_is_a_refusal(self):
        for running in (None, FakeRunningApplication(False)):
            with self.subTest(running=running):
                api = activation_api(running=running)
                status, stdout, stderr = self.run_driver(api)
                self.assertEqual((status, stdout), (1, ""))
                self.assertIn("code=activation-failed", stderr)
                self.assertNotIn(self.EXE, stderr)
                if isinstance(running, FakeRunningApplication):
                    assert_named_activation_options(self, api, running)

    def test_activation_exception_is_one_refusal_and_no_retry(self):
        running = FakeRunningApplication(RuntimeError("boom"))
        api = activation_api(running=running)
        status, stdout, stderr = self.run_driver(api)
        self.assertEqual((status, stdout), (1, ""))
        self.assertIn("code=activation-failed", stderr)
        assert_named_activation_options(self, api, running)

    def test_process_without_an_activation_hook_never_claims_success(self):
        api = activation_api(running=FakeRunningApplication(True))

        class Hookless(object):
            supports_activation = True

        plan = contract.parse_request(json.dumps(
            {"activate_pid": self.PID, "executable": self.EXE}))
        with self.assertRaises(contract.ContractError) as error:
            contract.execute(plan, Hookless())
        self.assertEqual(error.exception.code, "activation-unsupported")
        self.assertEqual(api.appkit.lookups, [])

    def test_non_macos_adapter_does_not_claim_activation_success(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        win32 = FakeWin32()
        injected = windows.WindowsAdapter(api=win32, uia=FakeUia())
        with patch.object(windows.WindowsAdapter, "__init__",
                          lambda self: self.__dict__.update(injected.__dict__)):
            status = driver.main(argv=["--platform", "windows"],
                                 stdin=io.BytesIO(json.dumps(
                                     {"activate_pid": self.PID, "executable": EXE}).encode()),
                                 stdout=stdout, stderr=stderr)
        self.assertEqual((status, stdout.getvalue()), (1, ""))
        self.assertIn("code=activation-unsupported", stderr.getvalue())
        self.assertEqual((win32.activations, win32.clicks), (0, []))


class MacCapabilityTests(unittest.TestCase):
    def test_untrusted_accessibility_is_a_fixed_refusal_without_a_prompt(self):
        api = macos.QuartzApi(quartz=StrictQuartz(False), appkit=types.SimpleNamespace())
        with self.assertRaises(contract.ContractError) as error:
            api.capability()
        self.assertEqual(error.exception.code, "capability-unavailable")

    def test_trusted_accessibility_is_only_queried(self):
        api = macos.QuartzApi(quartz=StrictQuartz(True), appkit=types.SimpleNamespace())
        self.assertTrue(api.capability() is None)

    def test_untrusted_adapter_refuses_before_listing_windows(self):
        api = FakeMacApi(trusted=False)
        adapter = macos.MacAdapter(api=api)
        with self.assertRaises(contract.ContractError) as error:
            execute(adapter, document())
        self.assertEqual(error.exception.code, "capability-unavailable")
        self.assertEqual(api.clicks, [])


class NativeNSString(str):
    """Stand-in for objc.pyobjc_unicode: a str subclass, not an exact str."""


class MacAdapterTests(unittest.TestCase):
    def test_one_physical_click_after_focus_verification(self):
        api = FakeMacApi()
        adapter = macos.MacAdapter(api=api)
        result = execute(adapter, document())
        self.assertEqual(api.clicks, [(240, 315)])
        self.assertEqual(result["clicks"][0]["label"], LABEL)
        self.assertEqual(api.activations, 0)

    def test_preserve_focus_refuses_instead_of_stealing_focus(self):
        api = FakeMacApi(windows_list=[dict(WINDOW_RAW, title="Locklark acceptance popup")], focus=999)
        adapter = macos.MacAdapter(api=api)
        with self.assertRaises(contract.ContractError) as error:
            execute(adapter, document(title=None, title_prefix="Locklark acceptance", preserve_focus=True))
        self.assertEqual(error.exception.code, "preserve-focus-lost")
        self.assertEqual(api.activations, 0)
        self.assertEqual(api.clicks, [])

    def test_secure_agent_window_refused(self):
        api = FakeMacApi(secure=True)
        with self.assertRaises(contract.ContractError) as error:
            execute(macos.MacAdapter(api=api), document())
        self.assertEqual(error.exception.code, "secure-desktop")
        self.assertEqual(api.clicks, [])

    def test_extra_widget_field_is_rejected_unread(self):
        api = FakeMacApi(controls=[dict(CONTROL, value="synthetic-private-canary-value")])
        with self.assertRaises(contract.ContractError) as error:
            execute(macos.MacAdapter(api=api), document())
        self.assertEqual(error.exception.code, "a11y-query")

    def test_native_string_title_is_normalised_to_exact_str(self):
        # objc.pyobjc_unicode stand-in: a str subclass equality accepts but
        # type() does not. Shared title_matches must keep demanding exact str.
        native = NativeNSString(TITLE)
        self.assertEqual(native, TITLE)
        self.assertIs(type(native), NativeNSString)
        self.assertFalse(contract.title_matches({"title": TITLE, "title_prefix": None},
                                                {"title": native}))
        window = macos.MacAdapter(api=FakeMacApi())._normalise(dict(WINDOW_RAW, title=native))
        self.assertIs(type(window["title"]), str)
        self.assertEqual(window["title"], TITLE)
        self.assertTrue(contract.title_matches({"title": TITLE, "title_prefix": None}, window))
        result = execute(macos.MacAdapter(
            api=FakeMacApi(windows_list=[dict(WINDOW_RAW, title=native)])), document())
        self.assertEqual(result["window"], "0x200003")

    def real_quartz_api(self, ax_value):
        """Real QuartzApi.list_windows over fake CG entries and one AX window.

        The CG window has an empty CGWindowName, so list_windows must take its
        AX fallback (QuartzApi._ax_title -> QuartzApi.title), whose raw AXTitle
        is ``ax_value``.
        """
        cg_entry = {"layer": 0, "pid": WINDOW_RAW["pid"], "number": WINDOW_RAW["id"],
                    "name": "", "bounds": {"X": 100, "Y": 100, "Width": 800, "Height": 600}}
        ax_window = {"title": ax_value}
        queried = []

        def copy_attribute(element, name, out):
            queried.append(name)
            if name in ("AXValue", "AXSelectedText", "AXRole", "AXChildren"):
                raise AssertionError("forbidden accessibility attribute requested: " + name)
            if name == "AXWindows":
                return 0, [ax_window]
            return 0, {"AXTitle": ax_window["title"]}.get(name)

        quartz = types.SimpleNamespace(
            kCGWindowListOptionOnScreenOnly=1, kCGWindowListExcludeDesktopElements=16,
            kCGNullWindowID=0, kCGWindowLayer="layer", kCGWindowOwnerPID="pid",
            kCGWindowNumber="number", kCGWindowBounds="bounds", kCGWindowName="name",
            CGWindowListCopyWindowInfo=lambda options, identifier: [dict(cg_entry)])
        ax = types.SimpleNamespace(
            kAXWindowsAttribute="AXWindows", kAXErrorNoValue=NO_VALUE,
            AXUIElementCreateApplication=lambda pid: ax_window,
            AXUIElementCopyAttributeValue=copy_attribute)
        api = macos.QuartzApi(quartz=quartz, appkit=types.SimpleNamespace(), ax=ax)
        api.process = lambda pid: (WINDOW_RAW["executable"], True)
        return api, queried

    def test_ax_fallback_title_is_exact_str_for_exact_find_window(self):
        native = NativeNSString(TITLE)
        api, queried = self.real_quartz_api(native)
        # The raw AX (and raw CG fallback) title is the native subclass only.
        self.assertIs(type(api.title(api.windows(WINDOW_RAW["pid"])[0])), str)
        raw = api.list_windows()
        self.assertEqual(len(raw), 1)
        self.assertIs(type(raw[0]["title"]), str)
        self.assertEqual(raw[0]["title"], TITLE)
        self.assertEqual(set(queried), {"AXWindows", "AXTitle"},
                         "only the AX window list and its AXTitle are read")
        adapter = macos.MacAdapter(api=api)
        window = contract.find_window({"title": TITLE, "title_prefix": None, "executable": EXE},
                                      adapter, contract.Budget())
        self.assertIs(type(window["title"]), str)
        self.assertEqual(window["executable"], EXE)
        self.assertEqual((window["id"], window["pid"]), (WINDOW_RAW["id"], WINDOW_RAW["pid"]))

    def test_non_string_ax_fallback_fails_closed_at_real_list_windows(self):
        class HostileValue(object):
            def __str__(self):
                raise AssertionError("arbitrary str() was called")

            def __eq__(self, other):
                raise AssertionError("hostile AX value was compared")

            def __bool__(self):
                raise AssertionError("hostile AX value was tested for truth")

        for value in (HostileValue(), 7, b"Locklark", ["Locklark"], None):
            with self.subTest(value=type(value).__name__):
                api, _ = self.real_quartz_api(value)
                adapter = macos.MacAdapter(api=api)
                windows_seen = adapter.list_windows()
                self.assertEqual(windows_seen[0]["title"], "")
                self.assertIs(type(windows_seen[0]["title"]), str)
                self.assertFalse(contract.title_matches({"title": TITLE, "title_prefix": None},
                                                        windows_seen[0]))
                with patch.object(contract, "DISCOVER_TIMEOUT", 0):
                    with self.assertRaises(contract.ContractError) as error:
                        contract.find_window({"title": TITLE, "title_prefix": None,
                                              "executable": EXE}, adapter, contract.Budget())
                self.assertEqual(error.exception.code, "window-timeout")

    def test_non_string_native_title_keeps_safe_empty_title(self):
        class Hostile(object):
            def __str__(self):
                raise AssertionError("arbitrary str() was called")

            def __eq__(self, other):
                raise AssertionError("hostile title was compared")

        adapter = macos.MacAdapter(api=FakeMacApi())
        for value in (Hostile(), None, 7, b"Locklark", ["Locklark"]):
            with self.subTest(value=type(value).__name__):
                window = adapter._normalise(dict(WINDOW_RAW, title=value, executable=value))
                self.assertEqual(window["title"], "")
                self.assertIs(type(window["title"]), str)
                self.assertEqual(window["executable"], "")
                self.assertFalse(contract.title_matches({"title": TITLE, "title_prefix": None}, window))

    def test_same_pid_other_ax_window_refused(self):
        api = FakeMacApi(focus_window=0x200004)
        adapter = macos.MacAdapter(api=api)
        with self.assertRaises(contract.ContractError) as error:
            execute(adapter, document())
        self.assertEqual(error.exception.code, "focus-lost")
        self.assertEqual(api.activations, 1)
        self.assertEqual(api.clicks, [])

    def test_click_point_must_resolve_to_the_bound_ax_window(self):
        api = FakeMacApi(root=False)
        adapter = macos.MacAdapter(api=api)
        with self.assertRaises(contract.ContractError) as error:
            execute(adapter, document(actions=[{"click": [10, 20]}]))
        self.assertEqual(error.exception.code, "control-offscreen")
        self.assertEqual(api.clicks, [])

    def test_success_click_is_posted_evidence_without_title(self):
        result = execute(macos.MacAdapter(api=FakeMacApi()), document())
        self.assertEqual(result["clicks"][0]["evidence"], "posted")
        self.assertNotIn("title", result)


    def test_adapter_hit_verdict_is_strictly_boolean(self):
        rect = dict(CONTROL["bounds"])
        for verdict, expected in ((True, True), (1, False), (-1, False), (None, False)):
            with self.subTest(verdict=verdict):
                adapter = macos.MacAdapter(api=FakeMacApi(control_hit=verdict))
                self.assertEqual(adapter.hit_test_control(dict(WINDOW_RAW), LABEL, rect, 240, 315),
                                 expected)


class MacProcessIdentityTests(unittest.TestCase):
    def api(self, pidinfo_result=0):
        class LibProc(object):
            def proc_pidpath(self, pid, buffer, size):
                buffer.value = b"/opt/locklark/test-browser"
                return len(buffer.value)

            def proc_pidinfo(self, pid, flavor, argument, buffer, size):
                return pidinfo_result

        api = macos.QuartzApi.__new__(macos.QuartzApi)
        api.libproc = LibProc()
        return api

    def test_unknown_process_uid_never_falls_back_to_the_file_owner(self):
        api = self.api(pidinfo_result=0)
        with patch.object(macos.os, "stat", side_effect=AssertionError("file owner used")):
            path, trusted = api.process(4242)
        self.assertEqual(path, "/opt/locklark/test-browser")
        self.assertFalse(trusted)

    def test_same_process_uid_is_trusted_without_any_stat(self):
        api = self.api()
        api.process_uid = lambda pid: os.getuid()
        with patch.object(macos.os, "stat", side_effect=AssertionError("file owner used")):
            path, trusted = api.process(4242)
        self.assertTrue(trusted)


class MacAxWalkTests(unittest.TestCase):
    def button(self, **overrides):
        value = {"role": "AXButton", "title": LABEL, "enabled": True, "hidden": False,
                 "children": [], "frame": {"x": 200, "y": 300, "width": 80, "height": 30}}
        value.update(overrides)
        return value

    def api(self, button=None, tree_windows=None):
        api = macos.QuartzApi.__new__(macos.QuartzApi)
        api.ax = types.SimpleNamespace(kAXWindowsAttribute="AXWindows")
        names = []
        tree = {"title": TITLE, "frame": dict(WINDOW_RAW["bounds"]), "children": [
            self.button() if button is None else button,
            {"role": "AXTextField", "title": "unlisted private label", "enabled": True, "hidden": False,
             "children": [], "frame": {"x": 0, "y": 0, "width": 10, "height": 10}},
        ]}
        api.tree = tree
        if tree_windows is None:
            tree_windows = [tree]

        def attribute(element, name):
            names.append(name)
            if name in ("AXValue", "AXSelectedText"):
                raise AssertionError("forbidden accessibility attribute requested: " + name)
            return {"AXRole": element.get("role"), "AXTitle": element.get("title"),
                    "AXDescription": element.get("description"),
                    "AXEnabled": element.get("enabled"), "AXHidden": element.get("hidden"),
                    "AXChildren": element.get("children")}.get(name)

        api.attribute = attribute
        api.windows = lambda pid: list(tree_windows)
        api.title = lambda element: element.get("title") or element.get("description") or ""
        api.frame = lambda element: element["frame"]
        return api, names

    def refused(self, api, code):
        with self.assertRaises(contract.ContractError) as error:
            api.controls(dict(WINDOW_RAW))
        self.assertEqual(error.exception.code, code)

    def test_walk_reads_only_public_metadata_and_drops_unknown_labels(self):
        api, names = self.api()
        controls = api.controls(dict(WINDOW_RAW))
        self.assertEqual(len(controls), 1)
        self.assertEqual(set(controls[0]), set(contract.WIDGET_FIELDS))
        self.assertEqual(controls[0]["role"], "push button")
        self.assertNotIn("AXValue", names)
        self.assertNotIn("AXSelectedText", names)

    def test_walk_requires_an_exact_window_binding(self):
        api, _ = self.api()
        with self.assertRaises(contract.ContractError) as error:
            api.controls(dict(WINDOW_RAW, title="another window"))
        self.assertEqual(error.exception.code, "a11y-query")

    def test_ambiguous_ax_window_binding_refused(self):
        api, _ = self.api()
        api.windows = lambda pid: [api.tree, api.tree]
        self.refused(api, "window-ambiguous")

    def test_unknown_enabled_or_hidden_state_refused(self):
        for overrides in ({"enabled": None}, {"hidden": None}, {"enabled": 1}, {"hidden": "no"}):
            with self.subTest(overrides=overrides):
                self.refused(self.api(button=self.button(**overrides))[0], "a11y-unavailable")

    def test_control_without_positive_bounds_refused(self):
        button = self.button(frame={"x": 200, "y": 300, "width": 0, "height": 30})
        self.refused(self.api(button=button)[0], "control-geometry")


# Measured on a real owned app: one CG window and one same-title AXWindow
# whose frame is exactly one point inside every CG edge, same centre.
MEASURED_CG = {"x": 313, "y": 75, "width": 1102, "height": 822}
MEASURED_AX = {"x": 314, "y": 76, "width": 1100, "height": 820}
# The fixed refusal a caller sees when the unique binding cannot be proven.
BINDING_REFUSAL = "a11y-query"


def measured_window(**overrides):
    value = dict(WINDOW_RAW, bounds=dict(MEASURED_CG))
    value.update(overrides)
    return value


def ax_window(title=None, frame=None, role="AXWindow", focused=None):
    return {"role": role, "title": TITLE if title is None else title,
            "frame": dict(MEASURED_CG if frame is None else frame), "children": [],
            "focused": False if focused is None else focused}


class MacWindowIdentityTests(unittest.TestCase):
    """Exact title plus exact frame OR the one canonical border inset; no more.

    The AX<->CG binding runs the real ``window_element``, ``_identity_matches``,
    ``focus_state`` and ``root_at`` over an AX tree. Only the frame relation may
    differ from equality; a title mismatch, a second same-title AX window or any
    other frame refuses. The AX fake serves only the window list, titles and
    public control metadata, so entering a factor/field value fails a test.
    """

    def api(self, tree_windows, window=None):
        api = macos.QuartzApi.__new__(macos.QuartzApi)
        api.quartz = types.SimpleNamespace()  # CFEqual source list only
        # One opaque application element per graph (never a window or a dict).
        app = (id(api), "AXApplication")
        # The public AXValue types only satisfy the real frame() signature;
        # no AXValue payload is ever produced or read by these fixtures.
        api.ax = types.SimpleNamespace(
            kAXWindowsAttribute="AXWindows", kAXErrorNoValue=NO_VALUE,
            kAXValueCGPointType="AXValueCGPointType",
            kAXValueCGSizeType="AXValueCGSizeType",
            AXIsProcessTrusted=lambda: True,
            AXValueGetValue=self.ax_value_get_value,
            AXUIElementCreateApplication=lambda pid: app,
            AXUIElementCopyAttributeValue=self.attribute(tree_windows, app),
            AXUIElementCopyElementAtPosition=lambda app, x, y, out: (1, None))
        api.window_list = [window if window is not None else measured_window()]
        api.list_windows = lambda: [dict(item) for item in api.window_list]
        api.process = lambda pid: (EXE, True)
        # Spies around the real probes so "never read" is observable.
        api.control_reads, api.hit_reads = [], []

        def controls(window):
            # Recorded only after the real bounded walk returned controls, so
            # a binding refusal inside the walk is not a control read.
            value = macos.QuartzApi.controls(api, window)
            api.control_reads.append(window["id"])
            return value

        def hit(window, label, rect, x, y):
            api.hit_reads.append((window["id"], label))
            return macos.QuartzApi.hit_test_control(api, window, label, rect, x, y)

        api.controls, api.hit_test_control = controls, hit
        api.point_visible = lambda window, x, y: True
        api.activate = lambda pid: True  # nothing below may reach input anyway
        api.foreground_pid = lambda: WINDOW_RAW["pid"]
        api.clicks, api.typed, api.chords = [], [], []
        api.click = lambda x, y: api.clicks.append((x, y)) or {"move": True, "down": True, "up": True}
        api.type_text = lambda text: api.typed.append(text) or {"move": True, "down": True, "up": True}
        api.press_chord = lambda parts: api.chords.append(tuple(parts)) or {
            "move": True, "down": True, "up": True}
        api.inputs = lambda: (api.clicks, api.typed, api.chords)

        api.focus_reads = []

        def focus(window=None):  # the real bound-window check, instance-bound
            api.focus_reads.append(None if window is None else window["id"])
            return macos.QuartzApi.focus_state(api, window)

        def root(window, x, y):  # the real hit-to-AXWindow walk, instance-bound
            return macos.QuartzApi.root_at(api, window, x, y)

        api.focus_state, api.root_at = focus, root
        return api

    def identity_api(self, tree_windows, window=None):
        """The fixture above plus the ONLY native identity CFEqual may answer.

        ``CFEqual`` is true only for two references to the very same object
        AXWindows holds: a second dict built with the same title and frame is a
        distinct AXUIElement and never equal.  Any other pair - two distinct
        listed elements, a listed/unlisted pair or two unlisted objects - is
        false.  Nothing here compares values or member counts.
        """
        api = self.api(tree_windows, window)

        def cf_equal(left, right):
            return left is right and any(item is left for item in self.listed(api))

        api.ax.CFEqual = cf_equal
        # The application and its AXWindows answer the same AX elements.
        listed = api.ax_windows_source = list(tree_windows)
        app = (id(api), "AXApplication")  # per graph, never a window or an app dict
        api.ax.AXUIElementCreateApplication = lambda pid: app
        api.ax.AXUIElementCopyAttributeValue = self.attribute(listed, app)
        return api

    @staticmethod
    def listed(api):
        """The fake's live AXWindows list (the AX elements this app serves)."""
        return api.ax_windows_source

    def attribute(self, tree_windows, application_element=None):
        source = tree_windows

        def attribute(element, name, out):
            if name in ("AXValue", "AXSelectedText", "AXValueType"):
                raise AssertionError("forbidden accessibility attribute requested: " + name)
            if name == "AXWindows":
                # The application element owns the window list; any other
                # element has no such attribute (kAXErrorNoValue).
                return (0, list(source)) if element is application_element else (-25205, None)
            if name == "AXFocusedWindow":
                # The focused window is one of the AXWindows elements, or
                # kAXErrorNoValue when the OS exposes none.
                focused = next((item for item in source if item.get("focused")), None)
                return (-25205, None) if focused is None else (0, focused)
            if element is application_element:  # no other application attribute
                return -25205, None
            if name in ("AXPosition", "AXSize") and element.get("frame") is not None:
                frame = element["frame"]
                if name == "AXPosition":
                    return 0, ("AXValueCGPointType", (frame["x"], frame["y"]))
                return 0, ("AXValueCGSizeType", (frame["width"], frame["height"]))
            return 0, {"AXRole": element.get("role"), "AXTitle": element.get("title"),
                       "AXDescription": element.get("description"),
                       "AXChildren": element.get("children"),
                       "AXEnabled": element.get("enabled"), "AXHidden": element.get("hidden"),
                       "AXParent": element.get("parent")}.get(name)
        return attribute

    @staticmethod
    def ax_value_get_value(value, kind, out):
        """AXValueGetValue over an (AXValue type, (first, second)) fixture."""
        value_kind, payload = value
        return value_kind == kind, types.SimpleNamespace(
            x=payload[0], y=payload[1], width=payload[0], height=payload[1])

    def ax_windows(self, api):
        return api.windows(WINDOW_RAW["pid"])

    @staticmethod
    def without_identity_refusal(call, *args):
        """The verdict, or (None, refusal) when the unique binding refuses.

        ``focus_state`` and ``root_at`` give ``_identity_matches`` an element
        and let ``window_element``'s fixed refusal escape instead of reporting
        a guessed identity; that is the fail-closed "no identity" outcome.
        """
        try:
            return call(*args)
        except contract.ContractError as error:
            if error.code not in ("a11y-query", "window-ambiguous"):
                raise
            return None, error.code

    def refusal(self, api, code):
        with self.assertRaises(contract.ContractError) as error:
            api.window_element(dict(api.window_list[0]))
        self.assertEqual(error.exception.code, code)
        return error.exception

    # -- accepted relations -------------------------------------------------
    def test_exact_frame_binds(self):
        api = self.identity_api([ax_window(frame=MEASURED_CG)])
        self.assertIs(api.window_element(dict(api.window_list[0])), self.ax_windows(api)[0])
        self.assertEqual(macos._frame_relation(dict(MEASURED_CG), dict(MEASURED_CG)), "exact")
        self.assertTrue(api._identity_matches(self.ax_windows(api)[0], api.window_list[0]))

    def test_measured_canonical_border_inset_binds(self):
        # CG {313,75,1102,822} / AX {314,76,1100,820}: one point inside every
        # edge, identical centre.
        api = self.identity_api([ax_window(frame=MEASURED_AX)])
        self.assertIs(api.window_element(dict(api.window_list[0])), self.ax_windows(api)[0])
        self.assertEqual(macos.AX_CG_BORDER_INSET, 1)
        self.assertEqual(macos._frame_relation(dict(MEASURED_AX), dict(MEASURED_CG)), "border-inset")
        self.assertTrue(api._identity_matches(self.ax_windows(api)[0], api.window_list[0]))

    def test_relation_is_arithmetic_not_a_measured_coordinate(self):
        # A secondary display can have a negative origin; the same arithmetic
        # relation applies there.
        for bounds, frame in (
                ({"x": 0, "y": 0, "width": 804, "height": 604},
                 {"x": 1, "y": 1, "width": 802, "height": 602}),
                ({"x": -1200, "y": -200, "width": 804, "height": 604},
                 {"x": -1199, "y": -199, "width": 802, "height": 602})):
            with self.subTest(bounds=bounds):
                api = self.api([ax_window(frame=frame)],
                               window=dict(WINDOW_RAW, bounds=bounds))
                self.assertIs(api.window_element(dict(api.window_list[0])),
                              self.ax_windows(api)[0])

    # -- refused relations --------------------------------------------------
    def test_center_shift_larger_smaller_or_partial_inset_refuses(self):
        cases = {
            "center-shift-right": {"x": 315, "y": 76, "width": 1100, "height": 820},
            "center-shift-down": {"x": 314, "y": 77, "width": 1100, "height": 820},
            "center-shift-left": {"x": 313, "y": 76, "width": 1100, "height": 820},
            "left-edge-only": {"x": 314, "y": 75, "width": 1101, "height": 822},
            "top-edge-only": {"x": 313, "y": 76, "width": 1102, "height": 821},
            "right-edge-only": {"x": 313, "y": 75, "width": 1101, "height": 822},
            "bottom-edge-only": {"x": 313, "y": 75, "width": 1102, "height": 821},
            "anti-diagonal-edges-only": {"x": 314, "y": 76, "width": 1101, "height": 821},
            "two-pixel-inset": {"x": 315, "y": 77, "width": 1098, "height": 818},
            "two-pixel-x-only": {"x": 314, "y": 75, "width": 1100, "height": 822},
            "inset-one-pixel-wider": {"x": 314, "y": 76, "width": 1101, "height": 820},
            "inset-one-pixel-shorter": {"x": 314, "y": 76, "width": 1100, "height": 821},
            "ax-larger-than-cg": {"x": 312, "y": 74, "width": 1104, "height": 824},
        }
        for name, frame in cases.items():
            with self.subTest(case=name):
                self.assertIsNone(macos._frame_relation(frame, dict(MEASURED_CG)))
                api = self.identity_api([ax_window(frame=frame)])
                self.assertIsNone(api._relation(self.ax_windows(api)[0], api.window_list[0]))
                self.refusal(api, "a11y-query")
        # The canonical shape 100 points away is still not this window.
        api = self.api([ax_window(frame=dict(MEASURED_AX, x=MEASURED_AX["x"] + 100))])
        self.refusal(api, "a11y-query")

    def test_malformed_or_non_integer_geometry_refuses(self):
        inset = {"x": 1, "y": 1, "width": 802, "height": 602}
        malformed = [
            {"x": True, "y": 1, "width": 802, "height": 602},
            {"x": "1", "y": 1, "width": 802, "height": 602},
            {"x": 1, "y": 1, "width": 802},
            {"x": 1, "y": 1, "width": 0, "height": 602},
            {"x": 1, "y": 1, "width": -802, "height": 602},
            {"x": 1, "y": 1, "width": 802, "height": None},
            [1, 1, 802, 602],
            None,
        ]
        for frame in malformed:
            with self.subTest(frame=frame):
                self.assertIsNone(macos._frame_relation(frame, dict(MEASURED_CG)))
        for bounds in ({"x": 0, "y": 0, "width": 0, "height": 604},
                       {"x": 0, "y": 0, "width": 804},
                       None, "804x604"):
            with self.subTest(bounds=bounds):
                self.assertIsNone(macos._frame_relation(dict(inset), bounds))
        # An AXValue coordinate is read only as a plain int or a finite
        # built-in float; bool, non-numeric, NaN/inf and a numeric subclass
        # never become geometry.
        class Hostile(int):
            def __int__(self):
                raise AssertionError("int() dispatch on hostile AX geometry")

        class HostileFloat(float):
            def __float__(self):
                raise AssertionError("float() dispatch on hostile AX geometry")

        for value in (True, "1", None, float("nan"), float("inf"), float("-inf"),
                      Hostile(1), HostileFloat(1.5)):
            with self.subTest(ax_coordinate=value):
                with self.assertRaises(macos.AxValueUnavailable):
                    macos._geometry_int(value)
        # Integral floats normalise to the same pixel; a genuine fractional
        # built-in float is preserved exactly, never truncated.
        self.assertEqual(macos._geometry_int(1.0), 1)
        self.assertEqual(macos._geometry_int(1.5), 1.5)
        self.assertEqual(macos._geometry_int(-0.25), -0.25)
        for position in ((1, (1, 1)), (1, (True, 1)), (1, (float("nan"), 1))):
            with self.subTest(position=position):
                api = self.api([ax_window(frame=MEASURED_AX)])
                get = api.ax.AXValueGetValue

                def get_value(value, kind, out, x=position[0], y=position[1]):
                    if kind == "AXValueCGPointType":
                        return True, types.SimpleNamespace(x=x, y=y)
                    return get(value, kind, out)

                api.ax.AXValueGetValue = get_value
                with self.assertRaises(macos.AxValueUnavailable):
                    api.frame(self.ax_windows(api)[0])
                # The binding turns that into the fixed a11y-query refusal.
                with self.assertRaises(contract.ContractError) as error:
                    api.window_element(dict(api.window_list[0]))
                self.assertEqual(error.exception.code, "a11y-query")

    def test_unreadable_ax_geometry_refuses(self):
        api = self.api([ax_window(frame=MEASURED_AX)])

        def frame(element):
            raise macos.AxValueUnavailable()

        api.frame = frame
        self.assertIsNone(api._relation(self.ax_windows(api)[0], api.window_list[0]))
        self.refusal(api, "a11y-query")
        # ``_same_element`` adds only a native identity compare: with no
        # CFEqual source it refuses instead of guessing equality.
        with self.assertRaises(contract.ContractError) as error:
            api._same_element(self.ax_windows(api)[0], api.window_list[0])
        self.assertEqual(error.exception.code, "a11y-unavailable")

    def test_title_mismatch_refuses_even_with_the_canonical_frame(self):
        for title in (TITLE + " ", TITLE[:-1], TITLE.upper(), "", "Locklark"):
            with self.subTest(title=title):
                api = self.api([ax_window(title=title, frame=MEASURED_AX)])
                self.refusal(api, "a11y-query")

    def test_duplicate_exact_title_ax_windows_refuse(self):
        # Two exact-title windows where EACH would bind alone (canonical and
        # exact frame): ambiguity is decided on the title, never on frame.
        for frames in ([MEASURED_AX, MEASURED_CG], [MEASURED_AX, MEASURED_AX],
                       [MEASURED_CG, MEASURED_CG], [MEASURED_AX, {"x": 0, "y": 0, "width": 1, "height": 1}]):
            with self.subTest(frames=frames):
                api = self.api([ax_window(frame=frame) for frame in frames])
                error = self.refusal(api, "window-ambiguous")
                self.assertEqual(error.guard, {"ax": 2})

    def test_other_titles_leave_the_unique_exact_title_bindable(self):
        api = self.api([ax_window(title="Locklark acceptance popup", frame=MEASURED_CG),
                        ax_window(frame=MEASURED_AX)])
        self.assertIs(api.window_element(dict(api.window_list[0])), self.ax_windows(api)[1])

    def test_no_or_other_title_single_ax_window_refuses(self):
        for tree_windows in ([], [ax_window(title=TITLE + " popup")],
                             [ax_window(title="", frame=MEASURED_AX)]):
            with self.subTest(count=len(tree_windows)):
                self.refusal(self.api(tree_windows), "a11y-query")

    # -- the shared CFEqual fake is truthful for distinct elements -----------
    def test_general_cf_equal_refuses_a_distinct_same_title_same_frame_twin(self):
        # A regression for the XOR-by-listed-membership fake: a listed window
        # and ANY distinct unlisted lookalike (same title and frame) are not
        # equal, with no per-object override in place.
        listed = ax_window(frame=MEASURED_AX)
        api = self.identity_api([listed])
        twin = ax_window(frame=MEASURED_AX)
        other_listed = ax_window(frame=MEASURED_AX)
        api.ax_windows_source.append(other_listed)  # a second distinct listed element
        equal = api.ax.CFEqual
        # Very same object (twice in AXWindows) is the only true pair.
        self.assertTrue(equal(listed, listed))
        for left, right in ((listed, twin), (twin, listed), (listed, other_listed),
                            (other_listed, listed), (twin, other_listed),
                            (other_listed, twin), (twin, twin), (ax_window(), ax_window())):
            with self.subTest(left=id(left), right=id(right)):
                self.assertFalse(equal(left, right))
        self.assertFalse(api._same_element(twin, listed))
        self.assertTrue(api._same_element(listed, listed))
        self.assertFalse(api._same_element(other_listed, listed))
        # Two listed exact-title AXWindows refuse the binding itself.
        self.assertEqual(self.without_identity_refusal(
            api._identity_matches, twin, api.window_list[0]), (None, "window-ambiguous"))

    def test_general_cf_equal_lone_listed_window_rejects_the_unlisted_twin(self):
        api = self.identity_api([ax_window(frame=MEASURED_AX)])
        listed = self.ax_windows(api)[0]
        twin = ax_window(frame=MEASURED_AX)  # same title, same frame, unlisted
        self.assertTrue(api._identity_matches(listed, api.window_list[0]))
        self.assertFalse(api._identity_matches(twin, api.window_list[0]))

    def test_shared_fixture_rejects_a_wrong_focused_and_hit_lookalike(self):
        # The same-title/same-frame twin observed by focus or by hit is a
        # distinct AXUIElement under the general fake, and each path refuses.
        for focus in (False, True):
            with self.subTest(focus=focus):
                api = self.identity_api([ax_window(frame=MEASURED_AX, focused=True)])
                twin = ax_window(frame=MEASURED_AX)
                self.assertFalse(api.ax.CFEqual(twin, self.ax_windows(api)[0]))
                if focus:
                    api.ax.AXUIElementCopyAttributeValue = (
                        lambda node, name, out, twin=twin, inner=api.ax.AXUIElementCopyAttributeValue:
                        (0, twin) if name == "AXFocusedWindow" else inner(node, name, out))
                    self.assertEqual(api.focus_state(api.window_list[0]),
                                     {"pid": WINDOW_RAW["pid"], "window": None})
                else:
                    api.ax.AXUIElementCopyElementAtPosition = lambda app, x, y, out: (0, twin)
                    self.assertFalse(api.root_at(api.window_list[0], 0, 0))

    # -- end-to-end: binding precedes controls and input ---------------------
    def test_ambiguity_refuses_before_controls_and_input(self):
        # Two same-PID, exact-title AX windows: one canonical and one exact
        # frame. Either would bind alone, so only title uniqueness can refuse.
        twin = [ax_window(frame=MEASURED_AX), ax_window(frame=MEASURED_CG)]
        for tree_windows, code in (
                (twin, "window-ambiguous"),
                ([ax_window(title=TITLE + " · ")], "a11y-query"),
                ([ax_window(frame={"x": 414, "y": 76, "width": 1100, "height": 820})], "a11y-query"),
                ([ax_window(frame={"x": 315, "y": 77, "width": 1098, "height": 818})], "a11y-query"),
                ([ax_window(frame={"x": 314, "y": 76, "width": 1101, "height": 820})], "a11y-query")):
            with self.subTest(code=code, titles=[item["title"] for item in tree_windows],
                              frames=[item["frame"] for item in tree_windows]):
                api = self.api(tree_windows)
                # The live target is the focused window (proven separately);
                # this test isolates the AX<->CG binding refusal.
                api.focus_state = lambda window=None: {
                    "pid": WINDOW_RAW["pid"], "window": WINDOW_RAW["id"]}
                with self.assertRaises(contract.ContractError) as error:
                    execute(macos.MacAdapter(api=api), document(
                        actions=[{"click_label": LABEL}, {"text": "abc"}, {"key": "Super_L+w"}]))
                self.assertEqual(error.exception.code, code)
                self.assertEqual(api.control_reads, [])
                self.assertEqual(api.hit_reads, [])
                self.assertEqual(api.inputs(), ([], [], []))

    # -- the other identity consumers use the same relation ------------------
    def test_canonical_border_inset_end_to_end_posts_one_click(self):
        # The measured relation must carry the REAL adapter and shared
        # contract all the way to exactly one physical input batch.
        window = ax_window(frame=MEASURED_AX, focused=True)
        button = {"role": "AXButton", "title": LABEL, "enabled": True,
                  "hidden": False, "children": [], "parent": window,
                  "frame": {"x": 200, "y": 300, "width": 80, "height": 30}}
        window["children"] = [button]
        # CFEqual over these fakes is the control-identity spy's element rule;
        # the window element is the unique AXWindows entry (above).
        api = self.api([window])
        api.ax.CFEqual = lambda left, right: left is right
        api.ax.AXUIElementCopyElementAtPosition = lambda app, x, y, out: (0, button)
        result = execute(macos.MacAdapter(api=api), document(actions=[{"click_label": LABEL}]))
        self.assertEqual(api.clicks, [(240, 315)])
        self.assertEqual(result["clicks"][0]["evidence"], "posted")
        self.assertEqual(result["window"], hex(WINDOW_RAW["id"]))
        self.assertEqual((api.typed, api.chords), ([], []))

    # -- first input actions never see a duplicate/wrong AX window ----------
    def first_action_refuses_like_click_label(self, actions, tree_windows):
        """Run a real-contract request whose FIRST action is the given ones.

        ``text`` and ``key`` never read controls, so before this binding only
        ``focus_state``/``root_at`` stood between a duplicate same-title
        AXWindow and input; both fixtures below reach input if either passes.
        """
        api = self.identity_api(tree_windows)
        with self.assertRaises(contract.ContractError) as error:
            execute(macos.MacAdapter(api=api), document(actions=actions))
        self.assertEqual(error.exception.code, "window-ambiguous")
        self.assertEqual(error.exception.guard, {"ax": 2})
        # The foreground was queried and refused; nothing was read or typed.
        self.assertTrue(api.focus_reads)
        self.assertEqual(api.control_reads, [])
        self.assertEqual(api.hit_reads, [])
        self.assertEqual(api.inputs(), ([], [], []))
        return api

    def test_duplicate_same_title_ax_windows_refuse_a_text_only_first_action(self):
        for frames in ([MEASURED_AX, MEASURED_CG], [MEASURED_AX, MEASURED_AX],
                       [MEASURED_CG, MEASURED_CG]):
            with self.subTest(frames=frames):
                for actions in ([{"text": "abc"}],
                                [{"text": "abc"}, {"click_label": LABEL}]):
                    self.first_action_refuses_like_click_label(
                        actions, [ax_window(frame=frame, focused=True) for frame in frames])

    def test_duplicate_same_title_ax_windows_refuse_a_key_only_first_action(self):
        for frames in ([MEASURED_AX, MEASURED_CG], [MEASURED_AX, MEASURED_AX],
                       [MEASURED_CG, MEASURED_CG]):
            with self.subTest(frames=frames):
                for actions in ([{"key": "Super_L+w"}],
                                [{"key": "Return"}, {"text": "abc"}]):
                    self.first_action_refuses_like_click_label(
                        actions, [ax_window(frame=frame, focused=True) for frame in frames])

    def wrong_element_api(self, focus=False):
        """One unique exact-title AXWindow, but a twin can be observed instead.

        The twin carries the identical title and frame and is its own native
        AXUIElement, so the general CFEqual never equates it with the selection
        (no per-twin override). ``focus`` makes AXFocusedWindow answer the twin;
        otherwise the AX element under the point is the twin.
        """
        selected = ax_window(frame=MEASURED_AX, focused=True)
        button = {"role": "AXButton", "title": LABEL, "enabled": True, "hidden": False,
                  "frame": {"x": 200, "y": 300, "width": 80, "height": 30},
                  "parent": selected, "children": []}
        selected["children"] = [button]
        twin = ax_window(frame=MEASURED_AX)
        twin["children"] = [dict(button, parent=twin)]
        api = self.identity_api([selected])
        api.twin = twin
        api.ax.AXUIElementCopyElementAtPosition = lambda app, x, y, out: (0, twin)
        if focus:  # bound after the spies, so focus_state sees the twin only
            listed = api.ax.AXUIElementCopyAttributeValue

            def attribute(node, name, out):
                return ((0, twin) if name == "AXFocusedWindow"
                        else listed(node, name, out))

            api.ax.AXUIElementCopyAttributeValue = attribute
        return api

    def test_focused_and_hit_ax_element_must_be_cf_equal(self):
        api = self.wrong_element_api()
        selected = self.ax_windows(api)[0]
        # Same title and frame, distinct AX element: the relation alone can
        # not tell them apart, CFEqual never equates them.
        self.assertEqual(api._relation(api.twin, api.window_list[0]), "border-inset")
        self.assertFalse(api._same_element(api.twin, selected))
        self.assertTrue(api._same_element(selected, selected))
        self.assertFalse(api._identity_matches(api.twin, api.window_list[0]))
        self.assertTrue(api._identity_matches(selected, api.window_list[0]))
        self.assertFalse(api.root_at(api.window_list[0], 0, 0))
        api.ax.AXUIElementCopyElementAtPosition = lambda app, x, y, out: (0, selected)
        self.assertTrue(api.root_at(api.window_list[0], 0, 0))

    def test_wrong_ax_element_identity_refuses_a_pointer_first_action(self):
        api = self.wrong_element_api()
        with self.assertRaises(contract.ContractError) as error:
            execute(macos.MacAdapter(api=api), document(actions=[{"click": [10, 10]}]))
        # Focus is the unique selection; only the hit element is the twin.
        self.assertEqual(error.exception.code, "control-offscreen")
        self.assertTrue(api.focus_reads)
        self.assertEqual(api.control_reads, [])
        self.assertEqual(api.hit_reads, [])
        self.assertEqual(api.inputs(), ([], [], []))

    def test_wrong_focused_ax_element_refuses_text_and_key_first(self):
        for actions in ([{"text": "abc"}], [{"key": "Super_L+w"}]):
            with self.subTest(actions=actions):
                # AXFocusedWindow answers the twin instead of the selection.
                api = self.wrong_element_api(focus=True)
                self.assertEqual(api.focus_state(api.window_list[0]),
                                 {"pid": WINDOW_RAW["pid"], "window": None})
                with self.assertRaises(contract.ContractError) as error:
                    execute(macos.MacAdapter(api=api), document(actions=actions))
                self.assertEqual(error.exception.code, "focus-lost")
                self.assertTrue(api.focus_reads)
                self.assertEqual(api.control_reads, [])
                self.assertEqual(api.hit_reads, [])
                self.assertEqual(api.inputs(), ([], [], []))

    def test_single_unique_ax_window_keeps_text_and_key_working(self):
        window = ax_window(frame=MEASURED_AX, focused=True)
        api = self.identity_api([window])
        # The selection is the listed AX window, so CFEqual only passes here.
        self.assertIs(api.window_element(dict(api.window_list[0])), window)
        self.assertTrue(api._same_element(window, self.listed(api)[0]))
        result = execute(macos.MacAdapter(api=api),
                         document(actions=[{"text": "abc"}, {"key": "Super_L+w"}]))
        self.assertEqual(api.control_reads, [])
        self.assertEqual(api.inputs(), ([], ["abc"], [("Super_L", "w")]))
        self.assertEqual(result["window"], hex(WINDOW_RAW["id"]))

    def test_focus_identity_accepts_only_the_canonical_border_inset(self):
        # AXFocusedWindow is the SAME AXWindow as AXWindows[0]: one same-PID
        # window. Its frame relation to the CG bounds decides the binding.
        for frame, bound in ((MEASURED_AX, True), (MEASURED_CG, True),
                             ({"x": 315, "y": 76, "width": 1100, "height": 820}, False),
                             ({"x": 314, "y": 76, "width": 1101, "height": 820}, False),
                             ({"x": 315, "y": 77, "width": 1098, "height": 818}, False)):
            with self.subTest(frame=frame):
                window = ax_window(frame=frame, focused=True)
                api = self.identity_api([window])
                self.assertEqual(
                    self.without_identity_refusal(api.focus_state, api.window_list[0]),
                    {"pid": WINDOW_RAW["pid"], "window": WINDOW_RAW["id"] if bound else None}
                    if bound else (None, BINDING_REFUSAL))
                # The AX element under the point is walked to its AXWindow
                # parent and tested with the same identity.
                api.ax.AXUIElementCopyElementAtPosition = (
                    lambda app, x, y, out, element=window: (0, element))
                verdict = self.without_identity_refusal(
                    lambda: api.root_at(api.window_list[0], 0, 0))
                if bound:
                    self.assertIs(verdict, True)
                else:
                    self.assertEqual(verdict, (None, BINDING_REFUSAL))


class MacControlIdentityTests(unittest.TestCase):
    """AX hit identity: CFEqual against the ACTUAL selected AX element."""

    RECT = {"x": 200, "y": 300, "width": 80, "height": 30}

    def button(self, title=None, parent=None, role="AXButton", **frame):
        bounds = {"x": 200, "y": 300, "width": 80, "height": 30}
        bounds.update(frame)
        return {"role": role, "title": LABEL if title is None else title, "enabled": True,
                "hidden": False, "frame": bounds, "children": [], "parent": parent}

    def api(self, hit=None, position=None, cf_equal=None, extra=None):
        api = macos.QuartzApi.__new__(macos.QuartzApi)
        tree = {"title": TITLE, "frame": dict(WINDOW_RAW["bounds"]), "role": "AXWindow",
                "children": []}
        target = self.button(parent=tree)
        tree["children"] = [] if extra is None else list(extra)
        tree["children"].insert(0, target)
        api.ax = types.SimpleNamespace(
            kAXWindowsAttribute="AXWindows", kAXErrorNoValue=NO_VALUE,
            AXUIElementCreateApplication=lambda pid: "application",
            AXUIElementCopyElementAtPosition=lambda app, x, y, out: (0, hit) if position is None else position,
            CFEqual=cf_equal if cf_equal is not None else (lambda left, right: left is right))
        api.quartz = types.SimpleNamespace()
        api.windows = lambda pid: [tree]
        api.title = lambda element: element.get("title") or ""
        api.frame = lambda element: element["frame"]
        api.attribute = lambda element, name: {
            "AXRole": element.get("role"), "AXTitle": element.get("title"),
            "AXDescription": element.get("description"), "AXEnabled": element.get("enabled"),
            "AXHidden": element.get("hidden"), "AXChildren": element.get("children"),
            "AXParent": element.get("parent")}.get(name)
        api.target = target
        return api

    def verdict(self, api):
        return api.hit_test_control(dict(WINDOW_RAW), LABEL, self.RECT, 240, 315)

    def refusal(self, api, code, label=None):
        with self.assertRaises(contract.ContractError) as error:
            api.hit_test_control(dict(WINDOW_RAW), LABEL if label is None else label,
                                 self.RECT, 240, 315)
        self.assertEqual(error.exception.code, code)

    def test_selected_control_and_a_legitimate_child_accept(self):
        api = self.api()
        api.ax.AXUIElementCopyElementAtPosition = lambda app, x, y, out: (0, api.target)
        self.assertTrue(self.verdict(api))
        api = self.api()
        child = {"role": "AXStaticText", "title": "", "parent": api.target}
        api.ax.AXUIElementCopyElementAtPosition = lambda app, x, y, out: (0, child)
        self.assertTrue(self.verdict(api))

    def test_overlay_sibling_above_the_control_refuses(self):
        overlay = self.button(title="解锁")
        api = self.api(hit=overlay, extra=[overlay])
        overlay["parent"] = api.windows(4242)[0]
        self.assertFalse(self.verdict(api))
        transparent = {"role": "AXGroup", "title": "", "parent": api.windows(4242)[0]}
        self.assertFalse(self.verdict(self.api(hit=transparent)))
        window = api.windows(4242)[0]
        self.assertFalse(self.verdict(self.api(hit=window)))  # AXWindow is never the control

    def test_rect_change_duplicate_and_unknown_label_refuse(self):
        changed = self.api(hit=None)
        changed.target["frame"] = {"x": 201, "y": 300, "width": 80, "height": 30}
        self.refusal(changed, "control-hit")
        duplicate = self.api()
        extra = self.button(parent=duplicate.windows(4242)[0])
        duplicate.windows(4242)[0]["children"].append(extra)
        self.refusal(duplicate, "control-ambiguous")
        self.refusal(self.api(), "control-missing", label="解锁")

    def test_cycle_parent_limit_and_query_failures_refuse(self):
        ring = {"role": "AXGroup", "title": ""}
        ring["parent"] = ring
        self.refusal(self.api(hit=ring), "a11y-query")

        node, chain = {"role": "AXGroup", "title": "", "parent": None}, []
        for _ in range(macos.MAX_HIT_PARENTS + 6):
            node = {"role": "AXGroup", "title": "", "parent": node}
            chain.append(node)
        self.assertFalse(self.verdict(self.api(hit=chain[-1])))

        self.refusal(self.api(position=(7, None)), "a11y-query")
        failing = self.api(hit=None)

        def raise_position(app, x, y, out):
            raise OSError("AX position query failed")

        failing.ax.AXUIElementCopyElementAtPosition = raise_position
        self.refusal(failing, "a11y-query")

        broken_parent = self.api(hit={"role": "AXGroup", "title": "", "parent": None})
        read = broken_parent.attribute

        def attribute(element, name):
            if name == "AXParent":
                raise OSError("AXParent query failed")
            return read(element, name)

        broken_parent.attribute = attribute
        self.refusal(broken_parent, "a11y-query")
        self.assertFalse(self.verdict(self.api(hit=None)))

    def test_native_identity_is_cf_equal_not_value_equality(self):
        twin = dict(self.api().target, children=[])
        self.assertFalse(self.verdict(self.api(hit=twin)))

        def hit_target(api):
            api.ax.AXUIElementCopyElementAtPosition = lambda app, x, y, out: (0, api.target)
            return api

        self.assertFalse(self.verdict(hit_target(self.api(cf_equal=lambda left, right: False))))
        for verdict, accepted in ((True, True), (1, True), (0, False), (None, False), ("yes", False)):
            with self.subTest(verdict=verdict):
                equal = lambda left, right, value=verdict: value
                self.assertEqual(self.verdict(hit_target(self.api(cf_equal=equal))), accepted)

    def test_cf_equal_is_required_and_never_guessed(self):
        api = self.api()
        del api.ax.CFEqual
        api.ax.AXUIElementCopyElementAtPosition = lambda app, x, y, out: (0, api.target)
        with patch.dict(sys.modules, {"CoreFoundation": None}):
            self.refusal(api, "a11y-unavailable")
        module = types.SimpleNamespace(CFEqual=lambda left, right: left is right)
        with patch.dict(sys.modules, {"CoreFoundation": module}):
            self.assertTrue(self.verdict(api))

class FakeQuartzEvents:
    kCGHIDEventTap = 0
    kCGEventMouseMoved = 5
    kCGEventLeftMouseDown = 1
    kCGEventLeftMouseUp = 2

    def __init__(self):
        self.created, self.posted, self.flagged = [], [], []

    def CGEventCreateMouseEvent(self, proxy, kind, point, button):
        event = {"kind": kind, "point": point}
        self.created.append(event)
        return event

    def CGEventCreateKeyboardEvent(self, proxy, code, down):
        event = {"kind": "key", "code": code, "down": down}
        self.created.append(event)
        return event

    def CGEventKeyboardSetUnicodeString(self, event, length, text):
        event["text"] = text

    def CGEventSetFlags(self, event, flags):
        self.flagged.append((event, flags))

    def CGEventPost(self, tap, event):
        self.posted.append(event)


class MacInputBuildingTests(unittest.TestCase):
    def api(self):
        api = macos.QuartzApi.__new__(macos.QuartzApi)
        api.quartz = FakeQuartzEvents()
        return api

    def test_click_posts_one_move_down_up_batch(self):
        api = self.api()
        api.click(500, 400)
        self.assertEqual([event["kind"] for event in api.quartz.posted], [5, 1, 2])
        self.assertEqual(api.quartz.posted[0]["point"], (500, 400))

    def test_fractional_click_point_reaches_quartz_untruncated(self):
        api = self.api()
        api.click(240.5, 315.25)
        self.assertEqual([event["point"] for event in api.quartz.posted],
                         [(240.5, 315.25)] * 3)
        for point in ((True, 1), (1, "2"), (float("nan"), 1), (1, float("inf"))):
            with self.subTest(point=point):
                before = len(api.quartz.posted)
                with self.assertRaises(contract.ContractError) as error:
                    api.click(*point)
                self.assertEqual(error.exception.code, "input-failed")
                self.assertEqual(len(api.quartz.posted), before)

    def test_chord_posts_modifier_first_and_release_last_with_flags(self):
        api = self.api()
        api.press_chord(("Control_L", "a"))
        posted = api.quartz.posted
        self.assertEqual([(event["code"], event["down"]) for event in posted],
                         [(0x3B, True), (0x00, True), (0x00, False), (0x3B, False)])
        self.assertEqual(len(api.quartz.flagged), 4)
        self.assertEqual({flags for _event, flags in api.quartz.flagged}, {macos.FLAGS["Control_L"]})

    def test_command_a_chord_posts_super_keycode_with_command_flag(self):
        api = self.api()
        api.press_chord(("Super_L", "a"))
        posted = api.quartz.posted
        self.assertEqual([event["code"] for event in posted], [0x37, 0x00, 0x00, 0x37])
        self.assertEqual([event["down"] for event in posted], [True, True, False, False])
        self.assertNotEqual(macos.FLAGS["Super_L"], macos.FLAGS["Control_L"])
        self.assertEqual(api.quartz.flagged, [(event, macos.FLAGS["Super_L"]) for event in posted])

    def test_typing_posts_two_events_per_character(self):
        api = self.api()
        api.type_text("hi")
        self.assertEqual([(event.get("text"), event["down"]) for event in api.quartz.posted],
                         [("h", True), ("h", False), ("i", True), ("i", False)])

    def test_unknown_chord_and_non_ascii_text_refused(self):
        api = self.api()
        with self.assertRaises(contract.ContractError) as error:
            api.press_chord(("NotAKey",))
        self.assertEqual(error.exception.code, "input-unsupported")
        with self.assertRaises(contract.ContractError) as error:
            api.type_text("naïve")
        self.assertEqual(error.exception.code, "input-charset")
        self.assertEqual(api.quartz.posted, [])


class MacFrameworkOwnershipTests(unittest.TestCase):
    """AX belongs to ApplicationServices; Quartz is never an AX stand-in."""

    def test_real_constructor_imports_application_services_separately(self):
        ax = types.SimpleNamespace(AXIsProcessTrusted=lambda: True)
        quartz = types.SimpleNamespace()
        modules = {"ApplicationServices": ax, "AppKit": types.SimpleNamespace(),
                   "Quartz": quartz}
        with patch.dict(sys.modules, modules), \
                patch.object(macos.ctypes, "CDLL", lambda name: types.SimpleNamespace()):
            api = macos.QuartzApi()
        self.assertIs(api.ax, ax)
        self.assertIs(api.quartz, quartz)
        self.assertIsNone(api.capability())

    def test_missing_application_services_never_falls_back_to_quartz(self):
        quartz = types.SimpleNamespace(AXIsProcessTrusted=lambda: True)
        modules = {"AppKit": types.SimpleNamespace(), "Quartz": quartz}
        with patch.dict(sys.modules, modules):
            sys.modules.pop("ApplicationServices", None)
            with patch.object(macos.ctypes, "CDLL", lambda name: types.SimpleNamespace()):
                with self.assertRaises(ImportError):
                    macos.QuartzApi()

    def test_an_injected_combined_fake_is_the_only_fallback(self):
        combined = types.SimpleNamespace(AXIsProcessTrusted=lambda: True)
        api = macos.QuartzApi(quartz=combined, appkit=types.SimpleNamespace())
        self.assertIs(api.ax, combined)
        self.assertIs(api.quartz, combined)

    def test_ax_calls_go_to_application_services_not_quartz(self):
        calls = []
        ax = types.SimpleNamespace(
            AXUIElementCreateApplication=lambda pid: calls.append(pid) or {"pid": pid},
            kAXWindowsAttribute="AXWindows", kAXErrorNoValue=NO_VALUE,
            AXUIElementCopyAttributeValue=lambda element, name, out: (0, ["window"]))
        api = macos.QuartzApi(quartz=types.SimpleNamespace(),
                              appkit=types.SimpleNamespace(), ax=ax)
        self.assertEqual(api.windows(4242), ["window"])
        self.assertEqual(calls, [4242])

    def test_a_missing_ax_symbol_is_never_answered_by_quartz(self):
        api = macos.QuartzApi(quartz=types.SimpleNamespace(AXIsProcessTrusted=lambda: True),
                              appkit=types.SimpleNamespace(), ax=types.SimpleNamespace())
        with self.assertRaises(AttributeError):
            api.capability()


class MacFocusIdentityTests(unittest.TestCase):
    """AXFocusedWindow is mandatory; AXMainWindow only adds consistency."""

    def api(self, focused="match", main="match"):
        api = macos.QuartzApi.__new__(macos.QuartzApi)
        api.foreground_pid = lambda: WINDOW_RAW["pid"]
        api.application = lambda pid: "application"

        def attribute(element, name):
            value = {"AXFocusedWindow": focused, "AXMainWindow": main}.get(name)
            return None if value is None else {"identity": value}

        api.attribute = attribute
        api._identity_matches = lambda element, window: element.get("identity") == "match"
        return api

    def focused(self, api):
        adapter = types.SimpleNamespace(exact_focus=True, focus_state=api.focus_state)
        return contract.focus_matches(adapter, dict(WINDOW_RAW), contract.Budget())

    def test_focused_window_binds_the_exact_identity(self):
        self.assertTrue(self.focused(self.api()))

    def test_missing_focused_window_refused_even_when_main_window_matches(self):
        self.assertFalse(self.focused(self.api(focused=None, main="match")))

    def test_focused_window_bound_to_another_window_refused(self):
        self.assertFalse(self.focused(self.api(focused="other", main="match")))

    def test_matching_focused_with_conflicting_main_window_refused(self):
        self.assertFalse(self.focused(self.api(focused="match", main="other")))

    def test_matching_focused_without_main_window_is_enough(self):
        self.assertTrue(self.focused(self.api(focused="match", main=None)))

    def test_missing_focused_window_refuses_before_any_input(self):
        api = self.api(focused=None, main="match")
        adapter = types.SimpleNamespace(platform="macos", exact_focus=True,
                                        supports_activation=True,
                                        focus_state=api.focus_state,
                                        activate=lambda window: None)
        with self.assertRaises(contract.ContractError) as error:
            contract.ensure_focus({"preserve_focus": False}, adapter, dict(WINDOW_RAW),
                                  contract.Budget())
        self.assertEqual(error.exception.code, "focus-lost")


class FailingQuartzEvents(FakeQuartzEvents):
    """CoreGraphics fake that fails creation, flag or post at chosen positions."""

    def __init__(self, fail_create=(), fail_post=(), fail_unicode=False, fail_flags=False):
        FakeQuartzEvents.__init__(self)
        self.fail_create, self.fail_post = set(fail_create), set(fail_post)
        self.fail_unicode, self.fail_flags = fail_unicode, fail_flags
        self.post_attempts = []

    def CGEventCreateMouseEvent(self, proxy, kind, point, button):
        if len(self.created) in self.fail_create:
            self.created.append({"kind": kind, "point": point, "dead": True})
            return None
        return FakeQuartzEvents.CGEventCreateMouseEvent(self, proxy, kind, point, button)

    def CGEventCreateKeyboardEvent(self, proxy, code, down):
        if len(self.created) in self.fail_create:
            self.created.append({"kind": "key", "code": code, "down": down, "dead": True})
            return None
        return FakeQuartzEvents.CGEventCreateKeyboardEvent(self, proxy, code, down)

    def CGEventKeyboardSetUnicodeString(self, event, length, text):
        if self.fail_unicode:
            raise RuntimeError("unicode string unavailable")
        FakeQuartzEvents.CGEventKeyboardSetUnicodeString(self, event, length, text)

    def CGEventSetFlags(self, event, flags):
        if self.fail_flags:
            raise RuntimeError("flags unavailable")
        FakeQuartzEvents.CGEventSetFlags(self, event, flags)

    def CGEventPost(self, tap, event):
        self.post_attempts.append(event)
        if len(self.post_attempts) in self.fail_post:
            raise RuntimeError("post failed")
        self.posted.append(event)


class MacInputPreconstructionTests(unittest.TestCase):
    """The whole batch is built before the first post; nothing is half posted."""

    def api(self, **options):
        api = macos.QuartzApi.__new__(macos.QuartzApi)
        api.quartz = FailingQuartzEvents(**options)
        return api

    def refused(self, api, code, action):
        with self.assertRaises(contract.ContractError) as error:
            action(api)
        self.assertEqual(error.exception.code, code)
        self.assertEqual(api.quartz.posted, [])
        self.assertEqual(api.quartz.post_attempts, [])

    def test_mouse_creation_failure_posts_nothing(self):
        self.refused(self.api(fail_create={1}), "input-failed",
                     lambda api: api.click(500, 400))

    def test_chord_creation_failure_leaves_no_orphan_key_down(self):
        self.refused(self.api(fail_create={3}), "input-failed",
                     lambda api: api.press_chord(("Control_L", "a")))

    def test_unicode_creation_failure_posts_nothing(self):
        self.refused(self.api(fail_create={2}), "input-failed",
                     lambda api: api.type_text("hi"))

    def test_unicode_string_failure_posts_nothing(self):
        self.refused(self.api(fail_unicode=True), "input-unsupported",
                     lambda api: api.type_text("hi"))

    def test_flag_failure_posts_nothing(self):
        self.refused(self.api(fail_flags=True), "input-unsupported",
                     lambda api: api.press_chord(("Control_L", "a")))

    def test_mid_batch_post_failure_is_unknown_and_never_retried(self):
        api = self.api(fail_post={2})
        with self.assertRaises(contract.ContractError) as error:
            api.click(500, 400)
        self.assertEqual(error.exception.code, "input-unknown")
        self.assertEqual(len(api.quartz.created), 3)        # batch never rebuilt
        self.assertEqual(len(api.quartz.post_attempts), 2)  # failed event not retried
        self.assertEqual(len(api.quartz.posted), 1)


class MacDisplayMembershipTests(unittest.TestCase):
    """CGGetActiveDisplayList/CGDisplayBounds: per-display membership."""

    def api(self, result=None, bounds=None, raise_error=False):
        api = macos.QuartzApi.__new__(macos.QuartzApi)

        class Quartz(object):
            def CGGetActiveDisplayList(self, maximum, displays, count):
                if raise_error or isinstance(result, Exception):
                    raise result if isinstance(result, Exception) else RuntimeError("CG")
                return result

            def CGDisplayBounds(self, display):
                # A per-display dict: a missing display has no readable bounds.
                value = bounds[display] if isinstance(bounds, dict) else bounds
                if isinstance(value, Exception):
                    raise value
                return value

        api.quartz = Quartz()
        return api

    def test_count_consistent_valid_display_is_visible(self):
        api = self.api(result=(0, [1, 2, 3], 1),
                       bounds={1: ((0, 0), (1920, 1080)),
                               2: ((3000, 0), (1280, 1024)),
                               3: ((9000, 0), (1280, 1024))})
        self.assertTrue(api.point_visible(None, 100, 100))
        self.assertFalse(api.point_visible(None, 3100, 100))  # beyond reported count

    def test_point_inside_one_display_is_visible(self):
        api = self.api(result=(0, [1, 2], 2),
                       bounds={1: ((0, 0), (1920, 1080)), 2: ((1920, 0), (1280, 1024))})
        self.assertTrue(api.point_visible(None, 100, 100))
        self.assertTrue(api.point_visible(None, 2000, 1000))

    def test_gap_between_display_rectangles_is_not_screen(self):
        api = self.api(result=(0, [1, 2], 2),
                       bounds={1: ((0, 0), (1920, 1080)), 2: ((2000, 0), (1280, 1024))})
        self.assertFalse(api.point_visible(None, 1950, 100))

    def refusal(self, result, bounds=((0, 0), (1920, 1080)), point=(100, 100)):
        api = self.api(result=result, bounds=bounds)  # keywords: never misaligned
        with self.assertRaises(contract.ContractError) as error:
            api.point_visible(None, *point)
        self.assertEqual(error.exception.code, "a11y-query")

    def test_display_api_exception_is_a_query_refusal_not_a_miss(self):
        self.refusal(RuntimeError("CGGetActiveDisplayList failed"))

    def test_unknown_or_empty_display_list_is_a_query_refusal(self):
        cases = ((1, [1], 1),          # CoreGraphics error
                 (0, [], 0),           # no active display
                 (0, None, 0),         # unreadable list
                 "not-a-tuple",
                 (0, [1], 2),          # count larger than the returned list
                 (0, [1], True),       # a bool is never a display count
                 (0, [1], "1"),        # non-integer count
                 (0, [1], 0), (0, [1], 33),
                 (0, [1], 1, 4),       # malformed arity (any non-3-tuple)
                 (None, [1], 1),       # missing error status
                 (0, 7, 1),            # an int is not a display sequence
                 (0, object(), 1),     # an unreadable list
                 (0, [1, 2], 3))       # count larger than the returned list
        # A returned member whose bounds cannot be read is checked separately
        # (the per-display bounds mapping only has a value for a member there).
        self.refusal((0, [1, "x"], 2), {1: ((0, 0), (1920, 1080)), "x": "bounds"})
        for result in cases:
            with self.subTest(result=result):
                self.refusal(result)

    def test_bool_display_status_is_malformed_never_a_success(self):
        # ``False == 0`` but a bool is not a CGError: the display query is
        # unknown and refuses even though the list itself is well formed.
        for error in (False, True):
            with self.subTest(error=error):
                self.refusal((error, [1], 1))
        self.assertIs(self.api(result=(0, [1], 1), bounds=((0, 0), (1920, 1080))
                               ).point_visible(None, 100, 100), True)

    def test_unreadable_display_bounds_is_a_query_refusal(self):
        for bounds in (RuntimeError("no bounds"), ("x", "y"), ("x", (0, 0)),
                       ((0, 0), (0, 0)), (None, (1920, 1080)),
                       ((0, 0), (float("nan"), 1080)),
                       ((float("inf"), 0), (1920, 1080)), None, "bounds"):
            with self.subTest(bounds=bounds):
                self.refusal((0, [1], 1), {1: bounds})

    def test_zero_area_display_is_a_malformed_query_and_never_skipped(self):
        on_display = (0, [1, 2], 2)
        both = {1: ((0, 0), (1920, 1080)), 2: ((2000, 0), (1280, 1024))}
        usable = self.api(result=on_display, bounds=both)
        self.assertIs(usable.point_visible(None, 100, 100), True)
        self.assertIs(usable.point_visible(None, 2500, 500), True)
        # The first display contains the point; the second (zero-area or
        # negative) still has to be a usable display for the whole query to be
        # trustworthy, so such a member is never silently passed over.
        for second in (((3000, 0), (0, 1024)), ((3000, 0), (1280, 0)),
                       ((3000, 0), (1280, -1))):
            with self.subTest(second=second):
                self.refusal(on_display,
                             {1: ((0, 0), (1920, 1080)), 2: second}, (100, 100))
        # Neither display reports usable bounds.
        self.refusal(on_display,
                     {1: ((3000, 0), (0, 1080)), 2: ((9000, 0), (1280, 0))},
                     (100, 100))

    def test_pyobjc_native_sequence_forms_are_accepted(self):
        # PyObjC returns a CoreFoundation array as NSArray (and the count as an
        # NSNumber); the documented native forms are read, not rejected for
        # not being a builtin list.
        class NSArray(object):
            def __init__(self, items):
                self.items = list(items)

            def __len__(self):
                return len(self.items)

            def __getitem__(self, index):
                return self.items[index]

        api = self.api(result=(0, NSArray([1, 2]), 2),
                       bounds={1: NSArray([NSArray([0, 0]), NSArray([1920, 1080])]),
                               2: NSArray([NSArray([1920, 0]), NSArray([1280, 1024])])})
        self.assertIs(api.point_visible(None, 100, 100), True)
        self.assertIs(api.point_visible(None, 2500, 100), True)
        self.assertIs(api.point_visible(None, 5000, 100), False)

    def test_out_of_display_membership_is_still_a_valid_false(self):
        api = self.api(result=(0, (1, 2), 2),
                       bounds={1: ((0, 0), (1920, 1080)), 2: ((2000, 0), (1280, 1024))})
        self.assertIs(api.point_visible(None, 1950, 100), False)  # the gap
        self.assertIs(api.point_visible(None, 5000, 100), False)  # beyond every display

    def test_real_display_error_reaches_the_contract_as_a11y_query(self):
        # The real QuartzApi over a failing CG fake: the search must abort on
        # the error, never fall through to another candidate.
        api = self.api(result=RuntimeError("CGGetActiveDisplayList failed"))
        with self.assertRaises(contract.ContractError) as error:
            macos.MacAdapter(api=api).point_visible(dict(WINDOW_RAW), 240, 315)
        self.assertEqual(error.exception.code, "a11y-query")
        for verdict in (None, 1, 0, "yes"):
            with self.subTest(adapter_answer=verdict):
                with self.assertRaises(contract.ContractError) as error:
                    macos.MacAdapter(api=types.SimpleNamespace(
                        point_visible=lambda window, x, y, value=verdict: value)
                    ).point_visible(dict(WINDOW_RAW), 240, 315)
                self.assertEqual(error.exception.code, "a11y-query")
        with self.assertRaises(contract.ContractError) as error:
            macos.MacAdapter(api=types.SimpleNamespace(
                point_visible=lambda window, x, y: (_ for _ in ()).throw(
                    OSError("display query")))).point_visible(dict(WINDOW_RAW), 240, 315)
        self.assertEqual(error.exception.code, "a11y-query")
        self.assertIs(macos.MacAdapter(api=types.SimpleNamespace(
            point_visible=lambda window, x, y: False)).point_visible(
                dict(WINDOW_RAW), 240, 315), False)

    def test_adapter_refuses_a_point_outside_every_display(self):
        # A SUCCESSFUL off-display verdict is a legitimate miss for every
        # bounded candidate: the search ends in control-hit, not a query error.
        api = FakeMacApi()
        api.display_bounds = [(-1000, -1000, 100, 100)]  # the control is on none
        adapter = macos.MacAdapter(api=api)
        with self.assertRaises(contract.ContractError) as error:
            execute(adapter, document())
        self.assertEqual(error.exception.code, "control-hit")
        # Every bounded candidate was refused on display visibility alone;
        # no control hit was even probed and nothing was clicked.
        candidates = [(item["x"], item["y"]) for item in macos.MacAdapter.click_candidates(
            dict(CONTROL["bounds"]))]
        self.assertEqual(api.display_queries, len(candidates))
        self.assertEqual(api.hit_calls, [])
        self.assertEqual(api.clicks, [])

    def test_adapter_refuses_when_the_window_root_lacks_the_candidate(self):
        api = FakeMacApi(root=False)
        adapter = macos.MacAdapter(api=api)
        with self.assertRaises(contract.ContractError) as error:
            execute(adapter, document())
        self.assertEqual(error.exception.code, "control-hit")
        self.assertEqual(api.hit_calls, [])
        self.assertEqual(api.clicks, [])


class MacRootAtQueryTests(unittest.TestCase):
    """root_at: a successful miss is False; an unknown query is a11y-query."""

    def api(self, position=None, application="application", attributes=None,
            parent="none"):
        """A QuartzApi over native-shaped AX fakes.

        ``position`` is the ``AXUIElementCopyElementAtPosition`` result: a
        ``(AXError, element)`` status tuple, a bare element (PyObjC may return
        the out-parameter alone) or a callable making a fresh element per
        query.  Attributes are read as ``(AXError, value)``.  ``parent`` is
        "none" (the chain ends at the leaf), "bound" (the leaf's AXParent is
        the bound AXWindow element) or "other" (a non-bound AXWindow).
        """
        api = macos.QuartzApi.__new__(macos.QuartzApi)
        window_element, other_window = object(), object()
        if isinstance(parent, str):
            parent = {"none": None, "bound": window_element, "other": other_window}[parent]
        values = {"AXRole": "AXButton", "AXParent": parent}
        values.update(attributes or {})

        def copy_attribute(element, name, out):
            # Checked first: a nil AXParent is not an AXWindow element.
            if element in (window_element, other_window) and name in ("AXRole", "AXParent"):
                return 0, "AXWindow" if name == "AXRole" else None
            value = values.get(name)
            # An attributes entry may be the value itself or a full
            # ``(AXError, value)`` result, so statuses are scripted per read.
            if type(value) is tuple and len(value) == 2 and type(value[0]) in (int, bool):
                return value
            return 0, (value(element) if callable(value) else value)

        def element_at(app, x, y, out):
            return position() if callable(position) else position

        api.ax = types.SimpleNamespace(
            AXUIElementCreateApplication=lambda pid: application,
            AXUIElementCopyElementAtPosition=element_at,
            AXUIElementCopyAttributeValue=copy_attribute,
            kAXErrorNoValue=NO_VALUE,
            # Held on the instance: a class attribute would be a bound method.
            CFEqual=staticmethod(lambda left, right: left is right))
        api.identity = []

        def matches(element, bound):
            api.identity.append(element)
            return element is window_element

        api._identity_matches = matches
        return api

    def root(self, api):
        return api.root_at(dict(WINDOW_RAW), 240, 315)

    def refused(self, api):
        identity = getattr(api, "identity", [])
        with self.assertRaises(contract.ContractError) as error:
            self.root(api)
        self.assertEqual(error.exception.code, "a11y-query")
        self.assertEqual(identity, [])

    def test_successful_queries_with_no_element_or_no_axwindow_are_false(self):
        # Trustworthy "no element at the point" is a legitimate miss.
        self.assertIs(self.root(self.api(position=(0, None))), False)
        # A chain that ends (nil AXParent) before any AXWindow has no root.
        self.assertIs(self.root(self.api(position=(0, "leaf"))), False)
        self.assertIs(self.root(self.api(position=lambda: {"AXRole": "AXButton"})), False)
        # The bound AXWindow under the point is the root (CFEqual identity).
        self.assertIs(self.root(self.api(position=(0, "window"), parent="bound")), True)
        # A chain whose AXWindow is not the bound element is a miss.
        self.assertIs(self.root(self.api(position=(0, "other"), parent="other")), False)

    def test_documented_native_output_forms_are_preserved(self):
        # PyObjC may surface the out-parameter as a bare element (no tuple):
        # an exact element, read like the (AXError, element) form.
        self.assertIs(self.root(self.api(position={"AXRole": "AXButton"})), False)
        self.assertIs(self.root(self.api(position={"AXRole": "AXWindow"},
                                         parent="bound")), True)
        # An unreadable out-parameter is an unknown query; a nil one is a miss.
        self.refused(self.api(position=()))
        self.refused(self.api(position=(0, "unreadable", 0)))
        self.refused(self.api(position=("element",)))
        self.assertIs(self.root(self.api(position=None)), False)

    def test_query_failures_refuse_a11y_query(self):
        def raising():
            raise OSError("AX position query failed")

        self.refused(self.api(position=raising))          # raised position query
        self.refused(self.api(position=(7, None)))        # AX error status
        self.refused(self.api(application=None))          # unavailable application
        self.refused(self.api(position=(0, "leaf", None)))  # odd status tuple
        # An unreadable role/status query is unknown, never a skipped miss.
        for payload in ((5, "AXButton"), (0, "AXButton", None), "AXButton", ()):
            with self.subTest(payload=payload):
                corrupt = self.api(position=(0, "leaf"))
                corrupt.ax.AXUIElementCopyAttributeValue = (
                    lambda element, name, out, payload=payload: payload)
                self.refused(corrupt)
        # A cyclic parent chain never reaches an AXWindow.
        self.refused(self.api(position=(0, "leaf"),
                              attributes={"AXParent": lambda element: element}))

    def test_native_string_axrole_is_normalized_before_strict_validation(self):
        # objc.pyobjc_unicode is a str subclass, not an exact str: the child
        # role is traversed and the exact bound window root is accepted.
        role = NativeNSString("AXButton")
        self.assertIs(type(role), NativeNSString)
        self.assertIsNot(type(role), str)
        api = self.api(position=(0, "leaf"), parent="bound",
                       attributes={"AXRole": role})
        bound = api.ax.AXUIElementCopyAttributeValue("leaf", "AXParent", None)[1]
        self.assertIs(self.root(api), True)
        self.assertEqual(api.identity, [bound])
        # An empty or non-string role is not an identity and still refuses.
        self.refused(self.api(position=(0, "leaf"),
                              attributes={"AXRole": ""}))
        for payload in (1, b"AXButton", object()):
            with self.subTest(payload=payload):
                self.refused(self.api(position=(0, "leaf"),
                                      attributes={"AXRole": payload}))
        # An AX error status on the AXRole read still refuses.
        self.refused(self.api(position=(0, "leaf"),
                              attributes={"AXRole": (5, NativeNSString("AXButton"))}))

    def test_no_value_status_is_the_documented_no_object_miss(self):
        # ApplicationServices.kAXErrorNoValue ("There is no accessibility
        # object at the specified position") is a query that SUCCEEDED with no
        # object: a miss the bounded candidate loop may skip, never an error.
        self.assertEqual(macos._ax_status(types.SimpleNamespace(kAXErrorNoValue=NO_VALUE)),
                         (NO_VALUE, 0))
        self.assertIs(self.root(self.api(position=(NO_VALUE, None))), False)

    def test_other_ax_statuses_stay_query_refusals(self):
        for status in (-25200, -25201, -25202, -25203, -25204, -25205, -25206,
                       -25208, 1, 7, -1):
            with self.subTest(status=status):
                self.refused(self.api(position=(status, None)))
                self.refused(self.api(position=(status, "leaf")))
                self.refused(self.api(position=(0, "leaf"),
                                      attributes={"AXParent": (status, None)}))
                self.refused(self.api(position=(0, "leaf"),
                                      attributes={"AXRole": (status, "AXButton")}))

    def test_parent_no_value_ends_the_chain_as_a_valid_false_hit(self):
        # AXParent has no value: the chain ends before any AXWindow.
        self.assertIs(self.root(self.api(position=(0, "leaf"),
                                         attributes={"AXParent": (NO_VALUE, None)})), False)
        # One step later it still ends before the bound AXWindow.
        self.assertIs(self.root(self.api(position=(0, "group"),
                                         attributes={"AXParent": (NO_VALUE, None)})), False)
        # But a no-value AXRole is an unknown identity, not a miss.
        self.refused(self.api(position=(0, "leaf"),
                              attributes={"AXRole": (NO_VALUE, None)}))

    def test_unavailable_no_value_constant_refuses(self):
        for constant in (None, -25212.0, "-25212", True, -25211, -25213):
            with self.subTest(constant=constant):
                api = self.api(position=(0, "leaf"))
                if constant is None:
                    del api.ax.kAXErrorNoValue
                else:
                    api.ax.kAXErrorNoValue = constant
                self.refused(api)

    def test_position_and_attribute_bool_statuses_are_malformed(self):
        # ``False == 0`` but a bool is not an AXError: it never proves a
        # success and never classifies as a no-value miss.
        for status in (False, True):
            with self.subTest(status=status):
                self.refused(self.api(position=(status, None)))
                self.refused(self.api(position=(status, "leaf")))
                self.refused(self.api(position=(status, "window"), parent="bound"))
                self.refused(self.api(position=(0, "leaf"),
                                      attributes={"AXRole": (status, "AXButton")}))
                self.refused(self.api(position=(0, "leaf"),
                                      attributes={"AXParent": (status, None)}))
        self.assertIs(self.root(self.api(position=(0, "window"), parent="bound")), True)
        self.assertIs(self.root(self.api(position=(0, "leaf"),
                                         attributes={"AXParent": (0, None)})), False)

    def adapter_refusal(self, api):
        with self.assertRaises(contract.ContractError) as error:
            execute(macos.MacAdapter(api=api), document())
        self.assertEqual(error.exception.code, "a11y-query")
        self.assertEqual(api.clicks, [])

    def test_adapter_root_error_is_refused_before_any_click(self):
        api = FakeMacApi()

        def failing_root(window, x, y):
            raise OSError("AX position query failed")

        api.root_at = failing_root
        self.adapter_refusal(api)
        self.assertEqual(api.hit_calls, [])

    def test_adapter_non_boolean_or_unavailable_root_is_refused(self):
        for value in (None, 1, 0, "window"):
            with self.subTest(value=value):
                api = FakeMacApi()
                api.root_at = lambda window, x, y, value=value: value
                self.adapter_refusal(api)
        api = FakeMacApi()
        unavailable = self.api(application=None)
        api.root_at = lambda window, x, y: unavailable.root_at(window, x, y)
        self.adapter_refusal(api)

CENTRE = (CONTROL["bounds"]["x"] + CONTROL["bounds"]["width"] // 2,
          CONTROL["bounds"]["y"] + CONTROL["bounds"]["height"] // 2)


class ScriptedMacApi(FakeMacApi):
    """FakeMacApi whose display/root queries are answered per point.

    ``failures`` maps a point to the query kind(s) that raise the real fixed
    ``a11y-query`` there; every other point is a successful display/root hit.
    Both queries are recorded so a test can show exactly how far the search
    got before it stopped.
    """

    def __init__(self, failures):
        FakeMacApi.__init__(self)
        self.failures = dict(failures)
        self.display_points = []
        self.root_points = []

    def hit_test_control(self, window, label, rect, x, y):
        # Every point reaches the selected control unless the query failed
        # first, so a skippable error WOULD recover and click here.
        self.hit_calls.append((window["id"], label, dict(rect), x, y))
        return True

    def _query(self, seen, kind, x, y):
        seen.append((x, y))
        if kind in self.failures.get((x, y), ()):
            raise contract.ContractError("a11y-query")
        return True

    def point_visible(self, window, x, y):
        return self._query(self.display_points, "display", x, y)

    def root_at(self, window, x, y):
        return self._query(self.root_points, "root", x, y)


def run_macos_queries(api):
    """Run one end-to-end macOS label click over a scripted QuartzApi fake."""
    return execute(macos.MacAdapter(api=api), document())


def macos_candidates(rect):
    return [(item["x"], item["y"])
            for item in macos.MacAdapter.click_candidates(rect)]


class MacEarlyCandidateQueryTests(unittest.TestCase):
    """A query failure on an early candidate aborts; it never skips ahead."""

    def assert_aborted(self, api, *, root):
        """Run to the first refusal; no click and no display query past it."""
        with self.assertRaises(contract.ContractError) as error:
            run_macos_queries(api)
        self.assertEqual(error.exception.code, "a11y-query")
        self.assertEqual(api.root_points, root)
        self.assertEqual(api.clicks, [])
        return error.exception

    def test_centre_display_query_failure_aborts_without_click(self):
        # Only the centre's display query fails; every later candidate is a
        # successful display/root hit whose control probe would pass, so a
        # skippable miss would recover and click.  The search must stop on the
        # first error after exactly one root and one display query.
        self.assert_aborted(ScriptedMacApi({CENTRE: ("display",)}), root=[CENTRE])

    def test_centre_window_root_failure_aborts_without_click(self):
        self.assert_aborted(ScriptedMacApi({CENTRE: ("root",)}), root=[CENTRE])

    def test_centre_display_failure_aborts_on_the_post_accept_reproof(self):
        # The centre passes its initial full proof; the display query then
        # fails on the immediate pre-click re-proof.  The accepted point is
        # never clicked and the search never resumes with an alternate.
        api = ScriptedMacApi({})
        queries = []

        def visible(window, x, y):
            queries.append((x, y))
            if len(queries) == 2:
                raise contract.ContractError("a11y-query")
            return True

        api.point_visible = visible
        self.assert_aborted(api, root=[CENTRE, CENTRE])
        self.assertEqual(queries, [CENTRE, CENTRE])
        self.assertEqual(api.root_points, [CENTRE, CENTRE])
        self.assertEqual(api.hit_calls,
                         [(WINDOW_RAW["id"], LABEL, dict(CONTROL["bounds"]), *CENTRE)])

    def test_accepted_click_receipt_names_the_fresh_window(self):
        # The adapter reports a new observation of the same window for the
        # post-accept re-proof; the receipt and the result use that fresh
        # window, not the one the search started from.
        api = FakeMacApi()
        fresh_bounds = {"x": 100, "y": 100, "width": 801, "height": 600}
        fresh = dict(WINDOW_RAW, bounds=dict(fresh_bounds), client=dict(fresh_bounds))
        reads = []

        class FreshWindowAdapter(macos.MacAdapter):
            def read_window(self, identifier):
                reads.append(identifier)
                return dict(fresh)

        result = execute(FreshWindowAdapter(api=api), document())
        self.assertEqual(reads, [WINDOW_RAW["id"], WINDOW_RAW["id"]])
        self.assertEqual(api.clicks, [CENTRE])
        self.assertEqual(result["clicks"][0]["window"], hex(WINDOW_RAW["id"]))
        self.assertEqual((result["x"], result["width"]),
                         (fresh_bounds["x"], fresh_bounds["width"]))

    def test_legitimate_off_display_miss_still_moves_on(self):
        # Control: a successful False (not an error) on the centre is a miss
        # and the next in-bounds candidate is clicked exactly once.
        api = FakeMacApi()
        api.display_bounds = [(0, 0, CENTRE[0], 2160)]
        result = run_macos_queries(api)
        accepted = macos_candidates(CONTROL["bounds"])[1]
        self.assertEqual(api.clicks, [accepted])
        # One full proof per candidate (the display query precedes the root
        # query in check_point) and the accepted point proved again before input.
        self.assertEqual(api.display_queries, 3)
        self.assertEqual(result["clicks"][0]["window"], hex(WINDOW_RAW["id"]))
        self.assertEqual((result["clicks"][0]["x"], result["clicks"][0]["y"]), accepted)


class DispatcherTests(unittest.TestCase):
    def test_native_platform_detection(self):
        with patch.object(driver.os, "name", "nt"), patch.object(driver.sys, "platform", "win32"):
            self.assertEqual(driver.detect_platform(), "windows")
        with patch.object(driver.sys, "platform", "darwin"):
            self.assertEqual(driver.detect_platform(), "macos")
        with patch.object(driver.sys, "platform", "linux"):
            self.assertEqual(driver.detect_platform(), "linux")
        with patch.object(driver.sys, "platform", "aix"):
            self.assertEqual(driver.detect_platform(), "unknown")

    def test_linux_replays_bytes_into_the_unchanged_x11_driver(self):
        spy = unittest.mock.Mock(return_value=types.SimpleNamespace(returncode=7))
        raw = document().encode()
        with patch.object(driver.subprocess, "run", spy), \
                patch.object(driver, "detect_platform", lambda: "linux"):
            status = driver.main(argv=[], stdin=io.BytesIO(raw),
                                 stdout=io.StringIO(), stderr=io.StringIO())
        self.assertEqual(status, 7)
        argv = spy.call_args.args[0]
        self.assertEqual(argv, [sys.executable, driver.X11_DRIVER])
        self.assertEqual(spy.call_args.kwargs["input"], raw)
        self.assertNotIn(TITLE, " ".join(argv))

    def test_windows_dispatch_forwards_bytes_not_arguments(self):
        spy = unittest.mock.Mock(return_value=0)
        raw = document().encode()
        with patch.object(windows, "main", spy), \
                patch.object(driver, "detect_platform", lambda: "windows"):
            status = driver.main(argv=[], stdin=io.BytesIO(raw),
                                 stdout=io.StringIO(), stderr=io.StringIO())
        self.assertEqual(status, 0)
        self.assertEqual(spy.call_args.kwargs["stdin"].read(), raw)
        self.assertEqual(spy.call_args.args, ())
        self.assertNotIn(TITLE, json.dumps(list(spy.call_args.args)))

    def test_macos_dispatch_on_linux_fails_closed_with_one_fixed_line(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        status = driver.main(argv=["--platform", "macos"], stdin=io.BytesIO(document().encode()),
                             stdout=stdout, stderr=stderr)
        self.assertEqual(status, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("code=capability-unavailable", stderr.getvalue())
        self.assertNotIn(TITLE, stderr.getvalue())
        self.assertEqual(stderr.getvalue().count("\n"), 1)

    def test_unknown_platform_argument_refused_without_echo(self):
        cases = ((["--platform", "solaris"], "platform-unsupported"),
                 (["--platform"], "request-invalid"),
                 (["--title", TITLE], "request-invalid"))
        for argv, code in cases:
            with self.subTest(argv=argv):
                stderr = io.StringIO()
                status = driver.main(argv=argv, stdin=io.BytesIO(b"{}"),
                                     stdout=io.StringIO(), stderr=stderr)
                self.assertEqual(status, 2)
                self.assertIn("code=" + code, stderr.getvalue())
                self.assertNotIn(TITLE, stderr.getvalue())


class SourceHygieneTests(unittest.TestCase):
    BANNED = ("ValuePattern", "TextPattern", "InvokePattern", "LegacyIAccessible",
              "kAXValueAttribute", "kAXSelectedTextAttribute", "AXUIElementSetAttributeValue",
              "AXUIElementPerformAction", "AXPress", "SetClipboard", "GetClipboardData",
              "SendKeys", "SetText", "AXIsProcessTrustedWithOptions")

    def source(self, module):
        with open(module.__file__, encoding="utf-8") as handle:
            return handle.read()

    def test_platform_sources_avoid_forbidden_automation_apis(self):
        for module in (windows, macos, driver):
            source = self.source(module)
            for token in self.BANNED:
                with self.subTest(module=module.__name__, token=token):
                    self.assertFalse(token in source,
                                     "%s contains %s" % (module.__name__, token))

    def test_platform_sources_do_not_read_environment_or_home(self):
        for module in (windows, macos, driver):
            source = self.source(module)
            for token in ("os.environ", "expanduser", "HOME", "getenv"):
                with self.subTest(module=module.__name__, token=token):
                    self.assertFalse(token in source,
                                     "%s contains %s" % (module.__name__, token))


# Wholly inside MEASURED_CG (x 313..1415, y 75..897), as the real QuartzApi
# reports a control: fractional, non-integral origin and extent.
FRACTIONAL_CONTROL = {"x": 400.5, "y": 300.25, "width": 80.5, "height": 30.5}


class MacFractionalGeometryTests(unittest.TestCase):
    """A fractional CGFloat bound keeps its exact fraction to the click.

    The full real AXValue -> QuartzApi.frame -> shared contract -> Quartz
    CGEvent path runs over the shared AX tree fixture; the click point and the
    receipt must both be the exact geometric centre of the control.
    """

    CENTRE = (440.75, 315.5)  # 400.5 + 80.5 / 2, 300.25 + 30.5 / 2 (true division)

    @staticmethod
    def window():
        # The fake window client is the actual CG bounds the identity is
        # proved against: QuartzApi.list_windows makes client a copy of bounds.
        return measured_window(bounds=dict(MEASURED_CG), client=dict(MEASURED_CG))

    def tree(self, control=None, window=None):
        selected = ax_window(frame=MEASURED_AX, focused=True)
        button = {"role": "AXButton", "title": LABEL, "enabled": True, "hidden": False,
                  "parent": selected, "children": [],
                  "frame": dict(FRACTIONAL_CONTROL if control is None else control)}
        if window is not None:
            selected["frame"] = dict(window)
        selected["children"] = [button]
        return [selected]

    def api(self, tree_windows, hit=None):
        fixture = self.fixture = MacWindowIdentityTests()  # fresh per graph
        api = fixture.identity_api(list(tree_windows), self.window())
        api.quartz = FakeQuartzEvents()
        # The shared fixture stubs input on the graph; the real QuartzApi
        # methods must run instead, with the real posting loop bound to this
        # graph's fake Quartz object (an instance attribute shadows the class).
        for name in ("click", "type_text", "press_chord", "_post"):
            api.__dict__.pop(name, None)
        api._post = types.MethodType(macos.QuartzApi._post, api)
        # ``__new__`` skipped __init__, so ``windows()`` would otherwise
        # resolve to the class function and read ``self.window_list``.
        api.windows = types.MethodType(macos.QuartzApi.windows, api)
        # The nodes the AXWindows fake actually serves (it holds its own list).
        served = fixture.listed(api)
        api.selected = served[0]
        # The shared fixture answers a fixed window list; serve the graph.
        fixture.window_list = served
        api.process = lambda pid: (EXE, True)
        api.probed = []
        # The topmost hit is the glyph (a child of the selected control); its
        # own frame is never part of the control identity.
        api.glyph = {"role": "AXStaticText", "title": "", "children": [],
                     "frame": {"x": 210, "y": 305, "width": 20, "height": 10},
                     "parent": served[0]["children"][0],
                     "enabled": None, "hidden": None, "description": None}
        served[0]["children"][0]["parent"] = served[0]
        # CFEqual over these fakes is object identity (as for the other
        # end-to-end Mac fixture): a distinct same-frame twin is never equal.
        api.ax.CFEqual = lambda left, right: left is right

        def element_at(app, x, y, out):
            api.probed.append((x, y))
            top = hit(x, y) if callable(hit) else hit
            return (0, api.glyph if top is None else top)

        api.ax.AXUIElementCopyElementAtPosition = element_at
        api.control_rects = []

        def hit_control(window, label, rect, x, y):
            api.control_rects.append(dict(rect))
            return macos.QuartzApi.hit_test_control(api, window, label, rect, x, y)

        api.hit_test_control = hit_control
        return api

    def execute(self, api, actions=None):
        adapter = macos.MacAdapter(api=api)
        # This class tests geometry, not display membership.
        adapter.point_visible = lambda window, x, y: True
        return execute(adapter,
                       document(actions=[{"click_label": LABEL}] if actions is None else actions))

    def test_fractional_ax_position_and_size_are_preserved_by_frame(self):
        api = self.api(self.tree())
        button = api.selected["children"][0]
        self.assertEqual(api.frame(button), FRACTIONAL_CONTROL)
        self.assertEqual([type(api.frame(button)[key]) for key in ("x", "y", "width", "height")],
                         [float, float, float, float])
        # An integral float is still the same pixel as the integer.
        api = self.api(self.tree(control={"x": 200.0, "y": 300.0, "width": 80.0, "height": 30.0}))
        button = api.selected["children"][0]
        self.assertEqual(api.frame(button), CONTROL["bounds"])
        self.assertEqual([type(value) for value in api.frame(button).values()],
                         [int, int, int, int])

    def test_fractional_control_fits_the_window_and_clicks_its_exact_centre(self):
        api = self.api(self.tree())
        window = api.window_list[0]
        # The fake window client is the exact CG bounds used for identity and
        # the fractional control lies wholly inside those bounds.
        self.assertEqual(window["bounds"], dict(MEASURED_CG))
        self.assertEqual(window["client"], dict(MEASURED_CG))
        self.assertEqual(macos._frame_relation(api.selected["frame"], window["bounds"]), "border-inset")
        left, top = window["client"]["x"], window["client"]["y"]
        right = left + window["client"]["width"]
        bottom = top + window["client"]["height"]
        self.assertTrue(left <= FRACTIONAL_CONTROL["x"] and
                        top <= FRACTIONAL_CONTROL["y"] and
                        FRACTIONAL_CONTROL["x"] + FRACTIONAL_CONTROL["width"] <= right and
                        FRACTIONAL_CONTROL["y"] + FRACTIONAL_CONTROL["height"] <= bottom)
        self.assertTrue(contract.rect_within(FRACTIONAL_CONTROL, window["client"]))
        result = self.execute(api)
        # The accepted centre is proved once to accept and once more, on the
        # fresh window, immediately before the single click.
        self.assertEqual(api.control_rects, [FRACTIONAL_CONTROL, FRACTIONAL_CONTROL])
        # The window-root hit test and the strict control hit test both query
        # the element under the very same exact centre, twice per accepted point.
        self.assertEqual(api.probed, [self.CENTRE] * 4)
        self.assertEqual([event["point"] for event in api.quartz.posted],
                         [self.CENTRE, self.CENTRE, self.CENTRE])
        self.assertEqual([event["kind"] for event in api.quartz.posted],
                         [FakeQuartzEvents.kCGEventMouseMoved,
                          FakeQuartzEvents.kCGEventLeftMouseDown,
                          FakeQuartzEvents.kCGEventLeftMouseUp])
        recorded = result["clicks"][0]
        self.assertEqual((recorded["x"], recorded["y"]), self.CENTRE)
        self.assertEqual(recorded["x"], 400.5 + 80.5 / 2)  # exact fraction, no floor
        self.assertEqual(recorded["y"], 300.25 + 30.5 / 2)
        self.assertIs(type(recorded["x"]), float)
        self.assertEqual(recorded["label"], LABEL)
        self.assertEqual(recorded["window"], hex(WINDOW_RAW["id"]))
        self.assertEqual(recorded["evidence"], "posted")
        self.assertEqual(recorded["ack"], {"move": True, "down": True, "up": True})
        self.assertEqual(result["window"], hex(WINDOW_RAW["id"]))
        # The real root/hit walks and the real identity check ran for it:
        # focus is proved before the search and again after the accepted
        # candidate, along with the window/control re-observation.
        self.assertEqual(api.focus_reads, [WINDOW_RAW["id"]] * 3)
        self.assertIs(api.window_element(dict(window)), api.selected)

    def test_fractional_odd_and_non_quarter_bounds_are_not_rounded(self):
        cases = (
            # Every control lies wholly inside MEASURED_CG; the centre of
            # geometry carrying a genuine fraction is the true centre.
            ("integral-origin-fractional-extent",
             {"x": 400.0, "y": 300.0, "width": 80.5, "height": 30.5}, (440.25, 315.25)),
            ("integral-floats-even-extent",
             {"x": 400.0, "y": 300.0, "width": 80.0, "height": 30.0}, (440.0, 315.0)),
            ("fractional-origin-odd-extent",
             {"x": 400.25, "y": 300.25, "width": 81.0, "height": 31.0}, (440.75, 315.75)),
            ("quarter-extents",
             {"x": 400.25, "y": 300.75, "width": 80.5, "height": 30.5}, (440.5, 316.0)),
            ("eighth-centre",
             {"x": 400.5, "y": 300.25, "width": 81.5, "height": 31.25}, (441.25, 315.875)))
        for name, control, centre in cases:
            with self.subTest(case=name):
                api = self.api(self.tree(control=control))
                result = self.execute(api)
                self.assertEqual([event["point"] for event in api.quartz.posted],
                                 [centre, centre, centre])
                recorded = (result["clicks"][0]["x"], result["clicks"][0]["y"])
                self.assertEqual(recorded, centre)
                # Geometry with any genuine fraction yields a finite float
                # centre; purely integral-float geometry keeps the historical
                # integer centre.
                kinds = (["int", "int"] if all(
                    type(control[key]) is int or float(control[key]).is_integer()
                    for key in ("x", "y", "width", "height")) else ["float", "float"])
                self.assertEqual([type(value).__name__ for value in recorded], kinds)

    def test_integer_geometry_still_clicks_the_integer_centre(self):
        # Plain ints wholly inside the measured CG client (x 313..1415,
        # y 75..897) keep the historical odd-size floor centre.
        api = self.api(self.tree(control={"x": 400, "y": 300, "width": 81, "height": 31}))
        result = self.execute(api)
        self.assertEqual([event["point"] for event in api.quartz.posted], [(440, 315)] * 3)
        self.assertEqual((result["clicks"][0]["x"], result["clicks"][0]["y"]), (440, 315))
        self.assertEqual([type(result["clicks"][0]["x"])], [int])

    def test_integer_geometry_outside_the_measured_client_refuses(self):
        # CONTROL["bounds"] {200,300,80,30} lies left of the measured CG client
        # (x 313..1415), so a faithful window refuses it as off screen.
        api = self.api(self.tree(control=dict(CONTROL["bounds"])))
        self.assertFalse(contract.rect_within(api.selected["children"][0]["frame"],
                                              api.window_list[0]["client"]))
        with self.assertRaises(contract.ContractError) as error:
            self.execute(api)
        self.assertEqual(error.exception.code, "control-offscreen")
        self.assertEqual(api.quartz.posted, [])

    def test_same_window_receipt_is_the_same_identity(self):
        api = self.api(self.tree())
        result = self.execute(api)
        self.assertEqual(result["clicks"][0]["window"], hex(WINDOW_RAW["id"]))
        self.assertEqual(api.focus_reads, [WINDOW_RAW["id"]] * 3)

    def test_changed_fractional_frame_refuses_before_input(self):
        # The control is read at the authorising frame; it then moves to a
        # changed frame (fractional, or the same pixel as an integer) and the
        # strict control identity re-resolves it before the click, so it must
        # refuse with no input posted.
        for changed in ({"x": 200.75, "y": 300.25, "width": 80.5, "height": 30.5},
                        {"x": 200.5, "y": 300.25, "width": 80.5, "height": 30.501},
                        {"x": 200.5, "y": 300.25, "width": 81, "height": 30},
                        {"x": 200.5, "y": 300.25, "width": 81.0, "height": 31.0}):
            with self.subTest(changed=changed):
                api = self.api(self.tree())
                target = api.selected["children"][0]
                current = {"frame": dict(FRACTIONAL_CONTROL)}
                probe = api.hit_test_control

                def frame_of(element):
                    if element is target:
                        return dict(current["frame"])
                    return macos.QuartzApi.frame(api, element)

                def move_then_probe(window, label, rect, x, y):
                    current["frame"] = dict(changed)
                    return probe(window, label, rect, x, y)

                api.frame = frame_of
                api.hit_test_control = move_then_probe
                with self.assertRaises(contract.ContractError) as error:
                    self.execute(api)
                self.assertEqual(error.exception.code, "control-hit")
                self.assertEqual(api.quartz.posted, [])

    def test_centre_overlay_then_in_bounds_field_point_reaches_the_field(self):
        # The unique synthetic 主密码 AXTextField lies wholly inside the exact
        # client; its centre is stably covered by another AX element, while
        # in-bounds left/right points still resolve to the field itself.
        window = ax_window(frame=MEASURED_AX, focused=True)
        field = {"role": "AXTextField", "title": "主密码", "enabled": True,
                 "hidden": False, "parent": window, "children": [],
                 "frame": dict(FRACTIONAL_CONTROL)}
        window["children"] = [field]
        overlay = {"role": "AXGroup", "title": "", "parent": window, "children": [],
                   "frame": {"x": self.CENTRE[0] - 1, "y": self.CENTRE[1] - 1,
                             "width": 2, "height": 2}}
        glyph = {"role": "AXStaticText", "title": "", "children": [],
                 "frame": {"x": 401, "y": 301, "width": 20, "height": 10},
                 "parent": field, "enabled": None, "hidden": None,
                 "description": None}
        overlay_hits = []

        def topmost(x, y):
            covered = (x, y) == self.CENTRE
            overlay_hits.append(covered)
            return overlay if covered else glyph

        api = self.api([window], hit=topmost)
        api.glyph = glyph
        served = api.window_list[0]
        # Exact identity: one eligible control record, wholly inside the client.
        controls = [record for record in api.controls(served)
                    if record["name"] == "主密码"]
        self.assertEqual(len(controls), 1)
        self.assertEqual(controls[0]["role"], "entry")
        self.assertEqual(controls[0]["bounds"], FRACTIONAL_CONTROL)
        self.assertTrue(contract.rect_within(FRACTIONAL_CONTROL, served["client"]))
        # The centre stays covered on every query; left/right in-bounds points
        # resolve to the selected field through the real AXParent/CFEqual walk.
        left = (FRACTIONAL_CONTROL["x"] + FRACTIONAL_CONTROL["width"] * 0.2,
                FRACTIONAL_CONTROL["y"] + FRACTIONAL_CONTROL["height"] * 0.5)
        right = (FRACTIONAL_CONTROL["x"] + FRACTIONAL_CONTROL["width"] * 0.8,
                 FRACTIONAL_CONTROL["y"] + FRACTIONAL_CONTROL["height"] * 0.5)
        for _ in range(2):
            self.assertFalse(api.hit_test_control(
                dict(served), "主密码", dict(FRACTIONAL_CONTROL), *self.CENTRE))
        self.assertTrue(api.hit_test_control(
            dict(served), "主密码", dict(FRACTIONAL_CONTROL), *left))
        self.assertTrue(api.hit_test_control(
            dict(served), "主密码", dict(FRACTIONAL_CONTROL), *right))
        self.assertEqual(overlay_hits, [True, True, False, False])
        # The shared contract takes the first in-bounds candidate after the
        # covered centre and clicks it exactly once at that exact coordinate.
        api.control_rects = []
        result = self.execute(api, actions=[{"click_label": "主密码"}])
        accepted = (FRACTIONAL_CONTROL["x"] + FRACTIONAL_CONTROL["width"] * 0.2,
                    FRACTIONAL_CONTROL["y"] + FRACTIONAL_CONTROL["height"] * 0.2)
        # The three overlay probes are the test's own; the contract probes only
        # the covered centre (a miss) and the accepted point, which is then
        # proved once more before the single click.
        self.assertEqual(api.control_rects, [FRACTIONAL_CONTROL] * 3)
        self.assertEqual([event["point"] for event in api.quartz.posted],
                         [accepted, accepted, accepted])
        recorded = result["clicks"][0]
        self.assertEqual((recorded["x"], recorded["y"]), accepted)
        self.assertEqual((type(recorded["x"]), type(recorded["y"])), (float, float))
        self.assertEqual(recorded["window"], hex(WINDOW_RAW["id"]))
        self.assertEqual(recorded["label"], "主密码")
        self.assertEqual(recorded["evidence"], "posted")
        self.assertEqual(recorded["ack"], {"move": True, "down": True, "up": True})
        self.assertTrue(contract.rect_positive(FRACTIONAL_CONTROL))
        self.assertTrue(accepted[0] < FRACTIONAL_CONTROL["x"] + FRACTIONAL_CONTROL["width"])
        self.assertTrue(accepted[1] < FRACTIONAL_CONTROL["y"] + FRACTIONAL_CONTROL["height"])

    def test_no_value_at_the_centre_misses_and_the_next_candidate_clicks(self):
        # The real QuartzApi, through the real AX tree fixture and the real
        # MacAdapter candidate search: the documented kAXErrorNoValue
        # ("no accessibility object at the specified position") at the centre
        # is a successful MISS, so the bounded loop tries the next in-bounds
        # point, reaches the selected control there, re-proves the accepted
        # point and clicks it exactly once - at that later exact point.
        expected = macos_candidates(FRACTIONAL_CONTROL)
        centre, later = expected[0], expected[1]
        api = self.api(self.tree())
        # A well-formed (kAXErrorNoValue, None) position result at the centre;
        # every other point answers the glyph under the selected control.
        position = api.ax.AXUIElementCopyElementAtPosition
        no_value_at = []

        def element_at(app, x, y, out):
            if (x, y) == centre:
                api.probed.append((x, y))
                no_value_at.append((x, y))
                return (api.ax.kAXErrorNoValue, None)
            return position(app, x, y, out)

        api.ax.AXUIElementCopyElementAtPosition = element_at
        result = self.execute(api)
        # Every AX position query on the centre was the no-object answer (the
        # centre is then skipped, never clicked) and the later point was
        # probed for its acceptance and again for the pre-click re-proof; the
        # accepted point is never resumed with an alternate after re-proof.
        self.assertEqual(no_value_at, [centre])
        self.assertEqual(api.probed.count(centre), 1)
        self.assertNotIn(centre, [event["point"] for event in api.quartz.posted])
        self.assertGreaterEqual(api.probed.count(later), 2)
        self.assertEqual(api.probed[-1], later)
        self.assertNotIn(later, no_value_at)
        self.assertEqual([event["point"] for event in api.quartz.posted], [later] * 3)
        self.assertEqual([event["kind"] for event in api.quartz.posted],
                         [FakeQuartzEvents.kCGEventMouseMoved,
                          FakeQuartzEvents.kCGEventLeftMouseDown,
                          FakeQuartzEvents.kCGEventLeftMouseUp])
        recorded = result["clicks"][0]
        self.assertEqual((recorded["x"], recorded["y"]), later)
        self.assertNotEqual(later, centre)
        self.assertEqual((type(recorded["x"]), type(recorded["y"])), (float, float))
        self.assertEqual(recorded["window"], hex(WINDOW_RAW["id"]))
        self.assertEqual(recorded["evidence"], "posted")
        self.assertEqual(len(api.quartz.posted), 3)  # exactly one click batch

    def test_sibling_overlay_at_fractional_centre_refuses_before_input(self):
        # A transparent group drawn above the control at the same fractional
        # bounds: it is the element under the centre and never reaches the
        # selected control.
        window = self.tree()[0]
        overlay = {"role": "AXGroup", "title": "", "parent": window, "children": [],
                   "frame": dict(FRACTIONAL_CONTROL)}
        window["children"].append(overlay)
        api = self.api([window], hit=overlay)
        with self.assertRaises(contract.ContractError) as error:
            self.execute(api)
        self.assertEqual(error.exception.code, "control-hit")
        self.assertEqual(api.quartz.posted, [])
        # A second unique-labelled button at the same frame is ambiguous.
        twin = {"role": "AXButton", "title": LABEL, "enabled": True, "hidden": False,
                "parent": window, "children": [], "frame": dict(FRACTIONAL_CONTROL)}
        window["children"].append(twin)
        api = self.api([window])
        with self.assertRaises(contract.ContractError) as error:
            self.execute(api)
        self.assertEqual(error.exception.code, "control-ambiguous")
        self.assertEqual(api.quartz.posted, [])

    def test_control_outside_the_window_refuses_with_fractions(self):
        for control, code in (
                # Past the CG right edge (313 + 1102 = 1415).
                ({"x": 1410.5, "y": 300.25, "width": 20.0, "height": 10.0}, "control-offscreen"),
                ({"x": 1400.5, "y": 300.25, "width": 0.0, "height": 10.0}, "control-geometry"),
                # Inside the window horizontally, but past its bottom edge
                # (75 + 822 = 897).
                ({"x": 400.5, "y": 900.25, "width": 20.0, "height": 10.0}, "control-offscreen")):
            with self.subTest(control=control):
                api = self.api(self.tree(control=control))
                with self.assertRaises(contract.ContractError) as error:
                    self.execute(api)
                self.assertEqual(error.exception.code, code)
                self.assertEqual(api.quartz.posted, [])

    def test_nonfinite_bool_and_subclass_geometry_refuses(self):
        class SubFloat(float):
            def __float__(self):
                raise AssertionError("float() dispatch on hostile AX geometry")

        for value in (True, False, float("nan"), float("inf"), float("-inf"),
                      SubFloat(80.5), "80.5", None):
            for key in ("x", "width"):
                with self.subTest(value=value, key=key):
                    control = dict(FRACTIONAL_CONTROL, **{key: value})
                    api = self.api(self.tree(control=control))
                    with self.assertRaises(macos.AxValueUnavailable):
                        api.frame(api.selected["children"][0])
                    with self.assertRaises(contract.ContractError) as error:
                        self.execute(api)
                    self.assertEqual(error.exception.code, "control-geometry")
                    self.assertEqual(api.quartz.posted, [])

    def test_window_frame_with_fractional_offset_refuses_binding(self):
        # A fractional AX window origin/size is genuine geometry now, but the
        # binding still demands the exact CG frame or the exact canonical
        # integer border inset, so the shared window stays unbound.
        for frame in (dict(MEASURED_AX, x=314.5), dict(MEASURED_AX, width=1100.5),
                      dict(MEASURED_CG, x=313.5)):
            with self.subTest(frame=frame):
                api = self.api(self.tree(window=frame))
                self.assertEqual(api.window_list[0]["bounds"], dict(MEASURED_CG))
                self.assertEqual(api.selected["frame"], frame)
                self.assertIsNone(api._relation(api.selected, api.window_list[0]))


class Win32IntegerGeometryTests(unittest.TestCase):
    """Win32 receives explicit integers; a fractional point is never truncated."""

    def test_screen_int_accepts_integral_values_and_converts_before_the_call(self):
        self.assertEqual(windows.screen_int(240.0), 240)
        self.assertIs(type(windows.screen_int(240.0)), int)

        class IntSubclass(int):
            def __int__(self):
                raise AssertionError("int() dispatch in screen_int")

        self.assertEqual(windows.screen_int(IntSubclass(240)), 240)
        self.assertIs(type(windows.screen_int(IntSubclass(240))), int)

    def test_screen_int_refuses_fractional_nonfinite_bool_and_nonnumeric(self):
        for value in (240.5, True, False, float("nan"), float("inf"), "240", None,
                      -2 ** 31 - 1, 2 ** 31):
            with self.subTest(value=value):
                with self.assertRaises(contract.ContractError) as error:
                    windows.screen_int(value)
                self.assertEqual(error.exception.code, "control-offscreen")

    def test_click_converts_to_integers_before_sending_win32_input(self):
        class Recording(windows.Win32Api):
            def __init__(self):
                self.sent = []

            def screen_bounds(self):
                return {"x": 0, "y": 0, "width": 1920, "height": 1080}

            def _send(self, events):
                self.sent.append(events)
                return {"input": True}

        api = Recording()
        with patch.object(contract, "monotonic", return_value=0):
            api.click(240.0, 315)
        self.assertEqual(len(api.sent), 1)
        for point in ((240.5, 315), (240, 315.5)):
            with self.subTest(point=point):
                with self.assertRaises(contract.ContractError) as error:
                    api.click(*point)
                self.assertEqual(error.exception.code, "control-offscreen")
        self.assertEqual(len(api.sent), 1)


if __name__ == "__main__":
    unittest.main()
