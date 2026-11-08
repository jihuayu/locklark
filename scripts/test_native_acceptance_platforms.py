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
                 ([dict(WINDOW_RAW, visible=False)], "window-hidden"),
                 ([dict(WINDOW_RAW, executable="/opt/other/browser")], "process-untrusted"))
        for windows_list, code in cases:
            with self.subTest(code=code):
                api = FakeWin32(windows_list=windows_list)
                adapter = windows.WindowsAdapter(api=api, uia=FakeUia())
                with self.assertRaises(contract.ContractError) as error:
                    execute(adapter, document())
                self.assertEqual(error.exception.code, code)
                self.assertEqual(api.clicks, [])

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
        self.trusted = trusted
        self.activations = 0
        self.clicks = []
        self.typed = []
        self.chords = []

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
        return self.visible

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

    def test_overlay_at_the_control_centre_refuses_without_any_click(self):
        api = FakeMacApi(root=True, control_hit=False)
        with self.assertRaises(contract.ContractError) as error:
            execute(macos.MacAdapter(api=api), document())
        self.assertEqual(error.exception.code, "control-hit")
        self.assertEqual(api.clicks, [])
        self.assertEqual(api.hit_calls,
                         [(WINDOW_RAW["id"], LABEL, dict(CONTROL["bounds"]), 240, 315)])

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
            kAXWindowsAttribute="AXWindows",
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
        self.assertEqual(api.quartz.posted[0]["point"], (500.0, 400.0))

    def test_chord_posts_modifier_first_and_release_last_with_flags(self):
        api = self.api()
        api.press_chord(("Control_L", "a"))
        posted = api.quartz.posted
        self.assertEqual([(event["code"], event["down"]) for event in posted],
                         [(0x3B, True), (0x00, True), (0x00, False), (0x3B, False)])
        self.assertEqual(len(api.quartz.flagged), 4)
        self.assertEqual({flags for _event, flags in api.quartz.flagged}, {macos.FLAGS["Control_L"]})

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
            kAXWindowsAttribute="AXWindows",
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

    def api(self, result=None, bounds=None):
        api = macos.QuartzApi.__new__(macos.QuartzApi)

        class Quartz(object):
            def CGGetActiveDisplayList(self, maximum, displays, count):
                if isinstance(result, Exception):
                    raise result
                return result

            def CGDisplayBounds(self, display):
                value = bounds[display] if isinstance(bounds, dict) else bounds
                if isinstance(value, Exception):
                    raise value
                return value

        api.quartz = Quartz()
        return api

    def test_count_consistent_valid_display_is_visible(self):
        api = self.api((0, [1, 2, 3], 1), {1: ((0, 0), (1920, 1080)),
                                           2: ((3000, 0), (1280, 1024)),
                                           3: ((9000, 0), (1280, 1024))})
        self.assertTrue(api.point_visible(None, 100, 100))
        self.assertFalse(api.point_visible(None, 3100, 100))  # beyond reported count

    def test_point_inside_one_display_is_visible(self):
        api = self.api((0, [1, 2], 2), {1: ((0, 0), (1920, 1080)),
                                        2: ((1920, 0), (1280, 1024))})
        self.assertTrue(api.point_visible(None, 100, 100))
        self.assertTrue(api.point_visible(None, 2000, 1000))

    def test_gap_between_display_rectangles_is_not_screen(self):
        api = self.api((0, [1, 2], 2), {1: ((0, 0), (1920, 1080)),
                                        2: ((2000, 0), (1280, 1024))})
        self.assertFalse(api.point_visible(None, 1950, 100))

    def test_unknown_or_empty_display_list_fails_closed(self):
        cases = ((1, [1], 1),          # CoreGraphics error
                 (0, [], 0),           # no active display
                 (0, None, 0),         # unreadable list
                 "not-a-tuple",
                 (0, [1], 2),          # count larger than the returned list
                 (0, [1], True),       # a bool is never a display count
                 (0, [1], "1"),        # non-integer count
                 (0, [1], 0), (0, [1], 33))
        for result in cases:
            with self.subTest(result=result):
                api = self.api(result, ((0, 0), (1920, 1080)))
                self.assertFalse(api.point_visible(None, 100, 100))

    def test_unreadable_display_bounds_fail_closed(self):
        for bounds in (RuntimeError("no bounds"), ("x", "y"), ((0, 0), (0, 0)),
                       ((0, 0), (float("nan"), 1080)),
                       ((float("inf"), 0), (1920, 1080)), None):
            with self.subTest(bounds=bounds):
                api = self.api((0, [1], 1), {1: bounds})
                self.assertFalse(api.point_visible(None, 100, 100))

    def test_adapter_refuses_a_point_outside_every_display(self):
        api = FakeMacApi()
        api.point_visible = lambda window, x, y: False
        adapter = macos.MacAdapter(api=api)
        with self.assertRaises(contract.ContractError) as error:
            execute(adapter, document())
        self.assertEqual(error.exception.code, "control-offscreen")
        self.assertEqual(api.clicks, [])


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


if __name__ == "__main__":
    unittest.main()
