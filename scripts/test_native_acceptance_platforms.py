"""Platform seam tests with fakes and spies: no real OS, GUI, TCC or input.

They prove the adapters only read the five public widget fields, only emit one
physical batch per action, verify foreground focus before input, refuse
ambiguity/untrusted/secure surfaces, and never prompt for OS permission.
"""
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
    def __init__(self, controls=None):
        self._controls = [dict(CONTROL)] if controls is None else controls
        self.reads = 0

    def controls(self, handle):
        self.reads += 1
        return [dict(item) for item in self._controls]


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

    def test_partial_sendinput_count_refused(self):
        class ShortUser32(object):
            def SendInput(self, count, array, size):
                return count - 1

        api = windows.Win32Api.__new__(windows.Win32Api)
        api.user32 = ShortUser32()
        with self.assertRaises(contract.ContractError) as error:
            api.type_text("a")
        self.assertEqual(error.exception.code, "input-failed")

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
                 focus_window=None, root=True):
        self.windows_list = [dict(WINDOW_RAW, secure=secure)] if windows_list is None else windows_list
        self._controls = [dict(CONTROL)] if controls is None else controls
        self.focus = focus
        self.focus_window = WINDOW_RAW["id"] if focus_window is None else focus_window
        self.root = root
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
        api.quartz = types.SimpleNamespace(kAXWindowsAttribute="AXWindows")
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
