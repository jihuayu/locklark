"""Focused contract tests for opaque per-request window identity.

Contract only: no OS, GUI, TCC, AX call or adapter wiring. A trusted fake
adapter hands out genuine opaque handle objects (and, in one case, an
unhashable one) so the contract can distinguish them from an optional genuine
OS window id:

* a genuine int id keeps the historical ``"0x..."`` receipts byte-for-byte;
* an opaque handle is compared ONLY by trusted adapter equality, and
  re-observation / focus must prove the same handle and the same PID;
* a missing, ambiguous or mismatched identity refuses;
* the window budget dedups real identities and stays bounded;
* a receipt never serializes or fake-hexes a handle.
"""
import gc
import json
import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import native_acceptance_contract as contract

LABEL = "仅批准本次 CLI 请求"
TITLE = "Locklark · 浏览器原生确认"
EXE = "/opt/locklark/test-browser"
PID = 4242
BOUNDS = {"x": 100, "y": 100, "width": 800, "height": 600}
CLIENT = {"x": 110, "y": 140, "width": 780, "height": 560}
CONTROL_RECT = {"x": 200, "y": 300, "width": 80, "height": 30}


class Handle:
    """A genuine opaque per-request handle. Equality is object identity."""

    def __init__(self, label="window"):
        self.label = label

    @staticmethod
    def equals(left, right):
        """The trusted adapter's CFEqual-like equality: the very same object."""
        return left is right

    def __repr__(self):
        raise AssertionError("a handle must never be formatted")


class UnhashableHandle:
    """An opaque handle that is unhashable; each instance is its own window."""

    __hash__ = None

    def __init__(self, name):
        self.name = name

    @staticmethod
    def equals(first, second):
        return first is second


def _opaque_focus(window, state):
    """The document's focus check: same PID and the very same handle."""
    return (type(state) is dict and state.get("pid") == window["pid"]
            and Handle.equals(window["id"], state.get("window")))


def window(identifier, pid=PID):
    return {"id": identifier, "pid": pid, "title": TITLE, "executable": EXE,
            "trusted": True, "visible": True, "onscreen": True, "secure": False,
            "bounds": dict(BOUNDS), "client": dict(CLIENT)}


def control():
    return {"role": "push button", "name": LABEL, "bounds": dict(CONTROL_RECT),
            "enabled": True, "visible": True}


class OpaqueAdapter:
    """A trusted fake adapter serving opaque handles; records every call."""

    def activate(self, window_):
        self.calls.append("activate")

    platform = "linux"
    supports_activation = True
    exact_focus = True
    input_evidence = "accepted"

    def __init__(self, windows, reader=None, focus=None, equals=None,
                 focus_identity=None, read_handle=None):
        self.windows = list(windows)
        self.reader = reader
        self.focus = focus
        self.focus_identity = (_opaque_focus if focus_identity is None
                               else focus_identity)
        self.equals = Handle.equals if equals is None else equals
        self.read_handle = read_handle
        self.calls = []
        self.click_ack = {"move": True, "down": True, "up": True}

    def identity_equal(self, first, second):
        self.calls.append("identity_equal")
        return self.equals(first, second)

    def list_windows(self):
        self.calls.append("list_windows")
        return list(self.windows)

    def read_window(self, identifier):
        self.calls.append("read_window")
        if self.read_handle is not None:
            return self.read_handle(identifier)
        for window_ in self.windows:
            if window_["id"] is identifier:
                return dict(window_)
        return None

    def read_controls(self, window_):
        self.calls.append("read_controls")
        return [control()]

    def focus_state(self, window_=None):
        self.calls.append("focus_state")
        if self.focus is None:
            return {"pid": PID, "window": window_["id"]}
        return self.focus

    def hit_test(self, window_, x, y):
        return True

    def hit_test_control(self, window_, label, rect, x, y):
        return True

    def point_visible(self, window_, x, y):
        return True

    def click(self, x, y):
        self.calls.append(("click", x, y))
        return dict(self.click_ack)

    def type_text(self, text):
        self.calls.append("type_text")

    def press_chord(self, parts):
        self.calls.append("press_chord")


def request(**overrides):
    document = {"title": TITLE, "executable": EXE, "actions": [{"click_label": LABEL}]}
    document.update(overrides)
    return json.dumps(document)


def run(adapter, **overrides):
    plan = contract.parse_request(request(**overrides))
    with patch.object(contract, "monotonic", return_value=0), patch.object(contract, "sleep"):
        return contract.execute(plan, adapter)


class WindowIdentityClassifierTests(unittest.TestCase):
    def test_genuine_int_id_is_the_only_id_kind(self):
        for identifier in (1, 0x200003):
            with self.subTest(identifier=identifier):
                self.assertEqual(contract.window_identity({"id": identifier}),
                                 ("id", identifier))

    def test_opaque_handle_is_internal_only(self):
        handle = Handle()
        self.assertEqual(contract.window_identity({"id": handle}),
                         ("opaque", handle))

    def test_missing_and_fake_identities_are_refused(self):
        for identifier in (None, 0, -1, True, False, 1.0, "0x200003", b"\x01",
                           bytearray(b"x"), ""):
            with self.subTest(identifier=identifier):
                self.assertIsNone(contract.window_identity({"id": identifier}))
        self.assertIsNone(contract.window_identity({}))
        self.assertIsNone(contract.window_identity(None))

    def test_receipt_window_field_never_serializes_a_handle(self):
        self.assertEqual(contract._receipt_window(("id", 0x200003)), "0x200003")
        self.assertIsNone(contract._receipt_window(("opaque", Handle())))


class OpaqueDiscoveryAndReceiptTests(unittest.TestCase):
    def test_equal_handle_is_accepted_and_receipt_has_no_handle(self):
        handle = Handle()
        adapter = OpaqueAdapter([window(handle)])
        result = run(adapter, inspect=True)
        self.assertIsNone(result["window"])
        self.assertEqual(result["clicks"][0]["window"], None)
        self.assertEqual(result["pid"], PID)
        self.assertEqual(set(result["clicks"][0]), {"label", "window", "x", "y",
                                                    "before", "evidence", "ack"})
        self.assertEqual(result["clicks"][0]["x"], 240)
        self.assertEqual(result["clicks"][0]["y"], 315)
        payload = json.dumps(result, ensure_ascii=False)
        self.assertNotIn("Handle", payload)
        self.assertNotIn("object at 0x", payload)
        # Trusted equality was consulted for the re-observation.
        self.assertIn("identity_equal", adapter.calls)

    def test_genuine_int_id_receipts_stay_byte_compatible(self):
        adapter = OpaqueAdapter([window(0x200003)])
        result = run(adapter, inspect=True)
        self.assertEqual(result["window"], "0x200003")
        self.assertEqual(result["clicks"][0]["window"], "0x200003")

    def test_wrong_handle_with_same_pid_is_denied(self):
        selected, other = Handle("selected"), Handle("other")
        adapter = OpaqueAdapter([window(selected)], read_handle=lambda _id: dict(window(other)))
        with self.assertRaises(contract.ContractError) as error:
            run(adapter)
        self.assertEqual(error.exception.code, "window-changed")
        self.assertEqual([call for call in adapter.calls if isinstance(call, tuple)], [])

    def test_missing_identity_after_discovery_is_denied(self):
        handle = Handle()
        adapter = OpaqueAdapter([window(handle)],
                                read_handle=lambda _id: dict(window(None)))
        with self.assertRaises(contract.ContractError) as error:
            run(adapter)
        self.assertEqual(error.exception.code, "window-changed")
        self.assertEqual([call for call in adapter.calls if isinstance(call, tuple)], [])

    def test_identity_kind_cannot_switch_between_observations(self):
        handle = Handle()
        adapter = OpaqueAdapter([window(handle)],
                                read_handle=lambda _id: dict(window(0x200003)))
        with self.assertRaises(contract.ContractError) as error:
            run(adapter)
        self.assertEqual(error.exception.code, "window-changed")

    def test_missing_identity_at_discovery_is_denied(self):
        adapter = OpaqueAdapter([window(None)])
        with self.assertRaises(contract.ContractError) as error:
            run(adapter)
        self.assertEqual(error.exception.code, "window-changed")
        self.assertEqual([call for call in adapter.calls if isinstance(call, tuple)], [])


class OpaqueFocusTests(unittest.TestCase):
    def test_focus_must_prove_the_same_handle(self):
        handle = Handle()
        adapter = OpaqueAdapter([window(handle)])
        self.assertTrue(contract.focus_matches(adapter, window(handle), contract.Budget()))

    def test_wrong_focus_handle_same_pid_is_denied(self):
        handle, other = Handle(), Handle("other")
        adapter = OpaqueAdapter(
            [window(handle)],
            focus={"pid": PID, "window": other},
            focus_identity=lambda w, s: Handle.equals(w["id"], s["window"]))
        self.assertFalse(contract.focus_matches(adapter, window(handle), contract.Budget()))

    def test_wrong_pid_focus_is_denied(self):
        handle = Handle()
        adapter = OpaqueAdapter([window(handle)], focus={"pid": PID + 1, "window": handle})
        self.assertFalse(contract.focus_matches(adapter, window(handle), contract.Budget()))

    def test_missing_focus_checker_is_denied(self):
        handle = Handle()

        adapter = OpaqueAdapter([window(handle)], focus_identity=None)
        adapter.focus_identity = None
        self.assertFalse(contract.focus_matches(adapter, window(handle), contract.Budget()))


class Wrapper:
    """A DISTINCT Python object per observation naming one semantic window.

    Two wrappers of the same window are different objects with no equal hash
    or value; only the trusted adapter (``CFEqual``-like) knows they are the
    same window. Default (untrusted) Python equality never merges them.
    """

    __hash__ = None

    def __init__(self, name):
        self.name = name


class SemanticAdapter:
    """A trusted adapter that proves wrapper equality by the window's name."""

    def __init__(self, trusted=True):
        self.trusted = trusted
        self.equal_calls = 0

    def identity_equal(self, first, second):
        self.equal_calls += 1
        if first is second:
            return True
        return (self.trusted and type(first) is type(second)
                and getattr(first, "name", None) == getattr(second, "name", None))


class IdentityBudgetTests(unittest.TestCase):
    def test_distinct_wrappers_of_one_window_dedup_once(self):
        adapter = SemanticAdapter()
        budget = contract.Budget()
        for _ in range(contract.MAX_OBSERVATIONS - 1):
            # A NEW wrapper object each poll, same semantic window.
            budget.charge_windows([window(Wrapper("main"))], adapter)
        self.assertEqual(budget.counts["windows"], 1)
        self.assertEqual(len(budget.opaque_identities), 1)
        self.assertEqual(adapter.equal_calls, contract.MAX_OBSERVATIONS - 2)
        # Dedup is by semantic identity, not Python hash/id: the retained
        # handle is the FIRST wrapper, and every later one compared equal.
        self.assertIsInstance(budget.opaque_identities[0][1], Wrapper)

    def test_genuinely_different_windows_never_dedup(self):
        adapter = SemanticAdapter()
        budget = contract.Budget()
        budget.charge_windows([window(Wrapper("a"))], adapter)
        budget.charge_windows([window(Wrapper("b"))], adapter)
        self.assertEqual(budget.counts["windows"], 2)
        self.assertEqual(len(budget.opaque_identities), 2)
        # An adapter that cannot prove equality does not merge anything.
        budget.charge_windows([window(Wrapper("a"))], SemanticAdapter(trusted=False))
        self.assertEqual(budget.counts["windows"], 3)

    def test_untrusted_equality_never_merges_distinct_objects(self):
        # An adapter that cannot prove equality: distinct wrappers never merge.
        budget = contract.Budget()
        budget.charge_windows([window(Wrapper("a"))], SemanticAdapter(trusted=False))
        budget.charge_windows([window(Wrapper("a"))], SemanticAdapter(trusted=False))
        self.assertEqual(len(budget.opaque_identities), 2)

    def test_no_identity_hook_compares_only_the_same_object(self):
        class Plain:
            pass

        budget = contract.Budget()
        handle = Plain()
        # No identity_equal hook: the same object and only it is one window.
        budget.charge_windows([window(handle)], Plain())
        budget.charge_windows([window(handle)], Plain())
        budget.charge_windows([window(Plain())], Plain())
        self.assertEqual(len(budget.opaque_identities), 2)
        self.assertIs(budget.opaque_identities[0][1], handle)

    def test_unhashable_handles_are_retained_across_gc_and_not_recycled(self):
        adapter = SemanticAdapter()
        budget = contract.Budget()
        yielded = []
        for index in range(3):
            handle = UnhashableHandle(index)
            yielded.append(handle)
            # Drop every external reference; only the budget may retain it.
            budget.charge_windows([window(handle)], adapter)
            del handle
            if index == 0:
                first = budget.opaque_identities[0][1]
                budget._first = first  # keep one for the assertion below
                del first
            gc.collect()
        retained = [handle for _, handle in budget.opaque_identities]
        # Each distinct unhashable window is retained for the request, so a
        # recycled id()/hash could never merge two different windows.
        self.assertEqual(len(retained), 3)
        self.assertTrue(all(handle is yielded[index] for index, handle in enumerate(retained)))
        self.assertIs(budget._first, yielded[0])
        self.assertEqual(budget.counts["windows"], 3)

    def test_semantic_dedup_survives_gc_of_each_wrapper(self):
        adapter = SemanticAdapter()
        budget = contract.Budget()
        for _ in range(50):
            budget.charge_windows([window(Wrapper("main"))], adapter)
            gc.collect()
        self.assertEqual(len(budget.opaque_identities), 1)
        self.assertEqual(budget.counts["windows"], 1)

    def test_identity_cap_still_bounded_at_max_windows(self):
        adapter = SemanticAdapter()
        budget = contract.Budget()
        with self.assertRaises(contract.ContractError) as error:
            for index in range(contract.MAX_WINDOWS + 1):
                budget.counts["observations"] = 0  # isolate the identity cap
                budget.charge_windows([window(Wrapper(index))], adapter)
        self.assertEqual(error.exception.code, "window-overrun")
        self.assertEqual(budget.counts["windows"], contract.MAX_WINDOWS + 1)

    def test_observation_cap_unchanged(self):
        budget = contract.Budget()
        with self.assertRaises(contract.ContractError) as error:
            for _ in range(contract.MAX_OBSERVATIONS + 1):
                budget.charge_windows([window(Wrapper("main"))], SemanticAdapter())
        self.assertEqual(error.exception.code, "observe-overrun")
        self.assertEqual(budget.counts["observations"], contract.MAX_OBSERVATIONS + 1)

    def test_one_snapshot_above_the_cap_is_refused(self):
        budget = contract.Budget()
        with self.assertRaises(contract.ContractError) as error:
            budget.charge_windows([window(Wrapper(i)) for i in range(contract.MAX_WINDOWS + 1)],
                                  SemanticAdapter())
        self.assertEqual(error.exception.code, "window-overrun")


if __name__ == "__main__":
    unittest.main()
