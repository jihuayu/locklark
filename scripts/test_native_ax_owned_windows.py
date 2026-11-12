"""Focused deterministic tests for the AXWindows-to-owned-PID helper.

No real OS, GUI, TCC, prompt or window inventory: ``QuartzApi.owned_windows``
runs over an in-memory fake ApplicationServices binding that enforces the real
PyObjC out-argument contract. ``AXUIElementCreateApplication(pid)`` takes the
one explicit PID, ``AXUIElementCopyAttributeValue(element, name, out)`` and
``AXUIElementGetPid(element, out)`` have a STRICT arity (they refuse a missing
out-argument, exactly like the C function would), and the fake records every
call so the tests can prove no CoreGraphics inventory and no other AX
attribute is ever touched.
"""
import os
import sys
import types
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import browser_native_macos as macos
import native_acceptance_contract as contract

OWNED_PID = 4242
OTHER_PID = 4243
KAX_ERROR_SUCCESS = 0
KAX_ERROR_MISMATCH = -25204
AX_WINDOWS = "AXWindows"
FORBIDDEN_CALLS = {"CGWindowListCopyWindowInfo", "CGWindowListCreateImage",
                   "CGEventPost", "CGGetActiveDisplayList"}
# Marks a missing out-argument slot for the strict AXUIElementGetPid binding.
_MISSING = object()
HOSTILE_TEXT = "private tuple text /tmp/llcb-hostile"
# Marks "no explicit AXWindows answer override" (None is itself a real answer).
_DEFAULT = object()


class Handle:
    """One hashable opaque fake AXUIElement; it carries no readable value."""

    def __init__(self, owner=OWNED_PID, failing=None):
        self.owner = owner
        self.failing = dict(failing or {})

    def __repr__(self):
        return "<fake AXUIElement>"


class FakeApplicationServices:
    """A strict PyObjC-shaped ApplicationServices binding.

    ``getpid`` maps a handle to its raw out-answer (a tuple, a bare value or a
    callable used instead of the default ``(0, handle.owner)``), and
    ``windows`` maps an application to its raw AXWindows answer. ``windows``
    and ``getpid`` may also be callables taking the element.
    """

    def __init__(self, windows, getpid=None, windows_answer=_DEFAULT):
        self.windows, self.getpid = windows, dict(getpid or {})
        self.windows_answer = windows_answer
        self.calls = []
        self.application = Handle(owner=OWNED_PID)

    # -- recorded by the helper -------------------------------------------
    def AXUIElementCreateApplication(self, pid):
        self.calls.append(("create", pid))
        return self.application

    def AXUIElementCopyAttributeValue(self, element, name, out):
        self.calls.append(("copy", element, name, out))
        if self.windows_answer is not _DEFAULT:
            answer = self.windows_answer
        elif element is self.application and name == AX_WINDOWS:
            answer = (0, list(self.windows))
        else:
            answer = (KAX_ERROR_MISMATCH, None)
        if callable(answer):
            answer = answer(element, name)
        if isinstance(answer, Exception):
            raise answer
        return answer

    def AXUIElementGetPid(self, element, out=_MISSING):
        # The strict binding: the out-argument slot is mandatory (PyObjC takes
        # the placeholder ``None`` there), and a call without it is a TypeError
        # exactly as the C function with a NULL pid pointer position would be.
        if out is _MISSING:
            raise TypeError("AXUIElementGetPid() missing required out argument")
        self.calls.append(("getpid", element, out))
        answer = self.getpid.get(element, (KAX_ERROR_SUCCESS, element.owner))
        if callable(answer):
            answer = answer(element)
        if isinstance(answer, Exception):
            raise answer
        return answer

    # -- call log views ----------------------------------------------------
    def names(self):
        return [call[0] for call in self.calls]

    def attributes(self):
        return [call[2] for call in self.calls if call[0] == "copy"]

    def pids_asked(self):
        return [call[1] for call in self.calls if call[0] == "create"]


def api_for(fake):
    """A QuartzApi with only the ApplicationServices side injected."""
    api = macos.QuartzApi.__new__(macos.QuartzApi)
    api.ax = fake
    return api


def refusal(test, call):
    """Run ``call`` and return the sanitized refusal raising inside it."""
    with test.assertRaises(contract.ContractError) as caught:
        call()
    return caught.exception


class OwnedWindowsTests(unittest.TestCase):
    def assertRefused(self, fake, pid=OWNED_PID, code="a11y-query"):
        error = refusal(self, lambda: api_for(fake).owned_windows(pid))
        self.assertIs(type(error), contract.ContractError)
        self.assertEqual(error.code, code)
        # Sanitized: the fixed message and an empty guard carry no payload.
        self.assertEqual(error.guard, {})
        self.assertEqual(str(error), contract.ERROR_MESSAGES[code])
        for name in FORBIDDEN_CALLS:
            self.assertNotIn(name, fake.names())
        return error

    def test_returns_only_the_owned_opaque_handles_in_ax_order(self):
        first, second = Handle(), Handle()
        fake = FakeApplicationServices([first, second])
        result = api_for(fake).owned_windows(OWNED_PID)
        self.assertEqual(result, [first, second])
        self.assertIs(result[0], first)
        self.assertIs(result[1], second)
        # Exactly one explicit creation, then AXWindows, then one GetPid each.
        self.assertEqual(fake.names(), ["create", "copy", "getpid", "getpid"])
        self.assertEqual(fake.pids_asked(), [OWNED_PID])
        self.assertEqual(fake.attributes(), [AX_WINDOWS])
        self.assertEqual([call[1] for call in fake.calls if call[0] == "getpid"],
                         [first, second])

    def test_empty_window_list_returns_no_handles(self):
        fake = FakeApplicationServices([])
        self.assertEqual(api_for(fake).owned_windows(OWNED_PID), [])
        self.assertEqual(fake.names(), ["create", "copy"])

    def test_tuple_and_list_answers_are_both_accepted(self):
        first = Handle()
        for listed in ((first,), [first]):
            with self.subTest(container=type(listed).__name__):
                fake = FakeApplicationServices(listed)
                self.assertEqual(api_for(fake).owned_windows(OWNED_PID), [first])

    def test_creation_is_bound_to_the_explicit_positive_owned_pid(self):
        first = Handle()
        fake = FakeApplicationServices([first])
        self.assertEqual(api_for(fake).owned_windows(OWNED_PID), [first])
        self.assertEqual(fake.pids_asked(), [OWNED_PID])
        self.assertIs(type(fake.pids_asked()[0]), int)

    def test_malformed_pid_refuses_before_any_ax_call(self):
        for pid in (0, -4242, True, False, None, 4242.0, "4242", object()):
            with self.subTest(pid=pid):
                fake = FakeApplicationServices([Handle()])
                self.assertRefused(fake, pid=pid)
                self.assertEqual(fake.names(), [])

    def test_mismatched_owner_pid_refuses(self):
        owned, foreign = Handle(), Handle(owner=OTHER_PID)
        for windows, expected in (((foreign, owned), 1), ((owned, foreign), 2)):
            with self.subTest(expected_getpid_calls=expected):
                fake = FakeApplicationServices(list(windows))
                self.assertRefused(fake)
                # Every listed window was checked; the refusal is the mismatch.
                self.assertEqual(fake.names().count("getpid"), expected)
                self.assertEqual(fake.attributes(), [AX_WINDOWS])

    def test_getpid_is_called_with_the_out_argument_slot(self):
        handle = Handle()
        fake = FakeApplicationServices([handle])
        self.assertEqual(api_for(fake).owned_windows(OWNED_PID), [handle])
        getpid = [call for call in fake.calls if call[0] == "getpid"]
        self.assertEqual(len(getpid), 1)
        # (element, out) - the documented two-argument PyObjC contract.
        self.assertEqual(len(getpid[0]), 3)  # name + two bound arguments
        self.assertIs(getpid[0][1], handle)
        self.assertIs(getpid[0][2], None)

    def test_missing_out_argument_in_binding_refuses(self):
        class NoOut(FakeApplicationServices):
            def AXUIElementGetPid(self, element):
                self.calls.append(("getpid", element))
                return (0, OWNED_PID)

        handle = Handle()
        self.assertRefused(NoOut([handle], windows_answer=(0, [handle])))

    def test_getpid_pid_must_equal_the_requested_exact_int(self):
        for answer in ((0, OTHER_PID), (0, OWNED_PID + 1), (0, float(OWNED_PID)),
                       (0, str(OWNED_PID)), (0, None), (0, _Bool(OWNED_PID))):
            with self.subTest(answer=answer):
                handle = Handle()
                fake = FakeApplicationServices([handle], getpid={handle: answer})
                self.assertRefused(fake)

    def test_nonzero_getpid_error_refuses(self):
        for code in (KAX_ERROR_MISMATCH, -25212, 1, -25205):
            with self.subTest(code=code):
                handle = Handle()
                fake = FakeApplicationServices([handle], getpid={handle: (code, OWNED_PID)})
                self.assertRefused(fake)

    def test_malformed_getpid_shapes_refuse(self):
        handle = Handle()
        malformed = (
            None, OWNED_PID, True, False, 0.0, "0 4242", (0,), (0, OWNED_PID, None),
            [0, OWNED_PID], {"code": 0, "pid": OWNED_PID}, (True, OWNED_PID),
            (0.0, OWNED_PID), ("0", OWNED_PID), (None, OWNED_PID),
        )
        for answer in malformed:
            with self.subTest(answer=answer):
                fake = FakeApplicationServices([handle], getpid={handle: answer})
                self.assertRefused(fake)

    def test_raised_getpid_or_creation_refuses_without_stringifying(self):
        marker = "private AX text /tmp/llcb-secret"
        handle = Handle()
        cases = (
            ("getpid-raises", {handle: OSError(marker)}),
            ("getpid-contract", {handle: contract.ContractError("a11y-query")}),
        )
        for name, answers in cases:
            with self.subTest(case=name):
                fake = FakeApplicationServices([handle], getpid=answers)
                self.assertRefused(fake)

        class RaisingCreate(FakeApplicationServices):
            def AXUIElementCreateApplication(self, pid):
                self.calls.append(("create", pid))
                raise OSError(marker)

        error = refusal(self, lambda: api_for(RaisingCreate([handle])).owned_windows(OWNED_PID))
        self.assertEqual(error.code, "a11y-query")
        self.assertEqual(str(error), contract.ERROR_MESSAGES["a11y-query"])
        self.assertNotIn(marker, str(error))
        self.assertNotIn(marker, repr(error.guard))

    def test_malformed_window_list_refuses(self):
        handle = Handle()
        answers = (
            None, handle, [], True, 0, 1.0, "windows", b"windows",
            (KAX_ERROR_MISMATCH, [handle]),
            (KAX_ERROR_MISMATCH, None),
            (-25212, [handle]),
            [handle, None],
            "AXWindows",
            (0,),
            (0, [handle], None),
            (True, [handle]),
            (0.0, [handle]),
            ("0", [handle]),
        )
        for answer in answers:
            with self.subTest(answer=answer):
                fake = FakeApplicationServices([handle], windows_answer=answer)
                self.assertRefused(fake)

    def test_listed_sequence_errors_refuse(self):
        handle = Handle()

        class Hostile:
            def __len__(self):
                return 1

            def __getitem__(self, index):
                raise OSError("private list failure")

        fake = FakeApplicationServices(handle, windows_answer=(0, Hostile()))
        self.assertRefused(fake)

        class BadLen(Hostile):
            def __getitem__(self, index):
                return handle

            def __len__(self):
                raise OSError("private length failure")

        fake = FakeApplicationServices(handle, windows_answer=(0, BadLen()))
        self.assertRefused(fake)

    def test_constant_missing_value_is_not_a_window_list(self):
        handle = Handle()
        fake = FakeApplicationServices([handle], windows_answer=(-25212, None))
        self.assertRefused(fake)

    def test_null_application_refuses(self):
        class NullApplication(FakeApplicationServices):
            def AXUIElementCreateApplication(self, pid):
                self.calls.append(("create", pid))
                return None

        self.assertRefused(NullApplication([Handle()]))

    def test_window_count_is_bounded(self):
        handles = [Handle() for _ in range(3)]
        fake = FakeApplicationServices(handles)
        api = api_for(fake)
        original = macos.MAX_AX_WINDOWS
        macos.MAX_AX_WINDOWS = 2
        try:
            error = refusal(self, lambda: api.owned_windows(OWNED_PID))
        finally:
            macos.MAX_AX_WINDOWS = original
        self.assertEqual(error.code, "a11y-overrun")
        self.assertEqual(fake.names(), ["create", "copy"])

    def test_no_cg_inventory_and_no_other_attribute_is_read(self):
        first, second = Handle(), Handle()
        fake = FakeApplicationServices([first, second])

        class Guarded(FakeApplicationServices):
            # Any CoreGraphics inventory access is a hard failure.
            def __getattr__(self, name):
                if name.startswith("CG") or name.startswith("NS"):
                    raise AssertionError("CoreGraphics/AppKit access: " + name)
                raise AttributeError(name)

        guarded = Guarded(fake.windows, fake.getpid)
        api = api_for(guarded)
        before = set(vars(api))
        self.assertEqual(api.owned_windows(OWNED_PID), [first, second])
        self.assertEqual(set(vars(api)) - before, set())
        self.assertEqual(guarded.attributes(), [AX_WINDOWS])
        for forbidden in ("AXTitle", "AXDescription", "AXRole", "AXChildren",
                          "AXValue", "AXSelectedText", "AXPosition", "AXSize",
                          "AXFrame", "AXFocused", "AXEnabled"):
            self.assertNotIn(forbidden, guarded.attributes())
        # Only the three documented binding entry points were called.
        self.assertEqual(set(guarded.names()), {"create", "copy", "getpid"})
        self.assertFalse([name for name in guarded.names() if name in FORBIDDEN_CALLS])

    def test_hostile_tuple_answers_refuse_without_leaking(self):
        handle = Handle()

        class HostileLen(tuple):
            def __len__(self):
                raise RuntimeError(HOSTILE_TEXT)

        class HostileIter(tuple):
            def __iter__(self):
                raise RuntimeError(HOSTILE_TEXT)

        class HostileGetitem(tuple):
            def __getitem__(self, index):
                raise RuntimeError(HOSTILE_TEXT)

        # A hostile AXWindows answer is decoded through the base tuple protocol
        # (its overrides never raise out of the helper) ...
        for hostile in (HostileLen, HostileIter, HostileGetitem):
            with self.subTest(where="AXWindows", kind=hostile.__name__):
                fake = FakeApplicationServices([handle],
                                               windows_answer=hostile((0, [handle])))
                self.assertEqual(api_for(fake).owned_windows(OWNED_PID), [handle])
                self.assertEqual(fake.attributes(), [AX_WINDOWS])
            with self.subTest(where="GetPid", kind=hostile.__name__):
                fake = FakeApplicationServices(
                    [handle], getpid={handle: hostile((KAX_ERROR_SUCCESS, OWNED_PID))})
                self.assertEqual(api_for(fake).owned_windows(OWNED_PID), [handle])
        # ... while a hostile answer of the wrong shape still refuses.
        for hostile in (HostileLen, HostileIter, HostileGetitem):
            with self.subTest(where="AXWindows-shape", kind=hostile.__name__):
                fake = FakeApplicationServices([handle],
                                               windows_answer=hostile((0,)))
                self.assertRefused(fake)
            with self.subTest(where="GetPid-shape", kind=hostile.__name__):
                fake = FakeApplicationServices([handle], getpid={handle: hostile(())})
                self.assertRefused(fake)
            with self.subTest(where="GetPid-foreign", kind=hostile.__name__):
                fake = FakeApplicationServices(
                    [handle], getpid={handle: hostile((KAX_ERROR_SUCCESS, OTHER_PID))})
                self.assertRefused(fake)

    def test_hostile_answers_stay_sanitized(self):
        # The refusal is ours alone: fixed message, empty guard, no raw text.
        class HostileLen(tuple):
            def __len__(self):
                raise RuntimeError(HOSTILE_TEXT)

        handle = Handle()
        fake = FakeApplicationServices([handle], getpid={handle: HostileLen((0,))})
        error = self.assertRefused(fake)
        for text in (HOSTILE_TEXT, "RuntimeError", "Traceback"):
            self.assertNotIn(text, str(error))
            self.assertNotIn(text, repr(error.guard))
        self.assertEqual(error.guard, {})

    def test_helper_is_reached_only_from_scoped_discovery(self):
        # Step 2 wires the helper into exactly ONE caller: owned discovery.
        self.assertIn("owned_windows", dir(macos.QuartzApi))
        with open(macos.__file__, encoding="utf-8") as handle:
            source = handle.read()
        self.assertEqual(source.count(".owned_windows("), 1)
        self.assertIn("elements = self.owned_windows(pid)", source)
        # The unscoped CoreGraphics path never uses it.
        cg = source[source.index("    def list_windows(self):"):]
        cg = cg[:cg.index("def _ax_title")]
        self.assertNotIn("owned_windows", cg)


def _Bool(value):
    """A bool-like int subclass, which must never pass as an exact status."""
    class Bool(int):
        pass

    return Bool(value)


if __name__ == "__main__":
    unittest.main()
