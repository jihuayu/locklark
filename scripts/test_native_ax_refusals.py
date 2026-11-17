"""Focused tests for the low-level AX refusal contract.

Two narrow guarantees are exercised here with in-memory fakes only (no OS, GUI,
TCC, prompt or AX call):

* ``QuartzApi._status_attribute`` validates the documented
  ``kAXErrorNoValue`` constant BEFORE any attribute read. A missing or
  substituted constant refuses with the existing sanitized refusal and touches
  no AX attribute at all.
* ``_ax_result`` never lets a hostile tuple subclass surface a raw exception:
  ``len``/``__iter__``/``__getitem__`` overrides cannot leak, and every
  malformed shape answers None (the caller's sanitized refusal).
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import browser_native_macos as macos
import native_acceptance_contract as contract

NO_VALUE = -25212
UNSUPPORTED = -25205
HOSTILE_TEXT = "private tuple text /tmp/llcb-refusal"
QUERY = contract.ERROR_MESSAGES["a11y-query"]


class FakeAx:
    """The AX framework side of status reads; every access is recorded."""

    def __init__(self, constant=NO_VALUE, answer=(0, "AXWindow")):
        if constant is not _MISSING:
            self.kAXErrorNoValue = constant
        self.answer = answer
        self.reads = []

    def AXUIElementCopyAttributeValue(self, element, name, out):
        self.reads.append((element, name, out))
        if isinstance(self.answer, Exception):
            raise self.answer
        if callable(self.answer):
            return self.answer(element, name)
        return self.answer


_MISSING = object()


def api_for(fake):
    api = macos.QuartzApi.__new__(macos.QuartzApi)
    api.ax = fake
    return api


class StatusConstantPrecheckTests(unittest.TestCase):
    """The constant is validated locally, before the first attribute read."""

    BAD_CONSTANTS = (None, -25212.0, "-25212", True, False, -25213, _MISSING)

    def refuse(self, fake, name="AXRole"):
        with self.assertRaises(contract.ContractError) as caught:
            api_for(fake)._status_attribute("window", name)
        error = caught.exception
        self.assertIs(type(error), contract.ContractError)
        self.assertEqual(error.code, "a11y-query")
        self.assertEqual(str(error), QUERY)
        self.assertEqual(error.guard,
                         {"operation": "status-walk", "attribute": name, "error": None})
        return error

    def test_bad_constant_refuses_before_any_attribute_read(self):
        for constant in self.BAD_CONSTANTS:
            for name in ("AXRole", "AXDescription", "AXChildren"):
                with self.subTest(constant=constant, attribute=name):
                    fake = FakeAx(constant=constant)
                    self.refuse(fake, name)
                    self.assertEqual(fake.reads, [])

    def test_constant_is_read_through_the_framework_each_call(self):
        # A validated-away constant is not cached: fixing it starts real reads.
        fake = FakeAx(constant=None)
        self.refuse(fake)
        self.assertEqual(fake.reads, [])
        fake.kAXErrorNoValue = NO_VALUE
        self.assertEqual(api_for(fake)._status_attribute("window", "AXRole"),
                         "AXWindow")
        self.assertEqual(fake.reads, [("window", "AXRole", None)])

    def test_valid_constant_still_reads_then_classifies(self):
        cases = ((0, "AXWindow"), (NO_VALUE, None), (UNSUPPORTED, None))
        for answer in cases:
            with self.subTest(answer=answer):
                fake = FakeAx(answer=answer)
                value = api_for(fake)._status_attribute("window", "AXDescription")
                if answer[0] == NO_VALUE or answer[0] == UNSUPPORTED:
                    self.assertIs(value, macos._STATUS_NO_VALUE)
                else:
                    self.assertEqual(value, "AXWindow")
                self.assertEqual(fake.reads, [("window", "AXDescription", None)])

    def test_valid_constant_and_bad_answer_refuses_after_one_read(self):
        for answer in (False, None, 0, (0,), (True, "x"), (0, "x", None),
                       OSError(HOSTILE_TEXT)):
            with self.subTest(answer=answer):
                fake = FakeAx(answer=answer)
                self.refuse(fake)
                self.assertEqual(len(fake.reads), 1)


class AxResultDecoderTests(unittest.TestCase):
    """Malformed/hostile out-argument answers decode to None, never to a raise."""

    class HostileLen(tuple):
        def __len__(self):
            raise RuntimeError(HOSTILE_TEXT)

    class HostileIter(tuple):
        def __iter__(self):
            raise RuntimeError(HOSTILE_TEXT)

    class HostileGetitem(tuple):
        def __getitem__(self, index):
            raise RuntimeError(HOSTILE_TEXT)

    def test_well_formed_answers_decode(self):
        self.assertEqual(macos._ax_result((0, "value")), (0, "value"))
        self.assertEqual(macos._ax_result((NO_VALUE, None)), (NO_VALUE, None))
        self.assertEqual(macos._ax_result((0, None)), (0, None))

    def test_hostile_overrides_are_bypassed_not_raised(self):
        # len/iter/getitem overrides raise raw text; the decoder reads through
        # the base tuple protocol, so it decodes the real two items instead of
        # letting that text escape.
        for hostile in (self.HostileLen, self.HostileIter, self.HostileGetitem):
            with self.subTest(kind=hostile.__name__):
                value = hostile((0, "value"))
                self.assertEqual(macos._ax_result(value), (0, "value"))
                self.assertEqual(macos._ax_result(hostile((7, "x"))), (7, "x"))

    def test_hostile_wrong_length_is_still_a_shape_refusal(self):
        # Bypassing the overrides cannot turn a non-2-tuple into an answer.
        for hostile in (self.HostileLen, self.HostileIter, self.HostileGetitem):
            with self.subTest(kind=hostile.__name__):
                self.assertIsNone(macos._ax_result(hostile((0,))))
                self.assertIsNone(macos._ax_result(hostile(())))
                self.assertIsNone(macos._ax_result(hostile((0, 1, 2))))
                self.assertIsNone(macos._ax_result(hostile((True, "x"))))

    def test_malformed_answers_decode_to_none(self):
        malformed = (None, 0, True, False, 0.0, "0 x", b"0", (0,), (0, 1, 2),
                     [0, 1], {"code": 0}, (True, "x"), (0.0, "x"), ("0", "x"),
                     (None, "x"), (object(), "x"))
        for value in malformed:
            with self.subTest(value=value):
                self.assertIsNone(macos._ax_result(value))

    def test_decoder_raises_nothing_for_any_hostile_answer(self):
        # Every hostile shape either decodes correctly or answers None; none
        # may raise, so no caller can ever see the overrides' exception text.
        for hostile in (self.HostileLen, self.HostileIter, self.HostileGetitem):
            for items in ((0, HOSTILE_TEXT), (NO_VALUE, None), (0,), (True, "x"), ()):
                with self.subTest(kind=hostile.__name__, items=items):
                    try:
                        macos._ax_result(hostile(items))
                    except BaseException as error:  # pragma: no cover - must not happen
                        self.fail("decoder raised " + type(error).__name__)


if __name__ == "__main__":
    unittest.main()
