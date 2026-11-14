"""Owned small-fixture contracts for scripts/run_release_contracts.py.

These tests use disposable modules outside the checkout. They exercise the
runner's ordering, full-coverage, minimum, duplicate, skip, expected-failure,
error, and class-fixture-once invariants; they do not mirror the runner's
implementation or run the real release suites.
"""

from __future__ import annotations

import importlib
import sys
import tempfile
import textwrap
import unittest
import uuid
from pathlib import Path

import scripts.run_release_contracts as runner


class TempModule:
    def __init__(self) -> None:
        self.directory = tempfile.TemporaryDirectory(prefix="locklark-runner-")
        self.root = Path(self.directory.name)
        sys.path.insert(0, str(self.root))
        self.names: list[str] = []

    def write(self, source: str) -> str:
        name = f"runnerfixture_{uuid.uuid4().hex}"
        (self.root / f"{name}.py").write_text(
            textwrap.dedent(source), encoding="utf-8"
        )
        importlib.invalidate_caches()
        self.names.append(name)
        return name

    def load(self, name: str):
        return importlib.import_module(name)

    def close(self) -> None:
        for name in self.names:
            sys.modules.pop(name, None)
        try:
            sys.path.remove(str(self.root))
        except ValueError:
            pass
        self.directory.cleanup()


class RunnerContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.modules = TempModule()
        self.addCleanup(self.modules.close)

    def group(self, module: str, minimum: tuple[str, ...], first: str | None = None):
        return runner.Group("fixture", module, "Fixture", minimum, first)

    def test_ordered_full_coverage_and_class_fixture_once(self) -> None:
        module = self.modules.write(
            """
            import unittest

            class Fixture(unittest.TestCase):
                order = []
                setups = 0

                @classmethod
                def setUpClass(cls):
                    cls.setups += 1

                def test_b(self):
                    type(self).order.append("b")

                def test_a(self):
                    type(self).order.append("a")

                def test_z_first(self):
                    type(self).order.append("z")
            """
        )
        plan = runner.load_plan(
            [self.group(module, ("test_z_first",), "test_z_first")]
        )
        self.assertEqual(len(plan), 3)
        self.assertEqual(len({item.test_id for item in plan}), 3)
        outcome = runner.run_plan(plan)
        self.assertTrue(outcome.ok(), outcome.result)
        self.assertEqual(outcome.result.testsRun, 3)
        cls = getattr(self.modules.load(module), "Fixture")
        self.assertEqual(cls.order, ["z", "a", "b"])
        self.assertEqual(cls.setups, 1)

    def test_skipped_minimum_does_not_expand(self) -> None:
        module = self.modules.write(
            """
            import unittest

            class Fixture(unittest.TestCase):
                later = []

                def test_z_skip(self):
                    raise unittest.SkipTest("minimum skipped")

                def test_a_later(self):
                    type(self).later.append("expanded")
            """
        )
        plan = runner.load_plan(
            [self.group(module, ("test_z_skip",), "test_z_skip")]
        )
        outcome = runner.run_plan(plan)
        self.assertFalse(outcome.ok())
        self.assertEqual(outcome.result.testsRun, 1)
        self.assertEqual(len(outcome.result.skipped), 1)
        cls = getattr(self.modules.load(module), "Fixture")
        self.assertEqual(cls.later, [])

    def test_expected_failure_fails_closed(self) -> None:
        module = self.modules.write(
            """
            import unittest

            class Fixture(unittest.TestCase):
                later = []

                @unittest.expectedFailure
                def test_z_expected(self):
                    self.fail("expected failure must not count as success")

                def test_a_later(self):
                    type(self).later.append("expanded")
            """
        )
        plan = runner.load_plan(
            [self.group(module, ("test_z_expected",), "test_z_expected")]
        )
        outcome = runner.run_plan(plan)
        self.assertFalse(outcome.ok())
        self.assertEqual(outcome.result.testsRun, 1)
        self.assertEqual(len(outcome.result.expectedFailures), 1)
        self.assertEqual(getattr(self.modules.load(module), "Fixture").later, [])

    def test_error_fails_closed(self) -> None:
        module = self.modules.write(
            """
            import unittest

            class Fixture(unittest.TestCase):
                later = []

                def test_z_error(self):
                    raise RuntimeError("runner fixture error")

                def test_a_later(self):
                    type(self).later.append("expanded")
            """
        )
        plan = runner.load_plan(
            [self.group(module, ("test_z_error",), "test_z_error")]
        )
        outcome = runner.run_plan(plan)
        self.assertFalse(outcome.ok())
        self.assertEqual(outcome.result.testsRun, 1)
        self.assertEqual(len(outcome.result.errors), 1)
        self.assertEqual(getattr(self.modules.load(module), "Fixture").later, [])

    def test_duplicate_id_fails_before_running(self) -> None:
        module = self.modules.write(
            """
            import unittest

            class Fixture(unittest.TestCase):
                def test_one(self):
                    pass
            """
        )
        first = runner.Group("first", module, "Fixture", ("test_one",))
        second = runner.Group("second", module, "Fixture", ("test_one",))
        with self.assertRaisesRegex(runner.ContractError, "duplicate test id"):
            runner.load_plan([first, second])

    def test_missing_minimum_fails_before_running(self) -> None:
        module = self.modules.write(
            """
            import unittest

            class Fixture(unittest.TestCase):
                def test_one(self):
                    pass
            """
        )
        with self.assertRaisesRegex(runner.ContractError, "missing minimum"):
            runner.load_plan([self.group(module, ("test_missing",))])

    def test_empty_class_fails_before_running(self) -> None:
        module = self.modules.write(
            """
            import unittest

            class Fixture(unittest.TestCase):
                pass
            """
        )
        with self.assertRaisesRegex(runner.ContractError, "no test methods"):
            runner.load_plan([self.group(module, ("test_one",))])


if __name__ == "__main__":
    unittest.main()
