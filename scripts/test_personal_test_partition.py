#!/usr/bin/env python3
"""Focused contracts for the Windows personal-package test partitioner."""
from __future__ import annotations

import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import personal_test_partition as split  # noqa: E402


FIXTURE = r'''package partitionfixture

import (
	"fmt"
	"os"
	"testing"
)

func record(t *testing.T, name string) {
	t.Helper()
	path := os.Getenv("PARTITION_SMOKE_LOG")
	if path == "" {
		t.Fatal("missing smoke log")
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err = file.WriteString(name + "\n"); err != nil {
		t.Fatal(err)
	}
}

func recordName(name string) {
	path := os.Getenv("PARTITION_SMOKE_LOG")
	if path == "" {
		os.Exit(80)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		os.Exit(81)
	}
	defer file.Close()
	if _, err = file.WriteString(name + "\n"); err != nil {
		os.Exit(82)
	}
}

func TestAlpha(t *testing.T) { record(t, "TestAlpha") }
func TestBeta(t *testing.T) {
	record(t, "TestBeta")
	if os.Getenv("PARTITION_SMOKE_FAIL") == "TestBeta" {
		t.Fatal("synthetic group failure")
	}
}
func TestDelta(t *testing.T) { record(t, "TestDelta") }
func TestGamma(t *testing.T) { record(t, "TestGamma") }

func Example() {
	recordName("Example")
	fmt.Println("example")
	// Output: example
}

func FuzzEpsilon(f *testing.F) {
	f.Add("seed")
	f.Fuzz(func(t *testing.T, value string) { record(t, "FuzzEpsilon") })
}

func BenchmarkNoise(b *testing.B) { b.Fatal("benchmark must stay disabled") }
'''


class RealTestBinarySmoke(unittest.TestCase):
    """Build one real tiny Go test binary once and reuse it for both checks."""

    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="locklark-partition-smoke-")
        root = pathlib.Path(cls.temporary.name)
        (root / "go.mod").write_text(
            "module locklark.local/partitionfixture\n\ngo 1.27.3\n", encoding="utf-8"
        )
        (root / "fixture_test.go").write_text(FIXTURE, encoding="utf-8")
        name = "fixture.test.exe" if os.name == "nt" else "fixture.test"
        cls.binary = root / name
        go = shutil.which("go")
        if go is None:
            raise RuntimeError("go executable unavailable")
        subprocess.run(
            [go, "test", "-c", "-o", str(cls.binary), "."],
            cwd=root,
            check=True,
            text=True,
        )

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def env(self, log: pathlib.Path) -> dict[str, str]:
        env = os.environ.copy()
        env["PARTITION_SMOKE_LOG"] = str(log)
        env.pop("PARTITION_SMOKE_FAIL", None)
        return env

    def test_cases_run_exactly_once_across_two_groups(self):
        cases = split.list_test_cases(str(self.binary))
        self.assertEqual(
            cases, ["Example", "FuzzEpsilon", "TestAlpha", "TestBeta", "TestDelta", "TestGamma"]
        )
        groups = split.partition_cases(cases)
        self.assertEqual(abs(len(groups[0]) - len(groups[1])), 0)
        log = pathlib.Path(self.temporary.name) / "exactly-once.log"
        env = self.env(log)
        returned = split.run_partitioned(str(self.binary), cases, env=env)
        self.assertEqual(returned, groups)
        lines = log.read_text(encoding="utf-8").splitlines()
        self.assertEqual(sorted(lines), cases)
        self.assertEqual(len(lines), len(cases))
        self.assertFalse(set(groups[0]) & set(groups[1]))
        self.assertEqual(set(groups[0]) | set(groups[1]), set(cases))

    def test_group_failure_propagates_after_both_groups_run_once(self):
        cases = split.list_test_cases(str(self.binary))
        log = pathlib.Path(self.temporary.name) / "failure.log"
        env = self.env(log)
        env["PARTITION_SMOKE_FAIL"] = "TestBeta"
        with self.assertRaises(split.PartitionError):
            split.run_partitioned(str(self.binary), cases, env=env)
        lines = log.read_text(encoding="utf-8").splitlines()
        self.assertEqual(sorted(lines), cases)
        self.assertEqual(len(lines), len(cases))


class PartitionContract(unittest.TestCase):
    def test_empty_malformed_and_duplicate_lists_fail(self):
        for cases in ([], ["TestGood", ""], ["TestGood", "BenchmarkNo"], ["TestGood", "TestGood"]):
            with self.subTest(cases=cases), self.assertRaises(split.PartitionError):
                split.validate_cases(cases)

    def test_single_case_cannot_make_two_nonempty_groups(self):
        with self.assertRaises(split.PartitionError):
            split.partition_cases(["TestOnly"])

    def test_partition_is_balanced_disjoint_and_complete(self):
        cases = ["TestE", "TestD", "TestC", "TestB", "TestA"]
        groups = split.partition_cases(cases)
        self.assertEqual(len(groups), 2)
        self.assertTrue(groups[0] and groups[1])
        self.assertLessEqual(abs(len(groups[0]) - len(groups[1])), 1)
        self.assertFalse(set(groups[0]) & set(groups[1]))
        self.assertEqual(set(groups[0]) | set(groups[1]), set(cases))
        split.validate_partition(cases, groups)

    def test_gap_overlap_and_unbalanced_groups_fail(self):
        cases = ["TestA", "TestB", "TestC", "TestD"]
        with self.assertRaises(split.PartitionError):
            split.validate_partition(cases, (["TestA"], ["TestB", "TestC"]))
        with self.assertRaises(split.PartitionError):
            split.validate_partition(cases, (["TestA", "TestB"], ["TestB", "TestD"]))
        with self.assertRaises(split.PartitionError):
            split.validate_partition(cases, (["TestA"], ["TestB", "TestC", "TestD"]))

    def test_only_the_exact_personal_package_is_excluded(self):
        packages = [
            split.PERSONAL_PACKAGE,
            split.PERSONAL_PACKAGE + "/helper",
            "github.com/jihuayu/locklark/internal/personalized",
            "github.com/jihuayu/locklark/cmd/locklark",
        ]
        self.assertEqual(
            split.filter_other_packages(packages),
            [
                split.PERSONAL_PACKAGE + "/helper",
                "github.com/jihuayu/locklark/internal/personalized",
                "github.com/jihuayu/locklark/cmd/locklark",
            ],
        )
        with self.assertRaises(split.PartitionError):
            split.filter_other_packages([split.PERSONAL_PACKAGE])
        with self.assertRaises(split.PartitionError):
            split.filter_other_packages(packages + ["github.com/jihuayu/locklark/cmd/locklark"])
        with self.assertRaises(split.PartitionError):
            split.filter_other_packages([p for p in packages if p != split.PERSONAL_PACKAGE])


if __name__ == "__main__":
    unittest.main()
