"""Cheap workflow contract for the Windows personal-package test split."""
from __future__ import annotations

import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import personal_test_partition as split  # noqa: E402

WORKFLOW = ROOT / ".github" / "workflows" / "check.yml"


def step_text(name: str) -> str:
    source = WORKFLOW.read_text(encoding="utf-8")
    marker = f"      - name: {name}\n"
    if source.count(marker) != 1:
        raise AssertionError("workflow step is not unique")
    start = source.index(marker)
    end = len(source)
    for line in source[start + len(marker) :].splitlines(keepends=True):
        if line.startswith("      - "):
            end = start + len(marker) + source[start + len(marker) :].index(line)
            break
    return source[start:end]


class PersonalTestPartitionWorkflowContract(unittest.TestCase):
    def test_windows_uses_the_runner_and_linux_keeps_the_ordinary_command(self):
        source = WORKFLOW.read_text(encoding="utf-8")
        step = step_text("Test Go packages and native OpenSSH transport")
        final = step.rsplit("if ($IsWindows) {", 1)
        self.assertEqual(len(final), 2, "Windows/Linux final branch is missing")
        windows, linux = final[1].split("} else {", 1)
        self.assertIn("python scripts/personal_test_partition.py", windows)
        self.assertNotIn("go test -count=1 ./...", windows)
        self.assertIn("go test -count=1 ./...", linux)
        self.assertNotIn("-bench", windows)
        self.assertEqual(source.count("python scripts/personal_test_partition.py"), 1)
        self.assertEqual(source.count("go test -count=1 ./..."), 1)
        self.assertNotIn("go test -count=1 ./internal/personal", source)
        self.assertNotIn("go test ./internal/personal -count=1", source)
        for preserved in (
            "LOCKLARK_TEST_OPENSSH: '1'",
            "$env:LOCKLARK_TEST_PYKEEPASS",
            "$env:LOCKLARK_TEST_BUN",
        ):
            self.assertIn(preserved, step)

    def test_runner_has_the_exact_package_cap_and_exclusion(self):
        self.assertEqual(split.PERSONAL_PACKAGE, "github.com/jihuayu/locklark/internal/personal")
        self.assertEqual(split.GROUP_TIMEOUT, "10m")
        packages = [
            split.PERSONAL_PACKAGE,
            split.PERSONAL_PACKAGE + "/helper",
            "github.com/jihuayu/locklark/internal/personalized",
        ]
        self.assertEqual(
            split.filter_other_packages(packages),
            [
                split.PERSONAL_PACKAGE + "/helper",
                "github.com/jihuayu/locklark/internal/personalized",
            ],
        )


if __name__ == "__main__":
    unittest.main()
