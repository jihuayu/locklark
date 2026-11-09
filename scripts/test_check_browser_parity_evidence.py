#!/usr/bin/env python3
"""Pure tests for the browser parity evidence checker.

Run with:
    python3 -m unittest scripts/test_check_browser_parity_evidence.py -v
"""

from __future__ import annotations

import contextlib
import copy
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))

import check_browser_parity_evidence as checker  # noqa: E402


ROOT = checker.repository_root()
EVIDENCE, CHECKLIST_ROWS = checker.load_inputs(
    ROOT,
    ROOT / checker.EVIDENCE_REL,
    ROOT / checker.CHECKLIST_REL,
)


def errors_after(mutator) -> list[str]:
    evidence = copy.deepcopy(EVIDENCE)
    checklist = copy.deepcopy(CHECKLIST_ROWS)
    mutator(evidence)
    return checker.validate_evidence(evidence, checklist, ROOT)["errors"]


def row(evidence: dict, row_id: str) -> dict:
    for entry in evidence["rows"]:
        if entry["id"] == row_id:
            return entry
    raise AssertionError(f"missing test row {row_id}")


class ChecklistParsingTests(unittest.TestCase):
    def test_checklist_has_exactly_65_unique_known_ids(self):
        rows = checker.parse_checklist(ROOT / checker.CHECKLIST_REL)
        ids = [entry["id"] for entry in rows]
        self.assertEqual(len(rows), 65)
        self.assertEqual(len(set(ids)), 65)
        self.assertEqual(set(ids), set(checker.EXPECTED_STABLE_IDS))

    def test_checked_in_evidence_passes(self):
        report = checker.validate_evidence(
            copy.deepcopy(EVIDENCE), copy.deepcopy(CHECKLIST_ROWS), ROOT
        )
        self.assertTrue(report["ok"], report["errors"])
        self.assertEqual(report["row_count"], 65)
        self.assertEqual(report["stable_id_count"], 65)
        self.assertEqual(report["reference_status"], "unverified")

    def test_every_row_has_paths_and_no_reference_pass(self):
        for entry in EVIDENCE["rows"]:
            self.assertTrue(entry["implementation_paths"], entry["id"])
            self.assertTrue(entry["test_paths"], entry["id"])
            self.assertTrue(entry["test_commands"], entry["id"])
            self.assertNotEqual(entry["reference_status"], "verified", entry["id"])
            self.assertNotEqual(entry["reference_status"], "passed", entry["id"])


class RejectionTests(unittest.TestCase):
    def test_duplicate_id_is_rejected(self):
        errors = errors_after(lambda ev: ev["rows"].append(copy.deepcopy(ev["rows"][0])))
        self.assertTrue(any("duplicate stable ID" in error for error in errors), errors)

    def test_missing_id_is_rejected(self):
        errors = errors_after(lambda ev: ev["rows"].pop(0))
        self.assertTrue(any("missing stable ID" in error for error in errors), errors)

    def test_unknown_id_is_rejected(self):
        errors = errors_after(lambda ev: row(ev, "B1.1").__setitem__("id", "B99.9"))
        self.assertTrue(any("unknown stable ID" in error for error in errors), errors)

    def test_absolute_path_is_rejected(self):
        errors = errors_after(
            lambda ev: row(ev, "B1.1").__setitem__(
                "implementation_paths", ["/etc/passwd"]
            )
        )
        self.assertTrue(any("absolute or home-relative" in error for error in errors), errors)

    def test_path_escape_is_rejected(self):
        errors = errors_after(
            lambda ev: row(ev, "B1.1").__setitem__(
                "implementation_paths", ["../README.md"]
            )
        )
        self.assertTrue(any("path escape" in error for error in errors), errors)

    def test_nonexistent_test_path_is_rejected(self):
        errors = errors_after(
            lambda ev: row(ev, "B1.1").__setitem__(
                "test_paths", ["browser-extension/test/does-not-exist.test.js"]
            )
        )
        self.assertTrue(any("does not exist" in error for error in errors), errors)

    def test_fabricated_reference_pass_is_rejected(self):
        errors = errors_after(
            lambda ev: row(ev, "B1.1").__setitem__("reference_status", "verified")
        )
        self.assertTrue(any("fabricated reference pass" in error for error in errors), errors)

    def test_top_level_reference_pass_is_rejected(self):
        errors = errors_after(
            lambda ev: ev["reference"].__setitem__("status", "passed")
        )
        self.assertTrue(
            any("must remain 'unverified'" in error for error in errors), errors
        )

    def test_incomplete_evidence_is_rejected(self):
        errors = errors_after(lambda ev: row(ev, "B1.1").pop("limitations"))
        self.assertTrue(any("limitations: non-empty list required" in error for error in errors), errors)

    def test_private_artifact_key_is_rejected(self):
        errors = errors_after(
            lambda ev: row(ev, "B1.1").__setitem__("screenshot", "private.png")
        )
        self.assertTrue(
            any("forbidden private artifact key" in error for error in errors), errors
        )

    def test_status_mismatch_and_verified_status_are_rejected(self):
        errors = errors_after(
            lambda ev: row(ev, "B1.1").__setitem__("implementation_status", "已实测")
        )
        self.assertTrue(any("does not match checklist" in error for error in errors), errors)
        self.assertTrue(any("已实测 is not permitted" in error for error in errors), errors)

    def test_accepted_difference_requires_decision_reference(self):
        errors = errors_after(lambda ev: row(ev, "B13.3").pop("decision_ref"))
        self.assertTrue(any("requires decision_ref" in error for error in errors), errors)

    def test_test_command_must_reference_checked_in_path(self):
        errors = errors_after(
            lambda ev: row(ev, "B1.1").__setitem__("test_commands", ["true"])
        )
        self.assertTrue(
            any("no test_command references" in error for error in errors), errors
        )


class CliTests(unittest.TestCase):
    def test_cli_returns_zero_for_checked_in_mapping(self):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(checker.main([]), 0)

    def test_cli_returns_one_for_duplicate_evidence(self):
        evidence = copy.deepcopy(EVIDENCE)
        evidence["rows"].append(copy.deepcopy(evidence["rows"][0]))
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", suffix=".json", delete=False
        ) as handle:
            json.dump(evidence, handle)
            path = Path(handle.name)
        try:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(
                    checker.main(["--root", str(ROOT), "--evidence", str(path)]), 1
                )
        finally:
            path.unlink()


if __name__ == "__main__":
    unittest.main(verbosity=2)
