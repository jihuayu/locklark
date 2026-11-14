#!/usr/bin/env python3
"""Pure negative checks for the pinned mobile tool verifier."""
import ast
import pathlib
import subprocess
import sys
import unittest

import verify_mobile_tools as verify

MODULE = "golang.org/x/mobile"


def metadata(version=verify.MOBILE_VERSION, sum_value=verify.MOBILE_SUM):
    return "\tmod\t" + MODULE + "\t" + version + "\t" + sum_value + "\n"


class VerifyMobileToolsTests(unittest.TestCase):
    def test_exact_version_and_sum(self):
        text = "\n".join([
            "/tool: go1.27.3",
            "\tpath\t" + MODULE + "/cmd/gomobile",
            metadata().rstrip("\n"),
            "\tbuild\tCGO_ENABLED=0",
        ]) + "\n"
        self.assertTrue(verify.metadata_matches(text))
        self.assertTrue(verify.verify_metadata([text, text]))

    def test_missing_module_line(self):
        self.assertFalse(verify.metadata_matches("/tool: go1.27.3\n"))

    def test_devel_version(self):
        self.assertFalse(verify.metadata_matches(metadata(version="(devel)")))

    def test_wrong_version(self):
        self.assertFalse(verify.metadata_matches(metadata(version="v0.0.0-20260101000000-000000000000")))

    def test_wrong_sum(self):
        self.assertFalse(verify.metadata_matches(metadata(sum_value="h1:wrong")))

    def test_second_tool_mismatch(self):
        exact = metadata()
        wrong = metadata(sum_value="h1:wrong")
        self.assertTrue(verify.verify_metadata([exact, exact]))
        self.assertFalse(verify.verify_metadata([exact, wrong]))

    def test_missing_tool(self):
        self.assertFalse(verify.verify_tools("go", ["/nonexistent/mobile-tool"]))

    def test_go_failure(self):
        self.assertFalse(verify.verify_tools("/nonexistent/go", [sys.executable]))

    def test_cli_failure_is_fixed(self):
        script = pathlib.Path(__file__).with_name("verify_mobile_tools.py")
        completed = subprocess.run(
            [sys.executable, str(script), "/nonexistent/mobile-tool"],
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(completed.stdout, "")
        self.assertEqual(completed.stderr, "verify-mobile-tools: failed\n")

    def test_source_manifest_pin_matches(self):
        source = pathlib.Path(__file__).with_name("source-manifest.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        constants = {}
        for node in tree.body:
            if not isinstance(node, ast.Assign) or len(node.targets) != 1:
                continue
            target = node.targets[0]
            if isinstance(target, ast.Name) and target.id in {"MOBILE_VERSION", "MOBILE_SUM"}:
                constants[target.id] = ast.literal_eval(node.value)
        self.assertEqual(constants["MOBILE_VERSION"], verify.MOBILE_VERSION)
        self.assertEqual(constants["MOBILE_SUM"], verify.MOBILE_SUM)


if __name__ == "__main__":
    unittest.main()
