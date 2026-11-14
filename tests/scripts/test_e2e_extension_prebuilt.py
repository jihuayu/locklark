"""Focused strict-path tests for the Python E2E prebuilt extension chain."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
for entry in (ROOT, ROOT / "scripts"):
    if str(entry) not in sys.path:
        sys.path.insert(0, str(entry))

from browserrelease.errors import ReleaseError  # noqa: E402
from tests.e2e.harness import E2EContext, PREBUILT_EXTENSION_ERROR  # noqa: E402


class PrebuiltHarnessTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.tmp = Path(temporary.name)
        self.ctx = E2EContext(ROOT, self.tmp / "bin", "prebuilt-env")
        self.addCleanup(self.ctx.cleanup)

    def env(self, **overrides):
        values = {
            "LOCKLARK_BROWSER_REQUIRE_PREBUILT": "1",
            "LOCKLARK_BROWSER_EXTENSION_PREPARED_DIR": str(self.tmp / "prepared"),
            "LOCKLARK_BROWSER_EXTENSION_CHROMIUM": str(self.tmp / "chromium"),
            "LOCKLARK_BROWSER_EXTENSION_FIREFOX": str(self.tmp / "firefox"),
        }
        values.update(overrides)
        return values

    def test_full_env_uses_api_with_fixed_root(self):
        with mock.patch.dict(os.environ, self.env(), clear=True), mock.patch(
            "browserrelease.prebuilt.verify_prebuilt"
        ) as verify:
            paths = self.ctx._prebuilt_extension_paths()
        self.assertEqual(paths, (self.tmp / "chromium", self.tmp / "firefox"))
        self.assertEqual(
            verify.call_args_list,
            [
                mock.call("chromium", self.tmp / "prepared", self.tmp / "chromium", self.ctx.repo_root),
                mock.call("firefox", self.tmp / "prepared", self.tmp / "firefox", self.ctx.repo_root),
            ],
        )

    def test_missing_partial_malformed_and_failure_are_fixed(self):
        for overrides in (
            {"LOCKLARK_BROWSER_EXTENSION_PREPARED_DIR": ""},
            {"LOCKLARK_BROWSER_EXTENSION_FIREFOX": ""},
            {"LOCKLARK_BROWSER_REQUIRE_PREBUILT": "0"},
            {"LOCKLARK_BROWSER_REQUIRE_PREBUILT": "true"},
            {"LOCKLARK_BROWSER_EXTENSION_SAFARI": ""},
        ):
            with self.subTest(overrides=overrides), mock.patch.dict(
                os.environ, self.env(**overrides), clear=True
            ):
                with self.assertRaises(AssertionError) as raised:
                    self.ctx._prebuilt_extension_paths()
                self.assertEqual(str(raised.exception), PREBUILT_EXTENSION_ERROR)
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(self.ctx._prebuilt_extension_paths())
        with mock.patch.dict(
            os.environ,
            {
                "LOCKLARK_BROWSER_EXTENSION_PREPARED_DIR": str(self.tmp / "prepared"),
                "LOCKLARK_BROWSER_EXTENSION_CHROMIUM": str(self.tmp / "chromium"),
            },
            clear=True,
        ):
            with self.assertRaises(AssertionError):
                self.ctx._prebuilt_extension_paths()
        with mock.patch.dict(os.environ, self.env(), clear=True), mock.patch(
            "browserrelease.prebuilt.verify_prebuilt",
            side_effect=ReleaseError("private"),
        ):
            with self.assertRaises(AssertionError) as raised:
                self.ctx._prebuilt_extension_paths()
        self.assertEqual(str(raised.exception), PREBUILT_EXTENSION_ERROR)
        self.assertNotIn(str(self.tmp), str(raised.exception))


if __name__ == "__main__":
    unittest.main()
