"""Clean-source pinning: dirty or untracked inputs must be refused."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from browserrelease import package, source
from browserrelease.errors import ReleaseError
from browserrelease.tests import support

PRODUCT = "chromium"


class CleanSourceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.root = support.make_root(self.base)
        self.target = str(self.base / "out")

    def test_clean_fixture_resolves_a_full_commit(self):
        self.assertRegex(source.source_commit(self.root), r"^[0-9a-f]{40}$")

    def test_dirty_tracked_input_is_refused_before_any_output(self):
        support.write_metadata(self.root, '{"version": "0.1.0"}\n')
        with self.assertRaises(ReleaseError):
            source.require_clean_source(self.root)
        with self.assertRaises(ReleaseError):
            package.prepare(PRODUCT, self.target, root=self.root)
        self.assertFalse(Path(self.target).exists())

    def test_untracked_product_and_version_inputs_are_refused(self):
        (self.root / "browser-extension" / "popup.js.bak").write_text(
            "x", encoding="utf-8"
        )
        with self.assertRaises(ReleaseError):
            package.prepare(PRODUCT, self.target, root=self.root)
        (self.root / "browser-extension" / "popup.js.bak").unlink()
        (self.root / "browser-extension" / "release-version.json").rename(
            self.root / "browser-extension" / "unused.json"
        )
        support.write_metadata(self.root, '{"version": "0.1.0"}\n')
        with self.assertRaises(ReleaseError):
            package.prepare(PRODUCT, self.target, root=self.root)

    def test_untracked_release_module_file_is_refused(self):
        (self.root / "scripts").mkdir()
        (self.root / "scripts" / "extra.py").write_text("x", encoding="utf-8")
        with self.assertRaises(ReleaseError):
            package.prepare(PRODUCT, self.target, root=self.root)

    def test_ignored_build_output_keeps_the_tree_clean(self):
        summary = package.prepare(PRODUCT, self.target, root=self.root)
        source.require_clean_source(self.root)
        self.assertEqual(summary["source_commit"], source.source_commit(self.root))
        self.assertEqual(summary["status"], "prepared")

    def test_refusal_never_exposes_git_output_or_paths(self):
        (self.root / "browser-extension" / "secret-note.js").write_text(
            "x", encoding="utf-8"
        )
        with self.assertRaises(ReleaseError) as raised:
            source.require_clean_source(self.root)
        message = str(raised.exception)
        self.assertNotIn("secret-note", message)
        self.assertNotIn(str(self.root), message)


if __name__ == "__main__":
    unittest.main()
