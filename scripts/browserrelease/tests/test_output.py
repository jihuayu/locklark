"""Output-path safety and non-overwrite publication refusals."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from browserrelease import package, receipt as receipt_module
from browserrelease.errors import ReleaseError
from browserrelease.tests import support

PRODUCT = "chromium"


class OutputSafetyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.root = support.make_root(self.base)

    def refuse(self, target: str):
        with self.assertRaises(ReleaseError):
            package.prepare(PRODUCT, target, root=self.root)

    def test_refuses_relative_or_root_output_paths(self):
        self.refuse("relative-out")
        self.refuse(str(self.root))
        self.refuse(str(self.base.parent))
        self.refuse(str(self.root / "browser-extension" / "dist"))

    def test_refuses_missing_or_symlinked_parent(self):
        self.refuse(str(self.base / "missing" / "out"))
        real = self.base / "real"
        real.mkdir()
        link = self.base / "link"
        try:
            os.symlink(real, link)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks are unavailable on this platform")
        self.refuse(str(link / "out"))

    def test_refuses_file_or_symlink_output(self):
        path = self.base / "out"
        path.write_text("", encoding="utf-8")
        self.refuse(str(path))
        path.unlink()
        target = self.base / "target"
        target.mkdir()
        os.symlink(target, path)
        self.refuse(str(path))

    def test_refuses_unrelated_files_in_output(self):
        path = self.base / "out"
        path.mkdir()
        (path / "notes.txt").write_text("x", encoding="utf-8")
        self.refuse(str(path))

    def test_refuses_symlinked_artifact(self):
        path = self.base / "out"
        path.mkdir()
        zip_name = receipt_module.artifact_names(PRODUCT)[0]
        real = self.base / "real.zip"
        real.write_bytes(b"not a zip")
        os.symlink(real, path / zip_name)
        self.refuse(str(path))

    def test_refuses_to_overwrite_a_newer_version_pair(self):
        target = str(self.base / "out")
        package.prepare(PRODUCT, target, root=self.root)
        support.write_metadata(self.root, '{"version": "0.2.0"}')
        support.commit(self.root)
        with self.assertRaises(ReleaseError):
            package.prepare(PRODUCT, target, root=self.root)


if __name__ == "__main__":
    unittest.main()
