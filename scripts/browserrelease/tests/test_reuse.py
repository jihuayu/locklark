"""Reuse, orphan completion, cross-product validation and publication races."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from browserrelease import package, publish, receipt as receipt_module
from browserrelease.errors import ReleaseError
from browserrelease.tests import support

PRODUCT = "chromium"


class ReuseTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.root = support.make_root(self.base)
        self.target = str(self.base / "out")

    def artifact(self, product: str = PRODUCT) -> Path:
        return Path(self.target) / receipt_module.artifact_names(product)[0]

    def receipt_file(self, product: str = PRODUCT) -> Path:
        return Path(self.target) / receipt_module.artifact_names(product)[1]

    def test_matching_orphan_zip_is_completed_without_touching_it(self):
        package.prepare(PRODUCT, self.target, root=self.root)
        original = self.artifact().read_bytes()
        self.receipt_file().unlink()
        summary = package.prepare(PRODUCT, self.target, root=self.root)
        self.assertEqual(summary["status"], "completed")
        self.assertEqual(self.artifact().read_bytes(), original)
        self.assertTrue(self.receipt_file().is_file())
        self.assertEqual(
            package.verify(PRODUCT, self.target, root=self.root)["sha256"],
            summary["sha256"],
        )

    def test_mismatched_orphan_zip_is_refused_and_preserved(self):
        package.prepare(PRODUCT, self.target, root=self.root)
        self.receipt_file().unlink()
        self.artifact().write_bytes(b"owner artifact")
        with self.assertRaises(ReleaseError):
            package.prepare(PRODUCT, self.target, root=self.root)
        self.assertEqual(self.artifact().read_bytes(), b"owner artifact")
        self.assertFalse(self.receipt_file().exists())

    def test_receipt_without_zip_is_refused(self):
        package.prepare(PRODUCT, self.target, root=self.root)
        receipt = self.receipt_file().read_bytes()
        self.artifact().unlink()
        with self.assertRaises(ReleaseError):
            package.prepare(PRODUCT, self.target, root=self.root)
        self.assertEqual(self.receipt_file().read_bytes(), receipt)
        self.assertFalse(self.artifact().exists())

    def test_corrupt_other_product_pair_is_refused(self):
        package.prepare("firefox", self.target, root=self.root)
        firefox = Path(self.target) / receipt_module.artifact_names("firefox")[0]
        firefox.write_bytes(firefox.read_bytes()[:-8])
        with self.assertRaises(ReleaseError):
            package.prepare(PRODUCT, self.target, root=self.root)

    def test_partial_other_product_pair_is_refused(self):
        package.prepare(PRODUCT, self.target, root=self.root)
        orphan = Path(self.target) / receipt_module.artifact_names("safari")[0]
        orphan.write_bytes(self.artifact().read_bytes())
        with self.assertRaises(ReleaseError):
            package.prepare(PRODUCT, self.target, root=self.root)

    def test_race_winner_zip_is_reused_instead_of_overwritten(self):
        original_link = publish.link_nonreplace
        state = {"fired": False}

        def racing_link(temporary, final):
            if not state["fired"] and final.name.endswith(".zip"):
                state["fired"] = True
                final.write_bytes(Path(temporary).read_bytes())
            return original_link(temporary, final)

        publish.link_nonreplace = racing_link
        self.addCleanup(setattr, publish, "link_nonreplace", original_link)
        summary = package.prepare(PRODUCT, self.target, root=self.root)
        self.assertEqual(summary["status"], "completed")
        self.assertEqual(
            package.verify(PRODUCT, self.target, root=self.root)["sha256"],
            summary["sha256"],
        )


if __name__ == "__main__":
    unittest.main()
