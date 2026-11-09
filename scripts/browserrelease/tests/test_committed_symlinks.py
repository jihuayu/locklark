"""A committed symlink keeps `git status` clean but must still be refused.

Each fixture is a private synthetic repository. The link target is a synthetic
canary inside the test's own temporary directory, never a real user file.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from browserrelease import package, source
from browserrelease.errors import ReleaseError
from browserrelease.tests import support

PRODUCT = "chromium"
CANARY = b"SYNTHETIC-OUTSIDE-CANARY-EXTERNAL-ONLY"


class CommittedSymlinkTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.root = support.make_root(self.base)
        self.extension = self.root / "browser-extension"
        self.target = str(self.base / "out")
        self.canary = self.base / "outside-canary.txt"
        self.canary.write_bytes(CANARY)

    def replace_with_symlink(self, name: str) -> None:
        path = self.extension / name
        try:
            path.unlink()
            os.symlink(self.canary, path)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks are unavailable on this platform")
        support.commit(self.root, f"committed symlink for {name}")

    def assert_canary_intact(self) -> None:
        self.assertEqual(self.canary.read_bytes(), CANARY)

    def assert_no_canary_in_build_output(self) -> None:
        dist = self.extension / "dist"
        if not dist.exists():
            return
        for path in dist.rglob("*"):
            if path.is_file() and not path.is_symlink():
                self.assertNotIn(CANARY, path.read_bytes(), str(path))

    def committed_mode(self, name: str) -> str:
        completed = subprocess.run(
            ["git", "ls-tree", "HEAD", "--", f"browser-extension/{name}"],
            cwd=self.root,
            shell=False,
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=60,
            env=support.GIT_ENVIRONMENT,
        )
        return completed.stdout.decode("ascii").split(" ", 1)[0]

    def run_build_directly(self) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["node", "build.js", PRODUCT],
            cwd=self.extension,
            shell=False,
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=120,
            env=support.GIT_ENVIRONMENT,
        )

    def test_committed_regular_inputs_are_accepted(self):
        source.require_clean_source(self.root)
        source.require_regular_source_blobs(self.root)
        self.assertRegex(source.source_commit(self.root), r"^[0-9a-f]{40}$")

    def test_committed_symlinked_product_source_is_refused(self):
        self.replace_with_symlink("core.js")
        # The worktree is clean: the symlink itself is the committed content.
        self.assertEqual(self.committed_mode("core.js"), "120000")
        source.require_clean_source(self.root)
        with self.assertRaises(ReleaseError):
            source.require_regular_source_blobs(self.root)
        with self.assertRaises(ReleaseError):
            source.source_commit(self.root)
        with self.assertRaises(ReleaseError):
            package.prepare(PRODUCT, self.target, root=self.root)
        self.assert_canary_intact()
        self.assert_no_canary_in_build_output()

    def test_committed_symlinked_version_input_is_refused(self):
        self.replace_with_symlink("release-version.json")
        self.assertEqual(self.committed_mode("release-version.json"), "120000")
        source.require_clean_source(self.root)
        with self.assertRaises(ReleaseError):
            source.require_regular_source_blobs(self.root)
        with self.assertRaises(ReleaseError):
            source.source_commit(self.root)
        with self.assertRaises(ReleaseError):
            package.prepare(PRODUCT, self.target, root=self.root)
        self.assert_canary_intact()
        self.assert_no_canary_in_build_output()

    def test_direct_build_js_refuses_symlinked_product_source(self):
        self.replace_with_symlink("core.js")
        completed = self.run_build_directly()
        self.assertNotEqual(completed.returncode, 0)
        self.assert_canary_intact()
        self.assert_no_canary_in_build_output()

    def test_direct_build_js_refuses_symlinked_version_source(self):
        self.replace_with_symlink("release-version.json")
        completed = self.run_build_directly()
        self.assertNotEqual(completed.returncode, 0)
        self.assert_canary_intact()
        self.assert_no_canary_in_build_output()

    def test_clean_committed_regular_tree_still_prepares(self):
        summary = package.prepare(PRODUCT, self.target, root=self.root)
        self.assertEqual(summary["status"], "prepared")
        self.assert_canary_intact()


if __name__ == "__main__":
    unittest.main()
