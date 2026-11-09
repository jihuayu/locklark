"""Tests for the single central release version document."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from browserrelease import version
from browserrelease.errors import ReleaseError
from browserrelease.tests import support


class ValidateVersionTests(unittest.TestCase):
    def test_accepts_browser_compatible_versions(self):
        for value in (
            "0",
            "1",
            "0.1.0",
            "0.0.0.1",
            "65535.65535.65535.65535",
            "2026.12.31",
        ):
            self.assertEqual(version.validate_version(value), value)

    def test_refuses_ambiguous_or_out_of_range_versions(self):
        for value in (
            "",
            "00",
            "01.0",
            "1.02",
            "1.2.3.4.5",
            "1..2",
            "1.",
            ".1",
            "1.65536",
            "v1.0",
            " 1.0",
            "1.0 ",
            "1.0\n",
            "-1",
            "1.-2",
            "1_0",
            "1.0.0.0.0",
            1,
            None,
            ["0.1.0"],
        ):
            with self.subTest(value=value):
                with self.assertRaises(ReleaseError):
                    version.validate_version(value)


class CentralMetadataTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.root = support.make_root(self.base)

    def test_repository_metadata_is_the_release_version(self):
        self.assertEqual(version.load_release_version(support.REPO_ROOT), "0.1.0")

    def test_accepts_the_single_member_document(self):
        self.assertEqual(version.load_release_version(self.root), "0.1.0")
        support.write_metadata(self.root, '{"version": "0.2.0"}')
        self.assertEqual(version.load_release_version(self.root), "0.2.0")

    def test_refuses_unknown_members(self):
        for payload in (
            '{"version": "0.1.0", "build": 1}',
            '{"version": "0.1.0", "version_name": "beta"}',
            '{"version": "0.1.0", "signed": true}',
        ):
            with self.subTest(payload=payload):
                support.write_metadata(self.root, payload)
                with self.assertRaises(ReleaseError):
                    version.load_release_version(self.root)

    def test_refuses_invalid_version_member(self):
        for payload in (
            '{"version": "01.0"}',
            '{"version": ""}',
            '{"version": 1}',
            '{"version": "1.2.3.4.5"}',
            '{"version": "1.65536"}',
            '{"version": null}',
        ):
            with self.subTest(payload=payload):
                support.write_metadata(self.root, payload)
                with self.assertRaises(ReleaseError):
                    version.load_release_version(self.root)

    def test_refuses_malformed_or_non_object_documents(self):
        for payload in ("[]", '"0.1.0"', "{", "null", "\xff"):
            with self.subTest(payload=payload):
                support.write_metadata(self.root, payload)
                with self.assertRaises(ReleaseError):
                    version.load_release_version(self.root)

    def test_refuses_missing_metadata(self):
        (self.root / "browser-extension" / "release-version.json").unlink()
        with self.assertRaises(ReleaseError):
            version.load_release_version(self.root)

    def test_refuses_symlinked_metadata(self):
        path = self.root / "browser-extension" / "release-version.json"
        target = self.root / "browser-extension" / "popup.js"
        path.unlink()
        try:
            os.symlink(target, path)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks are unavailable on this platform")
        with self.assertRaises(ReleaseError):
            version.load_release_version(self.root)
