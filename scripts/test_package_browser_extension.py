"""Tests for deterministic, fail-closed browser-extension preparation ZIPs."""

from __future__ import annotations

import base64
import copy
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import package_browser_extension as packaging  # noqa: E402


class PreparationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="locklark-package-test-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        os.chmod(cls.root, 0o700)
        real_extension = HERE.parent / "browser-extension"
        cls.fixture_root = cls.root / "fixture"
        cls.fixture_root.mkdir(mode=0o700)
        cls.extension = cls.fixture_root / "browser-extension"
        cls.extension.mkdir(mode=0o700)
        for name in ("build.js", "release-version.json", *packaging.PRODUCT_FILES):
            shutil.copyfile(real_extension / name, cls.extension / name)
        for attribute, value in (
            ("ROOT", cls.fixture_root),
            ("EXTENSION_DIR", cls.extension),
            ("BUILD_SCRIPT", cls.extension / "build.js"),
        ):
            patcher = mock.patch.object(packaging, attribute, value)
            patcher.start()
            cls.addClassCleanup(patcher.stop)
        cls.chromium_out = cls.root / "chromium-out"
        cls.firefox_out = cls.root / "firefox-out"
        cls.chromium_out.mkdir(mode=0o700)
        cls.firefox_out.mkdir(mode=0o700)
        for product, output in (
            ("chromium", cls.chromium_out),
            ("firefox", cls.firefox_out),
        ):
            code = cls._run_main(product, output)
            if code != 0:
                raise AssertionError(f"initial {product} preparation failed")

    @staticmethod
    def _run_main(product, output):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = packaging.main(["--product", product, "--output", str(output)])
        if code != 0:
            raise AssertionError(stderr.getvalue())
        return code

    def _artifact(self, product, output):
        name = f"locklark-browser-extension-{product}-unsigned.zip"
        return output / name

    def _manifest(self, product):
        with zipfile.ZipFile(self._artifact(product, getattr(self, f"{product}_out"))) as archive:
            return json.loads(archive.read("manifest.json"))

    def test_repeat_produces_identical_bytes_and_reuses_only_own_artifacts(self):
        first = self._artifact("chromium", self.chromium_out).read_bytes()
        first_receipt = (
            self.chromium_out
            / "locklark-browser-extension-chromium-unsigned.receipt.json"
        ).read_bytes()
        second_out = self.root / "chromium-repeat"
        second_out.mkdir()
        self._run_main("chromium", second_out)
        second = self._artifact("chromium", second_out).read_bytes()
        second_receipt = (
            second_out / "locklark-browser-extension-chromium-unsigned.receipt.json"
        ).read_bytes()
        self.assertEqual(first, second)
        self.assertEqual(first_receipt, second_receipt)

        # Re-running into a directory containing our receipt + ZIP is allowed,
        # but only after the receipt hash is revalidated.
        self._run_main("chromium", self.chromium_out)
        self.assertEqual(first, self._artifact("chromium", self.chromium_out).read_bytes())
        self.assertEqual(
            first_receipt,
            (
                self.chromium_out
                / "locklark-browser-extension-chromium-unsigned.receipt.json"
            ).read_bytes(),
        )

    def test_zip_entry_allowlist_timestamps_modes_and_no_source_maps(self):
        for product, output, expected_permissions in (
            ("chromium", self.chromium_out, packaging.EXPECTED_PERMISSIONS["chromium"]),
            ("firefox", self.firefox_out, packaging.EXPECTED_PERMISSIONS["firefox"]),
        ):
            with self.subTest(product=product), zipfile.ZipFile(
                self._artifact(product, output)
            ) as archive:
                self.assertEqual(archive.namelist(), list(packaging.ZIP_ENTRIES))
                self.assertEqual(
                    set(archive.namelist()),
                    {
                        "manifest.json",
                        "core.js",
                        "content.js",
                        "webauthn.js",
                        "background.js",
                        "popup.html",
                        "popup.css",
                        "popup.js",
                        "options.html",
                        "options.css",
                        "options.js",
                    },
                )
                for info in archive.infolist():
                    self.assertEqual(info.date_time, packaging.ZIP_TIMESTAMP)
                    self.assertEqual(info.compress_type, zipfile.ZIP_STORED)
                    self.assertEqual(info.create_system, 3)
                    self.assertTrue(stat.S_ISREG(info.external_attr >> 16))
                    self.assertEqual((info.external_attr >> 16) & 0o777, 0o644)
                    self.assertFalse(info.is_dir())
                    self.assertNotIn("/", info.filename)
                    self.assertFalse(info.filename.startswith("."))
                    self.assertFalse(info.filename.endswith(".map"))
                    self.assertNotIn("test", info.filename.lower())
                    self.assertNotIn("__MACOSX", info.filename)
                manifest = json.loads(archive.read("manifest.json"))
                self.assertEqual(set(manifest["permissions"]), expected_permissions)
                self.assertEqual(manifest["host_permissions"], ["https://*/*"])
                self.assertNotIn("optional_permissions", manifest)
                self.assertNotIn("optional_host_permissions", manifest)

    def test_unexpected_permissions_or_identity_are_rejected(self):
        valid_chromium = self._manifest("chromium")
        valid_firefox = self._manifest("firefox")
        packaging.validate_manifest(valid_chromium, "chromium")
        packaging.validate_manifest(valid_firefox, "firefox")

        cases = []

        def add(product, label, base, mutate):
            changed = copy.deepcopy(base)
            mutate(changed)
            cases.append((product, label, changed))

        add(
            "chromium",
            "extra permission",
            valid_chromium,
            lambda item: item["permissions"].append("tabs"),
        )
        add(
            "chromium",
            "missing permission",
            valid_chromium,
            lambda item: item["permissions"].remove("activeTab"),
        )
        add(
            "chromium",
            "duplicate permission",
            valid_chromium,
            lambda item: item["permissions"].append("storage"),
        )
        add(
            "chromium",
            "optional permission",
            valid_chromium,
            lambda item: item.update({"optional_permissions": ["tabs"]}),
        )
        add(
            "chromium",
            "optional host",
            valid_chromium,
            lambda item: item.update({"optional_host_permissions": ["https://*/*"]}),
        )
        add(
            "chromium",
            "http host",
            valid_chromium,
            lambda item: item.update({"host_permissions": ["http://*/*"]}),
        )
        add(
            "chromium",
            "extra host",
            valid_chromium,
            lambda item: item.update(
                {"host_permissions": ["https://*/*", "https://evil.example/*"]}
            ),
        )
        add(
            "chromium",
            "changed public key",
            valid_chromium,
            lambda item: item.update(
                {"key": base64.b64encode(b"not-the-release-key").decode()}
            ),
        )
        add(
            "chromium",
            "main world changed",
            valid_chromium,
            lambda item: item["content_scripts"][1].update({"world": "ISOLATED"}),
        )
        add(
            "chromium",
            "all_frames changed",
            valid_chromium,
            lambda item: item["content_scripts"][0].update({"all_frames": False}),
        )
        add(
            "chromium",
            "extra top-level capability",
            valid_chromium,
            lambda item: item.update({"externally_connectable": {"matches": ["*://*/*"]}}),
        )
        add(
            "firefox",
            "changed add-on id",
            valid_firefox,
            lambda item: item["browser_specific_settings"]["gecko"].update(
                {"id": "other@example.invalid"}
            ),
        )
        add(
            "firefox",
            "data collection changed",
            valid_firefox,
            lambda item: item["browser_specific_settings"]["gecko"].update(
                {"data_collection_permissions": {"required": ["technical"]}}
            ),
        )
        add(
            "firefox",
            "contextMenus added",
            valid_firefox,
            lambda item: item["permissions"].append("contextMenus"),
        )
        for product, label, manifest in cases:
            with self.subTest(product=product, rejection=label):
                with self.assertRaises(packaging.PackagingError):
                    packaging.validate_manifest(manifest, product)

    def test_symlink_and_unexpected_build_files_are_excluded(self):
        source = packaging.EXTENSION_DIR / "dist" / "chromium"
        self.assertTrue(source.is_dir())
        safe_bundle = self.root / "safe-bundle"
        safe_bundle.mkdir()
        for name in packaging.ZIP_ENTRIES:
            shutil.copyfile(source / name, safe_bundle / name)
        packaging.read_bundle(safe_bundle, "chromium")

        outside = self.root / "outside-secret.vault"
        outside.write_text("must never be packaged", encoding="utf-8")
        (safe_bundle / "popup.js").unlink()
        (safe_bundle / "popup.js").symlink_to(outside)
        with self.assertRaises(packaging.PackagingError):
            packaging.read_bundle(safe_bundle, "chromium")

        with tempfile.TemporaryDirectory(dir=self.root) as extra_raw:
            extra = Path(extra_raw)
            for name in packaging.ZIP_ENTRIES:
                shutil.copyfile(source / name, extra / name)
            (extra / "test_packaging.js").write_text("nope", encoding="utf-8")
            with self.assertRaises(packaging.PackagingError):
                packaging.read_bundle(extra, "chromium")

        with tempfile.TemporaryDirectory(dir=self.root) as hidden_raw:
            hidden = Path(hidden_raw)
            for name in packaging.ZIP_ENTRIES:
                shutil.copyfile(source / name, hidden / name)
            (hidden / ".DS_Store").write_bytes(b"hidden")
            with self.assertRaises(packaging.PackagingError):
                packaging.read_bundle(hidden, "chromium")

    def test_no_home_environment_or_profile_discovery_and_no_shell(self):
        sentinel = self.root / "sentinel-home"
        sentinel.mkdir()
        (sentinel / "vault.kdbx").write_bytes(b"vault must not be read")
        (sentinel / "profile").mkdir()
        (sentinel / "profile" / "Cookies").write_bytes(b"profile must not be read")
        output = self.root / "environment-out"
        output.mkdir()
        environment = {
            "HOME": str(sentinel),
            "USERPROFILE": str(sentinel),
            "APPDATA": str(sentinel),
            "LOCALAPPDATA": str(sentinel),
            "XDG_CONFIG_HOME": str(sentinel),
            "LOCKLARK_PROFILE": str(sentinel),
            "LOCKLARK_VAULT": str(sentinel / "vault.kdbx"),
        }
        with mock.patch.dict(os.environ, environment, clear=False), mock.patch.object(
            packaging.subprocess, "run", wraps=subprocess.run
        ) as run:
            self._run_main("chromium", output)
        self.assertEqual(run.call_args.args[0], ["node", "build.js", "chromium"])
        self.assertIs(run.call_args.kwargs["shell"], False)
        self.assertEqual(run.call_args.kwargs["cwd"], packaging.EXTENSION_DIR.resolve())
        artifact = self._artifact("chromium", output)
        with zipfile.ZipFile(artifact) as archive:
            self.assertEqual(archive.namelist(), list(packaging.ZIP_ENTRIES))
            for name in archive.namelist():
                self.assertNotIn(str(sentinel), name)
        receipt = (
            output / "locklark-browser-extension-chromium-unsigned.receipt.json"
        ).read_text(encoding="utf-8")
        self.assertNotIn(str(sentinel), receipt)
        self.assertNotIn("vault.kdbx", receipt)
        self.assertNotIn(str(self.root), receipt)

    def test_preflight_rejects_symlink_in_existing_build_output(self):
        source = packaging.EXTENSION_DIR / "dist" / "chromium"
        fake = self.root / "fake-extension"
        (fake / "dist" / "chromium").mkdir(parents=True)
        shutil.copyfile(packaging.BUILD_SCRIPT, fake / "build.js")
        for name in packaging.PRODUCT_FILES:
            shutil.copyfile(packaging.EXTENSION_DIR / name, fake / name)
        for name in packaging.ZIP_ENTRIES:
            shutil.copyfile(source / name, fake / "dist" / "chromium" / name)
        outside = self.root / "outside-vault.kdbx"
        outside.write_bytes(b"must not be followed")
        (fake / "dist" / "chromium" / "popup.js").unlink()
        (fake / "dist" / "chromium" / "popup.js").symlink_to(outside)
        with mock.patch.object(packaging, "EXTENSION_DIR", fake), mock.patch.object(
            packaging, "BUILD_SCRIPT", fake / "build.js"
        ):
            with self.assertRaises(packaging.PackagingError):
                packaging._preflight_source()

    def test_tampered_prior_receipt_refuses_overwrite(self):
        tampered = self.root / "tampered-output"
        tampered.mkdir()
        for name in (
            "locklark-browser-extension-chromium-unsigned.zip",
            "locklark-browser-extension-chromium-unsigned.receipt.json",
        ):
            shutil.copyfile(self.chromium_out / name, tampered / name)
        receipt_path = tampered / "locklark-browser-extension-chromium-unsigned.receipt.json"
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        receipt["artifact"]["sha256"] = "0" * 64
        receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
        before = {entry.name: entry.read_bytes() for entry in tampered.iterdir()}
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = packaging.main(["--product", "chromium", "--output", str(tampered)])
        self.assertEqual(code, 1)
        self.assertIn("does not match its receipt", stderr.getvalue())
        self.assertEqual(before, {entry.name: entry.read_bytes() for entry in tampered.iterdir()})

    def test_output_safety_refuses_unrelated_files_and_source_tree(self):
        unrelated = self.root / "unrelated-output"
        unrelated.mkdir()
        note = unrelated / "keep.txt"
        note.write_text("unrelated", encoding="utf-8")
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = packaging.main(
                ["--product", "chromium", "--output", str(unrelated)]
            )
        self.assertEqual(code, 1)
        self.assertIn("unrelated files", stderr.getvalue())
        self.assertEqual(note.read_text(encoding="utf-8"), "unrelated")
        self.assertEqual({entry.name for entry in unrelated.iterdir()}, {"keep.txt"})

        inside = packaging.EXTENSION_DIR / "dist" / "preparation-must-not-appear"
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = packaging.main(["--product", "chromium", "--output", str(inside)])
        self.assertEqual(code, 1)
        self.assertIn("outside the browser-extension", stderr.getvalue())
        self.assertFalse(inside.exists())

        with self.assertRaises(SystemExit) as missing:
            packaging.main(["--product", "chromium"])
        self.assertEqual(missing.exception.code, 2)

        receipt = json.loads(
            (
                self.chromium_out
                / "locklark-browser-extension-chromium-unsigned.receipt.json"
            ).read_text(encoding="utf-8")
        )
        self.assertTrue(receipt["unsigned"])
        self.assertFalse(receipt["signed"])
        self.assertEqual(receipt["manifest"]["identity"], f"chrome-extension://{packaging.CHROMIUM_ID}/")
        self.assertNotIn(str(self.root), json.dumps(receipt))
        self.assertEqual(
            {entry.name for entry in self.chromium_out.iterdir()},
            {
                "locklark-browser-extension-chromium-unsigned.zip",
                "locklark-browser-extension-chromium-unsigned.receipt.json",
            },
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
