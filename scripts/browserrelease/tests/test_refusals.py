"""Refusal tests: policy escapes, extra build output, tampering and mismatch."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from browserrelease import build, package, receipt as receipt_module
from browserrelease.errors import ReleaseError
from browserrelease.tests import support

PRODUCT = "chromium"


class RefusalTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.root = support.make_root(self.base)
        self.target = str(self.base / "out")

    def zip_path(self, product: str = PRODUCT) -> Path:
        return Path(self.target) / receipt_module.artifact_names(product)[0]

    def receipt_path(self, product: str = PRODUCT) -> Path:
        return Path(self.target) / receipt_module.artifact_names(product)[1]

    def refuse_prepare(self, product: str = PRODUCT, runner=build.run_build):
        with self.assertRaises(ReleaseError):
            package.prepare(product, self.target, root=self.root, runner=runner)

    def test_refuses_central_json_unknown_member_or_invalid_version(self):
        for index, payload in enumerate(
            (
                '{"version": "0.1.0", "build": 1}',
                '{"version": "01.0"}',
                '{"version": "1.2.3.4.5"}',
                '{"version": "0.1.0",}',
            )
        ):
            with self.subTest(payload=payload):
                base = self.base / f"fresh{index}"
                root = support.make_root(base)
                support.write_metadata(root, payload)
                support.commit(root)
                with self.assertRaises(ReleaseError):
                    package.prepare(PRODUCT, str(base / "out"), root=root)

    def test_refuses_a_hardcoded_manifest_version_drift(self):
        support.patch_build(
            self.root, "version: releaseVersion,", 'version: "0.1.0",'
        )
        support.write_metadata(self.root, '{"version": "0.2.0"}')
        support.commit(self.root)
        with self.assertRaises(ReleaseError):
            package.prepare(PRODUCT, self.target, root=self.root)

    def test_refuses_permission_and_identity_escapes(self):
        support.patch_build(
            self.root,
            'permissions: ["activeTab", "scripting", "nativeMessaging", "storage"],',
            'permissions: ["clipboardRead", "activeTab", "scripting", '
            '"nativeMessaging", "storage"],',
        )
        support.commit(self.root)
        with self.assertRaises(ReleaseError) as raised:
            package.prepare(PRODUCT, self.target, root=self.root)
        self.assertIn("permission", str(raised.exception))

    def test_refuses_externally_connectable_surface(self):
        support.patch_build(
            self.root,
            '    manifest.minimum_chrome_version = "120";',
            '    manifest.minimum_chrome_version = "120";\n'
            '    manifest.externally_connectable = { matches: ["https://*/*"] };',
        )
        support.commit(self.root)
        self.refuse_prepare()

    def test_refuses_changed_firefox_identity(self):
        support.patch_build(
            self.root, 'id: "browser@locklark.local"', 'id: "other@example.invalid"'
        )
        support.commit(self.root)
        self.refuse_prepare("firefox")

    def test_refuses_extra_symlinked_or_directory_build_output(self):
        extension = self.root / "browser-extension"

        def with_extra_file(root, product):
            build.run_build(root, product)
            (extension / "dist" / product / "notes.txt").write_text(
                "x", encoding="utf-8"
            )

        self.refuse_prepare(runner=with_extra_file)

        def with_directory(root, product):
            build.run_build(root, product)
            (extension / "dist" / product / "tests").mkdir()

        self.refuse_prepare(runner=with_directory)

        def with_symlink(root, product):
            build.run_build(root, product)
            output = extension / "dist" / product
            (output / "popup.js").unlink()
            os.symlink(output / "core.js", output / "popup.js")

        self.refuse_prepare(runner=with_symlink)

    def test_refuses_tampered_zip_and_receipt(self):
        package.prepare(PRODUCT, self.target, root=self.root)
        original = self.zip_path().read_bytes()
        tampered = bytearray(original)
        tampered[len(tampered) // 2] ^= 0xFF
        self.zip_path().write_bytes(bytes(tampered))
        with self.assertRaises(ReleaseError):
            package.verify(PRODUCT, self.target, root=self.root)
        self.zip_path().write_bytes(original)

        receipt = json.loads(self.receipt_path().read_text(encoding="utf-8"))
        receipt["entries"][0]["sha256"] = "0" * 64
        self.receipt_path().write_text(json.dumps(receipt), encoding="utf-8")
        with self.assertRaises(ReleaseError):
            package.verify(PRODUCT, self.target, root=self.root)

    def test_refuses_a_receipt_claiming_a_signed_release(self):
        package.prepare(PRODUCT, self.target, root=self.root)
        receipt = json.loads(self.receipt_path().read_text(encoding="utf-8"))
        receipt["signed"] = True
        receipt["unsigned"] = False
        self.receipt_path().write_text(json.dumps(receipt), encoding="utf-8")
        with self.assertRaises(ReleaseError):
            package.verify(PRODUCT, self.target, root=self.root)


if __name__ == "__main__":
    unittest.main()
