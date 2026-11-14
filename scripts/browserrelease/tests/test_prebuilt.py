"""Strict consumer tests over real producer pairs and private synthetic roots."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from browserrelease import (
    allowlist,
    bundle,
    package,
    prebuilt,
    receipt as receipt_module,
    zipbuild,
)
from browserrelease.errors import ReleaseError
from browserrelease.tests import support


class PrebuiltTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.root = support.make_root(self.base)
        self.out = self.base / "out"
        self.dist = self.root / "browser-extension" / "dist" / "chromium"
        package.prepare("chromium", str(self.out), root=self.root)

    def copy_pair(self, name: str, product: str = "chromium") -> tuple[Path, Path]:
        prepared = self.base / name / "prepared"
        dist = self.base / name / "dist"
        prepared.mkdir(parents=True)
        for artifact in receipt_module.artifact_names(product):
            shutil.copyfile(self.out / artifact, prepared / artifact)
        shutil.copytree(self.root / "browser-extension" / "dist" / product, dist)
        return prepared, dist

    def verify(self, product: str = "chromium", prepared=None, dist=None):
        return prebuilt.verify_prebuilt(
            product,
            prepared or self.out,
            dist or self.dist,
            self.root,
        )

    def assert_refused(self, product: str = "chromium", prepared=None, dist=None):
        with self.assertRaises(ReleaseError) as raised:
            self.verify(product, prepared, dist)
        self.assertEqual(str(raised.exception), prebuilt.ERROR)
        self.assertNotIn(str(self.base), str(raised.exception))

    def test_all_three_real_products_and_dist_match(self):
        for product in allowlist.PRODUCTS:
            with self.subTest(product=product):
                target = self.base / f"out-{product}"
                package.prepare(product, str(target), root=self.root)
                result = prebuilt.verify_prebuilt(
                    product,
                    target,
                    self.root / "browser-extension" / "dist" / product,
                    self.root,
                )
                self.assertEqual(result["product"], product)
                self.assertEqual(result["entries"], len(allowlist.entries_for(product)))
                self.assertEqual(result["identity"], allowlist.identity_for(product))

    def test_stale_head_is_refused(self):
        (self.root / "browser-extension" / "source-note.txt").write_text(
            "post-preparation source\n", encoding="utf-8"
        )
        support.commit(self.root, "after preparation")
        self.assert_refused()

    def test_wrong_product_is_refused(self):
        self.assert_refused("firefox")

    def test_missing_and_symlink_are_refused(self):
        prepared, dist = self.copy_pair("missing")
        zip_name, _ = receipt_module.artifact_names("chromium")
        (prepared / zip_name).unlink()
        self.assert_refused(prepared=prepared, dist=dist)

        prepared, dist = self.copy_pair("symlink")
        zip_name, _ = receipt_module.artifact_names("chromium")
        target = prepared / zip_name
        target.unlink()
        os.symlink(self.out / zip_name, target)
        self.assert_refused(prepared=prepared, dist=dist)

        prepared, dist = self.copy_pair("dist-symlink")
        dist_link = self.base / "dist-symlink" / "link"
        os.symlink(dist, dist_link)
        self.assert_refused(prepared=prepared, dist=dist_link)

    def test_dist_extra_and_tamper_are_refused(self):
        prepared, dist = self.copy_pair("extra")
        (dist / "extra.js").write_text("extra\n", encoding="utf-8")
        self.assert_refused(prepared=prepared, dist=dist)

        prepared, dist = self.copy_pair("tamper")
        (dist / "core.js").write_text("tampered\n", encoding="utf-8")
        self.assert_refused(prepared=prepared, dist=dist)

    def test_receipt_generator_and_version_metadata_are_exact(self):
        for field, mutate in (
            ("generator", lambda value: {**value, "command": ["node", "build.js", "firefox"]}),
            ("version_metadata", lambda value: {**value, "sha256": "0" * 64}),
        ):
            with self.subTest(field=field):
                prepared, dist = self.copy_pair("receipt-" + field)
                _, receipt_name = receipt_module.artifact_names("chromium")
                path = prepared / receipt_name
                document = json.loads(path.read_text(encoding="utf-8"))
                document[field] = mutate(document[field])
                path.write_text(
                    json.dumps(document, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                self.assert_refused(prepared=prepared, dist=dist)

    def test_zip_tamper_is_refused(self):
        prepared, dist = self.copy_pair("zip-tamper")
        zip_name, _ = receipt_module.artifact_names("chromium")
        path = prepared / zip_name
        data = bytearray(path.read_bytes())
        data[-1] ^= 0xFF
        path.write_bytes(data)
        self.assert_refused(prepared=prepared, dist=dist)


    def test_self_consistent_pair_cannot_mask_static_source_drift(self):
        targets = {
            "chromium": "core.js",
            "firefox": "popup.js",
            "safari": "safari-native-port.js",
        }
        for product in allowlist.PRODUCTS:
            with self.subTest(product=product):
                root = support.make_root(self.base / f"drift-{product}")
                out = self.base / f"drift-out-{product}"
                package.prepare(product, str(out), root=root)
                prepared = self.base / f"drift-pair-{product}"
                prepared.mkdir()
                for artifact in receipt_module.artifact_names(product):
                    shutil.copyfile(out / artifact, prepared / artifact)
                dist = self.base / f"drift-dist-{product}"
                shutil.copytree(
                    root / "browser-extension" / "dist" / product, dist
                )

                name = targets[product]
                static = dist / name
                static.write_bytes(static.read_bytes() + b"\n// artifact drift\n")

                version = "0.1.0"
                files = bundle.read_bundle(dist, product, version)
                zip_bytes = zipbuild.build_zip(
                    allowlist.entries_for(product), files
                )
                zip_name, receipt_name = receipt_module.artifact_names(product)
                (prepared / zip_name).write_bytes(zip_bytes)
                document = json.loads(
                    (prepared / receipt_name).read_text(encoding="utf-8")
                )
                for entry in document["entries"]:
                    if entry["name"] == name:
                        entry["size"] = len(files[name])
                        entry["sha256"] = hashlib.sha256(files[name]).hexdigest()
                document["artifact"]["size"] = len(zip_bytes)
                document["artifact"]["sha256"] = hashlib.sha256(zip_bytes).hexdigest()
                (prepared / receipt_name).write_bytes(
                    receipt_module.receipt_bytes(document)
                )

                # The tampered pair is self-consistent; only the source bytes
                # distinguish it, so the fixed consumer must reject it.
                self.assertEqual(
                    package.verify(product, str(prepared), root=root)["product"],
                    product,
                )
                with self.assertRaises(ReleaseError) as raised:
                    prebuilt.verify_prebuilt(product, prepared, dist, root)
                self.assertEqual(str(raised.exception), prebuilt.ERROR)
                self.assertNotIn(str(self.base), str(raised.exception))

    def test_cli_uses_fixed_refusal(self):
        self.assertEqual(
            prebuilt.main([
                "--product", "chromium",
                "--prepared-dir", str(self.out),
                "--dist", str(self.dist),
                "--root", str(self.root),
            ]), 0
        )


if __name__ == "__main__":
    unittest.main()
