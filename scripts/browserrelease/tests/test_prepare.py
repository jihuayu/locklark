"""Integration tests over the real node build in a private synthetic tree."""

from __future__ import annotations

import json
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

from browserrelease import allowlist, package, receipt as receipt_module, zipverify
from browserrelease.tests import support

VERSION = "0.1.0"
PRODUCT = "chromium"


class PrepareTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.root = support.make_root(self.base)

    def output(self, name: str = "out") -> str:
        return str(self.base / name)

    def artifact(self, name: str, product: str = PRODUCT) -> Path:
        return Path(name) / receipt_module.artifact_names(product)[0]

    def receipt(self, name: str, product: str = PRODUCT) -> Path:
        return Path(name) / receipt_module.artifact_names(product)[1]

    def test_prepare_publishes_a_verifiable_pair(self):
        summary = package.prepare(PRODUCT, self.output(), root=self.root)
        self.assertEqual(summary["status"], "prepared")
        self.assertEqual(summary["version"], VERSION)
        self.assertEqual(summary["entries"], list(allowlist.entries_for(PRODUCT)))
        self.assertEqual(
            sorted(entry.name for entry in (self.base / "out").iterdir()),
            sorted(receipt_module.artifact_names(PRODUCT)),
        )
        verified = package.verify(PRODUCT, self.output(), root=self.root)
        self.assertEqual(verified["sha256"], summary["sha256"])
        self.assertTrue(verified["unsigned"])
        self.assertEqual(verified["identity"], allowlist.IDENTITIES[PRODUCT])

    def test_receipt_is_canonical_and_free_of_host_environment(self):
        package.prepare(PRODUCT, self.output(), root=self.root)
        raw = self.receipt(self.output()).read_text(encoding="utf-8")
        receipt = json.loads(raw)
        self.assertEqual(
            raw,
            json.dumps(receipt, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        )
        self.assertEqual(receipt["schema"], receipt_module.SCHEMA)
        self.assertTrue(receipt["unsigned"])
        self.assertFalse(receipt["signed"])
        self.assertEqual(receipt["version"], VERSION)
        self.assertRegex(receipt["source_commit"], r"^[0-9a-f]{40}$")
        self.assertEqual(receipt["generator"]["command"], ["node", "build.js", PRODUCT])
        self.assertEqual(receipt["generator"]["cwd"], "browser-extension")
        for entry in receipt["entries"]:
            self.assertRegex(entry["sha256"], r"^[0-9a-f]{64}$")
            self.assertGreater(entry["size"], 0)
        self.assertNotIn(str(self.base), raw)
        self.assertNotIn("hostname", raw)
        self.assertNotIn("created_at", raw)
        self.assertNotIn("127.0.0.1", raw)

    def test_preparation_is_byte_identical_across_output_directories(self):
        package.prepare("firefox", self.output("one"), root=self.root)
        package.prepare("firefox", self.output("two"), root=self.root)
        for name in receipt_module.artifact_names("firefox"):
            self.assertEqual(
                (self.base / "one" / name).read_bytes(),
                (self.base / "two" / name).read_bytes(),
            )

    def test_rerun_reuses_the_existing_verified_pair(self):
        first = package.prepare(PRODUCT, self.output(), root=self.root)
        second = package.prepare(PRODUCT, self.output(), root=self.root)
        self.assertEqual(second["status"], "existing")
        self.assertEqual(second["sha256"], first["sha256"])

    def test_safari_ships_the_native_port_helper_without_foreign_identity(self):
        summary = package.prepare("safari", self.output(), root=self.root)
        self.assertEqual(summary["entries"][-1], "safari-native-port.js")
        files = zipverify.verify_zip(
            self.artifact(self.output(), "safari").read_bytes(), "safari"
        )
        manifest = json.loads(files["manifest.json"])
        self.assertEqual(
            manifest["background"]["scripts"],
            ["safari-native-port.js", "core.js", "background.js"],
        )
        self.assertNotIn("key", manifest)
        self.assertNotIn("browser_specific_settings", manifest)
        self.assertNotIn("clipboardRead", manifest["permissions"])

    def test_all_three_modes_read_the_one_central_version(self):
        support.write_metadata(self.root, '{"version": "0.2.0"}')
        support.commit(self.root)
        for product in allowlist.PRODUCTS:
            with self.subTest(product=product):
                summary = package.prepare(product, self.output(product), root=self.root)
                self.assertEqual(summary["version"], "0.2.0")
                files = zipverify.verify_zip(
                    self.artifact(self.output(product), product).read_bytes(), product
                )
                self.assertEqual(json.loads(files["manifest.json"])["version"], "0.2.0")

    def test_receipt_records_the_real_fixture_commit(self):
        package.prepare(PRODUCT, self.output(), root=self.root)
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=self.root,
            shell=False,
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=60,
            env=support.GIT_ENVIRONMENT,
        )
        expected = completed.stdout.decode("ascii").strip()
        recorded = json.loads(self.receipt(self.output()).read_text(encoding="utf-8"))
        self.assertEqual(recorded["source_commit"], expected)
        self.assertTrue(re.fullmatch(r"[0-9a-f]{40}", recorded["source_commit"]))


if __name__ == "__main__":
    unittest.main()
