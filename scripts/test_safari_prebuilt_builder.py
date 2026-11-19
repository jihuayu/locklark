"""Contract tests for the strict Safari prebuilt shell branch.

The producer is real Node/browserrelease output in a temporary clean repo.
Xcode is never run: a test-only xcodegen fake records its call and exits at a
fixed early stop. No Swift/app/CI acceptance is claimed.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from browserrelease import package, receipt  # noqa: E402
from browserrelease.tests import support  # noqa: E402


class SafariPrebuiltBuilderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ll-safari-contract-")
        self.addCleanup(self.temp.cleanup)
        self.root = support.make_root(Path(self.temp.name))
        for name in ("safari", "scripts"):
            shutil.copytree(ROOT / name, self.root / name, dirs_exist_ok=False)
        support.commit(self.root, "safari contract fixture")
        self.prepared = Path(self.temp.name) / "prepared"
        for product in ("chromium", "firefox", "safari"):
            package.prepare(product, str(self.prepared), root=self.root)
        self.fake = Path(self.temp.name) / "fake-bin"
        self.fake.mkdir(mode=0o700)
        self.log = Path(self.temp.name) / "calls.log"
        for name, code in (("node", 99), ("xcodegen", 42), ("xcodebuild", 43)):
            path = self.fake / name
            path.write_text(
                "#!/bin/sh\n"
                f"printf '%s\\n' '{name}' >> \"$FAKE_LOG\"\n"
                f"exit {code}\n",
                encoding="utf-8",
            )
            path.chmod(0o700)
        self.env = os.environ.copy()
        self.env.update({
            "PATH": str(self.fake) + ":" + os.environ.get("PATH", "/usr/bin:/bin"),
            "FAKE_LOG": str(self.log),
            "LOCKLARK_BROWSER_REQUIRE_PREBUILT": "1",
            "LOCKLARK_BROWSER_EXTENSION_PREPARED_DIR": str(self.prepared),
            "LOCKLARK_BROWSER_EXTENSION_CHROMIUM": str(self.root / "browser-extension/dist/chromium"),
            "LOCKLARK_BROWSER_EXTENSION_FIREFOX": str(self.root / "browser-extension/dist/firefox"),
            "LOCKLARK_BROWSER_EXTENSION_SAFARI": str(self.root / "browser-extension/dist/safari"),
            "LOCKLARK_UNSIGNED_CI": "1",
            "LOCKLARK_ALLOW_MISSING_HELPER": "1",
        })

    def run_builder(self, env=None):
        return subprocess.run(
            ["/bin/bash", str(self.root / "safari/scripts/build_safari.sh")],
            cwd=self.root, env=env or self.env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=120,
        )

    def calls(self):
        return self.log.read_text(encoding="utf-8").splitlines() if self.log.exists() else []

    def test_real_producer_strict_shell_stops_before_xcodebuild(self):
        completed = self.run_builder()
        self.assertEqual(completed.returncode, 42, completed.stderr)
        calls = self.calls()
        self.assertIn("xcodegen", calls)
        self.assertNotIn("xcodebuild", calls)
        self.assertNotIn("node", calls)

    def test_missing_partial_and_prebuilt_mismatch_never_run_node_or_xcode(self):
        # Flag omitted while prepared/product env is present: no fallback.
        env = dict(self.env); env.pop("LOCKLARK_BROWSER_REQUIRE_PREBUILT")
        completed = self.run_builder(env)
        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assertEqual(self.calls(), [])
        # Explicit empty/bad flag and partial product env all reject before node.
        for value in ("", "yes"):
            env = dict(self.env); env["LOCKLARK_BROWSER_REQUIRE_PREBUILT"] = value
            completed = self.run_builder(env)
            self.assertEqual(completed.returncode, 1, completed.stderr)
            self.assertEqual(self.calls(), [])
        for key in ("LOCKLARK_BROWSER_EXTENSION_SAFARI", "LOCKLARK_BROWSER_EXTENSION_FIREFOX"):
            env = dict(self.env); env.pop(key)
            completed = self.run_builder(env)
            self.assertEqual(completed.returncode, 1, completed.stderr)
            self.assertEqual(self.calls(), [])
        # Tamper one strict pair receipt: source/hash mismatch must stop here.
        _, receipt_name = receipt.artifact_names("chromium")
        target = self.prepared / receipt_name
        original = target.read_bytes()
        document = json.loads(original)
        document["source_commit"] = "0" * 40
        target.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        try:
            completed = self.run_builder()
            self.assertEqual(completed.returncode, 1, completed.stderr)
            self.assertEqual(self.calls(), [])
        finally:
            target.write_bytes(original)
        # Hash mismatch in the prepared ZIP must be refused at the same gate.
        zip_name, _ = receipt.artifact_names("chromium")
        zip_path = self.prepared / zip_name
        original_zip = zip_path.read_bytes()
        data = bytearray(original_zip); data[-1] ^= 0xFF
        zip_path.write_bytes(data)
        try:
            completed = self.run_builder()
            self.assertEqual(completed.returncode, 1, completed.stderr)
            self.assertEqual(self.calls(), [])
        finally:
            zip_path.write_bytes(original_zip)


if __name__ == "__main__":
    unittest.main()
