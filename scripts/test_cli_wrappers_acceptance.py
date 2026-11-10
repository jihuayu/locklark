"""Independent unit and end-to-end oracles for the CLI wrappers acceptance."""
import base64
import contextlib
import io
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import cli_wrappers_acceptance as acceptance

ROOT = pathlib.Path(__file__).resolve().parents[1]


class ScanTests(unittest.TestCase):
    def test_plain_base64_hex_and_json_escaped_canaries_are_refused(self):
        secret = 'FixtureCanary-"' + "a" * 48
        variants = (
            secret.encode(),
            base64.b64encode(secret.encode()),
            secret.encode().hex().encode(),
            json.dumps(secret)[1:-1].encode(),
        )
        for raw in variants:
            with self.subTest(length=len(raw)), self.assertRaises(acceptance.AcceptanceFailure):
                acceptance.scan(b"prefix " + raw + b" suffix", [secret])
        acceptance.scan(b"fixed child output only", [secret])
        acceptance.scan(b"fixed child output only", [])


class PrivacyTests(unittest.TestCase):
    def test_unexpected_exception_and_untrusted_stage_never_reach_stdout(self):
        secret = "NeverPrintFailureArguments-" + "f" * 48
        with tempfile.TemporaryDirectory() as directory:
            fake = mock.Mock()
            fake.root = pathlib.Path(directory)
            fake.stage, fake.checks, fake.logs, fake.values = secret, [], [], [secret]
            fake.run.side_effect = RuntimeError(secret)
            out = io.StringIO()
            with mock.patch.object(acceptance, "Acceptance", return_value=fake), contextlib.redirect_stdout(out):
                result = acceptance.main(["--cli", "/unused"])
            self.assertEqual(result, 1)
            self.assertIn("FAIL: cli-wrappers acceptance at prerequisites", out.getvalue())
            self.assertNotIn(secret, out.getvalue())
            fake.close.assert_called_once_with()

    def test_failed_run_still_scans_every_public_output(self):
        secret = "InjectedOutputCanary-" + "e" * 48
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            public = root / "child.stderr"
            public.write_text(secret)
            fake = mock.Mock()
            fake.root, fake.stage, fake.checks = root, "binding", []
            fake.logs, fake.values = [(public, set())], [secret]
            fake.run.side_effect = RuntimeError("fixed failure")
            out = io.StringIO()
            with mock.patch.object(acceptance, "Acceptance", return_value=fake), contextlib.redirect_stdout(out):
                self.assertEqual(acceptance.main(["--cli", "/unused"]), 1)
            self.assertIn("at privacy", out.getvalue())
            self.assertNotIn(secret, out.getvalue())

    def test_cleanup_exception_never_prints_private_details(self):
        secret = "PrivateCleanupFailure-" + "c" * 48
        with tempfile.TemporaryDirectory() as directory:
            fake = mock.Mock()
            fake.root = pathlib.Path(directory)
            fake.stage, fake.checks, fake.logs, fake.values = "complete", [], [], [secret]
            fake.close.side_effect = RuntimeError(secret)
            out = io.StringIO()
            with mock.patch.object(acceptance, "Acceptance", return_value=fake), contextlib.redirect_stdout(out):
                self.assertEqual(acceptance.main(["--cli", "/unused"]), 1)
            self.assertIn("at cleanup", out.getvalue())
            self.assertNotIn(secret, out.getvalue())


class EndToEndTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="cli-wrappers-unit-")
        cls.root = pathlib.Path(cls.temporary.name)
        cls.root.chmod(0o700)
        bin_dir = cls.root / "bin"
        bin_dir.mkdir(mode=0o700)
        suffix = ".exe" if os.name == "nt" else ""
        cls.cli = bin_dir / ("locklark" + suffix)
        cls.fixture = bin_dir / ("cli-wrappers-fixture" + suffix)
        environment = dict(os.environ)
        environment.pop("LOCKLARK_CLI_ACTIVE", None)
        environment.setdefault("GOTOOLCHAIN", "go1.27.3")
        for output, package in ((cls.cli, "./cmd/locklark"), (cls.fixture, "./scripts/cli_wrappers_fixture")):
            result = subprocess.run(
                ["go", "build", "-o", str(output), package], cwd=ROOT,
                env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=240,
            )
            if result.returncode != 0:
                raise RuntimeError("fixture build failed: " + result.stderr.decode(errors="replace"))

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_controller_end_to_end(self):
        artifacts = pathlib.Path(tempfile.mkdtemp(prefix="cli-wrappers-artifacts-", dir=self.root))
        artifacts.chmod(0o700)
        environment = dict(os.environ)
        environment.pop("LOCKLARK_CLI_ACTIVE", None)
        environment.setdefault("GOTOOLCHAIN", "go1.27.3")
        result = subprocess.run(
            [
                sys.executable,
                str(pathlib.Path(acceptance.__file__).resolve()),
                "--cli", str(self.cli),
                "--fixture-bin", str(self.fixture),
                "--artifacts", str(artifacts),
            ],
            cwd=ROOT, env=environment, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=180,
        )
        output = result.stdout.decode(errors="replace")
        if result.returncode != 0:
            self.fail("acceptance failed: " + output + result.stderr.decode(errors="replace"))
        self.assertIn("PASS: cli-wrappers complete", output)
        for name in (
            "all_builtin_profiles_reported",
            "owner_only_binding_pinned_program_and_zero_secret_values",
            "list_and_show_return_non_secret_metadata",
            "shell_functions_not_bare_aliases",
            "needs_auth_false_fast_path_runs_without_prompt",
            "denied_arguments_refused_before_prompt_or_execution",
            "deepseek_explicit_program_foreground_only_no_secret_files",
            "tampered_pinned_executable_refused",
            "public_streams_and_binding_are_canary_clean",
        ):
            self.assertIn("PASS: cli-wrappers " + name, output)
        results = sorted(artifacts.glob("cli-wrappers-*/result.json"))
        self.assertEqual(len(results), 1)
        payload = json.loads(results[0].read_bytes())
        self.assertTrue(payload["success"])
        self.assertEqual(payload["stage"], "complete")
        self.assertEqual(len(payload["checks"]), 10)


if __name__ == "__main__":
    unittest.main()
