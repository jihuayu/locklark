"""Focused tests for the opt-in native Chromium checkout acceptance row."""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tests.e2e import support  # noqa: E402
from tests.e2e.harness import (  # noqa: E402
    REGISTRY,
    FeatureNotImplementedError,
)

CHECKOUT_ENV_KEYS = (
    "LOCKLARK_E2E_CHECKOUT_EVIDENCE",
    "LOCKLARK_E2E_CHECKOUT_NATIVE",
    "LOCKLARK_E2E_CHECKOUT_EVIDENCE_OUT",
    "LOCKLARK_BROWSER_FIXTURE",
    "LOCKLARK_TEST_BROWSER_EXECUTABLE",
    "LOCKLARK_TEST_PLAYWRIGHT",
    "LOCKLARK_TEST_CHECKOUT_FRAMES",
    "LOCKLARK_TEST_BROWSER",
    "LOCKLARK_TEST_SHARED_CLIPBOARD",
    "LOCKLARK_TEST_FAILURE_STAGE",
    "LOCKLARK_TEST_BROWSER_PARITY",
    "LOCKLARK_BROWSER_HOST",
    "LOCKLARK_BROWSER_REGISTER",
)


class FakeContext:
    def __init__(self, repo_root: Path, bin_dir: Path):
        self.repo_root = repo_root
        self.bin_dir = bin_dir
        self.evidence = None

    def record_evidence(self, evidence):
        self.evidence = evidence


def _checkout_stage_labels() -> list[str]:
    return [
        stage
        for _, stages in support.CHECKOUT_CASES
        for stage in stages
    ]


def _pass_stdout(extra_lines: tuple[str, ...] = ()) -> str:
    lines = [
        "Native browser stage: " + stage for stage in _checkout_stage_labels()
    ]
    lines.extend(extra_lines)
    lines.append(support.CHECKOUT_PASS_SUMMARY)
    return "\n".join(lines) + "\n"


class CheckoutNativeAcceptanceTests(unittest.TestCase):
    def setUp(self):
        support._CHECKOUT_JOURNEY_CACHE.clear()
        self.addCleanup(support._CHECKOUT_JOURNEY_CACHE.clear)
        for key in CHECKOUT_ENV_KEYS:
            if key in os.environ:
                value = os.environ[key]
                self.addCleanup(os.environ.__setitem__, key, value)
            else:
                self.addCleanup(os.environ.pop, key, None)
            os.environ.pop(key, None)

        self.temp = Path(tempfile.mkdtemp(prefix="lk-checkout-test-"))
        self.addCleanup(shutil.rmtree, self.temp, ignore_errors=True)
        self.bin_dir = self.temp / "bin"
        self.bin_dir.mkdir()
        self.artifacts = {}
        for role in support.CHECKOUT_BINARY_ROLES:
            path = self.bin_dir / role
            path.write_bytes(role.encode("ascii") + b"-binary")
            path.chmod(0o755)
            self.artifacts[role] = path
        self.playwright = self.temp / "playwright"
        self.playwright.mkdir()
        (self.playwright / "package.json").write_text(
            json.dumps({"name": "playwright", "version": "1.64.1"}),
            encoding="utf-8",
        )
        self.artifacts["playwright"] = self.playwright
        self.artifacts["node"] = Path(sys.executable)

        artifacts_patch = mock.patch.object(
            support,
            "_resolve_checkout_artifacts",
            return_value=self.artifacts,
        )
        artifacts_patch.start()
        self.addCleanup(artifacts_patch.stop)
        execution_patch = mock.patch.object(
            support, "_checkout_execution_environment", return_value=None
        )
        execution_patch.start()
        self.addCleanup(execution_patch.stop)
        metadata_patch = mock.patch.object(
            support,
            "_checkout_tool_metadata",
            return_value={
                "node": "v26.4.0",
                "playwright": "1.64.1",
                "chromium": "Chromium 156.0.7900.0",
            },
        )
        metadata_patch.start()
        self.addCleanup(metadata_patch.stop)

    def _ctx(self) -> FakeContext:
        return FakeContext(ROOT, self.bin_dir)

    def _run_and_capture(
        self, stdout: str = "", returncode: int = 0
    ) -> tuple[dict, list[tuple[list[str], dict[str, str]]]]:
        calls: list[tuple[list[str], dict[str, str]]] = []

        def fake_invoke(command, *, env, cwd, timeout):
            calls.append((list(command), dict(env)))
            return returncode, stdout, "private diagnostic body"

        with mock.patch.object(
            support, "_invoke_checkout_journey", side_effect=fake_invoke
        ):
            evidence = support.checkout_native_acceptance(self._ctx())
        return evidence, calls

    def _generate_evidence(self) -> tuple[dict, Path]:
        output = self.temp / "evidence" / "checkout.json"
        output.parent.mkdir()
        os.environ["LOCKLARK_E2E_CHECKOUT_NATIVE"] = "1"
        os.environ["LOCKLARK_E2E_CHECKOUT_EVIDENCE_OUT"] = str(output)
        evidence, calls = self._run_and_capture(_pass_stdout())
        self.assertEqual(len(calls), 1)
        self.assertTrue(output.is_file())
        support._CHECKOUT_JOURNEY_CACHE.clear()
        os.environ.pop("LOCKLARK_E2E_CHECKOUT_NATIVE", None)
        os.environ.pop("LOCKLARK_E2E_CHECKOUT_EVIDENCE_OUT", None)
        return evidence, output

    def test_no_opt_in_is_pending_feature_without_touching_prerequisites(self):
        with mock.patch.object(
            support, "_resolve_checkout_artifacts"
        ) as resolve:
            with self.assertRaises(FeatureNotImplementedError) as raised:
                support.checkout_native_acceptance(self._ctx())
        self.assertIn("PROGRESSIVE_UNIMPLEMENTED: F11", str(raised.exception))
        resolve.assert_not_called()

    def test_missing_native_prerequisite_is_pending_feature(self):
        os.environ["LOCKLARK_E2E_CHECKOUT_NATIVE"] = "1"
        with mock.patch.object(
            support,
            "_resolve_checkout_artifacts",
            side_effect=FeatureNotImplementedError(
                "[PROGRESSIVE_UNIMPLEMENTED: F11] prerequisites are absent"
            ),
        ):
            with self.assertRaises(FeatureNotImplementedError):
                support.checkout_native_acceptance(self._ctx())

    def test_valid_evidence_consumes_pass_without_invoking_the_browser(self):
        generated, output = self._generate_evidence()
        os.environ["LOCKLARK_E2E_CHECKOUT_EVIDENCE"] = str(output)
        with mock.patch.object(
            support,
            "_invoke_checkout_journey",
            side_effect=AssertionError("browser must not run"),
        ) as invoke:
            consumed = support.checkout_native_acceptance(self._ctx())
        invoke.assert_not_called()
        self.assertEqual(consumed, generated)
        self.assertEqual(consumed["status"], "PASS")
        self.assertEqual(
            [case["case_id"] for case in consumed["cases"]],
            list(support.CHECKOUT_CASE_IDS),
        )
        self.assertEqual(
            consumed["cases"][0]["stages"],
            list(support.CHECKOUT_CASES[0][1]),
        )

    def test_stale_malformed_and_missing_case_evidence_fail(self):
        generated, output = self._generate_evidence()
        os.environ["LOCKLARK_E2E_CHECKOUT_EVIDENCE"] = str(output)

        with self.subTest("stale binary hash"):
            self.artifacts["chromium_host"].write_bytes(b"different binary")
            with self.assertRaisesRegex(
                AssertionError, "does not match the current binaries"
            ):
                support.checkout_native_acceptance(self._ctx())
            self.artifacts["chromium_host"].write_bytes(
                b"chromium_host-binary"
            )
            support._CHECKOUT_JOURNEY_CACHE.clear()

        with self.subTest("malformed manifest"):
            malformed = self.temp / "evidence" / "malformed.json"
            malformed.write_text("{not-json", encoding="utf-8")
            os.environ["LOCKLARK_E2E_CHECKOUT_EVIDENCE"] = str(malformed)
            support._CHECKOUT_JOURNEY_CACHE.clear()
            with self.assertRaises(AssertionError):
                support.checkout_native_acceptance(self._ctx())

        with self.subTest("missing case"):
            missing = self.temp / "evidence" / "missing.json"
            payload = json.loads(json.dumps(generated))
            payload["cases"].pop()
            missing.write_text(json.dumps(payload), encoding="utf-8")
            os.environ["LOCKLARK_E2E_CHECKOUT_EVIDENCE"] = str(missing)
            support._CHECKOUT_JOURNEY_CACHE.clear()
            with self.assertRaisesRegex(
                AssertionError, "missing an expected checkout case"
            ):
                support.checkout_native_acceptance(self._ctx())

        with self.subTest("stale source hash"):
            stale = self.temp / "evidence" / "stale-source.json"
            payload = json.loads(json.dumps(generated))
            payload["source"]["source_sha256"] = "0" * 64
            stale.write_text(json.dumps(payload), encoding="utf-8")
            os.environ["LOCKLARK_E2E_CHECKOUT_EVIDENCE"] = str(stale)
            support._CHECKOUT_JOURNEY_CACHE.clear()
            with self.assertRaisesRegex(
                AssertionError, "stale for the current source"
            ):
                support.checkout_native_acceptance(self._ctx())

    def test_source_with_current_revision_but_omitted_hash_is_rejected(self):
        generated, output = self._generate_evidence()
        payload = json.loads(json.dumps(generated))
        payload["source"]["git_revision"] = support._checkout_source_identity(
            ROOT
        )["git_revision"]
        self.assertIsNotNone(payload["source"]["git_revision"])
        del payload["source"]["source_sha256"]
        incomplete = self.temp / "evidence" / "incomplete-source.json"
        incomplete.write_text(json.dumps(payload), encoding="utf-8")
        os.environ["LOCKLARK_E2E_CHECKOUT_EVIDENCE"] = str(incomplete)
        support._CHECKOUT_JOURNEY_CACHE.clear()
        with self.assertRaisesRegex(AssertionError, "malformed"):
            support.checkout_native_acceptance(self._ctx())
        self.assertTrue(output.is_file())

    def test_explicit_run_executes_once_with_private_runtime_and_evidence(self):
        output = self.temp / "evidence" / "out.json"
        output.parent.mkdir()
        os.environ["LOCKLARK_E2E_CHECKOUT_NATIVE"] = "1"
        os.environ["LOCKLARK_E2E_CHECKOUT_EVIDENCE_OUT"] = str(output)
        captured: dict[str, object] = {}

        def fake_invoke(command, *, env, cwd, timeout):
            captured["command"] = list(command)
            captured["env"] = dict(env)
            tmpdir = Path(env["TMPDIR"])
            captured["tmpdir_mode"] = stat.S_IMODE(tmpdir.stat().st_mode)
            captured["runtime_mode"] = stat.S_IMODE(
                Path(env["XDG_RUNTIME_DIR"]).stat().st_mode
            )
            return 0, _pass_stdout(("synthetic-canary-value",)), ""

        with mock.patch.object(
            support, "_invoke_checkout_journey", side_effect=fake_invoke
        ) as invoke:
            evidence = support.checkout_native_acceptance(self._ctx())
        self.assertEqual(invoke.call_count, 1)

        command = captured["command"]
        self.assertEqual(
            command[:5],
            [
                "dbus-run-session",
                "--",
                "xvfb-run",
                "-a",
                "-s",
            ],
        )
        self.assertEqual(
            command[7:], ["scripts/browser_native_acceptance.mjs"]
        )
        env = captured["env"]
        self.assertEqual(env["LOCKLARK_TEST_CHECKOUT_FRAMES"], "1")
        self.assertEqual(env["LOCKLARK_TEST_BROWSER"], "chromium")
        self.assertTrue(Path(env["TMPDIR"]).name.startswith("lk-"))
        self.assertEqual(captured["tmpdir_mode"], 0o700)
        self.assertEqual(captured["runtime_mode"], 0o700)
        self.assertEqual(
            env["LOCKLARK_BROWSER_HOST"], str(self.artifacts["chromium_host"])
        )
        self.assertEqual(
            env["LOCKLARK_BROWSER_REGISTER"],
            str(self.artifacts["browser_register"]),
        )
        self.assertEqual(
            env["LOCKLARK_BROWSER_FIXTURE"], str(self.artifacts["fixture"])
        )
        self.assertEqual(
            env["LOCKLARK_TEST_BROWSER_EXECUTABLE"],
            str(self.artifacts["chromium"]),
        )
        self.assertEqual(
            env["LOCKLARK_TEST_PLAYWRIGHT"], str(self.playwright)
        )

        self.assertEqual(evidence["status"], "PASS")
        self.assertEqual(
            [case["case_id"] for case in evidence["cases"]],
            list(support.CHECKOUT_CASE_IDS),
        )
        self.assertEqual(
            [
                stage
                for case in evidence["cases"]
                for stage in case["stages"]
            ],
            _checkout_stage_labels(),
        )
        self.assertEqual(
            set(evidence["artifacts"]), set(support.CHECKOUT_BINARY_ROLES)
        )
        for digest in evidence["artifacts"].values():
            self.assertRegex(digest, r"^[a-f0-9]{64}$")
        self.assertRegex(evidence["source"]["source_sha256"], r"^[a-f0-9]{64}$")
        self.assertEqual(
            evidence["tools"],
            {
                "node": "v26.4.0",
                "playwright": "1.64.1",
                "chromium": "Chromium 156.0.7900.0",
            },
        )
        serialized = json.dumps(evidence)
        self.assertNotIn(str(self.temp), serialized)
        self.assertNotIn("/tmp/", serialized)
        self.assertNotIn("private diagnostic body", serialized)
        self.assertNotIn("synthetic-canary-value", serialized)
        self.assertEqual(
            json.loads(output.read_text(encoding="utf-8")), evidence
        )
        self.assertFalse(Path(env["TMPDIR"]).exists())

    def test_nonzero_timeout_and_missing_output_are_failures(self):
        os.environ["LOCKLARK_E2E_CHECKOUT_NATIVE"] = "1"

        with self.subTest("nonzero"):
            with mock.patch.object(
                support,
                "_invoke_checkout_journey",
                return_value=(7, _pass_stdout(), "secret diagnostics"),
            ):
                with self.assertRaises(AssertionError) as raised:
                    support.checkout_native_acceptance(self._ctx())
            self.assertNotIn("secret diagnostics", str(raised.exception))

        with self.subTest("timeout"):
            with mock.patch.object(
                support,
                "_invoke_checkout_journey",
                side_effect=subprocess.TimeoutExpired(cmd="native", timeout=1),
            ):
                with self.assertRaisesRegex(AssertionError, "timed out"):
                    support.checkout_native_acceptance(self._ctx())

        with self.subTest("missing fixed PASS summary"):
            with mock.patch.object(
                support,
                "_invoke_checkout_journey",
                return_value=(0, _pass_stdout().replace(
                    support.CHECKOUT_PASS_SUMMARY, "untrusted output"
                ), ""),
            ):
                with self.assertRaisesRegex(
                    AssertionError, "expected PASS summary"
                ):
                    support.checkout_native_acceptance(self._ctx())

        with self.subTest("missing expected stage"):
            output = _pass_stdout().replace(
                "Native browser stage: checkout-lock-review:status\n", ""
            )
            with mock.patch.object(
                support,
                "_invoke_checkout_journey",
                return_value=(0, output, ""),
            ):
                with self.assertRaises(AssertionError) as raised:
                    support.checkout_native_acceptance(self._ctx())
            message = str(raised.exception)
            self.assertIn(
                "expected checkout stage(s): checkout-lock-review:status",
                message,
            )
            self.assertNotIn("untrusted", message)
            self.assertEqual(
                [
                    stage
                    for stage in support._CHECKOUT_STAGE_LABELS
                    if stage in message
                ],
                ["checkout-lock-review:status"],
            )

    def test_missing_stage_reports_only_safe_allowlisted_ids(self):
        missing = (
            "checkout-picker-cancel:picker",
            "checkout-lock-review:status",
        )
        stages, summary = support._parse_checkout_stdout(
            _pass_stdout(("synthetic-canary-value",))
        )
        self.assertEqual(set(stages), set(support._CHECKOUT_STAGE_LABELS))
        self.assertTrue(summary)
        lines = _pass_stdout(("synthetic-canary-value",)).splitlines()
        stdout = "\n".join(
            line
            for line in lines
            if not any(
                line == "Native browser stage: " + stage for stage in missing
            )
        ) + "\n"
        # A non-allowlisted fabricated stage line must not be echoed.
        stdout += "Native browser stage: forged-stage:leak\n"
        os.environ["LOCKLARK_E2E_CHECKOUT_NATIVE"] = "1"
        with mock.patch.object(
            support,
            "_invoke_checkout_journey",
            return_value=(0, stdout, "private diagnostic body"),
        ):
            with self.assertRaises(AssertionError) as raised:
                support.checkout_native_acceptance(self._ctx())
        message = str(raised.exception)
        self.assertIn(
            "expected checkout stage(s): " + ", ".join(missing), message
        )
        self.assertNotIn("synthetic-canary-value", message)
        self.assertNotIn("private diagnostic body", message)
        self.assertNotIn("forged-stage", message)
        self.assertNotIn(support.CHECKOUT_PASS_SUMMARY, message)

    def test_cache_reuses_one_validated_journey(self):
        os.environ["LOCKLARK_E2E_CHECKOUT_NATIVE"] = "1"
        calls = 0

        def fake_invoke(command, *, env, cwd, timeout):
            nonlocal calls
            calls += 1
            return 0, _pass_stdout(), ""

        with mock.patch.object(
            support, "_invoke_checkout_journey", side_effect=fake_invoke
        ) as invoke:
            first = support.checkout_native_acceptance(self._ctx())
            second = support.checkout_native_acceptance(self._ctx())
            self.assertEqual(invoke.call_count, 1)
        self.assertEqual(calls, 1)
        self.assertEqual(first, second)

    def _mutating_source(self) -> tuple[Path, bytes]:
        relative = "browser-extension/core.js"
        path = self.temp_repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        data = b"product source\n"
        path.write_bytes(data)
        return path, data

    def _source_ctx(self) -> FakeContext:
        return FakeContext(self.temp_repo, self.bin_dir)

    def _copy_sources_repo(self) -> None:
        self.temp_repo = self.temp / "repo"
        for relative in support.CHECKOUT_SOURCE_FILES:
            target = self.temp_repo / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, target)

    def _assert_native_cache_hit_fails(self, mutate, pattern):
        path, original = self._mutating_source()
        os.environ["LOCKLARK_E2E_CHECKOUT_NATIVE"] = "1"
        with mock.patch.object(
            support,
            "_invoke_checkout_journey",
            return_value=(0, _pass_stdout(), ""),
        ) as invoke:
            first = support.checkout_native_acceptance(self._source_ctx())
            self.assertEqual(invoke.call_count, 1)
            self.assertEqual(
                support.checkout_native_acceptance(self._source_ctx()), first
            )
            self.assertEqual(invoke.call_count, 1)
            mutate(path, original)
            with self.assertRaisesRegex(AssertionError, pattern):
                support.checkout_native_acceptance(self._source_ctx())
            self.assertEqual(invoke.call_count, 1)

    def test_native_cache_hit_fails_after_source_mutation_without_rerun(self):
        self._copy_sources_repo()
        self._assert_native_cache_hit_fails(
            lambda path, original: path.write_bytes(original + b"# edit\n"),
            "stale for the current source",
        )

    def test_native_cache_hit_fails_after_source_deletion_without_rerun(self):
        self._copy_sources_repo()
        self._assert_native_cache_hit_fails(
            lambda path, original: path.unlink(),
            "checkout evidence source is unavailable",
        )

    def test_native_cache_hit_fails_after_binary_mutation_without_rerun(self):
        self._copy_sources_repo()
        self._mutating_source()
        os.environ["LOCKLARK_E2E_CHECKOUT_NATIVE"] = "1"
        with mock.patch.object(
            support,
            "_invoke_checkout_journey",
            return_value=(0, _pass_stdout(), ""),
        ) as invoke:
            first = support.checkout_native_acceptance(self._source_ctx())
            self.assertEqual(
                support.checkout_native_acceptance(self._source_ctx()), first
            )
            self.artifacts["chromium"].write_bytes(b"different chromium")
            with self.assertRaisesRegex(
                AssertionError, "does not match the current binaries"
            ):
                support.checkout_native_acceptance(self._source_ctx())
            self.assertEqual(invoke.call_count, 1)

    def test_evidence_cache_hit_revalidates_consumed_evidence(self):
        self._copy_sources_repo()
        self._mutating_source()
        output = self.temp / "evidence" / "checkout.json"
        output.parent.mkdir()
        self._generate_evidence_into(output)
        os.environ["LOCKLARK_E2E_CHECKOUT_EVIDENCE"] = str(output)
        with mock.patch.object(
            support,
            "_invoke_checkout_journey",
            side_effect=AssertionError("browser must not run"),
        ) as invoke:
            first = support.checkout_native_acceptance(self._source_ctx())
            self.assertEqual(
                support.checkout_native_acceptance(self._source_ctx()), first
            )
            invoke.assert_not_called()

            with self.subTest("consumed evidence mutated"):
                output.write_text(
                    output.read_text(encoding="utf-8").replace(
                        "\"PASS\"", "\"FAIL\""
                    ),
                    encoding="utf-8",
                )
                with self.assertRaisesRegex(
                    AssertionError, "not PASS"
                ):
                    support.checkout_native_acceptance(self._source_ctx())
                self._generate_evidence_into(output)

            with self.subTest("consumed evidence deleted"):
                output.unlink()
                with self.assertRaisesRegex(
                    AssertionError, "could not be read or parsed"
                ):
                    support.checkout_native_acceptance(self._source_ctx())
                self._generate_evidence_into(output)

            with self.subTest("source mutated"):
                path = self.temp_repo / "browser-extension/core.js"
                path.write_bytes(path.read_bytes() + b"# edit\n")
                with self.assertRaisesRegex(
                    AssertionError, "stale for the current source"
                ):
                    support.checkout_native_acceptance(self._source_ctx())
                path.write_bytes(b"product source\n")

            with self.subTest("binary mutated"):
                self.artifacts["fixture"].write_bytes(b"different fixture")
                with self.assertRaisesRegex(
                    AssertionError, "does not match the current binaries"
                ):
                    support.checkout_native_acceptance(self._source_ctx())

            invoke.assert_not_called()

    def _generate_evidence_into(self, output: Path) -> None:
        """Rewrite a valid PASS manifest for the current source, no journey."""

        evidence = {
            "schema": support.CHECKOUT_EVIDENCE_SCHEMA,
            "schema_version": support.CHECKOUT_EVIDENCE_VERSION,
            "journey": support.CHECKOUT_JOURNEY_ID,
            "status": "PASS",
            "cases": support._checkout_cases_evidence(),
            "source": support._checkout_source_identity(self.temp_repo),
            "artifacts": support._checkout_artifact_hashes(self.artifacts),
            "tools": support._checkout_tool_metadata(self.artifacts),
        }
        support._write_checkout_evidence(output, evidence)


RUNNER_GLUE_SOURCES = (
    "scripts/e2e_runner.py",
    "tests/e2e/harness.py",
    "tests/e2e/support.py",
    "tests/e2e/tier2_f09_f17.py",
)


def _local_module_graph(entry: Path) -> set[str]:
    """Relative-to-ROOT local module specifiers reachable from ``entry``."""

    pending = [entry]
    seen: set[Path] = set()
    while pending:
        module = pending.pop().resolve()
        if module in seen:
            continue
        seen.add(module)
        text = module.read_text(encoding="utf-8")
        for from_match, dynamic_match in re.findall(
            r"""\bfrom\s*["'](\.{1,2}/[^"']+)["']|\bimport\s*\(\s*["'](\.{1,2}/[^"']+)["']""", text
        ):
            pending.append(module.parent / (from_match or dynamic_match))
    return {str(path.relative_to(ROOT)) for path in seen}


class CheckoutSourceIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temp = Path(tempfile.mkdtemp(prefix="lk-checkout-source-"))
        self.addCleanup(shutil.rmtree, self.temp, ignore_errors=True)
        for index, relative in enumerate(support.CHECKOUT_SOURCE_FILES):
            path = self.temp / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"placeholder {index}\n", encoding="utf-8")
        self._baseline = self._identity()

    def _identity(self) -> str:
        return support._checkout_source_identity(self.temp)["source_sha256"]

    def test_runner_glue_sources_are_bound_after_native_journeys(self):
        self.assertEqual(
            support.CHECKOUT_SOURCE_FILES[-len(RUNNER_GLUE_SOURCES):],
            RUNNER_GLUE_SOURCES,
        )
        self.assertEqual(
            support.CHECKOUT_SOURCE_FILES[:5],
            (
                "scripts/browser_native_acceptance.mjs",
                "scripts/browser_checkout_acceptance.mjs",
                "scripts/browser_save_acceptance.mjs",
                "scripts/browser_native_x11.py",
                "browser-extension/build.js",
            ),
        )

    def test_changing_each_runner_glue_source_changes_identity(self):
        baseline = self._identity()
        for relative in RUNNER_GLUE_SOURCES:
            with self.subTest(source=relative):
                path = self.temp / relative
                original = path.read_bytes()
                path.write_bytes(original + b"# dirty edit\n")
                self.assertNotEqual(self._identity(), baseline)
                path.write_bytes(original)
                self.assertEqual(self._identity(), baseline)

    def test_current_build_inputs_are_bound_and_changes_fail_closed(self):
        root = ROOT
        build = (root / "browser-extension" / "build.js").read_text(
            encoding="utf-8"
        )
        listed = re.findall(r'^\s+"([A-Za-z0-9_-]+\.(?:js|html|css))",$', build, re.M)
        expected = [
            f"browser-extension/{name}"
            for name in listed
        ] + ["browser-extension/release-version.json"]
        self.assertIn("browser-extension/core.js", expected)
        self.assertIn("browser-extension/webauthn.js", expected)
        for relative in expected:
            with self.subTest(source=relative):
                self.assertIn(relative, support.CHECKOUT_SOURCE_FILES)
                path = self.temp / relative
                original = path.read_bytes()
                path.write_bytes(original + b"\n// dirty build input\n")
                changed = self._identity()
                self.assertNotEqual(changed, self._baseline)
                with self.assertRaisesRegex(
                    AssertionError, "checkout evidence source is unavailable"
                ):
                    path.unlink()
                    support._checkout_source_identity(self.temp)
                path.write_bytes(original)
                self.assertEqual(self._identity(), self._baseline)

    def test_journey_module_graph_is_fully_bound(self):
        root = ROOT
        graph = _local_module_graph(
            root / "scripts" / "browser_native_acceptance.mjs"
        )
        for relative in (
            "scripts/browser_native_acceptance.mjs",
            "scripts/browser_passkey_acceptance.mjs",
            "scripts/browser_otp_acceptance.mjs",
            "scripts/browser_popup_vault_acceptance.mjs",
            "scripts/browser_shared_clipboard_acceptance.mjs",
        ):
            self.assertIn(relative, graph)
        for relative in graph:
            self.assertIn(relative, support.CHECKOUT_SOURCE_FILES)
        fixtures = {
            relative
            for relative in support.CHECKOUT_SOURCE_FILES
            if "fixture" in Path(relative).name
        }
        self.assertFalse(fixtures & graph)
        for relative in sorted(graph - set(RUNNER_GLUE_SOURCES)):
            with self.subTest(source=relative):
                path = self.temp / relative
                original = path.read_bytes()
                path.write_bytes(original + b"\n// dirty module\n")
                self.assertNotEqual(self._identity(), self._baseline)
                with self.assertRaisesRegex(
                    AssertionError, "checkout evidence source is unavailable"
                ):
                    path.unlink()
                    support._checkout_source_identity(self.temp)
                path.write_bytes(original)
                self.assertEqual(self._identity(), self._baseline)

    def test_missing_runner_glue_source_is_rejected(self):
        for relative in RUNNER_GLUE_SOURCES:
            with self.subTest(source=relative):
                path = self.temp / relative
                original = path.read_bytes()
                path.unlink()
                with self.assertRaisesRegex(
                    AssertionError, "checkout evidence source is unavailable"
                ):
                    support._checkout_source_identity(self.temp)
                path.write_bytes(original)


class CheckoutRowRegistrationTests(unittest.TestCase):
    def test_functional_row_is_registered_and_old_components_are_preserved(self):
        from tests.e2e import tier2_f09_f17

        registry = {spec.test_id: spec for spec in REGISTRY.values()}
        self.assertIn("T2_F11_06", registry)
        new_row = registry["T2_F11_06"]
        self.assertEqual(new_row.coverage_kind, "functional")
        self.assertEqual(new_row.features, ["F11"])
        self.assertEqual(new_row.tier, 2)
        self.assertIn("Chromium checkout", new_row.summary)

        for test_id in ("T2_F11_02", "T2_F11_03", "T2_F11_04", "T2_F11_05"):
            self.assertIn(test_id, registry)
            self.assertEqual(
                registry[test_id].coverage_kind, "component_contract"
            )
        self.assertIn("T2_F11_01", registry)
        self.assertEqual(registry["T2_F11_01"].coverage_kind, "functional")

        fake_ctx = mock.Mock()
        with mock.patch.object(
            tier2_f09_f17,
            "checkout_native_acceptance",
            return_value={"schema": support.CHECKOUT_EVIDENCE_SCHEMA},
        ):
            tier2_f09_f17.t2_f11_06(fake_ctx)
        fake_ctx.record_evidence.assert_called_once_with(
            {"schema": support.CHECKOUT_EVIDENCE_SCHEMA}
        )


if __name__ == "__main__":
    unittest.main()
