"""Focused tests for the opt-in native Chromium checkout acceptance row."""

from __future__ import annotations

import json
import os
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
                with self.assertRaisesRegex(
                    AssertionError, "expected checkout stage"
                ):
                    support.checkout_native_acceptance(self._ctx())

    def test_cache_reuses_one_validated_journey(self):
        os.environ["LOCKLARK_E2E_CHECKOUT_NATIVE"] = "1"
        calls = 0

        def fake_invoke(command, *, env, cwd, timeout):
            nonlocal calls
            calls += 1
            return 0, _pass_stdout(), ""

        with mock.patch.object(
            support, "_invoke_checkout_journey", side_effect=fake_invoke
        ):
            first = support.checkout_native_acceptance(self._ctx())
            second = support.checkout_native_acceptance(self._ctx())
        self.assertEqual(calls, 1)
        self.assertEqual(first, second)


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
