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


CROSS_SITE_EXCLUDED = "checkout-cross-site:excluded"
CROSS_SITE_NATIVE_REVIEW = "checkout-cross-site:native-review"
CROSS_SITE_BRANCHES = (CROSS_SITE_EXCLUDED, CROSS_SITE_NATIVE_REVIEW)


def _case_stages(branch: str) -> list[str]:
    """The real stages one run records for the cross-site case on ``branch``."""

    return support._checkout_case_stages(
        support.CHECKOUT_BRANCH_CASE_ID, {branch}
    )


def _run_stages(branch: str) -> list[str]:
    """The real stage list one native acceptance run emits for ``branch``."""

    return [
        stage
        for case_id, _ in support.CHECKOUT_CASES
        for stage in (
            _case_stages(branch)
            if case_id == support.CHECKOUT_BRANCH_CASE_ID
            else support._checkout_case_stages(case_id)
        )
    ]


def _pass_stdout(
    branch: str = CROSS_SITE_NATIVE_REVIEW,
    extra_lines: tuple[str, ...] = (),
) -> str:
    lines = [
        "Native browser stage: " + stage for stage in _run_stages(branch)
    ]
    lines.extend(extra_lines)
    lines.append(support.CHECKOUT_PASS_SUMMARY)
    return "\n".join(lines) + "\n"

# Independent of production's own line splitting: a diagnostic is present when
# ANY line of stdout or stderr starts with the fixed prefix (Str.splitlines).
def _diagnostic_present(stdout: str, stderr: str) -> bool:
    return any(
        line.startswith(support._CHECKOUT_DIAGNOSTIC_PREFIX)
        for line in (str(stdout or "") + "\n" + str(stderr or "")).splitlines()
    )


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
        evidence, calls = self._run_and_capture(_pass_stdout(CROSS_SITE_NATIVE_REVIEW))
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
            return 0, _pass_stdout(
                CROSS_SITE_NATIVE_REVIEW,
                extra_lines=("synthetic-canary-value",),
            ), ""

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
            _run_stages(CROSS_SITE_NATIVE_REVIEW),
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
                return_value=(7, _pass_stdout(CROSS_SITE_NATIVE_REVIEW), "secret diagnostics"),
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
                return_value=(0, _pass_stdout(CROSS_SITE_NATIVE_REVIEW).replace(
                    support.CHECKOUT_PASS_SUMMARY, "untrusted output"
                ), ""),
            ):
                with self.assertRaisesRegex(
                    AssertionError, "expected PASS summary"
                ):
                    support.checkout_native_acceptance(self._ctx())

        with self.subTest("missing expected stage"):
            output = _pass_stdout(CROSS_SITE_NATIVE_REVIEW).replace(
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
            _pass_stdout(extra_lines=("synthetic-canary-value",))
        )
        # Every fixed stage of this branch parses, and only this branch marker.
        self.assertEqual(set(stages), set(_run_stages(CROSS_SITE_NATIVE_REVIEW)))
        self.assertNotIn(CROSS_SITE_EXCLUDED, stages)
        for stage in support.CHECKOUT_REQUIRED_STAGES:
            self.assertIn(stage, stages)
        self.assertTrue(summary)
        lines = _pass_stdout(extra_lines=("synthetic-canary-value",)).splitlines()
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

    def _nonzero(self, stderr: str, stdout: str = "") -> tuple[dict, str]:
        os.environ["LOCKLARK_E2E_CHECKOUT_NATIVE"] = "1"
        support._CHECKOUT_JOURNEY_CACHE.clear()
        ctx = self._ctx()
        with mock.patch.object(
            support,
            "_invoke_checkout_journey",
            return_value=(7, stdout, stderr),
        ):
            with self.assertRaises(AssertionError) as raised:
                support.checkout_native_acceptance(ctx)
        self.assertEqual(
            str(raised.exception), "native checkout acceptance exited with status 7"
        )
        self.assertEqual(set(ctx.evidence), {support.CHECKOUT_FAILURE_EVIDENCE_KEY})
        return ctx.evidence[support.CHECKOUT_FAILURE_EVIDENCE_KEY], str(
            raised.exception
        )

    def _assert_no_canary(self, value, message: str) -> None:
        text = json.dumps(value) + message
        for canary in ("CANARY-9f3a1c", "/home/runner/x", "https://leak.example"):
            self.assertNotIn(canary, text)

    def test_nonzero_run_records_only_the_fixed_checkout_failure(self):
        diagnostic = {
            "stage": "checkout-stale:navigation",
            "reason": "Native route approval label missing CANARY-9f3a1c",
            "ignored": "https://leak.example",
            "nativeError": {
                "code": "window-timeout",
                "action": "label-wait",
                "index": 2,
                "x_codes": [3, 170],
                "message": "CANARY-9f3a1c",
            },
        }
        stderr = (
            "CANARY-9f3a1c /home/runner/x\nNative browser diagnostic: "
            + json.dumps(diagnostic)
        )
        record, message = self._nonzero(stderr)
        self._assert_no_canary(record, message)
        self.assertEqual(
            record,
            {
                "stage": "checkout-stale:navigation",
                "kind": "native-helper",
                "native": {
                    "code": "window-timeout",
                    "action": "label-wait",
                    "index": 2,
                    "x_codes": [3, 170],
                },
                "exit": "exited 7",
                "startupPhase": "unknown",
                "failureRecordState": "accepted",
                "wrapperFamily": "unknown",
            },
        )
        stage = self._nonzero(
            "Native browser diagnostic: "
            + json.dumps({"stage": "native-unlock", "reason": "Paired popup not ready"})
        )[0]
        self.assertEqual(
            stage,
            {"stage": "native-unlock", "kind": "acceptance-failure",
             "native": None, "exit": "exited 7", "startupPhase": "unknown",
             "failureRecordState": "accepted", "wrapperFamily": "unknown"},
        )

    def test_invalid_checkout_diagnostics_are_unclassified(self):
        def line(stage, native):
            payload = {"stage": stage, "reason": "CANARY-9f3a1c"}
            if native is not None:
                payload["nativeError"] = native
            return "Native browser diagnostic: " + json.dumps(payload)

        def valid_native(code="window-timeout", action="label-wait"):
            return {"code": code, "action": action}

        def cases():
            yield line("checkout-stale:navigation CANARY-9f3a1c", None)
            yield line("passkey-get", None)
            # Non-allowlisted action and code, out-of-range x_codes and index,
            # a missing index and non-string values fail closed.
            yield line("fixture", valid_native(action="CANARY-9f3a1c"))
            yield line("fixture", valid_native(code="window-frozen"))
            yield line("fixture", {"code": "window-timeout", "action": "label-wait",
                                   "index": 0, "x_codes": [3, 0]})
            yield line("fixture", {"code": "window-timeout", "action": "label-wait",
                                   "index": -2})
            yield line("fixture", {"code": "window-timeout", "action": "label-wait"})
            yield line("fixture", {"code": "window-timeout", "action": "label-wait",
                                   "index": 256})
            yield line("fixture", {"code": ["window-timeout"], "action": "label-wait"})
            yield line("fixture", {"code": "window-timeout", "action": {"x": 1}})
            # Oversized, repeated (identical or otherwise valid) and
            # unparseable prefixes.
            yield line("fixture", None) + " " * 9000
            yield line("fixture", None) + "\n" + line("fixture", None)
            yield (line("fixture", None) + "\n"
                   + line("native-pair", valid_native()))
            yield "Native browser diagnostic: {not json"
            yield "Native browser diagnostic: {not json\n" + line("fixture", None)
            yield line("fixture", None).replace("Native browser diagnostic:", " x")

        expected = {
            "stage": "unclassified",
            "kind": "unclassified",
            "native": None,
            "exit": "exited 7",
            "startupPhase": "unknown",
            "wrapperFamily": "unknown",
        }
        for stderr in cases():
            state = "rejected" if _diagnostic_present("", stderr) else "absent"
            with self.subTest(stderr=stderr[:40]):
                record, message = self._nonzero(stderr)
                self._assert_no_canary(record, message)
                self.assertEqual(record, {**expected, "failureRecordState": state})

    def test_startup_diagnostic_is_a_fixed_projection_only(self):
        prefix = support._CHECKOUT_STARTUP_PREFIX
        self.assertEqual(len(support._CHECKOUT_STARTUP_PHASES), 5)

        def marker_all_but(omit):
            return "".join(prefix + p + "\n" for p in support._CHECKOUT_STARTUP_PHASES
                           if p != omit)
        https = marker_all_but("journey-entered")
        # Accepted diagnostic carrying canary text in reason/message.
        payload = {"stage": "fixture", "reason": "CANARY-9f3a1c",
                   "message": "CANARY-9f3a1c /home/runner/x"}
        good = support._CHECKOUT_DIAGNOSTIC_PREFIX + json.dumps(payload)
        # An invalid record after unrelated stderr: presence is any-line, so the
        # fixed projection is rejected rather than read as absent.
        not_first = "private body /home/runner/x\n" + (
            support._CHECKOUT_DIAGNOSTIC_PREFIX
            + json.dumps({**payload, "nativeError": {
                "code": "window-frozen", "action": "label-wait"}}))
        cases = (
            # (stdout, stderr, startupPhase, failureRecordState, wrapperFamily)
            (marker_all_but("journey-entered"), good, "https-ready", "accepted",
             "unknown"),
            ("", "", "unknown", "absent", "unknown"),
            ("", "private body", "unknown", "absent", "unknown"),
            # The state follows the diagnostic alone; repeated lines are
            # never partly trusted and keep the existing projection.
            (https, good + "\n" + good, "https-ready", "rejected", "unknown"),
            # A valid diagnostic is still accepted with no valid markers.
            (https + prefix + "CANARY-9f3a1c\n", good, "unknown", "accepted",
             "unknown"),
            # A wrapper signature in the excluded diagnostic line is ignored.
            (https, good.replace("CANARY-9f3a1c", "xvfb-run: error:"),
             "https-ready", "accepted", "unknown"),
            # An invalid marker never becomes a phase or leaks raw stdout.
            (https + prefix + "CANARY-9f3a1c\n", "private body", "unknown",
             "absent", "unknown"),
            (https, "xvfb-run: error: CANARY-9f3a1c", "https-ready", "absent", "xvfb"),
            (https, "Autolaunch error: CANARY-9f3a1c", "https-ready", "absent",
             "dbus"),
            (https, "SyntaxError: Cannot use import statement CANARY-9f3a1c",
             "https-ready", "absent", "node-loader"),
            # Per-line startup limit: the exact marker line is accepted, and
            # a prefixed line longer than 128 characters rejects the block.
            (https + prefix + "module-ready\n", "", "module-ready", "absent",
             "unknown"),
            (https + " " * (8 * 1024) + "\n" + prefix + "module-ready\n", "",
             "module-ready", "absent", "unknown"),
            (https + prefix + "module-ready" + " " * 100 + "\n", "", "unknown",
             "absent", "unknown"),
            (https + prefix + "\\" * 127 + "\n", "", "unknown", "absent",
             "unknown"),
            # Every marker line is read and only the last valid phase is
            # projected: an exact repeat keeps it, a repeated invalid value
            # rejects the whole block, and a different valid line wins.
            (https + "\n" + prefix + "journey-entered\n"
             + prefix + "journey-entered\n", "", "journey-entered", "absent",
             "unknown"),
            (https + "\n" + prefix + "journey-entered\n"
             + prefix + "journal-entered\n", "", "unknown", "absent", "unknown"),
            (https + "\n" + prefix + "journey-entered\n"
             + prefix + "state-ready\n", "", "state-ready", "absent",
             "unknown"),
            (https, "private body /home/runner/x\n" + good, "https-ready",
             "accepted", "unknown"),
            (https, not_first, "https-ready", "rejected", "unknown"),
        )
        def oversized_marker(stdout):
            """Some prefixed line exceeds 128 characters."""

            return any(
                len(text.rstrip("\r")) > 128
                for text in stdout.splitlines()
                if text.startswith(prefix)
            )

        self.assertTrue(oversized_marker(prefix + "module-ready" + " " * 100))
        self.assertFalse(oversized_marker(prefix + "module-ready"))
        for stdout, stderr, phase, state, family in cases:
            # An oversized prefixed line never leaves the block accepted.
            if oversized_marker(stdout):
                self.assertEqual(phase, "unknown")
            # Every expected rejected/absent state matches prefix presence
            # independently, not merely "present"; exact acceptance is
            # covered by the accepted cases and the startup assertions below.
            if state != "accepted":
                self.assertEqual(
                    state,
                    "rejected" if _diagnostic_present(stdout, stderr)
                    else "absent",
                )
            with self.subTest(case=stdout[-20:] + stderr[:20]):
                os.environ["LOCKLARK_E2E_CHECKOUT_NATIVE"] = "1"
                ctx = self._ctx()
                with mock.patch.object(
                    support, "_invoke_checkout_journey",
                    return_value=(7, stdout, stderr),
                ):
                    with self.assertRaisesRegex(
                        AssertionError,
                        "^native checkout acceptance exited with status 7$",
                    ):
                        support.checkout_native_acceptance(ctx)
                record = ctx.evidence[support.CHECKOUT_FAILURE_EVIDENCE_KEY]
                self._assert_no_canary(record, "")
                self.assertIn(record["startupPhase"],
                              support._CHECKOUT_STARTUP_PHASES + ("unknown",))
                self.assertIn(record["failureRecordState"],
                              ("absent", "rejected", "accepted"))
                self.assertIn(record["wrapperFamily"],
                              ("dbus", "xvfb", "node-loader", "unknown"))
                self.assertEqual(
                    (record["startupPhase"], record["failureRecordState"],
                     record["wrapperFamily"], record["exit"]),
                    (phase, state, family, "exited 7"),
                )
                # Accepted keeps its existing stage/kind; the others stay
                # unclassified, all derived from the fixed state above.
                self.assertEqual(
                    (record["stage"], record["kind"], record["native"]),
                    (("fixture", "acceptance-failure", None) if state == "accepted"
                     else ("unclassified", "unclassified", None)),
                )

    def test_source_frames_are_optional_fixed_basename_frames(self):
        names = support._CHECKOUT_SOURCE_FILES
        self.assertEqual(len(names), 5)
        native = {"code": "window-timeout", "action": "label-wait", "index": 0}
        base = {"stage": "fixture", "kind": "acceptance-failure", "native": None,
                "exit": "exited 7", "startupPhase": "unknown",
                "failureRecordState": "accepted", "wrapperFamily": "unknown"}

        def diagnostic(**fields):
            payload = {"stage": "fixture",
                       "reason": "CANARY-9f3a1c /home/runner/x", **fields}
            return support._CHECKOUT_DIAGNOSTIC_PREFIX + json.dumps(payload)

        frames = [f"{names[1]}:12:3", f"{names[0]}:5:40"]
        expect_frames = [
            {"file": names[1], "line": 12, "column": 3},
            {"file": names[0], "line": 5, "column": 40},
        ]
        cases = (
            # Missing, null and empty leave the existing projection.
            (diagnostic(), base),
            (diagnostic(frames=None), base),
            (diagnostic(frames=[]), base),
            (diagnostic(frames=frames), {**base, "sourceFrames": expect_frames}),
            # A helper failure keeps its allowlisted fields and frames.
            (diagnostic(nativeError=native, frames=[f"{names[2]}:1:1"]),
             {"stage": "fixture", "kind": "native-helper",
              "native": {**native, "x_codes": []},
              "sourceFrames": [{"file": names[2], "line": 1, "column": 1}],
              "exit": "exited 7", "startupPhase": "unknown",
              "failureRecordState": "accepted", "wrapperFamily": "unknown"}),
            # Unknown basenames, paths, zero and out-of-bound positions,
            # oversized lists, non-string entries and canary text reject the
            # whole record conservatively; nothing raw is copied.
            (diagnostic(frames=["app.js:1:1"]), None),
            (diagnostic(frames=["browser_native_acceptance.mjs.bak:1:1"]), None),
            (diagnostic(frames=["src/browser_native_acceptance.mjs:1:1"]), None),
            (diagnostic(frames=["/x/browser_native_acceptance.mjs:1:1"]), None),
            (diagnostic(frames=[f"{names[0]}:0:1"]), None),
            (diagnostic(frames=[f"{names[0]}:1:0"]), None),
            (diagnostic(frames=[f"{names[0]}:1000000:1"]), None),
            (diagnostic(frames=[f"{names[0]}:1:65536"]), None),
            (diagnostic(frames=[f"{names[0]}:12"]), None),
            (diagnostic(frames=[f"{names[0]}:12:3\nCANARY-9f3a1c"]), None),
            (diagnostic(frames=[names[0] + ":12:3"] * 17), None),
            (diagnostic(frames=[1]), None),
            (diagnostic(frames={"file": names[0]}), None),
            (diagnostic(frames="browser_native_acceptance.mjs:1:1"), None),
            (diagnostic(frames=["CANARY-9f3a1c"]), None),
        )
        for stderr, expected in cases:
            with self.subTest(frames=stderr[-60:]):
                record, message = self._nonzero(stderr)
                self._assert_no_canary(record, message)
                if expected is None:
                    self.assertEqual(
                        record,
                        {"stage": "unclassified", "kind": "unclassified",
                         "native": None, "exit": "exited 7",
                         "startupPhase": "unknown",
                         "failureRecordState": "rejected",
                         "wrapperFamily": "unknown"},
                    )
                    self.assertEqual(
                        message,
                        "native checkout acceptance exited with status 7",
                    )
                else:
                    self.assertEqual(record, expected)
        # Exactly the maximum number of valid frames is still accepted.
        record, _ = self._nonzero(
            diagnostic(frames=[f"{names[0]}:1:1"] * 16))
        self.assertEqual(len(record["sourceFrames"]), 16)
        # Exact line bound: 100000 is accepted, 100001 is over the limit.
        record, _ = self._nonzero(
            diagnostic(frames=[f"{names[0]}:100000:1"]))
        self.assertEqual(
            record["sourceFrames"],
            [{"file": names[0], "line": 100000, "column": 1}],
        )
        record, _ = self._nonzero(
            diagnostic(frames=[f"{names[0]}:100001:1"]))
        self.assertEqual(
            record,
            {"stage": "unclassified", "kind": "unclassified", "native": None,
             "exit": "exited 7", "startupPhase": "unknown",
             "failureRecordState": "rejected", "wrapperFamily": "unknown"},
        )

    def test_picker_status_is_an_optional_fixed_enum(self):
        names = support._CHECKOUT_SOURCE_FILES
        picker = "checkout-picker-cancel:picker"

        def diagnostic(**fields):
            payload = {
                "stage": picker,
                "reason": "CANARY-9f3a1c /home/runner/x Checkout origin picker "
                "missing: popup status other (unrecognised public status)",
                **fields,
            }
            return support._CHECKOUT_DIAGNOSTIC_PREFIX + json.dumps(payload)

        base = {
            "stage": picker,
            "kind": "acceptance-failure",
            "native": None,
            "exit": "exited 7",
            "startupPhase": "unknown",
            "failureRecordState": "accepted",
            "wrapperFamily": "unknown",
        }
        self.assertEqual(
            set(support.CHECKOUT_PICKER_STATUSES),
            {"no-gesture", "unavailable", "unsupported", "list-failed",
             "selected", "cancelled", "other"},
        )
        # Every fixed enum value is projected beside the existing fields.
        for value in support.CHECKOUT_PICKER_STATUSES:
            with self.subTest(pickerStatus=value):
                record, message = self._nonzero(
                    diagnostic(pickerStatus=value, frames=[f"{names[1]}:1:1"]))
                self._assert_no_canary(record, message)
                self.assertEqual(
                    record,
                    {**base, "pickerStatus": value,
                     "sourceFrames": [{"file": names[1], "line": 1, "column": 1}]},
                )
        # Absent, null or empty keeps the existing projection unchanged.
        for fields in ({}, {"pickerStatus": None}, {"pickerStatus": ""}):
            with self.subTest(fields=fields):
                self.assertEqual(self._nonzero(diagnostic(**fields))[0], base)
        # Anything not in the fixed enum (raw popup text, a recognisable but
        # unmapped line, wrong types or case) rejects the whole record.
        rejected = (
            "不会自动选择",
            "本次请求被拒绝",
            "selected CANARY-9f3a1c",
            "Selected",
            " selected",
            True,
            1,
            ["selected"],
            {"status": "selected"},
        )
        for value in rejected:
            with self.subTest(value=value):
                record, message = self._nonzero(diagnostic(pickerStatus=value))
                self._assert_no_canary(record, message)
                self.assertEqual(
                    record,
                    {"stage": "unclassified", "kind": "unclassified",
                     "native": None, "exit": "exited 7",
                     "startupPhase": "unknown",
                     "failureRecordState": "rejected",
                     "wrapperFamily": "unknown"},
                )
        # The enum set is exactly the seven fixed values the sender exports;
        # drift on either side fails here instead of at the next red run.
        self.assertEqual(
            support.CHECKOUT_PICKER_STATUSES,
            ("no-gesture", "unavailable", "unsupported", "list-failed",
             "selected", "cancelled", "other"),
        )
        self.assertEqual(len(set(support.CHECKOUT_PICKER_STATUSES)), 7)
        # A stage outside the allowlist still exposes no picker status, so the
        # enum is never attributed to a failure the picker did not set.
        self.assertEqual(
            self._nonzero(
                diagnostic(stage="checkout-picker-cancel",
                           pickerStatus="other"))[0],
            {"stage": "unclassified", "kind": "unclassified", "native": None,
             "exit": "exited 7", "startupPhase": "unknown",
             "failureRecordState": "rejected", "wrapperFamily": "unknown"},
        )

    def test_picker_status_never_coexists_with_a_native_error(self):
        # The sender writes pickerStatus only when no native helper error is
        # the original failure, so both together reject the whole record even
        # when each field alone would be accepted.
        picker = "checkout-picker-cancel:picker"
        valid_native = {"code": "window-timeout", "action": "label-wait",
                        "index": 0, "x_codes": [3]}

        def diagnostic(**fields):
            payload = {"stage": picker, "reason": "CANARY-9f3a1c", **fields}
            return support._CHECKOUT_DIAGNOSTIC_PREFIX + json.dumps(payload)

        rejected = {
            "stage": "unclassified", "kind": "unclassified", "native": None,
            "exit": "exited 7", "startupPhase": "unknown",
            "failureRecordState": "rejected", "wrapperFamily": "unknown",
        }
        combinations = [
            # Every fixed enum value beside a well-formed native error.
            *({"pickerStatus": value, "nativeError": valid_native}
              for value in support.CHECKOUT_PICKER_STATUSES),
            # Beside a malformed native error that would fail closed anyway.
            {"pickerStatus": "other",
             "nativeError": {**valid_native, "code": "window-frozen"}},
            {"pickerStatus": "other", "nativeError": None},
            {"pickerStatus": "other", "nativeError": {}},
        ]
        for fields in combinations:
            with self.subTest(fields=fields):
                record, message = self._nonzero(diagnostic(**fields))
                self._assert_no_canary(record, message)
                self.assertEqual(record, rejected)
        # Neither field alone changes: a valid native error alone keeps its
        # helper projection, and a picker status alone keeps its enum.
        self.assertEqual(
            self._nonzero(diagnostic(nativeError=valid_native))[0]["kind"],
            "native-helper",
        )
        alone = self._nonzero(diagnostic(pickerStatus="other"))[0]
        self.assertEqual(alone["pickerStatus"], "other")
        self.assertEqual(alone["kind"], "acceptance-failure")

    def test_fixed_diagnostic_is_read_on_either_captured_stream(self):
        prefix = support._CHECKOUT_STARTUP_PREFIX
        diag = support._CHECKOUT_DIAGNOSTIC_PREFIX
        last = support._CHECKOUT_STARTUP_PHASES[-2]

        def line(stage):
            return diag + json.dumps({"stage": stage, "reason": "CANARY-9f3a1c"})

        def expected(stage, kind, state, phase=last):
            return {"stage": stage, "kind": kind, "native": None,
                    "startupPhase": phase, "failureRecordState": state,
                    "wrapperFamily": "unknown", "exit": "exited 7"}

        startup = prefix + last + "\n"
        accepted = expected("fixture", "acceptance-failure", "accepted")
        rejected = expected("unclassified", "unclassified", "rejected")
        body = [f"wrapper line {index} " + "x" * 300 for index in range(190)]
        oversized = (startup + "\n".join(body), "\n".join(body) + "\n"
                     + line("fixture"))
        for stream in oversized:
            self.assertLessEqual(len(stream.encode()), 64 * 1024)
            self.assertTrue(all(len(raw.encode()) <= 8 * 1024
                                for raw in stream.splitlines()))
        self.assertGreater(
            len((oversized[0] + oversized[1]).encode()), 64 * 1024)
        # (stdout, stderr, expected fixed record); the same line on either
        # stream, or a malformed/duplicate/oversized line on either, is held
        # to the one combined rule.
        cases = (
            (startup + line("fixture"), "private body", accepted),
            (startup, line("fixture"), accepted),
            (startup + line("fixture"), line("fixture"), rejected),
            (startup + line("fixture"), diag + "{not json", rejected),
            (startup + diag + "{not json", line("fixture"), rejected),
            (startup + line("fixture") + " " * 9000, "", rejected),
            (startup, line("fixture") + " " * 9000, rejected),
            (startup, line("fixture") + "\n" + line("native-pair"), rejected),
            # Each stream and each line fits every bound, but the combined
            # capture exceeds 64 KiB: rejected, never partly trusted (the
            # startup phase is projected from stdout alone and stays valid).
            (*oversized, rejected),
        )
        for stdout, stderr, want in cases:
            with self.subTest(case=stdout[-40:] + stderr[:20]):
                record, message = self._nonzero(stderr, stdout)
                self._assert_no_canary(record, message)
                self.assertEqual(record, want)

    def _cross_site_recorded(self, evidence: dict) -> list[str]:
        case = next(
            entry
            for entry in evidence["cases"]
            if entry["case_id"] == support.CHECKOUT_BRANCH_CASE_ID
        )
        return case["stages"]

    def _run_branch(self, stdout: str) -> dict:
        """Run one explicit native journey from ``stdout`` with no evidence file."""

        os.environ["LOCKLARK_E2E_CHECKOUT_NATIVE"] = "1"
        # Each branch model is its own journey: no earlier success is reused.
        support._CHECKOUT_JOURNEY_CACHE.clear()
        with mock.patch.object(
            support, "_invoke_checkout_journey", return_value=(0, stdout, "")
        ) as invoke:
            evidence = support.checkout_native_acceptance(self._ctx())
        self.assertEqual(invoke.call_count, 1)
        return evidence

    def test_each_cross_site_branch_is_recorded_as_the_one_that_ran(self):
        # The script emits exactly one branch marker; evidence records only
        # that marker plus the stages every run must prove.
        for branch in CROSS_SITE_BRANCHES:
            with self.subTest(branch=branch):
                evidence = self._run_branch(_pass_stdout(branch))
                self.assertEqual(
                    self._cross_site_recorded(evidence), _case_stages(branch)
                )
                other = next(
                    marker for marker in CROSS_SITE_BRANCHES if marker != branch
                )
                self.assertNotIn(
                    other,
                    [stage for case in evidence["cases"] for stage in case["stages"]],
                )
                for stage in (
                    "checkout-cross-site:navigation",
                    "checkout-cross-site:picker",
                    "checkout-cross-site:refused",
                ):
                    self.assertIn(stage, self._cross_site_recorded(evidence))
                # Every other case keeps its exact required stage list.
                for case_id, required in support.CHECKOUT_CASES:
                    if case_id == support.CHECKOUT_BRANCH_CASE_ID:
                        continue
                    recorded = next(
                        entry["stages"]
                        for entry in evidence["cases"]
                        if entry["case_id"] == case_id
                    )
                    self.assertEqual(recorded, list(required))

    def test_missing_common_refused_stage_fails_even_with_a_branch_marker(self):
        # A branch marker alone never stands in for the common completion.
        for branch in CROSS_SITE_BRANCHES:
            with self.subTest(branch=branch):
                output = _pass_stdout(branch).replace(
                    "Native browser stage: checkout-cross-site:refused\n", ""
                )
                os.environ["LOCKLARK_E2E_CHECKOUT_NATIVE"] = "1"
                with mock.patch.object(
                    support,
                    "_invoke_checkout_journey",
                    return_value=(0, output, "private diagnostic body"),
                ):
                    with self.assertRaises(AssertionError) as raised:
                        support.checkout_native_acceptance(self._ctx())
                message = str(raised.exception)
                self.assertIn(
                    "expected checkout stage(s): checkout-cross-site:refused",
                    message,
                )
                self.assertNotIn(branch, message)
                self.assertNotIn("private diagnostic body", message)

    def test_missing_cross_site_navigation_or_picker_fails(self):
        for stage_name in ("navigation", "picker"):
            stage = "checkout-cross-site:" + stage_name
            with self.subTest(stage=stage):
                output = _pass_stdout(CROSS_SITE_EXCLUDED).replace(
                    "Native browser stage: " + stage + "\n", ""
                )
                os.environ["LOCKLARK_E2E_CHECKOUT_NATIVE"] = "1"
                with mock.patch.object(
                    support,
                    "_invoke_checkout_journey",
                    return_value=(0, output, ""),
                ):
                    with self.assertRaises(AssertionError) as raised:
                        support.checkout_native_acceptance(self._ctx())
                self.assertIn(
                    "expected checkout stage(s): " + stage,
                    str(raised.exception),
                )

    def test_a_run_without_any_branch_marker_fails_and_claims_neither(self):
        stages = [
            stage for stage in _run_stages(CROSS_SITE_EXCLUDED)
            if stage not in CROSS_SITE_BRANCHES
        ]
        output = "\n".join(
            ["Native browser stage: " + stage for stage in stages]
            + [support.CHECKOUT_PASS_SUMMARY]
        ) + "\n"
        os.environ["LOCKLARK_E2E_CHECKOUT_NATIVE"] = "1"
        with mock.patch.object(
            support,
            "_invoke_checkout_journey",
            return_value=(0, output, ""),
        ):
            with self.assertRaises(AssertionError) as raised:
                support.checkout_native_acceptance(self._ctx())
        message = str(raised.exception)
        self.assertIn(
            "expected checkout stage(s): "
            + ", ".join(CROSS_SITE_BRANCHES),
            message,
        )

    def test_evidence_rejects_unknown_and_duplicate_stages(self):
        evidence = self._run_branch(_pass_stdout(CROSS_SITE_EXCLUDED))
        with self.subTest("unknown stage"):
            payload = json.loads(json.dumps(evidence))
            self._cross_site_recorded(payload).append(
                "checkout-cross-site:refused-again"
            )
            with self.assertRaisesRegex(AssertionError, "malformed"):
                support._checkout_evidence_structure(payload)
        with self.subTest("duplicate stage"):
            payload = json.loads(json.dumps(evidence))
            self._cross_site_recorded(payload).append(
                "checkout-cross-site:picker"
            )
            with self.assertRaisesRegex(AssertionError, "malformed"):
                support._checkout_evidence_structure(payload)

    def test_evidence_validates_stages_against_the_case_not_the_global_allowlist(
        self,
    ):
        # A branch marker is optional only for the case that owns it. Attaching
        # either cross-site marker to another case must be rejected as
        # malformed even though both markers are globally allowlisted, and even
        # when the borrowed marker would otherwise "fill in" a missing stage.
        evidence = self._run_branch(_pass_stdout(CROSS_SITE_NATIVE_REVIEW))
        approve_id = "checkout-approve"
        approve_required = next(
            stages for case, stages in support.CHECKOUT_CASES if case == approve_id
        )
        for marker in CROSS_SITE_BRANCHES:
            with self.subTest(marker=marker, mode="appended"):
                payload = json.loads(json.dumps(evidence))
                recorded = next(
                    entry["stages"]
                    for entry in payload["cases"]
                    if entry["case_id"] == approve_id
                )
                recorded.append(marker)
                with self.assertRaisesRegex(AssertionError, "malformed"):
                    support._checkout_evidence_structure(payload)
            with self.subTest(marker=marker, mode="replacing a required stage"):
                payload = json.loads(json.dumps(evidence))
                recorded = next(
                    entry["stages"]
                    for entry in payload["cases"]
                    if entry["case_id"] == approve_id
                )
                recorded.remove(approve_required[-1])
                recorded.append(marker)
                with self.assertRaisesRegex(AssertionError, "malformed"):
                    support._checkout_evidence_structure(payload)
        # The same markers remain accepted on their own case, so the rejection
        # is the per-case ownership, not a blanket refusal.
        for branch in CROSS_SITE_BRANCHES:
            with self.subTest(own_case=branch):
                support._checkout_evidence_structure(
                    self._run_branch(_pass_stdout(branch))
                )
        # Each case's allowlist is exactly its required stages plus its own
        # branch markers, never any other case's stages.
        for case_id, required in support.CHECKOUT_CASES:
            with self.subTest(case=case_id):
                allowed = support._checkout_allowed_stages(case_id)
                self.assertEqual(
                    allowed,
                    frozenset(required)
                    | frozenset(
                        marker
                        for marker in CROSS_SITE_BRANCHES
                        if case_id == support.CHECKOUT_BRANCH_CASE_ID
                    ),
                )

    def test_evidence_rejects_both_cross_site_branch_markers(self):
        evidence = self._run_branch(_pass_stdout(CROSS_SITE_NATIVE_REVIEW))
        payload = json.loads(json.dumps(evidence))
        self._cross_site_recorded(payload).append(CROSS_SITE_EXCLUDED)
        with self.assertRaisesRegex(AssertionError, "malformed"):
            support._checkout_evidence_structure(payload)
        with self.assertRaisesRegex(AssertionError, "malformed"):
            support._checkout_case_stages(
                support.CHECKOUT_BRANCH_CASE_ID, set(CROSS_SITE_BRANCHES)
            )

    def test_evidence_missing_the_common_or_baseline_stage_fails(self):
        evidence = self._run_branch(_pass_stdout(CROSS_SITE_EXCLUDED))
        for stage in (
            "checkout-cross-site:refused",
            "checkout-cross-site:navigation",
            "checkout-cross-site:picker",
        ):
            with self.subTest(stage=stage):
                payload = json.loads(json.dumps(evidence))
                stages = self._cross_site_recorded(payload)
                stages.remove(stage)
                with self.assertRaisesRegex(
                    AssertionError, "missing an expected checkout stage"
                ):
                    support._checkout_evidence_structure(payload)

    def test_evidence_without_a_branch_marker_is_never_filled_in(self):
        # The excluded run observed no native review. Removing its own marker
        # must leave the record branch-free: validation never fills in the
        # branch that was not observed, neither its own nor the other one.
        evidence = self._run_branch(_pass_stdout(CROSS_SITE_EXCLUDED))
        payload = json.loads(json.dumps(evidence))
        self._cross_site_recorded(payload).remove(CROSS_SITE_EXCLUDED)
        support._checkout_evidence_structure(payload)
        self.assertFalse(
            set(self._cross_site_recorded(payload)) & set(CROSS_SITE_BRANCHES)
        )

    def test_evidence_records_no_branch_when_none_was_observed(self):
        # Without observed output the case records its required stages only.
        cases = support._checkout_cases_evidence()
        recorded = next(
            entry["stages"]
            for entry in cases
            if entry["case_id"] == support.CHECKOUT_BRANCH_CASE_ID
        )
        self.assertEqual(
            recorded,
            [
                "checkout-cross-site:navigation",
                "checkout-cross-site:picker",
                "checkout-cross-site:refused",
            ],
        )
        for case_id, required in support.CHECKOUT_CASES:
            with self.subTest(case=case_id):
                self.assertEqual(
                    support._checkout_case_stages(case_id), list(required)
                )

    def test_cache_reuses_one_validated_journey(self):
        os.environ["LOCKLARK_E2E_CHECKOUT_NATIVE"] = "1"
        calls = 0

        def fake_invoke(command, *, env, cwd, timeout):
            nonlocal calls
            calls += 1
            return 0, _pass_stdout(CROSS_SITE_NATIVE_REVIEW), ""

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
            return_value=(0, _pass_stdout(CROSS_SITE_NATIVE_REVIEW), ""),
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
            return_value=(0, _pass_stdout(CROSS_SITE_NATIVE_REVIEW), ""),
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


REPORT = {"stage": "fixture", "reason": "unclassified acceptance failure",
          "native": None}
PRIVATE_DIRECTORY = "/tmp/lk-diagnostics-CANARY-9f3a1c"


class CheckoutFailureEvidenceEmissionTests(unittest.TestCase):
    """The captured failure lines survive a failure.json write error."""

    def _run(self, write: str) -> dict:
        """Execute the real emitter with an injected writeFile; no UI or app."""

        source = (ROOT / "scripts" / "browser_native_acceptance.mjs").read_text(
            encoding="utf-8"
        )
        start = source.index("function recordNativeFailure(")
        end = source.index("\n}\n", start) + 3
        # The writer is injected, so no real file, raw error text or canary
        # escapes; stderr is ignored and only the fixed stdout is read.
        script = "\n".join((
            'const { join } = require("node:path");',
            "const writes = new Map();",
            "const lines = [];",
            "console.error = (line) => lines.push(String(line));",
            source[start:end],
            f"const report = {json.dumps(REPORT)};",
            f"const directory = {json.dumps(PRIVATE_DIRECTORY)};",
            "let thrown = null;",
            "try { recordNativeFailure((...args) => {",
            "  writes.set(String(args[0]), "
            f"{json.dumps(write)} === 'ok' ? args : ['attempted']);",
            f"  if ({json.dumps(write)} === 'throw') "
            "throw new Error('EACCES');",
            "}, report, directory); } catch (error) { "
            "thrown = String(error?.message); }",
            "process.stdout.write(JSON.stringify("
            "{lines, writes: [...writes.values()], thrown}));",
        ))
        result = subprocess.run(
            ["node", "--input-type=commonjs", "-e", script],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr[-500:])
        # Harness self-check: both cases run the extraction the test assumes.
        self.assertIn("writeFile(join(diagnostics,", script)
        return json.loads(result.stdout)

    def test_one_report_and_private_write_are_emitted_on_success(self):
        result = self._run("ok")
        self.assertEqual(result["lines"], [
            "Native browser diagnostic: "
            + json.dumps(REPORT, separators=(",", ":")),
            "Synthetic diagnostic directory: " + PRIVATE_DIRECTORY,
        ])
        self.assertIsNone(result["thrown"])
        self.assertEqual(result["writes"], [[
            PRIVATE_DIRECTORY + "/failure.json",
            json.dumps(REPORT, indent=2) + "\n",
            {"mode": 0o600},
        ]])

    def test_report_survives_a_failure_json_write_error(self):
        result = self._run("throw")
        self.assertEqual(result["lines"], [
            "Native browser diagnostic: "
            + json.dumps(REPORT, separators=(",", ":")),
            "Synthetic diagnostic directory: " + PRIVATE_DIRECTORY,
        ])
        # The disk write was attempted once and its error never escapes the
        # emitter as a different failure.
        self.assertIsNone(result["thrown"])
        self.assertEqual(result["writes"], [["attempted"]])


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
