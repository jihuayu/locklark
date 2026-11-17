import ast
import collections
import contextlib
import io
import json
import pathlib
import re
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import browser_native_x11 as native
import desktop_native_acceptance as desktop
from desktop_native_acceptance import Acceptance, AcceptanceFailure


def _product_cancel_caption():
    root = pathlib.Path(__file__).resolve().parents[1]
    lines = (root / "internal/desktop/app.go").read_text(encoding="utf-8").splitlines()
    cancel = next((i for i, line in enumerate(lines) if "a.cancelAccountUnlock(attempt)" in line), None)
    if cancel is None:
        raise AssertionError("NATIVE_CANCEL_ACTION_MISSING")
    button = next((i for i in range(cancel, -1, -1) if "oneui.Button(c," in lines[i]), None)
    if button is None:
        raise AssertionError("NATIVE_CANCEL_BUTTON_MISSING")
    match = re.search(r'"(?:\\.|[^"\\])*"', lines[button])
    if match is None:
        raise AssertionError("NATIVE_CANCEL_CAPTION_MISSING")
    return ast.literal_eval(match.group(0))


class _App:
    def __init__(self, alive=True):
        self.pid = 501
        self.alive = alive

    def poll(self):
        return None if self.alive else 1


class _Ready:
    def __init__(self, child_count):
        self.child_count = child_count


class _Cancelled:
    def __init__(self, closed_count=2, parent_locked=True):
        self.closed_count = closed_count
        self.parent_locked = parent_locked


class _HeldClient:
    def __init__(self, ready_count=2, pending=False, cancelled=None):
        self.ready_count = ready_count
        self.pending = pending
        self.cancelled = cancelled or _Cancelled()
        self.calls = []

    def ready(self):
        self.calls.append("ready")
        return _Ready(self.ready_count)

    def has_pending_event(self):
        self.calls.append("pending")
        return self.pending

    def wait_cancelled_drained(self):
        self.calls.append("cancelled")
        return self.cancelled

    def release(self):
        self.calls.append("release")
        raise AssertionError("release must not be sent")

    def close(self):
        self.calls.append("close")


class _HeldSubject:
    def __init__(self, client=None, window_sequence=None, process_alive=True, pair_error=None):
        self.events = []
        self.host = pathlib.Path("/synthetic/tagged-desktop")
        self.app = _App(process_alive)
        self.native_fence_client = client or _HeldClient()
        self.reason = None
        self.case_coverage = None
        self.account_factor_submissions = 0
        self.target_factor_submissions = 0
        self.window_sequence = list(window_sequence or [77, 77, 77])
        self.pair_error = pair_error
        self.native_initial_tagged_host_is_distinct = Mock(return_value=True)

    def phase(self, value):
        self.events.append(("phase", value))

    def native_initial_window_identity(self):
        self.events.append(("window",))
        return self.app.pid, self.window_sequence.pop(0)

    def unlock_onevra_submit(self):
        self.account_factor_submissions += 1
        self.events.append(("submit", self.account_factor_submissions))

    def unlock_onevra_wait(self):
        self.events.append(("wait-unlocked",))

    def click(self, label):
        self.events.append(("click", label))

    def native_initial_require_locked_form(self, phase):
        self.events.append(("locked", phase))

    def native_initial_cancel_within_budget(self, ready_at):
        return Acceptance.native_initial_cancel_within_budget(self, ready_at)

    def native_initial_pair_evidence(self, account, target, phase):
        self.events.append(("evidence", account, target, phase))
        if self.pair_error is not None:
            raise self.pair_error
        return {"actualRefreshes": 3, "freshItemCount": 2, "accountLocked": True}


class _NoopClient:
    def close(self):
        pass


class _FakeAggregateCase:
    def __init__(self, code, coverage):
        self.code = code
        self.case_coverage = coverage
        self.state = None

    def run(self):
        return self.code


class _AggregateFactory:
    def __init__(self, plans):
        self.plans = list(plans)
        self.calls = []
        self.cases = []

    def __call__(self, *, scenario, host, native_fence_client, privacy):
        self.calls.append((scenario, host, native_fence_client is not None, privacy))
        code, coverage = self.plans[len(self.calls) - 1]
        case = _FakeAggregateCase(code, coverage)
        self.cases.append(case)
        return case


class PrepareInitialPairFixtureTests(unittest.TestCase):
    def test_producer_precedes_observer_and_private_metadata(self):
        with tempfile.TemporaryDirectory() as root:
            subject = Acceptance.__new__(Acceptance)
            subject.state = pathlib.Path(root)
            subject.fixture_binary = subject.state / "fixture"
            subject.fixture_path = subject.state / "vault" / "fixture.json"
            subject.fixture_path.parent.mkdir()
            subject.fixture_path.write_text(json.dumps({"Path": str(subject.state / "synthetic.ll")}))
            events = []

            def command(args):
                events.append(("producer", tuple(args)))
                return b""

            def observer():
                events.append(("observer", subject.fixture_path.exists(),
                                subject.settings_path.exists()))

            subject.command = command
            subject.verify_local_vault_pair = observer
            Acceptance.prepare_initial_pair_fixture(subject)

            self.assertEqual([event[0] for event in events], ["producer", "observer"])
            _, args = events[0]
            self.assertEqual(args[1], "-prepare-initial-pair")
            self.assertEqual(args[2], str(subject.fixture_path.parent))
            self.assertEqual(args[3], "-prepare-workspace")
            self.assertEqual(args[4], str(subject.settings_dir / "vaultfile-workspace"))
            self.assertEqual(events[1][1:], (True, True))
            self.assertEqual(subject.fixture["Path"], str(subject.state / "synthetic.ll"))
            self.assertEqual(subject.settings_path.stat().st_mode & 0o777, 0o600)


class SetupOrderTests(unittest.TestCase):
    def test_new_scenario_prepares_before_app_and_unlocks_onevra_once(self):
        with tempfile.TemporaryDirectory() as root:
            subject = Acceptance.__new__(Acceptance)
            subject.state = pathlib.Path(root)
            subject.fixture_binary = subject.state / "fixture"
            subject.fixture_path = subject.state / "vault" / "fixture.json"
            subject.settings_path = pathlib.Path("/tmp/settings.json")
            subject.host = pathlib.Path("/tmp/locklark-desktop")
            subject.log = (subject.state / "private.log").open("w")
            self.addCleanup(subject.log.close)
            subject.scenario = desktop.NATIVE_INITIAL_SCENARIO
            subject.values = set()
            subject.env = {}
            subject.fixture = collections.defaultdict(str)
            subject.build_fixture = Mock()
            subject.command = Mock()
            events = []

            def prepare():
                events.append("preseed")
                subject.fixture = collections.defaultdict(str)

            subject.prepare_initial_pair_fixture = prepare
            subject.unlock_onevra = Mock(side_effect=lambda: events.append("unlock-onevra"))
            subject.unlock = Mock()
            subject.probe_request = Mock()
            probe_stdout = io.StringIO('{"ready": true}\n')
            app = Mock(pid=101)
            probe = Mock(pid=102, stdout=probe_stdout)
            popen_calls = []

            def popen(*args, **kwargs):
                popen_calls.append((args, kwargs))
                events.append("popen")
                return app if len(popen_calls) == 1 else probe

            with patch.object(desktop.subprocess, "Popen", side_effect=popen), \
                    patch.object(desktop.select, "select", return_value=([probe.stdout], [], [])):
                Acceptance.setup(subject)

            self.assertLess(events.index("preseed"), events.index("popen"))
            self.assertEqual(subject.unlock_onevra.call_count, 1)
            subject.unlock.assert_not_called()
            subject.command.assert_not_called()
            subject.probe_request.assert_called_once()

    def test_tagged_scenario_preselects_before_app_and_stays_locked(self):
        with tempfile.TemporaryDirectory() as root:
            subject = Acceptance.__new__(Acceptance)
            subject.state = pathlib.Path(root)
            subject.fixture_binary = subject.state / "fixture"
            subject.fixture_path = subject.state / "vault" / "fixture.json"
            subject.settings_path = pathlib.Path("/tmp/settings.json")
            subject.host = pathlib.Path("/tmp/tagged-desktop")
            subject.log = (subject.state / "private.log").open("w")
            self.addCleanup(subject.log.close)
            subject.scenario = desktop.NATIVE_INITIAL_TAGGED_SCENARIO
            subject.values = set()
            subject.env = {}
            subject.fixture = collections.defaultdict(str)
            subject.build_fixture = Mock()
            subject.command = Mock()
            subject.phase = Mock()
            events = []

            def prepare():
                events.append("preseed")
                subject.fixture = collections.defaultdict(str)

            subject.prepare_initial_pair_fixture = prepare
            subject.unlock_onevra = Mock(side_effect=lambda: events.append("unlock-onevra"))
            subject.unlock = Mock()
            subject.probe_request = Mock()
            probe_stdout = io.StringIO('{"ready": true}\n')
            app = Mock(pid=201)
            probe = Mock(pid=202, stdout=probe_stdout)
            popen_calls = []

            def popen(*args, **kwargs):
                popen_calls.append((args, kwargs))
                events.append("popen")
                return app if len(popen_calls) == 1 else probe

            with patch.object(desktop.subprocess, "Popen", side_effect=popen), \
                    patch.object(desktop.select, "select", return_value=([probe.stdout], [], [])):
                Acceptance.setup(subject)

            self.assertLess(events.index("preseed"), events.index("popen"))
            subject.unlock_onevra.assert_not_called()
            subject.unlock.assert_not_called()
            subject.phase.assert_called_once_with("native-initial-held-locked")
            subject.command.assert_not_called()
            subject.probe_request.assert_called_once()

    def test_invalid_preseed_blocks_app_start(self):
        subject = Acceptance.__new__(Acceptance)
        subject.scenario = desktop.NATIVE_INITIAL_SCENARIO
        subject.build_fixture = Mock()
        subject.prepare_initial_pair_fixture = Mock(side_effect=AcceptanceFailure())
        with patch.object(desktop.subprocess, "Popen") as popen:
            with self.assertRaises(AcceptanceFailure):
                Acceptance.setup(subject)
        popen.assert_not_called()


class NativeInitialFanoutBasicTests(unittest.TestCase):
    class Subject:
        def __init__(self):
            self.events = []
            self.account_factor_submissions = 1
            self.target_factor_submissions = 0
            self.target_refreshes = 0
            self.actual_refresh_provenance = False
            self.last_refresh_item_count = 0
            self.local_labels = ["Alpha", "Beta"]
            self.local_a_index = 0
            self.local_b_index = 1
            self.a_locked = False
            self.a_locked_observed = False

        def phase(self, value):
            self.events.append(("phase", value))

        def native_initial_pair_evidence(self, *args):
            return Acceptance.native_initial_pair_evidence(self, *args)

        def record_prebuilt_local_pair(self):
            self.events.append(("record",))

        def observe(self):
            self.events.append(("observe",))
            return {"items": [{"id": "fixture-item"}], "audit_safe": True}

        def refresh_local_vault(self, labels, index, phase):
            self.events.append(("refresh", tuple(labels), index, phase))
            self.target_refreshes += 1
            self.actual_refresh_provenance = True
            self.last_refresh_item_count = 1

        def select_local_vault(self, labels, index, phase):
            self.events.append(("select", tuple(labels), index, phase))

        def wait(self, label):
            self.events.append(("wait", label))

        def click(self, label):
            self.events.append(("click", label))

        def final_local_vault_pair_validation(self, before_ids):
            self.events.append(("account-lock", tuple(before_ids)))

    def test_basic_flow_reads_both_locks_a_and_keeps_b_readable(self):
        subject = self.Subject()
        coverage = Acceptance.native_initial_account_fanout_basic(subject)
        self.assertEqual(coverage["accountSubmits"], 1)
        self.assertEqual(coverage["targetSubmits"], 0)
        self.assertGreaterEqual(coverage["actualRefreshes"], 2)
        self.assertGreater(coverage["freshItemCount"], 0)
        self.assertEqual(coverage["case"], desktop.NATIVE_INITIAL_BASIC_CASE)
        self.assertTrue(coverage["aLocked"])
        self.assertTrue(coverage["aLockedObserved"])
        self.assertTrue(coverage["accountLocked"])
        self.assertTrue(desktop.native_initial_basic_coverage_ok(coverage))
        self.assertEqual(subject.target_refreshes, 3)
        self.assertEqual(subject.events[0], ("record",))
        self.assertEqual(subject.events[1], ("observe",))
        self.assertEqual(subject.events[2][0:3], ("refresh", ("Alpha", "Beta"), 0))
        self.assertEqual(subject.events[3][0:3], ("refresh", ("Alpha", "Beta"), 1))
        lock_index = subject.events.index(("wait", "本地文件库已锁定"))
        self.assertIn(("click", "锁定本地文件库"), subject.events[:lock_index + 1])
        after_lock = subject.events.index(("refresh", ("Alpha", "Beta"), 1,
                                           "native-initial-refresh-b-after-lock"))
        self.assertGreater(after_lock, lock_index)
        self.assertIn(("wait", "解锁本地文件库"), subject.events)
        self.assertEqual(subject.events[-1], ("account-lock", ("fixture-item",)))
        self.assertNotIn(("click", "完整验证并解锁"), subject.events)
        self.assertFalse(any(event[0] == "fill" for event in subject.events))

    def test_basic_case_returns_basic_only_coverage_without_forced_failure(self):
        subject = Acceptance.__new__(Acceptance)
        subject.native_initial_account_fanout_basic = Mock(return_value={
            "case": desktop.NATIVE_INITIAL_BASIC_CASE,
            "accountSubmits": 1,
            "targetSubmits": 0,
            "actualRefreshes": 3,
            "freshItemCount": 2,
            "accountLocked": True,
        })
        subject.phase = Mock()
        subject.late_result_coverage = None
        subject.case_coverage = None
        Acceptance.native_initial_account_fanout(subject)
        self.assertEqual(subject.case_coverage["case"], desktop.NATIVE_INITIAL_BASIC_CASE)
        self.assertEqual(subject.late_result_coverage, "NOT_RUN_IN_BASIC_CASE")
        phases = [call.args[0] for call in subject.phase.call_args_list]
        self.assertEqual(phases, [
            "native-initial-counts account=1 target=0 refresh=3",
            "native-initial-basic-flow-complete",
        ])
        self.assertFalse(desktop.native_initial_held_coverage_ok(subject.case_coverage))

    def test_pair_evidence_requires_actual_refresh_and_nonempty_items(self):
        for field, value in (
                ("target_refreshes", 0),
                ("actual_refresh_provenance", False),
                ("last_refresh_item_count", 0)):
            with self.subTest(field=field):
                subject = self.Subject()
                subject.refresh_local_vault = Mock()
                setattr(subject, field, value)
                if field != "target_refreshes":
                    subject.target_refreshes = 2
                if field != "actual_refresh_provenance":
                    subject.actual_refresh_provenance = True
                if field != "last_refresh_item_count":
                    subject.last_refresh_item_count = 1
                with self.assertRaises(AcceptanceFailure):
                    Acceptance.native_initial_pair_evidence(
                        subject, 1, 0, "native-initial")


class DefaultCompatibilityTests(unittest.TestCase):
    def test_default_scenario_still_runs_the_old_flow(self):
        subject = Acceptance.__new__(Acceptance)
        subject.scenario = None
        subject.setup = Mock()
        subject.create = Mock(side_effect=[None, {"generated": True}])
        subject.password_delivery = Mock()
        subject.regenerate = Mock()
        subject.stale_regeneration = Mock()
        subject.click = Mock()
        subject.wait = Mock()
        subject.select = Mock()
        subject.phase = Mock()
        subject.controls = Mock(return_value=collections.defaultdict(
            lambda: {"present": False}))
        subject.provider_acceptance = Mock()
        subject.otp_acceptance = Mock()
        subject.foreign_lock_case = Mock()
        subject.local_vault_file_create = Mock()
        subject.native_initial_account_fanout = Mock()
        subject.close = Mock()
        subject.finish = Mock(return_value=0)
        with patch.dict(desktop.os.environ, {}, clear=True):
            self.assertEqual(Acceptance.run(subject), 0)
        subject.provider_acceptance.assert_called_once()
        subject.otp_acceptance.assert_called_once()
        subject.foreign_lock_case.assert_called_once()
        subject.local_vault_file_create.assert_not_called()
        subject.native_initial_account_fanout.assert_not_called()
        subject.finish.assert_called_once()


class PrivacyRegistryTests(unittest.TestCase):
    def test_prebuilt_pair_registers_both_manifest_guards(self):
        subject = Acceptance.__new__(Acceptance)
        subject.values = set()
        subject.local_manifest_private_values = {}
        with tempfile.TemporaryDirectory() as root:
            first = {
                "path": str(pathlib.Path(root) / "a.json"),
                "vault_id": "fixture-a",
                "name": "Alpha",
            }
            second = {
                "path": str(pathlib.Path(root) / "b.json"),
                "vault_id": "fixture-b",
                "name": "Beta",
            }
            subject.read_local_vault_manifests = Mock(return_value=[first, second])
            subject.local_vault_labels = Mock(return_value=["Alpha", "Beta"])
            with patch.object(desktop, "_local_manifest_guard", lambda manifest: ("guard",)):
                Acceptance.record_prebuilt_local_pair(subject)
            self.assertEqual(subject.local_manifests, [first, second])
            self.assertEqual(subject.local_labels, ["Alpha", "Beta"])
            self.assertEqual(subject.values, {
                "fixture-a", "Alpha", "fixture-b", "Beta",
            })
            self.assertEqual(set(subject.local_manifest_private_values), {
                pathlib.Path(first["path"]), pathlib.Path(second["path"]),
            })


class NativeInitialHeldCancelTests(unittest.TestCase):
    @staticmethod
    def held_coverage():
        return {
            "case": desktop.NATIVE_INITIAL_HELD_CANCEL_CASE,
            "initialAccountSubmits": 1,
            "retryAccountSubmits": 1,
            "totalAccountSubmits": 2,
            "targetSubmits": 0,
            "readyChildCount": 2,
            "cancelled": True,
            "drainedCount": 2,
            "parentLocked": True,
            "sameProcess": True,
            "sameWindow": True,
            "retryActualRefreshes": 3,
            "retryFreshItemCount": 2,
            "accountLocked": True,
        }

    def test_held_cancel_then_retry_uses_one_submit_each_without_release_or_eof(self):
        subject = _HeldSubject()
        with patch.object(desktop.time, "sleep") as sleep:
            Acceptance.native_initial_held_cancel(subject)
        self.assertEqual(subject.account_factor_submissions, 2)
        self.assertEqual(subject.target_factor_submissions, 0)
        self.assertEqual(subject.native_fence_client.calls, ["ready", "pending", "cancelled"])
        self.assertNotIn("release", subject.native_fence_client.calls)
        self.assertNotIn("close", subject.native_fence_client.calls)
        self.assertEqual(subject.events, [
            ("window",),
            ("submit", 1),
            ("click", "取消解锁"),
            ("window",),
            ("locked", "native-initial-held-cancelled"),
            ("phase", "native-initial-retry-submit"),
            ("submit", 2),
            ("wait-unlocked",),
            ("window",),
            ("evidence", 2, 0, "native-initial-retry"),
            ("phase", "native-initial-held-counts initial=1 retry=1 total=2 target=0"),
            ("phase", "native-initial-held-flow-complete"),
        ])
        self.assertEqual(subject.case_coverage, self.held_coverage())
        self.assertTrue(desktop.native_initial_held_coverage_ok(subject.case_coverage))
        self.assertIsNone(subject.reason)
        subject.native_initial_tagged_host_is_distinct.assert_called_once_with()
        sleep.assert_not_called()

    def test_held_coverage_rejects_each_missing_evidence_field(self):
        for field, value in (
                ("readyChildCount", 1),
                ("cancelled", False),
                ("drainedCount", 1),
                ("parentLocked", False),
                ("sameProcess", False),
                ("sameWindow", False),
                ("retryActualRefreshes", 1),
                ("retryFreshItemCount", 0),
                ("totalAccountSubmits", 1),
                ("targetSubmits", 1),
                ("accountLocked", False)):
            with self.subTest(field=field):
                coverage = self.held_coverage()
                coverage[field] = value
                self.assertFalse(desktop.native_initial_held_coverage_ok(coverage))

    def test_held_case_fails_closed_without_full_observed_evidence(self):
        configs = (
            {"window_sequence": [77, 78, 77]},
            {"process_alive": False},
            {"pair_error": AcceptanceFailure()},
        )
        for config in configs:
            with self.subTest(config=tuple(config)):
                with self.assertRaises(AcceptanceFailure):
                    Acceptance.native_initial_held_cancel(_HeldSubject(**config))

        with self.assertRaises(AcceptanceFailure):
            Acceptance.native_initial_held_cancel(
                _HeldSubject(client=_HeldClient(ready_count=1)))
        with self.assertRaises(AcceptanceFailure):
            Acceptance.native_initial_held_cancel(
                _HeldSubject(client=_HeldClient(pending=True)))
        with self.assertRaises(AcceptanceFailure):
            Acceptance.native_initial_held_cancel(
                _HeldSubject(client=_HeldClient(cancelled=_Cancelled(closed_count=1))))
        with self.assertRaises(AcceptanceFailure):
            Acceptance.native_initial_held_cancel(
                _HeldSubject(client=_HeldClient(cancelled=_Cancelled(parent_locked=False))))
        missing = _HeldSubject()
        missing.native_fence_client = None
        with self.assertRaises(AcceptanceFailure):
            Acceptance.native_initial_held_cancel(missing)

    def test_cancel_budget_is_fixed_and_not_renewed(self):
        subject = Acceptance.__new__(Acceptance)
        subject.click = Mock()
        subject.reason = None
        with patch.object(desktop.time, "monotonic", return_value=16.0), \
                patch.object(desktop.time, "sleep") as sleep:
            with self.assertRaises(AcceptanceFailure):
                Acceptance.native_initial_cancel_within_budget(subject, 10.0)
        self.assertEqual(subject.reason, "native-initial-cancel-timeout")
        caption = _product_cancel_caption()
        if desktop.NATIVE_INITIAL_CANCEL_LABEL != caption:
            self.fail("NATIVE_CANCEL_SELECTOR_MISMATCH")
        if caption not in native.CONTROL_LABELS or not native.control_label_allowed(caption):
            self.fail("NATIVE_CANCEL_LABEL_NOT_ALLOWLISTED")
        calls = subject.click.call_args_list
        if len(calls) != 1 or calls[0].args != (caption,):
            self.fail("NATIVE_CANCEL_CLICK_SELECTOR_MISMATCH")
        for variant in (caption + " ", " " + caption):
            if native.control_label_allowed(variant):
                self.fail("NATIVE_CANCEL_LABEL_FUZZY_MATCH")
        sleep.assert_not_called()


class NativeInitialHostSelectionTests(unittest.TestCase):
    def test_tagged_host_is_required_and_must_be_distinct(self):
        self.assertIsNone(desktop.native_initial_host_paths({}))
        self.assertIsNone(desktop.native_initial_host_paths({
            "LOCKLARK_DESKTOP_HOST": "/ordinary",
        }))
        self.assertIsNone(desktop.native_initial_host_paths({
            "LOCKLARK_DESKTOP_HOST": "/ordinary",
            "LOCKLARK_DESKTOP_FENCE_HOST": "/ordinary",
        }))
        self.assertEqual(desktop.native_initial_host_paths({
            "LOCKLARK_DESKTOP_HOST": "/ordinary",
            "LOCKLARK_DESKTOP_FENCE_HOST": "/tagged",
        }), ("/ordinary", "/tagged"))


class DefaultAggregateTests(unittest.TestCase):
    @staticmethod
    def basic_coverage():
        return {
            "case": desktop.NATIVE_INITIAL_BASIC_CASE,
            "accountSubmits": 1,
            "targetSubmits": 0,
            "actualRefreshes": 3,
            "freshItemCount": 2,
            "accountLocked": True,
        }

    @staticmethod
    def held_coverage():
        return NativeInitialHeldCancelTests.held_coverage()

    @staticmethod
    def environ():
        return {
            "LOCKLARK_DESKTOP_HOST": "/ordinary",
            "LOCKLARK_DESKTOP_FENCE_HOST": "/tagged",
            "LOCKLARK_DESKTOP_FIXTURE": "/fixture",
        }

    def run_aggregate(self, environ, plans):
        factory = _AggregateFactory(plans)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = desktop.run_default_aggregate(
                environ, acceptance_factory=factory,
                client_factory=lambda: _NoopClient())
        return code, output.getvalue(), factory

    def test_aggregate_runs_legacy_basic_and_tagged_once_in_order(self):
        code, output, factory = self.run_aggregate(
            self.environ(),
            [(0, None), (0, self.basic_coverage()), (0, self.held_coverage())])
        self.assertEqual(code, 0)
        self.assertEqual([call[0] for call in factory.calls], [
            None,
            desktop.NATIVE_INITIAL_SCENARIO,
            desktop.NATIVE_INITIAL_TAGGED_SCENARIO,
        ])
        self.assertEqual(factory.calls[0][1], "/ordinary")
        self.assertEqual(factory.calls[1][1], "/ordinary")
        self.assertEqual(factory.calls[2][1], "/tagged")
        self.assertFalse(factory.calls[0][2])
        self.assertFalse(factory.calls[1][2])
        self.assertTrue(factory.calls[2][2])
        self.assertIs(factory.calls[0][3], factory.calls[1][3])
        self.assertIs(factory.calls[1][3], factory.calls[2][3])
        self.assertIn("NATIVE_INITIAL_AGGREGATE PASS", output)
        self.assertIn(
            "NATIVE_INITIAL_COUNTS basic_account=1 held_initial=1 held_retry=1 held_total=2 target=0",
            output)

    def test_missing_or_same_tagged_host_fails_closed_without_ordinary_fallback(self):
        for tagged in (None, "/ordinary"):
            with self.subTest(tagged=tagged):
                environ = self.environ()
                if tagged is None:
                    environ.pop("LOCKLARK_DESKTOP_FENCE_HOST")
                else:
                    environ["LOCKLARK_DESKTOP_FENCE_HOST"] = tagged
                code, output, factory = self.run_aggregate(
                    environ, [(0, None), (0, self.basic_coverage())])
                self.assertEqual(code, 1)
                self.assertEqual(len(factory.calls), 2)
                self.assertNotIn(
                    desktop.NATIVE_INITIAL_TAGGED_SCENARIO,
                    [call[0] for call in factory.calls])
                self.assertIn("held_cancel=FAIL", output)
                self.assertIn("reason=HOST_UNAVAILABLE", output)
                self.assertNotIn("NATIVE_INITIAL_AGGREGATE PASS", output)

    def test_earlier_failure_does_not_skip_later_required_cases(self):
        code, output, factory = self.run_aggregate(
            self.environ(),
            [(1, None), (0, self.basic_coverage()), (0, self.held_coverage())])
        self.assertEqual(code, 1)
        self.assertEqual(len(factory.calls), 3)
        self.assertIn("reason=LEGACY_FAILED", output)

    def test_basic_or_held_coverage_shortfall_cannot_pass(self):
        invalid_basic = self.basic_coverage()
        invalid_basic["actualRefreshes"] = 1
        code, output, _ = self.run_aggregate(
            self.environ(),
            [(0, None), (0, invalid_basic), (0, self.held_coverage())])
        self.assertEqual(code, 1)
        self.assertIn("reason=BASIC_COVERAGE", output)

        invalid_held = self.held_coverage()
        invalid_held["readyChildCount"] = 1
        code, output, _ = self.run_aggregate(
            self.environ(),
            [(0, None), (0, self.basic_coverage()), (0, invalid_held)])
        self.assertEqual(code, 1)
        self.assertIn("reason=HELD_CANCEL_COVERAGE", output)

    def test_final_all_case_privacy_scan_can_withhold_aggregate_pass(self):
        with patch.object(
                desktop, "native_initial_privacy_scan",
                return_value="known-value"):
            code, output, _ = self.run_aggregate(
                self.environ(),
                [(0, None), (0, self.basic_coverage()), (0, self.held_coverage())])
        self.assertEqual(code, 1)
        self.assertIn("reason=PRIVACY", output)
        self.assertNotIn("NATIVE_INITIAL_AGGREGATE PASS", output)

    def test_missing_fixture_artifact_fails_before_cases(self):
        environ = self.environ()
        environ.pop("LOCKLARK_DESKTOP_FIXTURE")
        code, output, factory = self.run_aggregate(environ, [])
        self.assertEqual(code, 1)
        self.assertEqual(factory.calls, [])
        self.assertIn("reason=ARTIFACT_UNAVAILABLE", output)


class MainDispatchTests(unittest.TestCase):
    def test_default_main_requires_the_aggregate(self):
        with patch.dict(desktop.os.environ, {}, clear=True), \
                patch.object(desktop, "run_default_aggregate", return_value=0) as aggregate, \
                patch.object(desktop, "Acceptance") as acceptance:
            self.assertEqual(desktop.main(), 0)
            aggregate.assert_called_once_with()
            acceptance.assert_not_called()

    def test_explicit_scenario_main_keeps_single_acceptance(self):
        with patch.dict(
                desktop.os.environ,
                {"LOCKLARK_TEST_SCENARIO": "foreign-owner"},
                clear=True), patch.object(desktop, "Acceptance") as acceptance:
            acceptance.return_value.run.return_value = 0
            self.assertEqual(desktop.main(), 0)
            acceptance.assert_called_once_with()


class SharedPrivacyRegistryTests(unittest.TestCase):
    def test_registry_accumulates_two_fixture_pairs_without_reset(self):
        privacy = desktop.NativeInitialPrivacyRegistry()
        with tempfile.TemporaryDirectory() as root:
            for prefix in ("one", "two"):
                first = {
                    "path": str(pathlib.Path(root) / (prefix + "-a.json")),
                    "vault_id": prefix + "-a",
                    "name": prefix + "-Alpha",
                }
                second = {
                    "path": str(pathlib.Path(root) / (prefix + "-b.json")),
                    "vault_id": prefix + "-b",
                    "name": prefix + "-Beta",
                }
                subject = Acceptance.__new__(Acceptance)
                subject.values = privacy.values
                subject.local_manifest_private_values = privacy.local_manifest_private_values
                subject.read_local_vault_manifests = Mock(return_value=[first, second])
                subject.local_vault_labels = Mock(
                    return_value=[first["name"], second["name"]])
                with patch.object(
                        desktop, "_local_manifest_guard",
                        lambda manifest: ("guard", manifest["vault_id"])):
                    Acceptance.record_prebuilt_local_pair(subject)
                self.assertIs(
                    subject.local_manifest_private_values,
                    privacy.local_manifest_private_values)
        self.assertEqual(len(privacy.local_manifest_private_values), 4)
        self.assertEqual(privacy.values, {
            "one-a", "one-Alpha", "one-b", "one-Beta",
            "two-a", "two-Alpha", "two-b", "two-Beta",
        })

    def test_scan_exempts_only_the_exact_manifest_value_span(self):
        with tempfile.TemporaryDirectory() as root:
            subject = Acceptance.__new__(Acceptance)
            subject.state = pathlib.Path(root)
            subject.fixture_path = subject.state / ".no-fixture"
            subject.values = {"fixture-value"}
            subject.codes = set()
            manifest_path = subject.state / "manifest.json"
            data = b'{"name":"fixture-value"}'
            manifest_path.write_bytes(data)
            subject.local_manifest_private_values = {manifest_path: ("guard",)}
            subject.privacy_failure = None
            start = data.index(b"fixture-value")
            with patch.object(
                    desktop, "_stable_local_vault_manifest",
                    return_value=data), patch.object(
                    desktop, "_local_vault_manifest_spans",
                    return_value={(start, start + len("fixture-value"))}):
                self.assertGreaterEqual(subject.scan(), 1)
                self.assertIsNone(subject.privacy_failure)
            subject.privacy_failure = None
            with patch.object(
                    desktop, "_stable_local_vault_manifest",
                    return_value=data), patch.object(
                    desktop, "_local_vault_manifest_spans",
                    return_value=set()):
                with self.assertRaises(AcceptanceFailure):
                    subject.scan()
                self.assertEqual(subject.privacy_failure, "known-value")


if __name__ == "__main__":
    unittest.main()
