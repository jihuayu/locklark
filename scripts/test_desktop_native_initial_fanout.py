import collections
import io
import json
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import desktop_native_acceptance as desktop
from desktop_native_acceptance import Acceptance, AcceptanceFailure


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
            self.local_labels = ["Alpha", "Beta"]
            self.local_a_index = 0
            self.local_b_index = 1
            self.a_locked = False
            self.a_locked_observed = False

        def phase(self, value):
            self.events.append(("phase", value))

        def record_prebuilt_local_pair(self):
            self.events.append(("record",))

        def observe(self):
            self.events.append(("observe",))
            return {"items": [{"id": "fixture-item"}], "audit_safe": True}

        def refresh_local_vault(self, labels, index, phase):
            self.events.append(("refresh", tuple(labels), index, phase))
            self.target_refreshes += 1
            self.actual_refresh_provenance = True

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
        self.assertTrue(coverage["aLocked"])
        self.assertTrue(coverage["aLockedObserved"])
        self.assertTrue(coverage["accountLocked"])
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

    def test_basic_flow_cannot_promote_late_unproven_to_success(self):
        subject = Acceptance.__new__(Acceptance)
        subject.native_initial_account_fanout_basic = Mock(return_value={
            "accountSubmits": 1,
            "targetSubmits": 0,
            "actualRefreshes": 3,
        })
        subject.phase = Mock()
        subject.late_result_coverage = None
        subject.reason = None
        with self.assertRaises(AcceptanceFailure):
            Acceptance.native_initial_account_fanout(subject)
        self.assertEqual(subject.late_result_coverage, "NOT_RUN_UNPROVEN")
        self.assertEqual(subject.reason, "LATE_RESULT_NOT_RUN")
        phases = [call.args[0] for call in subject.phase.call_args_list]
        self.assertEqual(phases, [
            "native-initial-counts account=1 target=0 refresh=3",
            "native-initial-basic-flow-complete",
            "native-initial-late-not-run",
        ])


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


if __name__ == "__main__":
    unittest.main()
