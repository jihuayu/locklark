"""Mock-only C4b driver contracts: profiles, target responses, pair schema, flow."""
import json
import os
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import Mock

import browser_native_x11 as x11
import desktop_native_acceptance as desktop


LABELS = ["alpha.llv · 01234567", "beta.llv · 012345671"]
PAIR_OK = {"manifest_count": 2, **{field: True for field in desktop.LOCAL_PROJECTION_FIELDS}}


def valid_select_click():
    return {
        "label": "pointer", "x": 1, "y": 2,
        "before": {"x": 1, "y": 2, "button_mask": 0, "pointer_available": True},
        "after": {"x": 1, "y": 2, "button_mask": 0, "pointer_available": True},
        "x_test": {"motion": True, "down": True, "up": True},
    }


def select_response(target_index):
    return {"action": "select-sidebar", "target_index": target_index,
            "clicks": [valid_select_click()]}


class ProfileAndLabelTests(unittest.TestCase):
    def setUp(self):
        self.private = tempfile.TemporaryDirectory()
        self.addCleanup(self.private.cleanup)
        self.root = pathlib.Path(self.private.name)
        self.profile = self.root / "profile"
        self.profile.mkdir(mode=0o700)

    def manifest(self, name, vault_id, filename=None, **overrides):
        record = {
            "version": 1, "kind": "vault_file_create", "vault_id": vault_id,
            "personal_file": str(self.root / "personal.ll"),
            "backend_root": str(self.root / "backend"),
            "name": name, "journal": str(self.root / ((filename or "a") + ".journal")),
            "archive": str(self.root / ((filename or "a") + ".llb")),
        }
        record.update(overrides)
        path = self.profile / ((filename or "a") + ".json")
        path.write_text(json.dumps(record), encoding="utf-8")
        return path

    def test_global_prefix_is_recomputed_for_both_entries(self):
        first = {"vault_id": "01234567000000000000000000000000", "name": "alpha.llv"}
        second = {"vault_id": "01234567111111111111111111111111", "name": "beta.llv"}
        before = desktop.local_vault_display_labels([first])
        after = desktop.local_vault_display_labels([first, second])
        self.assertEqual(before, ["alpha.llv · 01234567"])
        self.assertEqual(after, ["alpha.llv · 012345670", "beta.llv · 012345671"])
        for label in after:
            self.assertIsNotNone(x11.local_vault_display_label(label))

    def test_reads_expected_one_then_two_and_tracks_distinct_paths(self):
        first = self.manifest("alpha.llv", "01234567000000000000000000000000", "a")
        manifests = desktop.read_local_vault_manifests(self.profile)
        self.assertEqual(len(manifests), 1)
        self.assertEqual(manifests[0]["path"], str(first))
        second = self.manifest("beta.llv", "01234567111111111111111111111111", "b")
        manifests = desktop.read_local_vault_manifests(self.profile)
        self.assertEqual(len(manifests), 2)
        self.assertEqual({item["path"] for item in manifests}, {str(first), str(second)})
        self.assertEqual(len({item["vault_id"] for item in manifests}), 2)

    def test_symlink_oversize_malformed_and_extra_property_fail_closed(self):
        self.manifest("alpha.llv", "01234567000000000000000000000000", "a")
        link = self.profile / "link.json"
        link.symlink_to(self.profile / "a.json")
        with self.assertRaises(desktop.AcceptanceFailure):
            desktop.read_local_vault_manifests(self.profile)
        link.unlink()
        (self.profile / "big.json").write_bytes(b"{" + b" " * desktop.LOCAL_PROFILE_FILE_LIMIT)
        with self.assertRaises(desktop.AcceptanceFailure):
            desktop.read_local_vault_manifests(self.profile)
        (self.profile / "big.json").unlink()
        bad = self.profile / "bad.json"
        bad.write_text("{", encoding="utf-8")
        with self.assertRaises(desktop.AcceptanceFailure):
            desktop.read_local_vault_manifests(self.profile)
        bad.unlink()
        extra = self.profile / "extra.json"
        record = json.loads((self.profile / "a.json").read_text(encoding="utf-8"))
        record["extra"] = True
        extra.write_text(json.dumps(record), encoding="utf-8")
        with self.assertRaises(desktop.AcceptanceFailure):
            desktop.read_local_vault_manifests(self.profile)

    def test_b_filename_sort_first_routes_actual_ab_transport_labels(self):
        a_id = "01234567000000000000000000000000"
        b_id = "01234567111111111111111111111111"
        a_path = self.manifest("alpha.llv", a_id, "b")
        b_path = self.manifest("beta.llv", b_id, "a")
        manifests = desktop.read_local_vault_manifests(self.profile)
        self.assertEqual([manifest["path"] for manifest in manifests],
                         [str(b_path), str(a_path)])
        helper = desktop.local_vault_display_labels(manifests)
        subject = desktop.Acceptance.__new__(desktop.Acceptance)
        subject.values = set()
        subject.local_a_manifest = {"path": str(a_path), "name": "alpha.llv", "vault_id": a_id}
        subject.read_local_vault_manifests = lambda: manifests
        subject.record_local_vault_b()
        self.assertEqual((subject.local_a_index, subject.local_b_index), (0, 1))
        self.assertEqual(subject.local_labels, [helper[1], helper[0]])
        self.assertEqual(subject.local_a_label, helper[1])
        self.assertEqual(subject.local_b_label, helper[0])
        self.assertEqual(subject.local_a_manifest["path"], str(a_path))
        self.assertEqual(subject.local_b_manifest["path"], str(b_path))

        subject.host = pathlib.Path(os.path.realpath(sys.executable))
        subject.app = Mock(pid=4321)
        subject.command = Mock(side_effect=[
            json.dumps(select_response(0)).encode(),
            json.dumps(select_response(1)).encode(),
        ])
        subject.local_vault_target("select-sidebar", subject.local_labels, subject.local_a_index)
        subject.local_vault_target("select-sidebar", subject.local_labels, subject.local_b_index)
        first = json.loads(subject.command.call_args_list[0].args[1])
        second = json.loads(subject.command.call_args_list[1].args[1])
        for request, expected in ((first, helper[1]), (second, helper[0])):
            target = request["local_vault_target"]
            self.assertEqual(target["known_labels"][target["target_index"]], expected)

    def test_a_path_id_drift_refuses_without_transport(self):
        a_id = "01234567000000000000000000000000"
        b_id = "01234567111111111111111111111111"
        a_path = self.manifest("alpha.llv", a_id, "b")
        self.manifest("beta.llv", b_id, "a")
        subject = desktop.Acceptance.__new__(desktop.Acceptance)
        subject.values = set()
        subject.local_a_manifest = {"path": str(a_path), "name": "alpha.llv",
                                    "vault_id": "ffffffffffffffffffffffffffffffff"}
        subject.read_local_vault_manifests = lambda: desktop.read_local_vault_manifests(self.profile)
        subject.command = Mock()
        with self.assertRaises(desktop.AcceptanceFailure):
            subject.record_local_vault_b()
        self.assertFalse(subject.command.called)

    def test_entry_bound_duplicate_ids_and_invalid_names_refuse(self):
        for index in range(desktop.LOCAL_PROFILE_ENTRY_LIMIT + 1):
            (self.profile / ("entry-%03d" % index)).write_text("", encoding="utf-8")
        with self.assertRaises(desktop.AcceptanceFailure):
            desktop.read_local_vault_manifests(self.profile)
        duplicate = [
            {"vault_id": "01234567000000000000000000000000", "name": "a.llv"},
            {"vault_id": "01234567000000000000000000000000", "name": "b.llv"},
        ]
        with self.assertRaises(desktop.AcceptanceFailure):
            desktop.local_vault_display_labels(duplicate)
        with self.assertRaises(desktop.AcceptanceFailure):
            desktop.local_vault_display_labels([
                {"vault_id": "01234567000000000000000000000000", "name": ".hidden"}
            ])
        with self.assertRaises(desktop.AcceptanceFailure):
            desktop.local_vault_display_labels([
                {"vault_id": "01234567", "name": "a.llv"}
            ])


class TargetContractTests(unittest.TestCase):
    def test_strict_select_and_wait_responses(self):
        select = select_response(0)
        self.assertEqual(desktop.parse_local_vault_target_response("select-sidebar", 0, select), select)
        wait = {"action": "wait-title", "matched": True}
        self.assertEqual(desktop.parse_local_vault_target_response("wait-title", 1, wait), wait)
        for action, index, result in (
                ("select-sidebar", 0, {**select, "extra": True}),
                ("select-sidebar", True, select),
                ("wait-title", 0, {"action": "wait-title", "matched": 1}),
                ("wait-title", 0, {**wait, "extra": True})):
            with self.subTest(action=action):
                with self.assertRaises(desktop.AcceptanceFailure):
                    desktop.parse_local_vault_target_response(action, index, result)

    def test_recovery_mix_and_extra_target_field_refuse(self):
        base = {
            "title": x11.LOCAL_VAULT_TARGET_TITLE,
            "executable": os.path.realpath(sys.executable),
            "expected_pid": 1234,
            "local_vault_target": {
                "action": "select-sidebar",
                "known_labels": [LABELS[0]],
                "target_index": 0,
            },
        }
        mixed = {**base, "read_recovery": False}
        with self.assertRaises(RuntimeError):
            x11.parse_local_vault_target_request(mixed)
        extra = {**base, "local_vault_target": {
            **base["local_vault_target"], "extra": True}}
        with self.assertRaises(RuntimeError):
            x11.parse_local_vault_target_request(extra)

    def test_new_static_labels_are_in_the_closed_allowlists(self):
        for label in ("刷新本地文件库", "锁定本地文件库", "解锁本地文件库",
                      "解锁独立文件库", "完整验证并解锁"):
            self.assertIn(label, x11.CONTROL_LABELS)
        for label in ("解锁独立文件库", "显示上次验证结果", "本次刷新已验证",
                      "正在锁定本地文件库", "本地文件库已锁定",
                      "锁定未完成，请核查本地状态",
                      "本地文件库暂不可用，请稍后重试",
                      "完整验证失败；请重新输入"):
            self.assertIn(label, x11.LABEL_ROLE_STATUS_LABELS)

    def test_acceptance_target_request_uses_exact_pid_and_redacts_action(self):
        subject = desktop.Acceptance.__new__(desktop.Acceptance)
        subject.host = pathlib.Path(os.path.realpath(sys.executable))
        subject.app = Mock(pid=4321)
        subject.native_action = "none"
        subject.native_failed_index = None
        subject.native_x_error_codes = []
        subject.native_elapsed_ms = 0
        subject.last_native_click = {}
        subject.reason = "acceptance"
        subject.command = Mock(return_value=json.dumps(select_response(0)).encode())
        subject.local_vault_target("select-sidebar", LABELS, 0)
        request = json.loads(subject.command.call_args.args[1])
        self.assertEqual(request["expected_pid"], 4321)
        self.assertEqual(request["local_vault_target"]["known_labels"], LABELS)
        self.assertEqual(subject.native_action, "local-vault-select")
        self.assertNotIn(LABELS[0], subject.native_action)
        self.assertEqual(subject.last_native_click.get("label"), "pointer")

        subject.command = Mock(return_value=json.dumps({
            "action": "wait-title", "matched": True, "extra": True,
        }).encode())
        with self.assertRaises(desktop.AcceptanceFailure):
            subject.local_vault_target("wait-title", LABELS, 0)
        self.assertEqual(subject.reason, "native-response-schema")


class ClosedResponsePrivacyTests(unittest.TestCase):
    @staticmethod
    def target_subject(payload):
        subject = desktop.Acceptance.__new__(desktop.Acceptance)
        subject.host = pathlib.Path(os.path.realpath(sys.executable))
        subject.app = Mock(pid=4321)
        subject.native_action = "none"
        subject.native_failed_index = None
        subject.native_x_error_codes = []
        subject.native_elapsed_ms = 0
        subject.last_native_click = {"label": "sentinel"}
        subject.reason = "acceptance"
        subject.command = Mock(return_value=json.dumps(payload).encode())
        return subject

    def test_current_emitter_positive_and_safe_projection(self):
        source = {
            "x": 9, "y": 10,
            "before": {"x": 9, "y": 10, "button_mask": 0, "pointer_available": True},
            "after": {"x": 9, "y": 10, "button_mask": 0, "pointer_available": True},
            "x_test": {"motion": True, "down": True, "up": True},
            "label": "private", "target": "0xdeadbeef", "focus": "0xdead",
        }
        emitted = x11.local_vault_select_output(0, source)
        parsed = desktop.parse_local_vault_target_response("select-sidebar", 0, emitted)
        self.assertTrue(parsed == emitted)
        subject = self.target_subject(emitted)
        subject.local_vault_target("select-sidebar", LABELS, 0)
        click = subject.last_native_click
        self.assertEqual(click.get("label"), "pointer")
        self.assertEqual(set(click), {"label", "x", "y", "before", "after", "x_test"})
        self.assertTrue("target" not in click)
        for phase in ("before", "after"):
            self.assertTrue("focus" not in click[phase])

    def test_closed_unknown_target_and_focus_fields_reject_before_projection(self):
        base = select_response(0)
        cases = {}
        for name, path in (
                ("click-target", ("clicks", 0, "target")),
                ("before-focus", ("clicks", 0, "before", "focus")),
                ("after-focus", ("clicks", 0, "after", "focus")),
                ("click-unknown", ("clicks", 0, "extra")),
                ("pointer-unknown", ("clicks", 0, "before", "extra")),
                ("x-test-unknown", ("clicks", 0, "x_test", "extra")),
                ("dynamic-label", ("clicks", 0, "label")),
                ("before-missing", ("clicks", 0, "before", "x"))):
            result = json.loads(json.dumps(base))
            cursor = result
            for key in path[:-1]:
                cursor = cursor[key]
            cursor[path[-1]] = LABELS[0] if name == "dynamic-label" else "0xdeadbeef"
            if name == "before-missing":
                del result["clicks"][0]["before"]["x"]
            cases[name] = result
        for name, result in cases.items():
            with self.subTest(name=name):
                with self.assertRaises(desktop.AcceptanceFailure):
                    desktop.parse_local_vault_target_response("select-sidebar", 0, result)

        malicious = json.loads(json.dumps(base))
        malicious["clicks"][0]["target"] = "0xdeadbeef"
        malicious["clicks"][0]["before"]["focus"] = "0xdeadbeef"
        subject = self.target_subject(malicious)
        with self.assertRaises(desktop.AcceptanceFailure):
            subject.local_vault_target("select-sidebar", LABELS, 0)
        self.assertTrue(subject.last_native_click == {"label": "sentinel"})
        serialized = json.dumps(subject.last_native_click)
        self.assertTrue("0xdeadbeef" not in serialized)
        self.assertTrue("focus" not in serialized)
        self.assertEqual(subject.reason, "native-response-schema")

    def test_int_bool_confusion_and_false_x_test_reject(self):
        cases = []
        for name, path, value in (
                ("click-x-bool", ("clicks", 0, "x"), True),
                ("click-y-bool", ("clicks", 0, "y"), False),
                ("before-x-bool", ("clicks", 0, "before", "x"), True),
                ("pointer-int", ("clicks", 0, "before", "pointer_available"), 1),
                ("motion-int", ("clicks", 0, "x_test", "motion"), 1),
                ("motion-false", ("clicks", 0, "x_test", "motion"), False),
                ("down-false", ("clicks", 0, "x_test", "down"), False),
                ("up-false", ("clicks", 0, "x_test", "up"), False)):
            result = json.loads(json.dumps(select_response(0)))
            cursor = result
            for key in path[:-1]:
                cursor = cursor[key]
            cursor[path[-1]] = value
            cases.append((name, result))
        for name, result in cases:
            with self.subTest(name=name):
                with self.assertRaises(desktop.AcceptanceFailure):
                    desktop.parse_local_vault_target_response("select-sidebar", 0, result)


class PairProjectionTests(unittest.TestCase):
    def test_exact_two_and_nine_booleans(self):
        self.assertEqual(desktop.parse_local_vault_pair_projection(PAIR_OK), PAIR_OK)
        for changed in (
                {**PAIR_OK, "manifest_count": 1},
                {**PAIR_OK, "manifest_count": True},
                {**PAIR_OK, desktop.LOCAL_PROJECTION_FIELDS[0]: 1},
                {**PAIR_OK, "extra": True},
                {key: value for key, value in PAIR_OK.items()
                 if key != desktop.LOCAL_PROJECTION_FIELDS[-1]}):
            with self.subTest(changed=changed):
                with self.assertRaises(desktop.AcceptanceFailure):
                    desktop.parse_local_vault_pair_projection(changed)


class PrivacyRegistrationTests(unittest.TestCase):
    def test_dynamic_ids_and_labels_are_registered_and_scanned(self):
        with tempfile.TemporaryDirectory() as private:
            root = pathlib.Path(private)
            subject = desktop.Acceptance.__new__(desktop.Acceptance)
            subject.state = root
            subject.fixture_path = root / "fixture.json"
            subject.values = set()
            subject.codes = set()
            manifests = [
                {"path": str(root / "a.json"), "name": "alpha.llv",
                 "vault_id": "01234567000000000000000000000000"},
                {"path": str(root / "b.json"), "name": "beta.llv",
                 "vault_id": "01234567111111111111111111111111"},
            ]
            subject.local_a_manifest = manifests[0]
            subject.read_local_vault_manifests = lambda: manifests
            subject.record_local_vault_b()
            for manifest in manifests:
                self.assertIn(manifest["vault_id"], subject.values)
                self.assertIn(manifest["name"], subject.values)
                self.assertNotIn(manifest["path"], subject.values)
                pathlib.Path(manifest["path"]).write_text(
                    json.dumps({"vault_id": manifest["vault_id"], "name": manifest["name"]}),
                    encoding="utf-8")
            self.assertIn(subject.local_a_label, subject.values)
            self.assertIn(subject.local_b_label, subject.values)
            self.assertEqual(subject.scan(), 2)
            (root / "leak.log").write_text(subject.local_b_label, encoding="utf-8")
            with self.assertRaises(desktop.AcceptanceFailure):
                subject.scan()


class FlowFake:
    def __init__(self):
        self.fixture = {"Password": "synthetic-master", "Secret": "LL1-" + "A" * 26}
        self.calls = []
        self.values = set()
        self.local_kit_a = None
        self.local_labels = LABELS
        self.local_a_index, self.local_b_index = 0, 1
        self.wrong_confirms = 0
        self.wrong_confirm_at = None
        self.publish_at = None
        self.failure_seen = False
        self.wrong_password_filled = False
        self.wrong_secret_filled = False
        self.correct_after_failure = False

    def phase(self, value):
        self.calls.append(("phase", value))

    def observe(self):
        return {"audit_safe": True, "items": [{"id": "a"}, {"id": "b"}]}

    def wait(self, label):
        if label == "完整验证失败；请重新输入":
            self.failure_seen = True
        self.calls.append(("wait", label))

    def click(self, label):
        if label == "确认并发布备份":
            self.publish_at = len(self.calls)
        self.calls.append(("click", label))

    def fill(self, label, value):
        if label == "重新输入恢复码" and value == desktop.WRONG_RECOVERY_CONFIRMATION:
            self.wrong_confirms += 1
            self.wrong_confirm_at = len(self.calls)
        if label == "主密码" and value != self.fixture["Password"]:
            self.wrong_password_filled = True
        if label == "Secret Key" and value != self.fixture["Secret"]:
            self.wrong_secret_filled = True
        if self.failure_seen and label == "主密码" and value == self.fixture["Password"]:
            self.correct_after_failure = True
        self.calls.append(("fill", label))

    def read_recovery(self):
        self.calls.append(("read",))
        return "KIT-A" if self.local_kit_a is None else "KIT-B"

    def controls(self):
        return {"备份恢复码": {"present": False},
                "关闭本地基线视图": {"present": True},
                "解锁独立文件库": {"present": False}}

    def record_local_vault_a(self):
        self.calls.append(("record-a",))

    def record_local_vault_b(self):
        self.calls.append(("record-b",))

    def verify_local_vault(self):
        self.calls.append(("verify-a",))

    def create_local_vault_b(self):
        self.calls.append(("create-b",))

    def local_vault_pair_flow(self):
        self.calls.append(("pair-flow",))

    def final_local_vault_pair_validation(self, before_ids):
        self.calls.append(("final", tuple(before_ids)))

    def select_local_vault(self, labels, index, phase):
        self.calls.append(("select", phase, index))

    def refresh_local_vault(self, labels, index, phase):
        self.calls.append(("refresh", phase, index))

    def local_vault_target(self, action, labels, index):
        self.calls.append(("target", action, index))

    def eventually(self, check, timeout=10):
        self.calls.append(("eventually",))
        if not check():
            raise desktop.AcceptanceFailure()


class FlowOrchestrationTests(unittest.TestCase):
    def test_original_a_wrong_confirm_then_b_and_pair_flow(self):
        subject = FlowFake()
        desktop.Acceptance.local_vault_file_create(subject)
        self.assertIn(("fill", "重新输入恢复码"), subject.calls)
        self.assertEqual(subject.wrong_confirms, 1)
        self.assertIsNotNone(subject.wrong_confirm_at)
        self.assertIsNotNone(subject.publish_at)
        self.assertLess(subject.wrong_confirm_at, subject.publish_at)
        self.assertTrue(any(call == ("click", "确认并发布备份") for call in subject.calls))
        self.assertIn(("record-a",), subject.calls)
        self.assertIn(("create-b",), subject.calls)
        self.assertIn(("pair-flow",), subject.calls)
        self.assertIn(("final", ("a", "b")), subject.calls)
        self.assertLess(subject.calls.index(("record-a",)), subject.calls.index(("create-b",)))
        self.assertLess(subject.calls.index(("create-b",)), subject.calls.index(("pair-flow",)))

    def test_b_creation_reads_fresh_kit_before_confirm_publish(self):
        subject = FlowFake()
        subject.local_kit_a = "KIT-A"
        desktop.Acceptance.create_local_vault_b(subject)
        self.assertIn(("read",), subject.calls)
        self.assertIn(("wait", "重新输入恢复码"), subject.calls)
        self.assertLess(subject.calls.index(("read",)),
                        subject.calls.index(("wait", "备份恢复码")))
        self.assertIn(("wait", "关闭本地基线视图"), subject.calls)

    def test_pair_flow_locks_unlocks_wrong_then_correct_and_navigates_cached(self):
        subject = FlowFake()
        desktop.Acceptance.local_vault_pair_flow(subject)
        self.assertIn(("click", "锁定本地文件库"), subject.calls)
        self.assertIn(("wait", "本地文件库已锁定"), subject.calls)
        self.assertIn(("click", "解锁本地文件库"), subject.calls)
        self.assertIn(("wait", "解锁独立文件库"), subject.calls)
        self.assertIn(("click", "完整验证并解锁"), subject.calls)
        self.assertIn(("wait", "完整验证失败；请重新输入"), subject.calls)
        self.assertIn(("target", "wait-title", 0), subject.calls)
        self.assertIn(("click", "关闭本地基线视图"), subject.calls)
        self.assertIn(("select", "local-pair-navigate-back-a", 0), subject.calls)
        self.assertIn(("wait", "显示上次验证结果"), subject.calls)
        self.assertIn(("eventually",), subject.calls)
        self.assertLess(subject.calls.index(("eventually",)),
                        subject.calls.index(("target", "wait-title", 0)))
        self.assertTrue(subject.wrong_password_filled)
        self.assertTrue(subject.wrong_secret_filled)
        self.assertTrue(subject.correct_after_failure)
        self.assertTrue(subject.values)
        self.assertNotIn("synthetic-master", subject.values)


class FinalValidationFake:
    def __init__(self):
        self.calls = []

    def phase(self, value):
        self.calls.append(("phase", value))

    def verify_local_vault_pair(self):
        self.calls.append(("pair",))

    def observe(self):
        self.calls.append(("observe",))
        return {"audit_safe": True, "items": [{"id": "a"}, {"id": "b"}]}

    def click(self, label):
        self.calls.append(("click", label))

    def wait(self, label):
        self.calls.append(("wait", label))

    def controls(self):
        self.calls.append(("controls",))
        return {
            "使用应急资料…": {"present": True},
            "刷新本地文件库": {"present": False},
            "锁定本地文件库": {"present": False},
            "解锁本地文件库": {"present": False},
            "关闭本地基线视图": {"present": False},
        }


class FinalValidationTests(unittest.TestCase):
    def test_pair_observer_once_then_account_lock_hides_child_controls(self):
        subject = FinalValidationFake()
        desktop.Acceptance.final_local_vault_pair_validation(subject, ["a", "b"])
        self.assertEqual(subject.calls.count(("pair",)), 1)
        self.assertLess(subject.calls.index(("pair",)), subject.calls.index(("observe",)))
        self.assertLess(subject.calls.index(("observe",)),
                        subject.calls.index(("click", "立即锁定")))
        self.assertLess(subject.calls.index(("click", "立即锁定")),
                        subject.calls.index(("wait", "使用应急资料…")))
        self.assertIn(("controls",), subject.calls)


if __name__ == "__main__":
    unittest.main()
