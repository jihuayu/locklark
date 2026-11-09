"""Pure argument, privacy and real-controlling-terminal fixture tests.

No X server, desktop App, broker or product process is started here. The
fixture tests do start real private pseudo terminals and real child processes:
that is the whole point of ``scripts/cli_lease_terminal_fixture`` and it needs
no display, no vault and no GUI. Everything else exercises fixed vocabulary,
argv shape, report shape, canary scanning, intent accounting and public output.
"""
import contextlib
import inspect
import io
import json
import os
import pathlib
import re
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import cli_desktop_acceptance as acceptance
import browser_native_x11 as native
from cli_lease_terminal_fixture import FixtureError, TerminalSession
from cli_lease_terminal_fixture import terminal_session as terminal_module


SECRET = "SyntheticOrdinaryLoginValue-" + "a" * 40
PRODUCT_BROKER = pathlib.Path(acceptance.__file__).resolve().parents[1] / "internal" / "desktop" / "ipc_broker.go"


class LabelTests(unittest.TestCase):
    def test_exactly_the_two_cli_labels_are_native_allowlisted(self):
        for label in (acceptance.APPROVE_LABEL, acceptance.REFUSE_LABEL):
            self.assertEqual(native.CONTROL_LABELS.count(label), 1)
        self.assertEqual(acceptance.APPROVE_LABEL, "仅批准本次 CLI 请求")
        self.assertEqual(acceptance.REFUSE_LABEL, "拒绝本次请求")

    def test_lease_label_is_allowlisted_once_and_matches_the_product_source(self):
        self.assertEqual(native.CONTROL_LABELS.count(acceptance.LEASE_LABEL), 1)
        self.assertEqual(acceptance.LEASE_LABEL, "批准此终端相同命令 5 分钟")
        if PRODUCT_BROKER.is_file():
            source = PRODUCT_BROKER.read_text(encoding="utf-8")
            self.assertIn('cliV2LeaseLabel   = "' + acceptance.LEASE_LABEL + '"', source)
        self.assertEqual(acceptance.LOCK_LABEL, "立即锁定")
        self.assertIn(acceptance.LOCK_LABEL, native.CONTROL_LABELS)
        self.assertEqual(acceptance.DIALOG_LABELS,
                         (acceptance.APPROVE_LABEL, acceptance.LEASE_LABEL, acceptance.REFUSE_LABEL))

    def test_unlock_waits_for_the_modern_unlocked_label(self):
        subject = object.__new__(acceptance.Acceptance)
        subject.fixture = {"Path": "/private/synthetic.ll", "Password": "synthetic", "Secret": "synthetic"}
        subject.input = mock.Mock()
        subject.emit = mock.Mock()
        acceptance.Acceptance.unlock(subject)
        actions = subject.input.call_args.args[0]
        self.assertEqual(actions[-1], {"wait_label": "立即锁定"})
        self.assertNotIn("新建登录", json.dumps(actions, ensure_ascii=False))
        self.assertEqual(subject.stage, "unlock")

    def test_every_phase_literal_is_in_the_fixed_public_vocabulary(self):
        source = pathlib.Path(acceptance.__file__).read_text()
        literals = re.findall(r'self\.phase\("([a-z-]+)"\)', source)
        self.assertTrue(literals)
        for value in literals:
            self.assertIn(value, acceptance.STAGES)

    def test_unknown_phase_never_echoes_its_argument(self):
        subject = object.__new__(acceptance.Acceptance)
        emitted = []
        subject.emit = emitted.append
        acceptance.Acceptance.phase(subject, SECRET + " /private/command --flag")
        self.assertEqual(subject.stage, "internal")
        self.assertEqual(emitted, ["CLI desktop native stage: internal"])
        self.assertNotIn(SECRET, "".join(emitted))


class ArgumentShapeTests(unittest.TestCase):
    def test_run_arguments_use_the_real_launcher_and_no_secret(self):
        arguments = acceptance.cli_run_arguments("/private/run-cli-fixture", "/private/locklark",
                                                 "/dev/pts/7", "/private/binding.json",
                                                 "/private/approve.json")
        self.assertEqual(arguments[1], "ctty")
        self.assertEqual(arguments[2], "/dev/pts/7")
        self.assertEqual(arguments[3], "/private/locklark")
        self.assertEqual(arguments[4:7], ["cli", "run", "openai"])
        self.assertIn("--binding", arguments)
        self.assertEqual(arguments[-3:], ["--", "/private/approve.json", "openai"])
        self.assertNotIn(SECRET, arguments)

    def test_init_arguments_pin_exact_item_and_revision(self):
        item, revision = "0123456789abcdef0123456789abcdef", "f" * 64
        arguments = acceptance.cli_init_arguments("/private/locklark", "/private/vault.ll",
                                                  "/private/child", "/private/binding.json",
                                                  item, revision)
        self.assertEqual(arguments[1:4], ["cli", "init", "openai"])
        self.assertIn("--profile", arguments)
        self.assertEqual(arguments[arguments.index("--profile") + 1], "openai")
        self.assertEqual(arguments[arguments.index("--id") + 1], item)
        self.assertEqual(arguments[arguments.index("--revision") + 1], revision)
        self.assertNotIn(SECRET, arguments)

    def test_lease_command_is_exactly_the_command_the_ctty_launcher_execs(self):
        wrapped = acceptance.cli_run_arguments("/private/run-cli-fixture", "/private/locklark",
                                               "/dev/pts/7", "/private/binding.json", "/private/lease.json")
        command = acceptance.lease_command("/private/locklark", "/private/binding.json", "/private/lease.json")
        # Same ordinary CLI executable, binding, tool and child argv: the only
        # difference is that the persistent fixture already owns the terminal.
        self.assertEqual(command, wrapped[3:])
        self.assertEqual(command[0], "/private/locklark")
        self.assertEqual(command[1:3], ["cli", "run"])
        self.assertNotIn(SECRET, command)
        for part in command:
            self.assertNotIn("LOCKLARK_", part)
            self.assertIsNone(re.search(r"[;&|><`$]", part))

    def test_validated_lease_command_accepts_only_the_owned_cli_argv(self):
        cli, binding, report = "/private/locklark", "/private/binding.json", "/private/lease.json"
        good = acceptance.lease_command(cli, binding, report)
        self.assertEqual(acceptance.validate_lease_command(good, cli, binding, report), good)
        bad_commands = [
            acceptance.lease_command("/usr/bin/other", binding, report),
            acceptance.lease_command(cli, binding, "/private/other.json"),
            good + ["extra"],
            good[:6] + [good[6]] + good[6:],
            [cli, "cli", "init"] + good[3:],
            good[:7] + [report + "\n--bad", good[8]],
            [cli + "$(id)", "cli", "run", acceptance.TOOL, "--binding", binding, "--", report, acceptance.TOOL],
        ]
        for bad in bad_commands:
            with self.subTest(bad=bad[:4]):
                with self.assertRaises(acceptance.AcceptanceFailure):
                    acceptance.validate_lease_command(bad, cli, binding, report)
        for bad in ([], "cli run openai", [None], [cli, "cli", "run", acceptance.TOOL, "--binding", binding, "--", "", acceptance.TOOL]):
            with self.subTest(bad=bad):
                with self.assertRaises(acceptance.AcceptanceFailure):
                    acceptance.validate_lease_command(bad, cli, binding, report)


class ReportTests(unittest.TestCase):
    def report(self, digests, tool="openai", ok=True):
        return json.dumps({"tool": tool, "ok": ok, "env_sha256": digests}).encode()

    def test_exact_env_hash_matches(self):
        digest = "b" * 64
        self.assertTrue(acceptance.child_report_matches(self.report({"OPENAI_API_KEY": digest}),
                                                        "openai", digest))

    def test_wrong_hash_tool_state_or_shape_is_refused(self):
        digest = "b" * 64
        for raw in (
            self.report({"OPENAI_API_KEY": "c" * 64}),
            self.report({"OPENAI_API_KEY": digest}, tool="gh"),
            self.report({"OPENAI_API_KEY": digest}, ok=False),
            self.report({"OTHER": digest}),
            json.dumps([digest]).encode(),
            b"not-json " + SECRET.encode(),
            b"",
        ):
            with self.subTest(raw=raw[:12]):
                self.assertFalse(acceptance.child_report_matches(raw, "openai", digest))


class FactorPromptTests(unittest.TestCase):
    def test_local_factor_prompts_are_recognised(self):
        for raw in ("主密码", "Secret Key", "输入 RUN 确认本次可信命令披露",
                    "将以下一次性凭据交给本次可信本地程序。"):
            self.assertTrue(acceptance.factor_prompt_present(raw), raw)
            self.assertTrue(acceptance.factor_prompt_present(raw.encode()))

    def test_clean_broker_stream_is_not_a_prompt(self):
        self.assertFalse(acceptance.factor_prompt_present(b""))
        self.assertFalse(acceptance.factor_prompt_present(b"locklark: refused\n"))
        self.assertFalse(acceptance.factor_prompt_present("fixture help output\n"))


class _FakeRun:
    """Small stand-in for a fixture TerminalRun in pure controller tests."""

    def __init__(self, pid=4242, codes=(0,), terminal=b"", stdout=b"", stderr=b"",
                 live=True, exe="/private/locklark", argv=None):
        self.pid = pid
        self.identity = {"pid": pid, "session": 4200, "tty_nr": 34816,
                         "exe": exe, "live_exe": live,
                         "tty_path": "/dev/pts/9", "cwd": "/private/work"}
        self.argv = tuple(argv) if argv is not None else None
        self._codes = list(codes)
        self._terminal, self._stdout, self._stderr = terminal, stdout, stderr
        self.drained = False

    def captured_terminal(self):
        return self._terminal

    def captured_stdout(self):
        return self._stdout

    def captured_stderr(self):
        return self._stderr

    def drain(self, timeout=5.0):
        self.drained = True

    def status(self):
        if len(self._codes) > 1:
            return None
        code = self._codes[0]
        return {"ok": True, "state": "exited", "code": code}

    def wait(self, timeout):
        return self._codes[0]


class LeaseFlowTests(unittest.TestCase):
    def subject(self):
        subject = object.__new__(acceptance.Acceptance)
        subject.observed = {}
        subject.stage, subject.reason = "lease-terminal", "acceptance"
        subject.native_action = "none"
        subject.native_x_error_codes, subject.last_native_click = [], {}
        subject.lease_runs, subject.sessions, subject.processes = [], [], set()
        subject.intents = set()
        subject.output_lines = []
        subject.emit = subject.output_lines.append
        subject.cli = pathlib.Path("/private/locklark")
        subject.work = pathlib.Path("/private/work")
        subject.cli_env = {"HOME": "/private/home"}
        subject.binding = pathlib.Path("/private/binding.json")
        subject.report_lease = pathlib.Path("/private/reports/lease.json")
        subject.primary = mock.Mock()
        subject.primary.identity = {"pid": 4200, "session": 4200, "tty_nr": 34816,
                                    "tty_path": "/dev/pts/9", "fd0": "/dev/pts/9"}
        subject.alternate = mock.Mock()
        subject.alternate.identity = {"pid": 4300, "session": 4300, "tty_nr": 34817,
                                      "tty_path": "/dev/pts/10", "fd0": "/dev/pts/10"}
        subject.fail = lambda reason: acceptance.Acceptance.fail(subject, reason)
        return subject

    def test_kernel_identity_accepts_a_child_in_the_shared_session(self):
        subject = self.subject()
        run = _FakeRun()
        with mock.patch.object(acceptance.os.path, "realpath", side_effect=lambda value: str(value)):
            acceptance.Acceptance.assert_kernel_identity(subject, subject.primary, run)
        self.assertEqual(subject.processes, {4242})
        self.assertTrue(subject.observed["lease-child-exe-proof"])

    def test_kernel_identity_refuses_a_new_session_or_a_session_leader_child(self):
        for mutate in ("session", "tty", "leader", "exe"):
            subject = self.subject()
            run = _FakeRun()
            if mutate == "session":
                run.identity["session"] = 9999
            elif mutate == "tty":
                run.identity["tty_nr"] = 1
            elif mutate == "leader":
                run.identity["session"] = run.pid
                subject.primary.identity["session"] = run.pid
            else:
                run.identity["exe"] = "/usr/bin/other"
            with self.subTest(mutate=mutate):
                with mock.patch.object(acceptance.os.path, "realpath", side_effect=lambda value: str(value)):
                    with self.assertRaises(acceptance.AcceptanceFailure):
                        acceptance.Acceptance.assert_kernel_identity(subject, subject.primary, run)
                self.assertNotIn(SECRET, subject.reason)

    def test_quiet_run_refuses_a_dialog_and_accepts_a_clean_exit(self):
        subject = self.subject()
        subject.launch_shared = mock.Mock(return_value=_FakeRun(pid=4243, codes=(0,)))
        subject.controls = mock.Mock(return_value={acceptance.LEASE_LABEL: {"present": True}})
        with self.assertRaises(acceptance.AcceptanceFailure):
            acceptance.Acceptance.quiet_run(subject, subject.primary, subject.report_lease, "reuse")
        self.assertEqual(subject.reason, "unexpected-lease-dialog")

        subject = self.subject()
        subject.launch_shared = mock.Mock(return_value=_FakeRun(pid=4244, codes=(0,)))
        subject.controls = mock.Mock(return_value={})
        run, code = acceptance.Acceptance.quiet_run(subject, subject.primary, subject.report_lease, "reuse")
        self.assertEqual((run.pid, code), (4244, 0))

    def test_quiet_run_refuses_a_local_factor_prompt(self):
        subject = self.subject()
        subject.launch_shared = mock.Mock(return_value=_FakeRun(pid=4245, codes=(0,), stdout="主密码".encode()))
        subject.controls = mock.Mock(return_value={})
        with self.assertRaises(acceptance.AcceptanceFailure):
            acceptance.Acceptance.quiet_run(subject, subject.primary, subject.report_lease, "reuse")
        self.assertEqual(subject.reason, "fallback-factor-prompt")

    def event(self, link, result="intent"):
        return {"action": "item.run.bundle", "result": result, "link": link}

    def test_exactly_one_new_committed_intent_is_required(self):
        subject = self.subject()
        first, second = "a" * 64, "b" * 64
        subject.observe = mock.Mock(return_value={"events": [self.event(first)]})
        acceptance.Acceptance.expect_new_intent(subject, [])
        self.assertEqual(subject.intents, {first})
        subject.observe = mock.Mock(return_value={"events": [self.event(first), self.event(second)]})
        self.assertEqual(acceptance.Acceptance.expect_new_intent(subject, [first]), second)
        # A duplicate or an identical second intent is not a fresh intent.
        subject.observe = mock.Mock(return_value={"events": [self.event(first)]})
        with self.assertRaises(acceptance.AcceptanceFailure):
            acceptance.Acceptance.expect_new_intent(subject, [])
        subject.observe = mock.Mock(return_value={"events": [self.event(first, result="conflict")]})
        with self.assertRaises(acceptance.AcceptanceFailure):
            acceptance.Acceptance.expect_new_intent(subject, [])

    def test_no_intent_means_no_grant_was_prepared(self):
        subject = self.subject()
        link = "c" * 64
        subject.observe = mock.Mock(return_value={"events": [self.event(link)]})
        acceptance.Acceptance.expect_no_intent(subject, [link])
        with self.assertRaises(acceptance.AcceptanceFailure):
            acceptance.Acceptance.expect_no_intent(subject, [])

    def test_intent_shape_is_pinned_to_a_canonical_digest(self):
        subject = self.subject()
        for bad in ("", "private", "A" * 64, "d" * 63, None, 7):
            subject.observe = mock.Mock(return_value={"events": [self.event(bad)]})
            with self.subTest(bad=bad):
                with self.assertRaises(acceptance.AcceptanceFailure):
                    acceptance.Acceptance.intent_links(subject)
                self.assertEqual(subject.reason, "lease-intent-shape")

    def test_default_one_shot_flow_never_clicks_the_lease_label(self):
        for name in ("approve_case", "refuse_case", "request_decision", "await_decision"):
            source = inspect.getsource(getattr(acceptance.Acceptance, name))
            with self.subTest(name=name):
                self.assertNotIn("LEASE_LABEL", source)
                self.assertNotIn("lease", source.lower())

    def test_run_selects_lease_cases_only_for_lease_mode(self):
        for lease in (False, True):
            subject = self.subject()
            subject.lease = lease
            subject.setup = mock.Mock()
            subject.bind = mock.Mock()
            subject.approve_case = mock.Mock()
            subject.refuse_case = mock.Mock()
            subject.lease_cases = mock.Mock()
            subject.close_cli_runs = mock.Mock()
            subject.close = mock.Mock()
            subject.privacy = mock.Mock()
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(acceptance.Acceptance.run(subject), 0)
            with self.subTest(lease=lease):
                self.assertEqual(subject.lease_cases.call_count, 1 if lease else 0)
                self.assertEqual(subject.approve_case.call_count, 0 if lease else 1)
                self.assertEqual(subject.refuse_case.call_count, 0 if lease else 1)
                text = out.getvalue()
                self.assertIn("canary-scan=passed", text)
                self.assertIn("PASS:", text)
                self.assertEqual("lease ttl" in text, lease)


class ExpectedRefusalTests(unittest.TestCase):
    """The only accepted finished-process path: the post-lock refusal."""

    def subject(self):
        subject = LeaseFlowTests().subject()
        arguments = acceptance.lease_command(subject.cli, subject.binding, subject.report_lease)
        return subject, arguments

    def finished(self, arguments, code=1, **kwargs):
        run = _FakeRun(codes=(code,), live=False, exe=None, argv=arguments, **kwargs)
        return run

    def launch(self, subject, run, expect_refusal):
        subject.primary.run = mock.Mock(return_value=run)
        with mock.patch.object(acceptance.os.path, "realpath", side_effect=lambda value: str(value)):
            return acceptance.Acceptance.launch_shared(
                subject, subject.primary, subject.report_lease, expect_refusal=expect_refusal)

    def test_expected_after_lock_nonzero_refusal_is_accepted_without_live_proc(self):
        subject, arguments = self.subject()
        run = self.finished(arguments, code=7)
        self.assertIs(self.launch(subject, run, True), run)
        subject.primary.run.assert_called_once()
        self.assertTrue(subject.primary.run.call_args.kwargs["allow_finished"])
        self.assertEqual(run.identity["live_exe"], False)
        self.assertIsNone(run.identity["exe"])
        self.assertEqual(run.identity["pid"], run.pid)
        self.assertEqual(run.identity["session"], subject.primary.identity["session"])
        self.assertEqual(run.identity["tty_nr"], subject.primary.identity["tty_nr"])
        self.assertEqual(run.status()["code"], 7)
        self.assertEqual(subject.observed["lease-finished-refusal-peek"], "not-available")
        self.assertNotIn("lease-child-exe-proof", subject.observed)
        self.assertEqual(subject.processes, {run.pid})
        self.assertEqual(subject.lease_runs, [run])

    def test_no_live_proc_is_refused_for_every_non_explicit_mode(self):
        subject, arguments = self.subject()
        run = self.finished(arguments)
        with self.assertRaises(acceptance.AcceptanceFailure):
            self.launch(subject, run, False)
        self.assertEqual(subject.reason, "lease-live-proof-missing")
        self.assertFalse(subject.primary.run.call_args.kwargs["allow_finished"])
        self.assertNotIn("lease-child-exe-proof", subject.observed)

    def test_zero_exit_is_never_a_refusal_even_without_live_proc(self):
        for code in (0,):
            subject, arguments = self.subject()
            run = self.finished(arguments, code=code)
            with self.subTest(code=code):
                with self.assertRaises(acceptance.AcceptanceFailure):
                    self.launch(subject, run, True)
                self.assertEqual(subject.reason, "lease-finished-zero")
                self.assertNotIn("lease-lock-refused", subject.observed)

    def test_missing_identity_or_known_session_is_never_a_refusal(self):
        cases = {
            "pid": lambda run: run.identity.__setitem__("pid", run.pid + 1),
            "session": lambda run: run.identity.__setitem__("session", None),
            "tty": lambda run: run.identity.__setitem__("tty_nr", 1),
            "exe": lambda run: run.identity.__setitem__("exe", "/private/locklark"),
        }
        reasons = {"pid": "lease-finished-pid", "session": "lease-finished-session",
                   "tty": "lease-finished-tty", "exe": "lease-finished-exe"}
        for name, mutate in cases.items():
            subject, arguments = self.subject()
            run = self.finished(arguments)
            run.identity["live_exe"] = name != "exe"
            mutate(run)
            with self.subTest(name=name):
                with self.assertRaises(acceptance.AcceptanceFailure):
                    self.launch(subject, run, True)
                self.assertEqual(subject.reason, reasons[name])

    def test_signaled_finished_process_is_never_a_refusal(self):
        subject, arguments = self.subject()
        run = self.finished(arguments)
        run.status = lambda: {"ok": True, "state": "signaled", "signal": 9}
        with self.assertRaises(acceptance.AcceptanceFailure):
            self.launch(subject, run, True)
        self.assertEqual(subject.reason, "lease-finished-signaled")

    def test_grant_reuse_and_wrong_terminal_still_require_live_exe_proof(self):
        for live, reason in ((False, "lease-live-proof-missing"),
                             (True, "lease-kernel-exe")):
            subject, arguments = self.subject()
            run = _FakeRun(codes=(0,), live=live,
                           exe="/private/locklark" if live else None, argv=arguments)
            if live:
                run.identity["exe"] = "/usr/bin/other"
            with self.subTest(live=live):
                with self.assertRaises(acceptance.AcceptanceFailure):
                    self.launch(subject, run, False)
                self.assertEqual(subject.reason, reason)
                self.assertNotIn("lease-child-exe-proof", subject.observed)

    def test_quiet_run_expected_refusal_drains_and_requires_nonzero_exit(self):
        subject, arguments = self.subject()
        run = self.finished(arguments, code=1,
                            stderr=b"locklark: desktop browser broker refused the request\n")
        subject.launch_shared = mock.Mock(return_value=run)
        subject.controls = mock.Mock(return_value={})
        got, code = acceptance.Acceptance.quiet_run(
            subject, subject.primary, subject.report_lease, "after-lock", expect_refusal=True)
        self.assertIs(got, run)
        self.assertEqual(code, 1)
        self.assertTrue(run.drained)

        subject, arguments = self.subject()
        run = self.finished(arguments, code=0)
        subject.launch_shared = mock.Mock(return_value=run)
        subject.controls = mock.Mock(return_value={})
        with self.assertRaises(acceptance.AcceptanceFailure):
            acceptance.Acceptance.quiet_run(
                subject, subject.primary, subject.report_lease, "after-lock", expect_refusal=True)
        self.assertEqual(subject.reason, "lease-refusal-zero")

    def test_after_lock_requires_actual_product_refusal_not_arbitrary_child_failure(self):
        for code, stderr in ((1, b""), (127, b"exec failed\n"),
                             (7, b"desktop browser broker refused the request\n")):
            subject, arguments = self.subject()
            run = self.finished(arguments, code=code, stderr=stderr)
            subject.launch_shared = mock.Mock(return_value=run)
            subject.controls = mock.Mock(return_value={})
            with self.subTest(code=code, stderr=stderr):
                with self.assertRaises(acceptance.AcceptanceFailure):
                    acceptance.Acceptance.quiet_run(
                        subject, subject.primary, subject.report_lease, "after-lock", expect_refusal=True)
                self.assertEqual(subject.reason, "lease-refusal-product-marker")

    def test_expected_refusal_mode_is_explicit_and_only_used_after_lock(self):
        for name in ("launch_shared", "quiet_run"):
            signature = inspect.signature(getattr(acceptance.Acceptance, name))
            with self.subTest(name=name):
                self.assertIs(signature.parameters["expect_refusal"].default, False)
        source = inspect.getsource(acceptance.Acceptance.lease_cases)
        self.assertEqual(source.count("expect_refusal=True"), 1)
        self.assertIn("after-lock", source)
        source = pathlib.Path(acceptance.__file__).read_text()
        self.assertEqual(source.count("expect_refusal=True"), 1)

    def test_stale_or_different_command_metadata_is_refused(self):
        def changed(index, value):
            def mutate(arguments):
                wrong = list(arguments)
                wrong[index] = value
                return wrong
            return mutate

        def extra(arguments):
            return list(arguments) + ["extra"]

        cases = {
            "executable": changed(0, "/usr/bin/other"),
            "binding": changed(5, "/private/other-binding.json"),
            "report": changed(7, "/private/other-report.json"),
            "extra-argument": extra,
        }
        for name, mutate in cases.items():
            subject, arguments = self.subject()
            run = self.finished(arguments)
            run.argv = tuple(mutate(arguments))
            with self.subTest(name=name):
                with self.assertRaises(acceptance.AcceptanceFailure):
                    self.launch(subject, run, True)
                self.assertEqual(subject.reason, "lease-argv")
                self.assertNotIn("lease-child-exe-proof", subject.observed)

    def test_expected_refusal_evidence_requires_no_child_no_intent_no_factor_and_clean_temp(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            tmp = root / "tmp"
            tmp.mkdir()
            report = root / "lease.json"
            before = ["a" * 64]

            def subject_with_run():
                subject, _arguments = self.subject()
                subject.cli_tmp = tmp
                subject.values = set()
                subject.intent_links = mock.Mock(return_value=list(before))
                return subject, self.finished([], code=1)

            subject, run = subject_with_run()
            acceptance.Acceptance.assert_expected_refusal_evidence(
                subject, run, 1, before, report)

            for name, reason, setup in (
                ("zero-exit", "lease-lock-code",
                 lambda s, r, t: setattr(r, "_codes", [0])),
                ("child-report", "lease-lock-report",
                 lambda s, r, t: t.write_bytes(b"{}")),
                ("new-intent", "lease-lock-intent",
                 lambda s, r, t: s.intent_links.configure_mock(
                     return_value=list(before) + ["b" * 64])),
                ("factor-fallback", "fallback-factor-prompt",
                 lambda s, r, t: setattr(r, "_stdout", "主密码".encode())),
                ("unclean-temp", "lease-temp",
                 lambda s, r, t: (t.parent.parent / "tmp" / "left").write_bytes(b"x")),
            ):
                with self.subTest(name=name):
                    for path in tmp.iterdir():
                        path.unlink()
                    report.unlink(missing_ok=True)
                    subject, run = subject_with_run()
                    if name == "unclean-temp":
                        (tmp / "left").write_bytes(b"x")
                    else:
                        setup(subject, run, report)
                    with self.assertRaises(acceptance.AcceptanceFailure):
                        acceptance.Acceptance.assert_expected_refusal_evidence(
                            subject, run, 0 if name == "zero-exit" else 1,
                            before, report)
                    self.assertEqual(subject.reason, reason)

    def test_fixture_codes_are_whitelisted_and_never_echo_exception_text(self):
        subject, _arguments = self.subject()
        self.assertEqual(subject.fixture_reason(FixtureError("child-exe")), "fixture-child-exe")
        for code in terminal_module.PROOF_FAILURE_STAGES:
            with self.subTest(code=code):
                self.assertIn(code, acceptance.FIXTURE_FAILURE_REASONS)
                self.assertEqual(subject.fixture_reason(FixtureError(code)), "fixture-" + code)
        self.assertEqual(subject.fixture_reason(FixtureError(SECRET + " /private/command")),
                         "fixture-unknown")
        self.assertNotIn(SECRET, subject.fixture_reason(FixtureError(SECRET)))


class FinishedProofTests(unittest.TestCase):
    """Deterministic unit coverage of the fixture's finished-process fallback."""

    def session(self, status=None):
        subject = object.__new__(TerminalSession)
        subject.tty_path = "/dev/pts/9"
        subject.identity = {"pid": 4200, "session": 4200, "tty_nr": 34816,
                            "tty_path": "/dev/pts/9", "fd0": "/dev/pts/9"}
        subject.status = mock.Mock(return_value=status if status is not None
                                   else {"ok": True, "state": "exited", "code": 3})
        return subject

    def prove(self, subject, allow, fork_identity=None):
        with mock.patch.object(terminal_module, "_proc_exe", return_value=None), \
                mock.patch.object(terminal_module, "_proc_alive", return_value=False), \
                mock.patch.object(terminal_module.time, "monotonic", return_value=0.0):
            return subject._prove(4242, "/private/locklark", allow,
                                  fork_identity or {"session": 4200, "tty_nr": 34816})

    def prove_patched(self, subject, allow, fork_identity, exe, alive, monotonic, stat=None):
        """Run _prove with deterministic kernel-peek and clock patches."""
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(terminal_module, "_proc_exe",
                                                  return_value=exe))
            stack.enter_context(mock.patch.object(terminal_module, "_proc_alive",
                                                  return_value=alive))
            if stat is not None:
                stack.enter_context(mock.patch.object(terminal_module, "proc_stat", stat))
            stack.enter_context(mock.patch.object(terminal_module.time, "monotonic",
                                                  side_effect=list(monotonic)))
            stack.enter_context(mock.patch.object(terminal_module.time, "sleep"))
            return subject._prove(4242, "/private/locklark", allow, fork_identity)

    def test_fast_exit_without_live_proof_needs_the_explicit_finished_mode(self):
        subject = self.session()
        with self.assertRaises(FixtureError) as caught:
            self.prove(subject, False)
        self.assertEqual(str(caught.exception), "child-exe")
        subject.status.assert_not_called()

    def test_finished_mode_keeps_real_pid_session_tty_and_exit_status(self):
        subject = self.session({"ok": True, "state": "exited", "code": 3})
        identity = self.prove(subject, True)
        self.assertEqual(identity["pid"], 4242)
        self.assertEqual(identity["session"], 4200)
        self.assertEqual(identity["tty_nr"], 34816)
        self.assertEqual(identity["live_exe"], False)
        self.assertIsNone(identity["exe"])
        self.assertEqual(subject.status(4242)["code"], 3)

    def test_finished_mode_refuses_a_session_mismatch_or_missing_status(self):
        subject = self.session()
        with self.assertRaises(FixtureError) as caught:
            self.prove(subject, True, {"session": 1, "tty_nr": 34816})
        self.assertEqual(str(caught.exception), "child-identity")

        # A missing reaped status must not be reported as a fabricated
        # finished process: wait to the detector deadline and use the fixed
        # no-exe stage instead of the old immediate child-exe.
        subject = self.session(status=None)
        subject.status = mock.Mock(return_value=None)
        with self.assertRaises(FixtureError) as caught:
            self.prove_patched(subject, True, {"session": 4200, "tty_nr": 34816},
                               None, False, [0.0, 20.0])
        self.assertEqual(str(caught.exception), terminal_module.PROOF_NO_EXE)

    def test_finished_mode_polls_actual_status_through_the_not_ready_race(self):
        # The real child may exit and be reaped before the first status poll
        # observes it. A None status is not fatal: keep polling the actual
        # reaped status until the real terminal status appears.
        subject = self.session()
        subject.status = mock.Mock(side_effect=[
            None, None, {"ok": True, "state": "exited", "code": 3}])
        identity = self.prove_patched(subject, True, {"session": 4200, "tty_nr": 34816},
                                      None, False, [0.0, 0.1, 0.2, 0.3])
        self.assertEqual(identity["live_exe"], False)
        self.assertIsNone(identity["exe"])
        self.assertEqual(identity["pid"], 4242)
        self.assertEqual(identity["session"], 4200)
        self.assertEqual(identity["tty_nr"], 34816)
        self.assertEqual(subject.status.call_count, 3)

    def test_finished_mode_timeout_uses_only_fixed_proof_stage_names(self):
        cases = (
            (terminal_module.PROOF_NO_EXE, None, False),
            (terminal_module.PROOF_WRONG_EXE, "/usr/bin/other", False),
            (terminal_module.PROOF_WAITING_STATUS, "/private/locklark", True),
        )
        for stage, exe, stat_error in cases:
            subject = self.session(status=None)
            subject.status = mock.Mock(return_value=None)
            stat = (mock.Mock(side_effect=FixtureError("proc-stat")) if stat_error
                    else mock.Mock(return_value=None))
            with self.subTest(stage=stage):
                with self.assertRaises(FixtureError) as caught:
                    self.prove_patched(subject, True, {"session": 4200, "tty_nr": 34816},
                                       exe, False, [0.0, 20.0], stat=stat)
                self.assertEqual(str(caught.exception), stage)
                self.assertIn(str(caught.exception), terminal_module.PROOF_FAILURE_STAGES)
                self.assertNotIn("/private", str(caught.exception))
                self.assertNotIn("4242", str(caught.exception))


class ReceiptTests(unittest.TestCase):
    def subject(self):
        subject = object.__new__(acceptance.Acceptance)
        subject.observed = {}
        subject.stage, subject.reason = "complete", "acceptance"
        subject.native_action = "none"
        subject.processes = set()
        return subject

    def test_lease_receipt_booleans_and_the_skipped_wall_clock_ttl(self):
        subject = self.subject()
        text = "\n".join(acceptance.Acceptance.lease_lines(subject, True))
        self.assertIn("absolute-5min-real-expiry=not-run", text)
        self.assertIn("shared-kernel-terminal=false", text)
        self.assertIn("PASS: real native five-minute terminal lease", text)
        self.assertNotIn(SECRET, text)
        self.assertNotIn("/private", text)
        for line in text.splitlines():
            if line.startswith("PASS") or line.startswith("FAIL"):
                continue
            fields = line.split(" (")[0]
            self.assertRegex(fields, r"^(CLI desktop native [a-z -]+: )([a-z0-9-]+=[a-z0-9-]+ ?)+$")

    def test_lock_receipt_reports_live_fast_refusal_peek_honestly(self):
        for value, rendered in (("live", "live"), ("not-available", "not-available"),
                                (None, "not-run")):
            subject = self.subject()
            if value is not None:
                subject.observed["lease-lock-kernel-peek"] = value
            text = "\n".join(acceptance.Acceptance.lease_lines(subject, True))
            with self.subTest(value=value):
                self.assertIn("fast-refusal-kernel-peek=" + rendered, text)

    def test_lease_failure_line_never_leaks_paths_or_exceptions(self):
        subject = self.subject()
        subject.stage, subject.reason = "reuse", "unexpected-lease-dialog"
        text = "\n".join(acceptance.Acceptance.lease_lines(subject, False))
        self.assertIn("FAIL: CLI desktop native acceptance at reuse [unexpected-lease-dialog]", text)
        self.assertNotIn("/private", text)

    def test_one_shot_receipt_lines_are_unchanged(self):
        subject = self.subject()
        text = "\n".join(acceptance.Acceptance.one_shot_lines(subject, True))
        self.assertIn("PASS: real native one-shot desktop CLI approval and refusal", text)
        self.assertNotIn("lease", text.lower())


class FixtureSessionTests(unittest.TestCase):
    """Real private pseudo terminals and real children; no display, no product."""

    def setUp(self):
        self.sessions = []

    def tearDown(self):
        for session in self.sessions:
            try:
                session.close()
            except Exception:
                pass

    def session(self):
        session = TerminalSession()
        self.sessions.append(session)
        session.start()
        return session

    def spawn(self, session, code, *arguments, script=None):
        script = script or "import os,sys; print('out'); print('err', file=sys.stderr); sys.exit(int(sys.argv[1]))"
        argv = [sys.executable, "-c", script, *arguments]
        return session.run(argv, os.getcwd(), dict(os.environ))

    def test_two_children_share_one_real_terminal_but_not_a_process(self):
        session = self.session()
        identity = session.identity
        self.assertEqual(identity["session"], identity["pid"])
        self.assertNotEqual(identity["tty_nr"], 0)
        self.assertEqual(identity["fd0"], identity["tty_path"])
        first = self.spawn(session, "3", "3")
        second = self.spawn(session, "0", "0")
        for run in (first, second):
            self.assertEqual(run.identity["session"], identity["session"])
            self.assertEqual(run.identity["tty_nr"], identity["tty_nr"])
            self.assertNotEqual(run.identity["session"], run.pid)
            self.assertEqual(os.path.realpath(run.identity["exe"]), os.path.realpath(sys.executable))
        self.assertNotEqual(first.pid, second.pid)
        self.assertEqual(first.wait(20), 3)
        self.assertEqual(second.wait(20), 0)
        first.release()
        second.release()
        self.assertIn(b"out", first.captured_stdout())
        self.assertIn(b"err", first.captured_stderr())
        self.assertIn(b"out", second.captured_stdout())
        self.assertNotIn(b"out", first.captured_stderr())

    def test_child_gets_a_real_controlling_terminal_and_clean_stdio(self):
        session = self.session()
        script = ("import os,sys; fd=os.open('/dev/tty', os.O_RDWR); "
                  "print(os.isatty(0), os.isatty(1)); os.close(fd); sys.exit(0)")
        run = session.run([sys.executable, "-c", script], os.getcwd(), dict(os.environ))
        self.assertEqual(run.wait(20), 0)
        run.release()
        # stdin is the real tty; stdout is an externally owned pipe, not a tty.
        self.assertEqual(run.captured_stdout().strip(), b"True False")
        self.assertEqual(run.captured_terminal(), b"")

    def test_a_second_session_is_a_different_kernel_terminal(self):
        first, second = self.session(), self.session()
        self.assertNotEqual(first.identity["session"], second.identity["session"])
        self.assertNotEqual(first.identity["tty_nr"], second.identity["tty_nr"])
        run = self.spawn(first, "0", "0")
        self.assertEqual(run.identity["session"], first.identity["session"])
        self.assertNotEqual(run.identity["session"], second.identity["session"])
        self.assertEqual(run.wait(20), 0)
        run.release()

    def test_changed_argv_keeps_the_same_terminal(self):
        session = self.session()
        first = self.spawn(session, "0", "0")
        changed = self.spawn(session, "0", "0", script="import sys; sys.exit(int(sys.argv[1]))")
        self.assertNotEqual(first.argv, changed.argv)
        self.assertEqual(first.identity["tty_nr"], changed.identity["tty_nr"])
        self.assertEqual(first.identity["session"], changed.identity["session"])
        self.assertNotEqual(first.pid, changed.pid)
        self.assertEqual(first.wait(20), 0)
        self.assertEqual(changed.wait(20), 0)
        first.release()
        changed.release()

    def test_repeated_fast_false_runs_capture_real_kernel_identity(self):
        """Ten real /bin/false runs must never fabricate or lose SID/tty."""
        session = self.session()
        leader = session.identity
        for attempt in range(10):
            run = session.run(["/bin/false"], os.getcwd(), dict(os.environ),
                              allow_finished=True)
            with self.subTest(attempt=attempt):
                self.assertEqual(run.identity["pid"], run.pid)
                self.assertEqual(run.identity["session"], leader["session"])
                self.assertNotEqual(run.identity["session"], 0)
                self.assertNotEqual(run.identity["session"], run.pid)
                self.assertEqual(run.identity["tty_nr"], leader["tty_nr"])
                self.assertNotEqual(run.identity["tty_nr"], 0)
                if run.identity["live_exe"]:
                    self.assertEqual(os.path.realpath(run.identity["exe"]),
                                     os.path.realpath("/bin/false"))
                else:
                    self.assertIsNone(run.identity["exe"])
                # The real kernel wait status of /bin/false, never invented.
                self.assertEqual(run.wait(20), 1)
                self.assertEqual(run.status()["state"], "exited")
                self.assertEqual(run.status()["code"], 1)
            run.release()

    def test_stop_kills_a_running_child_and_the_session_survives(self):
        session = self.session()
        run = self.spawn(session, "0", "0", script="import time; time.sleep(30)")
        self.assertIsNone(run.status())
        run.stop()
        self.assertEqual(run.status()["state"], "signaled")
        following = self.spawn(session, "0", "0")
        self.assertEqual(following.identity["session"], session.identity["session"])
        self.assertEqual(following.wait(20), 0)
        following.release()

    def test_invalid_requests_are_refused_without_echoing_their_content(self):
        session = self.session()
        cases = [
            ([], os.getcwd(), dict(os.environ)),
            (["/bin/true", ""], os.getcwd(), dict(os.environ)),
            (["/bin/true"], os.getcwd(), {"bad": 1}),
            (["/bin/true"], os.getcwd(), {"BAD\x00": "x"}),
            (["/bin/true"], "relative", dict(os.environ)),
        ]
        for argv, cwd, env in cases:
            with self.subTest(argv=argv):
                with self.assertRaises(FixtureError) as caught:
                    session.run(argv, cwd, env)
                self.assertNotIn(SECRET, str(caught.exception))
                self.assertNotIn("BAD", str(caught.exception))


class PublicOutputTests(unittest.TestCase):
    def subject(self, diagnostics):
        subject = object.__new__(acceptance.Acceptance)
        subject.observed = {}
        subject.stage, subject.reason = "approve-request", "child-report-mismatch"
        subject.native_action = "click:" + acceptance.APPROVE_LABEL
        subject.native_x_error_codes, subject.last_native_click = [], {}
        subject.output_lines = []
        subject.diagnostics = diagnostics
        subject.setup = mock.Mock()
        subject.close_cli_runs = mock.Mock()
        subject.close = mock.Mock()
        subject.privacy = mock.Mock()
        return subject

    def test_private_exception_never_reaches_the_public_transcript(self):
        with tempfile.TemporaryDirectory() as directory:
            subject = self.subject(pathlib.Path(directory))
            subject.bind = mock.Mock(side_effect=RuntimeError(SECRET + " --private-command"))
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                result = subject.run()
            self.assertEqual(result, 1)
            text = out.getvalue()
            self.assertIn("CLI desktop native stage: setup", text)
            self.assertIn("FAIL: CLI desktop native acceptance at setup [child-report-mismatch]"
                          " action=click:" + acceptance.APPROVE_LABEL, text)
            self.assertIn("canary-scan=passed", text)
            self.assertNotIn(SECRET, text)
            self.assertNotIn("/private/command", text)
            failure = json.loads((subject.diagnostics / "failure.json").read_bytes())
            self.assertEqual(failure["error_class"], "unexpected")
            self.assertEqual(failure["stage"], "setup")
            self.assertNotIn(SECRET, json.dumps(failure))
            subject.close_cli_runs.assert_called_once_with()
            subject.close.assert_called_once_with()

    def test_fixture_error_is_classified_without_its_text(self):
        with tempfile.TemporaryDirectory() as directory:
            subject = self.subject(pathlib.Path(directory))
            subject.bind = mock.Mock(side_effect=FixtureError("child-identity"))
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(subject.run(), 1)
            failure = json.loads((subject.diagnostics / "failure.json").read_bytes())
            self.assertEqual(failure["error_class"], "fixture")
            self.assertNotIn("child-identity", out.getvalue())

    def test_canary_in_captured_streams_marks_the_scan_failed(self):
        with tempfile.TemporaryDirectory() as directory:
            subject = self.subject(pathlib.Path(directory))
            subject.bind = mock.Mock()
            subject.approve_case = mock.Mock()
            subject.refuse_case = mock.Mock()
            subject.privacy = mock.Mock(side_effect=acceptance.AcceptanceFailure())
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                result = subject.run()
            self.assertEqual(result, 1)
            text = out.getvalue()
            self.assertIn("canary-scan=failed", text)
            self.assertIn("FAIL: CLI desktop native acceptance at", text)
            self.assertNotIn(str(directory), text)

    def test_success_summary_reports_only_fixed_booleans(self):
        with tempfile.TemporaryDirectory() as directory:
            subject = self.subject(pathlib.Path(directory))
            subject.stage, subject.reason = "complete", "acceptance"
            subject.bind = mock.Mock()
            subject.approve_case = mock.Mock()
            subject.refuse_case = mock.Mock()
            subject.observed = {
                "binding-pinned-exact-revision": True,
                "approve-hash-match": True, "approve-exit-zero": True, "approve-isolated-clean": True,
                "refuse-report-absent": True, "refuse-exit-nonzero": True,
                "refuse-no-factor-fallback": True, "refuse-isolated-clean": True,
            }
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(subject.run(), 0)
            text = out.getvalue()
            self.assertIn("PASS: real native one-shot desktop CLI approval and refusal", text)
            self.assertIn("env-hash-match=true exit-zero=true isolated-clean=true", text)
            self.assertIn("no-fallback-factor=true", text)
            self.assertNotIn(directory, text)
            self.assertNotIn(SECRET, text)


class MainTests(unittest.TestCase):
    def test_unexpected_acceptance_exception_is_replaced_by_a_fixed_stage(self):
        fake = mock.Mock()
        fake.run.side_effect = RuntimeError(SECRET)
        out = io.StringIO()
        with mock.patch.object(acceptance, "Acceptance", return_value=fake), contextlib.redirect_stdout(out):
            self.assertEqual(acceptance.main(["--cli", "/unused"]), 1)
        self.assertEqual(out.getvalue(), "FAIL: CLI desktop native acceptance at internal\n")
        self.assertNotIn(SECRET, out.getvalue())

    def test_constructor_failure_is_replaced_by_the_setup_stage(self):
        out = io.StringIO()
        with mock.patch.object(acceptance, "Acceptance", side_effect=RuntimeError(SECRET)), contextlib.redirect_stdout(out):
            self.assertEqual(acceptance.main(["--cli", "/unused"]), 1)
        self.assertEqual(out.getvalue(), "FAIL: CLI desktop native acceptance at setup\n")

    def test_arguments_are_forwarded_without_a_go_toolchain_dependency(self):
        fake = mock.Mock()
        fake.run.return_value = 0
        constructor = mock.Mock(return_value=fake)
        with mock.patch.object(acceptance, "Acceptance", constructor):
            self.assertEqual(acceptance.main(["--cli", "/unused/locklark", "--fixture-bin",
                                              "/unused/fixture", "--desktop-host", "/unused/desktop",
                                              "--wrapper-bin", "/unused/wrapper"]), 0)
        args = constructor.call_args.args[0]
        self.assertEqual(args.cli, "/unused/locklark")
        self.assertEqual(args.fixture_bin, "/unused/fixture")
        self.assertEqual(args.desktop_host, "/unused/desktop")
        self.assertEqual(args.wrapper_bin, "/unused/wrapper")
        self.assertTrue(args.go)
        # The five-minute lease proof is opt-in; the default stays one-shot.
        self.assertFalse(args.lease)

    def test_lease_mode_is_opt_in_and_forwarded(self):
        fake = mock.Mock()
        fake.run.return_value = 0
        fake.lease = True
        constructor = mock.Mock(return_value=fake)
        with mock.patch.object(acceptance, "Acceptance", constructor):
            self.assertEqual(acceptance.main(["--cli", "/unused/locklark", "--lease"]), 0)
        self.assertTrue(constructor.call_args.args[0].lease)


if __name__ == "__main__":
    unittest.main()
