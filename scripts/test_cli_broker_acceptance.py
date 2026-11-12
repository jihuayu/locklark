"""Focused stdlib tests for the Darwin CLI broker acceptance checkpoint.

These tests never launch the desktop, the native driver, or any GUI. They
exercise the pure fixture, privacy, exact-stream, audit and command-shape
oracles plus the deterministic no-network child helper as an ordinary local
process.
"""
import contextlib
import hashlib
import io
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import cli_broker_acceptance as acceptance

ROOT = pathlib.Path(__file__).resolve().parents[1]
HELPER_AVAILABLE = (
    sys.platform != "win32"
    and pathlib.Path("/bin/sh").is_file()
    and pathlib.Path("/usr/bin/shasum").is_file()
)


def temporary_base(test):
    directory = pathlib.Path(tempfile.mkdtemp(prefix="llcb-unit-"))
    test.addCleanup(shutil.rmtree, directory, ignore_errors=True)
    return directory


def fixture_tree(test):
    fixture = acceptance.Fixture(temporary_base(test))
    test.addCleanup(shutil.rmtree, fixture.root, ignore_errors=True)
    return fixture


def synthetic_summary():
    """One exact product-shaped broker preamble, independent of the module."""
    vault = "/tmp/llcb-AbCdEfGh/vault/synthetic.ll"
    helper = "/tmp/llcb-AbCdEfGh/bin/child-helper"
    cwd = "/tmp/llcb-AbCdEfGh/run"
    helper_dir = "/tmp/llcb-AbCdEfGh/bin"
    receipt = "/tmp/llcb-AbCdEfGh/receipt/receipt.txt"
    lines = [
        "桌面代理 CLI 执行请求（locklark cli run）",
        '  密码库  ："%s"' % vault,
        '  Profile ："token"',
        '  终端    ："/dev/ttys007"（平台 "darwin"）',
        '  执行程序："%s"' % helper,
        "  SHA-256 ：" + "a" * 64,
        '  工作目录："%s"' % cwd,
        '  临时目录："/var/folders/owned/T/locklark-run-cli-AbCdEf"',
        "  超时上限：30 秒",
        '  Tokens  ："LOCKLARK_SYNTHETIC_TOKEN"',
        "槽位目标（读取不可变修订）：",
        '  "token" = %s @ %s（字段 "password"）' % ("b" * 32, "c" * 64),
        "透传环境变量名（不显示值）：",
        "辅助 PATH：",
        '  "%s"' % helper_dir,
        "命令参数（会显示在终端与系统进程列表中，请勿在参数内写入秘密）：",
        '  [0] "%s"' % receipt,
    ]
    return "\r\n".join(lines) + "\r\n"


def summary_pattern():
    return acceptance.broker_summary_pattern(
        "/tmp/llcb-AbCdEfGh/vault/synthetic.ll",
        "/tmp/llcb-AbCdEfGh/bin/child-helper",
        "a" * 64,
        "/tmp/llcb-AbCdEfGh/run",
        30,
        "LOCKLARK_SYNTHETIC_TOKEN",
        "b" * 32,
        "c" * 64,
        "/tmp/llcb-AbCdEfGh/bin",
        ["/tmp/llcb-AbCdEfGh/receipt/receipt.txt"],
    )


class ScanTests(unittest.TestCase):
    def test_plain_base64_hex_and_json_escaped_canaries_are_refused(self):
        secret = 'SyntheticCanary-"' + "d" * 48
        variants = (
            secret.encode(),
            acceptance.base64.b64encode(secret.encode()),
            secret.encode().hex().encode(),
            json.dumps(secret)[1:-1].encode(),
        )
        for raw in variants:
            with self.subTest(length=len(raw)), self.assertRaises(acceptance.AcceptanceFailure):
                acceptance.scan(b"fixed" + raw + b"fixed", [secret])
        acceptance.scan(b"fixed child output only", [secret])
        acceptance.scan(b"fixed child output only", [])

    def test_fixed_public_lines_are_clean(self):
        token = "synthetic-token-" + "e" * 64
        acceptance.scan(acceptance.CHILD_STDOUT + acceptance.CHILD_STDERR, [token])


class BinaryTests(unittest.TestCase):
    def test_binary_must_be_an_absolute_executable_regular_file(self):
        base = temporary_base(self)
        executable = base / "locklark"
        executable.write_bytes(b"#!/bin/sh\n")
        executable.chmod(0o700)
        regular = base / "not-executable"
        regular.write_bytes(b"data")
        regular.chmod(0o600)
        self.assertEqual(acceptance.validate_binary(str(executable), "cli"), executable.resolve())
        for value in ("locklark", "", str(regular), str(base / "missing")):
            with self.subTest(value=value), self.assertRaises(acceptance.AcceptanceFailure):
                acceptance.validate_binary(value, "cli")

    def test_symlink_resolves_to_the_actual_binary(self):
        base = temporary_base(self)
        target = base / "build" / "locklark"
        target.parent.mkdir(mode=0o700)
        target.write_bytes(b"binary")
        target.chmod(0o700)
        link = base / "locklark"
        link.symlink_to(target)
        self.assertEqual(acceptance.validate_binary(str(link), "cli"), target.resolve())


class FixtureTests(unittest.TestCase):
    def test_fixture_is_owner_only_and_inside_its_private_root(self):
        fixture = fixture_tree(self)
        fixture.verify_layout()
        for name in acceptance.DIRECTORY_NAMES:
            self.assertEqual(acceptance.file_mode(fixture.root / name), 0o700)
        self.assertEqual(acceptance.file_mode(fixture.root), 0o700)
        self.assertTrue(acceptance.owner_only(fixture.helper, executable=True))
        self.assertEqual(acceptance.file_mode(fixture.helper), 0o700)
        self.assertTrue(str(fixture.settings).startswith(str(fixture.root) + os.sep))
        self.assertTrue(str(fixture.socket).startswith(str(fixture.root / "s") + os.sep))
        self.assertFalse(fixture.receipt.exists())
        self.assertFalse(fixture.vault.exists())
        self.assertFalse(fixture.binding.exists())

    def test_helper_is_fixed_and_contains_no_synthetic_factor(self):
        fixture = fixture_tree(self)
        script = fixture.helper.read_text()
        self.assertEqual(script, acceptance.HELPER_SCRIPT)
        self.assertIn(acceptance.TOKEN_ENV, script)
        self.assertIn("exit 23", script)
        self.assertIn("/usr/bin/shasum", script)
        self.assertIn("cli-broker-child-stdout", script)
        self.assertIn("cli-broker-child-stderr", script)

    def test_settings_path_outside_or_symlinked_outside_the_fixture_is_refused(self):
        base = temporary_base(self)
        fixture = acceptance.Fixture(base)
        self.addCleanup(shutil.rmtree, fixture.root, ignore_errors=True)
        outside = base / "outside.json"
        outside.write_text("{}")
        outside.chmod(0o600)
        with self.assertRaises(acceptance.AcceptanceFailure):
            acceptance.require_within(outside, fixture.root)
        outside_real = base / "outside-real"
        outside_real.mkdir(mode=0o700)
        outside_target = outside_real / "settings.json"
        outside_target.write_text("{}")
        outside_target.chmod(0o600)
        fixture.settings.unlink(missing_ok=True)
        fixture.settings.symlink_to(outside_target)
        with self.assertRaises(acceptance.AcceptanceFailure):
            acceptance.validate_settings(fixture.settings, fixture.root)
        acceptance.validate_settings(fixture.root / "settings" / "missing.json", fixture.root)

    def test_validate_settings_rejects_group_or_world_readable_file(self):
        fixture = fixture_tree(self)
        acceptance.write_private(fixture.settings, b"{}")
        acceptance.validate_settings(fixture.settings, fixture.root)
        fixture.settings.chmod(0o644)
        with self.assertRaises(acceptance.AcceptanceFailure):
            acceptance.validate_settings(fixture.settings, fixture.root)


class HelperExecutionTests(unittest.TestCase):
    @unittest.skipUnless(HELPER_AVAILABLE, "POSIX sh and shasum are required")
    def test_helper_writes_only_the_token_digest_and_exits_23(self):
        fixture = fixture_tree(self)
        token = "synthetic-token-" + os.urandom(32).hex()
        environment = {acceptance.TOKEN_ENV: token}
        result = subprocess.run(
            [str(fixture.helper), str(fixture.receipt)],
            env=environment, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20,
        )
        self.assertEqual(result.returncode, acceptance.CHILD_EXIT)
        self.assertEqual(result.stdout, acceptance.CHILD_STDOUT)
        self.assertEqual(result.stderr, acceptance.CHILD_STDERR)
        self.assertTrue(acceptance.owner_only(fixture.receipt))
        self.assertEqual(acceptance.file_mode(fixture.receipt), 0o600)
        self.assertEqual(
            fixture.receipt.read_bytes(),
            hashlib.sha256(token.encode()).hexdigest().encode() + b"\n",
        )
        self.assertNotIn(token.encode(), fixture.receipt.read_bytes())


class SummaryTests(unittest.TestCase):
    def test_exact_product_preamble_matches_and_is_field_pinned(self):
        text = synthetic_summary()
        self.assertIsNotNone(summary_pattern().fullmatch(text))
        for replacement in (
            text.replace('"token" = ', '"other" = '),
            text.replace('"darwin"', '"linux"'),
            text.replace("  超时上限：30 秒", "  超时上限：31 秒"),
            text + "unexpected\r\n",
        ):
            self.assertIsNone(summary_pattern().fullmatch(replacement))
        self.assertIsNone(summary_pattern().fullmatch(text.replace("\r\n", "\n")))

    def test_summary_requires_ascii_quoted_values(self):
        with self.assertRaises(acceptance.AcceptanceFailure):
            acceptance.go_quote("非 ASCII")
        self.assertEqual(acceptance.go_quote('/tmp/a b"c'), '"/tmp/a b\\"c"')


class ChildOutputTests(unittest.TestCase):
    def setUp(self):
        self.fixture = acceptance.Fixture(temporary_base(self))
        self.addCleanup(shutil.rmtree, self.fixture.root, ignore_errors=True)
        self.token = "synthetic-token-" + "f" * 64
        self.expected = acceptance.expected_receipt(self.token)
        acceptance.write_private(self.fixture.receipt, self.expected)

    def test_exact_streams_exit_status_and_receipt(self):
        stderr = synthetic_summary().encode() + acceptance.CHILD_STDERR
        summary = acceptance.validate_child_output(
            acceptance.CHILD_STDOUT, stderr, acceptance.CHILD_EXIT,
            self.fixture.receipt, self.expected,
        )
        self.assertEqual(summary.decode(), synthetic_summary())
        self.assertIsNotNone(summary_pattern().fullmatch(summary.decode()))
        self.assertEqual(self.fixture.receipt.read_bytes(), self.expected)

    def test_any_stream_exit_or_receipt_difference_is_refused(self):
        good = synthetic_summary().encode() + acceptance.CHILD_STDERR
        bad = (
            (acceptance.CHILD_STDOUT + b"extra\n", good, acceptance.CHILD_EXIT, self.expected),
            (acceptance.CHILD_STDOUT, good, 0, self.expected),
            (acceptance.CHILD_STDOUT, good.replace(acceptance.CHILD_STDERR, b""), acceptance.CHILD_EXIT, self.expected),
            (acceptance.CHILD_STDOUT, good, acceptance.CHILD_EXIT, b"0" * 64 + b"\n"),
        )
        for stdout, stderr, code, expected in bad:
            with self.subTest(code=code), self.assertRaises(acceptance.AcceptanceFailure):
                acceptance.validate_child_output(stdout, stderr, code, self.fixture.receipt, expected)

    def test_receipt_must_be_owner_only(self):
        self.fixture.receipt.chmod(0o644)
        with self.assertRaises(acceptance.AcceptanceFailure):
            acceptance.validate_child_output(
                acceptance.CHILD_STDOUT,
                synthetic_summary().encode() + acceptance.CHILD_STDERR,
                acceptance.CHILD_EXIT, self.fixture.receipt, self.expected,
            )


class LocalFallbackTests(unittest.TestCase):
    def test_no_prompt_is_the_only_accepted_pty(self):
        acceptance.require_no_local_fallback(b"")
        acceptance.require_no_local_fallback(acceptance.CHILD_STDERR)
        for marker in acceptance.LOCAL_FALLBACK_MARKERS:
            with self.subTest(marker=marker), self.assertRaises(acceptance.AcceptanceFailure):
                acceptance.require_no_local_fallback(marker)

    def test_approval_label_is_the_allowlisted_native_label(self):
        self.assertEqual(acceptance.APPROVE_LABEL, "仅批准本次 CLI 请求")


class PTYCaptureTests(unittest.TestCase):
    @unittest.skipUnless(acceptance.pty is not None, "Python pty support is unavailable")
    def test_cli_run_mode_keeps_controlling_tty_and_separates_streams(self):
        base = temporary_base(self)
        program = (
            "import os\n"
            "assert os.isatty(0)\n"
            "control = os.open('/dev/tty', os.O_RDWR)\n"
            "assert os.isatty(control)\n"
            "os.write(1, b'pty-child-stdout\\n')\n"
            "os.write(2, b'pty-child-stderr\\n')\n"
        )
        child = acceptance.PTYChild(
            sys.executable, [sys.executable, "-c", program],
            {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}, base,
            capture_stderr=True,
        )
        try:
            child.start()
            self.assertEqual(child.wait(time.monotonic() + 20), 0)
            self.assertEqual(child.stdout(), b"pty-child-stdout\n")
            self.assertEqual(child.stderr(), b"pty-child-stderr\n")
            self.assertNotIn(b"pty-child-stdout", child.terminal())
            self.assertNotIn(b"pty-child-stderr", child.terminal())
        finally:
            child.terminate()

    @unittest.skipUnless(acceptance.pty is not None, "Python pty support is unavailable")
    def test_default_mode_keeps_stderr_prompts_on_the_pty(self):
        base = temporary_base(self)
        child = acceptance.PTYChild(
            sys.executable,
            [sys.executable, "-c", "import os; os.write(2, b'pty-default-prompt\\n')"],
            {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}, base,
        )
        try:
            child.start()
            self.assertEqual(child.wait(time.monotonic() + 20), 0)
            self.assertEqual(child.stderr(), b"")
            self.assertIn(b"pty-default-prompt", child.terminal())
        finally:
            child.terminate()


class AuditTests(unittest.TestCase):
    def events(self):
        return [
            {"action": "vault.create"},
            {"action": "item.add", "item_id": "a" * 32},
            {"action": "item.run.bundle", "result": "intent",
             "item_id": "a" * 32, "base_revision": "b" * 64},
            {"action": "audit.list"},
        ]

    def test_exactly_one_bound_intent_is_required(self):
        intent = acceptance.validate_audit(self.events(), "a" * 32, "b" * 64)
        self.assertEqual(intent["action"], "item.run.bundle")
        for events in (
            [event for event in self.events() if event["action"] != "item.run.bundle"],
            self.events() + [{"action": "item.run.bundle", "result": "intent",
                              "item_id": "a" * 32, "base_revision": "b" * 64}],
            [dict(event, result="succeeded") if event.get("action") == "item.run.bundle" else event
             for event in self.events()],
            [dict(event, base_revision="c" * 64) if event.get("action") == "item.run.bundle" else event
             for event in self.events()],
        ):
            with self.subTest(events=len(events)), self.assertRaises(acceptance.AcceptanceFailure):
                acceptance.validate_audit(events, "a" * 32, "b" * 64)


class CommandShapeTests(unittest.TestCase):
    def test_desktop_environment_is_additive_and_never_rewrites_user_state(self):
        base = {
            "HOME": "/Users/owner",
            "XDG_CONFIG_HOME": "/Users/owner/.config",
            "PATH": "/usr/bin:/bin",
            "TERM": "xterm-256color",
            "LOCKLARK_CLI_ACTIVE": "1",
        }
        original = dict(base)
        socket = "/tmp/llcb-AbCdEfGh/s/b.sock"
        environment = acceptance.desktop_environment(base, socket)
        self.assertEqual(base, original)
        self.assertEqual(environment["HOME"], base["HOME"])
        self.assertEqual(environment["XDG_CONFIG_HOME"], base["XDG_CONFIG_HOME"])
        self.assertEqual(environment["PATH"], base["PATH"])
        self.assertEqual(environment["TERM"], base["TERM"])
        self.assertEqual(environment["LOCKLARK_DESKTOP_LAYOUT"], "classic")
        self.assertEqual(environment["LOCKLARK_BROWSER_SOCKET"], socket)
        self.assertEqual(set(environment) - set(base), {"LOCKLARK_DESKTOP_LAYOUT", "LOCKLARK_BROWSER_SOCKET"})
        cli = acceptance.cli_environment(base, socket)
        self.assertNotIn("LOCKLARK_CLI_ACTIVE", cli)
        self.assertEqual(cli["HOME"], base["HOME"])
        self.assertEqual(cli["XDG_CONFIG_HOME"], base["XDG_CONFIG_HOME"])
        self.assertEqual(cli["LOCKLARK_BROWSER_SOCKET"], socket)
        self.assertEqual(base, original)

    def test_arguments_are_explicit_and_never_carry_factors(self):
        fixture = fixture_tree(self)
        master = "SyntheticMaster-" + "1" * 48
        secret = "LL1-" + "A" * 26
        token = "synthetic-token-" + "2" * 64
        desktop = acceptance.desktop_arguments("/build/locklark-desktop", fixture.settings)
        self.assertEqual(desktop, ["/build/locklark-desktop", "--settings", str(fixture.settings)])
        run = acceptance.cli_run_arguments(
            "/build/locklark", fixture.binding, fixture.run, fixture.helper, fixture.receipt)
        self.assertIn("--binding", run)
        self.assertIn(str(fixture.binding), run)
        self.assertIn("--", run)
        self.assertEqual(run[-2:], [str(fixture.helper), str(fixture.receipt)])
        self.assertNotIn(master, run)
        self.assertNotIn(secret, run)
        self.assertNotIn(token, run)
        init = acceptance.cli_init_arguments(
            "/build/locklark", fixture.vault, fixture.binding, fixture.helper,
            "a" * 32, "b" * 64)
        self.assertIn("--profile", init)
        self.assertIn("token", init)
        self.assertIn("--slot-token", init)
        self.assertIn("a" * 32 + ":" + "b" * 64, init)
        self.assertIn("--name", init)
        self.assertIn(acceptance.TOKEN_ENV, init)
        self.assertNotIn(master, init)
        self.assertNotIn(secret, init)
        self.assertNotIn(token, init)


class ActivationOrderTests(unittest.TestCase):
    """The harness activates its own launched PID once, before any window wait."""

    def acceptance(self, desktop):
        base = temporary_base(self)
        args = __import__("argparse").Namespace(
            cli=str(desktop), desktop=str(desktop), timeout=240)
        instance = acceptance.Acceptance(args)
        instance.fixture = acceptance.Fixture(base)
        self.addCleanup(shutil.rmtree, instance.fixture.root, ignore_errors=True)
        instance.settings = instance.fixture.settings
        instance.desktop = desktop
        return instance

    def launch(self, instance, stdout=b'{"activated": true}\n', returncode=0):
        """Drive one start_desktop with every OS touch replaced by a recorder."""
        calls = []

        def run_driver(request):
            calls.append(("driver", json.loads(request)))
            if returncode:
                raise acceptance.AcceptanceFailure()
            return json.loads(stdout)

        instance.run_driver = run_driver
        instance.wait_unlock_fields = lambda: calls.append(("wait_unlock_fields",))
        instance.mark = lambda name: calls.append(("mark", name))
        with mock.patch.object(acceptance.subprocess, "Popen", _FakePopen), \
                contextlib.redirect_stdout(io.StringIO()):
            instance.start_desktop()
        return calls

    def test_activation_names_the_launched_pid_and_exact_executable_first(self):
        desktop = pathlib.Path("/build/bin/locklark-desktop").resolve()
        instance = self.acceptance(desktop)
        calls = self.launch(instance)
        self.assertEqual([call[0] for call in calls],
                         ["driver", "wait_unlock_fields", "mark"])
        request = calls[0][1]
        self.assertEqual(request, {"activate_pid": _FakePopen.pid,
                                   "executable": str(desktop)})
        self.assertEqual(set(request), {"activate_pid", "executable"})
        self.assertIs(type(request["activate_pid"]), int)
        self.assertIs(type(request["executable"]), str)
        self.assertNotIn(acceptance.TITLE, json.dumps(request))
        self.assertNotIn("actions", request)

    def test_activation_request_is_validated_by_the_real_contract(self):
        sys.path.insert(0, str(ROOT / "scripts"))
        import native_acceptance_contract as contract
        desktop = pathlib.Path("/build/bin/locklark-desktop").resolve()
        instance = self.acceptance(desktop)
        instance.desktop_process = _FakePopen(None)
        plan = contract.parse_request(instance.activation_request())
        self.assertEqual(plan["activation"], {"pid": _FakePopen.pid,
                                              "executable": str(desktop)})

    def test_activation_refusal_stops_before_any_window_wait(self):
        desktop = pathlib.Path("/build/bin/locklark-desktop").resolve()
        instance = self.acceptance(desktop)
        with self.assertRaises(acceptance.AcceptanceFailure):
            self.launch(instance, returncode=1)

    def test_anything_other_than_the_fixed_result_is_refused(self):
        desktop = pathlib.Path("/build/bin/locklark-desktop").resolve()
        for stdout in (b'{"activated": false}\n', b'{"activated": true, "window": "0x1"}\n',
                       b"{}\n"):
            with self.subTest(stdout=stdout):
                instance = self.acceptance(desktop)
                with self.assertRaises(acceptance.AcceptanceFailure):
                    self.launch(instance, stdout=stdout)

    def test_exited_desktop_is_never_asked_to_activate(self):
        desktop = pathlib.Path("/build/bin/locklark-desktop").resolve()
        instance = self.acceptance(desktop)
        instance.desktop_process = _FakePopen(exit_code=0)
        with self.assertRaises(acceptance.AcceptanceFailure):
            instance.activation_request()


class UnlockPlanTests(unittest.TestCase):
    """The fixed nine unlock actions are split across fresh bounded requests."""

    MASTER = "SyntheticMaster-" + "1" * 48
    SECRET = "LL1-" + "A" * 26

    def acceptance(self):
        base = temporary_base(self)
        args = __import__("argparse").Namespace(
            cli="/build/locklark", desktop="/build/bin/locklark-desktop", timeout=240)
        instance = acceptance.Acceptance(args)
        instance.fixture = acceptance.Fixture(base)
        self.addCleanup(shutil.rmtree, instance.fixture.root, ignore_errors=True)
        instance.desktop = pathlib.Path("/build/bin/locklark-desktop").resolve()
        instance.master = self.MASTER
        instance.secret = self.SECRET
        return instance

    def original_actions(self, instance):
        """The pre-split nine-action sequence, written independently here."""
        return [
            {"click_label": "金库文件"},
            {"key": "Super_L+a"},
            {"text": str(instance.fixture.vault)},
            {"click_label": "主密码"},
            {"text": self.MASTER},
            {"click_label": "Secret Key"},
            {"text": self.SECRET},
            {"click_label": "解锁"},
            {"wait_label": "新建登录"},
        ]

    def expected_plans(self, instance):
        return [
            [
                {"click_label": "金库文件"},
                {"key": "Super_L+a"},
                {"text": str(instance.fixture.vault)},
            ],
            [{"click_label": "主密码"}, {"text": self.MASTER}],
            [{"click_label": "Secret Key"}, {"text": self.SECRET}],
            [{"click_label": "解锁"}],
            [{"wait_label": "新建登录"}],
        ]

    def test_flattened_plans_are_exactly_the_original_sequence(self):
        instance = self.acceptance()
        plans = acceptance.unlock_plans(
            instance.fixture.vault, self.MASTER, self.SECRET)
        self.assertEqual(plans, tuple(tuple(plan) for plan in self.expected_plans(instance)))
        self.assertEqual([action for plan in plans for action in plan],
                         self.original_actions(instance))
        self.assertEqual(len(plans), 5)

    def test_each_plan_is_one_fresh_exact_driver_request(self):
        instance = self.acceptance()
        expected_plans = self.expected_plans(instance)
        requests = []

        def run_driver(request):
            requests.append(json.loads(request))
            return {}

        instance.run_driver = run_driver
        with contextlib.redirect_stdout(io.StringIO()):
            instance.unlock()

        self.assertEqual(len(requests), len(expected_plans))
        for request, plan in zip(requests, expected_plans):
            with self.subTest(actions=plan):
                self.assertEqual(set(request), {"title", "executable", "actions", "inspect"})
                self.assertEqual(request["title"], acceptance.TITLE)
                self.assertEqual(request["title"], "Locklark · 本地金库")
                self.assertEqual(request["executable"], str(instance.desktop))
                self.assertIs(request["inspect"], False)
                self.assertEqual(request["actions"], plan)
                self.assertIsInstance(request["actions"], list)
        self.assertEqual([action for request in requests for action in request["actions"]],
                         self.original_actions(instance))

    def test_a_failed_plan_is_not_retried_and_later_actions_are_not_sent(self):
        instance = self.acceptance()
        expected_plans = self.expected_plans(instance)
        requests = []

        def run_driver(request):
            requests.append(json.loads(request))
            if len(requests) == 3:
                raise acceptance.AcceptanceFailure()
            return {}

        instance.run_driver = run_driver
        with contextlib.redirect_stdout(io.StringIO()), \
                self.assertRaises(acceptance.AcceptanceFailure):
            instance.unlock()

        self.assertEqual([request["actions"] for request in requests],
                         expected_plans[:3])
        self.assertNotIn("native_unlock_fields_and_button", instance.checks)


class _FakePopen:
    pid = 54321

    def __init__(self, *arguments, exit_code=None, **keywords):
        self.arguments = arguments
        self.keywords = keywords
        self.exit_code = exit_code

    def poll(self):
        return self.exit_code


class UnavailableTests(unittest.TestCase):
    def test_non_darwin_is_a_fixed_unavailable_result(self):
        output = io.StringIO()
        with mock.patch.object(acceptance, "current_platform", return_value="linux"), \
                contextlib.redirect_stdout(output):
            code = acceptance.main(["--cli", "/unused/cli", "--desktop", "/unused/desktop"])
        self.assertEqual(code, 2)
        self.assertEqual(output.getvalue(), "UNAVAILABLE: cli-broker platform\n")

    def test_untrusted_accessibility_is_a_fixed_unavailable_result(self):
        base = temporary_base(self)
        cli, desktop = base / "locklark", base / "locklark-desktop"
        for binary in (cli, desktop):
            binary.write_bytes(b"binary")
            binary.chmod(0o700)
        output = io.StringIO()
        with mock.patch.object(acceptance, "current_platform", return_value="darwin"), \
                mock.patch.object(acceptance.Acceptance, "prepare",
                                  side_effect=acceptance.Unavailable("accessibility")), \
                contextlib.redirect_stdout(output):
            code = acceptance.main(["--cli", str(cli), "--desktop", str(desktop)])
        self.assertEqual(code, 2)
        self.assertIn("UNAVAILABLE: cli-broker accessibility", output.getvalue())
        self.assertNotIn("PASS:", output.getvalue())


if __name__ == "__main__":
    unittest.main()
