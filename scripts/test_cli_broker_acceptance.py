"""Focused stdlib tests for the Darwin CLI broker acceptance checkpoint.

These tests never launch the desktop, the native driver, or any GUI. They
exercise the pure fixture, privacy, exact-stream, audit and command-shape
oracles plus the deterministic no-network child helper as an ordinary local
process.
"""
import contextlib
import ctypes
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
        generation = {"pid": _FakePopen.pid, "executable": str(instance.desktop),
                      "euid": os.geteuid(), "start_sec": 1, "start_usec": 1}
        with mock.patch.object(acceptance.subprocess, "Popen", _FakePopen), \
                mock.patch.object(acceptance, "capture_process_generation",
                                  return_value=generation), \
                mock.patch.object(acceptance, "validate_process_generation"), \
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
                                   "executable": str(desktop),
                                   "owned_generation": instance.desktop_generation})
        self.assertEqual(set(request), {"activate_pid", "executable",
                                        "owned_generation"})
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
        instance.desktop_generation = {
            "pid": _FakePopen.pid, "executable": str(desktop),
            "euid": os.geteuid(), "start_sec": 1, "start_usec": 1,
        }
        with mock.patch.object(acceptance, "validate_process_generation"):
            plan = contract.parse_request(instance.activation_request())
        self.assertEqual(plan["activation"], {"pid": _FakePopen.pid,
                                              "executable": str(desktop),
                                              "generation": instance.desktop_generation})

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


def inspect_controls(present=True, showing=True, new_login=False, hidden=()):
    """One synthetic existing label-keyed controls map with fixed records."""
    hidden = set(hidden)
    labels = ("金库文件", "主密码", "Secret Key", "解锁")
    controls = {
        label: {
            "present": present and label not in hidden,
            "enabled": False,
            "showing": showing and label not in hidden,
        }
        for label in labels
    }
    controls["新建登录"] = {
        "present": new_login, "enabled": False, "showing": new_login,
    }
    return controls


def inspect_result(present=True, showing=True, new_login=False, hidden=()):
    """One synthetic inspect result carrying only the two fixed boolean maps."""
    return {
        "controls": inspect_controls(present, showing, new_login, hidden),
        "status": {
            "available": True,
            "generic_unlock_error": False,
            "secret_key_format_error": False,
            "processing": True,
        },
    }


class InspectSummaryTests(unittest.TestCase):
    """The inspect parser publishes only seven fixed built-in booleans."""

    def test_valid_maps_classify_without_echoing_extra_control_labels(self):
        result = inspect_result()
        result["controls"]["仅批准本次 CLI 请求"] = {
            "present": True, "enabled": True, "showing": True,
        }
        summary = acceptance.inspect_summary(result)
        self.assertEqual(set(summary), {
            "snapshot_available", "locked_present", "locked_showing",
            "new_login_present", "generic_unlock_error",
            "secret_key_format_error", "processing",
        })
        self.assertTrue(all(type(value) is bool for value in summary.values()))
        self.assertEqual(summary, {
            "snapshot_available": True,
            "locked_present": True,
            "locked_showing": True,
            "new_login_present": False,
            "generic_unlock_error": False,
            "secret_key_format_error": False,
            "processing": True,
        })

    def test_unlocked_controls_and_new_login_presence_are_reported(self):
        summary = acceptance.inspect_summary(
            inspect_result(present=True, showing=False, new_login=True))
        self.assertTrue(summary["locked_present"])
        self.assertFalse(summary["locked_showing"])
        self.assertTrue(summary["new_login_present"])

    def test_status_flags_and_available_are_exact_passthrough_booleans(self):
        result = inspect_result()
        result["status"] = {
            "available": False,
            "generic_unlock_error": True,
            "secret_key_format_error": True,
            "processing": False,
        }
        summary = acceptance.inspect_summary(result)
        self.assertEqual(summary, {
            "snapshot_available": False,
            "locked_present": True,
            "locked_showing": True,
            "new_login_present": False,
            "generic_unlock_error": True,
            "secret_key_format_error": True,
            "processing": False,
        })

    def test_hidden_secret_is_reported_not_ready(self):
        summary = acceptance.inspect_summary(
            inspect_result(hidden=("Secret Key",)))
        self.assertTrue(summary["snapshot_available"])
        self.assertFalse(summary["locked_present"])
        self.assertFalse(summary["locked_showing"])
        self.assertFalse(summary["new_login_present"])
        self.assertNotIn("Secret Key", acceptance.inspect_summary_line(summary))

    def test_malformed_status_or_controls_collapse_to_all_false(self):
        empty = acceptance.empty_inspect_summary()
        statuses = (
            None,
            [],
            {"available": True},
            {"available": True, "generic_unlock_error": False,
             "secret_key_format_error": False},
            {"available": True, "generic_unlock_error": False,
             "secret_key_format_error": False, "processing": True, "text": "private"},
            {"available": 1, "generic_unlock_error": False,
             "secret_key_format_error": False, "processing": True},
            {"available": "true", "generic_unlock_error": False,
             "secret_key_format_error": False, "processing": True},
            {"available": True, "generic_unlock_error": None,
             "secret_key_format_error": False, "processing": True},
        )
        for status in statuses:
            with self.subTest(status=status):
                result = inspect_result()
                if status is None:
                    del result["status"]
                else:
                    result["status"] = status
                self.assertEqual(acceptance.inspect_summary(result), empty)

        controls = (
            None,
            [],
            {},
            {label: {"present": True, "enabled": False, "showing": True}
             for label in ("金库文件", "主密码", "Secret Key")},
        )
        for value in controls:
            with self.subTest(controls=value):
                result = inspect_result()
                if value is None:
                    del result["controls"]
                else:
                    result["controls"] = value
                self.assertEqual(acceptance.inspect_summary(result), empty)

    def test_bad_record_shapes_and_private_fields_collapse_without_echo(self):
        empty = acceptance.empty_inspect_summary()
        secret = "LL1-" + "B" * 26
        records = (
            {"present": True, "enabled": False, "showing": True, "value": secret},
            {"present": True, "enabled": False, "showing": True, "text": secret},
            {"present": 1, "enabled": False, "showing": True},
            {"present": True, "enabled": False, "showing": "true"},
            {"present": True, "enabled": False},
            {},
            "private",
            None,
        )
        for label in ("金库文件", "主密码", "Secret Key", "解锁", "新建登录"):
            for record in records:
                with self.subTest(label=label, record=record):
                    result = inspect_result()
                    result["controls"][label] = record
                    summary = acceptance.inspect_summary(result)
                    self.assertEqual(summary, empty)
                    self.assertNotIn(secret, repr(summary))
                    self.assertNotIn(secret, acceptance.inspect_summary_line(summary))

    def test_result_stdout_and_unknown_top_level_fields_are_never_read(self):
        secret = "LL1-" + "C" * 26
        result = inspect_result()
        result["stdout"] = secret
        result["stderr"] = "private exception detail"
        result["private"] = {"raw": secret}
        summary = acceptance.inspect_summary(result)
        self.assertEqual(summary, acceptance.inspect_summary(inspect_result()))
        self.assertNotIn(secret, repr(summary))
        self.assertNotIn("exception", repr(summary))

    def test_diagnostic_line_has_only_fixed_names_and_zero_one_values(self):
        summary = acceptance.inspect_summary(inspect_result())
        line = acceptance.inspect_summary_line(summary)
        self.assertTrue(line.startswith("DIAG: cli-broker unlock_inspect "))
        tokens = line.split()[3:]
        self.assertEqual(tokens, [
            field + "=" + ("1" if summary[field] else "0")
            for field in acceptance.INSPECT_SUMMARY_FIELDS
        ])
        self.assertNotIn("{", line)
        self.assertNotIn("/", line)
        self.assertTrue(all(token.split("=")[0] in acceptance.INSPECT_SUMMARY_FIELDS
                            for token in tokens))
        self.assertTrue(all(token.split("=")[1] in ("0", "1") for token in tokens))


class _LiveDesktop:
    """A live desktop Popen stand-in: its exact PID scopes every request."""

    pid = 4242

    def poll(self):
        return None


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
        instance.desktop_process = _LiveDesktop()
        instance.desktop_generation = {
            "pid": _LiveDesktop.pid, "executable": str(instance.desktop),
            "euid": os.geteuid(), "start_sec": 1, "start_usec": 1,
        }
        return instance

    def original_actions(self, instance):
        """The complete explicit-entry unlock sequence, written independently."""
        return [
            {"click_label": "金库文件"},
            {"key": "Super_L+a"},
            {"text": str(instance.fixture.vault)},
            {"click_label": "主密码"},
            {"text": self.MASTER},
            {"click_label": "使用应急资料…"},
            {"wait_label": "Secret Key"},
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
            [{"click_label": "使用应急资料…"}],
            [{"wait_label": "Secret Key"}],
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
        self.assertEqual(len(plans), 7)

    def test_readiness_waits_exact_entry_but_not_hidden_secret(self):
        instance = self.acceptance()
        requests = []

        def run_driver(request):
            requests.append(json.loads(request))
            return {}

        instance.run_driver = run_driver
        with contextlib.redirect_stdout(io.StringIO()):
            instance.wait_unlock_fields()

        self.assertEqual(len(requests), 1)
        self.assertEqual(
            requests[0]["actions"],
            [{"wait_label": label} for label in acceptance.UNLOCK_READY_FIELDS],
        )
        waited = [action.get("wait_label") for action in requests[0]["actions"]]
        self.assertIn("使用应急资料…", waited)
        self.assertNotIn("Secret Key", waited)

    def test_readiness_refuses_when_real_entry_is_missing(self):
        instance = self.acceptance()
        instance.deadline = time.monotonic()
        requests = []

        def run_driver(request):
            requests.append(json.loads(request))
            raise acceptance.DriverRetry("control-missing")

        instance.run_driver = run_driver
        with contextlib.redirect_stdout(io.StringIO()), \
                self.assertRaises(acceptance.AcceptanceFailure):
            instance.wait_unlock_fields()

        self.assertEqual(len(requests), 1)
        waited = [action.get("wait_label") for action in requests[0]["actions"]]
        self.assertIn("使用应急资料…", waited)
        self.assertNotIn("Secret Key", waited)
        self.assertNotIn("native_unlock_fields_and_button", instance.checks)

    def test_opt_in_precedes_reproved_secret_and_all_factors_remain(self):
        instance = self.acceptance()
        actions = [
            action
            for plan in acceptance.unlock_plans(
                instance.fixture.vault, self.MASTER, self.SECRET
            )
            for action in plan
        ]
        labels = [action.get("click_label") for action in actions]
        entry = labels.index("使用应急资料…")
        secret = labels.index("Secret Key")
        self.assertLess(entry, secret)
        self.assertLess(
            actions.index({"wait_label": "Secret Key"}), secret
        )
        for required in (
            {"text": str(instance.fixture.vault)},
            {"text": self.MASTER},
            {"text": self.SECRET},
            {"click_label": "使用应急资料…"},
            {"click_label": "解锁"},
            {"wait_label": "新建登录"},
        ):
            self.assertIn(required, actions)

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
                self.assertEqual(set(request), {"title", "executable", "actions",
                                                "inspect", "owned_pid",
                                                "owned_generation"})
                self.assertEqual(request["owned_pid"], instance.desktop_process.pid)
                self.assertEqual(request["owned_generation"],
                                 instance.desktop_generation)
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
        self.assertEqual(len(requests), 3)
        self.assertFalse(any(request["actions"] == [] for request in requests))
        sent = [action for request in requests for action in request["actions"]]
        self.assertNotIn({"click_label": "Secret Key"}, sent)
        self.assertNotIn({"click_label": "解锁"}, sent)
        self.assertEqual(instance.output_lines, [])
        self.assertNotIn("native_unlock_fields_and_button", instance.checks)

    def test_earlier_retryable_failure_never_inspects(self):
        instance = self.acceptance()
        expected_plans = self.expected_plans(instance)
        requests = []

        def run_driver(request):
            requests.append(json.loads(request))
            if len(requests) == 1:
                raise acceptance.DriverRetry("control-missing")
            return {}

        instance.run_driver = run_driver
        with contextlib.redirect_stdout(io.StringIO()), \
                self.assertRaises(acceptance.DriverRetry):
            instance.unlock()

        self.assertEqual([request["actions"] for request in requests],
                         expected_plans[:1])
        self.assertIs(requests[0]["inspect"], False)
        self.assertEqual(instance.output_lines, [])
        self.assertNotIn("native_unlock_fields_and_button", instance.checks)

    def test_terminal_wait_failure_issues_one_inspect_and_keeps_failure(self):
        instance = self.acceptance()
        expected_plans = self.expected_plans(instance)
        requests = []
        result = inspect_result()

        def run_driver(request):
            parsed = json.loads(request)
            requests.append(parsed)
            if len(requests) == len(expected_plans):
                raise acceptance.DriverRetry("control-missing")
            if len(requests) == len(expected_plans) + 1:
                return result
            return {}

        instance.run_driver = run_driver
        with contextlib.redirect_stdout(io.StringIO()), \
                self.assertRaises(acceptance.DriverRetry) as caught:
            instance.unlock()

        self.assertEqual(caught.exception.code, "control-missing")
        self.assertEqual([request["actions"] for request in requests[:len(expected_plans)]],
                         expected_plans)
        self.assertEqual(len(requests), len(expected_plans) + 1)
        inspect_request = requests[-1]
        self.assertEqual(set(inspect_request), {"title", "executable", "actions",
                                                 "inspect", "owned_pid",
                                                 "owned_generation"})
        self.assertEqual(inspect_request["owned_pid"], instance.desktop_process.pid)
        self.assertEqual(inspect_request["owned_generation"],
                         instance.desktop_generation)
        self.assertEqual(inspect_request["title"], acceptance.TITLE)
        self.assertEqual(inspect_request["executable"], str(instance.desktop))
        self.assertEqual(inspect_request["actions"], [])
        self.assertIs(inspect_request["inspect"], True)
        self.assertEqual([action for request in requests[:len(expected_plans)]
                          for action in request["actions"]],
                         self.original_actions(instance))
        self.assertEqual(instance.unlock_inspect_summary,
                         acceptance.inspect_summary(result))
        self.assertEqual(len(instance.output_lines), 1)
        self.assertEqual(instance.output_lines[0],
                         acceptance.inspect_summary_line(instance.unlock_inspect_summary))
        self.assertNotIn("native_unlock_fields_and_button", instance.checks)

    def test_failed_terminal_inspect_stores_all_false_and_keeps_failure(self):
        instance = self.acceptance()
        expected_plans = self.expected_plans(instance)
        requests = []

        def run_driver(request):
            parsed = json.loads(request)
            requests.append(parsed)
            if len(requests) == len(expected_plans):
                raise acceptance.DriverRetry("control-missing")
            if len(requests) == len(expected_plans) + 1:
                raise acceptance.AcceptanceFailure()
            return {}

        instance.run_driver = run_driver
        with contextlib.redirect_stdout(io.StringIO()), \
                self.assertRaises(acceptance.DriverRetry) as caught:
            instance.unlock()

        self.assertEqual(caught.exception.code, "control-missing")
        self.assertEqual(len(requests), len(expected_plans) + 1)
        self.assertEqual(requests[-1]["actions"], [])
        self.assertIs(requests[-1]["inspect"], True)
        self.assertEqual(instance.unlock_inspect_summary,
                         acceptance.empty_inspect_summary())
        self.assertEqual(len(instance.output_lines), 1)
        self.assertEqual(
            instance.output_lines[0].split()[-len(acceptance.INSPECT_SUMMARY_FIELDS):],
            [field + "=0" for field in acceptance.INSPECT_SUMMARY_FIELDS])
        self.assertNotIn("native_unlock_fields_and_button", instance.checks)


def driver_failure_line(code, action="click", index=0, platform="macos"):
    """The real fixed-format refusal line the driver writes to stderr."""
    return ("Native acceptance input failed [code=%s action=%s index=%d platform=%s]\n"
            % (code, action, index, platform)).encode()


class DriverErrorCategoryTests(unittest.TestCase):
    """One fixed allowlisted driver code in memory; a fake subprocess only."""

    PRIVATE = "LL1-" + "Z" * 26
    STDERR_TAIL = ('private exception detail title="Locklark · 本地金库" '
                   'label=仅批准本次 CLI 请求 path=/private/tmp/llcb-DoSX5a\n').encode()

    def acceptance(self):
        base = temporary_base(self)
        args = __import__("argparse").Namespace(
            cli="/build/locklark", desktop="/build/bin/locklark-desktop", timeout=240)
        instance = acceptance.Acceptance(args)
        instance.fixture = acceptance.Fixture(base)
        self.addCleanup(shutil.rmtree, instance.fixture.root, ignore_errors=True)
        instance.desktop = pathlib.Path("/build/bin/locklark-desktop")
        instance.desktop_process = _FakePopen(None)
        instance.desktop_generation = {
            "pid": _FakePopen.pid, "executable": str(instance.desktop),
            "euid": os.geteuid(), "start_sec": 1, "start_usec": 1,
        }
        patcher = mock.patch.object(acceptance, "validate_process_generation")
        patcher.start()
        self.addCleanup(patcher.stop)
        return instance

    def fake(self, instance, returncode, stdout, stderr):
        result = subprocess.CompletedProcess([], returncode, stdout, stderr)
        runner = mock.Mock(return_value=result)
        patcher = mock.patch.object(acceptance.subprocess, "run", runner)
        patcher.start()
        self.addCleanup(patcher.stop)
        return runner

    def test_allowlist_covers_retry_codes_and_fixed_refusals(self):
        self.assertTrue(acceptance.RETRY_DRIVER_CODES <= acceptance.DRIVER_ERROR_CATEGORIES)
        for code in ("window-ambiguous", "capability-unavailable", "a11y-query"):
            self.assertIn(code, acceptance.DRIVER_ERROR_CATEGORIES)
        self.assertNotIn("other", acceptance.DRIVER_ERROR_CATEGORIES)
        self.assertNotIn("unexpected", acceptance.DRIVER_ERROR_CATEGORIES)

    def test_each_allowlisted_code_is_classified_or_refused_as_before(self):
        cases = (
            ("window-timeout", acceptance.DriverRetry),
            ("control-missing", acceptance.DriverRetry),
            ("control-ready-timeout", acceptance.DriverRetry),
            ("control-disabled", acceptance.DriverRetry),
            ("control-hidden", acceptance.DriverRetry),
            ("window-ambiguous", acceptance.AcceptanceFailure),
            ("a11y-query", acceptance.AcceptanceFailure),
        )
        for code, expected in cases:
            with self.subTest(code=code):
                instance = self.acceptance()
                self.fake(instance, 1, b"", driver_failure_line(code))
                with self.assertRaises(expected) as caught:
                    instance.run_driver(b"{}")
                self.assertEqual(instance.driver_error_category, code)
                if expected is acceptance.DriverRetry:
                    self.assertEqual(caught.exception.code, code)

    def test_capability_unavailable_is_classified_and_still_unavailable(self):
        instance = self.acceptance()
        self.fake(instance, 1, b"", driver_failure_line("capability-unavailable"))
        with self.assertRaises(acceptance.Unavailable) as caught:
            instance.run_driver(b"{}")
        self.assertEqual(caught.exception.reason, "accessibility")
        self.assertEqual(instance.driver_error_category, "capability-unavailable")

    def test_unknown_missing_or_off_allowlist_codes_map_to_other(self):
        variants = (
            (b"", b"no failure line at all\n"),
            (1, b"error: could not import driver\n"),
            (1, driver_failure_line("unexpected")),
            (1, driver_failure_line("some-new-code")),
            (1, driver_failure_line("a11y-tree-limit")),
            (1, b"Native acceptance input failed [code=Not-Allowlisted action=x\n"),
        )
        for returncode, stderr in variants:
            with self.subTest(stderr=stderr):
                instance = self.acceptance()
                self.fake(instance, returncode, b"", stderr)
                with self.assertRaises(acceptance.AcceptanceFailure):
                    instance.run_driver(b"{}")
                self.assertEqual(instance.driver_error_category, "other")

    def test_every_category_is_reset_before_each_driver_call(self):
        instance = self.acceptance()
        instance.driver_error_category = "a11y-query"
        runner = self.fake(instance, 0, b'{"activated": true}\n', b"")
        self.assertEqual(instance.run_driver(b"{}"), {"activated": True})
        self.assertIsNone(instance.driver_error_category)

        runner.return_value = subprocess.CompletedProcess([], 1, b"",
                                                          driver_failure_line("control-hidden"))
        with self.assertRaises(acceptance.DriverRetry):
            instance.run_driver(b"{}")
        self.assertEqual(instance.driver_error_category, "control-hidden")

        runner.return_value = subprocess.CompletedProcess([], 0, b"{}\n", b"")
        instance.run_driver(b"{}")
        self.assertIsNone(instance.driver_error_category)

    def test_timeout_failure_leaves_the_category_reset(self):
        instance = self.acceptance()
        instance.driver_error_category = "control-missing"
        with mock.patch.object(acceptance.subprocess, "run",
                               side_effect=subprocess.TimeoutExpired("driver", 40)):
            with self.assertRaises(acceptance.AcceptanceFailure):
                instance.run_driver(b"{}")
        self.assertIsNone(instance.driver_error_category)

    def test_raw_stderr_never_leaks_into_state_or_output(self):
        instance = self.acceptance()
        observed = []
        instance.mark = lambda name: observed.append(name)
        stderr = driver_failure_line("window-ambiguous") + self.PRIVATE.encode() + self.STDERR_TAIL
        runner = self.fake(instance, 1, self.PRIVATE.encode(), stderr)
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaises(acceptance.AcceptanceFailure):
            instance.run_driver(b"{}")
        self.assertEqual(runner.call_count, 1)
        self.assertEqual(instance.driver_error_category, "window-ambiguous")

        written = b"".join(
            path.read_bytes() for path in sorted(instance.fixture.logs.iterdir()))
        canaries = (self.PRIVATE.encode(), "private exception detail".encode(),
                    acceptance.TITLE.encode(), "仅批准本次 CLI 请求".encode(),
                    b"/private/tmp/llcb-DoSX5a")
        for canary in canaries:
            with self.subTest(canary=canary):
                self.assertIn(canary, written)  # captured owner-only by design
        state = repr(instance.driver_error_category + inspect_module_state(instance))
        for canary in canaries:
            self.assertNotIn(canary.decode("utf-8", "replace"), state)
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(observed, [])
        self.assertNotIn(self.PRIVATE, repr(instance.__dict__))

    def test_seven_boolean_schema_is_unchanged_and_category_is_not_in_it(self):
        self.assertEqual(list(acceptance.STATUS_FIELDS), [
            "available", "generic_unlock_error", "secret_key_format_error", "processing"])
        self.assertEqual(list(acceptance.INSPECT_SUMMARY_FIELDS), [
            "snapshot_available", "locked_present", "locked_showing",
            "new_login_present", "generic_unlock_error", "secret_key_format_error",
            "processing"])
        summary = acceptance.empty_inspect_summary()
        self.assertTrue(all(type(value) is bool for value in summary.values()))
        instance = self.acceptance()
        self.fake(instance, 1, b"", driver_failure_line("a11y-query"))
        with self.assertRaises(acceptance.AcceptanceFailure):
            instance.run_driver(b"{}")
        self.assertEqual(instance.driver_error_category, "a11y-query")
        self.assertNotIn(instance.driver_error_category, summary.values())
        self.assertEqual(instance.unlock_inspect_summary, summary)


def inspect_module_state(instance):
    """Only the allowlisted-string state an operator smoke might read."""
    return repr({key: value for key, value in instance.__dict__.items()
                 if key in ("driver_error_category", "driver_index")})


class _FakePopen:
    pid = 54321

    def __init__(self, *arguments, exit_code=None, **keywords):
        self.arguments = arguments
        self.keywords = keywords
        self.exit_code = exit_code

    def poll(self):
        return self.exit_code


class ProcessGenerationSmokeTests(unittest.TestCase):
    """Real owned no-GUI child identity smoke; no product, GUI, AX or driver."""

    @staticmethod
    def _reap(process):
        try:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            pass
        finally:
            try:
                if process.stdin is not None and not process.stdin.closed:
                    process.stdin.close()
            except OSError:
                pass

    @unittest.skipUnless(sys.platform == "darwin", "libproc generation is Darwin-only")
    def test_real_owned_cat_capture_and_rejections(self):
        # Fixed private stdin pipe and DEVNULL streams; /bin/cat is the only
        # executable. No product, driver, GUI, AX, file or network is touched.
        first = subprocess.Popen(
            ["/bin/cat"], stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        second = subprocess.Popen(
            ["/bin/cat"], stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        self.addCleanup(self._reap, first)
        self.addCleanup(self._reap, second)

        generation = acceptance.capture_process_generation(first, "/bin/cat")
        self.assertIsInstance(generation, dict)
        self.assertEqual(set(generation), set(acceptance.GENERATION_FIELDS))
        self.assertIsNone(
            acceptance.validate_process_generation(first, "/bin/cat", generation))

        with self.assertRaises(acceptance.AcceptanceFailure):
            acceptance.capture_process_generation(first, "/bin/echo")
        with self.assertRaises(acceptance.AcceptanceFailure):
            acceptance.validate_process_generation(second, "/bin/cat", generation)

        stale = dict(generation)
        stale["start_usec"] = (generation["start_usec"] + 1) % 1000000
        if stale["start_usec"] == 0:
            stale["start_sec"] += 1
        with self.assertRaises(acceptance.AcceptanceFailure):
            acceptance.validate_process_generation(first, "/bin/cat", stale)

        try:
            first.stdin.close()
        except OSError:
            pass
        first.wait(timeout=5)
        with self.assertRaises(acceptance.AcceptanceFailure):
            acceptance.validate_process_generation(first, "/bin/cat", generation)
        with self.assertRaises(acceptance.AcceptanceFailure):
            acceptance.capture_process_generation(first, "/bin/cat")


class _GenerationPopen:
    """A live-or-exited fake Popen identity, never a real process."""

    def __init__(self, pid=54321, exit_code=None):
        self.pid = pid
        self.exit_code = exit_code

    def poll(self):
        return self.exit_code


class _LibprocCall:
    """A callable libproc symbol that accepts prototype attributes."""

    def __init__(self, function):
        self.function = function
        self.argtypes = None
        self.restype = None

    def __call__(self, *args):
        return self.function(*args)


class _GenerationLibproc:
    """Controllable libproc answers for pure generation protocol tests."""

    def __init__(self, path="/bin/cat", uid=None, start_sec=1700000000,
                 start_usec=123, pid=None, info_size=None, path_result=None,
                 error=None):
        self.path = path
        self.uid = os.geteuid() if uid is None else uid
        self.start_sec = start_sec
        self.start_usec = start_usec
        self.pid = pid
        self.info_size = info_size
        self.path_result = path_result
        self.error = error
        self.proc_pidpath = _LibprocCall(self._pidpath)
        self.proc_pidinfo = _LibprocCall(self._pidinfo)

    def _pidpath(self, pid, buffer, size):
        if self.error is not None:
            raise self.error
        if self.path_result is not None:
            return self.path_result
        raw = self.path.encode()
        buffer.value = raw
        return len(raw)

    def _pidinfo(self, pid, flavor, arg, info, size):
        if self.error is not None:
            raise self.error
        buffer = ctypes.cast(info, ctypes.POINTER(ctypes.c_char * size)).contents
        bsd = acceptance._BSDInfo.from_buffer(buffer)
        bsd.pbi_pid = pid if self.pid is None else self.pid
        bsd.pbi_uid = self.uid
        bsd.pbi_start_tvsec = self.start_sec
        bsd.pbi_start_tvusec = self.start_usec
        return size if self.info_size is None else self.info_size


class ProcessGenerationProtocolTests(unittest.TestCase):
    """Pure generation protocol fakes; no real process or libproc authority."""

    class Fatal(BaseException):
        pass

    def capture(self, process, libproc=None, executable="/bin/cat"):
        libproc = _GenerationLibproc() if libproc is None else libproc
        with mock.patch.object(acceptance.ctypes, "CDLL", return_value=libproc):
            return acceptance.capture_process_generation(process, executable)

    def acceptance(self):
        instance = acceptance.Acceptance(__import__("argparse").Namespace(
            cli="/build/locklark", desktop="/bin/cat", timeout=240))
        instance.desktop = pathlib.Path("/bin/cat")
        instance.desktop_process = _GenerationPopen()
        instance.desktop_generation = {
            "pid": instance.desktop_process.pid, "executable": "/bin/cat",
            "euid": os.geteuid(), "start_sec": 1700000000, "start_usec": 123,
        }
        instance.private_bytes = lambda name, raw: None
        return instance

    def test_missing_generation_is_refused_before_any_request(self):
        with self.assertRaises(acceptance.AcceptanceFailure):
            acceptance.validate_process_generation(None, "/bin/cat", None)
        instance = self.acceptance()
        instance.desktop_generation = None
        with self.assertRaises(acceptance.AcceptanceFailure):
            instance.scoped_request([])
        with self.assertRaises(acceptance.AcceptanceFailure):
            instance.activation_request()

    def assert_descriptor_refused_before_authority(self, process, generation):
        with mock.patch.object(acceptance, "capture_process_generation") as capture:
            with self.assertRaises(acceptance.AcceptanceFailure):
                acceptance.validate_process_generation(process, "/bin/cat", generation)
        capture.assert_not_called()

    def test_each_numeric_field_rejects_bool_before_any_authority_read(self):
        base = {"pid": 1, "executable": "/bin/cat", "euid": 0,
                "start_sec": 1, "start_usec": 0}
        process = _GenerationPopen(pid=1)
        for field, value in (("pid", True), ("euid", False),
                             ("start_sec", True), ("start_usec", False)):
            malformed = dict(base)
            malformed[field] = value
            with self.subTest(field=field):
                # bool == the original int, so equality alone cannot catch it.
                self.assertTrue(base == malformed)
                self.assert_descriptor_refused_before_authority(process, malformed)

    def test_each_numeric_field_rejects_float_before_any_authority_read(self):
        base = {"pid": 54321, "executable": "/bin/cat", "euid": os.geteuid(),
                "start_sec": 1700000000, "start_usec": 123}
        process = _GenerationPopen(pid=54321)
        for field in ("pid", "euid", "start_sec", "start_usec"):
            malformed = dict(base)
            malformed[field] = float(base[field])
            with self.subTest(field=field):
                # int == the same-valued float, so equality alone cannot catch it.
                self.assertTrue(base == malformed)
                self.assert_descriptor_refused_before_authority(process, malformed)

    def test_int_and_str_subclasses_are_refused_before_any_authority_read(self):
        class IntSubclass(int):
            pass

        class StrSubclass(str):
            pass

        base = {"pid": 54321, "executable": "/bin/cat", "euid": os.geteuid(),
                "start_sec": 1700000000, "start_usec": 123}
        process = _GenerationPopen(pid=54321)
        for field in ("pid", "euid", "start_sec", "start_usec"):
            malformed = dict(base)
            malformed[field] = IntSubclass(base[field])
            with self.subTest(field=field):
                self.assert_descriptor_refused_before_authority(process, malformed)
        malformed = dict(base)
        malformed["executable"] = StrSubclass("/bin/cat")
        self.assert_descriptor_refused_before_authority(process, malformed)

    def test_executable_rejects_invalid_plain_paths_before_any_authority_read(self):
        base = {"pid": 54321, "executable": "/bin/cat", "euid": os.geteuid(),
                "start_sec": 1700000000, "start_usec": 123}
        process = _GenerationPopen(pid=54321)
        values = (True, 1.0, None, "", "relative", "/bin/../bin/cat",
                  "/bin/cat\x00x", 123,
                  "/bin/" + "x" * (acceptance.MAX_EXECUTABLE + 1))
        for value in values:
            malformed = dict(base)
            malformed["executable"] = value
            with self.subTest(kind=type(value).__name__):
                self.assert_descriptor_refused_before_authority(process, malformed)

    def test_invalid_numeric_ranges_are_refused_before_any_authority_read(self):
        base = {"pid": 54321, "executable": "/bin/cat", "euid": os.geteuid(),
                "start_sec": 1700000000, "start_usec": 123}
        process = _GenerationPopen(pid=54321)
        cases = (("pid", 0), ("pid", -1), ("pid", 0x100000000),
                 ("euid", -1), ("euid", 0x100000000),
                 ("start_sec", 0), ("start_sec", -1),
                 ("start_sec", 0x10000000000000000),
                 ("start_usec", -1), ("start_usec", 1000000))
        for field, value in cases:
            malformed = dict(base)
            malformed[field] = value
            with self.subTest(field=field):
                self.assert_descriptor_refused_before_authority(process, malformed)

    def test_missing_and_extra_keys_are_refused_before_any_authority_read(self):
        base = {"pid": 54321, "executable": "/bin/cat", "euid": os.geteuid(),
                "start_sec": 1700000000, "start_usec": 123}
        process = _GenerationPopen(pid=54321)
        missing = dict(base)
        missing.pop("start_usec")
        malformed = (missing, dict(base, extra=1), [], "generation")
        for generation in malformed:
            with self.subTest(size=len(generation)):
                self.assert_descriptor_refused_before_authority(process, generation)

    def test_cross_process_generation_is_refused(self):
        first = _GenerationPopen(54321)
        second = _GenerationPopen(54322)
        libproc = _GenerationLibproc()
        with mock.patch.object(acceptance.ctypes, "CDLL", return_value=libproc):
            generation = acceptance.capture_process_generation(first, "/bin/cat")
            self.assertTrue(acceptance._generation_descriptor_ok(generation))
            self.assertIsNone(
                acceptance.validate_process_generation(first, "/bin/cat", generation))
            with self.assertRaises(acceptance.AcceptanceFailure):
                acceptance.validate_process_generation(second, "/bin/cat", generation)

    def test_stale_generation_is_refused(self):
        process = _GenerationPopen()
        libproc = _GenerationLibproc()
        with mock.patch.object(acceptance.ctypes, "CDLL", return_value=libproc):
            generation = acceptance.capture_process_generation(process, "/bin/cat")
            self.assertTrue(acceptance._generation_descriptor_ok(generation))
            stale = dict(generation)
            stale["start_usec"] = (generation["start_usec"] + 1) % 1000000
            if stale["start_usec"] == 0:
                stale["start_sec"] += 1
            with self.assertRaises(acceptance.AcceptanceFailure):
                acceptance.validate_process_generation(process, "/bin/cat", stale)

    def test_wrong_executable_euid_exit_and_libproc_failure_are_refused(self):
        process = _GenerationPopen()
        with self.assertRaises(acceptance.AcceptanceFailure):
            self.capture(process, _GenerationLibproc(), "/bin/echo")
        with self.assertRaises(acceptance.AcceptanceFailure):
            self.capture(process, _GenerationLibproc(uid=os.geteuid() + 1))
        with self.assertRaises(acceptance.AcceptanceFailure):
            self.capture(_GenerationPopen(exit_code=0))
        with self.assertRaises(acceptance.AcceptanceFailure):
            self.capture(process, _GenerationLibproc(info_size=0))
        with self.assertRaises(acceptance.AcceptanceFailure):
            self.capture(process, _GenerationLibproc(path_result=0))
        with self.assertRaises(acceptance.AcceptanceFailure):
            self.capture(process, _GenerationLibproc(error=self.Fatal()))

    def test_scoped_and_activation_requests_carry_the_captured_generation(self):
        instance = self.acceptance()
        generation = dict(instance.desktop_generation)
        with mock.patch.object(acceptance, "validate_process_generation"):
            scoped = json.loads(instance.scoped_request([]))
            activation = json.loads(instance.activation_request())
        self.assertEqual(scoped["owned_generation"], generation)
        self.assertEqual(activation["owned_generation"], generation)
        self.assertEqual(scoped["owned_pid"], instance.desktop_process.pid)
        self.assertEqual(activation["activate_pid"], instance.desktop_process.pid)

    def test_driver_validates_before_then_runs_then_validates_after(self):
        instance = self.acceptance()
        events = []
        same = []

        def validate(process, executable, generation):
            same.append((process is instance.desktop_process,
                         generation == instance.desktop_generation))
            events.append("post" if "run" in events else "pre")

        def run(*args, **kwargs):
            events.append("run")
            return subprocess.CompletedProcess([], 0, b"{}\n", b"")

        with mock.patch.object(acceptance, "validate_process_generation",
                               side_effect=validate), \
                mock.patch.object(acceptance.subprocess, "run", side_effect=run):
            self.assertEqual(instance.run_driver(b"{}"), {})
        self.assertEqual(events, ["pre", "run", "post"])
        self.assertEqual(same, [(True, True), (True, True)])

    def test_pre_validation_failure_prevents_the_driver_call(self):
        instance = self.acceptance()
        runner = mock.Mock()
        with mock.patch.object(acceptance, "validate_process_generation",
                               side_effect=acceptance.AcceptanceFailure), \
                mock.patch.object(acceptance.subprocess, "run", runner):
            with self.assertRaises(acceptance.AcceptanceFailure):
                instance.run_driver(b"{}")
        runner.assert_not_called()

    def test_post_validation_failure_refuses_after_the_call(self):
        instance = self.acceptance()
        calls = []

        def validate(*args):
            calls.append(1)
            if len(calls) == 2:
                raise acceptance.AcceptanceFailure()

        runner = mock.Mock(return_value=subprocess.CompletedProcess(
            [], 0, b"{}\n", b""))
        with mock.patch.object(acceptance, "validate_process_generation",
                               side_effect=validate), \
                mock.patch.object(acceptance.subprocess, "run", runner):
            with self.assertRaises(acceptance.AcceptanceFailure):
                instance.run_driver(b"{}")
        self.assertEqual(len(calls), 2)
        runner.assert_called_once()

    def test_cleanup_clears_the_generation(self):
        instance = self.acceptance()
        instance.desktop_process = _GenerationPopen(exit_code=0)
        instance.close()
        self.assertIsNone(instance.desktop_generation)
        self.assertIsNone(instance.desktop_process)


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
