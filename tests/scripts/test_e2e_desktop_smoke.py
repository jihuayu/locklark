"""Regression tests for the locked-desktop startup smoke launch.

``support.desktop_binary_starts`` used to pass the retired ``--file`` option,
so the T1 F5/F7/F8 smoke exited 2 before any GUI. These tests pin the helper
to the desktop's only command line, ``--settings ABSOLUTE_PATH``, without
building Go, starting a GUI or touching any cached product artifact: the real
helper is spawned against an executable stand-in inside a throwaway context.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tests.e2e import harness, support  # noqa: E402

# The stand-in records exactly what it was launched with, then stays alive like
# the GUI would. It still honours SIGTERM so an abandoned group stays visible.
# Consumers may append statements that run once (before the loop).
_STAND_IN = (
    "import json, os, signal, sys, time\n"
    "signal.signal(signal.SIGTERM, lambda signum, frame: sys.exit(3))\n"
    "with open(sys.argv[1], 'w', encoding='utf-8') as handle:\n"
    "    json.dump({'argv': sys.argv[2:], 'environ': dict(os.environ), 'pid': os.getpid()}, handle)\n"
)

_FORBIDDEN_IN_ARGV = ("--file", "--settings=")

# Keys that name a login factor or a path; ``security.revealPasswords`` is a
# display preference and ``app.defaultVaultForSaving`` a bounded empty save
# target, neither of which binds anything.
_FORBIDDEN_SETTING_KEY = re.compile(r"(?i)secret|password|private|file")
_DISPLAY_ONLY_SETTINGS = {"security.revealPasswords"}

# Keys the desktop schema in internal/desktop/settings.go declares. The smoke
# document must match them exactly so a schema drift shows up here.
_SCHEMA_KEYS = {
    "security.autolock.minutes",
    "security.clipboard.clearAfterSeconds",
    "security.autolock.onSleep",
    "security.autolock.onDeviceLock",
    "security.autolock.onWindowClose",
    "security.revealPasswords",
    "privacy.checkHibp",
    "appearance.theme",
    "appearance.interfaceDensity",
    "app.keepInTray",
    "app.defaultVaultForSaving",
}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _without_docstrings(source: str) -> str:
    """Drop module/function docstrings so prose mentions never count as code."""

    return re.sub(r'"""(.|\n)*?"""', "", source)


def _alive(pid: int) -> bool:
    """True while ``pid`` is a live, non-zombie process we may inspect."""

    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    stat_path = Path(f"/proc/{pid}/stat")
    if stat_path.is_file():
        try:
            return stat_path.read_text().rsplit(")", 1)[1].split()[0] != "Z"
        except (OSError, IndexError):
            return True
    try:
        # Zombies on hosts without procfs cannot be reaped by us; waitpid only
        # succeeds for our own children.
        return os.waitpid(pid, os.WNOHANG) == (0, 0)
    except ChildProcessError:
        return True


class DesktopSmokeFixture(unittest.TestCase):
    """A throwaway context whose desktop binary is a test stand-in."""

    SECONDS = 1.0

    def setUp(self) -> None:
        self.temp_dir = self._mkdtemp()
        os.chmod(self.temp_dir, 0o700)
        self.bin_dir = self._mkdtemp()
        self.record = self.temp_dir / "stand-in-record.json"
        self.executed = self.temp_dir / "stand-in-executions"
        self.vault = self.temp_dir / "target-vault.ll"
        self.vault.write_bytes(b"synthetic locked vault fixture\n")
        self.desktop = self._install_stand_in()
        self.ctx = SimpleNamespace(
            repo_root=ROOT,
            bin_dir=self.bin_dir,
            temp_dir=self.temp_dir,
            desktop_bin=self.desktop,
        )
        # A fake GUI session: no Xvfb, no D-Bus, no display. The helper still
        # runs its real settings writing, spawn and teardown code.
        patcher = mock.patch.object(
            support, "owned_gui_command", lambda target, **_: [str(part) for part in target]
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def _mkdtemp(self) -> Path:
        directory = Path(tempfile.mkdtemp(prefix="ll-desktop-smoke-"))
        os.chmod(directory, 0o700)
        self.addCleanup(shutil.rmtree, directory, ignore_errors=True)
        return directory

    def _install_stand_in(self) -> Path:
        script = self.temp_dir / "stand-in-desktop.py"
        script.write_text(
            _STAND_IN
            + "def _keep_running():\n"
            "    while True:\n"
            "        time.sleep(0.05)\n"
            "_keep_running()\n",
            encoding="utf-8",
        )
        binary = self.temp_dir / "locklark-desktop"
        binary.write_text(
            '#!/bin/sh\n'
            f'printf "%s\\n" "$$" >> {shlex.quote(str(self.executed))}\n'
            f'exec {shlex.quote(sys.executable)} {shlex.quote(str(script))} '
            f"{shlex.quote(str(self.record))} \"$@\"\n",
            encoding="utf-8",
        )
        binary.chmod(0o700)
        return binary

    def launch(self, vault: Path | None = None, seconds: float | None = None) -> bool:
        window = self.SECONDS if seconds is None else seconds
        return support.desktop_binary_starts(self.ctx, vault or self.vault, seconds=window)

    def record_of_launch_count(self) -> int:
        if not self.executed.is_file():
            return 0
        return len(self.executed.read_text(encoding="utf-8").split())

    def record_of_last_launch(self) -> dict:
        if not self.record.is_file():
            self.fail("the stand-in desktop recorded no launch")
        return json.loads(self.record.read_text(encoding="utf-8"))


class SpawnArgvTests(DesktopSmokeFixture):
    """The helper must spawn the supported command line and nothing else."""

    def test_live_locked_desktop_is_a_startup_smoke(self):
        self.assertTrue(self.launch())
        recorded = self.record_of_last_launch()
        self.assertEqual(recorded["argv"][0], "--settings")
        self.assertEqual(len(recorded["argv"]), 2)
        self.assertEqual(recorded["argv"], support.desktop_argv(Path(recorded["argv"][1])))

    def test_retired_file_option_never_reaches_argv(self):
        self.assertTrue(self.launch())
        argv = self.record_of_last_launch()["argv"]
        for forbidden in (*_FORBIDDEN_IN_ARGV, str(self.vault), support.DESKTOP_VAULT_SENTINEL):
            self.assertNotIn(forbidden, argv)
        self.assertNotIn("--file", " ".join(argv))

    def test_only_the_stand_in_was_executed(self):
        self.assertTrue(self.launch())
        pids = self.executed.read_text(encoding="utf-8").split()
        self.assertEqual(len(pids), 1, "the helper must spawn the desktop exactly once")
        # The stand-in wrap child already exited; only its exec'd replacement
        # may have been alive during the window, and teardown must reap it.
        recorded = self.record_of_last_launch()
        self.assertFalse(_alive(recorded["pid"]), "owned desktop process outlived the smoke")

    def test_usage_refusal_is_a_visible_failure(self):
        # Exit 2 is the desktop's fixed argument refusal and must surface as
        # an AssertionError from the helper's launch, not as a later failure.
        fast = self.temp_dir / "locklark-desktop-fast"
        fast.write_text("#!/bin/sh\nexit 2\n", encoding="utf-8")
        fast.chmod(0o700)
        self.ctx.desktop_bin = fast
        with self.assertRaisesRegex(AssertionError, "desktop refused its smoke argv"):
            self.launch()
        # Exit 2 is never mistaken for a live desktop.
        self.assertEqual(self.record_of_launch_count(), 0)

    def test_missing_target_vault_is_refused_before_spawning(self):
        with self.assertRaisesRegex(AssertionError, "does not exist"):
            self.launch(self.temp_dir / "absent.ll")
        self.assertFalse(self.executed.exists(), "no desktop may spawn for a missing vault")

    def test_target_vault_outside_the_private_root_is_refused_before_spawning(self):
        outside = Path(tempfile.mkdtemp(prefix="ll-desktop-outside-"))
        self.addCleanup(shutil.rmtree, outside, ignore_errors=True)
        vault = outside / "vault.ll"
        vault.write_bytes(b"outside\n")
        with self.assertRaisesRegex(AssertionError, "outside the private fixture root"):
            self.launch(vault)
        self.assertFalse(self.executed.exists(), "no desktop may spawn for an outside vault")


class PrivateSettingsTests(DesktopSmokeFixture):
    """The explicit settings file is private and outside HOME/XDG/CODEX_HOME."""

    def test_bound_settings_are_private_and_inside_the_context(self):
        self.assertTrue(self.launch())
        bound = Path(self.record_of_last_launch()["argv"][1])
        self.assertTrue(bound.is_absolute())
        self.assertEqual(str(bound), os.path.normpath(str(bound)))
        self.assertEqual(bound.parent, self.temp_dir / "desktop-smoke")
        self.assertTrue(bound.is_file() and not bound.is_symlink())
        self.assertEqual(stat.S_IMODE(bound.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(bound.parent.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(bound.parent.parent.stat().st_mode), 0o700)

    def test_settings_document_matches_the_desktop_schema_without_a_vault(self):
        self.assertTrue(self.launch())
        bound = Path(self.record_of_last_launch()["argv"][1])
        document = json.loads(bound.read_text(encoding="utf-8"))
        self.assertEqual(set(document), _SCHEMA_KEYS)
        self.assertEqual(document, dict(support.DESKTOP_SMOKE_SETTINGS))
        self.assertEqual(document["app.defaultVaultForSaving"], "")
        for key, value in document.items():
            if key not in _DISPLAY_ONLY_SETTINGS and key != "app.defaultVaultForSaving":
                self.assertNotRegex(key, _FORBIDDEN_SETTING_KEY)
            if isinstance(value, str):
                self.assertFalse(os.path.isabs(value), f"{key} carries an absolute path")
                self.assertNotIn(str(self.vault), value)
        # Bounded integer units from the product's own ValidateSettings.
        self.assertGreaterEqual(document["security.autolock.minutes"], 0)
        self.assertLessEqual(document["security.autolock.minutes"], 480)
        self.assertGreaterEqual(document["security.clipboard.clearAfterSeconds"], 0)
        self.assertLessEqual(document["security.clipboard.clearAfterSeconds"], 3600)
        self.assertIn(document["appearance.theme"], ("system", "light", "dark"))
        self.assertIn(document["appearance.interfaceDensity"], ("comfortable", "compact"))

    def test_settings_do_not_override_home_xdg_or_codex_home(self):
        env_names = (
            "HOME",
            "XDG_CONFIG_HOME",
            "XDG_DATA_HOME",
            "XDG_STATE_HOME",
            "XDG_CACHE_HOME",
            "CODEX_HOME",
        )
        marker = {name: os.environ.get(name, "") for name in env_names}
        self.assertTrue(self.launch())
        environ = self.record_of_last_launch()["environ"]
        for name in env_names:
            self.assertEqual(environ.get(name, ""), marker[name], f"launch overrode {name}")
        self.assertEqual(environ.get("TMPDIR"), str(self.temp_dir))
        # And the smoke wrote nothing into any of those directories.
        for name, value in marker.items():
            if not value:
                continue
            target = Path(value)
            if not target.is_dir():
                continue
            with self.subTest(variable=name):
                self.assertFalse(
                    (target / "desktop-smoke").exists(), f"smoke wrote under {name}"
                )

    def test_global_settings_path_is_never_bound(self):
        with mock.patch.object(
            support, "desktop_smoke_settings", wraps=support.desktop_smoke_settings
        ) as writer:
            self.assertTrue(self.launch())
        writer.assert_called_once_with(self.ctx)
        bound = Path(self.record_of_last_launch()["argv"][1])
        self.assertTrue(str(bound).startswith(str(self.temp_dir) + os.sep))


class LifecycleAndVaultTests(DesktopSmokeFixture):
    """The original liveness/cleanup contract stays and the vault is untouched."""

    SECONDS = 0.5

    def test_passing_smoke_leaves_no_owned_process_behind(self):
        self.assertTrue(self.launch())
        recorded = self.record_of_last_launch()
        self.assertFalse(_alive(recorded["pid"]), "teardown abandoned the owned group")
        pids = self.executed.read_text(encoding="utf-8").split()
        self.assertEqual(len(pids), 1)
        if Path("/proc").is_dir():
            needle = str(self.record).encode()
            leftovers = []
            for entry in Path("/proc").iterdir():
                if not entry.name.isdigit():
                    continue
                try:
                    cmdline = (entry / "cmdline").read_bytes().split(b"\0")
                except OSError:
                    continue
                if needle in cmdline:
                    leftovers.append(entry.name)
            self.assertEqual(leftovers, [], "a smoke process survived in the owned group")

    def test_two_runs_bind_the_same_contract_independently(self):
        self.assertTrue(self.launch())
        first = self.record_of_last_launch()["argv"]
        self.assertTrue(self.launch())
        second = self.record_of_last_launch()["argv"]
        self.assertEqual(first, second)
        self.assertEqual(len(self.executed.read_text(encoding="utf-8").split()), 2)

    def test_locked_smoke_does_not_mutate_the_target_vault(self):
        before = _sha256(self.vault)
        self.assertTrue(self.launch())
        self.assertEqual(_sha256(self.vault), before)

    def test_early_exit_is_false_not_a_liveness_pass(self):
        # A desktop that stops during the window (other than the exit-2 usage
        # refusal) fails the liveness smoke without raising.
        quick = self.temp_dir / "locklark-desktop-quick"
        quick.write_text("#!/bin/sh\nexec true\n", encoding="utf-8")
        quick.chmod(0o700)
        self.ctx.desktop_bin = quick
        self.assertFalse(self.launch(seconds=1.0), "a quick exit was reported as alive")


class ProductContractTests(unittest.TestCase):
    """The product parser is untouched; its strict refusal stays with root."""

    def _desktop_sources(self) -> str:
        paths = sorted((ROOT / "internal" / "desktop").glob("*.go"))
        paths = [path for path in paths if not path.name.endswith("_test.go")]
        self.assertTrue(paths)
        return "\n".join(path.read_text(encoding="utf-8") for path in paths)

    def test_helper_source_carries_the_supported_command_line_only(self):
        source = (ROOT / "tests" / "e2e" / "support.py").read_text(encoding="utf-8")
        start = source.index("def desktop_binary_starts")
        body = source[start : source.index("\ndef ", start + 1)]
        self.assertNotIn("--file", _without_docstrings(body))
        self.assertIn("*desktop_argv(settings)", body)
        # The original lifecycle contract is kept verbatim.
        self.assertIn("terminate_process_group(process, grace=3.0, owned_group=process.pid)", body)
        self.assertIn("start_new_session=True", body)
        argv = support.desktop_argv(Path("/tmp/private/settings.json"))
        self.assertEqual(argv, ["--settings", "/tmp/private/settings.json"])
        self.assertEqual(
            support.DESKTOP_SETTINGS_USAGE,
            "usage: locklark-desktop [--settings ABSOLUTE_PATH]",
        )

    def test_product_still_advertises_only_the_settings_argument(self):
        source = self._desktop_sources()
        usage = re.search(r'desktopSettingsUsage\s*=\s*"([^"]+)"', source)
        self.assertIsNotNone(usage, "the desktop usage constant moved")
        self.assertEqual(usage.group(1), support.DESKTOP_SETTINGS_USAGE)
        self.assertEqual(source.count('"--settings"'), 1, "the desktop grew a second option spelling")
        self.assertNotRegex(source, r'args\[0\]\s*==\s*"--file"|"--file"\s*,')
        # The settings schema has no vault/login path, so settings cannot
        # select or unlock one: these keys are introspected by the product
        # tests run with the same CI artifact, not rebuilt here.
        declared = set(re.findall(r'json:"([^",]+)"', source)) - {"-"}
        self.assertEqual(declared, _SCHEMA_KEYS)

    def test_tier1_smoke_calls_keep_the_locked_startup_scope(self):
        regression = (ROOT / "tests" / "e2e" / "tier1_f01_f08.py").read_text(encoding="utf-8")
        for test_id in ("t1_f5_01", "t1_f5_02", "t1_f7_01", "t1_f8_01"):
            start = regression.index(f"def {test_id}(")
            end = regression.index("\n@e2e_test", start)
            body = regression[start:end]
            self.assertIn("desktop_binary_starts(ctx, vault[\"path\"])", body)
            self.assertIn("Locked-desktop startup smoke", body)
        # No desktop invocation passes the retired option; the CLI's own
        # `personal ... --file` calls are a different product surface.
        self.assertNotRegex(
            _without_docstrings(regression),
            r"desktop_binary_starts\([^)]*--file|--file\W+str\(ctx\.desktop_bin",
        )

    def test_no_desktop_smoke_tier_case_is_registered(self):
        from tests.e2e import tier1_f01_f08  # noqa: F401  (registers its cases)

        ids = {spec.test_id for spec in harness.get_registered_tests()}
        self.assertEqual(
            [test_id for test_id in ids if "DESKTOP_SMOKE" in test_id], []
        )
        for test_id in ("T1_F5_01", "T1_F5_02", "T1_F7_01", "T1_F8_01"):
            self.assertIn(test_id, ids)


if __name__ == "__main__":
    unittest.main()
