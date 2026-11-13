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
import queue
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
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
# Only the fixed keys the fixture inspects are recorded -- HOME, the four XDG
# base directories, CODEX_HOME and TMPDIR -- never the rest of the parent's
# environment; a recording that does not carry one of those exact values is
# reported as ``repr(value)`` instead, so a missing or altered key is visible.
# The record is created 0600 (the parent umask could only make it stricter).
# Consumers may append statements that run once (before the loop).
_STAND_IN_KEYS = (
    "HOME",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_STATE_HOME",
    "XDG_CACHE_HOME",
    "CODEX_HOME",
    "TMPDIR",
)

# The same fixed keys in the test process. ``HOME``, ``XDG_*`` and
# ``CODEX_HOME`` are named explicitly; ``TMPDIR`` is the shared stand-in key
# whose parent value is normally unset. The stand-in is rendered from this
# tuple so the two spellings cannot drift.
_RECORDED_ENV = (
    "HOME",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_STATE_HOME",
    "XDG_CACHE_HOME",
    "CODEX_HOME",
    *_STAND_IN_KEYS[_STAND_IN_KEYS.index("TMPDIR") :],
)
_STAND_IN = (
    "import json, os, signal, sys, time\n"
    "signal.signal(signal.SIGTERM, lambda signum, frame: sys.exit(3))\n"
    "record = json.dumps({'argv': sys.argv[2:], 'environ': {name: (value if "
    "isinstance(value := os.environ.get(name), str) else repr(value)) "
    "for name in _RECORDED_ENV}, 'pid': os.getpid()})\n"
    "fd = os.open(sys.argv[1], os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)\n"
    "try:\n"
    "    while record:\n"
    "        record = record[os.write(fd, record.encode('utf-8')):]\n"
    "    os.fsync(fd)\n"
    "finally:\n"
    "    os.close(fd)\n"
)

# Bytes the stand-in writes into its own synthetic vault once the harness
# releases it. They differ from the fixture bytes, so a real change is visible.
_VAULT_BYTES = b"synthetic locked vault fixture\n"
_MUTATION = b"mutated by the stand-in desktop\n"

# The seeded stand-in proves it was spawned by the helper (its parent is the
# harness process, which the helper starts as a new session leader; anything
# else only exits with a fixed status). A foreign launch must never signal a
# process group it does not own: the pid it reports is not a group the test
# may kill, so no cleanup may depend on ``killpg`` here. It then reads the
# ``--settings`` file it was launched with, so the helper has already taken its
# ``before`` digest, and reports on stdout; the harness turns that into a nudge
# file. Only then does it rewrite its own vault, report ``mutated``/``alive``
# and ``exec`` the plain stand-in, which keeps running until teardown. Reports
# go out one at a time with ``os.write`` so no stdio buffer can hold one back.
# Its only wait is the nudge: it re-checks for the file every 0.01s until it
# appears (bounded by the helper's own window and teardown, never by the test).
# ``_OWNED_EXIT`` is the status both the session check and the vault rewrite's
# ownership check use. ``_harness_pid``, ``_nudge``, ``_vault_path`` and
# ``_launch_argv`` are filled in by the test.
_OWNED_EXIT = 78
_MUTATING_STAND_IN = f"""
# argv is [record, "--settings", path]; splice in the vault after the record.
_launch_argv.insert(1, _vault_path[0])
_vault = _launch_argv[1]
if os.getppid() != _harness_pid or os.getsid(0) != os.getpid():
    os._exit({_OWNED_EXIT})
with open(sys.argv[3], "r", encoding="utf-8") as _settings:
    json.load(_settings)
os.write(1, b"launch " + str(os.getpid()).encode() + b"\\n")
while not os.path.exists(_nudge[0]):
    time.sleep(0.01)
# Ownership again right before the write, without a group signal: only the
# helper's own session (and this process as its leader) may reach the vault.
if os.getppid() != _harness_pid or os.getsid(0) != os.getpid():
    os._exit({_OWNED_EXIT})
with open(_vault, "r+b") as _vault_file:
    _vault_file.seek(0)
    _vault_file.truncate()
    _vault_file.write({_MUTATION!r})
    _vault_file.flush()
    os.fsync(_vault_file.fileno())
os.write(1, b"mutated\\n")
os.write(1, b"alive\\n")
os.execv(sys.executable, [sys.executable] + list(_launch_argv))
"""

_FORBIDDEN_IN_ARGV = ("--file", "--settings=")

# The helper's fixed error once the vault changed. The helper keeps the two
# digest facts apart (during the window vs. after teardown) and names the
# vault; the test pins exactly that fixed shape.
_MUTATION_ERROR = (
    "desktop smoke mutated the target vault (during the window and/or "
    "after its owned session was terminated and reaped; pre={pre} post={post}): {vault}"
)

# Everything the helper may change in the launch environment: ``TMPDIR`` is
# redirected to the private root. Nothing else is added, dropped or overridden.
_FIXED_ENVIRON_DELTA = {"TMPDIR"}


def _parent_environ() -> dict[str, str]:
    return dict(os.environ)


def env_names_kept() -> tuple[str, ...]:
    """The fixed keys whose parent value must reach the launch unchanged."""

    return tuple(name for name in _RECORDED_ENV if name not in _FIXED_ENVIRON_DELTA)


def _recorded_environ() -> dict[str, str]:
    """The fixed keys as the parent (test) process holds them, same spelling."""

    return {
        name: _fixed_value(os.environ.get(name))
        for name in _RECORDED_ENV
    }


def _fixed_value(value: str | None) -> str:
    return value if isinstance(value, str) else repr(value)


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def _contract_facts(argv: list[str], root: Path) -> dict:
    """The launch-independent facts of one recorded argv, problems included.

    Separated from the randomized settings file name, so two independent runs
    can be compared for identical contract without demanding the same path.
    An unexpected argv is reported as a problem, never raised out of here.
    """

    problems: list[str] = []
    bound: Path | None = None
    document: dict | None = None
    if len(argv) != 2 or argv[0] != "--settings" or argv.count("--settings") != 1:
        problems.append(f"argv is not exactly --settings ABSOLUTE_PATH: {argv!r}")
    else:
        bound = Path(argv[1])
        if not bound.is_absolute() or os.path.normpath(str(bound)) != str(bound):
            problems.append(f"settings path is not absolute and clean: {bound}")
        if str(bound).startswith(str(root) + os.sep) and bound.is_relative_to(root):
            if bound.parent != root / "desktop-smoke":
                problems.append(f"settings file is not in the private smoke dir: {bound}")
            if not bound.is_file() or bound.is_symlink():
                problems.append(f"settings file is not a regular file: {bound}")
            else:
                if _mode(bound) != 0o600:
                    problems.append(f"settings file mode {_mode(bound):o} != 600")
                for parent in (bound.parent, bound.parent.parent):
                    if _mode(parent) != 0o700:
                        problems.append(f"{parent.name} mode {_mode(parent):o} != 700")
                document = json.loads(bound.read_text(encoding="utf-8"))
                if document != dict(support.DESKTOP_SMOKE_SETTINGS):
                    problems.append("settings values differ from the smoke defaults")
        else:
            problems.append(f"settings file is outside the private root: {bound}")
    return {
        "option": argv[0] if argv else None,
        "argument_count": len(argv),
        "parent": bound.parent.relative_to(root) if bound and bound.is_relative_to(root) else None,
        "available": bound is not None and bound.is_file(),
        "document": document,
        "problems": problems,
    }


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


# How long a worker thread gets to observably finish before the test reports
# it: one first join (polling ``is_alive``) and, only if that failed, one
# bounded reap that also joins the report queue so it can say why.
_WORKER_FIRST_WAIT = 60.0
_WORKER_REAP = 10.0
_WORKER_TICK = 0.05


def _await_thread(test_case: unittest.TestCase, worker: threading.Thread, what: str) -> None:
    """Prove ``worker`` finished, bounded: ``join() is None`` is not proof.

    ``Thread.join`` returns ``None`` whether the thread ended or timed out, so
    completion is read from ``is_alive`` while waiting up to
    ``_WORKER_FIRST_WAIT``; one failed thread is then reaped within
    ``_WORKER_REAP``, and either exit is reported as a test failure instead of
    wedging the module in an unbounded join.
    """

    if not _wait_until_dead(worker, _WORKER_FIRST_WAIT):
        _wait_until_dead(worker, _WORKER_REAP)
        test_case.fail(f"{what} was still alive {_WORKER_FIRST_WAIT + _WORKER_REAP:g}s after launch")
    if worker.is_alive():  # cannot be true after a dead read; kept explicit
        test_case.fail(f"{what} was not reaped")


def _wait_until_dead(worker: threading.Thread, window: float) -> bool:
    """Wait until ``worker`` reports not alive; completion is read, not slept in.

    ``join(timeout)`` returns once the thread ended (``is_alive`` false) or the
    slice elapsed; the read of ``is_alive`` is what decides, and the deadline
    only bounds the wait, so a finished thread is never waited on further.
    """

    deadline = time.monotonic() + window
    while worker.is_alive():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        worker.join(min(remaining, _WORKER_TICK))
    return not worker.is_alive()


class DesktopSmokeFixture(unittest.TestCase):
    """A throwaway context whose desktop binary is a test stand-in."""

    SECONDS = 1.0

    def setUp(self) -> None:
        self.temp_dir = self._mkdtemp()
        os.chmod(self.temp_dir, 0o700)
        self.bin_dir = self._mkdtemp()
        # One private record per stand-in install; it always holds the JSON of
        # that install's latest launch, so the fixture can read back the
        # launch it just made even if the helper was called earlier.
        self.records: list[Path] = []
        self.installs = 0
        self.executed = self.temp_dir / "stand-in-executions"
        self.vault = self.temp_dir / "target-vault.ll"
        self.vault.write_bytes(_VAULT_BYTES)
        self.desktop = self._install_stand_in()
        self.ctx = SimpleNamespace(
            repo_root=ROOT,
            bin_dir=self.bin_dir,
            temp_dir=self.temp_dir,
            desktop_bin=self.desktop,
        )
        # Every report a stand-in writes to its stdout, by first word. The
        # helper's stdout redirect is a fixed part of its argv contract;
        # ``_observe`` carries the same real spawn out with a pipe instead,
        # without mocking anything downstream of it.
        self.scrapers: list[threading.Thread] = []
        # Scrapers started so far; ``_drained_scrapers`` counts the ones whose
        # pipe is proven finished, so a reports read waits only for new ones.
        self.scrapers_started = 0
        self.scrapers_drained = 0
        self.reports: dict[str, str] = {}
        self.nudge = self.temp_dir / "stand-in-nudge"
        self.launched_pid = self.temp_dir / "stand-in-pid"
        # A fake GUI session: no Xvfb, no D-Bus, no display. The helper still
        # runs its real settings writing, spawn and teardown code.
        patcher = mock.patch.object(
            support, "owned_gui_command", lambda target, **_: [str(part) for part in target]
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        real_popen = support.subprocess.Popen
        # The wrapper only adds stdout capturing: a ``side_effect`` would turn
        # every call (and its keyboard-interrupt handling) into a MagicMock,
        # so exactly this attribute set is replaced and put back.
        observer = mock.patch.object(
            support.subprocess, "Popen", new=self._observe(real_popen)
        )
        observer.start()
        self.addCleanup(observer.stop)
        # Fallback only: tests that read ``reports`` drain first; this bounds
        # a collector left running by a test that failed before doing so.
        self.addCleanup(self._wait_for_scrapers)

    def _wait_for_scrapers(self) -> None:
        """Bounded proof that no started collector is still filling ``reports``.

        Each collector ends on its pipe's EOF (the owned group is gone by then)
        and is proven with ``is_alive``, never assumed; one that does not end is
        reported -- so neither a read of ``reports`` nor the next test's cleanup
        can race a still-running scraper -- and the ones proven done are not
        waited on again.
        """

        while self.scrapers_drained < self.scrapers_started:
            scraper = self.scrapers[self.scrapers_drained]
            if not _wait_until_dead(scraper, 5.0):
                self.fail("a stdout collector outlived its desktop's pipe")
            if scraper.is_alive():  # cannot be true after a dead read; kept explicit
                self.fail("a stdout collector was not proven finished")
            self.scrapers_drained += 1

    def drained_reports(self) -> dict[str, str]:
        """``reports`` only after every collector started so far is proven done."""

        self._wait_for_scrapers()
        return dict(self.reports)

    def _observe(self, real_popen):
        """Pipe stdout only for the helper's own desktop spawn.

        The patch sees every ``Popen`` on the module while the test runs,
        including other harness launches and teardown. Anything but the
        helper's exact invocation -- the one the smoke context installs,
        owning a new session, ``cwd`` at the private root, stdin null, exactly
        ``--settings ABSOLUTE_PATH`` pointing into the private root -- is
        carried out untouched, so no cleanup or other spawn gets a pipe the
        fixture would have to drain.
        """

        def popen(command, **kwargs):
            if not self._is_desktop_spawn(command, kwargs):
                return real_popen(command, **kwargs)
            # Pin the helper's own values first: the patch replaces the module
            # attribute the helper reads, so comparisons must use locals.
            null = kwargs.get("stdin")
            self.assertIs(kwargs.get("stdout"), null)
            self.assertIs(kwargs.get("stderr"), null)
            self.assertTrue(kwargs.get("start_new_session"))
            # Only stdout becomes a pipe, which is what a real GUI session does
            # to the desktop's log; every other spawn argument is untouched.
            process = real_popen(command, **{**kwargs, "stdout": subprocess.PIPE})
            scraper = threading.Thread(
                target=self._scrape, args=(process.stdout,), daemon=True
            )
            self.scrapers.append(scraper)
            self.scrapers_started += 1
            scraper.start()
            # The helper's contract never handles stdout, and the collector
            # owns the pipe from here (closing it once the child is gone).
            process.stdout = None
            return process

        return popen

    def _is_desktop_spawn(self, command, kwargs) -> bool:
        # ``owned_gui_command`` may wrap the target, so the shape is checked at
        # the end of the command: the two arguments of the smoke, with an
        # absolute, clean settings path inside the private fixture root.
        parts = command if isinstance(command, (list, tuple)) else [command]
        parts = [os.fspath(part) for part in parts]
        if parts[-3:-1] != [os.fspath(self.ctx.desktop_bin), "--settings"]:
            return False
        bound = Path(parts[-1])
        if not bound.is_absolute() or os.path.normpath(str(bound)) != str(bound):
            return False
        root = os.path.realpath(self.ctx.temp_dir)
        if os.path.commonpath([root, os.path.realpath(bound)]) != root:
            return False
        if kwargs.get("stdin") is not subprocess.DEVNULL or not kwargs.get("start_new_session"):
            return False
        return os.path.realpath(str(kwargs.get("cwd") or "")) == root

    def _scrape(self, stream) -> None:
        try:
            self._collect(stream)
        finally:
            stream.close()

    def _collect(self, stream) -> None:
        for line in iter(stream.readline, b""):
            head, _, rest = line.decode("utf-8", "replace").strip().partition(" ")
            self.reports.setdefault(head, rest)
            if head == "launch":
                # Private 0600 files of their own: the nudge releases the
                # seeded stand-in's rewrite, and the pid lets the test prove
                # the group was owned without relying on the live record. Both
                # are created 0600 at creation (``os.open`` mode is applied by
                # the kernel, bounded by the umask), never widened by a later
                # ``chmod`` of an already-readable file.
                _private_fd = os.open(
                    self.nudge, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600
                )
                os.close(_private_fd)
                _private_fd = os.open(
                    self.launched_pid, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600
                )
                try:
                    _written = os.write(_private_fd, rest.encode("utf-8"))
                    if _written != len(rest.encode("utf-8")):
                        raise OSError(f"short pid write: {_written} bytes")
                finally:
                    os.close(_private_fd)

    def _mkdtemp(self) -> Path:
        directory = Path(tempfile.mkdtemp(prefix="ll-desktop-smoke-"))
        os.chmod(directory, 0o700)
        self.addCleanup(shutil.rmtree, directory, ignore_errors=True)
        return directory

    def _install_stand_in(self, seed: str = "") -> Path:
        # Every install is a new executable path, so the Popen observer below
        # pipes the launch under test and never a stand-in installed earlier.
        self.installs = getattr(self, "installs", 0) + 1
        install = self.installs
        script = self.temp_dir / f"stand-in-desktop-{install}.py"
        script.write_text(
            f"_RECORDED_ENV = {list(_RECORDED_ENV)!r}\n"
            + _STAND_IN
            + seed
            + "def _keep_running():\n"
            "    while True:\n"
            "        time.sleep(0.05)\n"
            "_keep_running()\n",
            encoding="utf-8",
        )
        binary = self.temp_dir / f"locklark-desktop-{install}"
        record = self.temp_dir / f"stand-in-record-{install}.json"
        self.records.append(record)
        binary.write_text(
            '#!/bin/sh\n'
            f'printf "%s\\n" "$$" >> {shlex.quote(str(self.executed))}\n'
            f'exec {shlex.quote(sys.executable)} {shlex.quote(str(script))} '
            f"{shlex.quote(str(record))} \"$@\"\n",
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
        """The record of the launch just made, read from the current stand-in."""

        # ``records`` has one entry per *install*, but a record is rewritten
        # (truncated) by each launch of its stand-in, so it can only be mapped
        # by the install whose path is current -- never by launch count, which
        # has no entry of its own once a binary launches twice. The record's
        # pid must also still be the last launch the shim executed.
        if self.record_of_launch_count() == 0:
            self.fail("the stand-in desktop recorded no launch")
        current = self.records[self.installs - 1]
        if not current.is_file():
            self.fail(f"the current stand-in desktop recorded no launch: {current.name}")
        recorded = json.loads(current.read_text(encoding="utf-8"))
        last = int(self.executed.read_text(encoding="utf-8").split()[-1])
        if recorded.get("pid") != last:
            self.fail(
                f"the current stand-in's record is not its last launch "
                f"(recorded pid {recorded.get('pid')!r}, launched pid {last})"
            )
        return recorded


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
        # The stand-in reports only the seven fixed keys: the launch carries
        # the parent's HOME, XDG_*, CODEX_HOME and every other variable
        # untouched, and only redirects TMPDIR to the private root. The
        # parent's settings file is 0600 in a 0700 directory and nothing is
        # written into any of the directories it still points at.
        env_names = _RECORDED_ENV
        before = _parent_environ()
        self.assertTrue(self.launch())
        recorded = self.record_of_last_launch()["environ"]
        self.assertEqual(set(recorded), set(env_names), "the stand-in recorded other keys")
        for name in env_names_kept():
            with self.subTest(variable=name):
                self.assertEqual(recorded[name], _fixed_value(before.get(name)))
        self.assertEqual(recorded["TMPDIR"], str(self.temp_dir))
        self.assertEqual(_parent_environ(), before, "the launch changed the parent's environment")
        bound = Path(self.record_of_last_launch()["argv"][1])
        self.assertEqual(_mode(bound), 0o600)
        self.assertEqual(_mode(bound.parent), 0o700)
        # And the smoke wrote nothing into any of those directories.
        for name, value in before.items():
            if name not in env_names or name == "TMPDIR" or not value:
                continue
            target = Path(value)
            if not target.is_dir():
                continue
            with self.subTest(variable=name):
                self.assertFalse(
                    (target / "desktop-smoke").exists(), f"smoke wrote under {name}"
                )

    def test_standin_record_is_private_and_holds_only_the_fixed_keys(self):
        self.assertTrue(self.launch())
        record = self.records[0]
        self.assertTrue(record.is_file() and not record.is_symlink())
        self.assertEqual(_mode(record), 0o600)
        self.assertLessEqual(_mode(record.parent), 0o700)
        recorded = self.record_of_last_launch()["environ"]
        # Never a dump of os.environ: exactly the fixed keys.
        self.assertEqual(sorted(recorded), sorted(_RECORDED_ENV))
        self.assertNotIn("PATH", recorded)
        self.assertNotIn("DBUS_SESSION_BUS_ADDRESS", recorded)

    def test_launch_environment_differs_only_in_the_redirected_tmpdir(self):
        # The recorded TMPDIR shows the redirect; the parent's full environment
        # is unchanged before/after, and the only key the launch may change is
        # the declared TMPDIR: HOME, XDG_* and CODEX_HOME keep their values.
        before = _parent_environ()
        self.assertTrue(self.launch())
        self.assertEqual(_parent_environ(), before, "the launch changed the parent's environment")
        expected = _recorded_environ()
        expected["TMPDIR"] = str(self.temp_dir)
        self.assertEqual(self.record_of_last_launch()["environ"], expected)
        for name in env_names_kept():
            self.assertEqual(expected[name], _fixed_value(before.get(name)))

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
            needle = str(self.records[0]).encode()
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
        # Each launch gets its own private settings file (the name is random,
        # so two runs must not be compared by path), yet both bind exactly
        # ``--settings`` once to a 0600 file in the 0700 private directory
        # with the same valid defaults, and each spawns its own desktop. One
        # stand-in serves both runs, so each record is read before the next.
        self.assertTrue(self.launch())
        first_run = self.record_of_last_launch()
        self.assertTrue(self.launch())
        second_run = self.record_of_last_launch()
        first, first_pid = first_run["argv"], first_run["pid"]
        second, second_pid = second_run["argv"], second_run["pid"]
        for index, argv in enumerate((first, second), start=1):
            with self.subTest(run=index):
                self.assertTrue(argv, "the launch recorded no argv")
                self.assertEqual(argv.count("--settings"), 1)
                self.assertEqual(argv[0], "--settings")
                self.assertEqual(len(argv), 2)
                self.assertEqual(argv, support.desktop_argv(Path(argv[1])))
                self.assertEqual(argv[1], os.path.normpath(argv[1]))
                bound = Path(argv[1])
                self.assertTrue(bound.is_absolute())
                self.assertTrue(bound.is_relative_to(self.temp_dir))
                self.assertEqual(bound.parent, self.temp_dir / "desktop-smoke")
                self.assertTrue(bound.is_file() and not bound.is_symlink())
                self.assertEqual(_mode(bound), 0o600)
                self.assertEqual(_mode(bound.parent), 0o700)
                self.assertEqual(_mode(bound.parent.parent), 0o700)
        self.assertNotEqual(first[1], second[1], "runs must not share one settings file")
        self.assertNotEqual(first_pid, second_pid, "runs must not share one desktop process")
        # Same launch-independent contract and the same effective defaults.
        self.assertEqual(_contract_facts(first, self.temp_dir), _contract_facts(second, self.temp_dir))
        facts = _contract_facts(first, self.temp_dir)
        self.assertEqual(facts["problems"], [])
        self.assertEqual(facts["document"], dict(support.DESKTOP_SMOKE_SETTINGS))
        self.assertEqual(len(self.executed.read_text(encoding="utf-8").split()), 2)
        for pid in (first_pid, second_pid):
            self.assertFalse(_alive(pid), "an owned desktop outlived its run")

    def test_locked_smoke_does_not_mutate_the_target_vault(self):
        before = _sha256(self.vault)
        self.assertTrue(self.launch())
        self.assertEqual(_sha256(self.vault), before)

    def test_mutation_after_the_before_digest_fails_and_still_reaps(self):
        # The change is made by the owned child itself, never by the harness
        # or the helper, and only after it has read the settings the helper
        # bound, which the helper writes after taking its ``before`` digest.
        # Ordering to the child rides on its own stdout (which the real helper
        # redirects into a pipe) and a private nudge file: no polling sleeps.
        # The collector starts with the spawn, so the reports are read only
        # after it, and the child's stdout EOF, are proven -- not before.
        seed = (
            f"_harness_pid = {os.getpid()}\n"
            f"_nudge = [{str(self.nudge)!r}]\n"
            f"_vault_path = [{str(self.vault)!r}]\n"
            f"_launch_argv = [{str(self.records[-1])!r}, *sys.argv[2:]]\n"
            + _MUTATING_STAND_IN
        )
        self.ctx.desktop_bin = self._install_stand_in(seed)

        observed: queue.Queue[tuple[bool, BaseException | None]] = queue.Queue()

        def launch() -> None:
            try:
                observed.put((bool(self.launch(seconds=2.0)), None))
            except BaseException as exc:  # reported on the main thread
                observed.put((False, exc))

        worker = threading.Thread(target=launch, daemon=True)
        worker.start()
        try:
            # Completion is ``is_alive`` going false, never ``join() is None``
            # (which is also what a timed-out join returns); the wait is bounded.
            _await_thread(self, worker, "desktop smoke helper")
            if observed.empty():
                self.fail("desktop smoke helper reported no outcome")
            alive, error = observed.get_nowait()
            self.assertIsInstance(error, AssertionError, f"unexpected outcome {alive!r}")
            # One fixed error, evaluated after the owned session was reaped:
            # the child changed the vault while the helper was still in its
            # window, so both digests see the change and no cleanup note is
            # attached (teardown succeeded and the group was proven reaped).
            self.assertIsNone(getattr(error, "__notes__", None))
            mutated = re.fullmatch(
                re.escape(
                    _MUTATION_ERROR.format(pre=True, post=True, vault=self.vault)
                ),
                str(error),
            )
            self.assertIsNotNone(mutated, f"unexpected mutation error {str(error)!r}")
        finally:
            # A reported failure still reaps: bounded, and only the own
            # thread; nothing here ever signals a process group. The collector
            # is drained here too, so a failing assertion above never reaches
            # the cleanup with a scraper still writing ``reports``.
            _wait_until_dead(worker, _WORKER_REAP)
            self._wait_for_scrapers()

        # The child's own byte-level handshake: it announced its pid, changed
        # the vault and was still running when the helper reaped it. No static
        # substring stands in for the helper's post-window digest.
        self.assertEqual(self.vault.read_bytes(), _MUTATION)
        self.assertEqual(self.scrapers_started, 1, "the mutation launch was not observed")
        self.assertEqual(self.scrapers_drained, self.scrapers_started)
        for scraper in self.scrapers:
            self.assertFalse(scraper.is_alive(), "a stdout collector raced the reports read")
        reports = self.drained_reports()
        self.assertEqual(set(reports), {"launch", "mutated", "alive"}, reports)
        # Created 0600 by the collector itself; no chmod runs after creation.
        for private in (self.nudge, self.launched_pid):
            self.assertTrue(private.is_file() and not private.is_symlink())
            self.assertEqual(_mode(private), 0o600, f"{private.name} was not created 0600")
        pid = int(self.launched_pid.read_text(encoding="utf-8"))
        self.assertEqual(reports["launch"], str(pid))
        # The shim recorded the helper's session leader, which exec'd the
        # stand-in in place: same pid, and the owned group is that pid.
        self.assertEqual(int(self.executed.read_text(encoding="utf-8")), pid)
        self.assertFalse(_alive(pid), "a failing smoke must still reap its owned desktop")
        self.assertFalse(
            harness._group_has_members(pid),
            "a failing smoke must still reap its owned process group",
        )

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
