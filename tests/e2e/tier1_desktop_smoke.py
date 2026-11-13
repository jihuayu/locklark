"""Contract tests for the desktop smoke launch used by T1 F5/F7/F8.

The desktop accepts exactly one command line, ``--settings ABSOLUTE_PATH``;
``--file`` is refused with exit 2 before any GUI exists. These tests pin the
shared helper to that contract on three real surfaces, without building or
starting a GUI:

- the actual argv ``desktop_binary_starts`` spawns (a stand-in executable in
  the private fixture root records its argv, environment and exit while the
  unchanged helper runs its own live/cleanup/exit assertions against it);
- the real ``locklark-desktop`` artifact's argument parser, when that artifact
  is present, invoked through the same GUI session wrapper the helper uses;
- the settings document against the JSON schema in
  ``internal/desktop/settings.go`` and the product's own parser/value tests.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Iterator
from unittest import mock

from .harness import e2e_test, owned_gui_command, terminate_process_group
from .support import (
    DESKTOP_SETTINGS_USAGE,
    DESKTOP_SMOKE_SETTINGS,
    DESKTOP_VAULT_SENTINEL,
    desktop_argv,
    desktop_binary_starts,
    desktop_smoke_dir,
    desktop_smoke_settings,
    file_mode,
    go_package_test,
    go_tool,
    sha256_file,
    source_text,
)

# Stand-in for the desktop binary: records exactly what it was launched with,
# then stays alive like the GUI would. SIGTERM still stops it (exit code 3) so
# a helper that abandoned its group leaves a visible leftover instead.
_FAKE_DESKTOP = r"""
import json
import os
import signal
import sys
import time

record = sys.argv[1]
signal.signal(signal.SIGTERM, lambda signum, frame: sys.exit(3))
with open(record, "w", encoding="utf-8") as handle:
    json.dump({"argv": sys.argv[2:], "environ": dict(os.environ)}, handle)
while True:
    time.sleep(0.1)
"""

# The stand-in launches through ctx.desktop_bin exactly like the real binary,
# so it is reached through a one-line executable shim (argv unchanged) that
# runs the recorder in this interpreter.
_FAKE_DESKTOP_SHIM = '#!/bin/sh\nexec {python} {script} {record} "$@"\n'

# The smoke settings must bind nothing outside the process: no vault path and
# no credential-shaped key. ``revealPasswords`` is a display preference only.
_FORBIDDEN_SETTING_KEY = re.compile(r"vault|secret|password|key", re.IGNORECASE)
_DISPLAY_ONLY_SETTING_KEY = re.compile(r"\.revealPasswords$")


def _schema_keys(ctx) -> set[str]:
    """Every dotted ``json:"..."`` key declared in the desktop Settings struct."""

    text = source_text(ctx, "internal/desktop/settings.go")
    if not text:
        raise AssertionError("internal/desktop/settings.go is missing")
    return {key for key in re.findall(r'json:"([^",]+)"', text) if key != "-"}


def _retires_file_flag(ctx) -> None:
    """The helper must launch with ``--settings`` only and not touch HOME/XDG."""

    text = source_text(ctx, "tests/e2e/support.py")
    start = text.index("def desktop_binary_starts")
    end = text.index("\ndef ", start + 1)
    body = text[start:end]
    assert '"--file"' not in body, "desktop smoke launch still passes --file"
    assert "desktop_argv(settings)" in body
    for token in ('os.environ.get("HOME', "XDG_CONFIG_HOME", "CODEX_HOME", "SettingsPath()"):
        assert token not in body, f"desktop smoke launch references {token}"


@contextmanager
def _direct_desktop_environment() -> Iterator[SimpleNamespace]:
    """Let the stand-in run without a display, bus or session wrappers."""

    with mock.patch(
        "tests.e2e.support.owned_gui_command", lambda target, **_: list(target)
    ), mock.patch("tests.e2e.support.sys", SimpleNamespace(unix=True)):
        yield None


def _install_fake_desktop(ctx, record: Path) -> SimpleNamespace:
    script = ctx.temp_dir / "fake-desktop.py"
    script.write_text(_FAKE_DESKTOP, encoding="utf-8")
    fake = ctx.temp_dir / "fake-desktop"
    fake.write_text(
        _FAKE_DESKTOP_SHIM.format(
            python=shlex.quote(sys.executable),
            script=shlex.quote(str(script)),
            record=shlex.quote(str(record)),
        ),
        encoding="utf-8",
    )
    fake.chmod(0o700)
    # Serve the stand-in through an owner-only view of the context instead of
    # mutating it, so the shared bin directory is never touched.
    view = SimpleNamespace(**vars(ctx))
    view.desktop_bin = fake
    return view


def _host_can_link_go_tests(ctx) -> bool:
    """A missing C SDK/compiler is a blocked host, not a product failure."""

    try:
        probe = ctx.run_cli(
            ["test", "-c", "-o", str(ctx.temp_dir / "desktop-probe.test"), "./internal/desktop"],
            binary=go_tool(),
            timeout=300.0,
            cwd=ctx.repo_root,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return probe.returncode == 0


def _read_record(record: Path) -> dict[str, Any]:
    if not record.is_file():
        raise AssertionError("stand-in desktop recorded no launch")
    mode = file_mode(record)
    if mode & 0o077:
        raise AssertionError(f"stand-in launch record is not owner-only: {mode:o}")
    return json.loads(record.read_text(encoding="utf-8"))


def _target_vault(ctx) -> Path:
    vault = ctx.temp_dir / "target-vault.ll"
    vault.write_bytes(b"sentinel-vault-bytes\n")
    return vault


def _live_with_record(record: Path) -> list[str]:
    """PIDs of any process whose argv still names the launch record."""

    proc = Path("/proc")
    if not proc.is_dir():
        return []
    found: list[str] = []
    needle = str(record).encode()
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            cmdline = (entry / "cmdline").read_bytes().split(b"\0")
        except OSError:
            continue
        if needle in cmdline:
            found.append(entry.name)
    return found


@e2e_test(
    "T1_DESKTOP_SMOKE_01",
    1,
    ["F5"],
    "Desktop smoke launch passes only --settings ABSOLUTE_PATH, outside HOME/XDG",
)
def t1_desktop_smoke_01(ctx):
    _retires_file_flag(ctx)
    reference = Path(ctx.temp_dir) / "reference.json"
    assert desktop_argv(reference) == ["--settings", str(reference)]

    record = desktop_smoke_dir(ctx) / "launch.json"
    with _direct_desktop_environment():
        view = _install_fake_desktop(ctx, record)
        vault = _target_vault(ctx)
        before = sha256_file(vault)
        assert desktop_binary_starts(view, vault, seconds=1.0) is True

    launch = _read_record(record)
    settings = desktop_smoke_settings(ctx)
    argv = launch["argv"]
    assert argv == desktop_argv(settings), argv
    argv_text = " ".join(argv)
    for forbidden in ("--file", DESKTOP_VAULT_SENTINEL, str(vault), "--settings="):
        assert forbidden not in argv_text, f"smoke argv carries {forbidden!r}"
    # The explicit path is private to this context, absolute and clean.
    bound = Path(argv[1])
    assert bound.is_absolute() and str(bound) == os.path.normpath(str(bound))
    assert bound.parent == desktop_smoke_dir(ctx)
    assert os.path.realpath(bound).startswith(os.path.realpath(ctx.temp_dir) + os.sep)
    # No global configuration or home directory is exported or overridden.
    environ = launch["environ"]
    for name in ("HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "CODEX_HOME"):
        assert environ.get(name) == os.environ.get(name), f"smoke launch overrode {name}"
    assert environ.get("TMPDIR") == str(ctx.temp_dir)
    # An idle, locked smoke launch neither read nor wrote the target vault.
    assert sha256_file(vault) == before


@e2e_test(
    "T1_DESKTOP_SMOKE_02",
    1,
    ["F5"],
    "Desktop smoke run terminates its owned group and reaps every process",
)
def t1_desktop_smoke_02(ctx):
    record = desktop_smoke_dir(ctx) / "launch.json"
    with _direct_desktop_environment():
        view = _install_fake_desktop(ctx, record)
        vault = _target_vault(ctx)
        assert desktop_binary_starts(view, vault, seconds=0.5) is True
        first = _read_record(record)["argv"]
        assert _live_with_record(record) == [], "desktop smoke left live processes in its group"
        # A second run is independent: fresh private settings, same contract.
        assert desktop_binary_starts(view, vault, seconds=0.5) is True
        assert _read_record(record)["argv"] == first
        assert _live_with_record(record) == []


@e2e_test(
    "T1_DESKTOP_SMOKE_03",
    1,
    ["F5"],
    "Desktop smoke settings are private, schema-valid and bind no vault or factor",
)
def t1_desktop_smoke_03(ctx):
    settings = desktop_smoke_settings(ctx)
    # Owner-only regular file inside the context's own 0700 directory.
    assert settings.is_file() and not settings.is_symlink()
    assert file_mode(settings) == 0o600
    assert file_mode(desktop_smoke_dir(ctx)) == 0o700
    document = json.loads(settings.read_text(encoding="utf-8"))
    assert document == dict(DESKTOP_SMOKE_SETTINGS)
    # Exact schema: every fixture key is declared in settings.go and the
    # documented preference defaults are all present; no vault path, factor,
    # or absolute value.
    declared = _schema_keys(ctx)
    assert set(document) == declared, sorted(set(document) ^ declared)
    assert document["app.defaultVaultForSaving"] == ""
    for key, value in document.items():
        if _DISPLAY_ONLY_SETTING_KEY.search(key):
            continue
        assert not _FORBIDDEN_SETTING_KEY.search(key.replace("defaultVaultForSaving", "")), key
        if isinstance(value, str):
            assert not os.path.isabs(value), f"{key} carries a path: {value!r}"
            assert DESKTOP_VAULT_SENTINEL not in value
    # Bounded integer units accepted by ValidateSettings in settings.go.
    assert 0 <= document["security.autolock.minutes"] <= 480
    assert 0 <= document["security.clipboard.clearAfterSeconds"] <= 3600
    assert document["appearance.theme"] in ("system", "light", "dark")
    assert document["appearance.interfaceDensity"] in ("comfortable", "compact")
    for key in ("security.autolock.onSleep", "security.autolock.onDeviceLock"):
        assert document[key] is True
    # The product's own parser/value boundaries, executed from source.
    run_product_tests = go_tool() is not None and _host_can_link_go_tests(ctx)
    if not run_product_tests:
        raise AssertionError(
            "validation blocked: this host's Go toolchain/C SDK cannot link the desktop "
            "test binary; the product parser/value tests were not executed"
        )
    go_package_test(ctx, "./internal/desktop", "^TestDesktopArgs|^TestValidateSettingsFilePath$")


def _artifact_refuses_file(artifact: Path) -> bool:
    """True when the artifact predates the --settings contract.

    A current build refuses ``--file`` at parse time, before any GUI; ``strings``
    reveals the fixed usage constant, which an older build cannot contain.
    """

    strings = shutil.which("strings")
    if strings is None:
        return False
    result = subprocess.run(
        [strings, "-a", str(artifact)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=60,
    )
    return DESKTOP_SETTINGS_USAGE.encode() not in result.stdout


@e2e_test(
    "T1_DESKTOP_SMOKE_04",
    1,
    ["F5"],
    "Real desktop artifact accepts the smoke argv and still refuses --file",
)
def t1_desktop_smoke_04(ctx):
    if not (ctx.desktop_bin.is_file() and os.access(ctx.desktop_bin, os.X_OK)):
        raise AssertionError(
            "validation blocked: real locklark-desktop artifact is absent from "
            f"{ctx.bin_dir}; the argv contract cannot be exercised"
        )
    if sys.platform.startswith("linux") and shutil.which("dbus-run-session") is None:
        # Without an owned session bus the binary would start on the host
        # display, which this suite never does.
        raise AssertionError(
            "validation blocked: dbus-run-session is unavailable; the real desktop "
            "argv contract cannot be exercised in an owned GUI session"
        )
    settings = desktop_smoke_settings(ctx)
    env = dict(os.environ)
    env["TMPDIR"] = str(ctx.temp_dir)
    accepted = owned_gui_command(
        [str(ctx.desktop_bin), *desktop_argv(settings)],
        env=env,
        use_xvfb=shutil.which("xvfb-run") is not None,
    )
    assert accepted[-2:] == desktop_argv(settings), accepted
    # A cached binary built before the --settings contract must not be read as
    # a regression of this helper; it cannot be rebuilt here.
    stale = _artifact_refuses_file(ctx.desktop_bin)
    stale_note = (
        " (the prebuilt artifact was built before the --settings contract)"
        if stale
        else ""
    )

    def run(args: list[str]) -> tuple[int | str, str]:
        """Run the real desktop non-interactively; the GUI never gets a TTY.

        An accepted argv may either refuse to start or stay alive in this
        environment; neither is a verdict. Only the fixed parser refusal (exit
        2 / the usage text) is judged, and the process is always reaped by its
        own group.
        """

        process = subprocess.Popen(
            accepted[:-2] + args,
            cwd=str(ctx.temp_dir),
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        try:
            stdout, stderr = process.communicate(timeout=15)
            return process.returncode, (stdout + stderr).decode("utf-8", "replace")
        except subprocess.TimeoutExpired:
            # Still running: the argv was accepted (the parser refuses at once).
            terminate_process_group(process, grace=2.0, owned_group=process.pid)
            stdout, stderr = process.communicate()
            return "alive", (stdout + stderr).decode("utf-8", "replace")
        finally:
            terminate_process_group(process, grace=2.0, owned_group=process.pid)

    # Counter-control first: the retired --file form is still refused with the
    # fixed usage verdict, so the product parser was never relaxed to accept
    # the old helper argv.
    if stale:
        raise AssertionError(
            "validation blocked: the prebuilt locklark-desktop artifact does not "
            "refuse --file, i.e. it predates the current desktop sources; it cannot "
            "be rebuilt here"
        )
    verdict, text = run(["--file", DESKTOP_VAULT_SENTINEL])
    if verdict != 2 or DESKTOP_SETTINGS_USAGE not in text:
        raise AssertionError(
            "--file was not refused with the fixed usage verdict "
            f"(verdict={verdict}{stale_note}); the desktop parser may have been "
            f"relaxed: {text[-400:]}"
        )
    assert DESKTOP_VAULT_SENTINEL not in text
    # The real smoke argv never reaches the parser refusal.
    verdict, text = run(desktop_argv(settings))
    if verdict == 2 or DESKTOP_SETTINGS_USAGE in text:
        raise AssertionError(
            f"real desktop rejected the smoke argv (verdict={verdict}{stale_note}): "
            f"{text[-600:]}"
        )
