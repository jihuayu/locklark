"""Owned Go-child launch adapter for the private native fence pipes.

This module is source-only process construction. It merges the client's two
fixed descriptor variables into a private copy of the desktop child
environment and passes exactly those descriptors through Popen pass_fds. It
launches no product, probe, browser, helper or acceptance scenario itself.
"""
from __future__ import annotations

import enum
import subprocess

from desktop_native_fence import CONTROL_FD_ENV, EVENT_FD_ENV

_STOP_TIMEOUT = 5.0
_KILL_TIMEOUT = 5.0


class NativeFenceLaunchErrorCode(enum.Enum):
    SPAWN_FAILED = "SPAWN_FAILED"
    AFTER_SPAWN_FAILED = "AFTER_SPAWN_FAILED"


class NativeFenceLaunchError(Exception):
    """Fixed launch classification without OS text, argv, env or FD values."""

    def __init__(self, code: NativeFenceLaunchErrorCode):
        self.code = code
        super().__init__(code.value)

    def __str__(self) -> str:
        return self.code.value


def _stop_owned_child(child) -> None:
    """Stop and reap only the child just created by this launch."""
    try:
        child.terminate()
    except Exception:
        pass
    try:
        child.wait(timeout=_STOP_TIMEOUT)
        return
    except subprocess.TimeoutExpired:
        pass
    except Exception:
        pass
    try:
        child.kill()
    except Exception:
        pass
    try:
        child.wait(timeout=_KILL_TIMEOUT)
    except Exception:
        pass


def launch_owned_desktop_child(
    popen,
    argv,
    env,
    *,
    stdout,
    stderr,
    native_fence_client=None,
):
    """Launch the real owned Go desktop child with optional fence pipes.

    With no client this is exactly the existing env/stdout/stderr Popen call.
    With a fresh client it copies the base environment, adds only the two fixed
    fence descriptor variables, passes the exact descriptors via pass_fds, and
    closes the child ends only after a successful spawn. The parent ends stay
    owned by the client until terminal or cleanup.
    """
    if native_fence_client is None:
        return popen(argv, env=env, stdout=stdout, stderr=stderr)

    try:
        spawn = native_fence_client.spawn_parameters()
        child_env = dict(env)
        child_env[CONTROL_FD_ENV] = spawn.env_overlay[CONTROL_FD_ENV]
        child_env[EVENT_FD_ENV] = spawn.env_overlay[EVENT_FD_ENV]
        child = popen(
            argv,
            env=child_env,
            stdout=stdout,
            stderr=stderr,
            pass_fds=tuple(spawn.pass_fds),
            close_fds=True,
        )
    except Exception:
        try:
            native_fence_client.close()
        except Exception:
            pass
        raise NativeFenceLaunchError(
            NativeFenceLaunchErrorCode.SPAWN_FAILED
        ) from None

    try:
        native_fence_client.after_spawn()
    except Exception:
        _stop_owned_child(child)
        try:
            native_fence_client.close()
        except Exception:
            pass
        raise NativeFenceLaunchError(
            NativeFenceLaunchErrorCode.AFTER_SPAWN_FAILED
        ) from None

    return child
