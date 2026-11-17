"""Pure launch-adapter tests with real client pipes and a fake Popen.

No product, probe, browser, helper, native acceptance or X11 process is
started. These tests verify construction and ownership only; real exec
inheritance is proven later by the Go READY handshake.
"""
import os
import subprocess
import unittest

from desktop_native_fence import (
    CONTROL_FD_ENV,
    EVENT_FD_ENV,
    NativeFenceClient,
    SpawnParameters,
)
from desktop_native_fence_launch import (
    NativeFenceLaunchError,
    NativeFenceLaunchErrorCode,
    launch_owned_desktop_child,
)


def _fd_open(fd):
    try:
        os.fstat(fd)
        return True
    except OSError:
        return False


class _FakeChild:
    def __init__(self, wait_timeout=False):
        self.terminate_calls = 0
        self.kill_calls = 0
        self.wait_calls = []
        self._wait_timeout = wait_timeout

    def terminate(self):
        self.terminate_calls += 1

    def wait(self, timeout=None):
        self.wait_calls.append(timeout)
        if self._wait_timeout and len(self.wait_calls) == 1:
            raise subprocess.TimeoutExpired(["owned-child"], timeout)
        return 0

    def kill(self):
        self.kill_calls += 1


class _RecordingPopen:
    def __init__(self, child=None, error=None):
        self.child = child
        self.error = error
        self.calls = []

    def __call__(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        if self.error is not None:
            raise self.error
        return self.child


class _CountingClient(NativeFenceClient):
    def __init__(self):
        super().__init__()
        self.after_spawn_calls = 0

    def after_spawn(self):
        self.after_spawn_calls += 1
        super().after_spawn()


class _AfterSpawnFailingClient:
    def __init__(self, inner):
        self.inner = inner

    def spawn_parameters(self):
        return self.inner.spawn_parameters()

    def after_spawn(self):
        raise RuntimeError("synthetic after-spawn failure")

    def close(self):
        self.inner.close()


class _ExtraOverlayClient:
    def __init__(self, inner):
        self.inner = inner

    def spawn_parameters(self):
        parameters = self.inner.spawn_parameters()
        overlay = dict(parameters.env_overlay)
        overlay["LOCKLARK_UNRELATED"] = "must-not-be-forwarded"
        return SpawnParameters(parameters.pass_fds, overlay)

    def after_spawn(self):
        self.inner.after_spawn()

    def close(self):
        self.inner.close()


class OrdinaryLaunchTests(unittest.TestCase):
    def test_ordinary_desktop_launch_keeps_existing_popen_kwargs(self):
        base_env = {"BASE": "unchanged"}
        stdout, stderr = object(), object()
        child = _FakeChild()
        popen = _RecordingPopen(child)

        returned = launch_owned_desktop_child(
            popen, ["/owned/desktop"], base_env,
            stdout=stdout, stderr=stderr, native_fence_client=None)

        self.assertIs(returned, child)
        self.assertEqual(len(popen.calls), 1)
        argv, kwargs = popen.calls[0]
        self.assertEqual(argv, ["/owned/desktop"])
        self.assertIs(kwargs["env"], base_env)
        self.assertIs(kwargs["stdout"], stdout)
        self.assertIs(kwargs["stderr"], stderr)
        self.assertEqual(set(kwargs), {"env", "stdout", "stderr"})
        self.assertEqual(base_env, {"BASE": "unchanged"})

    def test_probe_style_launch_has_no_fence_overlay_or_fds(self):
        base_env = {"BASE": "unchanged"}
        child = _FakeChild()
        popen = _RecordingPopen(child)

        returned = launch_owned_desktop_child(
            popen, ["/usr/bin/python3", "/owned/probe.py"], base_env,
            stdout=object(), stderr=object(), native_fence_client=None)

        self.assertIs(returned, child)
        _, kwargs = popen.calls[0]
        self.assertIs(kwargs["env"], base_env)
        self.assertNotIn(CONTROL_FD_ENV, kwargs["env"])
        self.assertNotIn(EVENT_FD_ENV, kwargs["env"])
        self.assertNotIn("pass_fds", kwargs)
        self.assertNotIn("close_fds", kwargs)
        self.assertEqual(base_env, {"BASE": "unchanged"})


class TaggedLaunchTests(unittest.TestCase):
    def test_tagged_launch_copies_env_and_passes_exact_fds(self):
        client = _CountingClient()
        self.addCleanup(client.close)
        parameters = client.spawn_parameters()
        child_control_fd, child_event_fd = parameters.pass_fds
        parent_control_fd = client._control_write
        parent_event_fd = client._event_read
        base_env = {"BASE": "unchanged", "OTHER": "value"}
        child = _FakeChild()
        popen = _RecordingPopen(child)

        returned = launch_owned_desktop_child(
            popen, ["/owned/desktop"], base_env,
            stdout=object(), stderr=object(), native_fence_client=client)

        self.assertIs(returned, child)
        self.assertEqual(client.after_spawn_calls, 1)
        self.assertEqual(len(popen.calls), 1)
        argv, kwargs = popen.calls[0]
        self.assertEqual(argv, ["/owned/desktop"])
        self.assertIsNot(kwargs["env"], base_env)
        self.assertEqual(base_env, {"BASE": "unchanged", "OTHER": "value"})
        self.assertEqual(kwargs["env"][CONTROL_FD_ENV], str(child_control_fd))
        self.assertEqual(kwargs["env"][EVENT_FD_ENV], str(child_event_fd))
        self.assertEqual(
            set(kwargs["env"]) - set(base_env),
            {CONTROL_FD_ENV, EVENT_FD_ENV})
        self.assertEqual(tuple(kwargs["pass_fds"]), tuple(parameters.pass_fds))
        self.assertTrue(kwargs["close_fds"])
        self.assertFalse(_fd_open(child_control_fd))
        self.assertFalse(_fd_open(child_event_fd))
        self.assertTrue(_fd_open(parent_control_fd))
        self.assertTrue(_fd_open(parent_event_fd))

    def test_tagged_launch_forwards_only_the_two_fixed_env_names(self):
        inner = NativeFenceClient()
        self.addCleanup(inner.close)
        client = _ExtraOverlayClient(inner)
        parameters = client.spawn_parameters()
        child = _FakeChild()
        popen = _RecordingPopen(child)

        returned = launch_owned_desktop_child(
            popen, ["/owned/desktop"], {"BASE": "unchanged"},
            stdout=object(), stderr=object(), native_fence_client=client)

        self.assertIs(returned, child)
        _, kwargs = popen.calls[0]
        self.assertNotIn("LOCKLARK_UNRELATED", kwargs["env"])
        self.assertEqual(
            set(kwargs["env"]) - {"BASE"},
            {CONTROL_FD_ENV, EVENT_FD_ENV})
        self.assertEqual(tuple(kwargs["pass_fds"]), tuple(parameters.pass_fds))


class LaunchFailureTests(unittest.TestCase):
    def test_popen_failure_closes_all_client_owned_fds(self):
        client = _CountingClient()
        self.addCleanup(client.close)
        parameters = client.spawn_parameters()
        owned_fds = (
            *parameters.pass_fds,
            client._control_write,
            client._event_read)
        popen = _RecordingPopen(error=OSError("synthetic spawn failure"))

        with self.assertRaises(NativeFenceLaunchError) as caught:
            launch_owned_desktop_child(
                popen, ["/owned/desktop"], {"BASE": "unchanged"},
                stdout=object(), stderr=object(), native_fence_client=client)

        self.assertEqual(
            caught.exception.code,
            NativeFenceLaunchErrorCode.SPAWN_FAILED)
        self.assertEqual(client.after_spawn_calls, 0)
        for fd in owned_fds:
            self.assertFalse(_fd_open(fd))

    def test_closed_client_fails_closed_before_popen(self):
        client = NativeFenceClient()
        client.close()
        child = _FakeChild()
        popen = _RecordingPopen(child)

        with self.assertRaises(NativeFenceLaunchError) as caught:
            launch_owned_desktop_child(
                popen, ["/owned/desktop"], {"BASE": "unchanged"},
                stdout=object(), stderr=object(), native_fence_client=client)

        self.assertEqual(
            caught.exception.code,
            NativeFenceLaunchErrorCode.SPAWN_FAILED)
        self.assertEqual(popen.calls, [])

    def test_after_spawn_failure_stops_only_the_just_owned_child(self):
        inner = _CountingClient()
        self.addCleanup(inner.close)
        client = _AfterSpawnFailingClient(inner)
        parameters = inner.spawn_parameters()
        owned_fds = (
            *parameters.pass_fds,
            inner._control_write,
            inner._event_read)
        child = _FakeChild()
        popen = _RecordingPopen(child)

        with self.assertRaises(NativeFenceLaunchError) as caught:
            launch_owned_desktop_child(
                popen, ["/owned/desktop"], {"BASE": "unchanged"},
                stdout=object(), stderr=object(), native_fence_client=client)

        self.assertEqual(
            caught.exception.code,
            NativeFenceLaunchErrorCode.AFTER_SPAWN_FAILED)
        self.assertEqual(child.terminate_calls, 1)
        self.assertEqual(len(child.wait_calls), 1)
        self.assertEqual(child.kill_calls, 0)
        for fd in owned_fds:
            self.assertFalse(_fd_open(fd))

    def test_after_spawn_wait_timeout_escalates_to_bounded_kill(self):
        inner = _CountingClient()
        self.addCleanup(inner.close)
        client = _AfterSpawnFailingClient(inner)
        child = _FakeChild(wait_timeout=True)
        popen = _RecordingPopen(child)

        with self.assertRaises(NativeFenceLaunchError) as caught:
            launch_owned_desktop_child(
                popen, ["/owned/desktop"], {"BASE": "unchanged"},
                stdout=object(), stderr=object(), native_fence_client=client)

        self.assertEqual(
            caught.exception.code,
            NativeFenceLaunchErrorCode.AFTER_SPAWN_FAILED)
        self.assertEqual(child.terminate_calls, 1)
        self.assertEqual(child.kill_calls, 1)
        self.assertEqual(len(child.wait_calls), 2)
        for timeout in child.wait_calls:
            self.assertIsNotNone(timeout)
            self.assertLessEqual(timeout, 10.0)


class TeardownTests(unittest.TestCase):
    def test_double_close_is_safe_across_descriptor_reuse(self):
        first = NativeFenceClient()
        first_parameters = first.spawn_parameters()
        first_fds = (
            *first_parameters.pass_fds,
            first._control_write,
            first._event_read)
        first.close()
        first.close()
        for fd in first_fds:
            self.assertFalse(_fd_open(fd))

        second = NativeFenceClient()
        self.addCleanup(second.close)
        second_parameters = second.spawn_parameters()
        second_fds = (
            *second_parameters.pass_fds,
            second._control_write,
            second._event_read)
        for fd in second_fds:
            self.assertTrue(_fd_open(fd))

        first.close()
        for fd in second_fds:
            self.assertTrue(_fd_open(fd))

        second.close()
        for fd in second_fds:
            self.assertFalse(_fd_open(fd))


if __name__ == "__main__":
    unittest.main()
