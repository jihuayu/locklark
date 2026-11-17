import os
import select
import threading
import time
import unittest
from unittest import mock

import desktop_native_fence as fence


def _finite_clock(values):
    sequence = iter(values)
    last = values[-1]

    def now():
        try:
            return next(sequence)
        except StopIteration:
            return last

    return now


class _Peer:
    def __init__(self, client):
        control = client._child_control_read
        event = client._child_event_write
        if control is None or event is None:
            raise AssertionError("PEER_CHILD_END_MISSING")
        self.control_fd = os.dup(control)
        self.event_fd = os.dup(event)
        client.after_spawn()
        os.set_blocking(self.control_fd, False)

    def write_event(self, data):
        if self.event_fd is None:
            return
        try:
            os.write(self.event_fd, data)
        except OSError:
            pass

    def close_event(self):
        if self.event_fd is not None:
            os.close(self.event_fd)
            self.event_fd = None

    def close_control(self):
        if self.control_fd is not None:
            os.close(self.control_fd)
            self.control_fd = None

    def read_control_line(self, timeout=1.0):
        deadline = time.monotonic() + timeout
        data = b""
        while b"\n" not in data:
            if self.control_fd is None:
                raise AssertionError("PEER_CONTROL_CLOSED")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AssertionError("PEER_CONTROL_TIMEOUT")
            readable, _, _ = select.select([self.control_fd], [], [], remaining)
            if not readable:
                raise AssertionError("PEER_CONTROL_TIMEOUT")
            try:
                chunk = os.read(self.control_fd, 64)
            except BlockingIOError:
                continue
            except OSError:
                raise AssertionError("PEER_CONTROL_READ")
            if not chunk:
                raise AssertionError("PEER_CONTROL_EOF")
            data += chunk
            if len(data) > 16:
                raise AssertionError("PEER_CONTROL_OVERSIZE")
        return data

    def control_available(self):
        if self.control_fd is None:
            return b""
        try:
            return os.read(self.control_fd, 64)
        except BlockingIOError:
            return b""
        except OSError:
            return b""

    def close(self):
        self.close_control()
        self.close_event()


class NativeFenceClientTests(unittest.TestCase):
    def _pair(self, **kwargs):
        kwargs.setdefault("ready_timeout", 0.5)
        kwargs.setdefault("event_timeout", 0.5)
        kwargs.setdefault("write_timeout", 0.2)
        client = fence.NativeFenceClient(**kwargs)
        peer = _Peer(client)
        self.addCleanup(peer.close)
        self.addCleanup(client.close)
        return client, peer

    def _assert_code(self, expected, call):
        with self.assertRaises(fence.NativeFenceError) as caught:
            call()
        self.assertEqual(caught.exception.code, expected)

    def _assert_closed(self, *fds):
        for fd in fds:
            if fd is None:
                continue
            with self.assertRaises(OSError):
                os.fstat(fd)

    def test_absolute_deadlines_cannot_be_bypassed(self):
        client = fence.NativeFenceClient()
        client._event_buffer.extend(b"READY_HELD 2\n")
        with mock.patch.object(fence.time, "monotonic", _finite_clock([0.0, 0.6])):
            self._assert_code(
                fence.NativeFenceErrorCode.EVENT_TIMEOUT,
                lambda: client.ready(timeout=0.5),
            )

        client = fence.NativeFenceClient()
        client._event_buffer.extend(b"READY_HELD 2\n")
        with mock.patch.object(fence.time, "monotonic", _finite_clock([0.0, 0.0, 0.6])):
            self._assert_code(
                fence.NativeFenceErrorCode.EVENT_TIMEOUT,
                lambda: client.ready(timeout=0.5),
            )

        client = fence.NativeFenceClient()
        client._event_eof = True
        with mock.patch.object(fence.time, "monotonic", _finite_clock([0.0, 0.6])):
            self._assert_code(
                fence.NativeFenceErrorCode.EVENT_TIMEOUT,
                lambda: client._confirm_terminal_eof(0.5),
            )

        client = fence.NativeFenceClient()
        state = {"read": False}

        def fake_read(fd, count):
            state["read"] = True
            return b""

        def eof_clock():
            return 0.6 if state["read"] else 0.0

        with mock.patch.object(
            fence.select, "select", return_value=([client._event_read], [], [])
        ), mock.patch.object(fence.os, "read", side_effect=fake_read), mock.patch.object(
            fence.time, "monotonic", eof_clock
        ):
            self._assert_code(
                fence.NativeFenceErrorCode.EVENT_TIMEOUT,
                lambda: client._confirm_terminal_eof(0.5),
            )
        self.assertTrue(state["read"])

        client, peer = self._pair()
        peer.write_event(b"READY_HELD 2\n")
        client.ready()
        write_mock = mock.Mock()
        with mock.patch.object(fence.os, "write", write_mock), mock.patch.object(
            fence.time, "monotonic", _finite_clock([0.0, 0.6])
        ):
            self._assert_code(
                fence.NativeFenceErrorCode.CONTROL_WRITE_TIMEOUT,
                lambda: client.release(timeout=0.5),
            )
        write_mock.assert_not_called()

        client, peer = self._pair()
        peer.write_event(b"READY_HELD 2\n")
        client.ready()
        write_mock = mock.Mock(side_effect=InterruptedError)
        with mock.patch.object(fence.os, "write", write_mock), mock.patch.object(
            fence.time, "monotonic", _finite_clock([0.0, 0.0, 0.6])
        ):
            self._assert_code(
                fence.NativeFenceErrorCode.CONTROL_WRITE_TIMEOUT,
                lambda: client.release(timeout=0.5),
            )
        self.assertEqual(write_mock.call_count, 1)

        client, peer = self._pair()
        peer.write_event(b"READY_HELD 2\n")
        client.ready()
        write_mock = mock.Mock(side_effect=BlockingIOError)
        select_mock = mock.Mock(side_effect=InterruptedError)
        with mock.patch.object(fence.os, "write", write_mock), mock.patch.object(
            fence.select, "select", select_mock
        ), mock.patch.object(
            fence.time, "monotonic", _finite_clock([0.0, 0.0, 0.0, 0.6])
        ):
            self._assert_code(
                fence.NativeFenceErrorCode.CONTROL_WRITE_TIMEOUT,
                lambda: client.release(timeout=0.5),
            )
        self.assertEqual(write_mock.call_count, 1)
        self.assertEqual(select_mock.call_count, 1)

        client, peer = self._pair()
        peer.write_event(b"READY_HELD 2\n")
        client.ready()
        write_mock = mock.Mock(return_value=1)
        with mock.patch.object(fence.os, "write", write_mock), mock.patch.object(
            fence.time, "monotonic", _finite_clock([0.0, 0.0, 0.6])
        ):
            self._assert_code(
                fence.NativeFenceErrorCode.CONTROL_WRITE_TIMEOUT,
                lambda: client.release(timeout=0.5),
            )
        self.assertEqual(write_mock.call_count, 1)

    def test_stdio_fd_allocations_fail_closed(self):
        calls = {"count": 0}
        closed = []

        def fake_pipe():
            calls["count"] += 1
            if calls["count"] == 1:
                return (0, 1)
            return (2, 3)

        def fake_close(fd):
            closed.append(fd)

        def fake_set_blocking(fd, blocking):
            raise AssertionError("STDIO_SET_BLOCKING_CALLED")

        with self.assertRaises(fence.NativeFenceError) as caught:
            fence._allocate_owned_pipes(fake_pipe, fake_close, fake_set_blocking)
        self.assertEqual(caught.exception.code, fence.NativeFenceErrorCode.STDIO_CONFLICT)
        self.assertEqual(len(closed), 4)

    def test_spawn_parameters_and_lifecycle(self):
        client = fence.NativeFenceClient()
        self.assertEqual(repr(client), "<NativeFenceClient>")
        parent_fds = (client._control_write, client._event_read)
        child_fds = (client._child_control_read, client._child_event_write)
        spec = client.spawn_parameters()
        self.assertEqual(spec.pass_fds, child_fds)
        self.assertEqual(set(spec.env_overlay), {fence.CONTROL_FD_ENV, fence.EVENT_FD_ENV})
        self.assertEqual(spec.env_overlay[fence.CONTROL_FD_ENV], str(child_fds[0]))
        self.assertEqual(spec.env_overlay[fence.EVENT_FD_ENV], str(child_fds[1]))
        self.assertEqual(repr(spec), "<NativeFenceSpawnParameters>")
        client.after_spawn()
        self._assert_closed(child_fds[0], child_fds[1])
        for fd in parent_fds:
            self.assertIsNotNone(os.fstat(fd))
        self._assert_code(fence.NativeFenceErrorCode.SPAWN_CLOSED, client.spawn_parameters)
        client.close()
        client.close()
        self._assert_closed(parent_fds[0], parent_fds[1])

    def test_failed_launch_closes_all(self):
        client = fence.NativeFenceClient()
        fds = (
            client._child_control_read,
            client._child_event_write,
            client._control_write,
            client._event_read,
        )
        client.close()
        client.close()
        self._assert_closed(*fds)

    def test_partial_setup_closes_created_fds(self):
        real_pipe = os.pipe
        first = real_pipe()
        used = {"value": False}

        def fake_pipe():
            if not used["value"]:
                used["value"] = True
                return first
            raise OSError()

        with mock.patch.object(fence.os, "pipe", fake_pipe):
            with self.assertRaises(fence.NativeFenceError) as caught:
                fence.NativeFenceClient()
        self.assertEqual(caught.exception.code, fence.NativeFenceErrorCode.PIPE_CREATE)
        self._assert_closed(first[0], first[1])

    def test_ready_release_adopted(self):
        client, peer = self._pair()
        peer.write_event(b"READY_HELD 2\n")
        ready = client.ready()
        self.assertEqual(ready.child_count, 2)
        self.assertEqual(set(ready.__dataclass_fields__), {"child_count"})
        self.assertFalse(hasattr(ready, "passed"))
        client.release()
        self.assertEqual(peer.read_control_line(), b"RELEASE\n")
        peer.write_event(b"ADOPTED 2\n")
        peer.close_event()
        adopted = client.wait_adopted()
        self.assertEqual(adopted.child_count, 2)
        self.assertEqual(set(adopted.__dataclass_fields__), {"child_count"})
        self.assertFalse(hasattr(adopted, "passed"))

    def test_cancel_keeps_control_open_and_no_release(self):
        client, peer = self._pair()
        peer.write_event(b"READY_HELD 2\n")
        client.ready()
        self.assertEqual(peer.control_available(), b"")
        peer.write_event(b"CANCELLED\n")
        self.assertEqual(peer.control_available(), b"")
        peer.write_event(b"DRAINED 2 1\n")
        peer.close_event()
        observation = client.wait_cancelled_drained()
        self.assertEqual(observation.closed_count, 2)
        self.assertTrue(observation.parent_locked)
        self.assertEqual(
            set(observation.__dataclass_fields__), {"closed_count", "parent_locked"}
        )
        self.assertFalse(hasattr(observation, "passed"))
        self.assertEqual(peer.control_available(), b"")
        self._assert_code(fence.NativeFenceErrorCode.CLOSED, client.wait_cancelled_drained)

    def test_release_order_and_duplicate_ready(self):
        client = fence.NativeFenceClient()
        self._assert_code(fence.NativeFenceErrorCode.INVALID_STATE, client.release)
        client.close()

        client, peer = self._pair()
        peer.write_event(b"READY_HELD 2\n")
        client.ready()
        self._assert_code(fence.NativeFenceErrorCode.INVALID_STATE, client.ready)
        self._assert_code(fence.NativeFenceErrorCode.INVALID_STATE, client.wait_adopted)
        client.release()
        self.assertEqual(peer.read_control_line(), b"RELEASE\n")
        self._assert_code(fence.NativeFenceErrorCode.INVALID_STATE, client.release)

    def test_ready_frame_errors(self):
        cases = [
            (b"NOPE\n", fence.NativeFenceErrorCode.EVENT_UNKNOWN, False),
            (b"READY_HELD 2 X\n", fence.NativeFenceErrorCode.EVENT_FIELDS, False),
            (b"READY_HELD 02\n", fence.NativeFenceErrorCode.EVENT_COUNT, False),
            (b"READY_HELD 65\n", fence.NativeFenceErrorCode.EVENT_COUNT, False),
            (b"READY_HELD \xff\n", fence.NativeFenceErrorCode.EVENT_NON_ASCII, False),
            (b"READY_HELD 2\r\n", fence.NativeFenceErrorCode.EVENT_FIELDS, False),
            (b"X" * 65, fence.NativeFenceErrorCode.EVENT_OVERSIZE, False),
            (b"READY_HELD 2", fence.NativeFenceErrorCode.EVENT_INCOMPLETE, True),
            (b"CANCELLED\n", fence.NativeFenceErrorCode.EVENT_UNEXPECTED, False),
        ]
        for payload, code, close_event in cases:
            with self.subTest(code=code.value):
                client, peer = self._pair(ready_timeout=0.2)
                peer.write_event(payload)
                if close_event:
                    peer.close_event()
                self._assert_code(code, client.ready)

    def test_drained_errors(self):
        cases = [
            (b"DRAINED 1 1\n", fence.NativeFenceErrorCode.EVENT_COUNT),
            (b"DRAINED 2 0\n", fence.NativeFenceErrorCode.EVENT_LOCKED),
            (b"DRAINED 02 1\n", fence.NativeFenceErrorCode.EVENT_COUNT),
            (b"DRAINED 2 2\n", fence.NativeFenceErrorCode.EVENT_FIELDS),
            (b"ADOPTED 2\n", fence.NativeFenceErrorCode.EVENT_UNEXPECTED),
        ]
        for payload, code in cases:
            with self.subTest(code=code.value):
                client, peer = self._pair()
                peer.write_event(b"READY_HELD 2\n")
                client.ready()
                peer.write_event(b"CANCELLED\n")
                peer.write_event(payload)
                peer.close_event()
                self._assert_code(code, client.wait_cancelled_drained)

    def test_extra_terminal_frame(self):
        client, peer = self._pair()
        peer.write_event(b"READY_HELD 2\n")
        client.ready()
        peer.write_event(b"CANCELLED\n")
        peer.write_event(b"DRAINED 2 1\n")
        peer.write_event(b"ADOPTED 2\n")
        peer.close_event()
        self._assert_code(
            fence.NativeFenceErrorCode.EVENT_EXTRA, client.wait_cancelled_drained
        )

    def test_total_byte_cap(self):
        client, peer = self._pair()
        stages = []
        peer.write_event(b"READY_HELD 2\n")
        client.ready()

        def writer():
            stages.append("TOTAL_WRITER_STARTED")
            peer.write_event(b"CANCELLED\n")
            stages.append("TOTAL_WRITER_CANCELLED")
            peer.write_event(b"DRAINED 2 1\n")
            stages.append("TOTAL_WRITER_DRAINED")
            peer.write_event(b"X" * 600)
            stages.append("TOTAL_WRITER_CAP_WRITTEN")
            peer.close_event()
            stages.append("TOTAL_WRITER_CLOSED")

        worker = threading.Thread(target=writer, daemon=True)
        stages.append("TOTAL_WAIT_READY")
        worker.start()
        self._assert_code(
            fence.NativeFenceErrorCode.EVENT_TOTAL_OVERSIZE,
            client.wait_cancelled_drained,
        )
        stages.append("TOTAL_WAIT_REJECTED")
        worker.join(1.0)
        self.assertFalse(worker.is_alive())
        stages.append("TOTAL_WRITER_JOINED")
        self.assertIn("TOTAL_WRITER_STARTED", stages)
        self.assertIn("TOTAL_WRITER_CLOSED", stages)
        self.assertIn("TOTAL_WAIT_REJECTED", stages)
        self.assertIn("TOTAL_WRITER_JOINED", stages)

    def test_fragment_timeout_is_not_extended(self):
        client, peer = self._pair(ready_timeout=0.12)
        peer.write_event(b"READY_HELD 2")
        started = time.monotonic()
        self._assert_code(fence.NativeFenceErrorCode.EVENT_TIMEOUT, client.ready)
        self.assertLess(time.monotonic() - started, 0.6)

    def test_cancel_deadline_not_extended_by_first_frame(self):
        client, peer = self._pair(event_timeout=0.12)
        peer.write_event(b"READY_HELD 2\n")
        client.ready()
        peer.write_event(b"CANCELLED\n")

        def delayed_drained():
            time.sleep(0.3)
            peer.write_event(b"DRAINED 2 1\n")
            peer.close_event()

        worker = threading.Thread(target=delayed_drained, daemon=True)
        worker.start()
        self._assert_code(
            fence.NativeFenceErrorCode.EVENT_TIMEOUT, client.wait_cancelled_drained
        )
        worker.join(1.0)
        self.assertFalse(worker.is_alive())

    def test_broken_control_pipe(self):
        client, peer = self._pair(write_timeout=0.2)
        peer.write_event(b"READY_HELD 2\n")
        client.ready()
        peer.close_control()
        self._assert_code(fence.NativeFenceErrorCode.CONTROL_WRITE_FAILED, client.release)

    def test_broken_event_pipe(self):
        client, peer = self._pair(ready_timeout=0.2)
        peer.close_event()
        self._assert_code(fence.NativeFenceErrorCode.EVENT_EOF, client.ready)

    def test_fds_closed_on_event_error(self):
        client = fence.NativeFenceClient(ready_timeout=0.2)
        child_fds = (client._child_control_read, client._child_event_write)
        peer = _Peer(client)
        self.addCleanup(peer.close)
        parent_fds = (client._control_write, client._event_read)
        peer.write_event(b"NOPE\n")
        peer.close_event()
        self._assert_code(fence.NativeFenceErrorCode.EVENT_UNKNOWN, client.ready)
        self._assert_closed(child_fds[0], child_fds[1], parent_fds[0], parent_fds[1])

    def test_release_dropped_observation(self):
        client, peer = self._pair()
        peer.write_event(b"READY_HELD 2\n")
        client.ready()
        client.release()
        self.assertEqual(peer.read_control_line(), b"RELEASE\n")
        peer.write_event(b"DRAINED 2 1\n")
        peer.close_event()
        observation = client.wait_release_result()
        self.assertIsInstance(observation, fence.ReleaseDropObservation)
        self.assertEqual(observation.closed_count, 2)
        self.assertTrue(observation.parent_locked)
        self.assertEqual(
            set(observation.__dataclass_fields__), {"closed_count", "parent_locked"}
        )
        self.assertFalse(hasattr(observation, "passed"))
        self.assertEqual(peer.control_available(), b"")
        self._assert_code(fence.NativeFenceErrorCode.CLOSED, client.wait_release_result)

    def test_wait_adopted_rejects_release_drop(self):
        client, peer = self._pair()
        peer.write_event(b"READY_HELD 2\n")
        client.ready()
        client.release()
        self.assertEqual(peer.read_control_line(), b"RELEASE\n")
        peer.write_event(b"DRAINED 2 1\n")
        peer.close_event()
        self._assert_code(
            fence.NativeFenceErrorCode.RELEASE_DROPPED, client.wait_adopted
        )
        self.assertTrue(client._closed)

    def test_release_dropped_validation(self):
        def run_case(payload, code, release=True):
            client, peer = self._pair()
            peer.write_event(b"READY_HELD 2\n")
            client.ready()
            if release:
                client.release()
                self.assertEqual(peer.read_control_line(), b"RELEASE\n")
            peer.write_event(payload)
            peer.close_event()
            self._assert_code(code, client.wait_release_result)

        cases = [
            (b"DRAINED 1 1\n", fence.NativeFenceErrorCode.EVENT_COUNT, True),
            (b"DRAINED 2 0\n", fence.NativeFenceErrorCode.EVENT_LOCKED, True),
            (b"DRAINED 2 2\n", fence.NativeFenceErrorCode.EVENT_FIELDS, True),
            (b"CANCELLED\n", fence.NativeFenceErrorCode.EVENT_UNEXPECTED, True),
            (b"ADOPTED 1\n", fence.NativeFenceErrorCode.EVENT_COUNT, True),
            (
                b"DRAINED 2 1\nADOPTED 2\n",
                fence.NativeFenceErrorCode.EVENT_EXTRA,
                True,
            ),
            (b"DRAINED 2 1\n", fence.NativeFenceErrorCode.INVALID_STATE, False),
        ]
        for payload, code, release in cases:
            with self.subTest(code=code.value, release=release):
                run_case(payload, code, release)

    def test_pending_event_check(self):
        client, peer = self._pair()
        peer.write_event(b"READY_HELD 2\n")
        client.ready()
        self.assertFalse(client.has_pending_event())
        peer.write_event(b"CANCELLED\n")
        self.assertTrue(client.has_pending_event())
        peer.write_event(b"DRAINED 2 1\n")
        peer.close_event()
        observation = client.wait_cancelled_drained()
        self.assertEqual(observation.closed_count, 2)
        self.assertTrue(observation.parent_locked)


if __name__ == "__main__":
    unittest.main()
