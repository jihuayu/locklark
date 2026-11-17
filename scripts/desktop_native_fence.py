from __future__ import annotations

import enum
import os
import select
import time
from dataclasses import dataclass
from typing import Mapping, Optional, Tuple


CONTROL_FD_ENV = "LOCKLARK_NATIVE_FENCE_CONTROL_FD"
EVENT_FD_ENV = "LOCKLARK_NATIVE_FENCE_EVENT_FD"

_RELEASE_PAYLOAD = b"RELEASE\n"
_MAX_CONTROL_FRAME = 16
_MAX_EVENT_FRAME = 64
_MAX_EVENT_TOTAL = 512
_MAX_CHILD_COUNT = 64
_DEFAULT_READY_TIMEOUT = 20.0
_DEFAULT_EVENT_TIMEOUT = 5.0
_DEFAULT_WRITE_TIMEOUT = 0.5


class NativeFenceErrorCode(enum.Enum):
    CLOSED = "CLOSED"
    INVALID_STATE = "INVALID_STATE"
    PIPE_CREATE = "PIPE_CREATE"
    STDIO_CONFLICT = "STDIO_CONFLICT"
    EVENT_TIMEOUT = "EVENT_TIMEOUT"
    EVENT_EOF = "EVENT_EOF"
    EVENT_INCOMPLETE = "EVENT_INCOMPLETE"
    EVENT_OVERSIZE = "EVENT_OVERSIZE"
    EVENT_TOTAL_OVERSIZE = "EVENT_TOTAL_OVERSIZE"
    EVENT_NON_ASCII = "EVENT_NON_ASCII"
    EVENT_FIELDS = "EVENT_FIELDS"
    EVENT_UNKNOWN = "EVENT_UNKNOWN"
    EVENT_COUNT = "EVENT_COUNT"
    EVENT_LOCKED = "EVENT_LOCKED"
    EVENT_UNEXPECTED = "EVENT_UNEXPECTED"
    EVENT_EXTRA = "EVENT_EXTRA"
    CONTROL_WRITE_FAILED = "CONTROL_WRITE_FAILED"
    CONTROL_WRITE_TIMEOUT = "CONTROL_WRITE_TIMEOUT"
    SPAWN_CLOSED = "SPAWN_CLOSED"


class NativeFenceError(Exception):
    """A fixed error enum without frames, OS text, or descriptor values."""

    def __init__(self, code: NativeFenceErrorCode):
        self.code = code
        super().__init__(code.value)

    def __str__(self) -> str:
        return self.code.value


@dataclass(frozen=True)
class ReadyObservation:
    child_count: int


@dataclass(frozen=True)
class CancelObservation:
    closed_count: int
    parent_locked: bool


@dataclass(frozen=True)
class AdoptObservation:
    child_count: int


@dataclass(frozen=True)
class SpawnParameters:
    pass_fds: Tuple[int, int]
    env_overlay: Mapping[str, str]

    def __repr__(self) -> str:
        return "<NativeFenceSpawnParameters>"


@dataclass(frozen=True)
class _Frame:
    kind: str
    count: Optional[int] = None
    parent_locked: Optional[bool] = None


def _safe_close(fd: Optional[int]) -> None:
    if fd is None:
        return
    try:
        os.close(fd)
    except OSError:
        pass


def _allocate_owned_pipes(pipe_factory, close_fd, set_blocking):
    created = []
    try:
        control_read, control_write = pipe_factory()
        created.extend((control_read, control_write))
        event_read, event_write = pipe_factory()
        created.extend((event_read, event_write))
        if any(fd < 3 for fd in created):
            raise NativeFenceError(NativeFenceErrorCode.STDIO_CONFLICT)
        set_blocking(control_write, False)
        set_blocking(event_read, False)
    except NativeFenceError:
        for fd in created:
            close_fd(fd)
        created.clear()
        raise
    except Exception:
        for fd in created:
            close_fd(fd)
        created.clear()
        raise NativeFenceError(NativeFenceErrorCode.PIPE_CREATE) from None
    return control_read, control_write, event_read, event_write


class NativeFenceClient:
    """Owned inherited-pipe client for the future tagged native fence child.

    The client owns both pipes and all four ends. It performs no subprocess
    launch, product action, authentication, UI action, or native acceptance.
    """

    def __init__(
        self,
        *,
        ready_timeout: float = _DEFAULT_READY_TIMEOUT,
        event_timeout: float = _DEFAULT_EVENT_TIMEOUT,
        write_timeout: float = _DEFAULT_WRITE_TIMEOUT,
    ):
        self._ready_timeout = float(ready_timeout)
        self._event_timeout = float(event_timeout)
        self._write_timeout = float(write_timeout)
        self._closed = False
        self._after_spawn = False
        self._ready = False
        self._released = False
        self._terminal = False
        self._child_count: Optional[int] = None
        self._event_buffer = bytearray()
        self._event_eof = False
        self._event_total = 0
        self._child_control_read: Optional[int] = None
        self._control_write: Optional[int] = None
        self._event_read: Optional[int] = None
        self._child_event_write: Optional[int] = None

        control_read, control_write, event_read, event_write = _allocate_owned_pipes(
            os.pipe, _safe_close, os.set_blocking
        )
        self._child_control_read = control_read
        self._control_write = control_write
        self._event_read = event_read
        self._child_event_write = event_write

    def __repr__(self) -> str:
        return "<NativeFenceClient>"

    def __enter__(self) -> "NativeFenceClient":
        self._ensure_open()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    def spawn_parameters(self) -> SpawnParameters:
        self._ensure_open()
        if self._after_spawn or self._child_control_read is None or self._child_event_write is None:
            raise NativeFenceError(NativeFenceErrorCode.SPAWN_CLOSED)
        control_fd = self._child_control_read
        event_fd = self._child_event_write
        return SpawnParameters(
            (control_fd, event_fd),
            {
                CONTROL_FD_ENV: str(control_fd),
                EVENT_FD_ENV: str(event_fd),
            },
        )

    def after_spawn(self) -> None:
        if self._after_spawn:
            return
        self._after_spawn = True
        self._close_child_ends()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._close_child_ends()
        _safe_close(self._control_write)
        _safe_close(self._event_read)
        self._control_write = None
        self._event_read = None

    def ready(self, timeout: Optional[float] = None) -> ReadyObservation:
        self._ensure_open()
        if self._ready or self._released or self._terminal:
            raise NativeFenceError(NativeFenceErrorCode.INVALID_STATE)
        deadline = time.monotonic() + self._timeout(timeout, self._ready_timeout)
        frame = self._read_frame(deadline)
        if frame.kind != "READY_HELD" or frame.count is None:
            self._fail(NativeFenceErrorCode.EVENT_UNEXPECTED)
        self._require_before(deadline)
        self._ready = True
        self._child_count = frame.count
        return ReadyObservation(frame.count)

    def release(self, timeout: Optional[float] = None) -> None:
        self._ensure_open()
        if not self._ready or self._released or self._terminal or self._child_count is None:
            raise NativeFenceError(NativeFenceErrorCode.INVALID_STATE)
        self._write_control(_RELEASE_PAYLOAD, self._timeout(timeout, self._write_timeout))
        self._released = True

    def wait_cancelled_drained(
        self, timeout: Optional[float] = None
    ) -> CancelObservation:
        self._ensure_open()
        if not self._ready or self._released or self._terminal:
            raise NativeFenceError(NativeFenceErrorCode.INVALID_STATE)
        deadline = time.monotonic() + self._timeout(timeout, self._event_timeout)
        first = self._read_frame(deadline)
        if first.kind != "CANCELLED":
            self._fail(NativeFenceErrorCode.EVENT_UNEXPECTED)
        second = self._read_frame(deadline)
        if second.kind != "DRAINED" or second.count is None or second.parent_locked is None:
            self._fail(NativeFenceErrorCode.EVENT_UNEXPECTED)
        if second.count != self._child_count:
            self._fail(NativeFenceErrorCode.EVENT_COUNT)
        if not second.parent_locked:
            self._fail(NativeFenceErrorCode.EVENT_LOCKED)
        self._confirm_terminal_eof(deadline)
        self._require_before(deadline)
        self._terminal = True
        observation = CancelObservation(second.count, True)
        self.close()
        return observation

    def wait_adopted(self, timeout: Optional[float] = None) -> AdoptObservation:
        self._ensure_open()
        if not self._released or self._terminal or self._child_count is None:
            raise NativeFenceError(NativeFenceErrorCode.INVALID_STATE)
        deadline = time.monotonic() + self._timeout(timeout, self._event_timeout)
        frame = self._read_frame(deadline)
        if frame.kind != "ADOPTED" or frame.count is None:
            self._fail(NativeFenceErrorCode.EVENT_UNEXPECTED)
        if frame.count != self._child_count:
            self._fail(NativeFenceErrorCode.EVENT_COUNT)
        self._confirm_terminal_eof(deadline)
        self._require_before(deadline)
        self._terminal = True
        observation = AdoptObservation(frame.count)
        self.close()
        return observation

    def has_pending_event(self) -> bool:
        self._ensure_open()
        if self._event_buffer:
            return True
        if self._event_eof:
            return False
        try:
            readable, _, _ = select.select([self._event_read], [], [], 0)
        except (OSError, ValueError):
            self._fail(NativeFenceErrorCode.EVENT_EOF)
        return bool(readable)

    def _ensure_open(self) -> None:
        if self._closed:
            raise NativeFenceError(NativeFenceErrorCode.CLOSED)

    def _close_child_ends(self) -> None:
        _safe_close(self._child_control_read)
        _safe_close(self._child_event_write)
        self._child_control_read = None
        self._child_event_write = None

    @staticmethod
    def _timeout(value: Optional[float], default: float) -> float:
        if value is None:
            return default
        value = float(value)
        return value if value > 0 else default

    def _require_before(
        self,
        deadline: float,
        code: NativeFenceErrorCode = NativeFenceErrorCode.EVENT_TIMEOUT,
    ) -> None:
        if time.monotonic() >= deadline:
            self._fail(code)

    def _fail(self, code: NativeFenceErrorCode) -> None:
        self.close()
        raise NativeFenceError(code) from None

    def _read_frame(self, deadline: float) -> _Frame:
        while True:
            self._require_before(deadline)
            newline = self._event_buffer.find(b"\n")
            if newline >= 0:
                if newline + 1 > _MAX_EVENT_FRAME:
                    self._fail(NativeFenceErrorCode.EVENT_OVERSIZE)
                frame = bytes(self._event_buffer[: newline + 1])
                del self._event_buffer[: newline + 1]
                self._require_before(deadline)
                return self._parse_frame(frame)
            if len(self._event_buffer) >= _MAX_EVENT_FRAME:
                self._fail(NativeFenceErrorCode.EVENT_OVERSIZE)
            if self._event_eof:
                if self._event_buffer:
                    self._fail(NativeFenceErrorCode.EVENT_INCOMPLETE)
                self._require_before(deadline)
                self._fail(NativeFenceErrorCode.EVENT_EOF)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self._fail(NativeFenceErrorCode.EVENT_TIMEOUT)
            try:
                readable, _, _ = select.select([self._event_read], [], [], remaining)
            except InterruptedError:
                self._require_before(deadline)
                continue
            except (OSError, ValueError):
                self._fail(NativeFenceErrorCode.EVENT_EOF)
            if not readable:
                self._fail(NativeFenceErrorCode.EVENT_TIMEOUT)
            self._require_before(deadline)
            try:
                chunk = os.read(self._event_read, 4096)
            except InterruptedError:
                self._require_before(deadline)
                continue
            except BlockingIOError:
                self._require_before(deadline)
                continue
            except OSError:
                self._fail(NativeFenceErrorCode.EVENT_EOF)
            if chunk == b"":
                self._event_eof = True
                continue
            self._event_total += len(chunk)
            if self._event_total > _MAX_EVENT_TOTAL:
                self._fail(NativeFenceErrorCode.EVENT_TOTAL_OVERSIZE)
            self._event_buffer.extend(chunk)

    def _parse_frame(self, frame: bytes) -> _Frame:
        if not frame.isascii():
            self._fail(NativeFenceErrorCode.EVENT_NON_ASCII)
        try:
            text = frame.decode("ascii")
        except UnicodeDecodeError:
            self._fail(NativeFenceErrorCode.EVENT_NON_ASCII)
        if not text.endswith("\n"):
            self._fail(NativeFenceErrorCode.EVENT_INCOMPLETE)
        body = text[:-1]
        if "\r" in body:
            self._fail(NativeFenceErrorCode.EVENT_FIELDS)
        fields = body.split(" ")
        if not fields or any(field == "" for field in fields):
            self._fail(NativeFenceErrorCode.EVENT_FIELDS)
        kind = fields[0]
        if kind == "READY_HELD":
            if len(fields) != 2:
                self._fail(NativeFenceErrorCode.EVENT_FIELDS)
            return _Frame("READY_HELD", self._parse_count(fields[1]))
        if kind == "CANCELLED":
            if len(fields) != 1:
                self._fail(NativeFenceErrorCode.EVENT_FIELDS)
            return _Frame("CANCELLED")
        if kind == "DRAINED":
            if len(fields) != 3:
                self._fail(NativeFenceErrorCode.EVENT_FIELDS)
            count = self._parse_count(fields[1])
            if fields[2] not in ("0", "1"):
                self._fail(NativeFenceErrorCode.EVENT_FIELDS)
            return _Frame("DRAINED", count, fields[2] == "1")
        if kind == "ADOPTED":
            if len(fields) != 2:
                self._fail(NativeFenceErrorCode.EVENT_FIELDS)
            return _Frame("ADOPTED", self._parse_count(fields[1]))
        self._fail(NativeFenceErrorCode.EVENT_UNKNOWN)

    def _parse_count(self, token: str) -> int:
        if not token or any(char < "0" or char > "9" for char in token):
            self._fail(NativeFenceErrorCode.EVENT_COUNT)
        if len(token) > 1 and token[0] == "0":
            self._fail(NativeFenceErrorCode.EVENT_COUNT)
        value = int(token)
        if value < 0 or value > _MAX_CHILD_COUNT:
            self._fail(NativeFenceErrorCode.EVENT_COUNT)
        return value

    def _confirm_terminal_eof(self, deadline: float) -> None:
        self._require_before(deadline)
        if self._event_buffer:
            code = (
                NativeFenceErrorCode.EVENT_TOTAL_OVERSIZE
                if self._event_total > _MAX_EVENT_TOTAL
                else NativeFenceErrorCode.EVENT_EXTRA
            )
            self._fail(code)
        if self._event_eof:
            self._require_before(deadline)
            return
        while True:
            self._require_before(deadline)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self._fail(NativeFenceErrorCode.EVENT_TIMEOUT)
            try:
                readable, _, _ = select.select([self._event_read], [], [], remaining)
            except InterruptedError:
                self._require_before(deadline)
                continue
            except (OSError, ValueError):
                self._fail(NativeFenceErrorCode.EVENT_EOF)
            if not readable:
                self._fail(NativeFenceErrorCode.EVENT_TIMEOUT)
            self._require_before(deadline)
            try:
                chunk = os.read(self._event_read, 4096)
            except InterruptedError:
                self._require_before(deadline)
                continue
            except BlockingIOError:
                self._require_before(deadline)
                continue
            except OSError:
                self._fail(NativeFenceErrorCode.EVENT_EOF)
            if chunk == b"":
                self._require_before(deadline)
                self._event_eof = True
                return
            self._event_total += len(chunk)
            if self._event_total > _MAX_EVENT_TOTAL:
                self._fail(NativeFenceErrorCode.EVENT_TOTAL_OVERSIZE)
            self._event_buffer.extend(chunk)
            self._fail(NativeFenceErrorCode.EVENT_EXTRA)

    def _write_control(self, payload: bytes, timeout: float) -> None:
        if len(payload) > _MAX_CONTROL_FRAME:
            self._fail(NativeFenceErrorCode.CONTROL_WRITE_FAILED)
        deadline = time.monotonic() + timeout
        offset = 0
        while offset < len(payload):
            self._require_before(deadline, NativeFenceErrorCode.CONTROL_WRITE_TIMEOUT)
            try:
                written = os.write(self._control_write, payload[offset:])
            except InterruptedError:
                self._require_before(deadline, NativeFenceErrorCode.CONTROL_WRITE_TIMEOUT)
                continue
            except BlockingIOError:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self._fail(NativeFenceErrorCode.CONTROL_WRITE_TIMEOUT)
                try:
                    _, writable, _ = select.select([], [self._control_write], [], remaining)
                except InterruptedError:
                    self._require_before(
                        deadline, NativeFenceErrorCode.CONTROL_WRITE_TIMEOUT
                    )
                    continue
                except (OSError, ValueError):
                    self._fail(NativeFenceErrorCode.CONTROL_WRITE_FAILED)
                if not writable:
                    self._fail(NativeFenceErrorCode.CONTROL_WRITE_TIMEOUT)
                self._require_before(
                    deadline, NativeFenceErrorCode.CONTROL_WRITE_TIMEOUT
                )
                continue
            except OSError:
                self._fail(NativeFenceErrorCode.CONTROL_WRITE_FAILED)
            if written <= 0:
                self._fail(NativeFenceErrorCode.CONTROL_WRITE_FAILED)
            offset += written
            self._require_before(deadline, NativeFenceErrorCode.CONTROL_WRITE_TIMEOUT)
