#!/usr/bin/env python3
"""Owner fixture: one persistent, private, real controlling terminal.

The product binds an interactive CLI approval to the *terminal* of the socket
peer: it reads the peer pid's kernel session id, controlling tty number and the
session leader's birth tick (``captureCLILeaseEvidence`` →
``browserhost.AttestCLITerminal``). ``scripts/run_cli_fixture ctty`` calls
``setsid()`` for every single invocation, so two ordinary CLI processes can
never share one terminal through it. This controller is the owner-side fixture
that keeps one session leader alive on a private pseudo terminal and launches
successive ordinary CLI processes *inside that same session and terminal* while
every child still gets its own pid, its own externally owned stdio pipes and
its own exit status.

Design rules:

* no shell is ever involved: a run is a fully formed argv list of owned
  executables plus a cwd and an environment dictionary;
* the fixture never prints or returns captured bytes in an error; failures
  raise ``FixtureError`` with a fixed short name only;
* no product test switch, attestation seam or hook is used: the real kernel
  state of the actual child (``/proc/<pid>/stat`` session + tty number and
  ``/proc/<pid>/exe``) is read and required to agree with the session leader;
* a private close-on-exec pipe holds every new child before ``execve`` until
  the leader has recorded that child's actual ``proc_stat`` session/tty; the
  leader never substitutes its own values for an unread child identity;
* the session leader is the only process that calls ``setsid()`` and
  ``TIOCSCTTY``. Children inherit the controlling terminal and must never be
  session leaders themselves, so a recycled session cannot match.

Usage
-----

::

    session = TerminalSession()   # forks the session leader, no threads yet
    session.start()               # drains the pty and waits for the ready proof
    run = session.run(argv, cwd, env)
    run.wait(60), run.captured_stdout(), run.identity
    session.stop(run.pid); session.close()

``proc_stat(pid)``  parsed ``/proc/<pid>/stat`` (ppid, session, tty number).
"""
import fcntl
import json
import os
import pty
import select
import signal
import socket
import struct
import termios
import threading
import time

TIOCSCTTY = getattr(termios, "TIOCSCTTY", 0x540E)

MAX_FRAME = 1 << 20
READY_TIMEOUT = 10.0
IDENTITY_TIMEOUT = 10.0
STOP_TIMEOUT = 10.0

# Fixed public proof stages for a detector timeout. They are a closed enum:
# no raw path, pid or exception text ever becomes a public stage.
PROOF_NO_EXE = "child-noexe"
PROOF_WAITING_STATUS = "child-waitingstatus"
PROOF_WRONG_EXE = "child-wrongexe"
PROOF_FAILURE_STAGES = frozenset((PROOF_NO_EXE, PROOF_WAITING_STATUS, PROOF_WRONG_EXE))


class FixtureError(RuntimeError):
    """Fixed-name fixture failure; never carries captured bytes or argv."""


def proc_stat(pid):
    """Return ppid/session/tty_nr from the real ``/proc/<pid>/stat``."""
    with open("/proc/%d/stat" % int(pid), "rb") as handle:
        raw = handle.read()
    # The comm field is parenthesised and may contain spaces or parentheses.
    close = raw.rfind(b")")
    if close < 0:
        raise FixtureError("proc-stat")
    fields = raw[close + 2:].split()
    if len(fields) < 5:
        raise FixtureError("proc-stat")
    return {"ppid": int(fields[1]), "session": int(fields[3]), "tty_nr": int(fields[4])}


def _proc_exe(pid):
    try:
        return os.readlink("/proc/%d/exe" % int(pid))
    except OSError:
        return None


def _proc_alive(pid):
    try:
        with open("/proc/%d/stat" % int(pid), "rb") as handle:
            raw = handle.read()
    except OSError:
        return False
    close = raw.rfind(b")")
    if close < 0:
        return False
    fields = raw[close + 2:].split()
    return bool(fields) and fields[0] not in (b"Z", b"X", b"x")


def _validate_argv(argv):
    if not isinstance(argv, (list, tuple)) or not argv:
        raise FixtureError("argv")
    checked = []
    for item in argv:
        if not isinstance(item, str) or not item or "\x00" in item:
            raise FixtureError("argv")
        checked.append(item)
    return checked


def _validate_env(env):
    if not isinstance(env, dict):
        raise FixtureError("env")
    checked = {}
    for key, value in env.items():
        if not isinstance(key, str) or not isinstance(value, str) or not key:
            raise FixtureError("env")
        if "\x00" in key or "\x00" in value:
            raise FixtureError("env")
        checked[key] = value
    return checked


def _resolve_program(program, env):
    """Resolve argv[0] exactly like execvp, without ever using a shell."""
    if os.sep in program:
        if not os.path.isfile(program) or not os.access(program, os.X_OK):
            raise FixtureError("program")
        return program
    for directory in env.get("PATH", os.defpath).split(os.pathsep):
        candidate = os.path.join(directory or os.curdir, program)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    raise FixtureError("program")


def _send_frame(sock, message, fds=()):
    payload = json.dumps(message, separators=(",", ":"), sort_keys=True).encode("utf-8")
    frame = struct.pack(">I", len(payload)) + payload
    if fds:
        import array
        sock.sendmsg([frame], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", fds))])
    else:
        sock.sendall(frame)


def _recv_exact(sock, count, fds):
    buffer = bytearray()
    while len(buffer) < count:
        data, ancillary, _flags, _address = sock.recvmsg(count - len(buffer), socket.CMSG_SPACE(4 * 8))
        if not data and not ancillary:
            raise FixtureError("session-eof")
        for level, kind, content in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                found = len(content) // 4
                if found:
                    fds.extend(struct.unpack("%di" % found, content[:found * 4]))
        buffer.extend(data)
    return bytes(buffer)


def _recv_frame(sock):
    fds = []
    header = _recv_exact(sock, 4, fds)
    (length,) = struct.unpack(">I", header)
    if length > MAX_FRAME:
        raise FixtureError("session-frame")
    body = _recv_exact(sock, length, fds)
    try:
        message = json.loads(body)
    except ValueError:
        raise FixtureError("session-frame")
    if not isinstance(message, dict):
        raise FixtureError("session-frame")
    return message, fds


def _exec_child(program, argv, cwd, env, stdout_fd, stderr_fd, extra_fds):
    """Never returns: replace this process image with the owned child argv."""
    try:
        # Match the ordinary driver (subprocess) signal disposition so the
        # product sees the same process state as in the one-shot acceptance.
        for number in (signal.SIGPIPE, signal.SIGXFSZ, signal.SIGCHLD,
                       signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            try:
                signal.signal(number, signal.SIG_DFL)
            except (OSError, ValueError):
                pass
        os.dup2(stdout_fd, 1)
        os.dup2(stderr_fd, 2)
        for fd in set((stdout_fd, stderr_fd) + tuple(extra_fds)):
            if fd > 2:
                try:
                    os.close(fd)
                except OSError:
                    pass
        os.chdir(cwd)
        os.execve(program, argv, env)
    except BaseException:
        pass
    os._exit(127)


def _session_leader(control, tty_fd):
    """Own the private pty once, then serve controlled child launches forever."""
    control_fd = control.fileno()
    try:
        os.setsid()
        fcntl.ioctl(tty_fd, TIOCSCTTY, 0)
        os.dup2(tty_fd, 0)
        if tty_fd != 0:
            os.close(tty_fd)
        # The leader must never write onto the caller's own console.
        null = os.open(os.devnull, os.O_RDWR)
        os.dup2(null, 1)
        os.dup2(null, 2)
        if null > 2:
            os.close(null)
    except BaseException:
        os._exit(2)

    wake_read, wake_write = os.pipe()
    for fd in (wake_read, wake_write):
        fcntl.fcntl(fd, fcntl.F_SETFL, fcntl.fcntl(fd, fcntl.F_GETFL) | os.O_NONBLOCK)
        fcntl.fcntl(fd, fcntl.F_SETFD, fcntl.FD_CLOEXEC)

    reaped = {}

    def on_child(signum, frame):
        try:
            os.write(wake_write, b"\0")
        except OSError:
            pass

    signal.signal(signal.SIGCHLD, on_child)

    def reap():
        while True:
            try:
                pid, status = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                return
            if pid == 0:
                return
            reaped[pid] = status

    def reply(message):
        try:
            _send_frame(control, message)
        except OSError:
            raise FixtureError("session-control")

    try:
        ready = proc_stat(os.getpid())
        if ready["session"] != os.getpid() or ready["tty_nr"] == 0:
            os._exit(3)
        reply({"event": "ready", "pid": os.getpid(), "session": ready["session"],
               "tty_nr": ready["tty_nr"]})
    except BaseException:
        os._exit(4)
    leader = ready

    while True:
        try:
            readable = select.select([control, wake_read], [], [], 60.0)[0]
        except OSError:
            os._exit(5)
        if wake_read in readable:
            try:
                while os.read(wake_read, 4096):
                    pass
            except OSError:
                pass
            reap()
        if control not in readable:
            continue
        try:
            message, fds = _recv_frame(control)
        except FixtureError:
            os._exit(6)
        op = message.get("op")
        if op == "run":
            try:
                argv = _validate_argv(message.get("argv"))
                program = message.get("exec")
                if not isinstance(program, str) or not program or "\x00" in program:
                    raise FixtureError("program")
                cwd = message.get("cwd")
                env = _validate_env(message.get("env"))
                if not isinstance(cwd, str) or not cwd or "\x00" in cwd:
                    raise FixtureError("cwd")
                if len(fds) != 2:
                    raise FixtureError("stdio")
            except FixtureError:
                for fd in fds:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
                reply({"ok": False, "error": "run"})
                continue
            stdout_fd, stderr_fd = fds
            try:
                barrier_read, barrier_write = os.pipe()
            except OSError:
                for fd in fds:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
                reply({"ok": False, "error": "fork"})
                continue
            for fd in (barrier_read, barrier_write):
                try:
                    fcntl.fcntl(fd, fcntl.F_SETFD,
                                fcntl.fcntl(fd, fcntl.F_GETFD) | fcntl.FD_CLOEXEC)
                except OSError:
                    pass
            try:
                pid = os.fork()
            except OSError:
                for fd in (barrier_read, barrier_write) + tuple(fds):
                    try:
                        os.close(fd)
                    except OSError:
                        pass
                reply({"ok": False, "error": "fork"})
                continue
            if pid == 0:
                # Wait for the parent's single release byte before exec so the
                # parent can read this real child's actual kernel session/tty
                # while it is definitely alive and blocked here. Any failure
                # (EOF, wrong byte, interrupted read) exits without exec.
                try:
                    os.close(barrier_write)
                except OSError:
                    pass
                try:
                    released = os.read(barrier_read, 1) == b"\x01"
                except OSError:
                    released = False
                if not released:
                    os._exit(127)
                _exec_child(program, argv, cwd, env, stdout_fd, stderr_fd,
                            (control_fd, wake_read, wake_write, barrier_read))
                os._exit(127)  # unreachable
            try:
                os.close(barrier_read)
            except OSError:
                pass
            for fd in fds:
                try:
                    os.close(fd)
                except OSError:
                    pass
            # Capture the actual kernel session/tty of the real just-forked
            # child while it is guaranteed alive and blocked before exec. Only
            # this actual read is used; the leader's own values are never
            # substituted for a missing child read.
            child = None
            try:
                candidate = proc_stat(pid)
                if (candidate["session"] == leader["session"]
                        and candidate["tty_nr"] == leader["tty_nr"]
                        and candidate["session"] != pid):
                    child = candidate
            except (FixtureError, OSError):
                child = None
            if child is None:
                # No recorded real identity: never let this child exec.
                try:
                    os.kill(pid, signal.SIGKILL)
                except OSError:
                    pass
                try:
                    os.waitpid(pid, 0)
                except OSError:
                    pass
                try:
                    os.close(barrier_write)
                except OSError:
                    pass
                reply({"ok": False, "error": "child-identity"})
                continue
            try:
                os.write(barrier_write, b"\x01")
            except OSError:
                try:
                    os.kill(pid, signal.SIGKILL)
                except OSError:
                    pass
                try:
                    os.waitpid(pid, 0)
                except OSError:
                    pass
                reply({"ok": False, "error": "child-identity"})
                continue
            finally:
                try:
                    os.close(barrier_write)
                except OSError:
                    pass
            reply({"ok": True, "pid": pid, "session": child["session"],
                   "tty_nr": child["tty_nr"]})
        elif op == "status":
            pid = message.get("pid")
            if not isinstance(pid, int) or pid <= 0:
                reply({"ok": False, "error": "pid"})
                continue
            reap()
            if pid not in reaped:
                reply({"ok": True, "state": "running"})
                continue
            status = reaped[pid]
            if os.WIFSIGNALED(status):
                reply({"ok": True, "state": "signaled", "signal": os.WTERMSIG(status)})
            else:
                reply({"ok": True, "state": "exited", "code": os.WEXITSTATUS(status)})
        elif op == "stop":
            pid = message.get("pid")
            if not isinstance(pid, int) or pid <= 0:
                reply({"ok": False, "error": "pid"})
                continue
            if pid not in reaped:
                try:
                    os.kill(pid, signal.SIGKILL)
                except OSError:
                    pass
                deadline = time.monotonic() + STOP_TIMEOUT
                while pid not in reaped and time.monotonic() < deadline:
                    try:
                        if select.select([wake_read], [], [], 0.05)[0]:
                            while os.read(wake_read, 4096):
                                pass
                    except OSError:
                        pass
                    reap()
            reply({"ok": True, "reaped": pid in reaped})
        elif op == "close":
            reply({"ok": True})
            break
        else:
            reply({"ok": False, "error": "operation"})

    for fd in (wake_read, wake_write):
        try:
            os.close(fd)
        except OSError:
            pass
    os._exit(0)


class TerminalRun:
    """One ordinary CLI process launched inside the shared terminal session."""

    def __init__(self, session, argv, pid, identity, stdout_read, stderr_read):
        self.session = session
        self.argv = tuple(argv)
        self.pid = pid
        self.identity = identity
        self.cwd = identity["cwd"]
        self.stdout = bytearray()
        self.stderr = bytearray()
        self._lock = threading.Lock()
        self._readers = []
        self._status = None
        self._stop = threading.Event()
        for read_fd, sink in ((stdout_read, self.stdout), (stderr_read, self.stderr)):
            reader = threading.Thread(target=self._read_pipe, args=(read_fd, sink), daemon=True)
            reader.start()
            self._readers.append((reader, read_fd))

    def _read_pipe(self, fd, sink):
        while not self._stop.is_set():
            try:
                ready = select.select([fd], [], [], 0.1)[0]
            except (OSError, ValueError):
                return
            if not ready:
                continue
            try:
                chunk = os.read(fd, 4096)
            except OSError:
                return
            if not chunk:
                return
            with self._lock:
                sink.extend(chunk)

    def captured_stdout(self):
        with self._lock:
            return bytes(self.stdout)

    def captured_stderr(self):
        with self._lock:
            return bytes(self.stderr)

    def captured_terminal(self):
        return self.session.captured_terminal()

    def status(self):
        if self._status is None:
            self._status = self.session.status(self.pid)
        return self._status

    def wait(self, timeout):
        deadline = time.monotonic() + float(timeout)
        while True:
            state = self.status()
            if state is not None:
                return state.get("code") if state.get("state") == "exited" else -1
            if time.monotonic() >= deadline:
                return None
            time.sleep(0.05)

    def drain(self, timeout=5.0):
        """Wait for the capture readers to reach EOF without closing them.

        A fast, expected refusal may exit before the controller can inspect
        it. Draining the real stdout/stderr pipes first prevents a factor
        prompt from being missed in a not-yet-read kernel buffer.
        """
        for reader, _fd in list(self._readers):
            reader.join(timeout=timeout)

    def release(self):
        """Join the capture readers and close their pipe ends."""
        self._stop.set()
        for reader, fd in self._readers:
            reader.join(timeout=5)
            try:
                os.close(fd)
            except OSError:
                pass
        self._readers = []

    def stop(self):
        self.session.stop(self.pid)
        self.release()


class TerminalSession:
    """A persistent session leader with one private real controlling terminal."""

    def __init__(self):
        self.master, slave = pty.openpty()
        self.tty_path = os.ttyname(slave)
        parent_control, child_control = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        self._lock = threading.Lock()
        self._tty = bytearray()
        self._tty_lock = threading.Lock()
        self._closed = False
        self._reader = None
        self.identity = None
        self.pid = -1
        try:
            pid = os.fork()
            if pid == 0:
                try:
                    parent_control.close()
                    os.close(self.master)
                    _session_leader(child_control, slave)
                finally:
                    os._exit(7)
        except BaseException:
            parent_control.close()
            child_control.close()
            os.close(self.master)
            os.close(slave)
            raise
        child_control.close()
        os.close(slave)
        self.control = parent_control
        self.pid = pid
        fcntl.fcntl(self.control.fileno(), fcntl.F_SETFD, fcntl.FD_CLOEXEC)

    def start(self):
        """Start the private capture and require the real session-leader proof."""
        if self.identity is not None:
            return self
        self._reader = threading.Thread(target=self._read_terminal, daemon=True)
        self._reader.start()
        ready, _ = _recv_frame(self.control)
        if ready.get("event") != "ready" or ready.get("pid") != self.pid:
            self.close()
            raise FixtureError("session-ready")
        identity = {"pid": ready["pid"], "session": ready["session"],
                    "tty_nr": ready["tty_nr"], "tty_path": self.tty_path}
        try:
            identity["fd0"] = os.readlink("/proc/%d/fd/0" % self.pid)
        except OSError:
            identity["fd0"] = None
        if identity["session"] != identity["pid"] or identity["tty_nr"] == 0:
            self.close()
            raise FixtureError("session-identity")
        self.identity = identity
        return self

    def _read_terminal(self):
        while not self._closed:
            try:
                ready = select.select([self.master], [], [], 0.1)[0]
            except (OSError, ValueError):
                return
            if not ready:
                continue
            try:
                chunk = os.read(self.master, 4096)
            except OSError:
                return
            if not chunk:
                return
            with self._tty_lock:
                self._tty.extend(chunk)

    def captured_terminal(self):
        with self._tty_lock:
            return bytes(self._tty)

    def status(self, pid):
        with self._lock:
            _send_frame(self.control, {"op": "status", "pid": int(pid)})
            reply, _ = _recv_frame(self.control)
        if reply.get("ok") is not True:
            raise FixtureError("status")
        if reply.get("state") == "running":
            return None
        return reply

    def stop(self, pid):
        with self._lock:
            _send_frame(self.control, {"op": "stop", "pid": int(pid)})
            reply, _ = _recv_frame(self.control)
        if reply.get("ok") is not True:
            raise FixtureError("stop")

    def run(self, argv, cwd, env, allow_finished=False):
        """Launch one owned argv inside this terminal; returns a TerminalRun.

        With ``allow_finished=True`` the fixture may return a run whose real
        process already exited before a live /proc/<pid>/exe peek was
        possible. It still reports the actual forked pid, the kernel
        session/tty captured from the real child (held before exec by the
        leader's private pipe barrier) and the real reaped wait status; it
        never invents execution. The controller only uses this mode for the
        expected closed-lock refusal and still requires a nonzero exit.
        """
        if self.identity is None:
            raise FixtureError("session-not-started")
        argv = _validate_argv(argv)
        cwd = os.fspath(cwd)
        if not isinstance(cwd, str) or not cwd or "\x00" in cwd:
            raise FixtureError("cwd")
        env = _validate_env(env)
        program = _resolve_program(argv[0], env)
        stdout_read, stdout_write = os.pipe()
        stderr_read, stderr_write = os.pipe()
        try:
            with self._lock:
                _send_frame(self.control, {"op": "run", "argv": argv, "exec": program,
                                           "cwd": cwd, "env": env},
                            [stdout_write, stderr_write])
                reply, _ = _recv_frame(self.control)
        except BaseException:
            for fd in (stdout_read, stderr_read):
                try:
                    os.close(fd)
                except OSError:
                    pass
            raise
        finally:
            for fd in (stdout_write, stderr_write):
                try:
                    os.close(fd)
                except OSError:
                    pass
        if reply.get("ok") is not True or not isinstance(reply.get("pid"), int):
            for fd in (stdout_read, stderr_read):
                try:
                    os.close(fd)
                except OSError:
                    pass
            raise FixtureError("run")
        try:
            identity = self._prove(reply["pid"], program, allow_finished,
                                   {"session": reply.get("session"),
                                    "tty_nr": reply.get("tty_nr")})
        except BaseException:
            for fd in (stdout_read, stderr_read):
                try:
                    os.close(fd)
                except OSError:
                    pass
            raise
        identity["cwd"] = cwd
        return TerminalRun(self, argv, reply["pid"], identity, stdout_read, stderr_read)

    def _prove(self, pid, program, allow_finished=False, fork_identity=None):
        """Require real kernel proof of tty, session and executable.

        Every grant, reuse and default run must produce a live
        ``/proc/<pid>/exe`` peek plus the actual kernel session/tty. Only
        ``allow_finished`` (the expected closed-lock refusal) may accept a
        process that already finished. In that mode the actual reaped status is
        polled on every iteration: the kernel may reap the child before
        ``/proc/<pid>/exe`` is readable, and a terminal status still returns the
        session/tty captured by the session leader at the real fork. The
        returned identity honestly marks ``live_exe`` false and carries no
        executable path. If the status is still unavailable and the process is
        already gone, keep waiting until the detector deadline instead of
        reporting a fabricated result; timeouts use only fixed proof stages.
        """
        expected = os.path.realpath(program)
        deadline = time.monotonic() + IDENTITY_TIMEOUT
        saw_exe = matched_exe = wrong_exe = False
        while True:
            if allow_finished:
                state = self.status(pid)
                if isinstance(state, dict) and state.get("state") in ("exited", "signaled"):
                    return self._finished_identity(pid, fork_identity)
            exe = _proc_exe(pid)
            if exe is not None:
                saw_exe = True
                if os.path.realpath(exe) == expected:
                    matched_exe = True
                    try:
                        stat = proc_stat(pid)
                    except (FixtureError, OSError):
                        stat = None
                    if stat is not None and stat["tty_nr"] != 0:
                        if (stat["session"] != self.identity["session"]
                                or stat["tty_nr"] != self.identity["tty_nr"]):
                            raise FixtureError("child-identity")
                        if stat["session"] == pid:
                            raise FixtureError("child-identity")
                        return {"pid": pid, "session": stat["session"],
                                "tty_nr": stat["tty_nr"], "exe": exe,
                                "tty_path": self.tty_path, "live_exe": True}
                else:
                    wrong_exe = True
            if not _proc_alive(pid) and not allow_finished:
                # Default, grant, reuse and wrong-terminal runs must never
                # accept a finished process: no live proof is fatal.
                raise FixtureError("child-exe")
            if time.monotonic() >= deadline:
                raise FixtureError(self._proof_stage(saw_exe, matched_exe, wrong_exe))
            time.sleep(0.01)

    @staticmethod
    def _proof_stage(saw_exe, matched_exe, wrong_exe):
        """Fixed public proof stage; never a raw path, pid or exception text."""
        if wrong_exe and not matched_exe:
            return PROOF_WRONG_EXE
        if not saw_exe:
            return PROOF_NO_EXE
        return PROOF_WAITING_STATUS

    def _finished_identity(self, pid, fork_identity):
        """Honest finished identity from the actual fork metadata only."""
        fork_identity = fork_identity or {}
        session = fork_identity.get("session")
        tty_nr = fork_identity.get("tty_nr")
        if not isinstance(session, int) or not isinstance(tty_nr, int):
            raise FixtureError("child-identity")
        if session != self.identity["session"] or tty_nr != self.identity["tty_nr"]:
            raise FixtureError("child-identity")
        if session == pid:
            raise FixtureError("child-identity")
        return {"pid": pid, "session": session, "tty_nr": tty_nr,
                "exe": None, "tty_path": self.tty_path, "live_exe": False}

    def close(self):
        if self._closed:
            return
        self._closed = True
        try:
            with self._lock:
                _send_frame(self.control, {"op": "close"})
                _recv_frame(self.control)
        except (FixtureError, OSError):
            pass
        try:
            os.kill(self.pid, signal.SIGKILL)
        except OSError:
            pass
        try:
            os.waitpid(self.pid, 0)
        except OSError:
            pass
        try:
            self.control.close()
        except OSError:
            pass
        if self._reader is not None:
            self._reader.join(timeout=5)
        try:
            os.close(self.master)
        except OSError:
            pass

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.close()
        return False
