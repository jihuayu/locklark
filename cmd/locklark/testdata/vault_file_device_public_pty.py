"""Run the real CLI on an owned controlling PTY; emit only a bounded verdict."""

import errno
import json
import os
import pty
import select
import signal
import sys
import time


MASTER_PROMPT = "主密码: ".encode("utf-8")
SECRET_PROMPT = b"Secret Key: "
AUTH_REFUSAL = b"locklark: invalid personal vault, unlock factors or journal\n"
MISSING_REFUSAL = b"locklark: terminal input cancelled or exceeded maximum length\n"
PUBLIC_FIELDS = {"age_recipient", "content_signing_public_key"}
MAX_OUTPUT = 128 * 1024
READ_SIZE = 4096
DEADLINE_SECONDS = 20


def zero(output):
    for index in range(len(output)):
        output[index] = 0


def unique_fields(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate public field")
        result[key] = value
    return result


def one_public_record(transcript):
    prefix = MASTER_PROMPT + b"\n" + SECRET_PROMPT + b"\n"
    if not transcript.startswith(prefix):
        return None
    record = transcript[len(prefix):]
    if len(record) > 512 or not record.endswith(b"\n") or record.count(b"\n") != 1:
        return None
    try:
        public = json.loads(record[:-1], object_pairs_hook=unique_fields)
    except (UnicodeDecodeError, ValueError):
        return None
    if not isinstance(public, dict) or set(public) != PUBLIC_FIELDS:
        return None
    recipient = public["age_recipient"]
    signer = public["content_signing_public_key"]
    if (not isinstance(recipient, str) or not recipient.startswith("age1") or
            len(recipient) > 128 or not isinstance(signer, str) or
            len(signer) != 64 or any(c not in "0123456789abcdef" for c in signer)):
        return None
    return public


def verdict(status, echoed=False, public=None):
    print(json.dumps({"status": status, "echoed": echoed, "public": public}), flush=True)


def terminate_and_reap(leader):
    if leader["reaped"]:
        return leader["status"]
    try:
        os.kill(leader["pid"], signal.SIGKILL)
    except OSError:
        pass
    try:
        _, status = os.waitpid(leader["pid"], 0)
    except ChildProcessError:
        return None
    leader["status"] = status
    leader["reaped"] = True
    return status


def collect_owned_pty(leader, master, password, secret, missing, deadline,
                      read_size=READ_SIZE, exit_barrier=None, clock=None,
                      before_completion_accept=None):
    """Drain until the owned PTY reaches EOF/EIO, then reap the leader once.

    A leader exit is not transcript completion and reaping can discard bytes
    still buffered on the master.  This loop therefore never calls waitpid
    while the PTY is open: it keeps reading residual bytes until EOF/EIO (or a
    bound/deadline) and only then observes the leader's exit status.  An
    incomplete transcript is never classified as PUBLIC or REFUSED.
    """
    clock = time.monotonic if clock is None else clock
    output = bytearray()
    phase = 0
    eof = False
    bounded_out = False
    timed_out = False
    read_error = False
    barrier_closed = exit_barrier is None
    try:
        while True:
            if clock() >= deadline:
                timed_out = True
                break
            if eof:
                # The master is already at EOF/EIO.  Give the leader a
                # bounded opportunity to become reapable, then stop.
                select.select([], [], [], min(0.1, max(0.0, deadline - clock())))
            elif phase == 2 and not barrier_closed:
                # Regression seam: the child owns the write end of this pipe,
                # so its EOF proves the direct child has exited before any
                # residual transcript bytes are read.
                timeout = min(0.1, max(0.0, deadline - clock()))
                ready, _, _ = select.select([exit_barrier], [], [], timeout)
                if ready:
                    try:
                        if os.read(exit_barrier, 1) == b"":
                            barrier_closed = True
                    except OSError:
                        barrier_closed = True
                continue
            else:
                timeout = min(0.1, max(0.0, deadline - clock()))
                ready, _, _ = select.select([master], [], [], timeout)
                if ready:
                    try:
                        chunk = os.read(master, read_size)
                    except OSError as exc:
                        if exc.errno != errno.EIO:
                            read_error = True
                            break
                        chunk = b""
                        eof = True
                    if clock() >= deadline:
                        timed_out = True
                        break
                    if chunk:
                        output.extend(chunk)
                        if len(output) > MAX_OUTPUT:
                            bounded_out = True
                            break
                        try:
                            if phase == 0 and MASTER_PROMPT in output:
                                if clock() >= deadline:
                                    timed_out = True
                                    break
                                os.write(master, password + b"\n")
                                phase = 1
                            if phase == 1 and SECRET_PROMPT in output:
                                if clock() >= deadline:
                                    timed_out = True
                                    break
                                os.write(master, b"\x04" if missing else secret + b"\n")
                                phase = 2
                        except OSError:
                            read_error = True
                            break
                    else:
                        eof = True
            if eof and not leader["reaped"]:
                try:
                    got, status = os.waitpid(leader["pid"], os.WNOHANG)
                except ChildProcessError:
                    got = 0
                if got == leader["pid"]:
                    leader["status"] = status
                    leader["reaped"] = True
            if eof and leader["reaped"]:
                if before_completion_accept is not None:
                    before_completion_accept()
                if clock() >= deadline:
                    timed_out = True
                break
        return {
            "output": output,
            "phase": phase,
            "eof": eof,
            "bounded_out": bounded_out,
            "timed_out": timed_out,
            "read_error": read_error,
            "barrier_closed": barrier_closed,
        }
    except BaseException:
        zero(output)
        raise


def complete_transcript(collected, status):
    return (status is not None and collected["eof"] and
            not collected["bounded_out"] and not collected["timed_out"] and
            not collected["read_error"])


def classify(collected, status, password, secret, missing):
    output = collected["output"]
    complete = complete_transcript(collected, status)
    echoed = password in output or secret in output
    normalized = bytearray(bytes(output).replace(b"\r\n", b"\n"))
    try:
        public = one_public_record(normalized) if complete and not echoed else None
        expected = (MASTER_PROMPT + b"\n" + SECRET_PROMPT +
                    (b"" if missing else b"\n") +
                    (MISSING_REFUSAL if missing else AUTH_REFUSAL))
        if (complete and os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0 and
                collected["phase"] == 2 and not echoed and public is not None):
            return "PUBLIC", echoed, public
        if (complete and os.WIFEXITED(status) and os.WEXITSTATUS(status) == 1 and
                collected["phase"] == 2 and not echoed and public is None and
                normalized == expected):
            return "REFUSED", echoed, None
        return "HARNESS_ERROR", echoed, None
    finally:
        zero(normalized)


# A real PTY child for the drain regression.  It uses the same hidden prompts
# as the fixtures, reads both synthetic factors from the owned terminal, then
# writes its residual bytes (including a leaked factor when asked) and exits.
SELFTEST_CHILD = r'''
import os
import sys
import termios

mode = sys.argv[1]
attrs = termios.tcgetattr(0)
attrs[3] &= ~termios.ECHO
termios.tcsetattr(0, termios.TCSANOW, attrs)

def read_line():
    line = bytearray()
    while True:
        chunk = os.read(0, 1)
        if not chunk or chunk == b"\n":
            return bytes(line)
        if chunk != b"\r":
            line.extend(chunk)

os.write(1, "主密码: ".encode("utf-8"))
read_line()
os.write(1, b"\nSecret Key: ")
secret = read_line()
if mode == "leak":
    os.write(1, b"\n" + secret + b"\n")
    os.write(1, b'{"age_recipient":"age1selftest","content_signing_public_key":"' +
             b"0" * 64 + b'"}\n')
    os._exit(0)
if mode == "public":
    os.write(1, b'\n{"age_recipient":"age1selftest","content_signing_public_key":"' +
             b"0" * 64 + b'"}\n')
    os._exit(0)
os.write(1, b"\nlocklark: invalid personal vault, unlock factors or journal\n")
os._exit(1)
'''


class SelftestClock:
    """Test-only deadline control; real main always uses time.monotonic."""

    def __init__(self, deadline):
        self.deadline = deadline
        self.start = time.monotonic()
        self.expired = False

    def __call__(self):
        if self.expired:
            return self.deadline + 1.0
        return time.monotonic() - self.start

    def expire(self):
        self.expired = True


def run_selftest_case(mode, password, secret, missing=False, late_completion=False):
    barrier_read, barrier_write = os.pipe()
    os.set_inheritable(barrier_write, True)
    pid, master = pty.fork()
    if pid == 0:
        try:
            os.close(barrier_read)
            os.execv(sys.executable, [sys.executable, "-I", "-B", "-c",
                                      SELFTEST_CHILD, mode])
        except OSError:
            os._exit(127)
    os.close(barrier_write)
    leader = {"pid": pid, "reaped": False, "status": None}
    collected = None
    try:
        if late_completion:
            deadline = 5.0
            clock = SelftestClock(deadline)
            before_completion_accept = clock.expire
        else:
            deadline = time.monotonic() + 5
            clock = None
            before_completion_accept = None
        collected = collect_owned_pty(
            leader, master, password, secret, missing,
            deadline, read_size=1, exit_barrier=barrier_read, clock=clock,
            before_completion_accept=before_completion_accept)
        status = leader["status"]
        if not leader["reaped"]:
            status = terminate_and_reap(leader)
        result, echoed, public = classify(collected, status, password, secret, missing)
        return {
            "result": result,
            "echoed": echoed,
            "public": public,
            "barrier_closed": collected["barrier_closed"],
            "eof": collected["eof"],
            "timed_out": collected["timed_out"],
            "phase": collected["phase"],
            "leader_reaped": leader["reaped"],
        }
    finally:
        try:
            os.close(barrier_read)
        except OSError:
            pass
        try:
            os.close(master)
        except OSError:
            pass
        if not leader["reaped"]:
            terminate_and_reap(leader)
        if collected is not None:
            zero(collected["output"])


def selftest():
    password = b"synthetic-selftest-password"
    secret = b"SYNTHETIC-SELFTEST-FACTOR"
    leak = run_selftest_case("leak", password, secret)
    public = run_selftest_case("public", password, secret)
    refusal = run_selftest_case("refusal", password, secret)
    late = run_selftest_case("public", password, secret, late_completion=True)
    expected_public = {
        "age_recipient": "age1selftest",
        "content_signing_public_key": "0" * 64,
    }
    checks = {
        "leak_refused": (leak["result"] == "HARNESS_ERROR" and
                         leak["echoed"] and leak["public"] is None),
        "leak_after_exit": (leak["barrier_closed"] and leak["eof"] and
                            leak["phase"] == 2 and leak["leader_reaped"]),
        "public_exact": (public["result"] == "PUBLIC" and not public["echoed"] and
                         public["public"] == expected_public),
        "public_after_exit": (public["barrier_closed"] and public["eof"] and
                              public["phase"] == 2 and public["leader_reaped"]),
        "refusal_exact": (refusal["result"] == "REFUSED" and not refusal["echoed"] and
                          refusal["public"] is None),
        "refusal_after_exit": (refusal["barrier_closed"] and refusal["eof"] and
                               refusal["phase"] == 2 and refusal["leader_reaped"]),
        "late_completion_refused": (
            late["result"] == "HARNESS_ERROR" and not late["echoed"] and
            late["public"] is None and late["timed_out"] and late["eof"] and
            late["phase"] == 2 and late["leader_reaped"] and late["barrier_closed"]),
    }
    print(json.dumps(checks), flush=True)
    return 0 if all(checks.values()) else 1


def main():
    leader = {"pid": None, "reaped": False, "status": None}
    master = None
    collected = None
    try:
        request = json.load(sys.stdin)
        product = request["product"]
        path = request["path"]
        password = request["password"].encode("utf-8")
        secret = request["secret"].encode("ascii")
        missing = request["missing_secret"]
        if not os.path.isabs(product) or not os.path.isabs(path):
            verdict("HARNESS_ERROR")
            return
        pid, master = pty.fork()
        leader["pid"] = pid
        if pid == 0:
            try:
                os.execv(product, [product, "personal", "vault-file-device-public",
                                   "--file", path])
            except OSError:
                os._exit(127)
        collected = collect_owned_pty(
            leader, master, password, secret, missing,
            time.monotonic() + DEADLINE_SECONDS)
        status = leader["status"]
        if not leader["reaped"]:
            status = terminate_and_reap(leader)
        result, echoed, public = classify(collected, status, password, secret, missing)
        verdict(result, echoed=echoed, public=public)
    except (KeyError, OSError, ValueError):
        verdict("HARNESS_ERROR")
    finally:
        if collected is not None:
            zero(collected["output"])
        if master is not None:
            try:
                os.close(master)
            except OSError:
                pass
        if leader["pid"] is not None and not leader["reaped"]:
            terminate_and_reap(leader)


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "selftest":
        sys.exit(selftest())
    main()
