"""Run the guarded private clipboard probe behind a real POSIX pipe.

The probe deliberately refuses a socket stdout: on Linux, Node/libuv stdio
pipes are socketpairs (S_IFSOCK), not FIFOs. This test-only launcher starts the
probe with a genuine subprocess PIPE and forwards only its fixed JSON replies.
Expected values stay on the inherited private stdin/stdout pipes; nothing is
logged, and no value or path travels through argv, environment or files.
"""
import json
import os
import signal
import subprocess
import sys

PROBE = os.path.realpath(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                     "desktop_native_probe.py"))
child = None


def stop(*_unused):
    # Only the owned probe process may be terminated and reaped.
    if child is not None and child.poll() is None:
        child.terminate()
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=5)


def main():
    global child
    if len(sys.argv) != 2 or os.path.realpath(sys.argv[1]) != PROBE:
        return 2
    if not os.path.isfile(PROBE):
        return 2
    child = subprocess.Popen([sys.executable, PROBE], stdin=sys.stdin.buffer,
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        for line in child.stdout:
            try:
                value = json.loads(line)
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue
            if not isinstance(value, dict) or not ("ready" in value or "ok" in value):
                continue
            if not line.endswith(b"\n"):
                line += b"\n"
            sys.stdout.buffer.write(line)
            sys.stdout.buffer.flush()
        return 0
    finally:
        stop()


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, lambda *_args: (stop(), sys.exit(0)))
    signal.signal(signal.SIGINT, lambda *_args: (stop(), sys.exit(0)))
    try:
        sys.exit(main())
    except Exception:
        stop()
        print("Private pipe probe launcher unavailable", file=sys.stderr)
        sys.exit(1)
