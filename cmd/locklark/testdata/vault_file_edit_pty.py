"""Run the real title-edit CLI through a controlling terminal; return only a verdict."""

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
REFUSALS = {"VERIFY_REJECTED", "JOURNAL_REJECTED", "LOCAL_REVIEW", "CANCELLED"}


def verdict(status, echoed=False):
    print(json.dumps({"status": status, "echoed": echoed}), flush=True)


def main():
    try:
        request = json.load(sys.stdin)
        product = request["product"]
        config = request["config"]
        input_path = request["input"]
        password = request["password"].encode("utf-8")
        secret = request["secret"].encode("ascii")
        missing = request["missing_secret"]
        expected_refusal = request["expected_refusal"]
        if (not all(os.path.isabs(value) for value in (product, config, input_path)) or
                expected_refusal not in REFUSALS | {""} or
                not isinstance(missing, bool)):
            verdict("HARNESS_ERROR")
            return
        pid, master = pty.fork()
        if pid == 0:
            os.execv(product, [product, "vault-file", "edit-prepared", "--config", config,
                               "--input", input_path])
        output = bytearray()
        phase = 0
        deadline = time.monotonic() + 20
        status = None
        while time.monotonic() < deadline:
            ready, _, _ = select.select([master], [], [], 0.1)
            if ready:
                try:
                    chunk = os.read(master, 4096)
                except OSError as exc:
                    if exc.errno != errno.EIO:
                        break
                    chunk = b""
                if chunk:
                    output.extend(chunk)
                    if len(output) > 512:
                        break
                    if phase == 0 and MASTER_PROMPT in output:
                        os.write(master, password + b"\n")
                        phase = 1
                    if phase == 1 and SECRET_PROMPT in output:
                        os.write(master, b"\x04" if missing else secret + b"\n")
                        phase = 2
            got, wait_status = os.waitpid(pid, os.WNOHANG)
            if got == pid:
                status = wait_status
                break
        if status is None:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
            verdict("HARNESS_ERROR")
            return
        echoed = password in output or secret in output
        normalized = bytes(output).replace(b"\r\n", b"\n")
        prefix = MASTER_PROMPT + b"\n" + SECRET_PROMPT + (b"" if missing else b"\n")
        if (os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0 and phase == 2 and
                not echoed and expected_refusal == "" and
                normalized == prefix + b'{"status":"PREPARED"}\n'):
            verdict("PREPARED")
            return
        expected = prefix + ("locklark: " + expected_refusal + "\n").encode("ascii")
        if (os.WIFEXITED(status) and os.WEXITSTATUS(status) == 1 and phase == 2 and
                not echoed and expected_refusal in REFUSALS and normalized == expected):
            verdict(expected_refusal)
            return
        verdict("HARNESS_ERROR", echoed)
    except (KeyError, OSError, ValueError):
        verdict("HARNESS_ERROR")


if __name__ == "__main__":
    main()
