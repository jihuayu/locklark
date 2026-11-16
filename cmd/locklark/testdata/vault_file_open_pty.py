"""Exercise the real baseline CLI on a controlling PTY without logging its text."""

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
REFUSALS = {"VERIFY_REJECTED", "JOURNAL_REJECTED", "CANCELLED"}


def unique_fields(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate field")
        result[key] = value
    return result


def opened_items(transcript, include_item_ids):
    prefix = MASTER_PROMPT + b"\n" + SECRET_PROMPT + b"\n"
    if not transcript.startswith(prefix):
        return None
    record = transcript[len(prefix):]
    if len(record) > 1 << 20 or not record.endswith(b"\n") or record.count(b"\n") != 1:
        return None
    try:
        value = json.loads(record[:-1], object_pairs_hook=unique_fields)
    except (UnicodeDecodeError, ValueError):
        return None
    if (not isinstance(value, dict) or set(value) != {"status", "remote_freshness", "items"} or
            value["status"] != "LOCAL_BASELINE" or value["remote_freshness"] != "UNVERIFIED" or
            not isinstance(value["items"], list) or len(value["items"]) > 1024):
        return None
    item_fields = {"title", "category", "id"} if include_item_ids else {"title", "category"}
    for item in value["items"]:
        if (not isinstance(item, dict) or set(item) != item_fields or
                not isinstance(item["title"], str) or not isinstance(item["category"], str)):
            return None
        if include_item_ids and (not isinstance(item["id"], str) or not item["id"]):
            return None
    return value["items"]


def verdict(status, echoed=False, items=None):
    print(json.dumps({"status": status, "echoed": echoed, "items": items}), flush=True)


def main():
    try:
        request = json.load(sys.stdin)
        product = request["product"]
        config = request["config"]
        password = request["password"].encode("utf-8")
        secret = request["secret"].encode("ascii")
        missing = request["missing_secret"]
        expected_refusal = request["expected_refusal"]
        include_item_ids = request["include_item_ids"]
        if (not os.path.isabs(product) or not os.path.isabs(config) or
                expected_refusal not in REFUSALS | {""} or
                not isinstance(include_item_ids, bool)):
            verdict("HARNESS_ERROR")
            return
        pid, master = pty.fork()
        if pid == 0:
            arguments = [product, "vault-file", "open-baseline"]
            if include_item_ids:
                arguments.append("--include-item-ids")
            os.execv(product, arguments + ["--config", config])
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
                    if len(output) > (1 << 20) + 256:
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
        items = opened_items(normalized, include_item_ids)
        if (os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0 and
                phase == 2 and not echoed and items is not None and expected_refusal == ""):
            verdict("LOCAL_BASELINE", items=items)
            return
        prompt = MASTER_PROMPT + b"\n" + SECRET_PROMPT + (b"" if missing else b"\n")
        expected = prompt + ("locklark: " + expected_refusal + "\n").encode("ascii")
        if (os.WIFEXITED(status) and os.WEXITSTATUS(status) == 1 and
                phase == 2 and not echoed and items is None and
                expected_refusal in REFUSALS and normalized == expected):
            verdict(expected_refusal)
            return
        verdict("HARNESS_ERROR", echoed)
    except (KeyError, OSError, ValueError):
        verdict("HARNESS_ERROR")


if __name__ == "__main__":
    main()
