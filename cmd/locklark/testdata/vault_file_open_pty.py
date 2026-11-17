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

MAX_OUTPUT = (1 << 20) + 256
MAX_DRAIN_READS = 256


def exit_class_name(status):
    if status is None:
        return "unknown"
    if os.WIFEXITED(status):
        code = os.WEXITSTATUS(status)
        if code == 0:
            return "exited-0"
        if code == 1:
            return "exited-1"
        return "exited-other"
    if os.WIFSIGNALED(status):
        return "signaled"
    return "other"


def wait_exit_code(status):
    if status is None or not os.WIFEXITED(status):
        return None
    return os.WEXITSTATUS(status)


def drain_master(master, output):
    # Nonblocking and bounded: only read bytes already buffered on the
    # master. Callers use this after the child has exited or been reaped,
    # so this must never wait for a live child to produce more output.
    reads = 0
    while reads < MAX_DRAIN_READS and len(output) <= MAX_OUTPUT:
        ready, _, _ = select.select([master], [], [], 0)
        if not ready:
            break
        try:
            chunk = os.read(master, 4096)
        except OSError as exc:
            if exc.errno != errno.EIO:
                break
            break
        if not chunk:
            break
        output.extend(chunk)
        reads += 1


def refusal_matches(normalized, expected, expected_refusal, exit_code, phase, echoed, items):
    return (exit_code == 1 and phase == 2 and not echoed and items is None and
            expected_refusal in REFUSALS and normalized == expected)


def selftest():
    read_fd, write_fd = os.pipe()
    payload = b"TRAILING-PTY-BYTES"
    try:
        os.write(write_fd, payload)
    finally:
        os.close(write_fd)
    output = bytearray()
    drain_master(read_fd, output)
    os.close(read_fd)
    drain_ok = bytes(output) == payload

    expected = b"EXACT"
    exact_ok = refusal_matches(expected, expected, "CANCELLED", 1, 2, False, None)
    extra_rejected = not refusal_matches(expected + b"X", expected, "CANCELLED", 1, 2, False, None)
    echo_rejected = not refusal_matches(expected, expected, "CANCELLED", 1, 2, True, None)
    items_rejected = not refusal_matches(expected, expected, "CANCELLED", 1, 2, False, [])
    generic_items = verdict_payload("HARNESS_ERROR", items_present=True)
    generic_items_ok = (generic_items["status"] == "HARNESS_ERROR" and
                        generic_items["items_present"] is True and
                        generic_items["items"] is None)
    normal_no_items = verdict_payload("HARNESS_ERROR")
    normal_no_items_ok = (normal_no_items["items_present"] is False and
                          normal_no_items["items"] is None)
    items_rejected = items_rejected and generic_items_ok and normal_no_items_ok
    print(json.dumps({
        "drain_ok": drain_ok,
        "strict_exact_ok": exact_ok,
        "strict_extra_rejected": extra_rejected,
        "strict_echo_rejected": echo_rejected,
        "strict_items_rejected": items_rejected,
    }), flush=True)
    return 0 if all((drain_ok, exact_ok, extra_rejected, echo_rejected, items_rejected)) else 1


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


def verdict_payload(status, echoed=False, items=None, items_present=None, phase=0,
                   exit_class_value="unknown", normalized_len=0, expected_len=0,
                   normalized_matches_expected=False):
    if items_present is None:
        items_present = items is not None
    return {
        "status": status,
        "echoed": echoed,
        "items": items,
        "phase": phase,
        "exit_class": exit_class_value,
        "items_present": items_present,
        "normalized_len": normalized_len,
        "expected_len": expected_len,
        "normalized_matches_expected": normalized_matches_expected,
    }


def verdict(status, echoed=False, items=None, items_present=None, phase=0,
            exit_class_value="unknown", normalized_len=0, expected_len=0,
            normalized_matches_expected=False):
    print(json.dumps(verdict_payload(
        status, echoed=echoed, items=items, items_present=items_present, phase=phase,
        exit_class_value=exit_class_value, normalized_len=normalized_len,
        expected_len=expected_len, normalized_matches_expected=normalized_matches_expected,
    )), flush=True)


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
                    if len(output) > MAX_OUTPUT:
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
            drain_master(master, output)
            verdict(
                "HARNESS_ERROR",
                phase=phase,
                exit_class_value="timeout",
                normalized_len=min(len(output), MAX_OUTPUT),
            )
            return
        drain_master(master, output)
        echoed = password in output or secret in output
        normalized = bytes(output).replace(b"\r\n", b"\n")
        items = opened_items(normalized, include_item_ids)
        exit_code = wait_exit_code(status)
        exit_class_value = exit_class_name(status)
        prompt = MASTER_PROMPT + b"\n" + SECRET_PROMPT + (b"" if missing else b"\n")
        expected = prompt + b"locklark: " + expected_refusal.encode("utf-8") + b"\n"
        normalized_len = min(len(normalized), MAX_OUTPUT)
        expected_len = min(len(expected), MAX_OUTPUT)
        normalized_matches = normalized == expected
        if (exit_code == 0 and phase == 2 and not echoed and items is not None and
                expected_refusal == ""):
            verdict(
                "LOCAL_BASELINE",
                items=items,
                phase=phase,
                exit_class_value=exit_class_value,
                normalized_len=normalized_len,
                expected_len=expected_len,
                normalized_matches_expected=normalized_matches,
            )
            return
        if refusal_matches(normalized, expected, expected_refusal, exit_code, phase, echoed, items):
            verdict(
                expected_refusal,
                phase=phase,
                exit_class_value=exit_class_value,
                normalized_len=normalized_len,
                expected_len=expected_len,
                normalized_matches_expected=normalized_matches,
            )
            return
        verdict(
            "HARNESS_ERROR",
            echoed,
            items_present=items is not None,
            phase=phase,
            exit_class_value=exit_class_value,
            normalized_len=normalized_len,
            expected_len=expected_len,
            normalized_matches_expected=normalized_matches,
        )
    except (KeyError, OSError, ValueError):
        verdict("HARNESS_ERROR")


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "selftest":
        sys.exit(selftest())
    main()
