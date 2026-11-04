"""POSIX PTY scenario, synthetic credentials only; never print a terminal transcript."""
import json
import os
import pathlib
import re
import select
import subprocess
import sys
import tempfile
if os.name == "nt":
    from personal_windows import invoke as windows_invoke
else:
    import pty
    import termios
import time


def invoke(binary, action, path, answers, *, ok=True, issue=False, paste=False):
    if os.name == "nt":
        return windows_invoke(binary, action, path, answers, ok=ok, issue=issue)
    master, slave = pty.openpty()
    try:
        proc = subprocess.Popen([binary, "personal", action, "--file", path],
                                stdin=slave, stdout=subprocess.PIPE, stderr=slave, start_new_session=True)
        transcript = bytearray()
        offset = 0
        issued = None
        try:
            for index, (prompt, value) in enumerate(answers):
                deadline = time.monotonic() + 12
                marker = (prompt + ": ").encode()
                while marker not in transcript[offset:]:
                    if time.monotonic() >= deadline or proc.poll() is not None:
                        raise RuntimeError(f"{action}: missing terminal prompt")
                    if select.select([master], [], [], 0.2)[0]:
                        transcript.extend(os.read(master, 4096))
                offset = transcript.index(marker, offset) + len(marker)
                if value is None:
                    match = re.search(rb"LL1-[A-Z2-7]{26}", transcript[:offset])
                    if not issue or match is None:
                        raise RuntimeError("no new Secret Key issued to terminal")
                    issued = match.group().decode()
                    value = issued
                if termios.tcgetattr(slave)[3] & termios.ECHO:
                    raise RuntimeError("prompt appeared before echo was disabled")
                if paste and index == 0:
                    os.write(master, ("\n".join(x for _, x in answers) + "\n").encode())
                elif not paste:
                    os.write(master, value.encode() + b"\n")
            data, _ = proc.communicate(timeout=15)
            while select.select([master], [], [], 0)[0]:
                transcript.extend(os.read(master, 4096))
            if not termios.tcgetattr(slave)[3] & termios.ECHO:
                raise RuntimeError("terminal echo was not restored on exit")
            if (proc.returncode == 0) != ok or (not ok and data):
                raise RuntimeError(f"{action}: unexpected exit or output")
            if issued and issued.encode() in data:
                raise RuntimeError("Secret Key leaked to ordinary output")
            for _, value in answers:
                if value and len(value)>5 and value.encode() in transcript:
                    raise RuntimeError("hidden input echoed in terminal")
            return (json.loads(data) if ok else None), issued
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
    finally:
        os.close(master)
        os.close(slave)


def check(binary):
    with tempfile.TemporaryDirectory() as tmp:
        path = str(pathlib.Path(tmp) / "owner.ll")
        pw = "synthetic-master-" + os.urandom(8).hex()
        login = "synthetic-login-" + os.urandom(8).hex()
        result, key = invoke(binary, "init", path, [("主密码", pw), ("再次输入主密码", pw),
                             ("重新输入刚保存的 Secret Key", None)], issue=True)
        assert result["status"] == "created"
        if os.name != "nt":
            invoke(binary, "list", path, [("主密码", "\x03")], ok=False)
        factors = [("主密码", pw), ("Secret Key", key)]
        assert invoke(binary, "list", path, factors)[0] == []
        added, _ = invoke(binary, "add-login", path, factors + [
            ("登录标题", "开发账号"), ("用户名（可留空）", "local-fixture-user"), ("登录密码", login)], paste=os.name != "nt")
        for creds in ([("主密码", pw + "x"), factors[1]],
                      [factors[0], ("Secret Key", "LL1-" + "A" * 26)]):
            invoke(binary, "list", path, creds, ok=False)
        rows, _ = invoke(binary, "list", path, factors)
        assert rows == [{"id": added["id"], "title": "开发账号"}]
        events, _ = invoke(binary, "audit", path, factors)
        assert [e["action"] for e in events] == ["vault.create","item.list","item.add","item.list","audit.list"]
        assert events[2]["item_id"] == added["id"]
        assert all(s not in json.dumps(events) for s in (key, pw, login, "local-fixture-user"))
        denied = subprocess.run([binary, "personal", "list", "--file", path], input=b"",
                                capture_output=True, timeout=10)
        assert denied.returncode and not denied.stdout
    print("PASS: offline creation, terminal-only factors, saved login, restart, audit and wrong factors")


if __name__ == "__main__":
    check(str(pathlib.Path(sys.argv[1]).resolve(strict=True)))
