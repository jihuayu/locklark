"""Real terminal disclosure using synthetic values; never print transcripts."""
import json
import os
import pathlib
import subprocess
import sys
import tempfile

from personal_acceptance import invoke


def check(binary):
    with tempfile.TemporaryDirectory() as tmp:
        path = str(pathlib.Path(tmp) / "owner.ll")
        pw = "synthetic-master-" + os.urandom(8).hex()
        password = "synthetic-private-" + os.urandom(8).hex() + '\t"quote"[{}]'
        username = "synthetic-user-" + os.urandom(8).hex()
        _, key = invoke(binary, "init", path, [("主密码", pw), ("再次输入主密码", pw),
                        ("重新输入刚保存的 Secret Key", None)], issue=True)
        factors = [("主密码", pw), ("Secret Key", key)]
        invoke(binary, "add-login", path, factors + [("登录标题", "Synthetic login"),
               ("用户名（可留空）", username), ("登录密码", password)])
        rows, _ = invoke(binary, "list", path, factors)
        target = rows[0]
        options = ("--id", target["id"], "--revision", target["revision"], "--field", "password")
        consent = [("输入 SHOW 确认显示", "SHOW")]
        denied_values = ("synthetic-private-", username)
        invoke(binary, "reveal-login", path, factors + [("输入 SHOW 确认显示", "no")],
               options=options, ok=False, forbidden=denied_values, expect_error="disclosure cancelled")
        if os.name != "nt":
            invoke(binary, "reveal-login", path, factors + [("输入 SHOW 确认显示", "\x03")],
                   options=options, ok=False, forbidden=denied_values)
        for wrong in ([("主密码", pw + "x"), factors[1]],
                      [factors[0], ("Secret Key", "LL1-" + "A" * 26)]):
            invoke(binary, "reveal-login", path, wrong + consent, options=options,
                   ok=False, forbidden=denied_values, expect_error="invalid personal vault")
        unknown = ("--id", "a" * 32, *options[2:])
        invoke(binary, "reveal-login", path, factors + consent, options=unknown,
               ok=False, forbidden=denied_values, expect_error="no login")
        receipt, _ = invoke(binary, "reveal-login", path, factors + consent, options=options,
                            disclosed=password, forbidden=(username,))
        assert receipt["status"] == "written-to-terminal"
        assert len(receipt["session"]) == 32 and len(receipt["intent"]) == 64
        user_receipt, _ = invoke(binary, "reveal-login", path, factors + consent,
                                options=(*options[:-1], "username"), disclosed=username,
                                forbidden=("synthetic-private-",))
        assert user_receipt["session"] != receipt["session"]
        invoke(binary, "edit-login", path, factors + [("新登录密码", "replacement-private")], options=options)
        invoke(binary, "reveal-login", path, factors + consent, options=options,
               ok=False, forbidden=(*denied_values, "replacement-private"), expect_error="login changed")
        events, _ = invoke(binary, "audit", path, factors)
        disclosures = [e for e in events if e["action"].startswith("item.reveal.")]
        assert [e["result"] for e in disclosures] == ["not-found", "intent", "intent", "conflict"]
        assert disclosures[1]["session"] == receipt["session"]
        assert all(secret not in json.dumps(events) for secret in (pw, key, username, "synthetic-private-", "replacement-private"))
        denied = subprocess.run([binary, "personal", "reveal-login", "--file", path, *options],
                                input=b"", capture_output=True, timeout=10)
        assert denied.returncode and not denied.stdout and b"interactive terminal" in denied.stderr
    print("PASS: terminal-only disclosure, explicit consent, factors, stable targets, audit intents and stdout privacy")


if __name__ == "__main__":
    check(str(pathlib.Path(sys.argv[1]).resolve(strict=True)))
