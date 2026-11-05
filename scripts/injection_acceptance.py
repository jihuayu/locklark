"""Explicit sensitive JSON publication, JSON escaping and audit binding."""
import json
import os
import pathlib
import stat
import sys
import tempfile
from personal_acceptance import invoke


def check(binary):
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        path, dest = str(root / "owner.ll"), root / "private-output.json"
        pw, secret = "synthetic-master-password", 'private-quoted"value\\with-tab\tand-unicode-密钥'
        _, key = invoke(binary, "init", path, [("主密码", pw), ("再次输入主密码", pw), ("重新输入刚保存的 Secret Key", None)], issue=True)
        factors = [("主密码", pw), ("Secret Key", key)]
        invoke(binary, "add-login", path, factors + [("登录标题", "synthetic-title"), ("用户名（可留空）", "private-user"), ("登录密码", secret)])
        row = invoke(binary, "list", path, factors)[0][0]
        options = ("--id", row["id"], "--revision", row["revision"], "--field", "password", "--name", "TOKEN", "--out", str(dest))
        prompt = "输入 WRITE 确认写出明文 JSON"
        invoke(binary, "inject-json", path, factors + [(prompt, "no")], options=options, ok=False, expect_error="cancelled", forbidden=(secret,))
        assert not dest.exists()
        invoke(binary, "inject-json", path, [("主密码", pw + "wrong"), factors[1], (prompt, "WRITE")],
               options=options, ok=False, expect_error="invalid personal vault", forbidden=(secret,))
        assert not dest.exists()
        receipt, _ = invoke(binary, "inject-json", path, factors + [(prompt, "WRITE")], options=options,
                            forbidden=(secret,), required_before_last_prompt=("明文 JSON", "目标文件不会覆盖"))
        assert receipt["status"] == "written-sensitive-json" and len(receipt["destination_digest"]) == 64
        assert json.loads(dest.read_text(encoding="utf-8")) == {"TOKEN": secret}
        if os.name != "nt":
            assert stat.S_IMODE(dest.stat().st_mode) == 0o600
        original = dest.read_bytes()
        invoke(binary, "inject-json", path, factors + [(prompt, "WRITE")], options=options,
               ok=False, expect_error="publication failed", forbidden=(secret,))
        assert dest.read_bytes() == original
        trashed, _ = invoke(binary, "trash-login", path, factors + [("输入 SAVE 确认更改回收站状态", "SAVE")],
                             options=("--id", row["id"], "--revision", row["revision"]))
        stale = list(options)
        stale[-1] = str(root / "stale.json")
        invoke(binary, "inject-json", path, factors + [(prompt, "WRITE")], options=tuple(stale),
               ok=False, expect_error="login changed", forbidden=(secret,))
        assert not (root / "stale.json").exists()
        stale[3] = trashed["revision"]
        invoke(binary, "inject-json", path, factors + [(prompt, "WRITE")], options=tuple(stale),
               ok=False, expect_error="login is in trash", forbidden=(secret,))
        assert not (root / "stale.json").exists()
        events, _ = invoke(binary, "audit", path, factors, forbidden=(secret, str(dest), "TOKEN"))
        injections = [e for e in events if e["action"] == "item.inject.password"]
        assert [e["result"] for e in injections] == ["intent", "intent", "conflict", "trashed"]
        assert injections[0]["link"] == receipt["destination_digest"] == injections[1]["link"]
        assert injections[0]["session"] == receipt["session"]
        assert all("link" not in e for e in injections[2:])
        assert not list(root.glob(".locklark-inject-*"))
    print("PASS: explicit JSON injection, escaping, no overwrite, stale/trash refusal, private file and bound audit")


if __name__ == "__main__":
    check(str(pathlib.Path(sys.argv[1]).resolve(strict=True)))
