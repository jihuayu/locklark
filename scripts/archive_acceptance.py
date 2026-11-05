"""Archive lifecycle, recovery and legacy refusal using synthetic real-terminal input."""
import pathlib
import sys
import tempfile
from personal_acceptance import invoke

def check(binary, legacy=None):
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        path = str(root / "owner.ll")
        pw = "synthetic-master-password"
        _, key = invoke(binary, "init", path, [("主密码", pw), ("再次输入主密码", pw), ("重新输入刚保存的 Secret Key", None)], issue=True)
        factors = [("主密码", pw), ("Secret Key", key)]
        invoke(binary, "add-login", path, factors + [("登录标题", "synthetic-title"), ("用户名（可留空）", "synthetic-user"), ("登录密码", "synthetic-secret")])
        row = invoke(binary, "list", path, factors)[0][0]
        options = ("--id", row["id"], "--revision", row["revision"])
        prompt = "输入 SAVE 确认更改归档状态"
        invoke(binary, "archive-login", path, factors + [(prompt, "no")], options=options, ok=False, expect_error="cancelled")
        archived, _ = invoke(binary, "archive-login", path, factors + [(prompt, "SAVE")], options=options)
        assert invoke(binary, "list", path, factors)[0] == []
        rows, _ = invoke(binary, "list", path, factors, options=("--state", "archived"))
        assert len(rows) == 1 and rows[0]["state"] == "archived" and rows[0]["revision"] == archived["revision"]
        assert invoke(binary, "references", path, factors)[0]["items"] == []
        if legacy:
            invoke(legacy, "list", path, factors, ok=False, expect_error="invalid personal vault")
        backup = str(root / "backup.llb")
        _, kit = invoke(binary, "backup", path, factors + [("重新输入恢复码", None)], issue=True, options=("--out", backup))
        restored = str(root / "restored.ll")
        if legacy:
            invoke(legacy, "restore", backup, factors + [("此备份的恢复码", kit)], options=("--out", restored), ok=False, deny_issue=True)
        _, newkey = invoke(binary, "restore", backup, factors + [("此备份的恢复码", kit), ("重新输入新 Secret Key", None)], issue=True, options=("--out", restored))
        rows, _ = invoke(binary, "list", restored, [("主密码", pw), ("Secret Key", newkey)], options=("--state", "archived"))
        assert len(rows) == 1 and rows[0]["revision"] != archived["revision"]
        invoke(binary, "unarchive-login", path, factors + [(prompt, "SAVE")], options=options, ok=False, expect_error="login changed")
        invoke(binary, "unarchive-login", path, factors + [(prompt, "SAVE")], options=("--id", row["id"], "--revision", archived["revision"]))
        rows, _ = invoke(binary, "list", path, factors)
        assert len(rows) == 1 and rows[0]["state"] == "active"
        events, _ = invoke(binary, "audit", path, factors, forbidden=("synthetic-secret",))
        assert [e["result"] for e in events if e["action"] in ("item.archive", "item.unarchive")] == ["succeeded", "conflict", "succeeded"]
    print("PASS: archive, filtered discovery, cancellation, stale refusal, recovery and audit")

if __name__ == "__main__":
    check(str(pathlib.Path(sys.argv[1]).resolve(strict=True)), sys.argv[2] if len(sys.argv) > 2 else None)
