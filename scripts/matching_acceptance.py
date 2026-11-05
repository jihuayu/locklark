"""Synthetic origin candidate selection; this does not assert a trusted browser context."""
import pathlib
import sys
import tempfile
from personal_acceptance import invoke

def check(binary):
    with tempfile.TemporaryDirectory() as tmp:
        path = str(pathlib.Path(tmp) / "owner.ll")
        pw = "synthetic-master-password"
        _, key = invoke(binary, "init", path, [("主密码", pw), ("再次输入主密码", pw), ("重新输入刚保存的 Secret Key", None)], issue=True)
        factors = [("主密码", pw), ("Secret Key", key)]
        invoke(binary, "add-login", path, factors + [("登录标题", "synthetic-title"), ("用户名（可留空）", "synthetic-user"), ("登录密码", "synthetic-secret")])
        row = invoke(binary, "list", path, factors)[0][0]
        revision, _ = invoke(binary, "edit-login", path, factors + [("新网站 HTTPS URL（ASCII，留空清除）", "https://EXAMPLE.com:443/login")], options=("--id", row["id"], "--revision", row["revision"], "--field", "url"))
        def match(top, frame, ok=True):
            return invoke(binary, "match-logins", path, factors, options=("--origin", top, "--frame-origin", frame), forbidden=("synthetic-secret", "synthetic-user"), ok=ok, expect_error=None if ok else "cross-origin")[0]
        rows = match("https://example.com", "https://example.com:443/")
        assert len(rows) == 1 and rows[0]["id"] == row["id"] and rows[0]["revision"] == revision["revision"]
        assert match("https://example.com.evil.test", "https://example.com.evil.test") == []
        match("https://example.com", "https://evil.test", False)
        invoke(binary, "archive-login", path, factors + [("输入 SAVE 确认更改归档状态", "SAVE")], options=("--id", row["id"], "--revision", revision["revision"]))
        assert match("https://example.com", "https://example.com") == []
        events, _ = invoke(binary, "audit", path, factors, forbidden=("example.com", "evil.test", "synthetic-secret"))
        assert [e["result"] for e in events if e["action"] == "item.match"] == ["succeeded", "succeeded", "cross-origin", "succeeded"]
    print("PASS: hidden URL edit, exact same-origin metadata match, cross-frame refusal and archive exclusion")

if __name__ == "__main__":
    check(str(pathlib.Path(sys.argv[1]).resolve(strict=True)))
