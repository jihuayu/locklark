"""Local health report without values or secret fingerprints in a real terminal."""
import hashlib
import json
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
        for index, password in enumerate(("same-private-secret", "same-private-secret", "password", "archived-private-secret")):
            invoke(binary, "add-login", path, factors + [("登录标题", "private-title-" + str(index)),
                   ("用户名（可留空）", "private-user"), ("登录密码", password)])
        rows, _ = invoke(binary, "list", path, factors)
        archived = rows[-1]
        invoke(binary, "archive-login", path, factors + [("输入 SAVE 确认更改归档状态", "SAVE")],
               options=("--id", archived["id"], "--revision", archived["revision"]))
        before, _ = invoke(binary, "list", path, factors, options=("--state", "all"))
        private = ("private-title", "private-user", "same-private-secret", "archived-private-secret")
        prompt = "输入 SCAN 确认本地体检"
        invoke(binary, "health", path, factors + [(prompt, "no")], ok=False, expect_error="cancelled", forbidden=private)
        invoke(binary, "health", path, [("主密码", pw + "wrong"), factors[1], (prompt, "SCAN")],
               ok=False, expect_error="invalid personal vault", forbidden=private)
        receipt, _ = invoke(binary, "health", path, factors + [(prompt, "SCAN")], forbidden=private,
                            required_before_last_prompt=("不会联网查询泄露数据", "未发现问题不代表密码安全"))
        report = receipt["report"]
        assert report["profile"] == "local-heuristics-v1" and report["scope"] == "active-logins"
        assert report["checked"] == 3 and report["skipped"] == 1
        findings = {finding["id"]: finding for finding in report["findings"]}
        assert set(findings) == {row["id"] for row in rows[:3]}
        for row in rows[:2]:
            assert findings[row["id"]]["flags"] == ["reused", "totp-not-stored"]
            assert findings[row["id"]]["revision"] == row["revision"]
        assert findings[rows[2]["id"]]["flags"] == ["short", "common-example", "totp-not-stored"]
        digest = hashlib.sha256(json.dumps(report, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
        assert receipt["report_digest"] == digest
        assert invoke(binary, "list", path, factors, options=("--state", "all"))[0] == before
        events, _ = invoke(binary, "audit", path, factors, forbidden=private)
        checks = [event for event in events if event["action"] == "vault.health.local"]
        assert len(checks) == 1 and checks[0]["report_digest"] == digest
        assert checks[0]["session"] == receipt["session"]
        assert hashlib.sha256(json.dumps(checks[0], ensure_ascii=False, separators=(",", ":")).encode()).hexdigest() == receipt["event"]
        for secret in ("same-private-secret", "password", "archived-private-secret"):
            assert hashlib.sha256(secret.encode()).hexdigest() not in json.dumps(receipt)
    print("PASS: authenticated local health, scoped findings, no values/fingerprints, unchanged revisions and audited receipt")


if __name__ == "__main__":
    check(str(pathlib.Path(sys.argv[1]).resolve(strict=True)))
