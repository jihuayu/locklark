"""Real terminal live-action consent and refusal; deliberately no upstream call.

The five-byte synthetic token fails adapter validation before any network I/O.
Successful TLS projection is covered in gateway tests; real GitHub credentials
and end-to-end live account execution are separate acceptance requirements.
"""
import pathlib
import sys
import tempfile
from personal_acceptance import invoke


def check(binary):
    with tempfile.TemporaryDirectory() as tmp:
        path = str(pathlib.Path(tmp) / "owner.ll")
        pw, token = "synthetic-master-password", "short"
        _, key = invoke(binary, "init", path, [("主密码", pw), ("再次输入主密码", pw), ("重新输入刚保存的 Secret Key", None)], issue=True)
        factors = [("主密码", pw), ("Secret Key", key)]
        invoke(binary, "add-login", path, factors + [("登录标题", "synthetic-token"), ("用户名（可留空）", "private-user"), ("登录密码", token)])
        row = invoke(binary, "list", path, factors)[0][0]
        options = ("--id", row["id"], "--revision", row["revision"], "--repository-id", "1445507532", "--owner", "jihuayu", "--repository", "locklark", "--number", "18", "--api-ip", "140.82.112.6")
        prompt = "输入 CALL 确认此次 GitHub 查询"
        invoke(binary, "github-pull", path, factors + [(prompt, "no")], options=options, ok=False, expect_error="cancelled", forbidden=(token,))
        invoke(binary, "github-pull", path, [("主密码", pw + "wrong"), factors[1], (prompt, "CALL")], options=options, ok=False, expect_error="invalid personal vault", forbidden=(token,))
        invoke(binary, "github-pull", path, factors + [(prompt, "CALL")], options=options, ok=False, expect_error="intent recorded", forbidden=(token,), required_before_last_prompt=("api.github.com", "jihuayu/locklark", "1445507532", "PR #18", "140.82.112.6", "结果可能未知"))
        assert invoke(binary, "list", path, factors)[0][0] == row
        events = invoke(binary, "audit", path, factors, forbidden=(token, "jihuayu", "140.82.112.6"))[0]
        intents = [event for event in events if event["action"] == "item.invoke.github-pull"]
        assert len(intents) == 1 and intents[0]["result"] == "intent"
        assert len(intents[0]["link"]) == 64 and intents[0]["base_revision"] == row["revision"]
    print("PASS: live action terminal consent, hidden factors, fixed-target prompt, pre-network token refusal and durable intent")


if __name__ == "__main__":
    check(str(pathlib.Path(sys.argv[1]).resolve(strict=True)))
