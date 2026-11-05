"""Confirmed single-field disclosure to a real child with null stdio and minimal env."""
import os
import pathlib
import sys
import tempfile
from personal_acceptance import invoke

CHILD = '''import os, pathlib, sys, time
secret = "synthetic-run-secret-密钥"
# Emit bytes: Windows null-device stdout may use a legacy text encoding.
os.write(1, secret.encode("utf-8"))
os.write(2, secret.encode("utf-8"))
if os.environ.get("TEST_TOKEN") != secret: sys.exit(81)
if "LOCKLARK_PARENT_ONLY" in os.environ: sys.exit(82)
if set(os.environ) - {"TEST_TOKEN", "SystemRoot", "SYSTEMROOT", "LC_CTYPE"}: sys.exit(83)
if sys.stdin.read() != "": sys.exit(84)
if sys.argv[2:] != ["", "two words", "$(echo hidden)", "a;b"]: sys.exit(85)
mode = sys.argv[1]
if mode == "sleep": time.sleep(10)
pathlib.Path("child-proof").write_text("matched", encoding="utf-8")
sys.exit(7 if mode == "exit" else 0)
'''

def check(binary):
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        path, proof = str(root / "owner.ll"), root / "child-proof"
        script = root / "trusted child.py"
        script.write_text(CHILD, encoding="utf-8")
        pw, secret = "synthetic-master-password", "synthetic-run-secret-密钥"
        _, key = invoke(binary, "init", path, [("主密码", pw), ("再次输入主密码", pw), ("重新输入刚保存的 Secret Key", None)], issue=True)
        factors = [("主密码", pw), ("Secret Key", key)]
        invoke(binary, "add-login", path, factors + [("登录标题", "run fixture"), ("用户名（可留空）", "user"), ("登录密码", secret)])
        row = invoke(binary, "list", path, factors)[0][0]
        base = ("--id", row["id"], "--revision", row["revision"], "--field", "password", "--name", "TEST_TOKEN", "--cwd", str(root), "--timeout", "2", "--", str(pathlib.Path(sys.executable).resolve()), "-I", str(script))
        def options(mode):
            return base + (mode, "", "two words", "$(echo hidden)", "a;b")
        prompt = "输入 RUN 确认向本地程序披露字段"
        invoke(binary, "run-env", path, factors + [(prompt, "no")], options=options("ok"), ok=False, expect_error="cancelled", forbidden=(secret,))
        assert not proof.exists()
        invoke(binary, "run-env", path, [("主密码", pw + "wrong"), factors[1], (prompt, "RUN")], options=options("ok"), ok=False, expect_error="invalid personal vault", forbidden=(secret,))
        assert not proof.exists()
        for mode, code in (("ok", 0), ("exit", 7)):
            receipt, _ = invoke(binary, "run-env", path, factors + [(prompt, "RUN")], options=options(mode), forbidden=(secret,), required_before_last_prompt=("这不是沙箱", "只返回退出码", "后代可能继续运行", "TEST_TOKEN", "$(echo hidden)"))
            assert receipt["status"] == "process-exited" and receipt["exit_code"] == code, ("child-result", receipt["status"], receipt["exit_code"])
            assert proof.read_text() == "matched"
            proof.unlink()
        invoke(binary, "run-env", path, factors + [(prompt, "RUN")], options=options("sleep"), ok=False, expect_error="result unavailable", forbidden=(secret,))
        assert not proof.exists()
        rows = invoke(binary, "list", path, factors)[0]
        assert rows[0]["revision"] == row["revision"]
        trashed, _ = invoke(binary, "trash-login", path, factors + [("输入 SAVE 确认更改回收站状态", "SAVE")], options=("--id", row["id"], "--revision", row["revision"]))
        invoke(binary, "run-env", path, factors + [(prompt, "RUN")], options=options("ok"), ok=False, expect_error="login changed", forbidden=(secret,))
        fresh = list(options("ok")); fresh[3] = trashed["revision"]
        invoke(binary, "run-env", path, factors + [(prompt, "RUN")], options=tuple(fresh), ok=False, expect_error="login is in trash", forbidden=(secret,))
        assert not proof.exists()
        events, _ = invoke(binary, "audit", path, factors, forbidden=(secret, str(script), "TEST_TOKEN"))
        actions = [e for e in events if e["action"] == "item.run.password"]
        assert [e["result"] for e in actions] == ["intent", "intent", "intent", "conflict", "trashed"]
        assert actions[1]["session"] == receipt["session"] and actions[1]["link"] == receipt["target_digest"]
        assert len({e["link"] for e in actions[:3]}) == 3
        assert all("link" not in e for e in actions[3:])
    print("PASS: confirmed environment injection, real child, exact args, null stdio, timeout and durable intent")

if __name__ == "__main__":
    os.environ["LOCKLARK_PARENT_ONLY"] = "must-not-inherit"
    check(str(pathlib.Path(sys.argv[1]).resolve(strict=True)))
