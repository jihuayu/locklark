"""Reversible trash using synthetic PTY/ConPTY input and independent KDBX reads."""
import pathlib
import sys
import tempfile
from pykeepass import PyKeePass
from personal_acceptance import invoke


def check(binary, legacy=None):
    for prior in ("active", "archived"):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            path = str(root / "owner.ll")
            pw, secret = "synthetic-master-password", "synthetic-private-password"
            creator = legacy or binary
            _, key = invoke(creator, "init", path, [("主密码", pw), ("再次输入主密码", pw), ("重新输入刚保存的 Secret Key", None)], issue=True)
            factors = [("主密码", pw), ("Secret Key", key)]
            invoke(creator, "add-login", path, factors + [("登录标题", "synthetic-title"), ("用户名（可留空）", "synthetic-user"), ("登录密码", secret)])
            row = invoke(binary, "list", path, factors)[0][0]
            if legacy and prior == "active":
                old_backup = str(root / "old.llb")
                _, old_kit = invoke(legacy, "backup", path, factors + [("重新输入恢复码", None)], issue=True, options=("--out", old_backup))
                old_dest = str(root / "old-restored.ll")
                _, old_key = invoke(binary, "restore", old_backup, factors + [("此备份的恢复码", old_kit), ("重新输入新 Secret Key", None)], issue=True, options=("--out", old_dest))
                assert len(invoke(binary, "list", old_dest, [("主密码", pw), ("Secret Key", old_key)])[0]) == 1
            if prior == "archived":
                row = invoke(binary, "archive-login", path, factors + [("输入 SAVE 确认更改归档状态", "SAVE")], options=("--id", row["id"], "--revision", row["revision"]))[0]
            opts = ("--id", row["id"], "--revision", row["revision"])
            consent = [("输入 SAVE 确认更改回收站状态", "SAVE")]
            invoke(binary, "trash-login", path, factors + [(consent[0][0], "no")], options=opts, ok=False, expect_error="cancelled")
            invoke(binary, "trash-login", path, [("主密码", pw + "wrong"), factors[1]] + consent, options=opts, ok=False, expect_error="invalid personal vault")
            trashed = invoke(binary, "trash-login", path, factors + consent, options=opts)[0]
            assert invoke(binary, "list", path, factors)[0] == []
            rows = invoke(binary, "list", path, factors, options=("--state", "trashed"))[0]
            assert len(rows) == 1 and rows[0]["restore_state"] == prior
            current = ("--id", row["id"], "--revision", trashed["revision"])
            invoke(binary, "reveal-login", path, factors + [("输入 SHOW 确认显示", "SHOW")], options=(*current, "--field", "password"), ok=False, expect_error="in trash", forbidden=(secret,))
            invoke(binary, "edit-login", path, factors + [("新登录密码", "")], options=(*current, "--field", "password"), ok=False, expect_error="in trash")
            invoke(binary, "regenerate-password", path, factors + [("输入 SAVE 确认替换本地密码", "SAVE")], options=(*current, "--length", "0"), ok=False, expect_error="in trash")
            if legacy:
                invoke(legacy, "list", path, factors, ok=False, expect_error="invalid personal vault")
            portable = str(root / "portable.kdbx")
            export_pw = "synthetic-export-password"
            invoke(binary, "export-kdbx", path, factors + [("新导出密码（至少 12 字符）", export_pw), ("再次输入导出密码", export_pw), ("输入 SAVE 确认加密导出", "SAVE")], options=("--out", portable), forbidden=(secret,), required_before_last_prompt=("活动、归档和回收站", "其他工具未必识别归档或回收站状态"))
            entry = PyKeePass(portable, password=export_pw).entries[0]
            assert entry.password == secret and entry.get_custom_property("Locklark.State") == "trashed"
            assert (entry.get_custom_property("Locklark.PreviousState") or "active") == prior
            backup = str(root / "backup.llb")
            _, kit = invoke(binary, "backup", path, factors + [("重新输入恢复码", None)], issue=True, options=("--out", backup))
            dest = str(root / "restored.ll")
            if legacy:
                invoke(legacy, "restore", backup, factors + [("此备份的恢复码", kit)], options=("--out", dest), ok=False, deny_issue=True)
            _, fresh = invoke(binary, "restore", backup, factors + [("此备份的恢复码", kit), ("重新输入新 Secret Key", None)], issue=True, options=("--out", dest))
            recovered_factors = [("主密码", pw), ("Secret Key", fresh)]
            recovered = invoke(binary, "list", dest, recovered_factors, options=("--state", "trashed"))[0][0]
            assert recovered["restore_state"] == prior and recovered["revision"] != trashed["revision"]
            invoke(binary, "restore-login", dest, recovered_factors + consent, options=("--id", recovered["id"], "--revision", recovered["revision"]))
            assert len(invoke(binary, "list", dest, recovered_factors, options=("--state", prior))[0]) == 1
            invoke(binary, "restore-login", path, factors + consent, options=opts, ok=False, expect_error="login changed")
            restored = invoke(binary, "restore-login", path, factors + consent, options=current)[0]
            rows = invoke(binary, "list", path, factors, options=("--state", prior))[0]
            assert len(rows) == 1 and rows[0]["revision"] == restored["revision"] and "restore_state" not in rows[0]
            events = invoke(binary, "audit", path, factors, forbidden=(secret,))[0]
            assert [e["result"] for e in events if e["action"] in ("item.trash", "item.untrash")] == ["succeeded", "conflict", "succeeded"]
    print("PASS: trash/restore, prior state, refusal precedence, backup, legacy compatibility and independent KDBX state")

if __name__ == "__main__":
    check(str(pathlib.Path(sys.argv[1]).resolve(strict=True)), sys.argv[2] if len(sys.argv) > 2 else None)
