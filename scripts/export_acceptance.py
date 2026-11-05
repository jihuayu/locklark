"""Synthetic encrypted export via a real terminal and independent KDBX reader."""
import pathlib
import sys
import tempfile
from personal_acceptance import invoke
from pykeepass import PyKeePass

def check(binary):
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        path, dest = str(root / "owner.ll"), str(root / "portable.kdbx")
        pw, export_pw = "synthetic-master-password", "synthetic-export-password"
        _, key = invoke(binary, "init", path, [("主密码", pw), ("再次输入主密码", pw), ("重新输入刚保存的 Secret Key", None)], issue=True)
        factors = [("主密码", pw), ("Secret Key", key)]
        invoke(binary, "add-login", path, factors + [("登录标题", "synthetic-title"), ("用户名（可留空）", "synthetic-user"), ("登录密码", "synthetic-secret")])
        answers = factors + [("新导出密码（至少 12 字符）", export_pw), ("再次输入导出密码", export_pw)]
        consent = "输入 SAVE 确认加密导出"
        invoke(binary, "export-kdbx", path, answers + [(consent, "no")], options=("--out", dest), ok=False, expect_error="export cancelled")
        assert not pathlib.Path(dest).exists()
        receipt, _ = invoke(binary, "export-kdbx", path, answers + [(consent, "SAVE")], options=("--out", dest), forbidden=("synthetic-secret",))
        assert receipt["status"] == "exported-encrypted"
        db = PyKeePass(dest, password=export_pw)
        assert len(db.entries) == 1 and db.entries[0].password == "synthetic-secret"
        before = pathlib.Path(dest).read_bytes()
        invoke(binary, "export-kdbx", path, answers + [(consent, "SAVE")], options=("--out", dest), ok=False, expect_error="publication failed")
        assert pathlib.Path(dest).read_bytes() == before
        events, _ = invoke(binary, "audit", path, factors, forbidden=("synthetic-secret", export_pw))
        exports = [e for e in events if e["action"] == "vault.export.kdbx"]
        assert len(exports) == 2 and exports[0]["result"] == "intent" and exports[0]["session"] == receipt["session"]
    print("PASS: consent, encrypted KDBX export, independent reopen, no overwrite and audit intent")

if __name__ == "__main__":
    check(str(pathlib.Path(sys.argv[1]).resolve(strict=True)))
