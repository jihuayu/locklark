"""Synthetic real-process generated-login workflow; never log generated values."""
import json
import os
import pathlib
import re
import sys
import tempfile

from personal_acceptance import invoke


def check(binary, legacy=None):
    with tempfile.TemporaryDirectory() as tmp:
        path = str(pathlib.Path(tmp) / "owner.ll")
        pw = "synthetic-master-" + os.urandom(8).hex()
        _, key = invoke(legacy or binary, "init", path, [("主密码", pw), ("再次输入主密码", pw),
                        ("重新输入刚保存的 Secret Key", None)], issue=True)
        factors = [("主密码", pw), ("Secret Key", key)]
        fields = [("登录标题", "Generated login"), ("用户名（可留空）", "generated-user")]
        consent = [("输入 SAVE 确认生成并保存", "SAVE")]
        invoke(binary, "generate-login", path, factors + fields + [(consent[0][0], "no")], ok=False)
        invoke(binary, "generate-login", path, [("主密码", pw + "x"), factors[1]] + fields + consent,
               ok=False, expect_error="invalid personal vault")
        created, _ = invoke(binary, "generate-login", path, factors + fields + consent)
        assert created["profile"] == {"length": 24, "alphabet_size": 62, "entropy_bits_floor": 142}
        assert set(created) == {"id", "revision", "profile"}
        if legacy:
            invoke(legacy, "list", path, factors, ok=False)
        target = ("--id", created["id"], "--revision", created["revision"])
        show = [("输入 SHOW 确认显示", "SHOW")]
        _, first = invoke(binary, "reveal-login", path, factors + show,
                          options=(*target, "--field", "password"), capture_disclosure=True)
        assert re.fullmatch(r"[A-Za-z0-9]{24}", first)
        replace = [("输入 SAVE 确认替换本地密码", "SAVE")]
        invoke(binary, "regenerate-password", path, factors + [(replace[0][0], "no")],
               options=target, ok=False, forbidden=(first,))
        changed, _ = invoke(binary, "regenerate-password", path, factors + replace,
                            options=(*target, "--length", "32"), forbidden=(first,))
        assert set(changed) == {"id", "revision", "profile"}
        assert changed["id"] == created["id"] and changed["revision"] != created["revision"]
        invoke(binary, "regenerate-password", path, factors + replace,
               options=target, ok=False, expect_error="login changed", forbidden=(first,))
        _, second = invoke(binary, "reveal-login", path, factors + show,
                           options=("--id", changed["id"], "--revision", changed["revision"], "--field", "password"),
                           capture_disclosure=True, forbidden=(first,))
        assert re.fullmatch(r"[A-Za-z0-9]{32}", second)
        rows, _ = invoke(binary, "list", path, factors, forbidden=(first, second))
        events, _ = invoke(binary, "audit", path, factors, forbidden=(first, second))
        assert len(rows) == 1 and rows[0]["revision"] == changed["revision"]
        generated = [e for e in events if e["action"] in ("item.generate", "item.regenerate.password")]
        assert [e["result"] for e in generated] == ["succeeded", "succeeded", "conflict"]
        assert generated[0]["generation"] == created["profile"] and generated[1]["generation"] == changed["profile"]
        assert "generation" not in generated[2]
        public = json.dumps([created, changed, rows, events])
        disk = pathlib.Path(path).read_bytes()
        assert all(secret not in public and secret.encode() not in disk for secret in (first, second))
    print("PASS: generated create/replace, consent, encrypted persistence, explicit reveal, revisions and policy audit")


if __name__ == "__main__":
    check(*(str(pathlib.Path(p).resolve(strict=True)) for p in sys.argv[1:]))
