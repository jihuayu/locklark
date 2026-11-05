"""Synthetic TOTP terminal workflow, checked with an independent Python HMAC."""
import base64
import hashlib
import hmac
import json
import os
import pathlib
import re
import struct
import sys
import tempfile
import time

from personal_acceptance import invoke


def check(binary, legacy=None):
    seed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    config = "otpauth://totp/synthetic?secret=" + seed + "&digits=8"
    with tempfile.TemporaryDirectory() as tmp:
        path = str(pathlib.Path(tmp) / "owner.ll")
        pw = "synthetic-master-" + os.urandom(8).hex()
        _, key = invoke(legacy or binary, "init", path, [("主密码", pw), ("再次输入主密码", pw),
                        ("重新输入刚保存的 Secret Key", None)], issue=True)
        factors = [("主密码", pw), ("Secret Key", key)]
        invoke(binary, "add-login", path, factors + [("登录标题", "OTP fixture"),
               ("用户名（可留空）", "otp-user"), ("登录密码", "fixture-password")])
        rows, _ = invoke(binary, "list", path, factors)
        target = ("--id", rows[0]["id"], "--revision", rows[0]["revision"])
        show = [("输入 SHOW 确认显示验证码", "SHOW")]
        invoke(binary, "otp", path, factors + show, options=target, ok=False,
               expect_error="no TOTP configuration", forbidden=(seed, config))
        edit_options = (*target, "--field", "otp")
        edit_prompt = "新 TOTP 配置（Base32 或 otpauth URI，留空清除）"
        confirm = "输入 SAVE 确认更新 TOTP"
        invoke(binary, "edit-login", path, factors + [(edit_prompt, config), (confirm, "no")],
               options=edit_options, ok=False, forbidden=(seed, config))
        invoke(binary, "edit-login", path, factors + [(edit_prompt, "MZXW6"), (confirm, "SAVE")],
               options=edit_options, ok=False, expect_error="invalid TOTP configuration", forbidden=(seed, config))
        edited, _ = invoke(binary, "edit-login", path, factors + [(edit_prompt, config), (confirm, "SAVE")],
                           options=edit_options, forbidden=(seed, config))
        if legacy:
            invoke(legacy, "list", path, factors, ok=False)
        invoke(binary, "otp", path, factors + show, options=target, ok=False,
               expect_error="login changed", forbidden=(seed, config))
        current = ("--id", edited["id"], "--revision", edited["revision"])
        invoke(binary, "otp", path, factors + [(show[0][0], "no")], options=current,
               ok=False, expect_error="OTP disclosure cancelled", forbidden=(seed, config))
        for wrong in ([("主密码", pw + "x"), factors[1]], [factors[0], ("Secret Key", "LL1-" + "A" * 26)]):
            invoke(binary, "otp", path, wrong + show, options=current, ok=False,
                   expect_error="invalid personal vault", forbidden=(seed, config))
        before = time.time()
        receipt, code = invoke(binary, "otp", path, factors + show, options=current,
                               capture_disclosure=True, forbidden=(seed, config))
        after = time.time()
        assert re.fullmatch(r"[0-9]{8}", code)
        start, until = receipt["valid_from"], receipt["valid_until"]
        assert start % 30 == 0 and until == start + 30 and start <= after and until > before
        digest = hmac.new(base64.b32decode(seed), struct.pack(">Q", start // 30), hashlib.sha1).digest()
        offset = digest[-1] & 15
        expected = str((int.from_bytes(digest[offset:offset + 4], "big") & 0x7fffffff) % 100000000).zfill(8)
        assert code == expected and receipt["status"] == "written-to-terminal"
        assert set(receipt) == {"status", "session", "intent", "valid_from", "valid_until"}
        cleared, _ = invoke(binary, "edit-login", path, factors + [(edit_prompt, ""), (confirm, "SAVE")],
                            options=(*current, "--field", "otp"), forbidden=(seed, config))
        invoke(binary, "otp", path, factors + show,
               options=("--id", cleared["id"], "--revision", cleared["revision"]),
               ok=False, expect_error="no TOTP configuration", forbidden=(seed, config))
        events, _ = invoke(binary, "audit", path, factors, forbidden=(seed, config))
        requests = [e for e in events if e["action"] == "item.reveal.otp-code"]
        assert [e["result"] for e in requests] == ["not-configured", "conflict", "intent", "not-configured"]
        assert requests[2]["session"] == receipt["session"]
        public = json.dumps([receipt, events])
        assert all(secret not in public for secret in (seed, config, code))
        assert all(secret.encode() not in pathlib.Path(path).read_bytes() for secret in (seed, config, code))
    print("PASS: hidden OTP configuration, audited terminal code, independent HMAC, consent, revision and clearing")


if __name__ == "__main__":
    check(*(str(pathlib.Path(p).resolve(strict=True)) for p in sys.argv[1:]))
