"""Synthetic authenticated reference flows through a real POSIX/Windows terminal."""
import base64
import hashlib
import hmac
import json
import os
import pathlib
import struct
import sys
import tempfile

from personal_acceptance import invoke


def check(binary):
    seed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    secret = "reference-password-" + os.urandom(8).hex()
    with tempfile.TemporaryDirectory() as tmp:
        path = str(pathlib.Path(tmp) / "owner.ll")
        pw = "synthetic-master-" + os.urandom(8).hex()
        _, key = invoke(binary, "init", path, [("主密码", pw), ("再次输入主密码", pw),
                        ("重新输入刚保存的 Secret Key", None)], issue=True)
        factors = [("主密码", pw), ("Secret Key", key)]
        for _ in range(2):
            invoke(binary, "add-login", path, factors + [("登录标题", "same"),
                   ("用户名（可留空）", "reference-user"), ("登录密码", secret)])
        index, _ = invoke(binary, "references", path, factors, forbidden=(secret, seed, "reference-user"))
        row = index["items"][0]
        assert index["vault_name"] == "Personal" and set(row["references"]) == {"username", "password", "otp"}
        raw = row["references"]["password"]
        assert raw == "op://" + index["vault_id"] + "/" + row["id"] + "/password"
        target = ("--ref", raw, "--revision", row["revision"])
        show = [("输入 SHOW 确认按引用显示", "SHOW")]
        invoke(binary, "reveal-ref", path, factors + [(show[0][0], "no")], options=target,
               ok=False, expect_error="reference disclosure cancelled", forbidden=(secret, seed))
        invoke(binary, "reveal-ref", path, [("主密码", pw + "x"), factors[1]] + show,
               options=target, ok=False, expect_error="invalid personal vault", forbidden=(secret, seed))
        receipt, _ = invoke(binary, "reveal-ref", path, factors + show, options=target, disclosed=secret)
        assert set(receipt) == {"status", "session", "intent"}
        for action, ref, revision, error in (
            ("reveal-ref", "op://Personal/same/password", row["revision"], "ambiguous"),
            ("reveal-ref", "op://Personal/private-missing/password", row["revision"], "not found"),
            ("reveal-ref", row["references"]["otp"], row["revision"], "type does not match"),
            ("otp-ref", raw, row["revision"], "type does not match"),
            ("reveal-ref", raw, "0" * 64, "login changed"),
        ):
            invoke(binary, action, path, factors + show, options=("--ref", ref, "--revision", revision),
                   ok=False, expect_error=error, forbidden=(secret, seed))
        edited, _ = invoke(binary, "edit-login", path, factors + [
            ("新 TOTP 配置（Base32 或 otpauth URI，留空清除）", seed), ("输入 SAVE 确认更新 TOTP", "SAVE")],
            options=("--id", row["id"], "--revision", row["revision"], "--field", "otp"), forbidden=(seed, secret))
        otp_receipt, code = invoke(binary, "otp-ref", path, factors + show,
            options=("--ref", row["references"]["otp"], "--revision", edited["revision"]),
            capture_disclosure=True, forbidden=(seed, secret))
        digest = hmac.new(base64.b32decode(seed), struct.pack(">Q", otp_receipt["valid_from"] // 30), hashlib.sha1).digest()
        offset = digest[-1] & 15
        expected = str((int.from_bytes(digest[offset:offset + 4], "big") & 0x7fffffff) % 1000000).zfill(6)
        assert code == expected and otp_receipt["valid_until"] == otp_receipt["valid_from"] + 30
        # Name/ID collisions must not make canonical-ID references win silently.
        second = index["items"][1]
        invoke(binary, "edit-login", path, factors + [("新标题", row["id"])],
               options=("--id", second["id"], "--revision", second["revision"], "--field", "title"))
        invoke(binary, "reveal-ref", path, factors + show,
               options=("--ref", raw, "--revision", edited["revision"]),
               ok=False, expect_error="ambiguous", forbidden=(secret, seed))
        events, _ = invoke(binary, "audit", path, factors, forbidden=(seed, secret, "reference-user"))
        rejections = [e for e in events if e["action"] == "reference.reject"]
        assert [e["result"] for e in rejections] == ["ambiguous", "not-found", "wrong-type", "wrong-type", "stale", "ambiguous"]
        assert all(not e.get(field) for e in rejections for field in ("item", "base_revision", "link", "generation"))
        public = json.dumps([index, receipt, otp_receipt, events])
        assert all(value not in public for value in (secret, seed, "reference-user"))
        assert "op://" not in json.dumps(events) and "private-missing" not in json.dumps(events)
        assert any(e["action"] == "item.reveal.password" and e["session"] == receipt["session"] for e in events)
        assert any(e["action"] == "item.reveal.otp-code" and e["session"] == otp_receipt["session"] for e in events)
    print("PASS: authenticated index, reference disclosure, OTP HMAC, ambiguity, type/revision refusals and private audit")


if __name__ == "__main__":
    check(str(pathlib.Path(sys.argv[1]).resolve(strict=True)))
