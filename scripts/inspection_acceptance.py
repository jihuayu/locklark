"""Synthetic authenticated 1PUX inspection through a real terminal."""
import hashlib
import json
import os
import pathlib
import sys
import tempfile
import zipfile

from personal_acceptance import invoke


def check(binary, legacy=None):
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        path, source = str(root / "owner.ll"), root / "private-source.1pux"
        pw = "synthetic-master-" + os.urandom(8).hex()
        _, key = invoke(legacy or binary, "init", path, [("主密码", pw), ("再次输入主密码", pw),
                        ("重新输入刚保存的 Secret Key", None)], issue=True)
        factors = [("主密码", pw), ("Secret Key", key)]
        item = {"uuid": "i", "categoryUuid": "001", "state": "active",
                "overview": {"title": "private-title"}, "details": {
                    "loginFields": [{"designation": "password", "fieldType": "P", "value": "private-password"}],
                    "passwordHistory": [{"value": "private-old", "time": 9007199254740993}]}}
        data = {"accounts": [{"attrs": {"uuid": "a"}, "vaults": [{"attrs": {"uuid": "v"}, "items": [item]}]}]}
        with zipfile.ZipFile(source, "w", compression=zipfile.ZIP_STORED) as archive:
            archive.writestr("export.attributes", json.dumps({"version": 3, "description": "1Password Unencrypted Export", "createdAt": 0}))
            archive.writestr("export.data", json.dumps(data))
        original = source.read_bytes()
        options = ("--source", str(source))
        prompt = "输入 SCAN 确认预检"
        show = [(prompt, "SCAN")]
        forbidden = ("private-title", "private-password", "private-old", str(source))
        invoke(binary, "inspect-1pux", path, factors + [(prompt, "no")], options=options,
               ok=False, expect_error="1PUX inspection cancelled", forbidden=forbidden)
        invoke(binary, "inspect-1pux", path, [("主密码", pw + "x"), factors[1]] + show,
               options=options, ok=False, expect_error="invalid personal vault", forbidden=forbidden)
        receipt, _ = invoke(binary, "inspect-1pux", path, factors + show, options=options, forbidden=forbidden)
        assert receipt["status"] == "inspected-unmapped"
        report = receipt["report"]
        assert report["items"] == report["unmapped_items"] == 1 and not report["mapping_verified"]
        assert report["password_history"]["entries"] == report["login_field_inventory"]["fields"] == 1
        digest = hashlib.sha256(json.dumps(report, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
        assert receipt["report_digest"] == digest and source.read_bytes() == original
        if legacy:
            invoke(legacy, "list", path, factors, ok=False)
        bad = root / "private-bad.1pux"
        bad.write_bytes(b"private-invalid")
        invoke(binary, "inspect-1pux", path, factors + show, options=("--source", str(bad)),
               ok=False, expect_error="invalid 1PUX archive", forbidden=forbidden + (str(bad), "private-invalid"))
        invoke(binary, "inspect-1pux", path, factors + show, options=("--source", str(root)),
               ok=False, expect_error="bounded regular file", forbidden=forbidden)
        events, _ = invoke(binary, "audit", path, factors, forbidden=forbidden)
        inspections = [e for e in events if e["action"] == "migration.inspect.1pux"]
        assert [e["result"] for e in inspections] == ["succeeded", "invalid", "source-error"]
        assert inspections[0]["session"] == receipt["session"] and inspections[0]["report_digest"] == digest
        event_hash = hashlib.sha256(json.dumps(inspections[0], ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
        assert event_hash == receipt["event"]
        assert all("report_digest" not in e for e in inspections[1:])
        assert all(not e.get(k) for e in inspections for k in ("item_id", "base_revision", "link", "generation"))
    print("PASS: authenticated 1PUX inspection, consent, private report, independent receipt hashes and audited refusals")


if __name__ == "__main__":
    check(*(str(pathlib.Path(p).resolve(strict=True)) for p in sys.argv[1:]))
