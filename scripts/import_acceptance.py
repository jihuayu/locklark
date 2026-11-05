"""Authenticated, digest-bound login import and independent KDBX reconciliation."""
import base64
import copy
import hashlib
import json
import pathlib
import sys
import tempfile
import zipfile

from pykeepass import PyKeePass
from personal_acceptance import invoke


def check(binary):
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        path, source = str(root / "owner.ll"), root / "private.1pux"
        pw = "synthetic-master-password"
        _, key = invoke(binary, "init", path, [("主密码", pw), ("再次输入主密码", pw),
                         ("重新输入刚保存的 Secret Key", None)], issue=True)
        factors = [("主密码", pw), ("Secret Key", key)]
        item = {"uuid": "first", "categoryUuid": "001", "state": "active", "createdAt": 123,
                "overview": {"title": "private-title", "url": "https://example.test/login"},
                "details": {"loginFields": [
                    {"designation": "username", "type": "T", "value": "private-user"},
                    {"designation": "password", "type": "P", "value": "private-secret"}]}}
        archived = copy.deepcopy(item)
        archived.update(uuid="second", state="archived")
        archived["details"]["loginFields"][1]["value"] = ""
        data = {"accounts": [{"attrs": {"uuid": "account"}, "vaults": [
            {"attrs": {"uuid": "vault"}, "items": [item, archived]}]}]}
        def write_source(value):
            with zipfile.ZipFile(source, "w") as z:
                z.writestr("export.attributes", json.dumps({"version": 3, "description": "1Password Unencrypted Export", "createdAt": 0}))
                z.writestr("export.data", json.dumps(value))
        write_source(data)
        original = source.read_bytes()
        options = ("--source", str(source))
        private = ("private-title", "private-user", "private-secret", str(source))
        plan_prompt, import_prompt = "输入 PLAN 确认生成导入计划", "输入 SAVE 确认整批导入"
        invoke(binary, "plan-import-1pux", path, factors + [(plan_prompt, "no")], options=options,
               ok=False, expect_error="1PUX import cancelled", forbidden=private)
        invoke(binary, "plan-import-1pux", path, [("主密码", pw + "wrong"), factors[1], (plan_prompt, "PLAN")],
               options=options, ok=False, expect_error="invalid personal vault", forbidden=private)
        plan, _ = invoke(binary, "plan-import-1pux", path, factors + [(plan_prompt, "PLAN")], options=options, forbidden=private)
        assert len(plan["report"]["source_digest"]) == 64
        assert plan["report"]["source_digest"] != hashlib.sha256(original).hexdigest()
        assert plan["report"]["items"] == 2 and plan["report"]["archived"] == 1
        assert invoke(binary, "list", path, factors)[0] == []
        apply_options = options + ("--digest", plan["report"]["source_digest"])
        invoke(binary, "import-1pux", path, factors + [(import_prompt, "no")], options=apply_options,
               ok=False, expect_error="1PUX import cancelled", forbidden=private)
        source.write_bytes(original + b"changed")
        invoke(binary, "import-1pux", path, factors + [(import_prompt, "SAVE")], options=apply_options,
               ok=False, expect_error="source changed", forbidden=private)
        source.write_bytes(original)
        receipt, _ = invoke(binary, "import-1pux", path, factors + [(import_prompt, "SAVE")],
                            options=apply_options, forbidden=private,
                            required_before_last_prompt=("来源记录会加密保留", "不会覆盖已有条目"))
        assert receipt["report_digest"] == plan["report_digest"] and receipt["status"] == "imported-login-v1"
        invoke(binary, "import-1pux", path, factors + [(import_prompt, "SAVE")], options=apply_options,
               ok=False, expect_error="source item already exists", forbidden=private)
        rows, _ = invoke(binary, "list", path, factors, options=("--state", "all"))
        assert len(rows) == 2 and {row["state"] for row in rows} == {"active", "archived"}
        portable, export_pw = str(root / "portable.kdbx"), "synthetic-export-password"
        invoke(binary, "export-kdbx", path, factors + [("新导出密码（至少 12 字符）", export_pw),
               ("再次输入导出密码", export_pw), ("输入 SAVE 确认加密导出", "SAVE")], options=("--out", portable),
               forbidden=private, required_before_last_prompt=("包含导入来源记录",))
        entries = PyKeePass(portable, password=export_pw).entries
        assert len(entries) == 2
        for entry, expected in zip(entries, (item, archived)):
            provenance = json.loads(base64.b64decode(entry.get_custom_property("Locklark.ImportSource")))
            assert entry.is_custom_property_protected("Locklark.ImportSource")
            assert provenance["item"] == expected and provenance["account"] == {"uuid": "account"}
            assert provenance["vault"] == {"uuid": "vault"}
            assert entry.title == expected["overview"]["title"] and entry.url == expected["overview"]["url"]
            assert entry.username == "private-user" and (entry.password or "") == expected["details"]["loginFields"][1]["value"]
            assert (entry.get_custom_property("Locklark.State") or "active") == expected["state"]
        events, _ = invoke(binary, "audit", path, factors, forbidden=private)
        imports = [e for e in events if e["action"] == "migration.import.1pux"]
        assert [e["result"] for e in imports] == ["source-changed", "succeeded", "duplicate"]
        assert len([e for e in events if e["action"] == "item.import"]) == 2
        # A mixed supported/unsupported source must not create even its good item.
        invalid = copy.deepcopy(data)
        invalid["accounts"][0]["vaults"][0]["items"][1]["details"]["notesPlain"] = "private-unmapped"
        write_source(invalid)
        invoke(binary, "plan-import-1pux", path, factors + [(plan_prompt, "PLAN")], options=options,
               ok=False, expect_error="unsupported 1PUX", forbidden=private + ("private-unmapped",))
        assert invoke(binary, "list", path, factors, options=("--state", "all"))[0] == rows
    print("PASS: confirmed digest-bound import, atomic refusals, scoped identity, source retention and independent KDBX reconciliation")


if __name__ == "__main__":
    check(str(pathlib.Path(sys.argv[1]).resolve(strict=True)))
