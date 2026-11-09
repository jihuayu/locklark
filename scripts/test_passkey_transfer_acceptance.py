"""Pure unit tests for the owned passkey transfer acceptance helpers.

These tests never build or run the product CLI, never create a vault, never use
the network and never touch a real credential.
"""

import base64
import importlib.util
import json
import os
import pathlib
import stat
import tempfile
import unittest

MODULE_PATH = pathlib.Path(__file__).with_name("passkey_transfer_acceptance.py")
SPEC = importlib.util.spec_from_file_location("passkey_transfer_acceptance", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class PureHelperTests(unittest.TestCase):
    def test_hex64_and_token(self):
        self.assertTrue(MODULE.hex64("a" * 64))
        self.assertTrue(MODULE.hex64("0123456789abcdef" * 4))
        self.assertFalse(MODULE.hex64("A" * 64))
        self.assertFalse(MODULE.hex64("a" * 63))
        self.assertTrue(MODULE.token("item-1"))
        self.assertFalse(MODULE.token("item 1"))
        self.assertFalse(MODULE.token(""))

    def test_credential_id(self):
        raw = b"credential-id"
        value = base64.urlsafe_b64encode(raw).decode().rstrip("=")
        self.assertTrue(MODULE.credential_id(value))
        self.assertFalse(MODULE.credential_id(value + "="))
        self.assertFalse(MODULE.credential_id(""))

    def test_format_secret(self):
        raw = bytes(range(16))
        text = MODULE.format_secret(raw)
        self.assertTrue(text.startswith("LL1-"))
        self.assertEqual(base64.b32decode(text[4:] + "=" * (-len(text[4:]) % 8)), raw)
        with self.assertRaises(MODULE.Refusal):
            MODULE.format_secret(b"short")

    def test_selection_document_is_exact_private_shape(self):
        raw = MODULE.selection_document("item-1", "a" * 64, "Y3JlZA", "b" * 64)
        value = json.loads(raw)
        self.assertEqual(value, [{
            "item_id": "item-1",
            "revision": "a" * 64,
            "credential_id": "Y3JlZA",
            "credential_revision": "b" * 64,
        }])

    def test_mapping_document_freezes_new_title_group(self):
        raw = MODULE.mapping_document("c" * 64)
        self.assertEqual(json.loads(raw), [{
            "group_id": "c" * 64,
            "new_title": "Imported Passkey Login",
            "new_username": "imported-user",
        }])

    def test_validate_plan(self):
        digest = "d" * 64
        plan = {
            "digest": digest,
            "source_fingerprint": "a" * 64,
            "target_fingerprint": "b" * 64,
            "groups": [{"group_id": "c" * 64, "rp_id": "example.test", "credential_ids": ["Y3JlZA"]}],
        }
        self.assertEqual(MODULE.validate_plan(plan, "a" * 64, "b" * 64, "Y3JlZA"), (digest, "c" * 64))
        for mutate in (
            lambda value: value.update(digest="bad"),
            lambda value: value.update(source_fingerprint="e" * 64),
            lambda value: value["groups"][0].update(credential_ids=["other"]),
            lambda value: value["groups"][0].update(seed="x"),
        ):
            changed = json.loads(json.dumps(plan))
            mutate(changed)
            with self.assertRaises(MODULE.Refusal):
                MODULE.validate_plan(changed, "a" * 64, "b" * 64, "Y3JlZA")

    def test_validate_import(self):
        good = {"status": "imported", "items": [{"id": "item-2", "revision": "e" * 64}]}
        self.assertEqual(MODULE.validate_import(good), ("item-2", "e" * 64))
        with self.assertRaises(MODULE.Refusal):
            MODULE.validate_import({"status": "imported", "items": []})
        with self.assertRaises(MODULE.Refusal):
            MODULE.validate_import({"status": "imported", "items": [{"id": "item", "revision": "e" * 64, "private_key": "x"}]})

    def test_receipt_and_state(self):
        self.assertEqual(MODULE.receipt(b'{"status":"invited","fingerprint":"abc"}', "invited")["fingerprint"], "abc")
        with self.assertRaises(MODULE.Refusal):
            MODULE.receipt(b"not json", "invited")
        MODULE.assert_state({"a": 1, "b": 2}, {"a": 1})
        with self.assertRaises(MODULE.Refusal):
            MODULE.assert_state({"a": 1}, {"a": 2})

    def test_private_file_and_write_private(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "secret.json"
            MODULE.write_private(path, b"{}")
            self.assertTrue(MODULE.private_file_ok(path))
            self.assertEqual(stat.S_IMODE(os.lstat(path).st_mode), 0o600)
            os.chmod(path, 0o644)
            self.assertFalse(MODULE.private_file_ok(path))
            os.chmod(path, 0o700)
            self.assertFalse(MODULE.private_file_ok(path))
            self.assertTrue(MODULE.private_exec_ok(path))

    def test_privacy_scan_rejects_factor_in_artifact(self):
        factors = MODULE.Factors()
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            os.chmod(root, 0o700)
            clean = root / "selection.json"
            MODULE.write_private(clean, MODULE.selection_document("item-1", "a" * 64, "Y3JlZA", "b" * 64))
            MODULE.privacy_scan(root, factors, None)
            leaked = root / "leak.txt"
            MODULE.write_private(leaked, factors.source_password.encode())
            with self.assertRaises(MODULE.Refusal):
                MODULE.privacy_scan(root, factors, None)

    def test_assert_hidden_rejects_echoed_factor_and_consent(self):
        factors = MODULE.Factors()
        password = factors.source_password.encode()
        prompt = b"Enter INVITE to confirm invitation creation: "
        clean = MODULE.PtyResult(0, prompt + b"\r\n", b'{"status":"invited"}', b"")
        MODULE.assert_hidden(clean, factors, prompt, b"INVITE")
        echoed = MODULE.PtyResult(0, prompt + b"INVITE\r\n", b"", b"")
        with self.assertRaises(MODULE.Refusal):
            MODULE.assert_hidden(echoed, factors, prompt, b"INVITE")
        leaked = MODULE.PtyResult(0, b"", password, b"")
        with self.assertRaises(MODULE.Refusal):
            MODULE.assert_hidden(leaked, factors, prompt, b"INVITE")
        marker = MODULE.PtyResult(0, b"", b'{"signature":"x"}', b"")
        with self.assertRaises(MODULE.Refusal):
            MODULE.assert_hidden(marker, factors, prompt, b"INVITE")

    def test_recorder_log_is_fixed_and_private(self):
        with tempfile.TemporaryDirectory() as directory:
            log = pathlib.Path(directory) / "acceptance.log"
            recorder = MODULE.Recorder(log)
            recorder.stage("prerequisites")
            recorder.value("two_real_physical_devices", "open")
            recorder.fail("build_cli")
            data = log.read_bytes()
            self.assertEqual(stat.S_IMODE(os.lstat(log).st_mode), 0o600)
            self.assertEqual(data, b"stage=prerequisites ok=true\nstage=two_real_physical_devices value=open\nstage=build_cli ok=false\n")


if __name__ == "__main__":
    unittest.main()
