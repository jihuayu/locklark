"""Negative integrity/privacy gates, not a native bootstrap substitute."""
import base64
import contextlib
import hashlib
from importlib.util import module_from_spec, spec_from_file_location
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))
SPEC = spec_from_file_location("team_bootstrap_acceptance", SCRIPTS / "team_bootstrap_acceptance.py")
controller = module_from_spec(SPEC); SPEC.loader.exec_module(controller)


class BootstrapGates(unittest.TestCase):
    def evidence(self, root):
        root.chmod(0o700)
        canaries = []
        for participant in ["server", "owner"]:
            oracle = root / participant / "oracle"; oracle.mkdir(parents=True, mode=0o700)
            values = [("private-%s-value-%d" % (participant, index)).encode() for index in range(5)]
            controller.native.private_json(oracle / "canaries.json", [base64.b64encode(value).decode() for value in values])
            canaries += values
        log = root / "runtime-private.log"; log.write_bytes(b"PASS: fixed classification\n"); log.chmod(0o600)
        return canaries, log

    def test_clean_private_evidence(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); self.evidence(root)
            self.assertEqual(controller.privacy(root), 1)

    def test_either_provider_canary_leak_refuses_success(self):
        for index in [0, 5]:
            for transform in [lambda value: value, base64.b64encode, lambda value: value.hex().encode()]:
                with tempfile.TemporaryDirectory() as folder:
                    root = Path(folder); canaries, log = self.evidence(root)
                    log.write_bytes(transform(canaries[index]))
                    with self.assertRaises(controller.Failure): controller.privacy(root)

    def test_nested_oracle_name_never_hides_public_leak(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); canaries, _ = self.evidence(root)
            directory = root / "transfer" / "oracle"; directory.mkdir(parents=True)
            path = directory / "artifact.json"; path.write_bytes(canaries[0]); path.chmod(0o600)
            with self.assertRaises(controller.Failure): controller.privacy(root)

    def test_missing_partial_or_public_canary_manifest_fails(self):
        for damage in ["missing", "partial", "public"]:
            with tempfile.TemporaryDirectory() as folder:
                root = Path(folder); self.evidence(root)
                path = root / "server/oracle/canaries.json"
                if damage == "missing": path.unlink()
                elif damage == "partial": path.write_text("[]")
                else: path.chmod(0o644)
                with self.assertRaises(controller.Failure): controller.privacy(root)

    def test_symlinks_and_public_output_are_refused(self):
        for damage in ["alias", "public"]:
            with tempfile.TemporaryDirectory() as folder:
                root = Path(folder); _, log = self.evidence(root)
                if damage == "alias": (root / "alias").symlink_to(log)
                else: log.chmod(0o644)
                with self.assertRaises(controller.Failure): controller.privacy(root)

    def test_all_three_artifacts_need_external_matching_hashes(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); binaries = {}
            for name in ["cli", "service", "fixture"]:
                path = root / name; path.write_bytes(("reviewed-" + name).encode()); path.chmod(0o700)
                binaries[name] = {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
            config = {"binaries": binaries}
            controller.verify_binaries(config)
            for name in binaries:
                original = binaries[name]["sha256"]; binaries[name]["sha256"] = "0" * 64
                with self.assertRaises(controller.native.Failure): controller.verify_binaries(config)
                binaries[name]["sha256"] = original
            Path(binaries["fixture"]["path"]).write_bytes(b"changed-after-first-check")
            with self.assertRaises(controller.native.Failure): controller.verify_binaries(config)

    def test_hidden_worker_cannot_use_inherited_user_service(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); root.chmod(0o700)
            participant = root / "server"; participant.mkdir(mode=0o700)
            for name in ["home", "data", "config", "cache", "runtime"]: (participant / name).mkdir(mode=0o700)
            with patch.dict(os.environ, {"HOME": "private-user-canary"}), patch.object(controller.native, "Session") as session:
                with self.assertRaises(controller.native.Failure): controller.worker({"root": str(root)}, "server")
                session.assert_not_called()

    def test_cleanup_continues_after_one_owned_participant_fails(self):
        acceptance = object.__new__(controller.Acceptance)
        first, second = unittest.mock.Mock(), unittest.mock.Mock()
        first.close.side_effect = OSError("private-runtime-canary")
        first.cleaned, second.cleaned = False, True
        acceptance.owner, acceptance.server = first, second
        self.assertFalse(acceptance.cleanup())
        second.close.assert_called_once()

    def test_bad_cli_never_echoes_supplied_input(self):
        for args in [["--private-canary"], ["--cli", "/private-canary"], ["--worker", "--participant", "server"]]:
            output = io.StringIO()
            with contextlib.redirect_stdout(output): self.assertEqual(controller.main(args), 1)
            self.assertEqual(output.getvalue(), "FAIL: team bootstrap at prerequisites\n")

    def test_only_exact_owned_loopback_receipt_can_select_tls_endpoint(self):
        receipt = {"command": "serve-profile", "state": "active", "listen": "127.0.0.1:54321"}
        self.assertEqual(controller.service_endpoint(json.dumps(receipt).encode()), "https://127.0.0.1:54321")
        for value in ["0.0.0.0:54321", "example.test:443", "127.0.0.1:0", "127.0.0.1:65536", "127.0.0.1:443/path", "127.0.0.1:0443", None]:
            with self.assertRaises(controller.Failure): controller.service_endpoint(json.dumps({**receipt, "listen": value}).encode())
        with self.assertRaises(controller.Failure): controller.service_endpoint(json.dumps({**receipt, "state": "unknown"}).encode())


if __name__ == "__main__": unittest.main()
