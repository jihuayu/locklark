"""Negative artifact/privacy gates; these are not a Secret Service substitute."""
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
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
SPEC = spec_from_file_location("team_identity_acceptance", Path(__file__).resolve().parents[1] / "team_identity_acceptance.py")
controller = module_from_spec(SPEC)
SPEC.loader.exec_module(controller)


class Gates(unittest.TestCase):
    def fixture(self, root):
        root.chmod(0o700)
        (root / "oracle").mkdir(mode=0o700)
        canary = b"private-controller-canary"
        values = [canary] + [("private-other-canary-%d" % index).encode() for index in range(4)]
        controller.private_json(root / "oracle" / "canaries.json", [base64.b64encode(value).decode() for value in values])
        log = root / "runtime-private.log"
        log.write_bytes(b"PASS: fixed group\n")
        log.chmod(0o600)
        return canary, log

    def test_clean_private_runtime_passes(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            self.fixture(root)
            self.assertEqual(controller.privacy(root), 1)

    def test_raw_and_encoded_runtime_leaks_are_refused(self):
        for transform in [lambda value: value, base64.b64encode, lambda value: value.hex().encode()]:
            with tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                canary, log = self.fixture(root)
                log.write_bytes(transform(canary))
                with self.assertRaises(controller.Failure): controller.privacy(root)

    def test_nested_oracle_directory_cannot_hide_a_leak(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            canary, _ = self.fixture(root)
            nested = root / "data" / "oracle"
            nested.mkdir(parents=True)
            leaked = nested / "output.log"
            leaked.write_bytes(canary)
            leaked.chmod(0o600)
            with self.assertRaises(controller.Failure): controller.privacy(root)

    def test_missing_manifest_public_logs_and_symlinks_fail(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            with self.assertRaises(controller.Failure): controller.privacy(root)
            _, log = self.fixture(root)
            log.chmod(0o644)
            with self.assertRaises(controller.Failure): controller.privacy(root)
            log.chmod(0o600)
            (root / "alias").symlink_to(log)
            with self.assertRaises(controller.Failure): controller.privacy(root)

    def test_private_canary_manifest_permissions_are_required(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            self.fixture(root)
            (root / "oracle" / "canaries.json").chmod(0o644)
            with self.assertRaises(controller.Failure): controller.privacy(root)

    def test_empty_partial_or_duplicate_canary_manifests_fail(self):
        for values in [[], [base64.b64encode(b"private-one-canary").decode()], [base64.b64encode(b"private-one-canary").decode()] * 5]:
            with tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                self.fixture(root)
                (root / "oracle" / "canaries.json").write_text(json.dumps(values))
                with self.assertRaises(controller.Failure): controller.privacy(root)

    def test_private_leaf_does_not_hide_replaceable_parent(self):
        with tempfile.TemporaryDirectory() as folder:
            parent = Path(folder) / "public"
            parent.mkdir(mode=0o700)
            leaf = parent / "private"
            leaf.mkdir(mode=0o700)
            parent.chmod(0o777)
            with self.assertRaises(controller.Failure): controller.trusted_parent(leaf)

    def executable(self, root):
        binary = root / "fixture"
        binary.write_bytes(b"reviewed-fixture-artifact")
        binary.chmod(0o700)
        return binary, hashlib.sha256(binary.read_bytes()).hexdigest()

    def test_fixture_expected_hash_is_mandatory_and_must_match(self):
        with tempfile.TemporaryDirectory() as folder:
            binary, expected = self.executable(Path(folder))
            self.assertEqual(controller.verify_fixture(binary, expected), binary)
            for digest in [None, "", "0" * 64, expected.upper()]:
                with self.assertRaises(controller.Failure): controller.verify_fixture(binary, digest)

    def test_writable_fixture_file_or_ancestor_is_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            root.chmod(0o700)
            parent = root / "parent"
            parent.mkdir(mode=0o700)
            binary, expected = self.executable(parent)
            binary.chmod(0o722)
            with self.assertRaises(controller.Failure): controller.verify_fixture(binary, expected)
            binary.chmod(0o700)
            parent.chmod(0o777)
            with self.assertRaises(controller.Failure): controller.verify_fixture(binary, expected)
            with self.assertRaises(controller.Failure): controller.verify_dependencies(parent)

    def test_each_fixture_invocation_rechecks_frozen_artifact(self):
        with tempfile.TemporaryDirectory() as folder:
            binary, expected = self.executable(Path(folder))
            session = object.__new__(controller.Session)
            session.fixture, session.fixture_sha256 = binary, expected
            binary.write_bytes(b"substituted-between-fixture-operations")
            with patch.object(session, "command") as command:
                with self.assertRaises(controller.Failure): session.api("pins", {})
                command.assert_not_called()

    def test_explicit_input_aliases_are_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            binary, expected = self.executable(root)
            alias = root / "alias"
            alias.symlink_to(binary)
            with self.assertRaises(controller.Failure): controller.verify_fixture(alias, expected)
            directory_alias = root / "directory-alias"
            directory_alias.symlink_to(root, target_is_directory=True)
            with self.assertRaises(controller.Failure): controller.verify_dependencies(directory_alias)

    def test_packaged_library_links_remain_inside_trusted_extraction(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            binary, _ = self.executable(root)
            alias = root / "library.so"
            alias.symlink_to(binary.name)
            self.assertEqual(controller.trusted_file(alias, packaged_root=root), binary)
            binary.chmod(0o722)
            with self.assertRaises(controller.Failure): controller.trusted_file(alias, packaged_root=root)
            binary.chmod(0o700)
            alias.unlink()
            alias.symlink_to("/etc/passwd")
            with self.assertRaises(controller.Failure): controller.trusted_file(alias, packaged_root=root)

    def test_tampered_fixture_cannot_pass_completed_workflow(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            binary, expected = self.executable(base)
            root = base / "evidence"
            dependencies = base / "dependencies"
            dependencies.mkdir(mode=0o700)
            controller.private_json(dependencies / "manifest.json", {})
            fixture = self.fixture
            test = self

            class CompletedProcess:
                def __init__(self, argv, **kwargs):
                    # This fake is only a negative gate oracle. Even complete
                    # fixed status text cannot pass a changed frozen artifact.
                    test.assertIn("--private-session", argv)
                    test.assertEqual(argv[argv.index("--fixture-sha256") + 1], expected)
                    fixture(root)
                    for group in controller.GROUPS[:-1]:
                        kwargs["stdout"].write(("PASS: team identity " + group + "\n").encode())
                    binary.write_bytes(b"changed-artifact-after-preflight")

                def wait(self, **kwargs): return 0

            args = SimpleNamespace(fixture_bin=str(binary), fixture_sha256=expected, dependency_root=str(dependencies), artifacts=str(root))
            with patch.object(controller, "verify_dependencies", return_value=dependencies), patch.object(controller.subprocess, "Popen", CompletedProcess), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(controller.outer(args), 1)
            result = json.loads((root / "result.json").read_text())
            self.assertFalse(result["passed"])
            self.assertTrue(result["fixture_verified_before"])
            self.assertFalse(result["fixture_verified_after"])
            self.assertNotEqual(result["fixture_expected_sha256"], result["fixture_actual_sha256"])

    def test_hidden_session_rejects_replaceable_ancestor(self):
        with tempfile.TemporaryDirectory() as folder:
            parent = Path(folder) / "replaceable"
            parent.mkdir(mode=0o700)
            root = parent / "private"
            root.mkdir(mode=0o700)
            parent.chmod(0o777)
            with self.assertRaises(controller.Failure): controller.validate_private_session(root)

    def test_direct_hidden_entry_never_uses_inherited_user_environment(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            root.chmod(0o700)
            for name in ["home", "data", "config", "cache", "runtime"]: (root / name).mkdir(mode=0o700)
            with patch.dict(os.environ, {"HOME": "private-inherited-canary"}):
                with self.assertRaises(controller.Failure): controller.validate_private_session(root)

    def test_argument_and_failure_output_is_fixed(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(controller.main(["--private-inherited-canary"]), 1)
        self.assertEqual(output.getvalue(), "FAIL: team identity acceptance at prerequisites\n")
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(controller.main(["--fixture-bin", "/private-artifact", "--dependency-root", "/private-dependencies", "--artifacts", "/private-evidence"]), 1)
        self.assertEqual(output.getvalue(), "FAIL: team identity acceptance at prerequisites\n")


if __name__ == "__main__": unittest.main()
