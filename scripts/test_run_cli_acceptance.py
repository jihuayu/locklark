"""Independent negative oracles for the external RunCLI controller."""
import base64
import contextlib
import io
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import run_cli_acceptance as acceptance


class Connection:
    """A fragmented network stream, including EOF, without a TLS mock server."""
    def __init__(self, data, fragment=1):
        self.data, self.fragment = data, fragment

    def recv(self, length):
        chunk, self.data = self.data[:min(length, self.fragment)], self.data[min(length, self.fragment):]
        return chunk


class HTTPBodyTests(unittest.TestCase):
    def test_real_gh_chunked_json_body_is_reconstructed_exactly(self):
        raw = b'5\r\n{"mar\r\n9;owned=1\r\nker":"own\r\na\r\ned stdin"}\r\n0\r\n\r\n'
        self.assertEqual(acceptance.OracleConnection.body(Connection(raw), {"transfer-encoding": "chunked"}),
                         b'{"marker":"owned stdin"}')

    def test_truncated_content_length_never_accepts_partial_body(self):
        with self.assertRaises(acceptance.AcceptanceFailure):
            acceptance.OracleConnection.body(Connection(b"incomplete"), {"content-length": "20"})

    def test_ambiguous_length_and_transfer_encoding_rejected(self):
        with self.assertRaises(acceptance.AcceptanceFailure):
            acceptance.OracleConnection.body(Connection(b"0\r\n\r\n"), {"content-length": "0", "transfer-encoding": "chunked"})

    def test_oversized_chunk_is_refused_before_payload_read(self):
        with self.assertRaises(acceptance.AcceptanceFailure):
            acceptance.OracleConnection.body(Connection(b"100001\r\n"), {"transfer-encoding": "chunked"})

    def test_malformed_chunk_or_trailer_cannot_become_success(self):
        for raw in (b"-1\r\n", b"100000000\r\n", b"1\r\nx!!0\r\n\r\n", b"0\r\nAuthorization: value\r\n\r\n"):
            with self.subTest(raw_length=len(raw)), self.assertRaises(acceptance.AcceptanceFailure):
                acceptance.OracleConnection.body(Connection(raw), {"transfer-encoding": "chunked"})


class PrivacyTests(unittest.TestCase):
    def test_plain_encoded_and_json_escaped_canaries_refuse(self):
        secret = 'PrivateFactor-"' + "a" * 48
        representations = (secret.encode(), base64.b64encode(secret.encode()), secret.encode().hex().encode(),
                           json.dumps(secret)[1:-1].encode())
        for raw in representations:
            with self.subTest(length=len(raw)), self.assertRaises(acceptance.AcceptanceFailure):
                acceptance.scan(b"prefix " + raw + b" suffix", [secret])
        acceptance.scan(b"fixed child output only", [secret])

    def test_unexpected_exception_and_untrusted_stage_never_reach_stdout(self):
        secret = "NeverPrintFailureArguments-" + "f" * 48
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            fake = mock.Mock()
            fake.root, fake.stage, fake.checks, fake.logs, fake.values = root, secret, [], [], [secret]
            fake.run.side_effect = RuntimeError(secret)
            out = io.StringIO()
            with mock.patch.object(acceptance, "Acceptance", return_value=fake), contextlib.redirect_stdout(out):
                result = acceptance.main(["--cli", "/unused"])
            self.assertEqual(result, 1)
            self.assertIn("FAIL: RunCLI acceptance at prerequisites", out.getvalue())
            self.assertNotIn(secret, out.getvalue())
            fake.close.assert_called_once_with()

    def test_failed_run_still_scans_full_public_outputs(self):
        secret = "InjectedOutputCanary-" + "e" * 48
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            public = root / "child.stderr"
            public.write_text(secret)
            fake = mock.Mock()
            fake.root, fake.stage, fake.checks = root, "gh-success", []
            fake.logs, fake.values = [(public, set())], [secret]
            fake.run.side_effect = RuntimeError("fixed failure")
            out = io.StringIO()
            with mock.patch.object(acceptance, "Acceptance", return_value=fake), contextlib.redirect_stdout(out):
                self.assertEqual(acceptance.main(["--cli", "/unused"]), 1)
            self.assertIn("at privacy", out.getvalue())
            self.assertNotIn(secret, out.getvalue())

    def test_cleanup_exception_never_prints_private_exception(self):
        secret = "PrivateCleanupFailure-" + "c" * 48
        with tempfile.TemporaryDirectory() as directory:
            fake = mock.Mock()
            fake.root, fake.stage, fake.checks = pathlib.Path(directory), "complete", []
            fake.logs, fake.values = [], [secret]
            fake.close.side_effect = RuntimeError(secret)
            out = io.StringIO()
            with mock.patch.object(acceptance, "Acceptance", return_value=fake), contextlib.redirect_stdout(out):
                self.assertEqual(acceptance.main(["--cli", "/unused"]), 1)
            self.assertIn("at cleanup", out.getvalue())
            self.assertNotIn(secret, out.getvalue())


class FixedFailureLabelTests(unittest.TestCase):
    @staticmethod
    def fake(root, stage, error=None):
        fake = mock.Mock()
        fake.root, fake.stage, fake.checks = root, stage, ["fixed-check"]
        fake.logs, fake.values, fake.failure_metadata = [], [], {}
        fake.run.side_effect = error or acceptance.AcceptanceFailure("gh-pipe-stderr-output-or-receipt-mismatch")
        fake.write.side_effect = lambda path, value: path.write_text(json.dumps(value))
        return fake

    def test_failure_label_is_publicly_encoded_in_output_and_result(self):
        code = "gh-pipe-stderr-output-or-receipt-mismatch"
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            fake = self.fake(root, "gh-pipes", acceptance.AcceptanceFailure(code))
            fake.failure_metadata = {
                "request_substage": "pipe-stderr", "expected_exit_code": 1, "actual_exit_code": 1,
                "stdin_pipe": True, "stderr_pipe": True, "controlling": True,
                "prompts_observed": 3, "stdout_length": 27, "stderr_length": 128,
                "tls_request_count_delta": 1}
            out = io.StringIO()
            with mock.patch.object(acceptance, "Acceptance", return_value=fake), contextlib.redirect_stdout(out):
                self.assertEqual(acceptance.main(["--cli", "/unused"]), 1)
            public = out.getvalue()
            self.assertIn("FAIL: RunCLI acceptance at gh-pipes [" + code + "]", public)
            result_path = root / "result.json"
            result = json.loads(result_path.read_text())
            self.assertIs(result["success"], False)
            self.assertEqual(result["stage"], "gh-pipes")
            self.assertEqual(result["checks"], ["fixed-check"])
            self.assertEqual(result["failure_code"], code)
            self.assertEqual(result["failures"], [code])
            self.assertEqual(result["failure_metadata"], fake.failure_metadata)
            metadata_line = next(line for line in public.splitlines() if line.startswith("FAILURE_METADATA: "))
            self.assertEqual(json.loads(metadata_line.split(": ", 1)[1]), fake.failure_metadata)

    def test_malicious_exception_text_is_never_printed_or_persisted(self):
        secret = "RuntimeSecret-" + "b" * 48
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            fake = self.fake(root, "gh-success", RuntimeError(secret))
            fake.values = [secret]
            out = io.StringIO()
            with mock.patch.object(acceptance, "Acceptance", return_value=fake), contextlib.redirect_stdout(out):
                self.assertEqual(acceptance.main(["--cli", "/unused"]), 1)
            public = out.getvalue()
            self.assertIn("at gh-success [unexpected]", public)
            self.assertNotIn(secret, public)
            result_text = (root / "result.json").read_text()
            result = json.loads(result_text)
            self.assertEqual(result["failure_code"], "unexpected")
            self.assertEqual(result["failures"], ["unexpected"])
            self.assertNotIn(secret, result_text)

    def test_metadata_scrubber_drops_unrecognized_values_and_never_leaks(self):
        secret = "MetadataSecret-" + "d" * 48
        malicious = {"request_substage": secret, "expected_exit_code": secret,
                     "actual_exit_code": True, "stdin_pipe": "true",
                     "prompts_observed": -1, "stdout_length": secret,
                     "stderr_length": 3.5, "tls_request_count_delta": -4,
                     secret: secret}
        self.assertEqual(acceptance.scrub_failure_metadata(malicious), {})
        valid = {"request_substage": "pipe-stderr", "expected_exit_code": 1,
                 "actual_exit_code": 1, "stdin_pipe": True, "stderr_pipe": True,
                 "controlling": False, "prompts_observed": 3, "stdout_length": 12,
                 "stderr_length": 34, "tls_request_count_delta": 1}
        self.assertEqual(acceptance.scrub_failure_metadata(valid), valid)
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            fake = self.fake(root, "gh-pipes", RuntimeError(secret))
            fake.values, fake.failure_metadata = [secret], malicious
            out = io.StringIO()
            with mock.patch.object(acceptance, "Acceptance", return_value=fake), contextlib.redirect_stdout(out):
                self.assertEqual(acceptance.main(["--cli", "/unused"]), 1)
            public = out.getvalue()
            self.assertIn("FAILURE_METADATA: {}", public)
            self.assertNotIn(secret, public)
            result_text = (root / "result.json").read_text()
            self.assertEqual(json.loads(result_text)["failure_metadata"], {})
            self.assertNotIn(secret, result_text)

    def test_unknown_failure_labels_are_rejected_without_leaking_them(self):
        secret = "MaliciousLabel-" + "c" * 48
        with self.assertRaises(ValueError) as raised:
            acceptance.AcceptanceFailure(secret)
        self.assertEqual(str(raised.exception), "unknown acceptance failure code")
        self.assertNotIn(secret, str(raised.exception))
        for condition in (False, True):
            with self.subTest(condition=condition), self.assertRaises(ValueError) as raised:
                acceptance.require(condition, secret)
            self.assertNotIn(secret, str(raised.exception))

    def test_fixed_invariant_and_builtin_classification_enum(self):
        with self.assertRaises(acceptance.AcceptanceFailure) as raised:
            acceptance.require(False)
        self.assertEqual(raised.exception.code, "invariant")
        self.assertEqual(raised.exception.args, ("invariant",))
        self.assertEqual(acceptance.fixed_failure_code(raised.exception), "invariant")
        self.assertEqual(acceptance.fixed_failure_code(acceptance.AcceptanceFailure("invoke-prompt-timeout")),
                         "invoke-prompt-timeout")
        cases = ((subprocess.TimeoutExpired("fixed", 1), "timeout"),
                 (json.JSONDecodeError("fixed", "", 0), "json"),
                 (OSError("unfixed detail"), "io"),
                 (RuntimeError("unfixed detail"), "unexpected"))
        for error, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(acceptance.fixed_failure_code(error), expected)
                self.assertIn(expected, acceptance.UNEXPECTED_FAILURE_CODES)


if __name__ == "__main__":
    unittest.main()
