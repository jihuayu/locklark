"""Independent negative oracles for the external RunCLI controller."""
import base64
import contextlib
import io
import json
import pathlib
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


if __name__ == "__main__":
    unittest.main()
