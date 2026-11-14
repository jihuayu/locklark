"""Independent oracle known-vector checks; outputs no private fixture material."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import unittest
from browser_otp_hmac import codes
from browser_otp_privacy_acceptance import check_output, read_handoff, validate_handoff


class BrowserOTPOracle(unittest.TestCase):
    def test_rfc_vector_and_leading_zero_width(self):
        seed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        self.assertTrue(codes(dict(seed=seed, digits=8, first=1, last=1)) == ["94287082"])
        self.assertTrue(codes(dict(seed=seed, digits=6, first=1, last=1)) == ["287082"])
        self.assertTrue(all(len(value) == 8 for value in codes(dict(seed=seed, digits=8, first=2, last=4))))

    def test_oracle_budget_and_digits(self):
        for digits, first, last in [(7, 0, 0), (6, 0, 4), (6, -1, 0), (6, 2, 1)]:
            with self.assertRaises(ValueError):
                codes(dict(seed="GEZDGNBVGY3TQOJQ", digits=digits, first=first, last=last))


class BrowserOTPPrivacy(unittest.TestCase):
    def setUp(self):
        self.fixture = {name: "synthetic-" + name for name in (
            "Password", "Secret", "Username", "Value", "SaveUsername", "SaveValue", "UpdateUsername", "UpdateValue",
            "RejectedUsername", "RejectedValue", "OTPSeed", "OTPURI")}
        self.fixture["OTPSeed"] = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

    def test_output_codes_are_tokens_and_factors_always_checked(self):
        for value in (b'code="94287082"', b'code=287082', b'synthetic-Password'):
            with self.assertRaises(ValueError): check_output(value, self.fixture, 30, 31)
        check_output(b'id=a94287082b; nonce=a287082b; fixed PASS', self.fixture, 30, 31)

    def test_clock_bound_is_a_hard_failure(self):
        for first, last in ((40, 30), (0, 601)):
            with self.assertRaises(ValueError): check_output(b'fixed output', self.fixture, first, last)


if __name__ == "__main__":
    unittest.main()


class BrowserOTPPrivacyHandoff(unittest.TestCase):
    def make_state(self):
        suffix = str(os.getpid()) + str(time.time_ns())
        state = Path("/tmp") / ("locklark-browser-acceptance-" + suffix)
        state.mkdir(mode=0o700)
        self.addCleanup(shutil.rmtree, state, ignore_errors=True)
        return state

    def test_real_node_private_pipe_handoff(self):
        state = self.make_state()
        helper = Path(__file__).resolve().parent / "browser_native_setup.mjs"
        read_fd, write_fd = os.pipe()
        environment = dict(
            os.environ,
            LOCKLARK_TEST_DIAGNOSTIC_FD=str(write_fd),
            LOCKLARK_TEST_HANDOFF_STATE=str(state),
        )
        script = (
            "import { writeDiagnosticHandoff } from "
            + json.dumps(helper.as_uri())
            + "; writeDiagnosticHandoff(process.env.LOCKLARK_TEST_HANDOFF_STATE);"
        )
        try:
            process = subprocess.Popen(
                ["node", "--input-type=module", "-e", script],
                env=environment,
                pass_fds=(write_fd,),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            os.close(write_fd)
            write_fd = None
            stdout, stderr = process.communicate(timeout=20)
            self.assertEqual(process.returncode, 0, stderr)
            self.assertEqual(stdout, "")
            self.assertEqual(stderr, "")
            payload = read_handoff(read_fd)
            self.assertEqual(validate_handoff(payload), state)
        finally:
            if write_fd is not None:
                os.close(write_fd)
            os.close(read_fd)

    def test_missing_malformed_foreign_and_oversize_handoff_rejected(self):
        for raw in (
            b"",
            b"no-newline",
            b"/tmp/locklark-browser-acceptance-123\n\n",
            b"/var/tmp/locklark-browser-acceptance-123\n",
            b"/tmp/locklark-browser-acceptance-123/../../tmp/foreign\n",
            b"x" * 4097,
        ):
            with self.assertRaises(ValueError):
                validate_handoff(raw)

    def test_non_owned_symlink_and_non_private_state_rejected(self):
        state = self.make_state()
        payload = (str(state) + "\n").encode()
        self.assertEqual(validate_handoff(payload), state)
        with self.assertRaises(ValueError):
            validate_handoff(payload, expected_uid=os.getuid() + 1)

        link = Path("/tmp") / (
            "locklark-browser-acceptance-" + str(os.getpid()) + str(time.time_ns())
        )
        os.symlink(state, link)
        self.addCleanup(link.unlink)
        with self.assertRaises(ValueError):
            validate_handoff((str(link) + "\n").encode())

        os.chmod(state, 0o755)
        with self.assertRaises(ValueError):
            validate_handoff(payload)
