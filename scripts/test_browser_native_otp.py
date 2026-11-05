"""Independent oracle known-vector checks; outputs no private fixture material."""
import unittest
from browser_otp_hmac import codes
from browser_otp_privacy_acceptance import check_output


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
