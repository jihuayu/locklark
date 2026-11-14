"""Independent oracle known-vector checks; outputs no private fixture material."""
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from browser_otp_hmac import codes
from browser_otp_privacy_acceptance import (
    check_output,
    find_private_child_state,
    require_private_parent,
)


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



class BrowserOTPPrivateState(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="ll-otp-state-")).resolve()
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)

    def parent(self, name="parent", mode=0o700):
        path = self.root / name
        path.mkdir(mode=mode)
        os.chmod(path, mode)
        return path

    def child(self, parent, name="locklark-browser-acceptance-one", mode=0o700):
        child = parent / name
        child.mkdir(mode=mode)
        os.chmod(child, mode)
        vault = child / "vault"
        vault.mkdir(mode=0o700)
        fixture = vault / "fixture.json"
        fixture.write_text("{}", encoding="utf-8")
        os.chmod(fixture, 0o600)
        return child

    def test_owned_parent_and_unique_state_pass(self):
        parent = self.parent()
        child = self.child(parent)
        self.assertEqual(find_private_child_state(parent), child)

    def test_parent_symlink_foreign_mode_and_wrong_parent_refuse(self):
        parent = self.parent()
        link = self.root / "parent-link"
        link.symlink_to(parent, target_is_directory=True)
        with self.assertRaises(ValueError):
            require_private_parent(link)
        os.chmod(parent, 0o755)
        with self.assertRaises(ValueError):
            require_private_parent(parent)
        good = self.parent("good")
        other = self.parent("other")
        self.child(other)
        with self.assertRaises(ValueError):
            find_private_child_state(good)

    def test_state_symlink_foreign_mode_multiple_and_unrelated_refuse(self):
        parent = self.parent()
        link = parent / "locklark-browser-acceptance-link"
        link.symlink_to(parent, target_is_directory=True)
        with self.assertRaises(ValueError):
            find_private_child_state(parent)

        parent2 = self.parent("parent2")
        bad_mode = self.child(parent2, "locklark-browser-acceptance-mode", 0o755)
        with self.assertRaises(ValueError):
            find_private_child_state(parent2)
        self.assertFalse(bad_mode.is_symlink())

        parent3 = self.parent("parent3")
        self.child(parent3, "locklark-browser-acceptance-a")
        self.child(parent3, "locklark-browser-acceptance-b")
        with self.assertRaises(ValueError):
            find_private_child_state(parent3)

        parent4 = self.parent("parent4")
        (parent4 / "unrelated").mkdir()
        with self.assertRaises(ValueError):
            find_private_child_state(parent4)

    def test_vault_and_fixture_links_modes_refuse(self):
        parent = self.parent()
        child = self.child(parent)
        vault = child / "vault"
        fixture = vault / "fixture.json"
        fixture.chmod(0o644)
        with self.assertRaises(ValueError):
            find_private_child_state(parent)
        fixture.chmod(0o600)

        target = child / "fixture-target"
        target.write_text("{}", encoding="utf-8")
        os.chmod(target, 0o600)
        fixture.unlink()
        fixture.symlink_to(target)
        with self.assertRaises(ValueError):
            find_private_child_state(parent)

        fixture.unlink()
        target.unlink()
        vault.rmdir()
        outside = parent / "vault-target"
        outside.mkdir(mode=0o700)
        vault.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(ValueError):
            find_private_child_state(parent)


if __name__ == "__main__":
    unittest.main()
