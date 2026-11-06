import base64
import unittest
from test_emulator import scan_output, complete_pass, RuntimeFailure


class RuntimeWrapperTests(unittest.TestCase):
    def test_failure_or_partial_instrumentation_cannot_pass(self):
        passed = b"OK (1 test)\nINSTRUMENTATION_CODE: -1\n"
        self.assertTrue(complete_pass(0, passed))
        for code, raw in ((1, passed), (0,b"INSTRUMENTATION_CODE: -1"), (0,passed+b"FAILURES!!!"), (0,passed.replace(b"1 test",b"0 tests")), (0,passed+b"Process crashed")):
            self.assertFalse(complete_pass(code, raw))

    def test_even_failed_test_output_must_be_scanned(self):
        values = ["master-fixture", "account-fixture", "username-fixture", "password-fixture", "line one private\nline two private"]
        scan_output(b"fixed failure stage only", values)
        for leak in (values[0].encode(),base64.b64encode(values[1].encode()),values[2].encode().hex().encode(), b"line two private"):
            with self.assertRaises(RuntimeFailure): scan_output(b"FAILURES!!! "+leak,values)


if __name__ == "__main__": unittest.main()
