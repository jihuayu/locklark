"""Pure controller/oracle tests, not Windows console execution evidence."""
import base64
import contextlib
import io
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import run_cli_windows_acceptance as acceptance


class WindowsCLIOracleTests(unittest.TestCase):
    def test_approved_diagnosis_returns_only_fixed_subchecks(self):
        result={"exit_code":95,"timed_out":False,"console_available":True,"console_mode_before":7,"console_mode_after":7}
        error=b"LOCKLARK_WINDOWS_CHILD_ROOT=REFUSED code=known-folder-parent\nowned Windows CLI fixture failed at artifact-security\nPrivateSyntheticValue"
        observed=acceptance.approved_diagnosis(result,{},b"",error,"missing")
        self.assertEqual(observed["cli_exit_code"],95)
        self.assertEqual(observed["child_record"],"missing")
        self.assertTrue(observed["child_marker"])
        self.assertFalse(observed["artifact_private_policy"])
        self.assertEqual(observed["artifact_policy_reason"],"known-folder-parent")
        self.assertEqual(observed["fixture_phase"],"artifact-security")
        self.assertTrue(observed["console_mode_restored"])
        self.assertNotIn("PrivateSyntheticValue",str(observed))
        poisoned=acceptance.approved_diagnosis({"exit_code":"PrivateSyntheticValue"},{"token_matches":"PrivateSyntheticValue"},b"",b"", "invalid")
        self.assertIsNone(poisoned["cli_exit_code"])
        self.assertIsNone(poisoned["token_matches"])
        self.assertNotIn("PrivateSyntheticValue",str(poisoned))
    def test_no_console_requires_observed_absence_not_only_an_exit_code(self):
        result={"exit_code":1,"timed_out":False,"parent_console_absent":True}
        error=b"personal run-cli requires an interactive terminal with a controlling console for hidden input and prompts\n"
        acceptance.verify_no_console(result,b"",error,False)
        for key,value in (("parent_console_absent",False),("timed_out",True),("exit_code",0)):
            with self.subTest(key=key),self.assertRaises(acceptance.AcceptanceFailure):
                acceptance.verify_no_console({**result,key:value},b"",error,False)
        with self.assertRaises(acceptance.AcceptanceFailure):
            acceptance.verify_no_console(result,b"",error,True)
        for prompt in ("主密码:","Secret Key:","输入 RUN 确认本次可信命令披露:"):
            with self.subTest(prompt=prompt),self.assertRaises(acceptance.AcceptanceFailure):
                acceptance.verify_no_console(result,b"",error+prompt.encode(),False)

    def test_full_pipe_exit_and_console_oracle_rejects_partial_results(self):
        result = {"exit_code":23,"timed_out":False,"console_available":True,"console_mode_before":7,"console_mode_after":7}
        child = {"token_matches":True,"stdin_matches":True,"stdio_are_pipes":True,"only_allowed_environment":True,"console_mode":7,
                 "stdin_pipe":True,"stdout_pipe":True,"stderr_pipe":True,"artifact_private_policy":True}
        out, err = b"owned Windows child stdout\n", b"owned Windows child stderr\n"
        acceptance.verify_approved(result,child,out,err)
        for field,value in (("exit_code",0),("exit_code",23.0),("timed_out",True),("console_available",False),("console_mode_after",6)):
            with self.subTest(field=field), self.assertRaises(acceptance.AcceptanceFailure):
                acceptance.verify_approved({**result,field:value},child,out,err)
        for field in ("console_mode_before","console_mode_after","child_mode"):
            wrong={**result,"console_mode_before":1,"console_mode_after":1}
            wrong_child={**child,"console_mode":1}
            if field=="child_mode": wrong_child["console_mode"]=True
            else: wrong[field]=True
            with self.subTest(field=field),self.assertRaises(acceptance.AcceptanceFailure):
                acceptance.verify_approved(wrong,wrong_child,out,err)
        for field in ("token_matches","stdin_matches","stdio_are_pipes","only_allowed_environment",
                      "stdin_pipe","stdout_pipe","stderr_pipe","artifact_private_policy"):
            with self.subTest(field=field), self.assertRaises(acceptance.AcceptanceFailure):
                acceptance.verify_approved(result,{**child,field:False},out,err)
        with self.assertRaises(acceptance.AcceptanceFailure):
            acceptance.verify_approved(result,child,out+b'{"status":"process-exited"}',err)
        with self.assertRaises(acceptance.AcceptanceFailure):
            acceptance.verify_approved(result,child,out,err+b"approval prompt")

    def test_raw_encoded_and_ANSI_interleaved_echoes_fail(self):
        secret="OwnedSyntheticFactor556677"
        for raw in (secret.encode(),base64.b64encode(secret.encode()),secret.encode().hex().encode(),
                    (secret[:8]+"\x1b[31m"+secret[8:]).encode()):
            with self.subTest(size=len(raw)), self.assertRaises(acceptance.AcceptanceFailure):
                acceptance.scan(raw,[secret])
        acceptance.scan(b"owned fixed markers only",[secret])
        self.assertEqual(acceptance.fixture_phase(b"owned Windows CLI fixture failed at owned-job\n"),"owned-job")
        self.assertEqual(acceptance.fixture_phase(b"owned Windows CLI fixture failed at PrivateSyntheticFactor"),"unknown")

    def test_failed_command_preserves_partial_output_for_canary_scan(self):
        secret="OwnedSyntheticFactor556677"
        with tempfile.TemporaryDirectory() as root:
            runner=acceptance.Acceptance.__new__(acceptance.Acceptance)
            runner.fixture="owned-fixture.exe";runner.root=Path(root)
            runner.values=[secret]
            with mock.patch.object(acceptance.subprocess,"run",side_effect=subprocess.TimeoutExpired(
                    ["private-argument"],1,output=secret.encode())), self.assertRaises(acceptance.AcceptanceFailure):
                runner.command(["launch"],"failed")
            with self.assertRaises(acceptance.AcceptanceFailure): runner.scan()

    def test_invalid_target_is_a_fixed_failure_without_starting_any_child(self):
        with mock.patch.object(acceptance.subprocess,"run") as command, contextlib.redirect_stdout(io.StringIO()) as output:
            result=acceptance.main(["--cli","unused","--fixture-bin","unused"])
        self.assertEqual(result,1)
        command.assert_not_called()
        self.assertEqual(output.getvalue(),"FAIL: Windows RunCLI acceptance at prerequisites\n")


if __name__=="__main__": unittest.main()
