import json
import os
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
import device_credential_acceptance as auth
from device_credential_acceptance import credential_marker, focused_identity, validated_evidence, AcceptanceFailure, DeviceCredentialAcceptance


class DeviceCredentialHarnessTests(unittest.TestCase):
    def node(self, **values):
        return {"package":"com.android.systemui","enabled":"true","bounds":"[0,0][100,100]",**values}

    def test_unrelated_os_window_is_not_an_auth_prompt(self):
        self.assertFalse(credential_marker([self.node(text="Notifications")],"com.android.systemui"))
        self.assertFalse(credential_marker([self.node(**{"class":"android.widget.EditText","password":"true","resource-id":"com.android.settings:id/wifi_password","package":"com.android.settings"})],"com.android.settings"))
        self.assertFalse(credential_marker([self.node(**{"resource-id":"com.android.systemui:id/pinEntry"})],"org.locklark.android"))

    def test_real_credential_markers_are_required_and_enabled(self):
        pin=self.node(**{"resource-id":"com.android.systemui:id/pinEntry"})
        self.assertTrue(credential_marker([pin],"com.android.systemui"))
        self.assertFalse(credential_marker([{**pin,"enabled":"false"}],"com.android.systemui"))
        fallback=self.node(text="Use PIN")
        self.assertFalse(credential_marker([fallback],"com.android.systemui"))
        self.assertTrue(credential_marker([fallback,self.node(text="认证此设备以解封本地金库授权")],"com.android.systemui"))

    def test_api35_lockPassword_marker_stays_bound_to_OS(self):
        lock = self.node(**{"resource-id":"com.android.systemui:id/lockPassword","class":"com.android.internal.widget.ImeAwareEditText"})
        self.assertTrue(credential_marker([lock],"com.android.systemui"))
        self.assertFalse(credential_marker([{**lock,"package":"org.locklark.android"}],"org.locklark.android"))
        self.assertFalse(credential_marker([self.node(**{"package":"com.android.settings","resource-id":"com.android.settings:id/wifi_password","class":"android.widget.EditText","password":"true"})],"com.android.settings"))
        self.assertFalse(credential_marker([{**lock,"enabled":"false"}],"com.android.systemui"))

    def test_title_only_window_requires_system_uid_record(self):
        nodes=[self.node(**{"resource-id":"com.android.systemui:id/pinEntry"})]
        raw=b"mCurrentFocus=Window{abc u0 BiometricPrompt}\nWindow #0 Window{abc u0 BiometricPrompt}:\n mOwnerUid=1000\n"
        self.assertEqual(focused_identity(raw,nodes),"com.android.systemui")
        self.assertEqual(focused_identity(raw.replace(b"1000",b"10123"),nodes),"unknown")

    def test_disabled_queued_lock_page_does_not_refuse_prompt(self):
        queued = [self.node(package="org.locklark.android",text="打开本地金库",**{"class":"android.widget.Button","enabled":"false"})]
        prompt = [self.node(**{"resource-id":"com.android.systemui:id/pinEntry"})]
        runner = DeviceCredentialAcceptance.__new__(DeviceCredentialAcceptance)
        runner.args = SimpleNamespace(timeout=1)
        runner.stage = "quick-prompt"
        frames = iter([queued,prompt])
        runner.snapshot = lambda:next(frames)
        runner.focused_package = lambda nodes: "org.locklark.android" if nodes is queued else "com.android.systemui"
        observed=[]
        runner.observe_lifecycle = lambda nodes,package:observed.append((nodes,package))
        self.assertEqual(runner.os_prompt()[1],"com.android.systemui")
        self.assertEqual(observed,[(prompt,"com.android.systemui")])

    def test_timeout_after_PIN_attempt_still_cleans_only_verified_candidate(self):
        runner = DeviceCredentialAcceptance.__new__(DeviceCredentialAcceptance)
        runner.pin_attempted=True;runner.pin_owned=False;runner.pin="12345678"
        calls=[]
        runner.shell=lambda *args,**kwargs:calls.append(args) or SimpleNamespace(returncode=0)
        runner.cleanup_pin()
        self.assertIn(("locksettings","clear","--old","12345678"),calls)
        self.assertFalse(runner.pin_attempted)

    def test_locksettings_classification_never_includes_remote_text(self):
        cases = [
            (b"The device does not support lock screen - ignoring the command.", b"", "unsupported-secure-lock-screen"),
            (b"Old password 'synthetic-private-value' didn't match", b"", "credential-mismatch"),
            (b"Request throttled", b"", "credential-throttled"),
            (b"", b"java.lang.SecurityException: synthetic-private-value", "security-exception"),
            (b"", b"java.lang.IllegalStateException: synthetic-private-value", "illegal-state"),
            (b"synthetic-private-value", b"", "command-failed"),
        ]
        for stdout, stderr, expected in cases:
            with self.subTest(expected=expected):
                status = auth.locksettings_status(SimpleNamespace(returncode=255, stdout=stdout, stderr=stderr))
                self.assertEqual(status, {"exit_code":255,"classification":expected})
                self.assertNotIn("synthetic-private-value", json.dumps(status))
        self.assertEqual(auth.locksettings_status(SimpleNamespace(returncode=0, stdout=b"", stderr=b"")),
                         {"exit_code":0,"classification":"success"})

    def pin_runner(self, results, feature=True):
        runner = DeviceCredentialAcceptance.__new__(DeviceCredentialAcceptance)
        runner.pin_attempted=False; runner.pin_owned=False; runner.pin="12345678"
        runner.locksettings_diagnostic={}; runner.secure_lock_screen=None
        calls=[]
        def shell(*args,**kwargs):
            calls.append((runner.stage,args,kwargs))
            if args == ("pm","list","features"):
                return SimpleNamespace(returncode=0,stdout=b"feature:android.software.secure_lock_screen\n" if feature else b"",stderr=b"")
            return results.pop(0)
        runner.shell=shell
        return runner,calls

    def test_PIN_precondition_has_no_empty_remote_argument_and_set_has_distinct_stage(self):
        ok=SimpleNamespace(returncode=0,stdout=b"",stderr=b"")
        runner,calls=self.pin_runner([ok,ok])
        runner.provision_pin()
        self.assertEqual([(stage,args) for stage,args,_ in calls], [
            ("pin-capabilities",("pm","list","features")),
            ("pin-empty-precondition",("locksettings","verify")),
            ("pin-set",("locksettings","set-pin","12345678"))])
        self.assertTrue(runner.pin_attempted and runner.pin_owned)

    def test_unsupported_empty_precondition_never_attempts_PIN_change(self):
        unsupported=SimpleNamespace(returncode=255,stdout=b"",stderr=b"The device does not support lock screen - ignoring the command.")
        runner,calls=self.pin_runner([unsupported],feature=False)
        with self.assertRaises(AcceptanceFailure): runner.provision_pin()
        self.assertEqual(runner.stage,"pin-empty-precondition")
        self.assertFalse(runner.pin_attempted or runner.pin_owned or runner.secure_lock_screen)
        self.assertEqual(runner.locksettings_diagnostic,{"operation":"verify-empty","exit_code":255,"classification":"unsupported-secure-lock-screen"})
        self.assertFalse(any(args[:2]==("locksettings","set-pin") for _,args,_ in calls))

    def test_successful_verify_without_advertised_secure_lock_screen_never_mutates(self):
        ok=SimpleNamespace(returncode=0,stdout=b"",stderr=b"")
        runner,calls=self.pin_runner([ok,ok],feature=False)
        with self.assertRaises(AcceptanceFailure): runner.provision_pin()
        self.assertEqual(runner.stage,"pin-empty-precondition")
        self.assertFalse(runner.pin_attempted or runner.pin_owned)
        self.assertFalse(any(args[:2]==("locksettings","set-pin") for _,args,_ in calls))

    def test_failed_PIN_set_stays_owned_attempt_for_exact_cleanup(self):
        ok=SimpleNamespace(returncode=0,stdout=b"",stderr=b"")
        failed=SimpleNamespace(returncode=255,stdout=b"",stderr=b"java.lang.SecurityException: synthetic-private-value")
        runner,_=self.pin_runner([ok,failed])
        with self.assertRaises(AcceptanceFailure): runner.provision_pin()
        self.assertEqual(runner.stage,"pin-set")
        self.assertTrue(runner.pin_attempted)
        self.assertFalse(runner.pin_owned)
        self.assertEqual(runner.locksettings_diagnostic["classification"],"security-exception")

    def test_unknown_credential_is_never_cleared(self):
        runner = DeviceCredentialAcceptance.__new__(DeviceCredentialAcceptance)
        runner.pin_attempted=True;runner.pin_owned=False;runner.pin="12345678"
        calls=[]
        def shell(*args,**kwargs):
            calls.append(args)
            return SimpleNamespace(returncode=1 if args[0]=="locksettings" else 0)
        runner.shell=shell
        with self.assertRaises(AcceptanceFailure):runner.cleanup_pin()
        self.assertFalse(any(args[:2]==("locksettings","clear") for args in calls))

    def fixture(self, root):
        run=root/"android-host-ui-owned";run.mkdir(mode=0o700)
        key="LL1-"+"A"*26
        fixture={"master":"MasterFixture","key":key,"items":[{"id":"a"*32,"revision":"b"*64,"title":"HostFirst","password":"FirstPassword"},{"id":"c"*32,"revision":"d"*64,"title":"HostSecond","password":"SecondPassword"}]}
        for name,value in (("result.json",{"success":True,"stage":"complete","checks":["full_controller_and_logcat_outputs_contain_no_secret_canaries"]}),
                           ("expected-private.json",fixture),("canaries.json",["MasterFixture",key,"FirstPassword","SecondPassword"])):
            path=run/name;path.write_text(json.dumps(value));path.chmod(0o600)
        return run

    def test_evidence_is_exactly_one_private_completed_run(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);run=self.fixture(root)
            self.assertEqual(validated_evidence(root)[0],run)
            (root/"android-host-ui-other").mkdir(mode=0o700)
            with self.assertRaises(AcceptanceFailure):validated_evidence(root)

    def test_incomplete_or_public_fixture_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);run=self.fixture(root)
            (run/"expected-private.json").chmod(0o644)
            with self.assertRaises(AcceptanceFailure):validated_evidence(root)
            (run/"expected-private.json").chmod(0o600)
            (run/"result.json").write_text(json.dumps({"success":False,"stage":"create"}))
            with self.assertRaises(AcceptanceFailure):validated_evidence(root)


if __name__=="__main__":unittest.main()
