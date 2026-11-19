"""Security assertions in the external quick-search oracle, without app hooks."""
import ast
import inspect
import pathlib
import shutil
import subprocess
import tempfile
import time
import unittest
import desktop_quick_search_acceptance as quick_search
from desktop_quick_search_acceptance import disclosure_action, QuickSearchAcceptance
from desktop_native_acceptance import AcceptanceFailure
from desktop_quick_search_probe import exact_result_ids
from desktop_quick_search_x11 import ShortcutLauncher, ShortcutFailure, top_level_source
from unittest.mock import Mock, patch


class OracleTests(unittest.TestCase):
    def test_real_desktop_actions_and_other_disclosure_paths_are_counted(self):
        for action in ("item.desktop.show.password","item.desktop.copy.password","item.desktop.show.otp-code",
                       "item.desktop.copy.otp-code","item.reveal.password","item.browser.fill","item.browser.fill.otp-code",
                       "item.run.password","item.inject.password","item.invoke.github-pull","vault.export.kdbx"):
            self.assertTrue(disclosure_action(action))
        for action in ("item.search","item.list","item.list.all","item.add","item.edit.title",None):
            self.assertFalse(disclosure_action(action))

    def test_result_ids_must_be_complete_and_unique(self):
        self.assertTrue(exact_result_ids(["b","a"],["a","b"]))
        self.assertTrue(exact_result_ids([],[]))
        for seen in (["a","a"],["a"],["a","c"],["a","b","c"]):
            self.assertFalse(exact_result_ids(seen,["a","b"]))

    def test_field_display_uses_explicit_expected_keyword(self):
        tree=ast.parse(inspect.getsource(QuickSearchAcceptance))
        calls=[node for node in ast.walk(tree) if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute) and node.func.attr=="display"]
        self.assertTrue(calls)
        self.assertTrue(all(not call.args and any(keyword.arg=="expected" for keyword in call.keywords) for call in calls))

    def test_stale_wm_hint_is_absence_but_other_x_error_is_not(self):
        for errors,absence in (([(3,7)],True), ([(3,8)],False), ([(8,7)],False)):
            launcher=ShortcutLauncher.__new__(ShortcutLauncher)
            launcher.root=1;launcher.errors=[];launcher.error_events=[];launcher.ignored_stale_wm_hints=0
            def query(target,_name):
                if target==1:return 7
                launcher.error_events.extend(errors);launcher.errors.extend(code for code,_ in errors)
                raise ShortcutFailure()
            launcher.property_window=query
            if absence:
                self.assertFalse(launcher.window_manager_ready())
                self.assertEqual(launcher.errors,[])
            else:
                with self.assertRaises(ShortcutFailure):launcher.window_manager_ready()


class WindowManagerStartupTests(unittest.TestCase):
    class Clock:
        def __init__(self):self.now=0.0;self.sleeps=[]
        def monotonic(self):return self.now
        def sleep(self,seconds):self.sleeps.append(seconds);self.now+=max(seconds,.02)

    class Child:
        def __init__(self,polls):self.polls=list(polls);self.calls=0
        def poll(self):
            self.calls+=1
            return self.polls.pop(0) if len(self.polls)>1 else self.polls[0]

    class Launcher:
        def __init__(self,ready):self.ready=list(ready);self.calls=0
        def window_manager_ready(self):
            self.calls+=1
            value=self.ready.pop(0) if len(self.ready)>1 else self.ready[0]
            if isinstance(value,Exception):raise value
            return value

    def acceptance(self):
        q=QuickSearchAcceptance.__new__(QuickSearchAcceptance)
        q.env={};q.state=pathlib.Path(tempfile.mkdtemp(prefix="quick-wm-test-"))
        self.addCleanup(shutil.rmtree,q.state,True)
        q.launcher=None;q.wm=None;q.wm_ready=False;q.reason="acceptance";q.stage="setup"
        q.log=Mock()
        q.wm_startup={"state":"discovery","mode":"none","elapsed_ms":0,
                      "probes":0,"launches":0,"deadline_ms":5000}
        return q

    def prepare(self,q,launcher,child=None,run_error=None,error=AcceptanceFailure):
        clock=self.Clock()
        fake=Mock()
        fake.CalledProcessError=subprocess.CalledProcessError
        if run_error is not None:fake.run.side_effect=run_error
        if child is not None:fake.Popen.return_value=child
        with patch.object(quick_search,"ShortcutLauncher",return_value=launcher), \
             patch.object(quick_search,"subprocess",fake), \
             patch.object(quick_search,"time",clock):
            with self.assertRaises(error):q.prepare_window_manager()
        return fake,clock

    def test_owned_child_exit_is_distinct_from_a_live_child_at_the_deadline(self):
        q=self.acceptance()
        fake,clock=self.prepare(q,self.Launcher([False]),self.Child([1]))
        self.assertEqual(q.reason,"window-manager-unavailable")
        self.assertEqual(q.wm_startup["state"],"exited")
        self.assertEqual(q.wm_startup["mode"],"owned")
        self.assertEqual(q.wm_startup["launches"],1)
        self.assertEqual(q.wm_startup["probes"],2)
        self.assertEqual(q.wm_startup["elapsed_ms"],0)
        self.assertEqual(fake.Popen.call_count,1)
        self.assertEqual(fake.run.call_count,1)

        q=self.acceptance()
        fake,clock=self.prepare(q,self.Launcher([False]),self.Child([None]))
        self.assertEqual(q.reason,"window-manager-unavailable")
        self.assertEqual(q.wm_startup["state"],"deadline")
        self.assertEqual(q.wm_startup["mode"],"owned")
        self.assertEqual(q.wm_startup["launches"],1)
        self.assertEqual(q.wm_startup["elapsed_ms"],5000)
        self.assertGreaterEqual(q.wm_startup["probes"],2)
        self.assertLessEqual(q.wm_startup["probes"],252)
        self.assertEqual(fake.Popen.call_count,1)
        self.assertEqual(fake.run.call_count,1)

    def test_owned_readiness_keeps_its_full_window_after_a_slow_prelaunch(self):
        q=self.acceptance();clock=self.Clock()
        fake=Mock();fake.CalledProcessError=subprocess.CalledProcessError
        fake.Popen.return_value=self.Child([None])
        # Discovery and private-environment setup consume more than the whole
        # startup budget before the one owned spawn returns.
        def slow_prelaunch(*args,**kwargs):clock.now=5.25
        fake.run.side_effect=slow_prelaunch
        ready_at=[5.25+4.9]
        class TimedLauncher:
            def window_manager_ready(self):return clock.now>=ready_at[0]
        with patch.object(quick_search,"ShortcutLauncher",return_value=TimedLauncher()), \
             patch.object(quick_search,"subprocess",fake), \
             patch.object(quick_search,"time",clock):
            q.prepare_window_manager()
        self.assertTrue(q.wm_ready)
        self.assertEqual(q.wm_startup["state"],"ready")
        self.assertEqual(q.wm_startup["mode"],"owned")
        self.assertEqual(q.wm_startup["launches"],1)
        self.assertGreaterEqual(q.wm_startup["elapsed_ms"],4900)
        self.assertLess(q.wm_startup["elapsed_ms"],5000)
        self.assertGreaterEqual(q.wm_startup["probes"],200)
        self.assertEqual(fake.Popen.call_count,1)
        self.assertEqual(fake.run.call_count,1)

    def test_owned_deadline_is_five_seconds_after_spawn_not_after_prelaunch(self):
        q=self.acceptance();clock=self.Clock()
        fake=Mock();fake.CalledProcessError=subprocess.CalledProcessError
        fake.Popen.return_value=self.Child([None])
        def slow_prelaunch(*args,**kwargs):clock.now=5.25
        fake.run.side_effect=slow_prelaunch
        with patch.object(quick_search,"ShortcutLauncher",return_value=self.Launcher([False])), \
             patch.object(quick_search,"subprocess",fake), \
             patch.object(quick_search,"time",clock):
            with self.assertRaises(AcceptanceFailure):q.prepare_window_manager()
        self.assertEqual(q.wm_startup["state"],"deadline")
        self.assertEqual(q.wm_startup["mode"],"owned")
        self.assertEqual(q.wm_startup["elapsed_ms"],5000)
        self.assertGreaterEqual(clock.now,10.25)
        self.assertGreater(q.wm_startup["probes"],200)
        self.assertEqual(fake.Popen.call_count,1)
        self.assertEqual(fake.run.call_count,1)

    def test_valid_ewmh_is_the_only_ready_proof(self):
        q=self.acceptance()
        fake=Mock()
        with patch.object(quick_search,"ShortcutLauncher",return_value=self.Launcher([True])), \
             patch.object(quick_search,"subprocess",fake), \
             patch.object(quick_search,"time",self.Clock()):
            q.prepare_window_manager()
        self.assertTrue(q.wm_ready)
        self.assertEqual(q.wm_startup["state"],"ready")
        self.assertEqual(q.wm_startup["mode"],"pre-existing")
        self.assertEqual(q.wm_startup["launches"],0)
        fake.run.assert_not_called();fake.Popen.assert_not_called()

        q,fake,clock=self.acceptance_and_owned_ready()
        self.assertTrue(q.wm_ready)
        self.assertEqual(q.wm_startup["state"],"ready")
        self.assertEqual(q.wm_startup["mode"],"owned")
        self.assertEqual(q.wm_startup["launches"],1)
        self.assertEqual(fake.Popen.call_count,1)
        self.assertEqual(fake.run.call_count,1)

    def acceptance_and_owned_ready(self):
        q=self.acceptance();clock=self.Clock()
        fake=Mock();fake.CalledProcessError=subprocess.CalledProcessError
        fake.Popen.return_value=self.Child([None])
        with patch.object(quick_search,"ShortcutLauncher",return_value=self.Launcher([False,True])), \
             patch.object(quick_search,"subprocess",fake), \
             patch.object(quick_search,"time",clock):
            q.prepare_window_manager()
        return q,fake,clock

    def test_startup_probe_and_spawn_failures_keep_their_own_states(self):
        q=self.acceptance()
        fake,clock=self.prepare(q,self.Launcher([False,ShortcutFailure("x-protocol")]),
                                error=ShortcutFailure)
        self.assertEqual(q.reason,"window-manager-discovery")
        self.assertEqual(q.wm_startup["state"],"probe-failed")
        self.assertEqual(q.wm_startup["mode"],"owned")
        self.assertEqual(fake.Popen.call_count,1)

        q=self.acceptance()
        fake,clock=self.prepare(q,self.Launcher([False]),run_error=OSError("synthetic"),
                                error=OSError)
        self.assertEqual(q.reason,"window-manager-discovery")
        self.assertEqual(q.wm_startup["state"],"environment-failed")
        self.assertEqual(q.wm_startup["launches"],0)
        fake.Popen.assert_not_called()

        q=self.acceptance();clock=self.Clock()
        fake=Mock();fake.CalledProcessError=subprocess.CalledProcessError
        fake.Popen.side_effect=OSError("synthetic")
        with patch.object(quick_search,"ShortcutLauncher",return_value=self.Launcher([False])), \
             patch.object(quick_search,"subprocess",fake), \
             patch.object(quick_search,"time",clock):
            with self.assertRaises(OSError):q.prepare_window_manager()
        self.assertEqual(q.reason,"window-manager-discovery")
        self.assertEqual(q.wm_startup["state"],"spawn-failed")
        self.assertEqual(q.wm_startup["launches"],0)

    def test_startup_diagnostic_is_fixed_bounded_and_failure_only(self):
        q=self.acceptance()
        q.wm_startup={"state":"deadline","mode":"owned","elapsed_ms":99999,
                      "probes":999999,"launches":7,"deadline_ms":5000}
        self.assertEqual(q.startup_diagnostic(),
                         "Desktop quick search startup diagnostics: window_manager_state=deadline "
                         "window_manager_mode=owned window_manager_ready=false "
                         "window_manager_elapsed_ms=5000 window_manager_deadline_ms=5000 "
                         "window_manager_probes=10000 window_manager_launches=1")
        for unsafe in ("DISPLAY",":99","/tmp/","pid=","Traceback","synthetic","private-output"):
            self.assertNotIn(unsafe,q.startup_diagnostic())
        for state in ("discovery","ready","pending","unexpected"):
            q.wm_startup["state"]=state
            self.assertIsNone(q.startup_diagnostic())


class WindowSourceTests(unittest.TestCase):
    def test_raise_uses_the_owned_root_child_not_only_the_client(self):
        self.assertEqual(top_level_source({7:9,9:1}.get,7,1),9)
        self.assertEqual(top_level_source({7:1}.get,7,1),7)

    def test_broken_or_cyclic_source_chain_fails_before_any_input(self):
        for mapping in ({7:None},{7:9,9:7},{n:n+1 for n in range(7,25)}):
            with self.assertRaises(ShortcutFailure):top_level_source(mapping.get,7,1)


class ShortcutFailurePrivacy(unittest.TestCase):
    def test_failed_attempt_is_recorded_with_only_fixed_phase_and_public_flags(self):
        q=QuickSearchAcceptance.__new__(QuickSearchAcceptance)
        q.input=Mock(return_value={"window":7})
        q.launcher=Mock()
        q.launcher.last_attempt={"phase":"source-focus","foreign_frame_raised":True,"foreign_focus_established":False,
                                 "shortcut_batches":0,"private":"Synthetic-secret-only"}
        q.launcher.wake.side_effect=ShortcutFailure("source-focus")
        q.shortcut_observations=[]
        with self.assertRaises(AcceptanceFailure):q.wake()
        self.assertEqual(q.reason,"shortcut-source-focus")
        self.assertEqual(q.shortcut_observations,[{"phase":"source-focus","foreign_frame_raised":True,
                         "foreign_focus_established":False,"shortcut_batches":0}])
        q.launcher.wake.assert_called_once_with(7)


def controlled_acceptance(metadata):
    """Quick-search acceptance with a mocked AT-SPI probe and mocked wake."""
    q=QuickSearchAcceptance.__new__(QuickSearchAcceptance)
    q.output_lines=[]
    q.emit=lambda message:q.output_lines.append(message)
    q.input=Mock(return_value={"window":7})
    q.launcher=Mock()
    q.launcher.wake.return_value={"phase":"native-focus","foreign_frame_raised":True,"foreign_focus_established":True,
                                  "native_focus_after_shortcut":True,"shortcut_batches":1}
    q.shortcut_observations=[]
    q.last_metadata={}
    q.result_focus_elapsed_ms=0
    q.last_native_focus_after_shortcut=False
    q.reason="acceptance"
    q.stage=""
    q.completed=[]
    q.metadata=Mock(side_effect=metadata)
    q.displays_empty=Mock(return_value=True)
    return q


def keys_sent(q):
    actions=[action for call in q.input.call_args_list for action in (call.args[0] if call.args else call.kwargs.get("actions") or ())]
    return [action["key"] for action in actions if "key" in action]


class ResultFocusRestoration(unittest.TestCase):
    def test_delayed_focus_after_one_wake_is_polled_then_selected_once(self):
        calls={"n":0}
        def metadata(expected=(),target=""):
            calls["n"]+=1
            # Already focused before the wake; after the one real wake the
            # widget tree lags several frames before the row is restored.
            if calls["n"]<=2:return {"target_focused":True,"detail_target_matches":False}
            return {"target_focused":calls["n"]>7,"detail_target_matches":True}
        q=controlled_acceptance(metadata)
        q.tab_select(["a"],"a")
        self.assertEqual(q.launcher.wake.call_count,1)
        self.assertEqual(keys_sent(q),["Return"])
        self.assertGreaterEqual(calls["n"],8)
        self.assertLessEqual(q.result_focus_elapsed_ms,2000)

    def test_never_restored_focus_times_out_before_any_return(self):
        calls={"n":0}
        def metadata(expected=(),target=""):
            calls["n"]+=1
            return {"target_focused":calls["n"]<=2,"detail_target_matches":False}
        q=controlled_acceptance(metadata)
        started=time.monotonic()
        with self.assertRaises(AcceptanceFailure):q.tab_select(["a"],"a")
        self.assertLess(time.monotonic()-started,2.6)
        self.assertEqual(q.reason,"quick-result-focus")
        self.assertEqual(q.result_focus_elapsed_ms,2000)
        self.assertEqual(keys_sent(q),[])
        self.assertEqual(q.launcher.wake.call_count,1)

    def test_focus_lost_after_the_stable_gap_refuses_before_any_return(self):
        started=time.monotonic()
        def metadata(expected=(),target=""):
            return {"target_focused":time.monotonic()-started<0.1,"detail_target_matches":False}
        q=controlled_acceptance(metadata)
        with self.assertRaises(AcceptanceFailure):q.tab_select(["a"],"a")
        self.assertEqual(q.reason,"quick-result-focus-lost")
        self.assertEqual(keys_sent(q),[])
        self.assertEqual(q.launcher.wake.call_count,1)

    def test_successful_wake_leaves_no_stale_shortcut_reason(self):
        q=controlled_acceptance(lambda expected=(),target="":{"target_focused":True})
        q.wake()
        self.assertEqual(q.shortcut_observations,[{"phase":"native-focus","foreign_focus_established":True,
                         "foreign_frame_raised":True,"native_focus_after_shortcut":True,"shortcut_batches":1}])
        self.assertEqual(q.reason,"wake-complete")
        self.assertIs(q.last_native_focus_after_shortcut,True)

    def test_public_failure_diagnostics_are_fixed_and_carry_no_item_details(self):
        q=controlled_acceptance(lambda expected=(),target="":{"target_focused":False})
        q.last_metadata={"query_present":True,"query_focused":False,"target_focused":False,
                         "items":[{"id":"item-secret-id","title":"Synthetic secret title"}],
                         "events":[{"action":"item.desktop.show.password","item_id":"item-secret-id"}]}
        q.shortcut_observations=[{"phase":"native-focus","native_focus_after_shortcut":True,
                                  "foreign_focus_established":True}]
        q.result_focus_elapsed_ms=99999
        line=q.failure_diagnostic()
        self.assertEqual(line,"Desktop quick search public failure diagnostics: native_focus_after_shortcut=true "
                              "target_focused=false target_focus_elapsed_ms=2000")
        for secret in ("item-secret-id","Synthetic secret title","item.desktop.show.password","query_present"):
            self.assertNotIn(secret,line)

    def test_failure_checkpoints_never_exceed_the_bounded_elapsed(self):
        q=controlled_acceptance(lambda expected=(),target="":{"target_focused":False})
        q.result_focus_elapsed_ms=-5
        self.assertIn(" target_focus_elapsed_ms=0",q.failure_diagnostic())
        q.result_focus_elapsed_ms=1999
        self.assertIn(" target_focus_elapsed_ms=1999",q.failure_diagnostic())


if __name__=="__main__":unittest.main()
