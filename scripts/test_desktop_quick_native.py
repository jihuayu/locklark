"""Security assertions in the external quick-search oracle, without app hooks."""
import ast
import inspect
import time
import unittest
from desktop_quick_search_acceptance import disclosure_action, QuickSearchAcceptance
from desktop_native_acceptance import AcceptanceFailure
from desktop_quick_search_probe import exact_result_ids
from desktop_quick_search_x11 import ShortcutLauncher, ShortcutFailure, top_level_source
from unittest.mock import Mock


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
