"""Security assertions in the external quick-search oracle, without app hooks."""
import ast
import inspect
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


if __name__=="__main__":unittest.main()
