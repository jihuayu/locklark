"""Real Linux quick-search UI acceptance. Values remain in private owner pipes."""
import json
import os
import pathlib
import sys
import subprocess
import time
import select

from desktop_native_acceptance import Acceptance, AcceptanceFailure, require
from desktop_quick_search_x11 import ShortcutLauncher, ShortcutFailure, safe_shortcut_attempt, SHORTCUT_REASONS
from desktop_quick_search_probe import QuickMetadataReader
from browser_native_x11 import failure_reason as native_reason


def disclosure_action(action):
    return (isinstance(action,str) and
            (action.startswith(("item.reveal.","item.desktop.show.","item.desktop.copy.","item.browser.fill", "item.run.","item.inject."))
             or action in ("item.invoke.github-pull","vault.export.kdbx")))


class QuickSearchAcceptance(Acceptance):
    RESULT_FOCUS_TIMEOUT=2.0

    def __init__(self):
        super().__init__()
        self.launcher=None
        self.shortcut_observations=[]
        self.wm=None
        self.wm_ready=False
        self.completed=[]
        self.reader=None
        self.last_metadata={}
        self.result_focus_elapsed_ms=0
        self.last_native_focus_after_shortcut=False
        self.barriers=[]

    def phase(self,value):
        self.stage=value
        self.reason="acceptance"
        self.emit("Desktop quick search stage: "+value)

    def wake(self):
        xid=self.input(inspect=True)["window"]
        try:result=self.launcher.wake(xid)
        except ShortcutFailure as error:
            self.shortcut_observations.append(safe_shortcut_attempt(getattr(self.launcher,"last_attempt",{})))
            self.last_native_focus_after_shortcut=False
            self.reason="shortcut-"+(error.reason if error.reason in SHORTCUT_REASONS else "unexpected")
            raise AcceptanceFailure() from None
        observation=safe_shortcut_attempt(result)
        self.shortcut_observations.append(observation)
        self.last_native_focus_after_shortcut=observation.get("native_focus_after_shortcut") is True
        self.reason="global-shortcut-focus"
        require(result["foreign_focus_established"] and result["native_focus_after_shortcut"])
        # The shortcut itself passed; drop its reason so a later failure is not
        # attributed to a wake that already succeeded.
        self.reason="wake-complete"

    def prepare_window_manager(self):
        self.reason="window-manager-discovery"
        self.launcher=ShortcutLauncher()
        if self.launcher.window_manager_ready():self.wm_ready=True;return
        wm_env=dict(self.env)
        for variable,folder in (("XDG_CONFIG_HOME","wm-config"),("XDG_CACHE_HOME","wm-cache"),("XDG_DATA_HOME","wm-data")):
            target=self.state/folder;target.mkdir(mode=0o700);wm_env[variable]=str(target)
        subprocess.run(["dbus-update-activation-environment","XDG_CONFIG_HOME","XDG_CACHE_HOME","XDG_DATA_HOME"],env=wm_env,check=True,stdout=self.log,stderr=self.log)
        self.wm=subprocess.Popen(["xfwm4","--compositor=off","--vblank=off","--sm-client-disable"],env=wm_env,stdout=self.log,stderr=self.log)
        deadline=time.monotonic()+5
        while time.monotonic()<deadline:
            if self.launcher.window_manager_ready():self.wm_ready=True;return
            if self.wm.poll() is not None:break
            time.sleep(.02)
        self.reason="window-manager-unavailable";raise AcceptanceFailure()

    def metadata(self,expected=(),target=""):
        try:
            if self.reader is None:self.reader=QuickMetadataReader(self.app.pid)
            self.last_metadata=self.reader.inspect(expected,target)
            return self.last_metadata
        except Exception as error:
            self.reason="quick-metadata-"+native_reason(error)
            raise AcceptanceFailure() from None

    @staticmethod
    def active_rows(snapshot,query="Daily"):
        return [{"id":item["id"],"title":item["title"]} for item in snapshot["items"]
                if item["state"]=="active" and query.casefold() in item["title"].casefold()]

    @staticmethod
    def disclosures(snapshot):
        return [event for event in snapshot["events"] if disclosure_action(event["action"])]

    def panel_ready(self):
        self.reason="quick-panel-unavailable"
        self.eventually(lambda:self.metadata()["query_present"])
        controls=self.controls()
        require(controls["关闭快捷搜索"]["present"])
        require(not controls["保存登录"]["present"] and not controls["显示密码"]["present"])

    def enter_query(self,value,expected,autofocused=False):
        if not autofocused:self.fill("快捷搜索标题",value)
        else:self.input([{"text":value}])
        self.input([{"key":"Return"}])
        self.eventually(lambda:self.controls()["搜索活动登录"]["enabled"] and
                        self.metadata(expected)["result_count"]==len(expected))
        require(self.metadata(expected)["all_results_exact"])

    def await_result_focus(self,expected,target):
        # A source wake only asks for query focus. The native window can be
        # focused before the widget tree restores the selected row, so the
        # restored result focus is polled for a bounded window before it is
        # asserted; no extra key, click or wake is sent while polling.
        self.reason="quick-result-focus"
        started=time.monotonic()
        deadline=started+self.RESULT_FOCUS_TIMEOUT
        focused=False
        while True:
            if self.metadata(expected,target)["target_focused"]:focused=True;break
            if time.monotonic()>=deadline:break
            time.sleep(.05)
        self.result_focus_elapsed_ms=min(int((time.monotonic()-started)*1000),int(self.RESULT_FOCUS_TIMEOUT*1000))
        require(focused)

    def failure_diagnostic(self):
        # Fixed public booleans plus a bounded elapsed value only: never ids,
        # titles, focus factors, raw errors or full metadata.
        latest=self.shortcut_observations[-1] if self.shortcut_observations else {}
        native=latest.get("native_focus_after_shortcut")
        if type(native) is not bool:native=self.last_native_focus_after_shortcut is True
        elapsed=min(max(int(self.result_focus_elapsed_ms),0),int(self.RESULT_FOCUS_TIMEOUT*1000))
        return ("Desktop quick search public failure diagnostics: "
                "native_focus_after_shortcut="+("true" if native else "false")+
                " target_focused="+("true" if self.last_metadata.get("target_focused") is True else "false")+
                " target_focus_elapsed_ms="+str(elapsed))

    def tab_select(self,expected,target):
        self.phase("keyboard-select-stable-id")
        for _ in range(16):
            if self.metadata(expected,target)["target_focused"]:break
            self.input([{"key":"Tab"}])
        require(self.metadata(expected,target)["target_focused"])
        # Another real wake must preserve the focused result and list rather
        # than requesting query focus again on every frame/open callback.
        self.wake()
        self.await_result_focus(expected,target)
        # Restored focus must also survive the settle window; losing it is a
        # hard failure and never a reason to press Tab again.
        self.reason="quick-result-focus-lost"
        time.sleep(.2)
        require(self.metadata(expected,target)["target_focused"])
        self.input([{"key":"Return"}])
        self.wait("显示密码")
        require(self.metadata(target=target)["detail_target_matches"])
        require(self.displays_empty())

    def hold_database(self):
        child=subprocess.Popen([str(self.fixture_binary),"-fixture",str(self.fixture_path),"-hold-readonly"],
                               env=self.env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=self.log)
        self.barriers.append(child)
        require(bool(select.select([child.stdout],[],[],5)[0]))
        require(json.loads(child.stdout.readline()).get("ready") is True)
        return child

    def release_database(self,child):
        child.stdin.close()
        try:require(child.wait(timeout=5)==0)
        except subprocess.TimeoutExpired:self.reason="readonly-barrier-timeout";raise AcceptanceFailure() from None
        self.barriers.remove(child)

    def scenarios(self):
        self.phase("open-from-foreign-window")
        before=self.observe()
        self.wake();self.panel_ready()
        require(self.metadata()["query_focused"] and self.metadata()["result_count"]==0)
        after=self.observe();self.same_items(before,after)
        require(len(before["events"])==len(after["events"]) and self.displays_empty())
        self.assert_independent_clipboard("Later independent synthetic clipboard owner")
        self.completed.append("one real global shortcut opens without automatic query/disclosure")

        self.phase("query-enter-active-metadata")
        expected=self.active_rows(after)
        self.enter_query("Daily",expected,autofocused=True)
        searched=self.observe();self.same_items(after,searched)
        require(len(self.events(searched,"item.search"))==len(self.events(after,"item.search"))+1)
        require(len(self.disclosures(searched))==len(self.disclosures(after)))
        target=self.target(searched,"Daily OTP login")
        self.tab_select(expected,target["id"])
        selected=self.observe();self.same_items(searched,selected)
        require(len(self.disclosures(selected))==len(self.disclosures(searched)))
        self.completed.append("Enter active-only ID metadata; Tab/Enter selection; repeated wake preserves focus")

        self.phase("explicit-show-and-copy")
        self.click("显示密码")
        self.eventually(lambda:self.display(expected=[self.fixture["Value"]])["matches"]==[True])
        shown=self.observe()
        reveal=self.events(shown,"item.desktop.show.password")
        require(len(reveal)==len(self.events(selected,"item.desktop.show.password"))+1 and reveal[-1]["item_id"]==target["id"])
        self.click("复制密码")
        self.eventually(lambda:self.clipboard([self.fixture["Value"]])["matches"]==[True])
        copied=self.observe();reveal=self.events(copied,"item.desktop.copy.password")
        require(len(reveal)==len(self.events(shown,"item.desktop.copy.password"))+1 and reveal[-1]["item_id"]==target["id"])
        self.wake();self.panel_ready()
        require(self.displays_empty() and self.clipboard()["empty"])
        reopened=self.observe();self.same_items(copied,reopened)
        require(len(reopened["events"])==len(copied["events"]))
        self.completed.append("explicit audited show/copy then quick-open clears owned exposure")

        self.phase("nonempty-escape-preserves-draft")
        self.input([{"text":"Nonempty escape query"},{"key":"Escape"}])
        self.wait("显示密码")
        require(not self.metadata()["query_present"] and self.metadata(target=target["id"])["detail_target_matches"])
        self.click("新建登录")
        self.fill("登录标题","Daily manual login")
        self.fill("新登录用户名",self.fixture["Username"])
        self.fill("新登录密码",self.fixture["Value"])
        self.fill("网站（可选）",self.fixture["URL"])
        draft=self.observe()
        self.wake();self.panel_ready()
        self.input([{"text":"Draft cancellation query"},{"key":"Escape"}])
        self.wait("保存登录")
        closed=self.observe();self.same_items(draft,closed)
        require(len(closed["events"])==len(draft["events"]))
        self.click("保存登录")
        self.wait("新建登录")
        self.eventually(lambda:len(self.observe()["items"])==len(draft["items"])+1)
        saved=self.observe();row=self.target(saved,"Daily manual login")
        require(row["Username"]==self.fixture["Username"] and row["Password"]==self.fixture["Value"] and row["URL"]==self.fixture["URL"])
        self.completed.append("nonempty Escape cancels panel; original draft survives into explicit save")

        self.phase("main-busy-shortcut-only-raises")
        self.fill("搜索标题","Daily")
        barrier=self.hold_database()
        self.click("搜索 / 刷新")
        self.eventually(lambda:not self.controls()["搜索 / 刷新"]["enabled"])
        self.wake()
        require(not self.metadata()["query_present"] and not self.controls()["搜索 / 刷新"]["enabled"])
        self.release_database(barrier)
        self.eventually(lambda:self.controls()["搜索 / 刷新"]["enabled"])
        require(not self.metadata()["query_present"])
        self.completed.append("busy original operation is neither replaced nor cancelled")

        self.phase("query-close-reopen-discards-late-worker")
        start=self.observe();self.wake();self.panel_ready()
        self.fill("快捷搜索标题","Daily")
        barrier=self.hold_database()
        self.input([{"key":"Return"}])
        self.eventually(lambda:not self.controls()["搜索活动登录"]["enabled"])
        self.input([{"key":"Return"},{"key":"Escape"}])
        self.wait("新建登录")
        self.wake();self.panel_ready()
        require(not self.controls()["搜索活动登录"]["enabled"] and self.metadata()["result_count"]==0)
        self.release_database(barrier)
        self.eventually(lambda:self.controls()["搜索活动登录"]["enabled"])
        require(self.metadata()["result_count"]==0)
        finished=self.observe();self.same_items(start,finished)
        require(len(self.events(finished,"item.search"))==len(self.events(start,"item.search"))+1)
        expected=self.active_rows(finished,"Daily other")
        self.enter_query("Daily other",expected)
        other=self.target(finished,"Daily other login")
        self.tab_select(expected,other["id"])
        self.completed.append("one in-flight query; close/reopen rejects late rows; no queued requery")

        self.phase("lock-revokes-pending-query")
        start=self.observe();self.wake();self.panel_ready()
        self.fill("快捷搜索标题","Daily")
        barrier=self.hold_database()
        self.input([{"key":"Return"}])
        self.eventually(lambda:not self.controls()["搜索活动登录"]["enabled"])
        self.click("立即锁定")
        self.eventually(lambda:self.controls()["解锁"]["present"],timeout=3)
        self.wake()
        require(self.controls()["解锁"]["present"] and not self.metadata()["query_present"] and self.metadata()["result_count"]==0)
        self.release_database(barrier)
        self.eventually(lambda:self.displays_empty())
        locked=self.observe();self.same_items(start,locked)
        require(len(self.disclosures(locked))==len(self.disclosures(start)))
        self.unlock()
        require(not self.metadata()["query_present"])
        self.wake();self.panel_ready()
        self.eventually(lambda:self.controls()["搜索活动登录"]["enabled"])
        require(self.metadata()["result_count"]==0 and self.displays_empty())
        self.input([{"key":"Escape"}])
        self.completed.append("locked shortcut exposes no metadata; unlock does not reopen quick results or fields")

    def run(self):
        success=False
        try:
            self.prepare_window_manager()
            self.setup()
            self.scenarios()
            success=True
        except Exception as error:
            kind={AcceptanceFailure:"acceptance",ShortcutFailure:"shortcut",OSError:"os",json.JSONDecodeError:"json"}.get(type(error),"unexpected")
            failure={"stage":self.stage,"reason":self.reason,"error_class":kind,
                     "shortcut":self.shortcut_observations,"ewmh_window_manager_ready":self.wm_ready,"native_action":self.native_action,
                     "native_elapsed_ms":self.native_elapsed_ms,"metadata":self.last_metadata}
            try:failure["controls"]=self.controls()
            except Exception:failure["controls_unavailable"]=True
            with os.fdopen(os.open(self.diagnostics/"failure.json",os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600),"w") as out:json.dump(failure,out)
            self.reason,self.native_action=failure["reason"],failure["native_action"]
            self.emit(self.failure_diagnostic())
        finally:
            record={"ewmh_window_manager_ready":self.wm_ready,
                    "shortcut_observations":self.shortcut_observations,
                    "completed_cases":self.completed}
            try:
                with os.fdopen(os.open(self.diagnostics/"shortcut-proof.json",os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600),"w") as out:json.dump(record,out)
            except Exception:
                success=False;self.reason="shortcut-proof-output"
            for barrier in list(self.barriers):
                try:self.release_database(barrier)
                except Exception:barrier.kill();barrier.wait(timeout=3)
            if self.launcher:self.launcher.close()
            if hasattr(self,"fixture"):
                try:self.observe()
                except Exception:pass
            self.close()
            if self.wm:
                self.wm.terminate()
                try:self.wm.wait(timeout=3)
                except subprocess.TimeoutExpired:self.wm.kill();self.wm.wait(timeout=3)
        lines=["Desktop quick search private state: "+str(self.state),
               "PASS: real desktop quick search: "+"; ".join(self.completed) if success else
               "FAIL: desktop quick search at "+self.stage+" ["+self.reason+"]"]
        try:
            with os.fdopen(os.open(self.state/"controller.log",os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600),"w") as out:out.write("\n".join(self.output_lines+lines)+"\n")
            self.scan()
        except Exception:
            print("FAIL: desktop quick search privacy scan",flush=True);return 1
        for line in lines:print(line,flush=True)
        return 0 if success else 1


if __name__=="__main__":
    try:sys.exit(QuickSearchAcceptance().run())
    except Exception:
        print("FAIL: desktop quick search setup",file=sys.stderr);sys.exit(1)
