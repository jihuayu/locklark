"""Read only fixed public quick-search metadata and focus, never input values."""
import time

from browser_native_x11 import AccessibilityQueryUnavailable, NativeControls


def exact_result_ids(seen,expected):
    return len(seen)==len(set(seen)) and set(seen)==set(expected)


class QuickMetadataReader(NativeControls):
    def __init__(self,pid):
        super().__init__("Locklark · 本地金库",pid)

    def focused(self,node):
        state=self.at.atspi_accessible_get_state_set(node)
        if not state:raise AccessibilityQueryUnavailable()
        try:return bool(self.at.atspi_state_set_contains(state,12))
        finally:self.go.g_object_unref(state)

    def inspect(self,expected=(),target=""):
        deadline=time.monotonic()+.5
        while True:
            try:return self.once(expected,target)
            except AccessibilityQueryUnavailable:
                remaining=deadline-time.monotonic()
                if remaining<=0:raise
                time.sleep(min(.02,remaining))

    def once(self,expected,target):
        for _ in range(100):
            if not self.gl.g_main_context_iteration(None,0):break
        lookup={item["id"]:item["title"] for item in expected}
        windows=[]
        seen=[]
        result={"query_present":False,"query_focused":False,"result_count":0,
                "all_results_exact":True,"target_focused":False,"detail_target_matches":False}

        def window(node,depth):
            if (self.string(self.at.atspi_accessible_get_name,node)==self.title and
                    self.checked(self.at.atspi_accessible_get_process_id,node)==self.pid):
                windows.append(self.go.g_object_ref(node));return False
            return depth<2

        def row(group):
            ids=[];buttons=[];focused=False
            def child(node,depth):
                nonlocal focused
                if depth==0:return True
                role=self.string(self.at.atspi_accessible_get_role_name,node)
                if role in ("push button","button","label"):
                    name=self.string(self.at.atspi_accessible_get_name,node)
                    if role=="label" and name.startswith("ID："):ids.append(name[3:])
                    if role in ("push button","button"):
                        buttons.append(name);focused=focused or self.focused(node)
                return role in ("panel","grouping","group")
            self.walk(group,child)
            exact=(len(ids)==1 and len(buttons)==1 and ids[0] in lookup and buttons[0]=="选择登录："+lookup[ids[0]])
            if len(ids)==1:seen.append(ids[0])
            result["result_count"]+=1
            result["all_results_exact"]=result["all_results_exact"] and exact
            if ids==[target] and focused:result["target_focused"]=True

        def inspect_node(node,_depth):
            role=self.string(self.at.atspi_accessible_get_role_name,node)
            name=self.string(self.at.atspi_accessible_get_name,node)
            if name in ("已授权显示的字段","已授权显示的验证码"):return False
            if name=="快捷搜索结果" and role in ("panel","grouping","group"):
                row(node);return False
            if name=="快捷搜索标题" and role in ("text","password text","entry"):
                result["query_present"]=True;result["query_focused"]=self.focused(node)
            if role=="label" and name=="ID: "+target and target:result["detail_target_matches"]=True
            return True

        try:
            self.walk(self.desktop,window)
            if len(windows)!=1:raise RuntimeError("Native accessibility window must be unique")
            self.walk(windows[0],inspect_node)
            result["all_results_exact"]=result["all_results_exact"] and exact_result_ids(seen,lookup)
            return result
        finally:
            for node in windows:self.go.g_object_unref(node)
