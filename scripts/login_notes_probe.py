"""Fixed public target metadata only; no editable-text/value API is bound."""
import re
import time
from browser_native_x11 import NativeControls, AccessibilityQueryUnavailable


class NotesMetadataReader(NativeControls):
    def __init__(self,pid):
        super().__init__("Locklark · 本地金库",pid)

    def inspect(self,item_id,revision):
        if not re.fullmatch("[0-9a-f]{32}",item_id) or not re.fullmatch("[0-9a-f]{64}",revision):
            raise RuntimeError("metadata-request")
        deadline=time.monotonic()+.5
        while True:
            try:return self.once(item_id,revision)
            except AccessibilityQueryUnavailable:
                remaining=deadline-time.monotonic()
                if remaining<=0:raise
                time.sleep(min(.02,remaining))

    def once(self,item_id,revision):
        for _ in range(100):
            if not self.gl.g_main_context_iteration(None,0):break
        windows=[]
        result={"id_matches":False,"revision_matches":False,"editor_present":False}
        def window(node,depth):
            if (self.string(self.at.atspi_accessible_get_name,node)==self.title and
                    self.checked(self.at.atspi_accessible_get_process_id,node)==self.pid):
                windows.append(self.go.g_object_ref(node));return False
            return depth<2
        def field(node,_depth):
            role=self.string(self.at.atspi_accessible_get_role_name,node)
            name=self.string(self.at.atspi_accessible_get_name,node)
            if name in ("已授权显示的字段","已授权显示的验证码"):return False
            if role=="label":
                if name=="ID: "+item_id:result["id_matches"]=True
                if name=="修订: "+revision:result["revision_matches"]=True
            if name=="备注正文（可见多行）":
                result["editor_present"]=role in ("text","password text","entry")
                return False  # Never traverse an editable body or its descendants.
            return True
        try:
            self.walk(self.desktop,window)
            if len(windows)!=1:raise RuntimeError("Native accessibility window must be unique")
            self.walk(windows[0],field)
            return result
        finally:
            for node in windows:self.go.g_object_unref(node)
