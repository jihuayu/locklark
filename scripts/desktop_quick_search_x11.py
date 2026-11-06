"""Actual global shortcut from a separate public X11 window; no product focus API."""
import ctypes as C
import os
import time


SHORTCUT_REASONS=frozenset(("display","source-window","source-viewability","source-geometry","source-pointer","source-focus","key-map","xtest-pointer","xtest-keys","x-protocol","unexpected"))


class ShortcutFailure(Exception):
    def __init__(self,reason="x-protocol"):
        self.reason=reason if reason in SHORTCUT_REASONS else "unexpected"
        super().__init__()


SHORTCUT_PHASES=frozenset(("source-viewable","source-frame","source-pointer","source-click","source-focus","shortcut-keys","native-focus"))


def safe_shortcut_attempt(value):
    if not isinstance(value,dict):return {}
    result={"phase":value.get("phase") if value.get("phase") in SHORTCUT_PHASES else "unexpected"}
    for key in ("foreign_focus_established","foreign_frame_raised","pointer_on_foreign_frame","native_focus_after_shortcut"):
        if type(value.get(key)) is bool:result[key]=value[key]
    if type(value.get("shortcut_batches")) is int and value["shortcut_batches"] in (0,1):result["shortcut_batches"]=value["shortcut_batches"]
    if type(value.get("focus_elapsed_ms")) is int and 0<=value["focus_elapsed_ms"]<=60000:result["focus_elapsed_ms"]=value["focus_elapsed_ms"]
    return result


def top_level_source(parent_of,source,root):
    seen=set()
    for _ in range(12):
        if source in seen:raise ShortcutFailure("source-window")
        seen.add(source)
        parent=parent_of(source)
        if parent==root:return source
        if parent in (None,0,1):raise ShortcutFailure("source-window")
        source=parent
    raise ShortcutFailure("source-window")


class XError(C.Structure):
    _fields_=[("type",C.c_int),("display",C.c_void_p),("resource",C.c_ulong),("serial",C.c_ulong),("code",C.c_ubyte),("request",C.c_ubyte),("minor",C.c_ubyte)]


class Attributes(C.Structure):
    _fields_=[(name,C.c_int) for name in ("x","y","width","height","border_width","depth")]+[("visual",C.c_void_p),("root",C.c_ulong),("class",C.c_int),("bit_gravity",C.c_int),("win_gravity",C.c_int),("backing_store",C.c_int),("backing_planes",C.c_ulong),("backing_pixel",C.c_ulong),("save_under",C.c_int),("colormap",C.c_ulong),("map_installed",C.c_int),("map_state",C.c_int),("all_event_masks",C.c_long),("your_event_mask",C.c_long),("do_not_propagate_mask",C.c_long),("override_redirect",C.c_int),("screen",C.c_void_p)]


class ShortcutLauncher:
    def __init__(self):
        self.x = C.CDLL("libX11.so.6")
        self.xt = C.CDLL("libXtst.so.6")
        p, w = C.c_void_p, C.c_ulong
        signatures = {
            "XOpenDisplay": ([C.c_char_p], p), "XDefaultRootWindow": ([p], w),
            "XCreateSimpleWindow": ([p,w,C.c_int,C.c_int,C.c_uint,C.c_uint,C.c_uint,w,w], w),
            "XMapRaised": ([p,w], C.c_int), "XRaiseWindow": ([p,w], C.c_int), "XSetInputFocus": ([p,w,C.c_int,w], C.c_int),
            "XGetInputFocus": ([p,C.POINTER(w),C.POINTER(C.c_int)], C.c_int),
            "XSync": ([p,C.c_int], C.c_int), "XDestroyWindow": ([p,w], C.c_int),
            "XCloseDisplay": ([p], C.c_int), "XStringToKeysym": ([C.c_char_p], w),
            "XKeysymToKeycode": ([p,w], C.c_uint), "XFree": ([p], C.c_int),
            "XQueryTree": ([p,w,C.POINTER(w),C.POINTER(w),C.POINTER(C.POINTER(w)),C.POINTER(C.c_uint)], C.c_int),
        }
        for name,(args,result) in signatures.items():
            fn=getattr(self.x,name);fn.argtypes=args;fn.restype=result
        self.errors=[]
        self.error_events=[]
        self.ignored_stale_wm_hints=0
        callback=C.CFUNCTYPE(C.c_int,p,C.POINTER(XError))
        @callback
        def record_error(_display,event):
            code=int(event.contents.code)
            self.error_events.append((code,int(event.contents.resource)))
            if code not in self.errors:self.errors.append(code)
            return 0
        self.error_handler=record_error
        self.x.XSetErrorHandler.argtypes=[callback]
        self.x.XSetErrorHandler(self.error_handler)
        self.x.XGetWindowAttributes.argtypes=[p,w,C.POINTER(Attributes)]
        self.x.XGetWindowAttributes.restype=C.c_int
        self.x.XTranslateCoordinates.argtypes=[p,w,w,C.c_int,C.c_int,C.POINTER(C.c_int),C.POINTER(C.c_int),C.POINTER(w)]
        self.x.XTranslateCoordinates.restype=C.c_int
        self.x.XInternAtom.argtypes=[p,C.c_char_p,C.c_int];self.x.XInternAtom.restype=w
        self.x.XGetWindowProperty.argtypes=[p,w,w,C.c_long,C.c_long,C.c_int,w,C.POINTER(w),C.POINTER(C.c_int),C.POINTER(w),C.POINTER(w),C.POINTER(p)]
        self.x.XGetWindowProperty.restype=C.c_int
        self.x.XQueryPointer.argtypes=[p,w,C.POINTER(w),C.POINTER(w),C.POINTER(C.c_int),C.POINTER(C.c_int),C.POINTER(C.c_int),C.POINTER(C.c_int),C.POINTER(C.c_uint)]
        self.x.XQueryPointer.restype=C.c_int
        self.xt.XTestFakeMotionEvent.argtypes=[p,C.c_int,C.c_int,C.c_int,w];self.xt.XTestFakeMotionEvent.restype=C.c_int
        self.xt.XTestFakeButtonEvent.argtypes=[p,C.c_uint,C.c_int,w];self.xt.XTestFakeButtonEvent.restype=C.c_int
        self.xt.XTestFakeKeyEvent.argtypes=[p,C.c_uint,C.c_int,w]
        self.xt.XTestFakeKeyEvent.restype=C.c_int
        self.display=self.x.XOpenDisplay(os.environ.get("DISPLAY","").encode())
        if not self.display: raise ShortcutFailure("display")
        self.root=self.x.XDefaultRootWindow(self.display)
        self.window=self.x.XCreateSimpleWindow(self.display,self.root,20,20,180,90,0,0,0)
        if not self.window: self.close();raise ShortcutFailure("source-window")

    def sync(self):
        self.x.XSync(self.display,0)
        if self.errors:raise ShortcutFailure()

    def property_window(self,target,name):
        atom=self.x.XInternAtom(self.display,name,0)
        actual,count,remaining=C.c_ulong(),C.c_ulong(),C.c_ulong()
        fmt,data=C.c_int(),C.c_void_p()
        status=self.x.XGetWindowProperty(self.display,target,atom,0,1,0,33,C.byref(actual),C.byref(fmt),C.byref(count),C.byref(remaining),C.byref(data))
        try:
            self.sync()
            if status or actual.value!=33 or fmt.value!=32 or count.value!=1 or not data:return 0
            return C.cast(data,C.POINTER(C.c_ulong))[0]
        finally:
            if data:self.x.XFree(data)

    def window_manager_ready(self):
        owner=self.property_window(self.root,b"_NET_SUPPORTING_WM_CHECK")
        if not owner:return False
        before=len(self.error_events)
        try:return self.property_window(owner,b"_NET_SUPPORTING_WM_CHECK")==owner
        except ShortcutFailure:
            events=self.error_events[before:]
            # A terminated WM can leave a stale root hint. Only BadWindow for
            # that unselected supporting-window hint is absence, never errors
            # involving the real native target, source window or other codes.
            if events and all(code==3 and resource==owner for code,resource in events):
                self.errors.clear();self.ignored_stale_wm_hints+=1;return False
            raise

    def focus(self):
        value,revert=C.c_ulong(),C.c_int()
        self.x.XGetInputFocus(self.display,C.byref(value),C.byref(revert))
        self.sync()
        return value.value

    def parent_of(self,candidate):
        root,parent=C.c_ulong(),C.c_ulong()
        children,count=C.POINTER(C.c_ulong)(),C.c_uint()
        ok=self.x.XQueryTree(self.display,candidate,C.byref(root),C.byref(parent),C.byref(children),C.byref(count))
        if children:self.x.XFree(children)
        self.sync()
        return parent.value if ok else None

    def pointer_child(self):
        root,child=C.c_ulong(),C.c_ulong()
        rx,ry,wx,wy,mask=C.c_int(),C.c_int(),C.c_int(),C.c_int(),C.c_uint()
        ok=self.x.XQueryPointer(self.display,self.root,C.byref(root),C.byref(child),C.byref(rx),C.byref(ry),C.byref(wx),C.byref(wy),C.byref(mask))
        self.sync()
        if not ok:raise ShortcutFailure("source-pointer")
        return child.value

    def inside(self, candidate, target):
        for _ in range(12):
            if candidate == target:return True
            if candidate in (0,1,self.root):return False
            root,parent=C.c_ulong(),C.c_ulong()
            children,count=C.POINTER(C.c_ulong)(),C.c_uint()
            ok=self.x.XQueryTree(self.display,candidate,C.byref(root),C.byref(parent),C.byref(children),C.byref(count))
            if children:self.x.XFree(children)
            self.sync()
            if not ok:return False
            candidate=parent.value
        return False

    def wake(self, target, timeout=3):
        result={"phase":"source-viewable","foreign_focus_established":False,
                "foreign_frame_raised":False,"pointer_on_foreign_frame":False,
                "native_focus_after_shortcut":False,"shortcut_batches":0}
        self.last_attempt=result
        self.x.XMapRaised(self.display,self.window);self.sync()
        deadline=time.monotonic()+timeout
        attributes=Attributes()
        while True:
            valid=self.x.XGetWindowAttributes(self.display,self.window,C.byref(attributes));self.sync()
            if not valid:raise ShortcutFailure("source-window")
            if time.monotonic()>=deadline:raise ShortcutFailure("source-viewability")
            if attributes.map_state==2:break
            time.sleep(.01)
        result["phase"]="source-frame"
        frame=top_level_source(self.parent_of,self.window,self.root)
        self.x.XRaiseWindow(self.display,frame);self.sync()
        result["foreign_frame_raised"]=True
        cx,cy,child=C.c_int(),C.c_int(),C.c_ulong()
        translated=self.x.XTranslateCoordinates(self.display,self.window,self.root,attributes.width//2,attributes.height//2,C.byref(cx),C.byref(cy),C.byref(child));self.sync()
        if not translated:raise ShortcutFailure("source-geometry")
        result["phase"]="source-pointer"
        motion=bool(self.xt.XTestFakeMotionEvent(self.display,-1,cx.value,cy.value,0));self.sync()
        if not motion:raise ShortcutFailure("xtest-pointer")
        result["pointer_on_foreign_frame"]=self.pointer_child()==frame
        if not result["pointer_on_foreign_frame"]:raise ShortcutFailure("source-pointer")
        result["phase"]="source-click"
        down=bool(self.xt.XTestFakeButtonEvent(self.display,1,1,0))
        up=bool(self.xt.XTestFakeButtonEvent(self.display,1,0,0));self.sync()
        if not(down and up):raise ShortcutFailure("xtest-pointer")
        result["phase"]="source-focus"
        while True:
            focused=self.focus();now=time.monotonic()
            if now>=deadline:raise ShortcutFailure("source-focus")
            if focused==self.window:break
            time.sleep(.01)
        result["foreign_focus_established"]=True
        result["phase"]="shortcut-keys"
        codes=[self.x.XKeysymToKeycode(self.display,self.x.XStringToKeysym(name)) for name in (b"Control_L",b"Shift_L",b"l")]
        if not all(codes):raise ShortcutFailure("key-map")
        emitted=[]
        for pressed,sequence in ((True,codes),(False,reversed(codes))):
            for code in sequence:emitted.append(bool(self.xt.XTestFakeKeyEvent(self.display,code,pressed,0)))
        self.sync();result["shortcut_batches"]=1
        if not all(emitted):raise ShortcutFailure("xtest-keys")
        result["phase"]="native-focus"
        start=time.monotonic()
        while time.monotonic()-start<timeout:
            focused=self.inside(self.focus(),target);now=time.monotonic()
            if now-start>=timeout:break
            if focused:
                result["native_focus_after_shortcut"]=True;break
            time.sleep(.01)
        result["focus_elapsed_ms"]=round((time.monotonic()-start)*1000)
        return dict(result)

    def close(self):
        if getattr(self,"display",None):
            if getattr(self,"window",None):self.x.XDestroyWindow(self.display,self.window)
            self.x.XCloseDisplay(self.display);self.display=None
