"""Real foreign X11 selection owner for isolated native acceptance.

Starts with a private JSON line containing marker text. No text is printed.
Before 'respond', every SelectionRequest is counted and deliberately unanswered.
Ownership is verified with a server round trip, without reading selection data.
"""
import ctypes as C
import json
import os
import select
import sys


class Request(C.Structure):
    _fields_ = [("type",C.c_int),("serial",C.c_ulong),("send_event",C.c_int),("display",C.c_void_p),
                ("owner",C.c_ulong),("requestor",C.c_ulong),("selection",C.c_ulong),("target",C.c_ulong),
                ("property",C.c_ulong),("time",C.c_ulong)]


class Notify(C.Structure):
    _fields_ = [("type",C.c_int),("serial",C.c_ulong),("send_event",C.c_int),("display",C.c_void_p),
                ("requestor",C.c_ulong),("selection",C.c_ulong),("target",C.c_ulong),
                ("property",C.c_ulong),("time",C.c_ulong)]


class Event(C.Union):
    _fields_ = [("type",C.c_int),("request",Request),("notify",Notify),("pad",C.c_long*24)]


class Connection:
    def __init__(self):
        self.x = C.CDLL("libX11.so.6")
        p,w = C.c_void_p,C.c_ulong
        self.x.XOpenDisplay.argtypes,self.x.XOpenDisplay.restype = [C.c_char_p],p
        self.x.XCloseDisplay.argtypes = [p]
        self.x.XDefaultRootWindow.argtypes,self.x.XDefaultRootWindow.restype = [p],w
        self.x.XInternAtom.argtypes,self.x.XInternAtom.restype = [p,C.c_char_p,C.c_int],w
        self.x.XGetSelectionOwner.argtypes,self.x.XGetSelectionOwner.restype = [p,w],w
        self.x.XSetSelectionOwner.argtypes = [p,w,w,w]
        self.x.XSync.argtypes = [p,C.c_int]
        self.display = self.x.XOpenDisplay(os.environ.get("DISPLAY","").encode())
        if not self.display:
            raise RuntimeError("foreign-owner-display")
        self.selection = self.atom("CLIPBOARD")

    def atom(self,name):
        return self.x.XInternAtom(self.display,name.encode("ascii"),0)

    def owner(self):
        # XGetSelectionOwner is a server query, never a foreign-client request.
        return self.x.XGetSelectionOwner(self.display,self.selection)

    def close(self):
        self.x.XCloseDisplay(self.display)


def current_owner():
    connection = Connection()
    try:
        return hex(connection.owner())
    finally:
        connection.close()


class SelectionOwner(Connection):
    def __init__(self,marker):
        super().__init__()
        self.marker = marker.encode("utf-8")
        self.responding = False
        self.requests = self.payload_requests = self.metadata_requests = 0
        self.pending = []
        self.errors = []
        self.error_type = C.CFUNCTYPE(C.c_int,C.c_void_p,C.c_void_p)
        self.error_handler = self.error_type(lambda _display,_event: 0)
        self.x.XSetErrorHandler.argtypes = [self.error_type]
        self.x.XSetErrorHandler(self.error_handler)
        p,w = C.c_void_p,C.c_ulong
        self.x.XCreateSimpleWindow.argtypes,self.x.XCreateSimpleWindow.restype = [p,w,C.c_int,C.c_int,C.c_uint,C.c_uint,C.c_uint,w,w],w
        self.x.XDestroyWindow.argtypes = [p,w]
        self.x.XPending.argtypes,self.x.XPending.restype = [p],C.c_int
        self.x.XNextEvent.argtypes = [p,C.POINTER(Event)]
        self.x.XConnectionNumber.argtypes,self.x.XConnectionNumber.restype = [p],C.c_int
        self.x.XChangeProperty.argtypes = [p,w,w,w,C.c_int,C.c_int,p,C.c_int]
        self.x.XSendEvent.argtypes = [p,w,C.c_int,C.c_long,C.POINTER(Event)]
        self.x.XFlush.argtypes = [p]
        root = self.x.XDefaultRootWindow(self.display)
        self.window = self.x.XCreateSimpleWindow(self.display,root,-100,-100,1,1,0,0,0)
        self.targets = {name:self.atom(name) for name in ("UTF8_STRING","TEXT","STRING","TARGETS","TIMESTAMP")}
        self.x.XSetSelectionOwner(self.display,self.selection,self.window,0)
        self.x.XSync(self.display,0)
        if self.owner() != self.window:
            raise RuntimeError("foreign-owner-claim")

    def stats(self):
        return {"owner":hex(self.owner()),"expected_owner":hex(self.window),"requests":self.requests,
                "payload_requests":self.payload_requests,"metadata_requests":self.metadata_requests,
                "pending":len(self.pending),"responding":self.responding}

    def drain(self):
        while self.x.XPending(self.display):
            event = Event()
            self.x.XNextEvent(self.display,C.byref(event))
            if event.type != 30:
                continue
            request = Request.from_buffer_copy(event.request)
            self.requests += 1
            if request.target in (self.targets["TARGETS"],self.targets["TIMESTAMP"]):
                self.metadata_requests += 1
            else:
                self.payload_requests += 1
            if self.responding:
                self.reply(request)
            else:
                self.pending.append(request)

    def reply(self,request):
        property = request.property or request.target
        if request.target == self.targets["TARGETS"]:
            atoms = (C.c_ulong*len(self.targets))(*self.targets.values())
            self.x.XChangeProperty(self.display,request.requestor,property,4,32,0,C.cast(atoms,C.c_void_p),len(self.targets))
        elif request.target == self.targets["TIMESTAMP"]:
            timestamp = C.c_ulong(0)
            self.x.XChangeProperty(self.display,request.requestor,property,19,32,0,C.byref(timestamp),1)
        elif request.target in (self.targets["UTF8_STRING"],self.targets["TEXT"],self.targets["STRING"]):
            data = C.create_string_buffer(self.marker)
            actual_type = self.targets["STRING"] if request.target == self.targets["STRING"] else self.targets["UTF8_STRING"]
            self.x.XChangeProperty(self.display,request.requestor,property,actual_type,8,0,C.cast(data,C.c_void_p),len(self.marker))
        else:
            property = 0
        notify = Event()
        notify.notify = Notify(31,0,1,self.display,request.requestor,request.selection,request.target,property,request.time)
        self.x.XSendEvent(self.display,request.requestor,0,0,C.byref(notify))
        self.x.XFlush(self.display)

    def enable(self):
        self.responding = True
        for request in self.pending:
            self.reply(request)
        self.pending.clear()

    def close(self):
        self.x.XDestroyWindow(self.display,self.window)
        super().close()


def main():
    first = json.loads(sys.stdin.readline(2<<20))
    marker = first.get("marker")
    if not isinstance(marker,str) or len(marker.encode("utf-8")) > 1<<20:
        raise RuntimeError("foreign-owner-input")
    owner = SelectionOwner(marker)
    try:
        print(json.dumps({"ready":True,**owner.stats()}),flush=True)
        while True:
            owner.drain()
            ready,_,_ = select.select([sys.stdin,owner.x.XConnectionNumber(owner.display)],[],[],0.02)
            if sys.stdin not in ready:
                continue
            line = sys.stdin.readline()
            if not line:
                return
            request = json.loads(line)
            op = request.get("op")
            if op == "respond":
                owner.enable()
            elif op != "stats":
                raise RuntimeError("foreign-owner-operation")
            owner.drain()
            print(json.dumps({"ok":True,**owner.stats()}),flush=True)
    finally:
        owner.close()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("Foreign clipboard owner failed [fixed]",file=sys.stderr)
        sys.exit(1)
