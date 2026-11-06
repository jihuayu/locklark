"""Bounded raw UTF8_STRING reader: private expected bodies in, booleans out.

Unlike GTK's text convenience API this observes the selection wire bytes. No
payload, property value, or arbitrary exception is written to output.
"""
import ctypes as C
import json
import os
import select
import stat
import sys
import time

from desktop_clipboard_owner import Connection, Event


class RawClipboardFailure(Exception):
    pass


def compare(expected):
    if not isinstance(expected, list) or len(expected) > 8 or any(not isinstance(value, str) or len(value.encode()) > 65536 for value in expected):
        raise RawClipboardFailure()
    connection = Connection()
    x, display = connection.x, connection.display
    errors = []
    handler_type = C.CFUNCTYPE(C.c_int, C.c_void_p, C.c_void_p)
    handler = handler_type(lambda _display, _event: errors.append(True) or 0)
    x.XSetErrorHandler.argtypes, x.XSetErrorHandler.restype = [handler_type], C.c_void_p
    previous = x.XSetErrorHandler(handler)
    p, w = C.c_void_p, C.c_ulong
    x.XCreateSimpleWindow.argtypes, x.XCreateSimpleWindow.restype = [p,w,C.c_int,C.c_int,C.c_uint,C.c_uint,C.c_uint,w,w],w
    x.XDestroyWindow.argtypes = [p,w]
    x.XConvertSelection.argtypes = [p,w,w,w,w,w]
    x.XFlush.argtypes = [p]
    x.XPending.argtypes, x.XPending.restype = [p], C.c_int
    x.XNextEvent.argtypes = [p,C.POINTER(Event)]
    x.XConnectionNumber.argtypes, x.XConnectionNumber.restype = [p], C.c_int
    x.XGetWindowProperty.argtypes = [p,w,w,C.c_long,C.c_long,C.c_int,w,C.POINTER(w),C.POINTER(C.c_int),C.POINTER(w),C.POINTER(w),C.POINTER(p)]
    x.XFree.argtypes = [p]
    window = 0
    try:
        owner = connection.owner()
        if not owner:
            return {"empty": True, "matches": [value == "" for value in expected]}
        window = x.XCreateSimpleWindow(display,x.XDefaultRootWindow(display),-100,-100,1,1,0,0,0)
        target, property = connection.atom("UTF8_STRING"), connection.atom("LOCKLARK_NOTES_PRIVATE_READ")
        deadline = time.monotonic()+1
        x.XConvertSelection(display,connection.selection,target,property,window,0)
        x.XFlush(display)
        while time.monotonic()<deadline:
            if errors:
                raise RawClipboardFailure()
            if not x.XPending(display):
                select.select([x.XConnectionNumber(display)],[],[],min(.02,max(0,deadline-time.monotonic())))
                continue
            event=Event();x.XNextEvent(display,C.byref(event))
            if event.type!=31:
                continue
            if event.notify.requestor!=window or event.notify.selection!=connection.selection or event.notify.target!=target or event.notify.property!=property:
                raise RawClipboardFailure()
            actual, format, count, remaining, data = w(), C.c_int(), w(), w(), p()
            try:
                status=x.XGetWindowProperty(display,window,property,0,16385,1,0,C.byref(actual),C.byref(format),C.byref(count),C.byref(remaining),C.byref(data))
                if status or actual.value!=target or format.value!=8 or remaining.value or count.value>65536 or errors or time.monotonic()>=deadline or connection.owner()!=owner:
                    raise RawClipboardFailure()
                raw=C.string_at(data,count.value) if count.value else b""
                return {"empty":not raw,"matches":[raw==value.encode() for value in expected]}
            finally:
                if data:x.XFree(data)
        raise RawClipboardFailure()
    finally:
        if window:x.XDestroyWindow(display,window)
        x.XSync(display,0)
        connection.close()
        # Restore the process-global handler; this standalone reader never
        # retains a pointer to a short-lived Python callback after returning.
        C.cast(x.XSetErrorHandler,C.CFUNCTYPE(C.c_void_p,C.c_void_p))(previous)


def main():
    if not stat.S_ISFIFO(os.fstat(sys.stdout.fileno()).st_mode):
        raise RawClipboardFailure()
    request=json.loads(sys.stdin.readline(2<<20))
    print(json.dumps({"ok":True,**compare(request["expected"])}),flush=True)


if __name__=="__main__":
    try:main()
    except Exception:
        print('{"ok":false,"reason":"raw-clipboard-read"}',flush=True)
        sys.exit(1)
