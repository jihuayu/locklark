"""External XTest driver for synthetic native-window acceptance; no app hooks.

Reads one JSON request from stdin. Values are never echoed. Requires DISPLAY,
libX11 and libXtst. Coordinates are relative to the requested real X window.
"""
import ctypes as C
import json
import os
import sys
import time


def main():
    request = json.load(sys.stdin)
    x = C.CDLL("libX11.so.6")
    xt = C.CDLL("libXtst.so.6")
    pointer, window = C.c_void_p, C.c_ulong
    x.XOpenDisplay.argtypes = [C.c_char_p]
    x.XOpenDisplay.restype = pointer
    x.XDefaultRootWindow.argtypes = [pointer]
    x.XDefaultRootWindow.restype = window
    x.XQueryTree.argtypes = [pointer, window, C.POINTER(window), C.POINTER(window), C.POINTER(C.POINTER(window)), C.POINTER(C.c_uint)]
    x.XFetchName.argtypes = [pointer, window, C.POINTER(C.c_char_p)]
    x.XInternAtom.argtypes = [pointer, C.c_char_p, C.c_int]
    x.XInternAtom.restype = C.c_ulong
    x.XGetWindowProperty.argtypes = [pointer, window, C.c_ulong, C.c_long, C.c_long, C.c_int, C.c_ulong, C.POINTER(C.c_ulong), C.POINTER(C.c_int), C.POINTER(C.c_ulong), C.POINTER(C.c_ulong), C.POINTER(pointer)]
    x.XFree.argtypes = [pointer]
    x.XRaiseWindow.argtypes = [pointer, window]
    x.XSetInputFocus.argtypes = [pointer, window, C.c_int, C.c_ulong]
    x.XTranslateCoordinates.argtypes = [pointer, window, window, C.c_int, C.c_int, C.POINTER(C.c_int), C.POINTER(C.c_int), C.POINTER(window)]
    x.XStringToKeysym.argtypes = [C.c_char_p]
    x.XStringToKeysym.restype = C.c_ulong
    x.XKeysymToKeycode.argtypes = [pointer, C.c_ulong]
    x.XKeysymToKeycode.restype = C.c_uint
    x.XKeycodeToKeysym.argtypes = [pointer, C.c_uint, C.c_int]
    x.XKeycodeToKeysym.restype = C.c_ulong
    x.XFlush.argtypes = [pointer]
    x.XCloseDisplay.argtypes = [pointer]
    xt.XTestFakeKeyEvent.argtypes = [pointer, C.c_uint, C.c_int, C.c_ulong]
    xt.XTestFakeMotionEvent.argtypes = [pointer, C.c_int, C.c_int, C.c_int, C.c_ulong]
    xt.XTestFakeButtonEvent.argtypes = [pointer, C.c_uint, C.c_int, C.c_ulong]
    display = x.XOpenDisplay(os.environ.get("DISPLAY", "").encode())
    if not display:
        raise RuntimeError("X display unavailable")
    root = x.XDefaultRootWindow(display)
    name_atom = x.XInternAtom(display, b"_NET_WM_NAME", 0)
    utf8_atom = x.XInternAtom(display, b"UTF8_STRING", 0)

    def window_title(candidate):
        actual, count, remaining = C.c_ulong(), C.c_ulong(), C.c_ulong()
        fmt, data = C.c_int(), pointer()
        status = x.XGetWindowProperty(display, candidate, name_atom, 0, 1024, 0, utf8_atom, C.byref(actual), C.byref(fmt), C.byref(count), C.byref(remaining), C.byref(data))
        if status == 0 and data:
            try:
                if actual.value == utf8_atom and fmt.value == 8:
                    return C.string_at(data, count.value).decode("utf-8", errors="replace")
            finally:
                x.XFree(data)
        name = C.c_char_p()
        if x.XFetchName(display, candidate, C.byref(name)) and name.value:
            title = name.value.decode("utf-8", errors="replace")
            x.XFree(name)
            return title
        return ""

    def children(parent):
        root_return, parent_return, count = window(), window(), C.c_uint()
        result = C.POINTER(window)()
        if not x.XQueryTree(display, parent, C.byref(root_return), C.byref(parent_return), C.byref(result), C.byref(count)):
            return []
        found = [result[i] for i in range(count.value)]
        if result:
            x.XFree(result)
        return found

    def find(parent, depth=0):
        if depth > 3:
            return None
        for candidate in children(parent):
            title = window_title(candidate)
            if request.get("title") == title or (request.get("title_prefix") and title.startswith(request["title_prefix"])):
                return candidate
            nested = find(candidate, depth + 1)
            if nested:
                return nested
        return None

    target = None
    for _ in range(100):
        target = find(root)
        if target:
            break
        time.sleep(0.05)
    if not target:
        raise RuntimeError("Native acceptance window unavailable")
    x.XRaiseWindow(display, target)
    x.XSetInputFocus(display, target, 1, 0)
    px, py, child = C.c_int(), C.c_int(), window()
    if not x.XTranslateCoordinates(display, target, root, 0, 0, C.byref(px), C.byref(py), C.byref(child)):
        raise RuntimeError("Native acceptance window geometry unavailable")

    def key(code, down):
        xt.XTestFakeKeyEvent(display, code, int(down), 0)

    def named(name):
        return x.XKeysymToKeycode(display, x.XStringToKeysym(name.encode("ascii")))

    for action in request.get("actions", []):
        if "click" in action:
            dx, dy = action["click"]
            xt.XTestFakeMotionEvent(display, -1, px.value + dx, py.value + dy, 0)
            xt.XTestFakeButtonEvent(display, 1, 1, 0)
            xt.XTestFakeButtonEvent(display, 1, 0, 0)
        if "text" in action:
            shift = named("Shift_L")
            for char in action["text"]:
                symbol = ord(char)
                if symbol < 32 or symbol > 126:
                    raise RuntimeError("Acceptance input must be ASCII")
                code = x.XKeysymToKeycode(display, symbol)
                if not code:
                    raise RuntimeError("Acceptance keyboard mapping unavailable")
                shifted = x.XKeycodeToKeysym(display, code, 0) != symbol
                if shifted:
                    key(shift, True)
                key(code, True)
                key(code, False)
                if shifted:
                    key(shift, False)
        if "key" in action:
            parts = action["key"].split("+")
            codes = [named(part) for part in parts]
            if not all(codes):
                raise RuntimeError("Acceptance shortcut unavailable")
            for code in codes:
                key(code, True)
            for code in reversed(codes):
                key(code, False)
        x.XFlush(display)
        time.sleep(0.15)
    print(json.dumps({"window": target, "x": px.value, "y": py.value}))
    x.XCloseDisplay(display)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("Native acceptance input failed", file=sys.stderr)
        sys.exit(1)
