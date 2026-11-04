"""ConPTY driver for synthetic personal acceptance; requires pywinpty==3.1.2."""
import json
import re
import subprocess
import time
from winpty import PTY


def invoke(binary, action, path, answers, *, ok, issue, options, barrier):
    terminal = PTY(2000, 40, backend=0)
    terminal.spawn(binary, " " + subprocess.list2cmdline(["personal", action, "--file", path, *options]))
    view = ""
    issued = None
    offset = 0
    # ConPTY emits cursor/style controls for its rendered screen.
    ansi = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
    def pump():
        nonlocal view
        try:
            view += terminal.read(blocking=False)
        except EOFError:
            pass
        time.sleep(0.01)
    for index,(prompt, value) in enumerate(answers):
        marker = prompt + ":"
        deadline = time.monotonic() + 15
        while marker not in ansi.sub("", view)[offset:]:
            pump()
            if time.monotonic() > deadline or not terminal.isalive():
                raise RuntimeError(f"{action}: missing ConPTY prompt")
        screen = ansi.sub("", view)
        offset = screen.index(marker, offset) + len(marker)
        if value is None:
            match = re.search(r"LL1-[A-Z2-7]{26}", screen)
            if not issue or match is None:
                raise RuntimeError("Secret Key not displayed at initialization")
            issued = value = match.group()
        if barrier is not None and index == len(answers)-1:
            barrier.wait(timeout=15)
        terminal.write(value + "\r")
    deadline = time.monotonic() + 18
    while terminal.isalive():
        pump()
        if time.monotonic() > deadline:
            raise RuntimeError(f"{action}: command did not finish")
    pump()
    if ok is None:
        ok = terminal.get_exitstatus() == 0
        if not ok and "login changed;" not in ansi.sub("", view):
            raise RuntimeError("expected a revision conflict")
    if (terminal.get_exitstatus() == 0) != ok:
        raise RuntimeError(f"{action}: unexpected exit")
    screen = ansi.sub("",view)
    for _,value in answers:
        if value and len(value)>5 and value in screen:
            raise RuntimeError("hidden terminal input echoed")
    if issue and screen.count(issued) != 1:
        raise RuntimeError("Secret Key echoed or repeated")
    if not ok:
        return None, None
    # The JSON response follows the last hidden prompt; do not print the screen.
    tail = screen[offset:]
    start = re.search(r"[\[{]",tail)
    if not start:
        raise RuntimeError(f"{action}: missing JSON response")
    return json.JSONDecoder().raw_decode(tail[start.start():])[0], issued
