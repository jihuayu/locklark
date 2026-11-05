"""ConPTY driver for synthetic personal acceptance; requires pywinpty==3.1.2."""
import json
import re
import subprocess
import time
from winpty import PTY


def invoke(binary, action, path, answers, *, ok, issue, options, barrier, deny_issue=False, expect_error=None, disclosed=None, forbidden=(), capture_disclosure=False, required_before_last_prompt=()):
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
            return False
        time.sleep(0.01)
        return True
    for index,(prompt, value) in enumerate(answers):
        marker = prompt + ":"
        deadline = time.monotonic() + 15
        while marker not in ansi.sub("", view)[offset:]:
            pump()
            if time.monotonic() > deadline or not terminal.isalive():
                raise RuntimeError(f"{action}: missing ConPTY prompt")
        screen = ansi.sub("", view)
        offset = screen.index(marker, offset) + len(marker)
        if index == len(answers)-1 and any(value not in screen[:offset] for value in required_before_last_prompt):
            raise RuntimeError("required scope notice missing before confirmation")
        if value is None:
            match = re.search(r"(?:LL1-[A-Z2-7]{26}|LLR2-[A-Z2-7]{52}-[A-Z2-7]{52}|LLR1-[A-Z2-7]{52})", screen)
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
    # ConPTY may keep its transport open after the child exits. Wait for a
    # complete successful response and a quiet interval, rather than EOF alone.
    deadline = time.monotonic() + 5
    quiet_since = time.monotonic()
    while True:
        previous = len(view)
        if not pump():
            break
        now = time.monotonic()
        if len(view) != previous:
            quiet_since = now
        complete = terminal.get_exitstatus() != 0
        tail = ansi.sub("", view)[offset:]
        if disclosed is not None:
            tail = tail.replace(json.dumps(disclosed, ensure_ascii=False), "", 1)
        start = re.search(r"[\[{]", tail)
        if start:
            try:
                json.JSONDecoder().raw_decode(tail[start.start():])
                complete = True
            except json.JSONDecodeError:
                pass
        if complete and now - quiet_since >= 0.5:
            break
        if now > deadline:
            raise RuntimeError(f"{action}: incomplete ConPTY response")
    if ok is None:
        ok = terminal.get_exitstatus() == 0
        if not ok and "login changed;" not in ansi.sub("", view):
            raise RuntimeError("expected a revision conflict")
    if (terminal.get_exitstatus() == 0) != ok:
        raise RuntimeError(f"{action}: unexpected exit")
    screen = ansi.sub("",view)
    if capture_disclosure:
        if not ok or issue or disclosed is not None:
            raise RuntimeError("invalid disclosure capture request")
        try:
            disclosed, _ = json.JSONDecoder().raw_decode(screen[offset:].lstrip())
        except ValueError:
            raise RuntimeError("missing explicit disclosure") from None
        if not isinstance(disclosed, str):
            raise RuntimeError("explicit disclosure was not a string")
        issued = disclosed
    if disclosed is not None and screen.count(json.dumps(disclosed, ensure_ascii=False)) != 1:
        raise RuntimeError("disclosure missing or repeated")
    if any(value in screen for value in forbidden):
        raise RuntimeError("unselected or refused field disclosed")
    if deny_issue and re.search(r"LL1-[A-Z2-7]{26}|重新输入新 Secret Key", screen):
        raise RuntimeError("failed restore issued a new Secret Key")
    if expect_error and expect_error not in screen:
        raise RuntimeError(f"{action}: expected error category missing")
    for _,value in answers:
        if value and len(value)>5 and value in screen:
            raise RuntimeError("hidden terminal input echoed")
    if issue and screen.count(issued) != 1:
        raise RuntimeError("Secret Key echoed or repeated")
    if not ok:
        return None, None
    # The JSON response follows the last hidden prompt; do not print the screen.
    tail = screen[offset:]
    if disclosed is not None:
        tail = tail.replace(json.dumps(disclosed, ensure_ascii=False), "", 1)
    start = re.search(r"[\[{]",tail)
    if not start:
        raise RuntimeError(f"{action}: missing JSON response")
    return json.JSONDecoder().raw_decode(tail[start.start():])[0], issued
