"""Synthetic ConPTY transport regression; does not emulate native Windows."""
import sys
import types
import unittest
from unittest.mock import patch

sys.modules.setdefault("winpty", types.SimpleNamespace(PTY=None))
import personal_windows

class DelayedTerminal:
    def __init__(self, *args, **kwargs):
        self.chunks = iter(["", "", '{"backup":true}', None])
    def spawn(self, *args): pass
    def isalive(self): return False
    def get_exitstatus(self): return 0
    def read(self, **kwargs):
        chunk = next(self.chunks, None)
        if chunk is None: raise EOFError()
        return chunk

class TerminalDrainTest(unittest.TestCase):
    def test_output_delayed_after_process_exit(self):
        with patch.object(personal_windows, "PTY", DelayedTerminal):
            result, issued = personal_windows.invoke("synthetic", "backup", "synthetic", [], ok=True, issue=False, options=(), barrier=None)
        self.assertEqual(result, {"backup": True})
        self.assertIsNone(issued)

    def test_delayed_hidden_input_is_still_rejected(self):
        class EchoTerminal(DelayedTerminal):
            def __init__(self, *args, **kwargs):
                self.chunks = iter(["secret:", "", "", 'private-input{"ok":true}', None])
            def write(self, text): self.written = True
            def isalive(self): return not getattr(self, "written", False)
        with patch.object(personal_windows, "PTY", EchoTerminal):
            with self.assertRaisesRegex(RuntimeError, "hidden terminal input echoed"):
                personal_windows.invoke("synthetic", "backup", "synthetic", [("secret", "private-input")], ok=True, issue=False, options=(), barrier=None)

    def test_scope_notice_precedes_confirmation(self):
        for prefix, valid in (("required scope\nconsent:", True), ("consent:", False), ("consent: required scope", False)):
            with self.subTest(prefix=prefix):
                writes = []
                class ConsentTerminal(DelayedTerminal):
                    def __init__(self, *args, **kwargs):
                        self.chunks = iter([prefix, '{"ok":true}', None])
                    def write(self, text): writes.append(text)
                    def isalive(self): return not writes
                with patch.object(personal_windows, "PTY", ConsentTerminal):
                    def invoke():
                        return personal_windows.invoke("synthetic", "export", "synthetic", [("consent", "SAVE")], ok=True, issue=False, options=(), barrier=None, required_before_last_prompt=("required scope",))
                    if valid:
                        self.assertEqual(invoke()[0], {"ok": True})
                    else:
                        with self.assertRaisesRegex(RuntimeError, "scope notice missing before confirmation"):
                            invoke()
                        self.assertEqual(writes, [])

    def test_transport_stays_open_after_complete_response(self):
        class OpenTerminal(DelayedTerminal):
            def read(self, **kwargs):
                return next(self.chunks, "") or ""
        with patch.object(personal_windows, "PTY", OpenTerminal):
            result, _ = personal_windows.invoke("synthetic", "backup", "synthetic", [], ok=True, issue=False, options=(), barrier=None)
        self.assertEqual(result, {"backup": True})

if __name__ == "__main__": unittest.main()
