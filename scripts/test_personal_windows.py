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

if __name__ == "__main__": unittest.main()
