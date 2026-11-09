"""Portable pure test: importing the owner fixture package stays Unix-free.

``unittest`` discovery imports packages regardless of the ``-p`` pattern, so a
bare ``import cli_lease_terminal_fixture`` must not pull in ``fcntl``/``pty``/
``termios`` nor spawn anything. The check runs in a fresh subprocess whose
``sys.meta_path`` rejects those Unix modules, and never drives a real terminal.
"""
import os
import subprocess
import sys
import unittest

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))

_CHILD = r"""
import importlib.abc
import sys

sys.path.insert(0, sys.argv[1])

BLOCKED = ("fcntl", "pty", "termios")
attempts = []


class RejectUnixModules(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split(".")[0] in BLOCKED:
            attempts.append(fullname)
            raise ImportError("Unix-only module blocked by portable test: " + fullname)
        return None


blocker = RejectUnixModules()
sys.meta_path.insert(0, blocker)

import cli_lease_terminal_fixture as fixture

assert fixture.__name__ == "cli_lease_terminal_fixture"
assert fixture.__all__ == ["FixtureError", "TerminalRun", "TerminalSession", "proc_stat"], fixture.__all__
assert fixture.__path__, "package __path__ probe failed"
assert hasattr(fixture, "__path__")
assert sorted(dir(fixture)) == sorted(
    {"FixtureError", "TerminalRun", "TerminalSession", "proc_stat"} | set(vars(fixture))
), sorted(dir(fixture))
assert not hasattr(fixture, "load_tests"), "discovery probe must not resolve load_tests"

try:
    fixture.not_a_public_export
except AttributeError:
    pass
else:
    raise AssertionError("unknown attribute should raise AttributeError")

loaded = sorted(name for name in sys.modules if name.split(".")[0] in BLOCKED)
assert not loaded, "Unix modules imported by package import: " + repr(loaded)
assert "cli_lease_terminal_fixture.terminal_session" not in sys.modules, "eager Unix implementation import"
assert not attempts, "package import attempted Unix modules: " + repr(attempts)

try:
    fixture.TerminalSession
except ImportError:
    pass
else:
    raise AssertionError("public export should only import the Unix implementation on access")
print("ok lazy package import")

sys.meta_path.remove(blocker)
try:
    import fcntl  # noqa: F401
except ImportError:
    print("ok native exports skipped (no POSIX pty stack)")
else:
    import cli_lease_terminal_fixture.terminal_session as implementation
    from cli_lease_terminal_fixture import FixtureError, TerminalRun, TerminalSession, proc_stat

    assert FixtureError is implementation.FixtureError
    assert TerminalSession is implementation.TerminalSession
    assert TerminalRun is implementation.TerminalRun
    assert proc_stat is implementation.proc_stat
    print("ok native exports unchanged")
"""


class LazyFixtureImportTest(unittest.TestCase):
    def test_package_import_never_loads_unix_terminal(self):
        env = dict(os.environ)
        env.pop("PYTHONPATH", None)
        completed = subprocess.run(
            [sys.executable, "-c", _CHILD, SCRIPTS_DIR],
            cwd=SCRIPTS_DIR,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            timeout=120,
        )
        self.assertEqual(
            completed.returncode,
            0,
            "portable fixture import subprocess failed\nstdout:\n%s\nstderr:\n%s"
            % (completed.stdout, completed.stderr),
        )
        self.assertIn("ok lazy package import", completed.stdout)
        self.assertNotIn("Traceback", completed.stderr)


if __name__ == "__main__":
    unittest.main()
