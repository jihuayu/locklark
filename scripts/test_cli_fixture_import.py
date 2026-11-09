"""Portable pure test: ``unittest`` discovery imports the fixture Unix-free.

``unittest`` discovery imports every package directory regardless of the ``-p``
pattern and then runs ``TestLoader.loadTestsFromModule`` on it, which walks
``dir(module)`` and ``getattr``s every advertised name. So the fixture package
must keep ``fcntl``/``pty``/``termios`` and any child process out of a bare
import *and* out of that loader walk.

The check runs in a fresh subprocess whose ``sys.meta_path`` rejects those Unix
modules. It drives the REAL loader entry points (``loadTestsFromModule`` and a
real ``discover`` over the scripts directory) and requires them to succeed with
zero tests and zero Unix attempts; an ``ImportError`` raised by the loader is a
failure, never swallowed. It never drives a real terminal.
"""
import os
import subprocess
import sys
import unittest

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))

_CHILD = r"""
import importlib.abc
import sys
import unittest

sys.path.insert(0, sys.argv[1])

EXPORTS = ["FixtureError", "TerminalRun", "TerminalSession", "proc_stat"]
BLOCKED = ("fcntl", "pty", "termios")
attempts = []


class RejectUnixModules(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split(".")[0] in BLOCKED:
            attempts.append(fullname)
            raise ImportError("Unix-only module blocked by portable test: " + fullname)
        return None


def unix_loaded():
    return sorted(name for name in sys.modules if name.split(".")[0] in BLOCKED)


blocker = RejectUnixModules()
sys.meta_path.insert(0, blocker)

import cli_lease_terminal_fixture as fixture

# The public API is unchanged: same package name, same __all__, same __path__.
assert fixture.__name__ == "cli_lease_terminal_fixture"
assert fixture.__all__ == EXPORTS, fixture.__all__
assert fixture.__path__, "package __path__ probe failed"
assert hasattr(fixture, "__path__")

# __dir__ advertises ONLY currently loaded globals; unresolved lazy exports are
# not advertised until an explicit intentional access resolves them.
advertised = dir(fixture)
assert advertised == sorted(vars(fixture)), (advertised, sorted(vars(fixture)))
assert [name for name in EXPORTS if name in advertised] == [], advertised
assert "load_tests" not in advertised, "discovery probe must not resolve load_tests"

try:
    fixture.not_a_public_export
except AttributeError:
    pass
else:
    raise AssertionError("unknown attribute should raise AttributeError")

assert not unix_loaded(), "Unix modules imported by package import: " + repr(unix_loaded())
assert "cli_lease_terminal_fixture.terminal_session" not in sys.modules, "eager Unix implementation import"
assert not attempts, "package import attempted Unix modules: " + repr(attempts)
print("ok lazy package import")

# The regression: the REAL loader call unittest discovery performs on a package.
# Unresolved __all__ names must not be advertised, otherwise this walks into the
# POSIX implementation. Any ImportError here is a genuine failure.
loader = unittest.TestLoader()
suite = loader.loadTestsFromModule(fixture)
assert suite.countTestCases() == 0, suite.countTestCases()
assert not loader.errors, loader.errors
assert not attempts, "loader attempted Unix modules: " + repr(attempts)
assert not unix_loaded(), "loader imported Unix modules: " + repr(unix_loaded())
assert "cli_lease_terminal_fixture.terminal_session" not in sys.modules
assert dir(fixture) == advertised, "loader must not resolve lazy exports"
print("ok real loadTestsFromModule: 0 tests, no Unix attempts")

# And the real directory-discovery walk, which imports package dirs even when no
# file matches the pattern.
walk = unittest.TestLoader()
discovered = walk.discover(
    start_dir=sys.argv[1], pattern="_no_such_test_file_.py", top_level_dir=sys.argv[1]
)
assert discovered.countTestCases() == 0, discovered.countTestCases()
assert not walk.errors, walk.errors
assert not attempts, "discovery attempted Unix modules: " + repr(attempts)
assert not unix_loaded(), "discovery imported Unix modules: " + repr(unix_loaded())
assert "cli_lease_terminal_fixture" in sys.modules
print("ok real discover: 0 tests, no Unix attempts")

# An intentional forced access on a blocked host still raises the real
# ImportError (unsupported here), it never returns a fake TerminalSession.
# This catch is the deliberate probe below, never the loader calls above.
try:
    fixture.TerminalSession
except ImportError:
    pass
else:
    raise AssertionError("blocked host must not fake TerminalSession")
assert attempts, "forced access must really try the Unix implementation"
print("ok forced export raises unsupported when blocked")

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
    # Explicit access resolved the same objects the module exports, and only
    # now do they show up in dir(); __all__ is untouched.
    assert fixture.TerminalSession is implementation.TerminalSession
    assert fixture.proc_stat is implementation.proc_stat
    assert set(EXPORTS) <= set(dir(fixture)), dir(fixture)
    assert fixture.__all__ == EXPORTS, fixture.__all__
    print("ok native exports unchanged")
"""


class LazyFixtureImportTest(unittest.TestCase):
    def test_real_discovery_never_loads_unix_terminal(self):
        env = dict(os.environ)
        env.pop("PYTHONPATH", None)
        completed = subprocess.run(
            [sys.executable, "-c", _CHILD, SCRIPTS_DIR],
            cwd=SCRIPTS_DIR,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            timeout=300,
        )
        self.assertEqual(
            completed.returncode,
            0,
            "portable fixture import subprocess failed\nstdout:\n%s\nstderr:\n%s"
            % (completed.stdout, completed.stderr),
        )
        for marker in (
            "ok lazy package import",
            "ok real loadTestsFromModule: 0 tests, no Unix attempts",
            "ok real discover: 0 tests, no Unix attempts",
            "ok forced export raises unsupported when blocked",
        ):
            self.assertIn(marker, completed.stdout)
        self.assertNotIn("Traceback", completed.stderr)


if __name__ == "__main__":
    unittest.main()
