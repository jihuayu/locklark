"""Owner fixture: one persistent real controlling terminal for CLI acceptance.

``terminal_session`` keeps a single session leader alive on a private pseudo
terminal so successive ordinary CLI processes share the real kernel terminal
(session id + tty device) the desktop lease binds to. Only the public helpers
below are exported; the acceptance controller and the pure unit tests use the
same code path.

The POSIX implementation is imported lazily through PEP 562 ``__getattr__`` so
that importing the package (or letting ``unittest`` discovery probe it) never
touches ``fcntl``/``pty``/``termios`` and never spawns a process. On Windows the
package stays importable; a real ``TerminalSession`` is still kernel-proofed on
POSIX hosts, never faked.
"""
import importlib

__all__ = ["FixtureError", "TerminalRun", "TerminalSession", "proc_stat"]

_EXPORTED_NAMES = frozenset(__all__)
_IMPLEMENTATION = ".terminal_session"


def __getattr__(name):
    """Resolve a public export on first access only (PEP 562)."""
    if name not in _EXPORTED_NAMES:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(importlib.import_module(_IMPLEMENTATION, __name__), name)
    globals()[name] = value
    return value


def __dir__():
    return sorted(set(globals()) | _EXPORTED_NAMES)
