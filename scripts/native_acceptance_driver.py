"""Platform dispatcher for the external native acceptance input driver.

Linux is passed through UNCHANGED: stdin bytes are replayed into the existing
scripts/browser_native_x11.py as a subprocess and its exit status is returned
verbatim, so X11 behaviour is identical until the integration change lands.

Windows uses the new external Win32 + UI Automation adapter, macOS the AX +
CGEvent adapter. Both read one bounded JSON request from stdin and emit either
safe JSON on stdout or one fixed-code refusal line on stderr. Request content
is never placed in argv, and no environment, home or private path is read.
"""
import io
import os
import subprocess
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import native_acceptance_contract as contract  # noqa: E402

X11_DRIVER = os.path.join(_HERE, "browser_native_x11.py")
SELECTABLE = ("linux", "windows", "macos")


def detect_platform():
    if os.name == "nt":
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    if sys.platform.startswith("linux"):
        return "linux"
    return "unknown"


def parse_arguments(argv):
    """Only a fixed platform literal is accepted; nothing else may appear."""
    selected = detect_platform()
    index = 0
    while index < len(argv):
        if argv[index] != "--platform" or index + 1 >= len(argv):
            return selected, contract.ContractError("request-invalid")
        if argv[index + 1] not in SELECTABLE:
            return selected, contract.ContractError("platform-unsupported")
        selected = argv[index + 1]
        index += 2
    return selected, None


def run_linux(raw):
    """Replay stdin into the unchanged X11 driver; keep its output and status."""
    completed = subprocess.run([sys.executable, X11_DRIVER], input=raw)
    return completed.returncode


def run_platform(platform, raw, stdout, stderr):
    if platform == "windows":
        import browser_native_windows as driver
    elif platform == "macos":
        import browser_native_macos as driver
    else:
        stderr.write(contract.failure_line(
            contract.ContractError("platform-unsupported"), "setup", -1, "unknown") + "\n")
        return 1
    return driver.main(stdin=io.BytesIO(raw), stdout=stdout, stderr=stderr)


def main(argv=None, stdin=None, stdout=None, stderr=None):
    argv = sys.argv[1:] if argv is None else argv
    stdin = sys.stdin.buffer if stdin is None else stdin
    stdout = sys.stdout if stdout is None else stdout
    stderr = sys.stderr if stderr is None else stderr
    platform, error = parse_arguments(list(argv))
    if error is not None:
        stderr.write(contract.failure_line(error, "setup", -1, platform) + "\n")
        return 2
    raw = stdin.read(contract.MAX_REQUEST_BYTES + 1)
    if platform == "linux":
        return run_linux(raw)
    return run_platform(platform, raw, stdout, stderr)


if __name__ == "__main__":
    sys.exit(main())
