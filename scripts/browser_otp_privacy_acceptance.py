"""Real driver-failure privacy gate; run under the same DISPLAY/DBus as normal GUI."""
import argparse
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time

from browser_otp_hmac import codes


def _owned_private_directory(path):
    try:
        info = path.lstat()
    except OSError:
        return False
    return (
        stat.S_ISDIR(info.st_mode)
        and not stat.S_ISLNK(info.st_mode)
        and info.st_uid == os.geteuid()
        and stat.S_IMODE(info.st_mode) == 0o700
    )


def require_private_parent(path):
    """Accept only one canonical, owned, 0700 real directory."""
    path = Path(path)
    try:
        if not path.is_absolute() or path.resolve(strict=True) != path:
            raise ValueError
    except (OSError, RuntimeError):
        raise ValueError("privacy-state") from None
    if not _owned_private_directory(path):
        raise ValueError("privacy-state")
    return path


def find_private_child_state(parent):
    """Find the one child state under the wrapper-owned parent, no global scan."""
    parent = require_private_parent(parent)
    try:
        children = [
            child
            for child in parent.iterdir()
            if child.name.startswith("locklark-browser-acceptance-")
        ]
    except OSError:
        raise ValueError("privacy-state") from None
    if len(children) != 1:
        raise ValueError("privacy-state")
    child = require_private_parent(children[0])
    vault = child / "vault"
    if not _owned_private_directory(vault):
        raise ValueError("privacy-state")
    fixture = vault / "fixture.json"
    try:
        info = fixture.lstat()
    except OSError:
        raise ValueError("privacy-state") from None
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        raise ValueError("privacy-state")
    return child


def create_private_state_parent(prefix="locklark-browser-otp-privacy-"):
    """Create the wrapper's own parent and canonicalize only that new path.

    macOS temp paths commonly traverse a symlink such as /var -> /private/var.
    The wrapper owns this fresh directory, so resolving it strictly after
    creation is safe. Externally supplied parents still go through the strict
    require_private_parent rules and are never canonicalized for the caller.
    """
    created = Path(tempfile.mkdtemp(prefix=prefix))
    try:
        state = created.resolve(strict=True)
    except (OSError, RuntimeError):
        raise ValueError("privacy-state") from None
    os.chmod(state, 0o700)
    return require_private_parent(state)


def check_output(raw, fixture, first, last):
    if last < first or last - first > 600:
        raise ValueError("privacy-clock")
    text = raw.decode("utf-8", errors="replace")
    names = ("Password", "Secret", "Username", "Value", "SaveUsername", "SaveValue",
             "UpdateUsername", "UpdateValue", "RejectedUsername", "RejectedValue", "OTPSeed", "OTPURI")
    for name in names:
        value = fixture[name]
        variants = (value, json.dumps(value, ensure_ascii=True)[1:-1], json.dumps(value, ensure_ascii=False)[1:-1])
        if any(value in text for value in variants):
            raise ValueError("privacy-factor")
    for counter in range(int(first // 30) - 1, int(last // 30) + 2):
        for digits in (6, 8):
            for code in codes(dict(seed=fixture["OTPSeed"], digits=digits, first=counter, last=counter)):
                if re.search(r"(?<![A-Za-z0-9_])" + code + r"(?![A-Za-z0-9_])", text):
                    raise ValueError("privacy-code")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("engine", choices=("chromium", "firefox"))
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    script = "browser_native_acceptance.mjs" if args.engine == "chromium" else "browser_firefox_native_acceptance.mjs"
    state = create_private_state_parent()
    environment = dict(
        os.environ,
        LOCKLARK_TEST_FAILURE_STAGE="otp-page-arguments",
        LOCKLARK_TEST_PRIVATE_STATE_PARENT=str(state),
    )
    first = time.time()
    with (state / "controller.log").open("xb") as log:
        os.chmod(log.name, 0o600)
        process = subprocess.Popen(["node", str(root / "scripts" / script)], cwd=root, env=environment,
                                   stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            process.wait(timeout=180)
        except subprocess.TimeoutExpired:
            process.terminate()
            try:
                process.wait(timeout=12)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            raise ValueError("privacy-timeout")
    last = time.time()
    raw = (state / "controller.log").read_bytes()
    text = raw.decode("utf-8", errors="replace")
    if process.returncode != 1 or "otp-6:positive:driver-arguments-failure" not in text:
        raise ValueError("privacy-failure-stage")
    if args.engine == "chromium":
        # The public failure console intentionally no longer prints the private
        # diagnostics path. The wrapper-owned state directory is this run's
        # exclusive parent, so only that parent is inspected and validated.
        private = find_private_child_state(state)
    else:
        marker = r"Private diagnostic files: (/tmp/locklark-firefox-native-[A-Za-z0-9]+)"
        match = re.search(marker, text)
        if not match:
            raise ValueError("privacy-state")
        private = Path(match.group(1))
    fixture = json.loads((private / "vault/fixture.json").read_text())
    check_output(raw, fixture, first, last)
    diagnostics = list(private.glob("diagnostics-*"))
    if len(diagnostics) != 1 or any(diagnostics[0].glob("*.png")):
        raise ValueError("privacy-otp-screenshot")
    if args.engine == "firefox":
        manifest = Path.home() / ".mozilla/native-messaging-hosts/org.locklark.browser.json"
        if manifest.exists() or manifest.is_symlink():
            raise ValueError("privacy-manifest")
    print("PASS: real " + args.engine + " OTP argument failure exits 1; full controller canary scan, no OTP screenshots")
    print("Private fault artifacts: [private]")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        allowed = {"privacy-clock", "privacy-factor", "privacy-code", "privacy-failure-stage", "privacy-state", "privacy-otp-screenshot", "privacy-manifest", "privacy-timeout"}
        reason = error.args[0] if type(error) is ValueError and len(error.args) == 1 and error.args[0] in allowed else "privacy-unexpected"
        print("FAIL: browser OTP privacy acceptance (" + reason + ")", file=sys.stderr)
        sys.exit(1)
