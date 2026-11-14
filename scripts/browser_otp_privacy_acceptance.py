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

HANDOFF_LIMIT = 4096
HANDOFF_PATTERN = re.compile(r"^/tmp/locklark-browser-acceptance-[A-Za-z0-9]+$")


def read_handoff(fd):
    os.set_blocking(fd, False)
    chunks = []
    total = 0
    while total <= HANDOFF_LIMIT:
        try:
            chunk = os.read(fd, HANDOFF_LIMIT + 1 - total)
        except BlockingIOError:
            break
        if not chunk:
            break
        total += len(chunk)
        chunks.append(chunk)
    raw = b"".join(chunks)
    if len(raw) > HANDOFF_LIMIT:
        raise ValueError("privacy-state")
    return raw


def validate_handoff(raw, expected_uid=None):
    if not raw or len(raw) > HANDOFF_LIMIT:
        raise ValueError("privacy-state")
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        raise ValueError("privacy-state")
    if not text.endswith("\n") or text.count("\n") != 1:
        raise ValueError("privacy-state")
    path_text = text[:-1]
    if not HANDOFF_PATTERN.fullmatch(path_text):
        raise ValueError("privacy-state")
    path = Path(path_text)
    if path.is_symlink():
        raise ValueError("privacy-state")
    if path.parent.resolve() != Path("/tmp").resolve():
        raise ValueError("privacy-state")
    try:
        info = path.stat()
    except OSError:
        raise ValueError("privacy-state")
    if not stat.S_ISDIR(info.st_mode):
        raise ValueError("privacy-state")
    uid = os.getuid() if expected_uid is None else expected_uid
    if info.st_uid != uid:
        raise ValueError("privacy-state")
    if info.st_mode & 0o077:
        raise ValueError("privacy-state")
    return path


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
    state = Path(tempfile.mkdtemp(prefix="locklark-browser-otp-privacy-"))
    os.chmod(state, 0o700)
    environment = dict(os.environ, LOCKLARK_TEST_FAILURE_STAGE="otp-page-arguments")
    handoff_read = handoff_write = None
    if args.engine == "chromium":
        handoff_read, handoff_write = os.pipe()
        environment["LOCKLARK_TEST_DIAGNOSTIC_FD"] = str(handoff_write)
    first = time.time()
    try:
        with (state / "controller.log").open("xb") as log:
            os.chmod(log.name, 0o600)
            process = subprocess.Popen(
                ["node", str(root / "scripts" / script)],
                cwd=root,
                env=environment,
                stdout=log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
                pass_fds=((handoff_write,) if handoff_write is not None else ()),
            )
            if handoff_write is not None:
                os.close(handoff_write)
                handoff_write = None
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
            if handoff_read is None:
                raise ValueError("privacy-state")
            private = validate_handoff(read_handoff(handoff_read))
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
        print("Private fault artifacts: " + str(state))
    finally:
        if handoff_write is not None:
            os.close(handoff_write)
        if handoff_read is not None:
            os.close(handoff_read)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        allowed = {"privacy-clock", "privacy-factor", "privacy-code", "privacy-failure-stage", "privacy-state", "privacy-otp-screenshot", "privacy-manifest", "privacy-timeout"}
        reason = error.args[0] if type(error) is ValueError and len(error.args) == 1 and error.args[0] in allowed else "privacy-unexpected"
        print("FAIL: browser OTP privacy acceptance (" + reason + ")", file=sys.stderr)
        sys.exit(1)
