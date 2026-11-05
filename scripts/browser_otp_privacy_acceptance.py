"""Real driver-failure privacy gate; run under the same DISPLAY/DBus as normal GUI."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time

from browser_otp_hmac import codes


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
    marker = (r"Synthetic diagnostic directory: (/tmp/locklark-browser-acceptance-[A-Za-z0-9]+)/(diagnostics-[A-Za-z0-9]+)"
              if args.engine == "chromium" else r"Private diagnostic files: (/tmp/locklark-firefox-native-[A-Za-z0-9]+)")
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


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        allowed = {"privacy-clock", "privacy-factor", "privacy-code", "privacy-failure-stage", "privacy-state", "privacy-otp-screenshot", "privacy-manifest", "privacy-timeout"}
        reason = error.args[0] if type(error) is ValueError and len(error.args) == 1 and error.args[0] in allowed else "privacy-unexpected"
        print("FAIL: browser OTP privacy acceptance (" + reason + ")", file=sys.stderr)
        sys.exit(1)
