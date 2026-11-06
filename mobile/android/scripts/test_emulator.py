"""Dedicated-emulator runtime gate. All fixture-bearing logs stay private."""
import base64
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import threading
import urllib.parse


class RuntimeFailure(Exception):
    pass


STAGE = "prerequisites"
STATE = None


def scan_output(raw, values):
    if not isinstance(values, list) or len(values) < 5 or any(not isinstance(value, str) or not value for value in values):
        raise RuntimeFailure()
    for value in values:
        parts = (value, *value.splitlines())
        for part in parts:
            if not part:
                continue
            encoded = part.encode()
            patterns = (json.dumps(part, ensure_ascii=True)[1:-1].encode(),
                        json.dumps(part, ensure_ascii=False)[1:-1].encode(), urllib.parse.quote(part, safe="").encode(),
                        base64.b64encode(encoded), base64.urlsafe_b64encode(encoded), encoded.hex().encode(), encoded.hex().upper().encode())
            if any(pattern and pattern in raw for pattern in patterns):
                raise RuntimeFailure()
            if re.fullmatch(r"[0-9]{6,8}", part):
                if re.search(rb"(?<![A-Za-z0-9])" + encoded + rb"(?![A-Za-z0-9])", raw):
                    raise RuntimeFailure()
            elif encoded in raw:
                raise RuntimeFailure()


def complete_pass(returncode, raw, expected_tests=1):
    counts = re.findall(rb"OK \(([0-9]+) tests?\)", raw)
    return (returncode == 0 and counts == [str(expected_tests).encode()] and
            b"INSTRUMENTATION_CODE: -1" in raw and not any(marker in raw for marker in
            (b"FAILURES!!!", b"INSTRUMENTATION_FAILED", b"Process crashed", b"INSTRUMENTATION_ABORTED")))


def main():
    global STAGE, STATE
    root = Path(__file__).resolve().parents[1]
    sdk = Path(os.environ["ANDROID_HOME"])
    serial = os.environ["ANDROID_SERIAL"]
    if not re.fullmatch(r"emulator-[0-9]+", serial):
        raise RuntimeFailure()
    adb = [str(sdk / "platform-tools/adb"), "-s", serial]
    state = STATE = Path(tempfile.mkdtemp(prefix="locklark-android-runtime-"))
    log = (state / "controller.log").open("xb")
    os.chmod(log.name, 0o600)
    def command(arguments, *, private=False, timeout=60, required=True):
        result = subprocess.run(adb + arguments, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        if not private:
            log.write(result.stdout); log.write(result.stderr); log.flush()
        if required and result.returncode:
            raise RuntimeFailure()
        return result
    if command(["shell", "getprop", "ro.kernel.qemu"]).stdout.strip() != b"1" or command(["shell", "getprop", "sys.boot_completed"]).stdout.strip() != b"1":
        raise RuntimeFailure()
    package, test_package = "org.locklark.android", "org.locklark.android.test"
    STAGE = "install"
    command(["install", "-r", str(root / "app/build/outputs/apk/debug/app-debug.apk")], timeout=120)
    command(["install", "-r", str(root / "app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk")], timeout=120)
    if os.environ.get("LOCKLARK_ANDROID_TEST_RESET") != "1":
        raise RuntimeFailure()
    command(["shell", "pm", "clear", package]); command(["shell", "pm", "clear", test_package])
    runtime = (state / "runtime.log").open("xb")
    os.chmod(runtime.name, 0o600)
    logger = subprocess.Popen(adb + ["logcat", "-v", "brief"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    log_failed = threading.Event()
    def capture():
        written = 0
        try:
            while chunk := logger.stdout.read(4096):
                written += len(chunk)
                if written > 64 * 1024 * 1024:
                    log_failed.set(); logger.terminate(); break
                runtime.write(chunk)
        except Exception:
            log_failed.set()
    thread = threading.Thread(target=capture)
    thread.start()
    STAGE = "instrumentation"
    result = None
    try:
        result = command(["shell", "am", "instrument", "-w", "-r", test_package + "/androidx.test.runner.AndroidJUnitRunner"], timeout=900, required=False)
    except subprocess.TimeoutExpired as error:
        for data in (error.stdout, error.stderr):
            if data: log.write(data)
        command(["shell", "am", "force-stop", package], required=False)
    finally:
        logger.terminate()
        try: logger.wait(timeout=5)
        except subprocess.TimeoutExpired: logger.kill(); logger.wait()
        thread.join(timeout=5); runtime.close(); log.close()
    STAGE = "private-canary-scan"
    # The test APK alone writes this fixture in the target's private cache;
    # release app code has no fixture loader or secret-observation endpoint.
    canary = command(["exec-out", "run-as", package, "cat", "cache/instrumentation-canaries.json"], private=True, required=False)
    if canary.returncode:
        raise RuntimeFailure()
    values = json.loads(canary.stdout)
    for path in (state / "controller.log", state / "runtime.log"):
        scan_output(path.read_bytes(), values)
    if log_failed.is_set() or thread.is_alive():
        raise RuntimeFailure()
    STAGE = "complete-test-count"
    if result is None or not complete_pass(result.returncode, result.stdout):
        raise RuntimeFailure()
    command(["shell", "run-as", package, "rm", "cache/instrumentation-canaries.json"], private=True)
    print("PASS: Android native offline UI instrumentation; controller/logcat canary scan")
    print("Private Android runtime evidence: " + str(state))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("FAIL: Android native runtime validation at " + STAGE)
        if STATE is not None: print("Private Android runtime evidence: " + str(STATE))
        raise SystemExit(1)
