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
DIAGNOSTIC = {}

# Narrow real-OS Autofill fill gate: only AutofillHandoffTest, only the owned
# emulator, API 36, bounded UI timeout, prior autofill_service restored.
AUTOFILL_ONLY = os.environ.get("LOCKLARK_ANDROID_AUTOFILL_ONLY") == "1"
AUTOFILL_SERIAL = "emulator-5572"
AUTOFILL_API = "36"
AUTOFILL_TESTS = 2
AUTOFILL_TIMEOUT = 300


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


def complete_pass(returncode, raw, expected_tests=5):
    counts = re.findall(rb"OK \(([0-9]+) tests?\)", raw)
    summaries = re.findall(rb"(?<![\w.!])(?:OK \(([0-9]+) tests?\)|FAILURES!!! Tests run: ([0-9]+))", raw)
    return (returncode == 0 and counts == [str(expected_tests).encode()] and
            summaries == [(str(expected_tests).encode(), b"")] and
            b"INSTRUMENTATION_CODE: -1" in raw and not any(marker in raw for marker in
            (b"FAILURES!!!", b"INSTRUMENTATION_FAILED", b"Process crashed", b"INSTRUMENTATION_ABORTED")))


def safe_diagnostic(raw):
    allowed_steps = {"platform-fs", "binding-create", "binding-unlock", "capsule-storage", "bound-operation", "create", "add-login", "show-password", "edit-password", "edit-notes", "empty-fields", "edit-otp", "show-otp", "search", "cancel-edit", "generate-login", "regenerate", "exact-target", "platform-auth-refusal", "background-lock", "reopen", "late-unlock"}
    steps = re.findall(rb"INSTRUMENTATION_STATUS: locklark_stage=([a-z-]+)", raw)
    step = steps[-1].decode("ascii") if steps and steps[-1].decode("ascii") in allowed_steps else "unknown"
    exception = "unknown"
    for name in ("java.lang.AssertionError", "junit.framework.AssertionFailedError", "java.lang.IllegalStateException", "java.lang.UnsatisfiedLinkError", "java.lang.NullPointerException", "android.os.DeadObjectException", "android.system.ErrnoException", "java.lang.RuntimeException"):
        if name.encode() in raw: exception = name; break
    lines = re.findall(rb"(?:OfflineVaultTest|BoundOperationTest|AutofillHandoffTest)\.kt:([0-9]{1,5})\)", raw)
    waits = re.findall(rb"INSTRUMENTATION_STATUS: locklark_wait=([a-z-]+)", raw)
    allowed_waits = {"initial-create", "account-key", "new-vault-list", "native-control", "native-visible", "ime-hidden", "native-input", "native-input-focus", "native-input-exact", "login-metadata", "detail", "editor", "saved-list", "disclosure", "empty-username", "empty-notes", "platform-auth-refusal", "background-lock", "explicit-lock", "late-unlock", "other"}
    wait = waits[-1].decode() if waits and waits[-1].decode() in allowed_waits else "unknown"
    statuses = re.findall(rb"INSTRUMENTATION_STATUS: locklark_ui_status=([a-z-]+)", raw)
    allowed_status = {"operation-refused", "outcome-unknown", "backup-ack-required", "empty", "other"}
    status = statuses[-1].decode() if statuses and statuses[-1].decode() in allowed_status else "unknown"
    empty_context = {key:"unknown" for key in ("step", "wait", "ui_status", "core_phase", "core_error", "inputs_intact", "fs_owned", "fs_link", "fs_errno",
                                              "control", "control_phase", "ime", "ime_hide_requested", "window_focus", "control_visible", "control_enabled", "control_present", "control_focused", "input_active", "activity", "autofill_stage")}
    context = empty_context.copy()
    failures = []
    fields = ((b"INSTRUMENTATION_STATUS: locklark_stage=", "step", allowed_steps),
              (b"INSTRUMENTATION_STATUS: locklark_wait=", "wait", allowed_waits),
              (b"INSTRUMENTATION_STATUS: locklark_ui_status=", "ui_status", allowed_status),
              (b"INSTRUMENTATION_STATUS: locklark_core_phase=", "core_phase", {"operation", "capture", "create", "unlock", "refresh", "device_setup", "device_ready", "device_key", "device_cipher", "device_prompt", "device_wait", "device_aad", "device_crypto", "device_read", "device_write"}),
              (b"INSTRUMENTATION_STATUS: locklark_core_error=", "core_error", {"locked", "closed", "invalid", "conflict", "cancelled", "unknown", "expired", "unavailable", "exists", "capacity", "other"}),
              (b"INSTRUMENTATION_STATUS: locklark_inputs_intact=", "inputs_intact", {"true", "false"}),
              (b"INSTRUMENTATION_STATUS: locklark_fs_owned=", "fs_owned", {"true", "false"}),
              (b"INSTRUMENTATION_STATUS: locklark_fs_link=", "fs_link", {"true", "false"}),
              (b"INSTRUMENTATION_STATUS: locklark_fs_errno=", "fs_errno", {str(value) for value in range(4096)}),
              (b"INSTRUMENTATION_STATUS: locklark_control=", "control", {"generate-account-key", "backup-ack", "create-vault", "new-login", "generate-password", "save-login", "login-row", "show-password", "hide-secret", "edit-login", "save-field", "show-notes", "show-username", "show-otp", "back-to-list", "search", "cancel-edit", "regenerate-password", "confirm-regenerate", "enable-quick-unlock", "quick-unlock", "lock", "unlock", "new-master-password", "repeat-master-password", "login-title", "login-url", "login-username", "login-password", "edit-value", "query", "regenerate-length", "master-password", "secret-key"}),
              (b"INSTRUMENTATION_STATUS: locklark_control_phase=", "control_phase", {"ready", "ime-observe", "ime-dismiss", "ime-hidden", "ime-wait-hidden", "scroll", "offscreen", "visibility", "press", "released", "input-ready", "input-focus", "input-send", "input-exact"}),
              (b"INSTRUMENTATION_STATUS: locklark_ime=", "ime", {"true", "false"}),
              (b"INSTRUMENTATION_STATUS: locklark_ime_hide_requested=", "ime_hide_requested", {"true", "false"}),
              (b"INSTRUMENTATION_STATUS: locklark_window_focus=", "window_focus", {"true", "false"}),
              (b"INSTRUMENTATION_STATUS: locklark_control_visible=", "control_visible", {"true", "false"}),
              (b"INSTRUMENTATION_STATUS: locklark_control_enabled=", "control_enabled", {"true", "false"}),
              (b"INSTRUMENTATION_STATUS: locklark_control_present=", "control_present", {"true", "false"}),
              (b"INSTRUMENTATION_STATUS: locklark_control_focused=", "control_focused", {"true", "false"}),
              (b"INSTRUMENTATION_STATUS: locklark_input_active=", "input_active", {"true", "false"}),
              (b"INSTRUMENTATION_STATUS: locklark_activity=", "activity", {"DESTROYED", "INITIALIZED", "CREATED", "STARTED", "RESUMED"}),
              (b"INSTRUMENTATION_STATUS: locklark_autofill_stage=", "autofill_stage", {"preconditions", "fixture-create", "target-launch", "fill-request", "presentation-visible", "presentation-clicked", "auth-resumed", "auth-canceled", "fields-empty", "unlocked", "row-selected", "approved", "dataset-visible", "dataset-clicked", "fields-filled", "no-ui-disclosure"}))
    for line in raw.splitlines():
        for prefix, key, allowed in fields:
            if line.startswith(prefix):
                value = line[len(prefix):].decode("ascii", errors="replace")
                context[key] = value if value in allowed else "unknown"
        if line.strip() == b"INSTRUMENTATION_STATUS_CODE: 1":
            context = empty_context.copy()
        elif line.strip() in (b"INSTRUMENTATION_STATUS_CODE: -1", b"INSTRUMENTATION_STATUS_CODE: -2"):
            failures.append(context.copy())
    if failures:
        step, wait, status = (failures[0][key] for key in ("step", "wait", "ui_status"))
    counts = re.findall(rb"(?:Tests run: |OK \()([0-9]{1,3})", raw)
    return {"step": step, "wait": wait, "ui_status": status, "exception": exception, "own_source_line": int(lines[0]) if lines else 0, "own_source_lines": [int(line) for line in lines[:20]], "failed_contexts": failures[:10],
            "core_phase": failures[0]["core_phase"] if failures else context["core_phase"],
            "core_error": failures[0]["core_error"] if failures else context["core_error"],
            "inputs_intact": failures[0]["inputs_intact"] if failures else context["inputs_intact"],
            "fs_owned": failures[0]["fs_owned"] if failures else context["fs_owned"],
            "fs_link": failures[0]["fs_link"] if failures else context["fs_link"],
            "fs_errno": failures[0]["fs_errno"] if failures else context["fs_errno"],
            "autofill_stage": failures[0]["autofill_stage"] if failures else context["autofill_stage"],
            "tests_run": int(counts[-1]) if counts else 0,
            "process_crashed": b"Process crashed" in raw, "runner_aborted": b"INSTRUMENTATION_ABORTED" in raw}


def main():
    global STAGE, STATE, DIAGNOSTIC, cleanup_failed
    # Every call starts from the entry state, so a second run in one process
    # never inherits the previous run's stage, evidence, diagnosis or bool.
    STAGE, STATE, DIAGNOSTIC, cleanup_failed = "prerequisites", None, {}, False
    root = Path(__file__).resolve().parents[1]
    sdk = Path(os.environ["ANDROID_HOME"])
    serial = os.environ["ANDROID_SERIAL"]
    if not re.fullmatch(r"emulator-[0-9]+", serial):
        raise RuntimeFailure()
    if AUTOFILL_ONLY and serial != AUTOFILL_SERIAL:
        # The Autofill-only mode is bound to the one owned AVD and nothing else.
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
    if AUTOFILL_ONLY and command(["shell", "getprop", "ro.build.version.sdk"]).stdout.strip() != AUTOFILL_API.encode():
        raise RuntimeFailure()
    if command(["shell", "service", "check", "package"]).stdout.strip() != b"Service package: found":
        raise RuntimeFailure()
    package, test_package = "org.locklark.android", "org.locklark.android.test"
    STAGE = "install"
    command(["install", "-r", str(root / "app/build/outputs/apk/debug/app-debug.apk")], timeout=120)
    command(["install", "-t", "-r", str(root / "app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk")], timeout=120)
    if os.environ.get("LOCKLARK_ANDROID_TEST_RESET") != "1":
        raise RuntimeFailure()
    command(["shell", "pm", "clear", package]); command(["shell", "pm", "clear", test_package])
    autofill_service = package + "/" + package + ".autofill.AutofillAuthService"
    def secure_setting(arguments):
        setting = subprocess.run(
            adb + ["shell", "settings"] + arguments,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60,
        )
        if setting.returncode:
            raise RuntimeFailure()
        return setting.stdout.strip()
    def normalized_autofill():
        value = secure_setting(["get", "secure", "autofill_service"])
        return b"" if value in (b"", b"null") else value
    prior_autofill = normalized_autofill()
    # The primary is recorded by the except below; the finally runs the
    # restore and, when the primary already escaped, re-raises it unchanged.
    primary = None
    try:
        STAGE = "autofill-setting"
        secure_setting(["put", "secure", "autofill_service", autofill_service])
        if secure_setting(["get", "secure", "autofill_service"]) != autofill_service.encode():
            raise RuntimeFailure()
        run_gate(state, adb, root, package, test_package, log, autofill_only=AUTOFILL_ONLY)
    except BaseException as error:
        primary = error
        raise
    finally:
        # The module's fixed bool, read by the caller; the restore never
        # touches STAGE and never raises. Only an exception it did not catch
        # (KeyboardInterrupt, SystemExit) is recorded here as a failed
        # cleanup, so it is reported, not re-raised.
        try:
            cleanup_failed = restore_autofill(
                adb, secure_setting, normalized_autofill, prior_autofill, package, test_package)
        except BaseException:
            cleanup_failed = True
        globals()["cleanup_failed"] = cleanup_failed
        if primary is not None:
            # The runtime failure keeps its reached stage and its own
            # instance, even when the cleanup also failed.
            raise
        if cleanup_failed:
            # Cleanup only: the restore is the sole failure, so the caller
            # reports exactly that one stage; main() prints no failure page.
            globals()["STAGE"] = "autofill-setting-restore"
            return 1
    if AUTOFILL_ONLY:
        recovery = "PASS: Android real OS autofill approve -> Dataset -> exactly two bound fields; controller/logcat canary scan"
    else:
        recovery = "PASS: Android native offline UI instrumentation, real OS autofill authentication handoff; controller/logcat canary scan"
    print(recovery)
    print("Private Android runtime evidence: " + str(state))
    return 0


def restore_autofill(adb, secure_setting, normalized_autofill, prior_autofill, package, test_package):
    """Restore the exact prior Autofill service, then clear own app data.

    Returns the fixed cleanup_failed bool. Any exception, including an
    interrupt or exit request during the restore, is that failed bool; an
    interrupt or exit raised by the fake device itself is judged by main().
    """
    try:
        if prior_autofill:
            secure_setting(["put", "secure", "autofill_service", prior_autofill.decode("ascii")])
        else:
            secure_setting(["delete", "secure", "autofill_service"])
        if normalized_autofill() != prior_autofill:
            raise RuntimeFailure()
        if AUTOFILL_ONLY:
            for cleared in (package, test_package):
                try:
                    subprocess.run(adb + ["shell", "pm", "clear", cleared],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
                except subprocess.TimeoutExpired:
                    pass
    except (Exception, KeyboardInterrupt, SystemExit):
        # A cleanup that is interrupted or asked to exit reports a failed
        # cleanup; it never replaces the primary failure nor ends the run 0.
        return True
    return False


def run_gate(state, adb, root, package, test_package, log, *, autofill_only=False):
    global STAGE, DIAGNOSTIC
    runtime = (state / "runtime.log").open("xb")
    os.chmod(runtime.name, 0o600)
    def command(arguments, *, private=False, timeout=60, required=True):
        result = subprocess.run(adb + arguments, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        if not private:
            log.write(result.stdout); log.write(result.stderr); log.flush()
        if required and result.returncode:
            raise RuntimeFailure()
        return result
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
    if autofill_only:
        selected = "org.locklark.android.AutofillHandoffTest"
        timeout = AUTOFILL_TIMEOUT
    else:
        selected = "org.locklark.android.BoundOperationTest,org.locklark.android.OfflineVaultTest,org.locklark.android.AutofillHandoffTest"
        timeout = 900
    try:
        result = command(["shell", "am", "instrument", "-w", "-r", "-e", "class", selected, test_package + "/androidx.test.runner.AndroidJUnitRunner"], timeout=timeout, required=False)
    except subprocess.TimeoutExpired as error:
        for data in (error.stdout, error.stderr):
            if data: log.write(data)
        command(["shell", "am", "force-stop", package], required=False)
    finally:
        logger.terminate()
        try: logger.wait(timeout=5)
        except subprocess.TimeoutExpired: logger.kill(); logger.wait()
        thread.join(timeout=5); runtime.close(); log.close()
    DIAGNOSTIC = safe_diagnostic(result.stdout if result is not None else b"")
    STAGE = "private-canary-scan"
    # The test APK alone writes this fixture in the target's private cache;
    # release app code has no fixture loader or secret-observation endpoint.
    canary = command(["exec-out", "run-as", package, "cat", "cache/instrumentation-canaries.json"], private=True, required=False)
    if canary.returncode:
        raise RuntimeFailure()
    values = json.loads(canary.stdout)
    with os.fdopen(os.open(state / "fixture.json", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "wb") as private_fixture:
        private_fixture.write(canary.stdout)
    for path in (state / "controller.log", state / "runtime.log"):
        scan_output(path.read_bytes(), values)
    if log_failed.is_set() or thread.is_alive():
        raise RuntimeFailure()
    STAGE = "complete-test-count"
    # BoundOperationTest 1 + OfflineVaultTest 3 + AutofillHandoffTest 2.
    expected_tests = AUTOFILL_TESTS if autofill_only else 6
    if result is None or not complete_pass(result.returncode, result.stdout, expected_tests):
        raise RuntimeFailure()
    command(["shell", "run-as", package, "rm", "cache/instrumentation-canaries.json"], private=True)


def entrypoint():
    """Run the gate once and report: returns the exit code, prints one page.

    A runtime failure keeps its own reached STAGE and instance; a cleanup-only
    failure has already set STAGE to the restore. Only main() returns 0, and
    only when nothing above failed, so an exit request during cleanup (which
    main() records as a failure and does not re-raise) is never a success.
    """
    try:
        code = main()
    except BaseException:
        # Exception, KeyboardInterrupt or SystemExit: all are a failure page.
        code = 1
    if code != 0:
        print("FAIL: Android native runtime validation at " + STAGE)
        print("Fixed Android runtime diagnosis: " + json.dumps(DIAGNOSTIC, sort_keys=True))
        print("Android autofill setting restore failed: " + str(cleanup_failed).lower())
        if STATE is not None: print("Private Android runtime evidence: " + str(STATE))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(entrypoint())
