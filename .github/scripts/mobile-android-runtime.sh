#!/usr/bin/env bash
# Run both independent base checks even if instrumentation fails. Credential
# checks require the exact completed host fixture, on the same owned emulator.
set -uo pipefail
result=0
ANDROID_SERIAL=emulator-5554 LOCKLARK_ANDROID_TEST_RESET=1 mobile/android/scripts/test-emulator.sh || result=1
if python3 scripts/mobile_android_acceptance.py \
  --adb "$ANDROID_HOME/platform-tools/adb" --serial emulator-5554 \
  --apk mobile/android/app/build/outputs/apk/debug/app-debug.apk \
  --reset-test-app --cli "$RUNNER_TEMP/locklark-mobile-peer" \
  --peer "$RUNNER_TEMP/mobile-kdbx-peer/bin/python" \
  --artifacts "$RUNNER_TEMP/mobile-host-evidence"; then
  mobile/android/scripts/test-device-credential.sh \
    --adb "$ANDROID_HOME/platform-tools/adb" --serial emulator-5554 \
    --apk mobile/android/app/build/outputs/apk/debug/app-debug.apk \
    --evidence-root "$RUNNER_TEMP/mobile-host-evidence" \
    --artifacts "$RUNNER_TEMP/mobile-auth-evidence" \
    --authorize-device-pin-setup || result=1
else
  result=1
fi
exit "$result"
