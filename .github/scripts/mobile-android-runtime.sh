#!/usr/bin/env bash
# Run both independent runtime checks on the owned synthetic emulator, even if
# the first fails. Both tools keep fixture-bearing outputs private.
set -uo pipefail
result=0
ANDROID_SERIAL=emulator-5554 LOCKLARK_ANDROID_TEST_RESET=1 mobile/android/scripts/test-emulator.sh || result=1
python3 scripts/mobile_android_acceptance.py \
  --adb "$ANDROID_HOME/platform-tools/adb" --serial emulator-5554 \
  --apk mobile/android/app/build/outputs/apk/debug/app-debug.apk \
  --reset-test-app --cli "$RUNNER_TEMP/locklark-mobile-peer" \
  --peer "$RUNNER_TEMP/mobile-kdbx-peer/bin/python" || result=1
exit "$result"
