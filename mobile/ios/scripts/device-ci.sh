#!/usr/bin/env bash
set -euo pipefail
umask 077
if [[ "$(uname -s)" != Darwin ]]; then
  echo "ios physical acceptance requires macOS and Xcode" >&2
  exit 1
fi
ios_dir="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$ios_dir/Build"
mkdir -p "$ios_dir/Build/DeviceRuns"
run_dir="$(mktemp -d "$ios_dir/Build/DeviceRuns/run.XXXXXXXX")"
chmod 700 "$run_dir"
if python3 "$ios_dir/scripts/test_device_policy.py" >"$run_dir/policy-tests-private.log" 2>&1; then echo "ios physical policy tests PASS"; else echo "ios physical policy tests FAIL"; exit 1; fi
if python3 "$ios_dir/scripts/test_diagnostics.py" >"$run_dir/diagnostic-tests-private.log" 2>&1; then echo "ios physical diagnostic privacy PASS"; else echo "ios physical diagnostic privacy FAIL"; exit 1; fi
if python3 "$ios_dir/scripts/test_ui_evidence.py" >"$run_dir/evidence-tests-private.log" 2>&1; then echo "ios physical evidence verifier tests PASS"; else echo "ios physical evidence verifier tests FAIL"; exit 1; fi
python3 "$ios_dir/scripts/device-preflight.py"
device_id="$IOS_DEVICE_ID"
bundle_base="$IOS_TEST_BUNDLE_BASE"
signing_team="$IOS_DEVELOPMENT_TEAM"
if ! xcrun devicectl device info apps --device "$device_id" --json-output "$run_dir/device-apps-private.json" >"$run_dir/device-discovery-private.log" 2>&1; then
  echo "ios paired physical device inventory FAIL"
  exit 1
fi
python3 "$ios_dir/scripts/device-preflight.py" "$run_dir/device-apps-private.json"
if "$ios_dir/scripts/build-core.sh" >"$run_dir/device-core-build-private.log" 2>&1; then echo "ios physical core build PASS"; else echo "ios physical core build FAIL"; exit 1; fi
if "$ios_dir/scripts/generate-project.sh" >"$run_dir/device-project-private.log" 2>&1; then echo "ios physical project PASS"; else echo "ios physical project FAIL"; exit 1; fi
if swift test --package-path "$ios_dir/SecurityLogic" --scratch-path "$ios_dir/Build/DeviceSecurityLogic" >"$run_dir/device-logic-private.log" 2>&1; then echo "ios physical logic PASS"; else echo "ios physical logic FAIL"; exit 1; fi
result_bundle="$run_dir/DeviceResults.xcresult"
runtime_log="$run_dir/device-runtime-private.log"
test_exit=0
# Uses only the host's already configured Xcode account/certificates/profiles.
# No provisioning-update, credential-import, app-delete or device-reset action.
xcodebuild test -project "$ios_dir/Locklark.xcodeproj" -scheme Locklark -destination "platform=iOS,id=$device_id" -derivedDataPath "$ios_dir/Build/DeviceDerivedData" -resultBundlePath "$result_bundle" DEVELOPMENT_TEAM="$signing_team" LOCKLARK_BUNDLE_BASE="$bundle_base" CODE_SIGN_STYLE=Automatic CODE_SIGNING_ALLOWED=YES >"$runtime_log" 2>&1 || test_exit=$?
privacy_exit=0
python3 "$ios_dir/scripts/verify-ui-evidence.py" --device "$device_id" --runner-bundle "$bundle_base.uitests.xctrunner" --runtime-log "$runtime_log" --xcresult "$result_bundle" --test-exit-code "$test_exit" --artifacts "$run_dir/DeviceUIEvidence" || privacy_exit=$?
if [[ "$test_exit" -eq 0 && "$privacy_exit" -eq 0 ]]; then
  echo "ios signed physical full-positive acceptance PASS"
else
  echo "ios signed physical full-positive acceptance FAIL"
  python3 "$ios_dir/scripts/summarize-failure.py" "$runtime_log"
  exit 1
fi
