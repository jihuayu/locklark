#!/usr/bin/env bash
set -euo pipefail
umask 077
ios_dir="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$ios_dir/Build"
if python3 "$ios_dir/scripts/test_diagnostics.py" >"$ios_dir/Build/diagnostics-private.log" 2>&1; then echo "ios diagnostic privacy PASS"; else echo "ios diagnostic privacy FAIL"; exit 1; fi
if python3 "$ios_dir/scripts/test_simulator_selection.py" >"$ios_dir/Build/selection-tests-private.log" 2>&1; then echo "ios simulator selection tests PASS"; else echo "ios simulator selection tests FAIL"; exit 1; fi
if python3 "$ios_dir/scripts/test_ui_evidence.py" >"$ios_dir/Build/evidence-tests-private.log" 2>&1; then echo "ios UI evidence verifier tests PASS"; else echo "ios UI evidence verifier tests FAIL"; exit 1; fi
if python3 "$ios_dir/scripts/test_protection_probe.py" >"$ios_dir/Build/protection-reader-tests-private.log" 2>&1; then echo "ios protection metadata privacy PASS"; else echo "ios protection metadata privacy FAIL"; exit 1; fi
if "$ios_dir/scripts/build-core.sh" >"$ios_dir/Build/core-build-private.log" 2>&1; then echo "ios core build PASS"; else echo "ios core build FAIL"; exit 1; fi
if "$ios_dir/scripts/generate-project.sh" >"$ios_dir/Build/project-private.log" 2>&1; then echo "ios project PASS"; else echo "ios project FAIL"; exit 1; fi
if swift test --package-path "$ios_dir/SecurityLogic" --scratch-path "$ios_dir/Build/SecurityLogic" >"$ios_dir/Build/logic-private.log" 2>&1; then echo "ios logic PASS"; else echo "ios logic FAIL"; exit 1; fi
xcrun simctl list runtimes -j >"$ios_dir/Build/runtimes-private.json"
xcrun simctl list devices available -j >"$ios_dir/Build/devices-private.json"
if selection="$(python3 "$ios_dir/scripts/select-simulator.py" "$ios_dir/Build/runtimes-private.json" "$ios_dir/Build/devices-private.json" 2>"$ios_dir/Build/selection-private.log")"; then
  read -r runtime_id device_type <<<"$selection"
else
  echo "ios compatible simulator selection FAIL"
  exit 1
fi
simulator_id="$(xcrun simctl create "Locklark-CI-${GITHUB_RUN_ID:-local}-$$" "$device_type" "$runtime_id")"
trap 'xcrun simctl delete "$simulator_id" >/dev/null 2>&1 || true' EXIT
xcrun simctl boot "$simulator_id"
xcrun simctl bootstatus "$simulator_id" -b >"$ios_dir/Build/simulator-private.log" 2>&1
preflight_bundle="$ios_dir/Build/ProtectionPreflight-${GITHUB_RUN_ID:-local}-$(date +%s).xcresult"
preflight_exit=0
xcodebuild test -project "$ios_dir/Locklark.xcodeproj" -scheme Locklark -destination "platform=iOS Simulator,id=$simulator_id" -derivedDataPath "$ios_dir/Build/DerivedData" -resultBundlePath "$preflight_bundle" -only-testing:LocklarkTests/ProtectionPreflightTests/testNativeProtectionPreflight CODE_SIGNING_ALLOWED=NO >"$ios_dir/Build/protection-preflight-private.log" 2>&1 || preflight_exit=$?
metadata_exit=0
python3 "$ios_dir/scripts/read-protection-probe.py" "$ios_dir/Build/protection-preflight-private.log" || metadata_exit=$?
if [[ "$preflight_exit" -ne 0 || "$metadata_exit" -ne 0 ]]; then
  echo "ios native protection preflight FAIL"
  python3 "$ios_dir/scripts/summarize-failure.py" "$ios_dir/Build/protection-preflight-private.log"
  exit 1
fi
echo "ios native protection preflight PASS"
result_bundle="$ios_dir/Build/TestResults-${GITHUB_RUN_ID:-local}-$(date +%s).xcresult"
test_exit=0
xcodebuild test -project "$ios_dir/Locklark.xcodeproj" -scheme Locklark -destination "platform=iOS Simulator,id=$simulator_id" -derivedDataPath "$ios_dir/Build/DerivedData" -resultBundlePath "$result_bundle" CODE_SIGNING_ALLOWED=NO >"$ios_dir/Build/runtime-private.log" 2>&1 || test_exit=$?
privacy_exit=0
python3 "$ios_dir/scripts/verify-ui-evidence.py" --simulator "$simulator_id" --owned-simulator --runtime-log "$ios_dir/Build/runtime-private.log" --xcresult "$result_bundle" --test-exit-code "$test_exit" --artifacts "$ios_dir/Build/UIEvidence" || privacy_exit=$?
if [[ "$test_exit" -eq 0 && "$privacy_exit" -eq 0 ]]; then
  echo "ios simulator tests PASS"
else
  echo "ios simulator tests FAIL"
  python3 "$ios_dir/scripts/summarize-failure.py" "$ios_dir/Build/runtime-private.log"
  exit 1
fi
