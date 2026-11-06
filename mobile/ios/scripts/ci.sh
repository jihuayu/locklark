#!/usr/bin/env bash
set -euo pipefail
ios_dir="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$ios_dir/Build"
if "$ios_dir/scripts/build-core.sh" >"$ios_dir/Build/core-build-private.log" 2>&1; then echo "ios core build PASS"; else echo "ios core build FAIL"; exit 1; fi
if "$ios_dir/scripts/generate-project.sh" >"$ios_dir/Build/project-private.log" 2>&1; then echo "ios project PASS"; else echo "ios project FAIL"; exit 1; fi
if swift test --package-path "$ios_dir/SecurityLogic" --scratch-path "$ios_dir/Build/SecurityLogic" >"$ios_dir/Build/logic-private.log" 2>&1; then echo "ios logic PASS"; else echo "ios logic FAIL"; exit 1; fi
runtime_id="$(xcrun simctl list runtimes -j | python3 -c 'import json,sys; r=[r for r in json.load(sys.stdin)["runtimes"] if r.get("isAvailable") and "iOS" in r["name"]]; print(sorted(r,key=lambda r:tuple(map(int,r["version"].split("."))))[-1]["identifier"])')"
device_type="$(xcrun simctl list devicetypes -j | python3 -c 'import json,sys; d=[d for d in json.load(sys.stdin)["devicetypes"] if d["name"].startswith("iPhone")]; print(d[-1]["identifier"])')"
simulator_id="$(xcrun simctl create "Locklark-CI-${GITHUB_RUN_ID:-local}-$$" "$device_type" "$runtime_id")"
trap 'xcrun simctl delete "$simulator_id" >/dev/null 2>&1 || true' EXIT
xcrun simctl boot "$simulator_id"
xcrun simctl bootstatus "$simulator_id" -b
if xcodebuild test -project "$ios_dir/Locklark.xcodeproj" -scheme Locklark -destination "platform=iOS Simulator,id=$simulator_id" -derivedDataPath "$ios_dir/Build/DerivedData" -resultBundlePath "$ios_dir/Build/TestResults.xcresult" CODE_SIGNING_ALLOWED=NO >"$ios_dir/Build/runtime-private.log" 2>&1; then
  echo "ios simulator tests PASS"
else
  echo "ios simulator tests FAIL"
  exit 1
fi
