#!/usr/bin/env bash
# Build the Safari package. A signed build requires a real Team ID, the fixed
# app group and a helper signed by that same team. An unsigned CI compile is
# allowed only when LOCKLARK_UNSIGNED_CI=1; it is NOT an installed or signed
# Safari build and does not prove Safari can load it.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SAFARI="$ROOT/safari"
FIXED_APP_GROUP="group.org.locklark.browser.safari"
TEAM="${LOCKLARK_TEAM_ID:-}"
GROUP="${LOCKLARK_APP_GROUP_ID:-$FIXED_APP_GROUP}"
UNSIGNED="${LOCKLARK_UNSIGNED_CI:-0}"
HELPER="${LOCKLARK_SAFARI_HELPER:-$ROOT/dist/locklark-browser-safari}"
ALLOW_MISSING_HELPER="${LOCKLARK_ALLOW_MISSING_HELPER:-0}"
REQUIRE_PREBUILT="${LOCKLARK_BROWSER_REQUIRE_PREBUILT:-0}"
PREPARED_DIR="${LOCKLARK_BROWSER_EXTENSION_PREPARED_DIR:-}"
CHROMIUM_DIR="${LOCKLARK_BROWSER_EXTENSION_CHROMIUM:-}"
FIREFOX_DIR="${LOCKLARK_BROWSER_EXTENSION_FIREFOX:-}"
SAFARI_DIR="${LOCKLARK_BROWSER_EXTENSION_SAFARI:-}"

fail() {
  echo "error: $*" >&2
  exit 1
}

case "$UNSIGNED" in
  0|1) ;;
  *) fail "LOCKLARK_UNSIGNED_CI must be 0 or 1" ;;
esac

if [[ "$UNSIGNED" == "0" ]]; then
  [[ -n "$TEAM" ]] || fail "LOCKLARK_TEAM_ID is required for a signed build"
  [[ "$TEAM" =~ ^[A-Z0-9]{10}$ ]] || fail "LOCKLARK_TEAM_ID must be 10 uppercase alphanumerics"
  [[ "$GROUP" == "$FIXED_APP_GROUP" ]] || fail "LOCKLARK_APP_GROUP_ID must be $FIXED_APP_GROUP"
  case "$TEAM$GROUP" in
    *REPLACE*|*CHANGEME*|*YOUR_*|*PLACEHOLDER*|*EXAMPLE*|*TEAMID*|*TEAM_ID*|*UNSIGNED*)
      fail "Team ID/app group placeholder is not accepted for a signed build"
      ;;
  esac
else
  TEAM="${TEAM:-UNSIGNEDCI0}"
  [[ "$GROUP" == "$FIXED_APP_GROUP" ]] || fail "LOCKLARK_APP_GROUP_ID must be $FIXED_APP_GROUP"
  echo "warning: unsigned CI compile only; this is not an installed/signed Safari package" >&2
fi

command -v python3 >/dev/null 2>&1 || fail "python3 is required"

# The prebuilt branch consumes one producer's real browserrelease pairs and
# unpacked outputs. It is all-or-nothing: no partial product, missing env,
# alternate path or fallback to build.js is accepted. The three directories
# must be the exact dist directories the Xcode project already references.
case "$REQUIRE_PREBUILT" in
  0|1) ;;
  *) fail "LOCKLARK_BROWSER_REQUIRE_PREBUILT must be 0 or 1" ;;
esac
if [[ "$REQUIRE_PREBUILT" == "1" ]]; then
  [[ -n "$PREPARED_DIR" && -d "$PREPARED_DIR" ]] \
    || fail "LOCKLARK_BROWSER_EXTENSION_PREPARED_DIR is required and must exist"
  for product in chromium firefox safari; do
    case "$product" in
      chromium) dir="$CHROMIUM_DIR" ;;
      firefox) dir="$FIREFOX_DIR" ;;
      safari) dir="$SAFARI_DIR" ;;
    esac
    expected="$ROOT/browser-extension/dist/$product"
    [[ -n "$dir" && -d "$dir" ]] \
      || fail "LOCKLARK_BROWSER_EXTENSION_${product^^} is required and must exist"
    [[ "$(cd "$dir" && pwd -P)" == "$(cd "$expected" && pwd -P)" ]] \
      || fail "LOCKLARK_BROWSER_EXTENSION_${product^^} must be $expected"
  done
  for product in chromium firefox safari; do
    PYTHONPATH="$ROOT/scripts" python3 -m browserrelease.prebuilt \
      --product "$product" --prepared-dir "$PREPARED_DIR" \
      --dist "$ROOT/browser-extension/dist/$product" --root "$ROOT" \
      || fail "strict prebuilt verification failed for $product"
  done
else
  command -v node >/dev/null 2>&1 || fail "node is required"
  # Developer path: keep the original default Chromium + Firefox baseline and
  # explicit Safari build order. No prebuilt env is consulted here.
  node "$ROOT/browser-extension/build.js"
  node "$ROOT/browser-extension/build.js" safari
fi
python3 "$ROOT/scripts/test_safari_package.py" --verify-dist

if [[ -f "$HELPER" && -x "$HELPER" ]]; then
  [[ "$(basename "$HELPER")" == "locklark-browser-safari" ]] \
    || fail "helper basename must be locklark-browser-safari"
  if [[ "$UNSIGNED" == "0" ]]; then
    helper_team="$(codesign -dv --verbose=4 "$HELPER" 2>&1 | awk -F= '/^TeamIdentifier=/{print $2; exit}')"
    [[ "$helper_team" == "$TEAM" ]] \
      || fail "helper is not signed by the configured Team ID"
  fi
else
  [[ "$UNSIGNED" == "1" && "$ALLOW_MISSING_HELPER" == "1" ]] \
    || fail "fixed Safari helper is missing; build it or set LOCKLARK_SAFARI_HELPER"
  echo "warning: compiling without the Safari helper; runtime reports unavailable" >&2
fi

command -v xcodegen >/dev/null 2>&1 || fail "xcodegen is required"
command -v xcodebuild >/dev/null 2>&1 || fail "xcodebuild is required"

xcodegen generate --spec "$SAFARI/project.yml" --project "$SAFARI"

XCODE_ARGS=(
  -project "$SAFARI/LocklarkSafari.xcodeproj"
  -scheme LocklarkSafari
  -configuration Release
  -derivedDataPath "$SAFARI/build"
  "LOCKLARK_TEAM_ID=$TEAM"
  "LOCKLARK_APP_GROUP_ID=$GROUP"
  "LOCKLARK_APP_BUNDLE_ID=org.locklark.browser.safari"
  "LOCKLARK_EXTENSION_BUNDLE_ID=org.locklark.browser.safari.Extension"
  "LOCKLARK_SAFARI_HELPER=$HELPER"
)
if [[ "$UNSIGNED" == "1" ]]; then
  XCODE_ARGS+=(
    CODE_SIGNING_ALLOWED=NO
    CODE_SIGNING_REQUIRED=NO
    "LOCKLARK_ALLOW_MISSING_HELPER=$ALLOW_MISSING_HELPER"
  )
else
  XCODE_ARGS+=(
    CODE_SIGN_STYLE=Manual
    "CODE_SIGN_IDENTITY=${LOCKLARK_SIGNING_IDENTITY:-Apple Development}"
    "DEVELOPMENT_TEAM=$TEAM"
  )
fi

xcodebuild "${XCODE_ARGS[@]}" build

echo "Built Safari app at $SAFARI/build/Build/Products/Release/Locklark.app"
if [[ "$UNSIGNED" == "1" ]]; then
  echo "warning: unsigned output is compile-only and cannot be installed as a Safari extension" >&2
fi
