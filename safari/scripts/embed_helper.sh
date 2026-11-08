#!/usr/bin/env bash
# Xcode build-phase helper. Only the containing macOS app calls this script,
# and it copies exactly one fixed helper name into the app bundle. No value
# here comes from Safari, a web page, a native frame or argv supplied at app
# launch time.
set -euo pipefail

source_path="${LOCKLARK_SAFARI_HELPER:-${SRCROOT:-.}/../dist/locklark-browser-safari}"
dest_dir="${BUILT_PRODUCTS_DIR:?}/${CONTENTS_FOLDER_PATH:?}/MacOS"
dest_path="${dest_dir}/locklark-browser-safari"

if [[ "${LOCKLARK_ALLOW_MISSING_HELPER:-0}" == "1" && "${CODE_SIGNING_ALLOWED:-YES}" == "NO" ]]; then
  if [[ ! -f "$source_path" ]]; then
    echo "warning: unsigned CI build has no Safari helper; runtime will report unavailable" >&2
    exit 0
  fi
fi

if [[ ! -f "$source_path" || ! -x "$source_path" ]]; then
  echo "error: fixed Safari helper is missing or not executable" >&2
  exit 1
fi
if [[ "$(basename "$source_path")" != "locklark-browser-safari" ]]; then
  echo "error: Safari helper basename must be locklark-browser-safari" >&2
  exit 1
fi

mkdir -p "$dest_dir"
install -m 0755 "$source_path" "$dest_path"

if [[ "${CODE_SIGNING_ALLOWED:-YES}" != "NO" ]]; then
  identity="${EXPANDED_CODE_SIGN_IDENTITY:-}"
  if [[ -z "$identity" || "$identity" == "-" ]]; then
    echo "error: signed build has no code-signing identity" >&2
    exit 1
  fi
  codesign --force --options runtime --timestamp \
    --sign "$identity" \
    --identifier "org.locklark.browser.safari.Helper" \
    "$dest_path"
fi
