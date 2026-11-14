#!/usr/bin/env bash
set -euo pipefail
if [[ "$(uname -s)" != Darwin ]]; then
  echo "ios core build requires macOS and Xcode" >&2
  exit 1
fi
ios_dir="$(cd "$(dirname "$0")/.." && pwd)"
repo_dir="$(cd "$ios_dir/../.." && pwd)"
go_bin="${GO_BIN:-go}"
export GOTOOLCHAIN=go1.27.3
cd "$repo_dir"
tools="$ios_dir/Build/Tools"
MOBILE_BOOTSTRAP_REPO="$repo_dir" \
MOBILE_BOOTSTRAP_GO="$go_bin" \
MOBILE_BOOTSTRAP_TOOLS="$tools/bin" \
MOBILE_BOOTSTRAP_GOPATH="$ios_dir/Build/GOPATH" \
  source "$repo_dir/mobile/core/scripts/mobile-tool-bootstrap.sh"
# Verification is deliberately after init: init installs gobind, and must not
# overwrite the pinned tools with an implicit latest build.
python3 "$repo_dir/mobile/core/scripts/verify_mobile_tools.py" --go "$go_bin" \
  "$tools/bin/gomobile" "$tools/bin/gobind"
test "$(command -v gomobile)" = "$tools/bin/gomobile"
test "$(command -v gobind)" = "$tools/bin/gobind"
"$tools/bin/gomobile" bind -target=ios,iossimulator -iosversion=17.0 -prefix Mobilecore -trimpath -o "$ios_dir/Build/Mobilecore.xcframework" ./mobile/core
test -f "$ios_dir/Build/Mobilecore.xcframework/Info.plist"
echo "ios core XCFramework built"
