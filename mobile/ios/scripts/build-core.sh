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
export GOBIN="$ios_dir/Build/Tools"
export PATH="$GOBIN:$PATH"
mkdir -p "$GOBIN"
cd "$repo_dir"
for tool in gomobile gobind; do
  # go.mod tool directive: builds the exact golang.org/x/mobile require version.
  "$go_bin" install "golang.org/x/mobile/cmd/$tool"
done
gomobile init
gomobile bind -target=ios,iossimulator -iosversion=17.0 -prefix Mobilecore -trimpath -o "$ios_dir/Build/Mobilecore.xcframework" ./mobile/core
test -f "$ios_dir/Build/Mobilecore.xcframework/Info.plist"
echo "ios core XCFramework built"
