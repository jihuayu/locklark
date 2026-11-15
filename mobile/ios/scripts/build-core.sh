#!/usr/bin/env bash
set -euo pipefail
if [[ "$(uname -s)" != Darwin ]]; then
  echo "ios core build requires macOS and Xcode" >&2
  exit 1
fi
ios_dir="$(cd "$(dirname "$0")/.." && pwd)"
repo_dir="$(cd "$ios_dir/../.." && pwd)"
# Keep the selected Go executable stable when the task-local tools lead PATH.
go_bin="$(command -v "${GO_BIN:-go}")"
go_bin="$(cd "$(dirname "$go_bin")" && pwd -P)/$(basename "$go_bin")"
python_bin="$(command -v python3)"
python_bin="$(cd "$(dirname "$python_bin")" && pwd -P)/$(basename "$python_bin")"
export GOTOOLCHAIN=go1.27.3
export GOBIN="$ios_dir/Build/Tools"
"$python_bin" "$repo_dir/mobile/core/scripts/source-manifest.py" --check-tool-dir --tools-dir "$GOBIN"
mkdir -p "$GOBIN"
export PATH="$GOBIN:$(dirname "$go_bin"):$PATH"
cd "$repo_dir"
for tool in gomobile gobind; do
  # go.mod tool directive: builds the exact golang.org/x/mobile require version.
  "$go_bin" install "golang.org/x/mobile/cmd/$tool"
done
GO_BIN="$go_bin" "$python_bin" mobile/core/scripts/source-manifest.py --check-tool-paths --tools-dir "$GOBIN"
"$GOBIN/gomobile" init
"$GOBIN/gomobile" bind -target=ios,iossimulator -iosversion=17.0 -prefix Mobilecore -trimpath -o "$ios_dir/Build/Mobilecore.xcframework" ./mobile/core
test -f "$ios_dir/Build/Mobilecore.xcframework/Info.plist"
echo "ios core XCFramework built"
