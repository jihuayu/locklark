#!/usr/bin/env bash
set -euo pipefail
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$repo_dir"
go_bin="$(command -v "${GO_BIN:-${LOCKLARK_GO:-go}}")"
go_bin="$(cd "$(dirname "$go_bin")" && pwd -P)/$(basename "$go_bin")"
python_bin="$(command -v python3)"
python_bin="$(cd "$(dirname "$python_bin")" && pwd -P)/$(basename "$python_bin")"
mobile_tools="${LOCKLARK_MOBILE_TOOLS:-${TMPDIR:-/tmp}/locklark-mobile-tools}"
export GOTOOLCHAIN="${GOTOOLCHAIN:-go$(awk '$1 == "go" { print $2; exit }' go.mod)}"
: "${ANDROID_HOME:?Set ANDROID_HOME to the Android SDK root}"
: "${JAVA_HOME:?Set JAVA_HOME to JDK 21 or newer}"
"$python_bin" "$repo_dir/mobile/core/scripts/source-manifest.py" --check-tool-dir --tools-dir "$mobile_tools/bin"
mkdir -p "$mobile_tools/bin" mobile/core/build
export PATH="$mobile_tools/bin:$(dirname "$go_bin"):$JAVA_HOME/bin:$PATH"
for tool in gobind gomobile; do
  # go.mod tool directive: builds the exact golang.org/x/mobile require version.
  GOBIN="$mobile_tools/bin" "$go_bin" install "golang.org/x/mobile/cmd/$tool"
done
GO_BIN="$go_bin" "$python_bin" mobile/core/scripts/source-manifest.py --check-tool-paths --tools-dir "$mobile_tools/bin"
"$mobile_tools/bin/gomobile" init
GO_BIN="$go_bin" "$python_bin" mobile/core/scripts/source-manifest.py --prepare --tools-dir "$mobile_tools/bin"
"$mobile_tools/bin/gomobile" bind -target=android/arm64,android/amd64 -androidapi 30 \
  -o mobile/core/build/mobilecore.aar ./mobile/core
GO_BIN="$go_bin" "$python_bin" mobile/core/scripts/source-manifest.py --after-build --tools-dir "$mobile_tools/bin"
