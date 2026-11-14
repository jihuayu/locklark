#!/usr/bin/env bash
set -euo pipefail
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$repo_dir"
go_bin="${GO_BIN:-${LOCKLARK_GO:-go}}"
mobile_tools="${LOCKLARK_MOBILE_TOOLS:-${TMPDIR:-/tmp}/locklark-mobile-tools}"
export GOTOOLCHAIN="${GOTOOLCHAIN:-go$(awk '$1 == "go" { print $2; exit }' go.mod)}"
export PATH="$(dirname "$(command -v "$go_bin")"):$mobile_tools/bin:$PATH"
: "${ANDROID_HOME:?Set ANDROID_HOME to the Android SDK root}"
: "${JAVA_HOME:?Set JAVA_HOME to JDK 21 or newer}"
export PATH="$JAVA_HOME/bin:$PATH"
mkdir -p "$mobile_tools/bin" mobile/core/build
MOBILE_BOOTSTRAP_REPO="$repo_dir" \
MOBILE_BOOTSTRAP_GO="$go_bin" \
MOBILE_BOOTSTRAP_TOOLS="$mobile_tools/bin" \
MOBILE_BOOTSTRAP_GOPATH="$mobile_tools/gopath" \
  source "$repo_dir/mobile/core/scripts/mobile-tool-bootstrap.sh"
python3 "$repo_dir/mobile/core/scripts/verify_mobile_tools.py" --go "$go_bin" \
  "$mobile_tools/bin/gomobile" "$mobile_tools/bin/gobind"
test "$(command -v gomobile)" = "$mobile_tools/bin/gomobile"
test "$(command -v gobind)" = "$mobile_tools/bin/gobind"
GO_BIN="$go_bin" python3 mobile/core/scripts/source-manifest.py --prepare
"$mobile_tools/bin/gomobile" bind -target=android/arm64,android/amd64 -androidapi 30 \
  -o mobile/core/build/mobilecore.aar ./mobile/core
GO_BIN="$go_bin" python3 mobile/core/scripts/source-manifest.py --after-build
