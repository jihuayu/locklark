#!/usr/bin/env bash
# Foundation-only Swift tests for framing, envelopes, identity, peer policy and
# path policy. Requires macOS/Xcode; this repository's Linux worker cannot run
# it and must not claim that it did.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
if ! command -v swift >/dev/null 2>&1; then
  echo "skip: swift toolchain unavailable; Swift tests were not run" >&2
  exit 0
fi
if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "skip: macOS/Xcode is required for the Safari Swift tests" >&2
  exit 0
fi
swift test --package-path "$ROOT/safari"

# Standalone native probe (its own process, SIGPIPE at SIG_DFL): a closed-peer
# socket write and a closed-pipe write must return the fixed failure instead of
# terminating the process, and the caller thread mask must be restored.
swift build --package-path "$ROOT/safari" --product LocklarkSafariSIGPipeProbe
BIN_DIR="$(swift build --package-path "$ROOT/safari" --show-bin-path)"
"$BIN_DIR/LocklarkSafariSIGPipeProbe"
