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
