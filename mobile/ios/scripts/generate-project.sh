#!/usr/bin/env bash
set -euo pipefail
ios_dir="$(cd "$(dirname "$0")/.." && pwd)"
tools_dir="$ios_dir/Build/Tools/XcodeGen-2.46.0"
archive="$tools_dir/xcodegen.zip"
mkdir -p "$tools_dir"
if [[ ! -x "$tools_dir/xcodegen/bin/xcodegen" ]]; then
  curl --fail --location --silent --show-error https://github.com/yonaskolb/XcodeGen/releases/download/2.46.0/xcodegen.zip --output "$archive"
  echo "4d9e34b62172d645eed6457cac13fc222569974098ef4ee9c3368bedf0196806  $archive" | shasum -a 256 --check --status
  unzip -q -o "$archive" -d "$tools_dir"
fi
"$tools_dir/xcodegen/bin/xcodegen" generate --spec "$ios_dir/project.yml" --project "$ios_dir"
