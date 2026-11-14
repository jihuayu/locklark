#!/usr/bin/env bash
set -euo pipefail
android_root="$(cd "$(dirname "$0")/.." && pwd)"
: "${JAVA_HOME:?Set JAVA_HOME to a JDK 21 installation}"
: "${ANDROID_HOME:?Set ANDROID_HOME to an Android SDK with platform 36 and build-tools 36.0.0}"
export ANDROID_SDK_ROOT="$ANDROID_HOME"
if [[ ! -x "$JAVA_HOME/bin/javac" ]]; then
  echo 'A complete JDK is required.' >&2
  exit 1
fi
if [[ $# -eq 0 ]]; then
  set -- :policy:test :app:testDebugUnitTest :app:assembleDebug :app:assembleDebugAndroidTest
fi
exec "$android_root/gradlew" -p "$android_root" --no-daemon "$@"
