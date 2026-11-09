#!/usr/bin/env bash
# Signed, notarized macOS build of the native desktop app.
#
# Requires an Apple Developer Program identity, a Developer ID provisioning
# profile that authorizes app.locklark.desktop and its keychain-access-groups,
# and (optionally) notarytool credentials. An ad-hoc build cannot use the
# data-protection keychain: Security.framework returns errSecMissingEntitlement
# (-34018), so Touch ID quick unlock and passkey user verification stay
# unavailable. See macos/README.md.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

fail() {
  echo "error: $*" >&2
  exit 1
}

identity="${LOCKLARK_MACOS_SIGNING_IDENTITY:-}"
[[ -n "$identity" ]] || fail "set LOCKLARK_MACOS_SIGNING_IDENTITY to a Developer ID Application identity"

team="${LOCKLARK_TEAM_ID:-}"
if [[ -z "$team" ]]; then
  team="$(sed -n 's/.*(\([A-Z0-9]\{10\}\))[[:space:]]*$/\1/p' <<<"$identity")"
fi
[[ "$team" =~ ^[A-Z0-9]{10}$ ]] || fail "LOCKLARK_TEAM_ID must be 10 uppercase letters/digits (or include (TEAMID) in the identity)"

profile="${LOCKLARK_MACOS_PROVISIONING_PROFILE:-}"
[[ -n "$profile" ]] || fail "set LOCKLARK_MACOS_PROVISIONING_PROFILE to a Developer ID provisioning profile"
[[ -f "$profile" ]] || fail "provisioning profile not found: $profile"

out="${LOCKLARK_BUILD_DIR:-$ROOT/.mygo-release}"
mkdir -p "$out"
entitlements="$out/locklark.entitlements.plist"
sed "s/TEAMID/$team/g" macos/locklark.entitlements.plist.template >"$entitlements"

# MyGo defaults to CGO_ENABLED=0. The macOS quick-unlock adapter is cgo code
# (Security.framework + LocalAuthentication); without cgo the app silently
# falls back to the "system unlock unavailable" build. Pin the native SDK so a
# mixed Xcode/CLT installation does not pick a mismatched sysroot either.
export CGO_ENABLED=1
if [[ -z "${SDKROOT:-}" ]]; then
  export SDKROOT="$(xcrun --sdk macosx --show-sdk-path)"
fi
if [[ -z "${CGO_CFLAGS:-}" ]]; then
  export CGO_CFLAGS="-isysroot $SDKROOT"
fi
if [[ -z "${CGO_LDFLAGS:-}" ]]; then
  export CGO_LDFLAGS="-isysroot $SDKROOT"
fi

export LOCKLARK_MACOS_ENTITLEMENTS="$entitlements"
export LOCKLARK_MACOS_PROVISIONING_PROFILE="$profile"
if [[ -n "${LOCKLARK_NOTARY_PROFILE:-}" ]]; then
  export LOCKLARK_NOTARY_PROFILE
fi

# Pin the packaging CLI to the MyGo version in go.mod. The TypeScript config is
# evaluated by Bun or Node; no npm dependency is needed.
exec go run github.com/egoist/mygo/cmd/mygo@v0.7.4 build \
  --platform "${LOCKLARK_PLATFORM:-darwin/universal}" "$@"
