#!/usr/bin/env bash
# Offline checks for a Locklark.app that is supposed to use the macOS data
# protection keychain. This cannot prove Touch ID works (that needs a real
# signed app and a human), but it catches the common packaging mistakes first:
# ad-hoc signing, a missing Team ID, no keychain-access-groups entitlement, no
# embedded provisioning profile, or a Gatekeeper rejection.
set -euo pipefail

app="${1:-}"
if [[ -z "$app" ]]; then
  echo "usage: $0 /Applications/Locklark.app" >&2
  exit 2
fi
if [[ ! -d "$app" ]]; then
  echo "error: app bundle not found: $app" >&2
  exit 2
fi

status=0
pass() { printf 'PASS  %s\n' "$*"; }
fail() { printf 'FAIL  %s\n' "$*"; status=1; }
note() { printf 'NOTE  %s\n' "$*"; }

info="$(codesign -dv --verbose=4 "$app" 2>&1 || true)"
if grep -q '^Signature=adhoc' <<<"$info"; then
  fail "ad-hoc signature; Touch ID keychain items need a Developer ID signature"
else
  pass "not ad-hoc"
fi
team="$(sed -n 's/^TeamIdentifier=//p' <<<"$info" | head -1)"
if [[ -z "$team" || "$team" == "not set" ]]; then
  fail "no TeamIdentifier; a self-signed certificate cannot authorize keychain-access-groups"
else
  pass "TeamIdentifier=$team"
fi
if codesign --verify --deep --strict "$app" >/dev/null 2>&1; then
  pass "codesign --verify --deep --strict"
else
  fail "codesign verification failed"
fi

entitlements="$(codesign -d --entitlements :- "$app" 2>/dev/null || true)"
if grep -q 'keychain-access-groups' <<<"$entitlements"; then
  pass "keychain-access-groups entitlement present"
else
  fail "keychain-access-groups entitlement missing"
fi
if [[ -f "$app/Contents/embedded.provisionprofile" ]]; then
  pass "embedded.provisionprofile present"
  profile="$(mktemp)"
  trap 'rm -f "$profile"' EXIT
  if security cms -D -i "$app/Contents/embedded.provisionprofile" >"$profile" 2>/dev/null; then
    if grep -q 'keychain-access-groups' "$profile"; then
      pass "provisioning profile authorizes keychain-access-groups"
    else
      fail "provisioning profile does not mention keychain-access-groups"
    fi
  else
    fail "embedded.provisionprofile is not a readable CMS profile"
  fi
else
  fail "embedded.provisionprofile missing; Developer ID keychain groups require a profile"
fi

if spctl -a -vv "$app" >/dev/null 2>&1; then
  pass "Gatekeeper assessment"
else
  note "Gatekeeper assessment did not pass (expected before notarization/stapling)"
fi
if xcrun stapler validate "$app" >/dev/null 2>&1; then
  pass "notarization ticket stapled"
else
  note "no stapled notarization ticket"
fi

echo
if ((status == 0)); then
  echo "Static checks passed. Now complete the signed Touch ID acceptance in macos/README.md."
else
  echo "Static checks failed; fix the FAIL lines before testing Touch ID." >&2
fi
exit "$status"
