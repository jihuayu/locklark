#!/usr/bin/env bash
set -euo pipefail
repo=$(cd "$(dirname "$0")/../../.." && pwd)
tmp=$(mktemp -d /private/tmp/mobile-tool-bootstrap-test.XXXXXX)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
fake_go="$tmp/fake-go"
cat > "$fake_go" <<'GO'
#!/usr/bin/env bash
set -euo pipefail
if [ "${1:-}" = env ] && [ "${2:-}" = GOMODCACHE ]; then
  printf '%s\n' "$FAKE_GOMODCACHE"
  exit 0
fi
if [ "${1:-}" = install ]; then
  mkdir -p "$GOBIN"
  cat > "$GOBIN/gomobile" <<'GOM'
#!/usr/bin/env bash
printf 'init\n' >> "$INIT_LOG"
GOM
  chmod 0755 "$GOBIN/gomobile"
  exit 0
fi
exit 1
GO
chmod 0755 "$fake_go"

run_shape() {
  local shape=$1
  local caller_tools="$tmp/$shape/Tools"
  local caller_repo="$repo"
  local caller_go="$fake_go"
  local init_log="$tmp/$shape-init.log"
  mkdir -p "$caller_tools"
  (
    set -euo pipefail
    tools="$caller_tools"
    repo_dir="$caller_repo"
    go_bin="$caller_go"
    export FAKE_GOMODCACHE="$tmp/$shape-modcache"
    export INIT_LOG="$init_log"
    export MOBILE_BOOTSTRAP_REPO="$repo_dir"
    export MOBILE_BOOTSTRAP_GO="$go_bin"
    export MOBILE_BOOTSTRAP_TOOLS="$tools/bin"
    export MOBILE_BOOTSTRAP_GOPATH="$tmp/$shape/GOPATH"
    source "$repo_dir/mobile/core/scripts/mobile-tool-bootstrap.sh"
    test "$tools" = "$caller_tools"
    test "$repo_dir" = "$caller_repo"
    test "$go_bin" = "$caller_go"
    test "$GOBIN" = "$caller_tools/bin"
    test "$GOPATH" = "$tmp/$shape/GOPATH"
    test "$GOMODCACHE" = "$tmp/$shape-modcache"
    test -n "$LOCKLARK_REAL_GO"
    test -n "$LOCKLARK_MOBILE_VERSION"
    test -x "$caller_tools/bin/gomobile"
    test ! -e "$caller_tools/bin/bin/gomobile"
    test "$(command -v gomobile)" = "$caller_tools/bin/gomobile"
    test "$(command -v go)" = "$caller_tools/bin/guard/go"
    test "$(grep -c '^init$' "$init_log")" = 1
  )
}

run_shape ios
run_shape android
printf 'mobile tool bootstrap caller shape PASS\n'
