#!/usr/bin/env bash
# Source after setting MOBILE_BOOTSTRAP_REPO, MOBILE_BOOTSTRAP_GO,
# MOBILE_BOOTSTRAP_TOOLS, MOBILE_BOOTSTRAP_GOPATH.
set -euo pipefail

mobile_tool_bootstrap() {
  local repo_dir go_path real_go version sum tools gopath guard modcache
  : "${MOBILE_BOOTSTRAP_REPO:?repo required}"
  : "${MOBILE_BOOTSTRAP_GO:?go executable required}"
  : "${MOBILE_BOOTSTRAP_TOOLS:?tools directory required}"
  : "${MOBILE_BOOTSTRAP_GOPATH:?private GOPATH required}"
  repo_dir=$(cd "$MOBILE_BOOTSTRAP_REPO" && pwd)
  go_path=$(command -v "$MOBILE_BOOTSTRAP_GO") || {
    echo "mobile-tool-bootstrap: Go executable not found" >&2
    return 1
  }
  real_go=$(cd "$(dirname "$go_path")" && pwd)/$(basename "$go_path")
  version=$(awk '$1 == "golang.org/x/mobile" { print $2; exit }' "$repo_dir/go.mod")
  sum=$(awk -v version="$version" '$1 == "golang.org/x/mobile" && $2 == version { print $3; exit }' "$repo_dir/go.sum")
  case "$version" in
    v[0-9]*) ;;
    *) echo "mobile-tool-bootstrap: pinned x/mobile version missing" >&2; return 1 ;;
  esac
  case "$sum" in
    h1:*) ;;
    *) echo "mobile-tool-bootstrap: pinned x/mobile sum missing" >&2; return 1 ;;
  esac
  tools=$MOBILE_BOOTSTRAP_TOOLS
  gopath=$MOBILE_BOOTSTRAP_GOPATH
  guard="$tools/guard"
  mkdir -p "$tools" "$gopath" "$guard"
  chmod 0700 "$tools" "$gopath" "$guard"
  modcache=$("$real_go" env GOMODCACHE)
  if [ -n "$modcache" ]; then
    export GOMODCACHE="${LOCKLARK_MOBILE_GOMODCACHE:-$modcache}"
  fi
  export GOBIN="$tools"
  export GOPATH="$gopath"
  export LOCKLARK_REAL_GO="$real_go"
  export LOCKLARK_MOBILE_VERSION="$version"
  ln -sfn "$repo_dir/mobile/core/scripts/mobile_go_shim.py" "$guard/go"
  chmod 0755 "$repo_dir/mobile/core/scripts/mobile_go_shim.py"
  export PATH="$guard:$tools:$(dirname "$real_go"):$PATH"
  # Install only the pinned gomobile. Its init will request gobind@latest; the
  # private go shim rewrites exactly that request to this go.mod version.
  GOBIN="$tools" "$real_go" install "golang.org/x/mobile/cmd/gomobile@$version"
  "$tools/gomobile" init
}

mobile_tool_bootstrap
