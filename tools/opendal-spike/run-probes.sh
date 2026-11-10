#!/usr/bin/env bash
# Boundary probes for the official OpenDAL Go binding (v0.1.16).
# Cases are run in separate processes because some deliberately trigger panics,
# crashes, or an unbounded loop. Synthetic memory data only; no network, no
# credentials. Native libraries are published for linux/amd64 and linux/arm64
# only, so the probes execute inside a Linux container (glibc >= 2.38).
set -uo pipefail

cd "$(dirname "$0")"
platform="${1:-linux/arm64}"
image="${SPIKE_IMAGE:-golang:1.24-trixie@sha256:5835f052b784aa39f2fe9070def3568605c8bc3fcd810f10402066348b61e716}"

exec docker run --rm --platform "$platform" \
  -v "$PWD":/src:ro -w /src \
  -e GOFLAGS=-mod=mod \
  "$image" \
  sh -ec '
set -u
go build -trimpath -o /tmp/opendal-spike-probe ./cmd/probe
run() {
  name="$1"; shift
  if out=$(timeout 25s "$@" 2>&1); then rc=0; else rc=$?; fi
  printf "\n=== %s: exit=%s\n%s\n" "$name" "$rc" "$out"
  return 0
}
run load-missing        /tmp/opendal-spike-probe -case load-missing
run load-corrupt        /tmp/opendal-spike-probe -case load-corrupt
run load-tmpdir         env TMPDIR=/nonexistent-spike-tmp /tmp/opendal-spike-probe -case load-tmpdir
run timeout-invalid     /tmp/opendal-spike-probe -case timeout-invalid
run info-name           /tmp/opendal-spike-probe -case info-name
run capabilities        /tmp/opendal-spike-probe -case capabilities
run error-matrix        /tmp/opendal-spike-probe -case error-matrix
run timeout-io          /tmp/opendal-spike-probe -case timeout-io
run close-then-use      /tmp/opendal-spike-probe -case close-then-use
run close-during-list   /tmp/opendal-spike-probe -case close-during-list
run slow-uncancellable  timeout 5s /tmp/opendal-spike-probe -case slow-uncancellable
'
