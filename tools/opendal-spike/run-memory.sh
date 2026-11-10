#!/usr/bin/env bash
# Reproducible run of the memory spike against the official OpenDAL Go binding.
#
# The official companion module github.com/apache/opendal-go-services/memory
# only ships native libraries for linux/amd64 and linux/arm64, so the binary is
# built and executed inside a pinned Linux container even on macOS. No cloud
# credentials are read and no network I/O is performed by the program itself.
#
# Default image is pinned by digest so a tag re-push cannot change the run
# (golang:1.24-trixie, Debian trixie, glibc 2.41). Args:
#   $1 platform: linux/arm64 (default) or linux/amd64
#   $2 mode:     emulated (default) - any run under emulation (e.g. linux/amd64
#                on this arm64 Mac, or QEMU anywhere)
#                native   - only when host arch == container platform
# The mode is printed with the run; nothing verifies it, so choose honestly.
set -eu

cd "$(dirname "$0")"
platform="${1:-linux/arm64}"
mode="${2:-emulated}"
image="${SPIKE_IMAGE:-golang:1.24-trixie@sha256:5835f052b784aa39f2fe9070def3568605c8bc3fcd810f10402066348b61e716}"
modcache="${SPIKE_GOMODCACHE:-oci/docker-image/golang/trixie}"

case "$mode" in
  emulated|native) ;;
  *) echo "usage: $0 [linux/arm64|linux/amd64] [emulated|native]" >&2; exit 2 ;;
esac

# The module cache volume persists already-fetched pinned modules so re-runs
# need no download. Set SPIKE_GOMODCACHE to point at an isolated cache.
docker run --rm --platform "$platform" \
  -v "$PWD":/src:ro \
  -v "$modcache":/go/pkg/mod \
  -w /src \
  -e GOFLAGS=-mod=mod \
  "$image" \
  sh -ec "echo \"platform=$platform mode=$mode image=$image modcache=$modcache\"
go build -trimpath -o /tmp/opendal-spike-memory ./cmd/memory && /tmp/opendal-spike-memory"
