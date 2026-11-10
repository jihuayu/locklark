#!/usr/bin/env bash
# Reproducible run of the memory spike against the official OpenDAL Go binding.
#
# The official companion module github.com/apache/opendal-go-services/memory
# only ships native libraries for linux/amd64 and linux/arm64, so the binary is
# built and executed inside a Linux container even on macOS. On Linux hosts the
# same command runs natively. No cloud credentials are read and no network I/O
# is performed by the program itself.
set -euo pipefail

cd "$(dirname "$0")"
platform="${1:-linux/arm64}"
image="${SPIKE_IMAGE:-golang:1.24-trixie}"

exec docker run --rm --platform "$platform" \
  -v "$PWD":/src:ro \
  -w /src \
  -e GOFLAGS=-mod=mod \
  "$image" \
  sh -ec 'go build -trimpath -o /tmp/opendal-spike-memory ./cmd/memory && /tmp/opendal-spike-memory'
