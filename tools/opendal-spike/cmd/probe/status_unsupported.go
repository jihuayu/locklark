//go:build !linux

package main

import (
	"fmt"
	"os"
	"runtime"
)

// The official companion modules embed native libraries for linux/amd64 and
// linux/arm64 only; there is no official darwin/windows artifact to load.
func main() {
	fmt.Fprintf(os.Stderr, "opendal-spike/probe: no official opendal native library for %s/%s\n", runtime.GOOS, runtime.GOARCH)
	os.Exit(3)
}
