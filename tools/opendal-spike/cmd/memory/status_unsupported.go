//go:build !linux

package main

import (
	"fmt"
	"os"
	"runtime"
)

// The published github.com/apache/opendal-go-services/memory module only
// embeds native libraries for linux/amd64 and linux/arm64
// (embed_linux_amd64.go / embed_linux_arm64.go, go:build linux && <arch>).
// No other platform is supported by the official package, so we fail
// loudly instead of shipping a fake in-process replacement.
func main() {
	fmt.Fprintf(os.Stderr, "opendal-spike/memory: official opendal-go-services/memory supports only linux/amd64 and linux/arm64; this build is %s/%s (unsupported)\n", runtime.GOOS, runtime.GOARCH)
	os.Exit(3)
}
