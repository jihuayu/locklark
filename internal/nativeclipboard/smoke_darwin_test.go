//go:build darwin && (amd64 || arm64)

package nativeclipboard

import (
	"testing"
	"unsafe"

	"github.com/ebitengine/purego/objc"
)

func smokeOwnership() (count uint64) {
	withPool(func() { count = uint64(msg[int64](pasteboard(), "changeCount")) })
	return count
}

func readSmokeOwned(lease *Lease, expected []byte) (matches bool) {
	p := lease.native.(*macLease)
	withPool(func() {
		board := pasteboard()
		if msg[int64](board, "changeCount") != p.count {
			return
		}
		typ := nsText([]byte("public.utf8-plain-text"))
		defer msg[objc.ID](typ, "release")
		text := msg[objc.ID](board, "stringForType:", typ)
		if text == 0 {
			return
		}
		length := msg[uintptr](text, "lengthOfBytesUsingEncoding:", uintptr(4))
		pointer := msg[unsafe.Pointer](text, "UTF8String")
		if pointer == nil || length != uintptr(len(expected)) {
			return
		}
		matches = string(unsafe.Slice((*byte)(pointer), int(length))) == string(expected)
	})
	return matches
}

func smokeHoldClipboard(t *testing.T) func() { t.Fatal("macOS has no OpenClipboard lock"); return nil }
func smokePlatformCases(*testing.T, []byte)  {}

func smokeWait(wait func() error) error { return wait() }
