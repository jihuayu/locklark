//go:build darwin && (amd64 || arm64)

package nativeclipboard

import (
	"runtime"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
	"github.com/ebitengine/purego/objc"
)

const leaseSupported = false

type macLease struct{ count int64 }

var appKitOnce sync.Once
var appKitAvailable bool

func msg[T any](object objc.ID, selector string, args ...any) T {
	return objc.Send[T](object, objc.RegisterName(selector), args...)
}

func withPool(fn func()) {
	pool := msg[objc.ID](objc.ID(objc.GetClass("NSAutoreleasePool")), "new")
	defer msg[objc.ID](pool, "drain")
	fn()
}

func pasteboard() objc.ID {
	return msg[objc.ID](objc.ID(objc.GetClass("NSPasteboard")), "generalPasteboard")
}

func nsText(value []byte) objc.ID {
	var zero byte
	p := unsafe.Pointer(&zero)
	if len(value) != 0 {
		p = unsafe.Pointer(&value[0])
	}
	allocated := msg[objc.ID](objc.ID(objc.GetClass("NSString")), "alloc")
	text := msg[objc.ID](allocated, "initWithBytes:length:encoding:", uintptr(p), uintptr(len(value)), uintptr(4)) // NSUTF8StringEncoding
	runtime.KeepAlive(value)
	return text
}

func write(value []byte) (lease *Lease, err error) {
	// AppKit is already loaded by MyGo; binding explicitly also supports
	// standalone native ownership tests without importing MyGo internals.
	appKitOnce.Do(func() {
		_, e := purego.Dlopen("/System/Library/Frameworks/AppKit.framework/AppKit", purego.RTLD_NOW|purego.RTLD_GLOBAL)
		appKitAvailable = e == nil
	})
	if !appKitAvailable {
		return nil, ErrUnsupported
	}
	err = ErrWrite
	withPool(func() {
		board := pasteboard()
		if board == 0 {
			err = ErrUnavailable
			return
		}
		text := nsText(value)
		typ := nsText([]byte("public.utf8-plain-text"))
		if text == 0 || typ == 0 {
			if text != 0 {
				msg[objc.ID](text, "release")
			}
			if typ != 0 {
				msg[objc.ID](typ, "release")
			}
			return
		}
		defer msg[objc.ID](text, "release")
		defer msg[objc.ID](typ, "release")
		types := msg[objc.ID](objc.ID(objc.GetClass("NSArray")), "arrayWithObject:", typ)
		// Anchor to the atomic declaration's count, never to an observation
		// taken after writing which might adopt a foreign acquisition.
		lease, err = acquireMac(
			func() int64 { return msg[int64](board, "declareTypes:owner:", types, objc.ID(0)) },
			func() bool { return msg[bool](board, "setString:forType:", text, typ) },
			func() int64 { return msg[int64](board, "changeCount") },
		)
	})
	return lease, err
}

func clearOwned(lease *Lease) Result {
	p, ok := lease.native.(*macLease)
	if !ok || p == nil {
		return Superseded
	}
	// Never touch NSPasteboard here. clearContents/declareTypes destroy the
	// current owner unconditionally, and a changeCount precheck cannot close
	// the race with a foreign process. Production passes no probes.
	return clearMac(p, nil, nil)
}

func acquireMac(declare func() int64, set func() bool, count func() int64) (*Lease, error) {
	original := declare()
	lease := &Lease{native: &macLease{count: original}}
	if !set() || count() != original {
		return lease, ErrWrite
	}
	return lease, nil
}

// clearMac is the terminal Darwin cleanup boundary. NSPasteboard has no public
// atomic compare-and-clear, so even a fresh changeCount observation can be
// followed by a foreign write before any unconditional clear. This function
// therefore never invokes count or clear, never registers clearContents or
// declareTypes, and returns the distinct terminal ManualCleanup result. The
// observe/clear probes exist only so the regression test can prove both remain
// uncalled; production passes nil.
func clearMac(p *macLease, _ func() int64, _ func() int64) Result {
	if p == nil {
		return Superseded
	}
	return ManualCleanup
}
