//go:build windows && (amd64 || arm64)

package nativeclipboard

import (
	"testing"
	"time"
	"unicode/utf16"
	"unsafe"
)

func smokeOwnership() uint64 { owner, _, _ := clipOwner.Call(); return uint64(owner) }

func readSmokeOwned(lease *Lease, expected []byte) bool {
	p := lease.native.(*winLease)
	opened, _, _ := clipOpen.Call(p.window)
	if opened == 0 {
		return false
	}
	defer clipClose.Call()
	owner, _, _ := clipOwner.Call()
	if owner != p.window || !windowIsOurs(p.window) {
		return false
	}
	h, _, _ := clipGet.Call(13)
	if h == 0 {
		return false
	}
	n, _, _ := clipSize.Call(h)
	data := nativeLock(h)
	if data == nil {
		return false
	}
	defer clipUnlock.Call(h)
	units := unsafe.Slice((*uint16)(data), int(n)/2)
	for i, unit := range units {
		if unit == 0 {
			return string(utf16.Decode(units[:i])) == string(expected)
		}
	}
	return false
}

func smokeHoldClipboard(t *testing.T) func() {
	if !initWinClipboard() {
		t.Fatal("busy child window failed")
	}
	if opened, _, _ := clipOpen.Call(clipHWND); opened == 0 {
		t.Fatal("busy child lock failed")
	}
	return func() {
		if closed, _, _ := clipClose.Call(); closed == 0 {
			t.Fatal("busy child unlock failed")
		}
	}
}

func smokePlatformCases(t *testing.T, value []byte) {
	lease, err := Write(value)
	if err != nil {
		t.Fatal("busy precondition failed")
	}
	finish := startSmokeChild(t, "busy")
	if ClearOwned(lease) != Unavailable {
		t.Fatal("busy cleanup did not refuse immediately")
	}
	if other, e := Write(value); e != ErrUnavailable || other != nil {
		t.Fatal("busy write reported success")
	}
	finish()
	if ClearOwned(lease) != Cleared {
		t.Fatal("busy cleanup could not recover")
	}
	// A real OS sequence change without a new owner must not discard a valid
	// nonce lease. Publish an additional eager format under the same Open lock.
	lease, err = Write(value)
	if err != nil {
		t.Fatal("format mutation precondition failed")
	}
	addSmokeFormat(t, lease)
	if ClearOwned(lease) != Cleared {
		t.Fatal("sequence-only change lost valid nonce cleanup")
	}
	// Genuine eager text reaches the OS; only the metadata publication fails.
	set := setWinClipboard
	setWinClipboard = func(format, data uintptr) uintptr {
		if format == clipFormat {
			return 0
		}
		return set(format, data)
	}
	lease, err = Write(value)
	setWinClipboard = set
	if err != ErrWrite || lease == nil || !readSmokeOwned(lease, value) {
		t.Fatal("partial native write lost its cleanup lease")
	}
	if ClearOwned(lease) != Cleared {
		t.Fatal("partial native write cleanup failed")
	}
	setWinClipboard = func(format, data uintptr) uintptr {
		if format == clipFormat {
			return 0
		}
		return set(format, data)
	}
	lease, err = Write(value)
	setWinClipboard = set
	if err != ErrWrite || lease == nil {
		t.Fatal("ambiguous partial precondition failed")
	}
	addSmokeFormat(t, lease)
	if ClearOwned(lease) != Unavailable {
		t.Fatal("partial sequence change incorrectly proved replacement")
	}
	finish = startSmokeChild(t, "owner")
	if ClearOwned(lease) != Superseded {
		t.Fatal("foreign replacement did not retire partial lease")
	}
	finish()
}

func addSmokeFormat(t *testing.T, lease *Lease) {
	t.Helper()
	p := lease.native.(*winLease)
	if opened, _, _ := clipOpen.Call(p.window); opened == 0 {
		t.Fatal("format mutation open failed")
	}
	h := nativeBytes([]byte{1, 2, 3, 4})
	if setWinClipboard(1, h) == 0 {
		freeNative(h)
		clipClose.Call()
		t.Fatal("format mutation failed")
	}
	if closed, _, _ := clipClose.Call(); closed == 0 {
		t.Fatal("format mutation close failed")
	}
}

func smokeWait(wait func() error) error {
	// The child may synchronously send WM_DESTROYCLIPBOARD to our owner HWND.
	// Keep the real Windows message pump alive while a goroutine waits on pipes.
	done := make(chan error, 1)
	go func() { done <- wait() }()
	peek := clipUser.NewProc("PeekMessageW")
	translate := clipUser.NewProc("TranslateMessage")
	dispatch := clipUser.NewProc("DispatchMessageW")
	type message struct {
		window         uintptr
		id             uint32
		wparam, lparam uintptr
		time           uint32
		x, y           int32
		private        uint32
	}
	for {
		select {
		case err := <-done:
			return err
		default:
		}
		var msg message
		for {
			available, _, _ := peek.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0, 1)
			if available == 0 {
				break
			}
			translate.Call(uintptr(unsafe.Pointer(&msg)))
			dispatch.Call(uintptr(unsafe.Pointer(&msg)))
		}
		time.Sleep(time.Millisecond)
	}
}
