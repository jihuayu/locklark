package desktop

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/nativeclipboard"
	"github.com/jihuayu/locklark/internal/personal"
)

type fakeClipboard struct {
	owner                    *nativeclipboard.Lease
	value                    string
	beforeWrite, beforeClear func()
	unavailable              bool
}

func attachFakeClipboard(a *App) *fakeClipboard {
	f := &fakeClipboard{}
	a.clipboardWrite, a.clipboardClear = f.write, f.clear
	return f
}
func (f *fakeClipboard) write(value []byte) (*nativeclipboard.Lease, error) {
	if f.beforeWrite != nil {
		f.beforeWrite()
	}
	lease := new(nativeclipboard.Lease)
	f.owner, f.value = lease, string(value)
	return lease, nil
}
func (f *fakeClipboard) replace(value string) { f.owner = new(nativeclipboard.Lease); f.value = value }
func (f *fakeClipboard) clear(lease *nativeclipboard.Lease) nativeclipboard.Result {
	if f.beforeClear != nil {
		f.beforeClear()
	}
	if f.unavailable {
		return nativeclipboard.Unavailable
	}
	if f.owner != lease {
		return nativeclipboard.Superseded
	}
	f.owner, f.value = nil, ""
	return nativeclipboard.Cleared
}

func TestClipboardCleanupNeverRequestsForeignContent(t *testing.T) {
	a := New()
	f := attachFakeClipboard(a)
	lease, _ := f.write([]byte("same-value"))
	a.recordClipboardOwner(lease, time.Now().Add(time.Minute))
	a.Lock()
	if f.value != "" || a.clipboardLease != nil {
		t.Fatal("owned cleanup incomplete")
	}
	// The adapter surface has only write and ownership cleanup; neither App
	// nor this external-owner simulation exposes a content-read operation.
}

func TestClipboardCleanupPreservesSameValueFromNewOwner(t *testing.T) {
	a := New()
	f := attachFakeClipboard(a)
	lease, _ := f.write([]byte("same-value"))
	a.recordClipboardOwner(lease, time.Now().Add(time.Minute))
	f.replace("same-value")
	a.Lock()
	if f.value != "same-value" {
		t.Fatal("same-value foreign owner was cleared")
	}
}

func TestClipboardUnavailableRetainsOneOpaqueCleanupAndNewCopySupersedes(t *testing.T) {
	a := New()
	f := attachFakeClipboard(a)
	lease, _ := f.write([]byte("old-value"))
	a.recordClipboardOwner(lease, time.Now().Add(time.Minute))
	f.unavailable = true
	a.Lock()
	if a.clipboardPending != lease || !a.clipboardWarning {
		t.Fatal("unavailable cleanup was lost")
	}
	if strings.Contains(fmt.Sprintf("%#v", *a.clipboardPending), "old-value") {
		t.Fatal("opaque lease exposed a value")
	}
	if e := a.writeClipboard([]byte("same-value"), time.Now().Add(time.Minute), func() bool { return true }); e != nil {
		t.Fatal(e)
	}
	if a.clipboardPending != nil || a.clipboardWarning {
		t.Fatal("new acquisition retained old retry")
	}
	f.unavailable = false
	a.cleanupClipboard(lease)
	if f.value != "same-value" {
		t.Fatal("old retry erased new acquisition")
	}
	a.clearClipboard()
}

func TestClipboardPartialWriteIsUnknownAndRetainsCleanupOnly(t *testing.T) {
	a := New()
	f := attachFakeClipboard(a)
	f.unavailable = true
	a.clipboardWrite = func(value []byte) (*nativeclipboard.Lease, error) {
		lease, _ := f.write(value)
		return lease, nativeclipboard.ErrWrite
	}
	if e := a.writeClipboard([]byte("private-value"), time.Now().Add(time.Minute), func() bool { return true }); e != nativeclipboard.ErrWrite {
		t.Fatal("partial write was not unknown")
	}
	if a.clipboardLease != nil || a.clipboardPending == nil || !a.clipboardWarning {
		t.Fatal("partial write lost cleanup authority")
	}
	f.unavailable = false
	a.cleanupClipboard(a.clipboardPending)
	if f.value != "" || a.clipboardPending != nil || a.clipboardWarning {
		t.Fatal("cleanup retry did not resolve ownership")
	}
}

func TestClipboardReplacementKeepsOldOTPDeadlineUntilNativeResult(t *testing.T) {
	a := New()
	f := attachFakeClipboard(a)
	lease, _ := f.write([]byte("old-code"))
	a.recordClipboardOwner(lease, time.Now().Add(time.Minute))
	a.otpClipboard = new(personal.OTPBounds)
	a.otpClipboardTimer = time.AfterFunc(time.Hour, func() {})
	f.beforeWrite = func() {
		if a.otpClipboard == nil || a.otpClipboardTimer == nil {
			t.Fatal("pending replacement discarded old OTP expiry")
		}
		a.clearClipboard() // the still-armed old deadline wins during native work
	}
	if e := a.writeClipboard([]byte("new-value"), time.Now().Add(time.Minute), func() bool { return true }); e != nil {
		t.Fatal(e)
	}
	if f.value != "new-value" || a.otpClipboard != nil {
		t.Fatal("old expiry replaced new ownership")
	}
	f.beforeWrite = nil
	a.clearClipboard()
}

func TestClipboardExpiredReplacementRetainsPartialCleanupLease(t *testing.T) {
	a := New()
	f := attachFakeClipboard(a)
	old, _ := f.write([]byte("old-code"))
	a.recordClipboardOwner(old, time.Now().Add(time.Minute))
	f.unavailable = true
	f.beforeWrite = func() { time.Sleep(30 * time.Millisecond) }
	if e := a.writeClipboard([]byte("new-code"), time.Now().Add(20*time.Millisecond), func() bool { return true }); e == nil {
		t.Fatal("late write reported success")
	}
	if a.clipboardLease != nil || a.clipboardPending != f.owner || !a.clipboardWarning {
		t.Fatal("expired replacement lost its own cleanup authority")
	}
	f.unavailable, f.beforeWrite = false, nil
	a.cleanupClipboard(a.clipboardPending)
}
