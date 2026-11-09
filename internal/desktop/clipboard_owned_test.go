package desktop

import (
	"context"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/nativeclipboard"
)

func TestOwnedClipboardWriteReturnsExactPartialLease(t *testing.T) {
	a := New()
	f := attachFakeClipboard(a)
	f.unavailable = true
	a.clipboardWrite = func(value []byte) (*nativeclipboard.Lease, error) {
		lease, _ := f.write(value)
		return lease, nativeclipboard.ErrWrite
	}
	lease, err := a.writeClipboardOwned([]byte("private-value"), time.Now().Add(time.Minute), func() bool { return true })
	if err != nativeclipboard.ErrWrite || lease == nil {
		t.Fatalf("owned write = %v, %v; want the exact lease and ErrWrite", lease, err)
	}
	if lease != f.owner || a.clipboardPending != lease || !a.clipboardWarning {
		t.Fatal("partial write did not return its owned cleanup authority")
	}
	if a.clipboardLease != nil {
		t.Fatal("partial write stayed the current App owner")
	}
	f.unavailable = false
	a.cleanupClipboard(lease)
	if f.value != "" || a.clipboardPending != nil {
		t.Fatal("partial cleanup authority did not resolve")
	}
}

func TestBrowserClipboardManagerUsesOwnedWriterAndLockClearsGlobalLease(t *testing.T) {
	if !nativeclipboard.NativeLeaseSupported() {
		t.Skip("native clipboard leases are unavailable; platform fallback has separate coverage")
	}
	a := New()
	f := attachFakeClipboard(a)
	m := a.newBrowserClipboardManager()
	ticket, err := m.Prepare([]byte("browser-secret"), time.Now().Add(5*time.Second), time.Time{}, func() bool { return true })
	if err != nil || len(ticket) != 64 {
		t.Fatalf("prepare = %q, %v", ticket, err)
	}
	if f.value != "" {
		t.Fatal("prepare wrote to the OS clipboard")
	}
	outcome := <-m.Commit(context.Background(), ticket)
	if outcome != nativeclipboard.Confirmed {
		t.Fatalf("commit outcome = %v, want Confirmed", outcome)
	}
	if f.value != "browser-secret" {
		t.Fatalf("owner value = %q", f.value)
	}
	if a.clipboardLease == nil || a.clipboardLease != f.owner {
		t.Fatal("native lease was not tracked as the App global owner")
	}
	// A zero contextual deadline means the existing no-auto-clear contract, not
	// an immediate expiry.
	if !a.clipboardUntil.After(time.Now().Add(365 * 24 * time.Hour)) {
		t.Fatalf("zero deadline was translated to %v", a.clipboardUntil)
	}
	a.Lock()
	if f.value != "" || a.clipboardLease != nil {
		t.Fatal("lock did not synchronously clear the App global lease")
	}
}

func TestClearBrowserClipboardLeaseCannotClearNewerAppOwner(t *testing.T) {
	a := New()
	f := attachFakeClipboard(a)
	older, _ := f.write([]byte("old-value"))
	a.recordClipboardOwner(older, time.Now().Add(time.Minute))
	newer, _ := f.write([]byte("new-value"))
	a.recordClipboardOwner(newer, time.Now().Add(time.Minute))
	if result := a.clearBrowserClipboardLease(older); result != nativeclipboard.Superseded {
		t.Fatalf("older cleanup = %v, want Superseded", result)
	}
	if f.value != "new-value" || a.clipboardLease != newer {
		t.Fatal("older lease cleared the newer App owner")
	}
	if result := a.clearBrowserClipboardLease(newer); result != nativeclipboard.Cleared {
		t.Fatalf("current cleanup = %v, want Cleared", result)
	}
	if f.value != "" || a.clipboardLease != nil {
		t.Fatal("matching cleanup did not update App ownership")
	}
}
