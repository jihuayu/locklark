//go:build darwin && (amd64 || arm64)

package browserhost

import (
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/nativeclipboard"
)

// TestDarwinDoesNotAdvertiseOrInstallNativeClipboardLease pins the truthful
// platform fallback: NSPasteboard has no compare-and-clear, so the broker must
// not call the desktop clipboard factory, install per-connection state, or
// advertise native-clipboard-lease-v1. The extension then keeps its existing
// navigator.clipboard.write manual-cleanup prompt.
func TestDarwinDoesNotAdvertiseOrInstallNativeClipboardLease(t *testing.T) {
	if nativeclipboard.NativeLeaseSupported() {
		t.Fatal("Darwin reported owner-safe native cleanup support")
	}
	called := false
	c := NewDesktopConnection(NewWriter(&memoryPipe{}, time.Second), nil)
	t.Cleanup(c.Close)
	c.SetBroker(NewBroker(BrokerCallbacks{NewClipboard: func() (*nativeclipboard.Manager, time.Duration) {
		called = true
		return nativeclipboard.NewManager(func(func()) bool { return true }, nil, nil), 3 * time.Second
	}}))
	if called {
		t.Fatal("Darwin broker invoked the native clipboard manager factory")
	}
	if state := c.clipboard.Load(); state != nil {
		t.Fatal("Darwin broker installed native clipboard state")
	}
	for _, capability := range c.capabilities() {
		if capability == clipboardCapability {
			t.Fatal("Darwin advertised native-clipboard-lease-v1")
		}
	}
	// Even a direct injection must be refused; capability truthfulness cannot
	// depend on one caller remembering to check the platform.
	c.setClipboard(nativeclipboard.NewManager(func(func()) bool { return true }, nil, nil), 3*time.Second)
	if state := c.clipboard.Load(); state != nil {
		t.Fatal("Darwin direct clipboard installation was accepted")
	}
}
