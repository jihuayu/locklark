//go:build darwin && (amd64 || arm64)

package desktop

import (
	"testing"

	"github.com/jihuayu/locklark/internal/nativeclipboard"
)

// TestDarwinDesktopDoesNotCreateNativeClipboardManager keeps the App factory
// consistent with the broker capability gate. Ordinary desktop copy still uses
// writeClipboard and the manual-cleanup status.
func TestDarwinDesktopDoesNotCreateNativeClipboardManager(t *testing.T) {
	if nativeclipboard.NativeLeaseSupported() {
		t.Fatal("Darwin reported owner-safe native cleanup support")
	}
	a := New()
	if manager := a.newBrowserClipboardManager(); manager != nil {
		t.Fatal("Darwin App created an advertised native clipboard manager")
	}
	callbacks := a.browserBrokerCallbacks()
	if manager, _ := callbacks.NewClipboard(); manager != nil {
		t.Fatal("Darwin broker callback returned a native clipboard manager")
	}
}
