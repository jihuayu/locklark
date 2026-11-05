package desktop

import (
	"os"

	"github.com/jihuayu/locklark/internal/browserhost"
)

// Supported browsers disable their own GTK accessibility bridge and export
// that internal flag to native-messaging children. Our native UI must follow the
// system's normal accessibility settings instead of the browser-internal flag.
// This changes no unlock, pairing or approval decisions and uses no test switch.
func restoreBrowserAccessibility(browser browserhost.Browser) error {
	if browser == browserhost.Chromium || browser == browserhost.Firefox {
		return os.Unsetenv("NO_AT_BRIDGE")
	}
	return nil
}
