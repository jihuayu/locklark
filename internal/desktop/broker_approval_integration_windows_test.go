//go:build windows

package desktop

import (
	"fmt"
	"testing"
	"time"
)

// desktopBrokerSocket returns a unique LOCKLARK_BROWSER_SOCKET value. On
// Windows that variable is a safe token appended to the per-user named-pipe
// name, not a filesystem path, so it must stay short and use only
// [A-Za-z0-9._-] (see browserhost.safeBrokerToken).
func desktopBrokerSocket(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("test-%d-%d", time.Now().UnixNano(), len(t.Name()))
}
