//go:build darwin

package browserhost

import "golang.org/x/sys/unix"

// termiosGetRequest is the Darwin "read terminal attributes" request; only
// succeeds on a terminal device.
const termiosGetRequest = unix.TIOCGETA
