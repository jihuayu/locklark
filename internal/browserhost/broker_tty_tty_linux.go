//go:build linux

package browserhost

import "golang.org/x/sys/unix"

// termiosGetRequest is the Linux "read terminal attributes" request; only
// succeeds on a terminal device.
const termiosGetRequest = unix.TCGETS
