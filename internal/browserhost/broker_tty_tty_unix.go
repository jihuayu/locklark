//go:build unix

package browserhost

import (
	"os"

	"golang.org/x/sys/unix"
)

// attestationPlatformDisabled, when set by a test through withTTYSeams,
// makes this build behave like a platform without peer attestation, so the
// fail-closed "unavailable" path of every checkpoint is exercised natively.
// It is an unexported test seam; production code never sets it and no request
// field or exported option can reach it.
var attestationPlatformDisabled bool

// ttyHandleIsTerminal proves one open handle is a real terminal by asking the
// kernel for its terminal attributes (TIOCGETA on darwin, TCGETS on linux).
// The ioctl is given a real termios buffer, since the kernel rejects a nil
// one (EFAULT); it fails on any non-terminal file. The open flags are never
// inspected instead: the kernel's own attribute call is the evidence.
func ttyHandleIsTerminal(f *os.File) bool {
	if f == nil {
		return false
	}
	raw, e := f.SyscallConn()
	if e != nil {
		return false
	}
	var termios unix.Termios
	var ioctlErr error
	return raw.Control(func(fd uintptr) {
		ioctlErr = unix.IoctlSetTermios(int(fd), termiosGetRequest, &termios)
	}) == nil && ioctlErr == nil
}
