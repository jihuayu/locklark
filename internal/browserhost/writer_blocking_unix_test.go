//go:build linux || darwin

package browserhost

import (
	"golang.org/x/sys/unix"
	"os"
)

func forceBlockingStdout() error { return unix.SetNonblock(int(os.Stdout.Fd()), false) }
