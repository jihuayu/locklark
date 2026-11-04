//go:build unix

package preview

import "syscall"

const readFlags = syscall.O_NONBLOCK
