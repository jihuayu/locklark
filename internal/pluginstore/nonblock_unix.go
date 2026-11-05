//go:build unix

package pluginstore

import "syscall"

const nonblock = syscall.O_NONBLOCK
