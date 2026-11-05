//go:build unix

package personal

import (
	"os"
	"syscall"
)

// Validate the opened handle in decodeArchive. A path check alone would race
// with replacement by a FIFO; opening must not wait for its writer first.
func openArchive(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOCTTY, 0)
}
