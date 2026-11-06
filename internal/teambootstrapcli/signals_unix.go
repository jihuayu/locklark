//go:build unix

package teambootstrapcli

import (
	"os"
	"syscall"
)

func bootstrapSignals() []os.Signal {
	return []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGHUP}
}
