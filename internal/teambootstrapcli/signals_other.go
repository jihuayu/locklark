//go:build !unix && !windows

package teambootstrapcli

import "os"

func bootstrapSignals() []os.Signal { return []os.Signal{os.Interrupt} }
