//go:build unix && !linux && !darwin

package browserhost

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// devUnit has no verified encoding on this platform.
func devUnit(uint64) (uint32, bool) { return 0, false }

// cliRunTTYAttestedPlatform reports whether this build can attest a peer's
// controlling terminal. Every CLI-run is unavailable when it cannot.
func cliRunTTYAttestedPlatform() bool { return false }

// peerControllingTerminal has no safe implementation on this platform: there
// is no verified kernel view of another process's controlling terminal here.
func peerControllingTerminal(int) (string, uint64, uint32, bool) { return "", 0, 0, false }

// ttyNodeIdentity has no verified implementation on this platform.
func ttyNodeIdentity(string) (string, uint64, uint32, bool) { return "", 0, 0, false }

// TTYPeerIdentity has no verified implementation on this platform.
func TTYPeerIdentity(string) (device uint32, rdev uint64, ok bool) { return 0, 0, false }

// handleTTYIdentity has no verified implementation on this platform.
func handleTTYIdentity(uint64, uint64, bool) (uint32, bool) { return 0, false }

// openTTYNode has no verified implementation on this platform.
func openTTYNode(string) (*os.File, error) { return nil, errCLIRunUnavailable }

// fstatTTYHandle has no verified implementation on this platform.
func fstatTTYHandle(*os.File) (uint64, bool, bool) { return 0, false, false }
