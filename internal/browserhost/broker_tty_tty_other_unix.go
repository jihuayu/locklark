//go:build unix && !linux && !darwin

package browserhost

import "os"

// attestationPlatformDisabled is the test seam shared with the supported unix
// platforms. There is no ioctl path on this platform, so the value never
// changes the outcome; it exists only so the package compiles.
var attestationPlatformDisabled bool

// ttyHandleIsTerminal has no verified implementation on this platform: there
// is no ioctl request for terminal attributes here, so it never issues one and
// every handle is rejected.
func ttyHandleIsTerminal(*os.File) bool { return false }
