//go:build !unix

package browserhost

import "os"

// ttyHandleIsTerminal has no verified implementation outside unix: there is no
// terminal attribute call to make, so a handle is never a terminal here.
func ttyHandleIsTerminal(*os.File) bool { return false }
