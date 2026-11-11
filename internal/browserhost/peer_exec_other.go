//go:build !unix && !windows

package browserhost

// trustedPeerExecutable never accepts a peer executable on platforms that have
// no ownership/ACL implementation for the process-path policy, so an
// unsupported OS can never trust a peer process.
func trustedPeerExecutable(process, peerUser, goos string) bool {
	return false
}
