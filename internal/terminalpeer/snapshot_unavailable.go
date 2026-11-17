//go:build !darwin || !cgo

package terminalpeer

import "net"

// This build has no kernel observation implementation. Every entry point is a
// fixed unavailable result; there is no path-only, process-name, UUID, or
// sysctl fallback.
func socketIdentity(*net.UnixConn) (socketID, error) {
	return socketID{}, ErrUnavailable
}

func readPeerSample(*net.UnixConn) (peerSample, error) {
	return peerSample{}, ErrUnavailable
}

func readPeerCredential(int32) (peerCredential, error) {
	return peerCredential{}, ErrUnavailable
}
