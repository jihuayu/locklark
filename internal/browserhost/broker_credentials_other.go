//go:build !linux

package browserhost

import "net"

// listenUnixLocal preserves the platform's previous listener behavior outside
// Linux. Only Linux provides per-message SCM_CREDENTIALS, so there is nothing
// to enable before bind.
func listenUnixLocal(path string) (*net.UnixListener, error) {
	return net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
}

// guardRequestWriter is a no-op outside Linux: the connection-level
// authenticatedPeer check (SO_PEERCRED/LOCAL_PEERCRED) remains the documented
// boundary because those kernels do not attribute each received chunk to its
// writer.
func guardRequestWriter(c net.Conn) (net.Conn, error) {
	return c, nil
}
