//go:build linux

package browserhost

import (
	"net"
	"os"
	"strconv"
)

func cliRunCTTYProofRequired() bool { return true }

func newCLIRunCTTYProof(conn net.Conn, peer Peer, scope CLIRunScope) (*clirunCTTYProof, Peer, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return nil, peer, errCLIRunCTTYUnsupported
	}
	path, dev, _, ok := peerControllingTerminal(os.Getpid())
	if !ok {
		return nil, peer, errCLIRunCTTYUnsupported
	}
	held, ok := openLinuxPeerTTY(path, dev, uint32(os.Geteuid()))
	if !ok {
		return nil, peer, errLinuxPeerCTTYUnavailable
	}
	assoc, err := newLinuxPeerCTTYAssociation(unixConn, held)
	if err != nil {
		return nil, peer, errLinuxPeerCTTYUnavailable
	}
	fail := func() (*clirunCTTYProof, Peer, error) {
		_ = assoc.Close()
		return nil, peer, errLinuxPeerCTTYUnavailable
	}
	if assoc.proof.pid != int(peer.PID) ||
		peer.User != "UID "+strconv.FormatUint(uint64(assoc.proof.uid), 10) {
		return fail()
	}
	// The declared terminal remains display data, never authority. It must
	// still name the kernel-associated terminal shown in the approval.
	if scope.TTYPlatform != CLIRunTTYPlatform() || scope.TTY != assoc.proof.tty.path || scope.TTYPeerID != "" {
		return fail()
	}
	peer.Process = assoc.proof.exe.path
	digest, ok := cliRunScopeDigest(scope)
	if !ok {
		return fail()
	}
	proof := &clirunCTTYProof{
		owner: assoc, peerUser: peer.User, peerPID: peer.PID,
		peerProcess: peer.Process, scopeDigest: digest,
	}
	if !assoc.live() {
		_ = proof.Close()
		return nil, peer, errLinuxPeerCTTYUnavailable
	}
	return proof, peer, nil
}
