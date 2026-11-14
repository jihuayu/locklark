//go:build !linux

package browserhost

import "net"

func cliRunCTTYProofRequired() bool { return false }

func newCLIRunCTTYProof(_ net.Conn, peer Peer, _ CLIRunScope) (*clirunCTTYProof, Peer, error) {
	return nil, peer, nil
}
