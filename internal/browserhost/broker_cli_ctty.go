package browserhost

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
)

// errCLIRunCTTYUnsupported marks only the absence of a self CTTY or a
// non-Unix connection. It tells serveCLIRun to use the legacy gate, which on
// Linux always refuses in production. It is not a proof-failure fallback.
var errCLIRunCTTYUnsupported = errors.New("linux CLI-run CTTY association unavailable")

// clirunCTTYProofOwner is implemented only inside browserhost. It is not a
// validator callback and cannot be supplied by a client or desktop.
type clirunCTTYProofOwner interface {
	live() bool
	Close() error
}

// clirunCTTYProof is the sealed carrier for one CLI-run connection's live CTTY
// association. It is never encoded on the wire; the enclosing request field is
// unexported.
type clirunCTTYProof struct {
	owner       clirunCTTYProofOwner
	peerUser    string
	peerPID     uint32
	peerProcess string
	scopeDigest [sha256.Size]byte
}

// VerifyCLIRunCTTY is the fixed read-only check used by the desktop. It
// re-runs the owner's kernel association and binds it to the exact peer and
// request scope. A nil, forged, stale, or rebinding proof fails on Linux.
func (r CLIRunBrokerRequest) VerifyCLIRunCTTY(peer Peer) bool {
	if !cliRunCTTYProofRequired() {
		return true
	}
	p := r.cttyProof
	if p == nil || p.owner == nil || !p.owner.live() {
		return false
	}
	if p.peerUser != peer.User || p.peerPID != peer.PID || p.peerProcess != peer.Process {
		return false
	}
	digest, ok := cliRunScopeDigest(r.Scope)
	return ok && digest == p.scopeDigest
}

func cliRunScopeDigest(scope CLIRunScope) ([sha256.Size]byte, bool) {
	raw, err := json.Marshal(scope)
	if err != nil {
		return [sha256.Size]byte{}, false
	}
	defer clear(raw)
	return sha256.Sum256(raw), true
}

func (p *clirunCTTYProof) Close() error {
	if p == nil || p.owner == nil {
		return nil
	}
	return p.owner.Close()
}
