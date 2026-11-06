package directory

import (
	"crypto/ed25519"

	"github.com/jihuayu/locklark/internal/vault"
)

// VerifyInitial verifies a complete genesis bootstrap against independently
// trusted configuration, using the same proposal, snapshot and transition
// verification as Create. It observes inputs without signing, decrypting,
// accessing storage or requiring the sequencer's private key.
func VerifyInitial(c *Config, p Proposal, s vault.Snapshot) error {
	if !c.valid() || p.Parent != c.Genesis() || p.Mode != "active" || c.verifyProposal(p) != nil || c.verifySnapshot(p, s) != nil {
		return ErrInvalid
	}
	state := newEvolution()
	if c.verifyTransition(state, p) != nil || state.advance(p) != nil {
		return ErrInvalid
	}
	// Create stores this exact receipt shape after adding a fixed-size Ed25519
	// signature. Zero bytes reproduce its JSON size only; they are never treated
	// as signature evidence or returned to the caller.
	if len(encoded(Receipt{Proposal: p, Signature: make([]byte, ed25519.SignatureSize)})) > maxRecord {
		return ErrInvalid
	}
	return nil
}
