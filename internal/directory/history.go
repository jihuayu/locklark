package directory

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"

	"github.com/jihuayu/locklark/internal/vault"
)

// History is signed public transition evidence and the encrypted head snapshot.
// It is not a freshness statement and never contains plaintext items.
type History struct {
	Receipts []Receipt      `json:"receipts"`
	Snapshot vault.Snapshot `json:"snapshot"`
}

const MaxHistoryBytes = 32 << 20

type historyVerifier struct {
	config          *Config
	anchor, current Checkpoint
	matched         bool
	state           *evolution
	head            Receipt
}

func newHistoryVerifier(c *Config, anchor Checkpoint) (*historyVerifier, error) {
	if !c.validCheckpoint(anchor) {
		return nil, ErrInvalid
	}
	genesis := c.Genesis()
	return &historyVerifier{config: c, anchor: anchor, current: genesis, matched: anchor == genesis, state: newEvolution()}, nil
}

// This reducer is shared by trusted local reload and untrusted remote history.
// A valid individual signature never substitutes for transition authorization.
func (v *historyVerifier) advance(r Receipt) error {
	if v.current.Version >= maxVersions || v.config.verifyReceipt(r) != nil || r.Proposal.Parent != v.current || v.config.verifyTransition(v.state, r.Proposal) != nil || v.state.advance(r.Proposal) != nil {
		return ErrInvalid
	}
	v.current = r.Checkpoint()
	v.matched = v.matched || v.current == v.anchor
	v.head = r
	return nil
}
func (v *historyVerifier) finish(snapshot vault.Snapshot) (View, error) {
	if v.current.Version == 0 || !v.matched || v.config.verifySnapshot(v.head.Proposal, snapshot) != nil {
		return View{}, ErrInvalid
	}
	signer, e := v.config.snapshotSigner(v.head.Proposal)
	if e != nil {
		return View{}, ErrInvalid
	}
	return View{Receipt: v.head, Snapshot: snapshot, SnapshotSigner: signer}, nil
}

func (h History) valid() bool { return len(h.Receipts) > 0 && len(h.Receipts) <= maxVersions }

// storageSize counts the stored JSON bytes a verified history would occupy.
// Protocol fields are plain ASCII, so their encoding never grows past these
// bounds; a forged value that could still verify is always within limits.
func (h History) storageSize() (int, error) {
	size := len(`{"receipts":[`) + len(`],"snapshot":`) + 1
	for n, r := range h.Receipts {
		raw := encoded(r)
		if len(raw) > maxRecord {
			return 0, ErrInvalid
		}
		size += len(raw)
		if n > 0 {
			size++
		}
		if size > MaxHistoryBytes {
			return 0, ErrCapacity
		}
	}
	if size+len(encoded(h.Snapshot)) > MaxHistoryBytes {
		return 0, ErrCapacity
	}
	return size, nil
}

func VerifyHistory(c *Config, anchor Checkpoint, h History) (View, error) {
	view, _, e := verifyHistory(c, anchor, h)
	return view, e
}

// AssembleHistory verifies an untrusted history and requires it to be exactly
// the history retained by a database read that produced the expected head, so
// a tampered receipt cannot be mistaken for the trusted checkpoint.
func AssembleHistory(c *Config, anchor, expected Checkpoint, h History) (View, error) {
	if expected == (Checkpoint{}) {
		return View{}, ErrInvalid
	}
	view, _, e := verifyHistory(c, anchor, h)
	if e != nil {
		return View{}, e
	}
	if view.Receipt.Checkpoint() != expected {
		return View{}, ErrInvalid
	}
	return view, nil
}

func verifyHistory(c *Config, anchor Checkpoint, h History) (View, int, error) {
	v, e := newHistoryVerifier(c, anchor)
	if e != nil || !h.valid() {
		return View{}, 0, ErrInvalid
	}
	for _, r := range h.Receipts {
		if v.advance(r) != nil {
			return View{}, 0, ErrInvalid
		}
	}
	size, e := h.storageSize()
	if e != nil {
		return View{}, 0, e
	}
	out, e := v.finish(h.Snapshot)
	if e != nil {
		return View{}, 0, e
	}
	// Do not lend caller-owned mutable proof or ciphertext buffers to consumers.
	var owned View
	if json.Unmarshal(encoded(out), &owned) != nil {
		return View{}, 0, ErrInvalid
	}
	return owned, size, nil
}

// ReadHistory returns the trusted local view together with the exact signed
// transition history behind it. It opens the database once and verifies the
// chain once; the returned history satisfies VerifyHistory(anchor).
func ReadHistory(path string, c *Config, anchor Checkpoint) (View, History, error) {
	var h History
	res, e := readStore(path, c, anchor, &h)
	if e != nil {
		return View{}, History{}, e
	}
	return res.view, h, nil
}

func (c *Config) WriterACLPolicy() bool              { return c.valid() && c.writerACL && c.requirePossession }
func (c *Config) ValidCheckpoint(cp Checkpoint) bool { return c.validCheckpoint(cp) }
func (c *Config) SequencerSigningKey() ed25519.PublicKey {
	if !c.valid() {
		return nil
	}
	return bytes.Clone(c.sequencer)
}
func (c *Config) OwnerSigningKey(id string) ed25519.PublicKey {
	if !c.valid() || !hexSize(id, 32) {
		return nil
	}
	return bytes.Clone(c.owners[id])
}
