package directory

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"

	"github.com/jihuayu/locklark/internal/vault"
	bolt "go.etcd.io/bbolt"
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

func ExportHistory(path string, c *Config, anchor Checkpoint) (out History, err error) {
	if !c.validCheckpoint(anchor) {
		return History{}, ErrInvalid
	}
	db, e := open(path, true, false)
	if e != nil {
		return History{}, ErrStorage
	}
	defer func() {
		if e := db.Close(); e != nil && err == nil {
			out = History{}
			err = ErrStorage
		}
	}()
	err = db.View(func(tx *bolt.Tx) error {
		v, _, e := load(tx, c, anchor)
		if e != nil {
			return e
		}
		out.Snapshot = v.Snapshot
		out.Receipts = make([]Receipt, 0, v.Receipt.Proposal.Epoch)
		size := len(`{"receipts":[`) + len(`],"snapshot":`) + len(encoded(v.Snapshot)) + 1
		return tx.Bucket(bucket).Bucket(recordsKey).ForEach(func(_ []byte, raw []byte) error {
			if len(out.Receipts) > 0 {
				size++
			}
			size += len(raw)
			if size > MaxHistoryBytes {
				return ErrCapacity
			}
			var receipt Receipt
			if json.Unmarshal(raw, &receipt) != nil {
				return ErrInvalid
			}
			out.Receipts = append(out.Receipts, receipt)
			return nil
		})
	})
	if err != nil {
		return History{}, err
	}
	return out, nil
}

func VerifyHistory(c *Config, anchor Checkpoint, h History) (View, error) {
	v, e := newHistoryVerifier(c, anchor)
	if e != nil || len(h.Receipts) == 0 || len(h.Receipts) > maxVersions {
		return View{}, ErrInvalid
	}
	size := len(`{"receipts":[`) + len(`],"snapshot":`) + 1
	for n, r := range h.Receipts {
		if v.advance(r) != nil {
			return View{}, ErrInvalid
		}
		raw := encoded(r)
		if len(raw) > maxRecord {
			return View{}, ErrInvalid
		}
		size += len(raw)
		if n > 0 {
			size++
		}
		if size > MaxHistoryBytes {
			return View{}, ErrCapacity
		}
	}
	out, e := v.finish(h.Snapshot)
	if e != nil {
		return View{}, e
	}
	if size+len(encoded(h.Snapshot)) > MaxHistoryBytes {
		return View{}, ErrCapacity
	}
	// Do not lend caller-owned mutable proof or ciphertext buffers to consumers.
	var owned View
	if json.Unmarshal(encoded(out), &owned) != nil {
		return View{}, ErrInvalid
	}
	return owned, nil
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
