package directory

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/jihuayu/locklark/internal/vault"
	bolt "go.etcd.io/bbolt"
)

var bucket = []byte("locklark.team-directory/v1")
var recordsKey = []byte("records")
var snapshotKey = []byte("snapshot")

type locatedDevice struct {
	member string
	device Device
}
type evolution struct {
	ids, enc, sign map[string]bool
	members        map[string]bool
	devices        map[string]locatedDevice
	mode           string
	roster         []Member
}

func newEvolution() *evolution {
	return &evolution{ids: map[string]bool{}, enc: map[string]bool{}, sign: map[string]bool{}, members: map[string]bool{}, devices: map[string]locatedDevice{}}
}
func (e *evolution) advance(p Proposal) error {
	if e.mode == "frozen" && p.Mode == "frozen" {
		return ErrInvalid
	}
	nextMembers := map[string]bool{}
	nextDevices := map[string]locatedDevice{}
	for _, m := range p.Members {
		if !e.members[m.ID] && e.ids[m.ID] {
			return ErrInvalid
		}
		nextMembers[m.ID] = true
		e.ids[m.ID] = true
		for _, d := range m.Devices {
			old, found := e.devices[d.ID]
			if found {
				if old.member != m.ID || old.device != d {
					return ErrInvalid
				}
			} else if e.ids[d.ID] || e.enc[d.Encryption] || e.sign[d.Signing] {
				return ErrInvalid
			}
			e.ids[d.ID], e.enc[d.Encryption], e.sign[d.Signing] = true, true, true
			nextDevices[d.ID] = locatedDevice{m.ID, d}
		}
	}
	e.members, e.devices, e.mode = nextMembers, nextDevices, p.Mode
	e.roster = cloneMembers(p.Members)
	return nil
}
func canonical(raw []byte, v any) bool {
	return len(raw) > 0 && json.Unmarshal(raw, v) == nil && bytes.Equal(raw, encoded(v))
}

func load(tx *bolt.Tx, c *Config, anchor Checkpoint) (View, *evolution, error) {
	var out View
	if !c.validCheckpoint(anchor) {
		return out, nil, ErrInvalid
	}
	b := tx.Bucket(bucket)
	if b == nil {
		return out, nil, ErrInvalid
	}
	records := b.Bucket(recordsKey)
	if records == nil {
		return out, nil, ErrInvalid
	}
	verifier, err := newHistoryVerifier(c, anchor)
	if err != nil {
		return View{}, nil, err
	}
	err = records.ForEach(func(k, raw []byte) error {
		if len(k) != 8 || verifier.current.Version >= maxVersions || binary.BigEndian.Uint64(k) != verifier.current.Version+1 || len(raw) > maxRecord {
			return ErrInvalid
		}
		var receipt Receipt
		if !canonical(raw, &receipt) || verifier.advance(receipt) != nil {
			return ErrInvalid
		}
		out.Receipt = receipt
		return nil
	})
	if err != nil || verifier.current.Version == 0 || !verifier.matched {
		return View{}, nil, ErrInvalid
	}
	raw := b.Get(snapshotKey)
	if out.Receipt.Proposal.Mode == "active" {
		if len(raw) > 12<<20 || !canonical(raw, &out.Snapshot) || c.verifySnapshot(out.Receipt.Proposal, out.Snapshot) != nil {
			return View{}, nil, ErrInvalid
		}
	} else if raw != nil {
		return View{}, nil, ErrInvalid
	}
	out, err = verifier.finish(out.Snapshot)
	if err != nil {
		return View{}, nil, ErrInvalid
	}
	return out, verifier.state, nil
}

// readRequest narrows one store read. A nil value is a plain Read. A non-nil
// value also proves a detached proof anchor on the same pass and returns the
// sealed evidence behind it.
type readRequest struct{ proof Checkpoint }

// checkedView performs the single hash-chain pass for one request. Receipts and
// the head snapshot are re-verified from their stored canonical bytes. A plain
// read returns only the head view; a readRequest also returns every retained
// receipt, once both the persistent anchor and the requested proof anchor have
// been proven by that same pass.
func checkedView(tx *bolt.Tx, c *Config, anchor Checkpoint, req *readRequest) (res readResult, err error) {
	// A trusted single pass may pass the zero minimum NewHandler is constructed
	// with; any other anchor must be a canonical checkpoint.
	zeroMin := req != nil && anchor == (Checkpoint{})
	b := tx.Bucket(bucket)
	if b == nil || c == nil || !zeroMin && !c.validCheckpoint(anchor) {
		return readResult{}, ErrInvalid
	}
	records := b.Bucket(recordsKey)
	if records == nil {
		return readResult{}, ErrInvalid
	}
	v, err := newHistoryVerifier(c, anchor)
	if err != nil {
		return readResult{}, err
	}
	// The proof anchor is an additional constraint on the same pass, checked in
	// the same loop that advances the chain; the persistent anchor still decides
	// rollback exactly as Read does. A plain read has no proof anchor to match.
	// A proof anchor this configuration could not have issued is unsatisfiable on
	// this chain and is known before the pass; it never widens any check.
	proof, proofMatched := Checkpoint{}, true
	if req != nil {
		proof, proofMatched = req.proof, c.valid() && req.proof == c.Genesis()
	}
	var receipts []Receipt
	err = records.ForEach(func(k, raw []byte) error {
		if len(k) != 8 || len(raw) > maxRecord || v.current.Version >= maxVersions || binary.BigEndian.Uint64(k) != v.current.Version+1 {
			return ErrInvalid
		}
		var receipt Receipt
		if !canonical(raw, &receipt) || v.advance(receipt) != nil {
			return ErrInvalid
		}
		res.view.Receipt = receipt
		receipts = append(receipts, receipt)
		proofMatched = proofMatched || receipt.Checkpoint() == proof
		return nil
	})
	if err != nil || len(receipts) == 0 || !v.matched || !proofMatched {
		return readResult{}, ErrInvalid
	}
	raw := tx.Bucket(bucket).Get(snapshotKey)
	if len(raw) > 12<<20 {
		return readResult{}, ErrInvalid
	}
	var snapshot vault.Snapshot
	if res.view.Receipt.Proposal.Mode == "active" {
		if !canonical(raw, &snapshot) || c.verifySnapshot(res.view.Receipt.Proposal, snapshot) != nil {
			return readResult{}, ErrInvalid
		}
	} else if raw != nil {
		return readResult{}, ErrInvalid
	}
	if res.view, err = v.finish(snapshot); err != nil {
		return readResult{}, ErrInvalid
	}
	if req != nil {
		res.trusted = TrustedRead{valid: true, head: res.view.Receipt, receipts: receipts, snapshot: snapshot, signer: res.view.SnapshotSigner, proof: proof}
	}
	return res, nil
}

func cloneReceipts(in []Receipt) []Receipt {
	out := make([]Receipt, len(in))
	for i, r := range in {
		out[i] = r
		out[i].Proposal.Parent = r.Proposal.Parent
		out[i].Proposal.Members = cloneMembers(r.Proposal.Members)
		out[i].Proposal.Admissions = cloneAdmissions(r.Proposal.Admissions)
		out[i].Signature = bytes.Clone(r.Signature)
	}
	return out
}

func cloneSnapshot(s vault.Snapshot) vault.Snapshot {
	return vault.Snapshot{Epoch: s.Epoch, Database: bytes.Clone(s.Database), Envelope: bytes.Clone(s.Envelope), Signature: bytes.Clone(s.Signature)}
}
func open(path string, readOnly, initial bool) (*bolt.DB, error) {
	return bolt.Open(path, 0600, &bolt.Options{ReadOnly: readOnly, Timeout: 10 * time.Second, OpenFile: func(name string, flags int, mode os.FileMode) (*os.File, error) {
		f, err := os.OpenFile(name, flags&^os.O_CREATE, mode)
		if err != nil {
			return nil, err
		}
		st, err := f.Stat()
		if err != nil || !st.Mode().IsRegular() || st.Size() > 256<<20 || (!initial && st.Size() == 0) {
			f.Close()
			return nil, ErrInvalid
		}
		return f, nil
	}})
}
func authorized(c *Config, sequencer ed25519.PrivateKey, p Proposal, s vault.Snapshot) error {
	if !c.valid() || !validPrivate(sequencer) || !bytes.Equal(sequencer.Public().(ed25519.PublicKey), c.sequencer) || c.verifyProposal(p) != nil || c.verifySnapshot(p, s) != nil {
		return ErrInvalid
	}
	return nil
}

// Create commits a complete database in a temporary file, closes it, then
// atomically publishes a new name. A failed publish returns no receipt.
func Create(path string, c *Config, sequencer ed25519.PrivateKey, p Proposal, s vault.Snapshot) (Receipt, error) {
	if authorized(c, sequencer, p, s) != nil || p.Parent != c.Genesis() || p.Mode != "active" {
		return Receipt{}, ErrInvalid
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".locklark-directory-*")
	if err != nil {
		return Receipt{}, ErrStorage
	}
	defer os.Remove(f.Name())
	if f.Close() != nil {
		return Receipt{}, ErrStorage
	}
	receipt, err := commit(f.Name(), c, sequencer, p, s, true)
	if err != nil {
		return Receipt{}, err
	}
	if err = publishDirectory(f.Name(), path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return Receipt{}, ErrExists
		}
		return Receipt{}, ErrStorage
	}
	return receipt, nil
}
func Commit(path string, c *Config, sequencer ed25519.PrivateKey, p Proposal, s vault.Snapshot) (Receipt, error) {
	return commit(path, c, sequencer, p, s, false)
}
func commit(path string, c *Config, sequencer ed25519.PrivateKey, p Proposal, s vault.Snapshot, initial bool) (Receipt, error) {
	if err := authorized(c, sequencer, p, s); err != nil {
		return Receipt{}, err
	}
	db, err := open(path, false, initial)
	if err != nil {
		return Receipt{}, ErrStorage
	}
	return commitWithClose(func() (Receipt, error) { return commitWithUpdate(db.Update, c, sequencer, p, s, initial) }, db.Close)
}
func commitWithClose(run func() (Receipt, error), closeDB func() error) (out Receipt, err error) {
	defer func() {
		if closeErr := closeDB(); closeErr != nil && err == nil {
			out = Receipt{}
			err = ErrStorage
		}
	}()
	return run()
}
func commitWithUpdate(update func(func(*bolt.Tx) error) error, c *Config, sequencer ed25519.PrivateKey, p Proposal, s vault.Snapshot, initial bool) (Receipt, error) {
	if err := authorized(c, sequencer, p, s); err != nil {
		return Receipt{}, err
	}
	// Own the receipt's mutable slices independently of the caller's proposal.
	p.Members = cloneMembers(p.Members)
	p.Admissions = cloneAdmissions(p.Admissions)
	p.Signature = bytes.Clone(p.Signature)
	var out Receipt
	err := update(func(tx *bolt.Tx) error {
		var b *bolt.Bucket
		var state *evolution
		current := c.Genesis()
		if initial {
			if tx.Bucket(bucket) != nil || p.Parent != current || p.Mode != "active" {
				return ErrInvalid
			}
			var err error
			b, err = tx.CreateBucket(bucket)
			if err != nil {
				return ErrStorage
			}
			if _, err = b.CreateBucket(recordsKey); err != nil {
				return ErrStorage
			}
			state = newEvolution()
		} else {
			view, e, err := load(tx, c, c.Genesis())
			if err != nil {
				return err
			}
			current = view.Receipt.Checkpoint()
			state = e
			b = tx.Bucket(bucket)
		}
		if current.Version >= maxVersions {
			return ErrCapacity
		}
		if p.Parent != current {
			return ErrConflict
		}
		if c.verifyTransition(state, p) != nil || state.advance(p) != nil {
			return ErrInvalid
		}
		out = Receipt{Proposal: p}
		out.Signature = ed25519.Sign(sequencer, out.proof())
		raw := encoded(out)
		if len(raw) > maxRecord {
			return ErrInvalid
		}
		if err := b.Bucket(recordsKey).Put(binary.BigEndian.AppendUint64(nil, p.Epoch), raw); err != nil {
			return ErrStorage
		}
		if p.Mode == "frozen" {
			if err := b.Delete(snapshotKey); err != nil {
				return ErrStorage
			}
		} else {
			raw = encoded(s)
			if len(raw) > 12<<20 {
				return ErrInvalid
			}
			if err := b.Put(snapshotKey, raw); err != nil {
				return ErrStorage
			}
		}
		return nil
	})
	if err != nil {
		switch err {
		case ErrInvalid, ErrConflict, ErrCapacity:
			return Receipt{}, err
		default:
			return Receipt{}, ErrStorage
		}
	}
	return out, nil
}

// Read verifies the entire authorized-author/sequencer chain and requires the independently
// retained anchor to be an ancestor (or the exact head). A genesis anchor has no
// rollback protection. Read from the trusted sequencer's local storage only;
// an untrusted relay can withhold a newer valid head.
func Read(path string, c *Config, anchor Checkpoint) (View, error) {
	res, err := readStore(path, c, anchor, nil)
	if err != nil {
		return View{}, err
	}
	return res.view, nil
}

// readStore opens the trusted local directory once and performs one hash-chain
// pass. A non-nil readRequest additionally proves its proof anchor on the same
// pass and receives the sealed evidence behind it.
func readStore(path string, c *Config, anchor Checkpoint, req *readRequest) (res readResult, err error) {
	if c == nil || !c.validCheckpoint(anchor) {
		return readResult{}, ErrInvalid
	}
	db, err := open(path, true, false)
	if err != nil {
		return readResult{}, ErrStorage
	}
	var txn readResult
	err = db.View(func(tx *bolt.Tx) (e error) {
		txn, e = checkedView(tx, c, anchor, req)
		return e
	})
	if closeErr := db.Close(); closeErr != nil && err == nil {
		return readResult{}, ErrStorage
	}
	if err != nil {
		return readResult{}, err
	}
	return txn, nil
}

type readResult struct {
	view    View
	trusted TrustedRead
}
