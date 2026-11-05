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
	current := c.Genesis()
	matched := anchor == current
	e := newEvolution()
	err := records.ForEach(func(k, raw []byte) error {
		if len(k) != 8 || current.Version >= maxVersions || binary.BigEndian.Uint64(k) != current.Version+1 || len(raw) > maxRecord {
			return ErrInvalid
		}
		var receipt Receipt
		if !canonical(raw, &receipt) || c.verifyReceipt(receipt) != nil || receipt.Proposal.Parent != current || e.advance(receipt.Proposal) != nil {
			return ErrInvalid
		}
		current = receipt.Checkpoint()
		if current == anchor {
			matched = true
		}
		out.Receipt = receipt
		return nil
	})
	if err != nil || current.Version == 0 || !matched {
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
	return out, e, nil
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
		if state.advance(p) != nil {
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

// Read verifies the entire owner/sequencer chain and requires the independently
// retained anchor to be an ancestor (or the exact head). A genesis anchor has no
// rollback protection. Read from the trusted sequencer's local storage only;
// an untrusted relay can withhold a newer valid head.
func Read(path string, c *Config, anchor Checkpoint) (out View, err error) {
	if !c.validCheckpoint(anchor) {
		return View{}, ErrInvalid
	}
	db, err := open(path, true, false)
	if err != nil {
		return View{}, ErrStorage
	}
	defer func() {
		if closeErr := db.Close(); closeErr != nil && err == nil {
			out = View{}
			err = ErrStorage
		}
	}()
	err = db.View(func(tx *bolt.Tx) error { var e error; out, _, e = load(tx, c, anchor); return e })
	if err != nil {
		return View{}, err
	}
	return out, nil
}
