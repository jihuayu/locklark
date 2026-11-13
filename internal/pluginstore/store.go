package pluginstore

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"time"

	bolt "go.etcd.io/bbolt"
	berrors "go.etcd.io/bbolt/errors"
)

var eventsBucket = []byte("locklark.plugin-events/v1")
var packagesBucket = []byte("locklark.plugin-packages/v1")

const maxCatalogSize = 256 << 20

type Info struct {
	ID        string `json:"id"`
	Publisher string `json:"publisher"`
	Version   uint64 `json:"version"`
	Digest    string `json:"package_digest"`
	Revoked   bool   `json:"revoked"`
}
type Status struct {
	Checkpoint string `json:"checkpoint"`
	Sequence   uint64 `json:"sequence"`
	Execution  string `json:"execution"`
	Plugins    []Info `json:"plugins"`
}

// Events are local operator records, not cryptographic owner signatures.
// The catalog relies on a trusted local filesystem; an external checkpoint
// detects rollback, but does not authenticate a malicious local user's appends.
type Event struct {
	Sequence  uint64 `json:"sequence"`
	Catalog   string `json:"catalog"`
	Action    string `json:"action"`
	ID        string `json:"id,omitempty"`
	Publisher string `json:"publisher,omitempty"`
	Version   uint64 `json:"version,omitempty"`
	Digest    string `json:"package_digest,omitempty"`
	Previous  string `json:"previous,omitempty"`
}

func (e Event) hash() string {
	h := sha256.Sum256(append([]byte("locklark/plugin-catalog/event/v1\x00"), encoded(e)...))
	return hex.EncodeToString(h[:])
}
func canonical(raw []byte, v any) bool {
	return len(raw) > 0 && json.Unmarshal(raw, v) == nil && bytes.Equal(raw, encoded(v))
}

type state struct {
	status  Status
	events  []Event
	plugins map[string]Info
	catalog string
}

// loadObserver is a test seam that counts full catalog replays; it is nil in
// production.
var loadObserver func()

func load(tx *bolt.Tx, anchor string, pins Pins) (state, error) {
	if loadObserver != nil {
		loadObserver()
	}
	out := state{plugins: map[string]Info{}, status: Status{Execution: "disabled", Plugins: []Info{}}}
	if !hexValue(anchor, 32) {
		return state{}, ErrInvalid
	}
	events, packages := tx.Bucket(eventsBucket), tx.Bucket(packagesBucket)
	if events == nil || packages == nil {
		return state{}, ErrInvalid
	}
	matched := false
	e := events.ForEach(func(k, raw []byte) error {
		if len(k) != 8 || len(raw) > 2048 || out.status.Sequence >= maxEvents || binary.BigEndian.Uint64(k) != out.status.Sequence+1 {
			return ErrInvalid
		}
		var ev Event
		if !canonical(raw, &ev) || ev.Sequence != out.status.Sequence+1 || !hexValue(ev.Catalog, 16) || ev.Previous != out.status.Checkpoint {
			return ErrInvalid
		}
		if ev.Sequence == 1 {
			if ev.Action != "catalog.create" || ev.ID != "" || ev.Publisher != "" || ev.Version != 0 || ev.Digest != "" {
				return ErrInvalid
			}
			out.catalog = ev.Catalog
		} else {
			if ev.Catalog != out.catalog || !ValidID(ev.ID) || !hexValue(ev.Digest, 32) || ev.Version == 0 || ev.Version > 1_000_000_000 {
				return ErrInvalid
			}
			if _, e := publicKey(ev.Publisher); e != nil {
				return ErrInvalid
			}
			old, found := out.plugins[ev.ID]
			switch ev.Action {
			case "plugin.install":
				if found && (old.Revoked || old.Publisher != ev.Publisher || ev.Version <= old.Version) || !found && len(out.plugins) >= maxPlugins {
					return ErrInvalid
				}
				out.plugins[ev.ID] = Info{ID: ev.ID, Publisher: ev.Publisher, Version: ev.Version, Digest: ev.Digest}
			case "plugin.revoke":
				if !found || old.Revoked || old.Publisher != ev.Publisher || old.Version != ev.Version || old.Digest != ev.Digest {
					return ErrInvalid
				}
				old.Revoked = true
				out.plugins[ev.ID] = old
			default:
				return ErrInvalid
			}
		}
		out.status.Sequence = ev.Sequence
		out.status.Checkpoint = ev.hash()
		matched = matched || out.status.Checkpoint == anchor
		out.events = append(out.events, ev)
		return nil
	})
	if e != nil || !matched || out.status.Sequence == 0 {
		return state{}, ErrInvalid
	}
	count := 0
	e = packages.ForEach(func(k, raw []byte) error {
		if len(k) > 113 || len(raw) > MaxPackage {
			return ErrInvalid
		}
		info, ok := out.plugins[string(k)]
		if !ok {
			return ErrInvalid
		}
		if pins[info.ID] != info.Publisher {
			return ErrInvalid
		}
		p, e := Verify(raw, info.ID, pins[info.ID])
		if e != nil || p.Version != info.Version || Digest(raw) != info.Digest {
			return ErrInvalid
		}
		count++
		return nil
	})
	if e != nil {
		return state{}, ErrInvalid
	}
	for _, info := range out.plugins {
		out.status.Plugins = append(out.status.Plugins, info)
	}
	if len(out.plugins) != count {
		return state{}, ErrInvalid
	}
	sort.Slice(out.status.Plugins, func(i, j int) bool { return out.status.Plugins[i].ID < out.status.Plugins[j].ID })
	return out, nil
}

func open(path string, readOnly bool) (*bolt.DB, error) {
	return bolt.Open(path, 0600, &bolt.Options{ReadOnly: readOnly, MaxSize: maxCatalogSize, Timeout: 5 * time.Second, OpenFile: func(name string, flags int, mode os.FileMode) (*os.File, error) {
		f, e := os.OpenFile(name, flags&^os.O_CREATE|nonblock, mode)
		if e != nil {
			return nil, e
		}
		st, e := f.Stat()
		if e != nil || !st.Mode().IsRegular() || st.Size() > maxCatalogSize {
			f.Close()
			return nil, ErrInvalid
		}
		return f, nil
	}})
}
func withClose(run func() (Status, error), closeDB func() error) (out Status, err error) {
	defer func() {
		if e := closeDB(); e != nil && err == nil {
			out = Status{}
			err = ErrStorage
		}
	}()
	return run()
}
func Create(path string) (Status, error) {
	f, e := os.CreateTemp(filepath.Dir(path), ".locklark-plugins-*")
	if e != nil {
		return Status{}, ErrStorage
	}
	defer os.Remove(f.Name())
	if f.Close() != nil {
		return Status{}, ErrStorage
	}
	db, e := open(f.Name(), false)
	if e != nil {
		return Status{}, ErrStorage
	}
	out, e := withClose(func() (Status, error) {
		id := make([]byte, 16)
		if _, e := rand.Read(id); e != nil {
			return Status{}, ErrStorage
		}
		ev := Event{Sequence: 1, Catalog: hex.EncodeToString(id), Action: "catalog.create"}
		e := db.Update(func(tx *bolt.Tx) error {
			b, e := tx.CreateBucket(eventsBucket)
			if e != nil {
				return e
			}
			if _, e = tx.CreateBucket(packagesBucket); e != nil {
				return e
			}
			return b.Put(binary.BigEndian.AppendUint64(nil, 1), encoded(ev))
		})
		if e != nil {
			return Status{}, ErrStorage
		}
		return Status{Checkpoint: ev.hash(), Sequence: 1, Execution: "disabled", Plugins: []Info{}}, nil
	}, db.Close)
	if e != nil {
		return Status{}, e
	}
	if e = publish(f.Name(), path); e != nil {
		if errors.Is(e, os.ErrExist) {
			return Status{}, ErrExists
		}
		return Status{}, ErrStorage
	}
	return out, nil
}

func Install(path, parent, id, publisher, digest string, raw []byte, pins Pins) (Status, error) {
	if len(raw) > MaxPackage || !hexValue(parent, 32) || !hexValue(digest, 32) {
		return Status{}, ErrInvalid
	}
	pins, e := copyPins(pins)
	if e != nil || pins[id] != publisher {
		return Status{}, ErrInvalid
	}
	raw = bytes.Clone(raw)
	p, e := Verify(raw, id, publisher)
	if e != nil || Digest(raw) != digest {
		return Status{}, ErrInvalid
	}
	return mutate(path, parent, id, &p, raw, pins)
}
func Revoke(path, parent, id string, pins Pins) (Status, error) {
	if !ValidID(id) || !hexValue(parent, 32) {
		return Status{}, ErrInvalid
	}
	pins, e := copyPins(pins)
	if e != nil {
		return Status{}, e
	}
	return mutate(path, parent, id, nil, nil, pins)
}
func mutate(path, parent, id string, p *Release, raw []byte, pins Pins) (Status, error) {
	db, e := open(path, false)
	if e != nil {
		return Status{}, ErrStorage
	}
	return withClose(func() (Status, error) { return mutateWithUpdate(db.Update, parent, id, p, raw, pins) }, db.Close)
}
func mutateWithUpdate(update func(func(*bolt.Tx) error) error, parent, id string, p *Release, raw []byte, pins Pins) (Status, error) {
	var result Status
	e := update(func(tx *bolt.Tx) error {
		events, packages := tx.Bucket(eventsBucket), tx.Bucket(packagesBucket)
		if events == nil || packages == nil {
			return ErrInvalid
		}
		before, e := load(tx, parent, pins)
		if e != nil {
			return e
		}
		if before.status.Checkpoint != parent {
			return ErrConflict
		}
		if before.status.Sequence >= maxEvents {
			return ErrCapacity
		}
		old, found := before.plugins[id]
		if found && old.Revoked {
			return ErrRevoked
		}
		ev := Event{Sequence: before.status.Sequence + 1, Catalog: before.catalog, ID: id, Previous: parent}
		// Decode before appending so every later check can fail the transaction
		// without leaving a partially applied event.
		var next Release
		var digest string
		if p != nil {
			raw = bytes.Clone(raw)
			if next, digest, e = verifyDigest(raw, id, p.Publisher); e != nil || next.Publisher != p.Publisher || next.Version != p.Version {
				return ErrInvalid
			}
		}
		if p == nil {
			if !found {
				return ErrNotFound
			}
			ev.Action = "plugin.revoke"
			ev.Publisher = old.Publisher
			ev.Version = old.Version
			ev.Digest = old.Digest
			// Retain the last signed bundle so revoked entries remain verifiable.
			// There is no execution or re-enable API, including for these bytes.
		} else {
			if found && p.Publisher != old.Publisher {
				return ErrPublisher
			}
			if found && p.Version <= old.Version {
				return ErrVersion
			}
			if !found && len(before.plugins) >= maxPlugins {
				return ErrCapacity
			}
			ev.Action = "plugin.install"
			ev.Publisher = p.Publisher
			ev.Version = p.Version
			ev.Digest = digest
			if e = packages.Put([]byte(id), raw); e != nil {
				return e
			}
		}
		if e = events.Put(binary.BigEndian.AppendUint64(nil, ev.Sequence), encoded(ev)); e != nil {
			return e
		}
		// Apply the appended event to the loaded state instead of replaying the
		// whole catalog. The second pass could only differ from this apply by
		// finding a store corruption that rolls this transaction back, so a
		// failed apply rejects instead of committing a divergent head.
		after, e := before.applied(ev, digest, p != nil)
		if e != nil {
			return e
		}
		// load lists the same plugin map sorted and never exposes the internal
		// map or event slice, so the mutation receipt keeps that shape.
		result = after.status
		result.Plugins = make([]Info, 0, len(after.plugins))
		for _, info := range after.plugins {
			result.Plugins = append(result.Plugins, info)
		}
		sort.Slice(result.Plugins, func(i, j int) bool { return result.Plugins[i].ID < result.Plugins[j].ID })
		return nil
	})
	if e != nil {
		if errors.Is(e, berrors.ErrMaxSizeReached) {
			return Status{}, ErrCapacity
		}
		switch e {
		case ErrInvalid, ErrConflict, ErrVersion, ErrRevoked, ErrPublisher, ErrNotFound, ErrCapacity:
			return Status{}, e
		default:
			return Status{}, ErrStorage
		}
	}
	return result, nil
}

// applied advances an already canonical event series by one canonical event
// and mirrors the matching per-event rules of load without re-reading package
// blobs. A mismatch returns ErrInvalid.
func (s state) applied(ev Event, digest string, install bool) (state, error) {
	next := ev.Sequence
	if next != s.status.Sequence+1 || !hexValue(ev.Catalog, 16) || ev.Catalog != s.catalog || ev.Previous != s.status.Checkpoint || !ValidID(ev.ID) || !hexValue(ev.Digest, 32) || ev.Version == 0 || ev.Version > 1_000_000_000 || install != (ev.Action == "plugin.install") {
		return state{}, ErrInvalid
	}
	old, found := s.plugins[ev.ID]
	plugins := make(map[string]Info, len(s.plugins)+1)
	for id, info := range s.plugins {
		plugins[id] = info
	}
	plugins[ev.ID] = old
	receipt := s.status
	if install {
		if found && (old.Revoked || old.Publisher != ev.Publisher || ev.Version <= old.Version) || !found && len(s.plugins) >= maxPlugins {
			return state{}, ErrInvalid
		}
		plugins[ev.ID] = Info{ID: ev.ID, Publisher: ev.Publisher, Version: ev.Version, Digest: ev.Digest}
		for n, listed := range receipt.Plugins {
			if listed.ID == ev.ID {
				receipt.Plugins[n] = plugins[ev.ID]
			}
		}
	} else {
		if !found || old.Revoked || old.Publisher != ev.Publisher || old.Version != ev.Version || old.Digest != ev.Digest {
			return state{}, ErrInvalid
		}
		old.Revoked = true
		plugins[ev.ID] = old
	}
	events := append(s.events[:len(s.events):len(s.events)], ev)
	receipt.Sequence, receipt.Checkpoint = next, ev.hash()
	return state{status: receipt, events: events, plugins: plugins, catalog: s.catalog}, nil
}

func Read(path, anchor string, pins Pins) (Status, error) {
	pins, e := copyPins(pins)
	if e != nil {
		return Status{}, e
	}
	db, e := open(path, true)
	if e != nil {
		return Status{}, ErrStorage
	}
	return withClose(func() (Status, error) {
		var s state
		e := db.View(func(tx *bolt.Tx) error { var err error; s, err = load(tx, anchor, pins); return err })
		if e != nil {
			return Status{}, e
		}
		return s.status, nil
	}, db.Close)
}
func Audit(path, anchor string, pins Pins) (out []Event, err error) {
	pins, e := copyPins(pins)
	if e != nil {
		return nil, e
	}
	db, e := open(path, true)
	if e != nil {
		return nil, ErrStorage
	}
	defer func() {
		if e := db.Close(); e != nil && err == nil {
			out = nil
			err = ErrStorage
		}
	}()
	e = db.View(func(tx *bolt.Tx) error {
		s, e := load(tx, anchor, pins)
		if e == nil {
			out = s.events
		}
		return e
	})
	if e != nil {
		return nil, e
	}
	return out, nil
}
