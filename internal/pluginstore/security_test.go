package pluginstore

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	bolt "go.etcd.io/bbolt"
)

func TestCatalogIndependentPinsAndCorruption(t *testing.T) {
	path, s := fixture(t)
	raw := release(t, 1)
	s, e := Install(path, s.Checkpoint, "example.tools/pull-reader", pub(1), Digest(raw), raw, pinset())
	if e != nil {
		t.Fatal(e)
	}
	for _, pins := range []Pins{nil, {}, {"example.tools/pull-reader": pub(2)}} {
		if _, e = Read(path, s.Checkpoint, pins); e != ErrInvalid {
			t.Fatal("missing or replaced independent pin", e)
		}
	}
	_, other := fixture(t)
	if _, e = Read(path, other.Checkpoint, pinset()); e != ErrInvalid {
		t.Fatal("cross-catalog checkpoint", e)
	}
	if _, e = Read(path, Digest([]byte("unknown")), pinset()); e != ErrInvalid {
		t.Fatal("unknown checkpoint", e)
	}
	p, e := Verify(raw, "example.tools/pull-reader", pub(1))
	if e != nil {
		t.Fatal(e)
	}
	p.Version = 2
	replacement, e := Sign(p, key(2))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Install(path, s.Checkpoint, p.ID, pub(2), Digest(replacement), replacement, Pins{p.ID: pub(2)}); e != ErrInvalid {
		t.Fatal("pin rotation accepted", e)
	}
	s, e = Revoke(path, s.Checkpoint, p.ID, pinset())
	if e != nil {
		t.Fatal(e)
	}
	db, e := open(path, false)
	if e != nil {
		t.Fatal(e)
	}
	e = db.Update(func(tx *bolt.Tx) error { return tx.Bucket(packagesBucket).Delete([]byte(p.ID)) })
	db.Close()
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Read(path, s.Checkpoint, pinset()); e != ErrInvalid {
		t.Fatal("revoked proof silently dropped", e)
	}
}

func TestPackageEverySignedFieldAndBounds(t *testing.T) {
	raw := release(t, 1)
	original, e := Verify(raw, "example.tools/pull-reader", pub(1))
	if e != nil {
		t.Fatal(e)
	}
	for name, mutate := range map[string]func(*Release){
		"bundle": func(p *Release) { p.Bundle = []byte("throw 'tampered'") },
		"dependencies": func(p *Release) {
			p.Dependencies = []Dependency{{Name: "a", Version: "1.2.3", SHA256: Digest([]byte("dependency"))}}
		},
		"runtime":    func(p *Release) { p.Runtime = "bun-next" },
		"capability": func(p *Release) { p.Capabilities = []string{"shell"} },
		"version":    func(p *Release) { p.Version++ },
		"identity":   func(p *Release) { p.ID = "other.tools/pull-reader" },
		"signature":  func(p *Release) { p.Signature = bytes.Repeat([]byte{0}, 64) },
	} {
		t.Run(name, func(t *testing.T) {
			p := original
			mutate(&p)
			if _, e := Verify(encoded(p), original.ID, original.Publisher); e != ErrInvalid {
				t.Fatal("signature binding", e)
			}
		})
	}
	for _, mutate := range []func(*Release){
		func(p *Release) { p.Bundle = make([]byte, (1<<20)+1) }, func(p *Release) { p.Version = 1_000_000_001 }, func(p *Release) { p.Dependencies = make([]Dependency, 65) },
		func(p *Release) {
			p.Dependencies = []Dependency{{"a", "1.2.3", Digest(nil)}, {"a", "1.2.3", Digest(nil)}}
		},
		func(p *Release) { p.Dependencies = []Dependency{{"a", "^1.2.3", Digest(nil)}} },
		func(p *Release) { p.Capabilities = append([]string(nil), "github.pulls.get", "github.pulls.get") },
	} {
		p := original
		mutate(&p)
		if _, e := Sign(p, key(1)); e != ErrInvalid {
			t.Fatal("unsupported package shape", e)
		}
	}
	if _, e = Verify(make([]byte, MaxPackage+1), original.ID, original.Publisher); e != ErrInvalid {
		t.Fatal("unbounded package", e)
	}
}

func TestCatalogCapacityKeepsReadableHead(t *testing.T) {
	path, first := fixture(t)
	raw := release(t, maxEvents-1)
	db, e := open(path, false)
	if e != nil {
		t.Fatal(e)
	}
	var checkpoint string
	e = db.Update(func(tx *bolt.Tx) error {
		current, e := load(tx, first.Checkpoint, pinset())
		if e != nil {
			return e
		}
		previous := first.Checkpoint
		for n := uint64(2); n <= maxEvents; n++ {
			ev := Event{Sequence: n, Catalog: current.catalog, Action: "plugin.install", ID: "example.tools/pull-reader", Publisher: pub(1), Version: n - 1, Digest: Digest(raw), Previous: previous}
			if e = tx.Bucket(eventsBucket).Put(binary.BigEndian.AppendUint64(nil, n), encoded(ev)); e != nil {
				return e
			}
			previous = ev.hash()
		}
		checkpoint = previous
		return tx.Bucket(packagesBucket).Put([]byte("example.tools/pull-reader"), raw)
	})
	db.Close()
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Read(path, checkpoint, pinset()); e != nil {
		t.Fatal("capacity head unreadable", e)
	}
	raw = release(t, maxEvents)
	if _, e = Install(path, checkpoint, "example.tools/pull-reader", pub(1), Digest(raw), raw, pinset()); e != ErrCapacity {
		t.Fatal("capacity write", e)
	}
	if _, e = Read(path, checkpoint, pinset()); e != nil {
		t.Fatal("capacity changed state", e)
	}
}

func TestPackageAndPinsSources(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pins.json")
	for _, raw := range []string{fmt.Sprintf(`{"example.tools/pull-reader":%q,"example.tools/pull-reader":%q}`, pub(1), pub(1)), `{"a":null}`, `{} {}`, `[]`} {
		if e := os.WriteFile(path, []byte(raw), 0600); e != nil {
			t.Fatal(e)
		}
		if _, e := ReadPins(path); e != ErrInvalid {
			t.Fatal("invalid pins source", e)
		}
	}
	raw, _ := json.MarshalIndent(pinset(), "", "  ")
	if e := os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := ReadPins(path); e != nil {
		t.Fatal(e)
	}
	if _, e := ReadPackage(t.TempDir()); e != ErrInvalid {
		t.Fatal("directory source", e)
	}
	if e := os.WriteFile(path, make([]byte, MaxPackage+1), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := ReadPackage(path); e != ErrInvalid {
		t.Fatal("oversized source", e)
	}
}

func TestCatalogPhysicalSizeAndGrowthLimit(t *testing.T) {
	oversized := filepath.Join(t.TempDir(), "oversized.db")
	f, e := os.Create(oversized)
	if e != nil {
		t.Fatal(e)
	}
	e = f.Truncate(maxCatalogSize + 1)
	closeErr := f.Close()
	if e != nil || closeErr != nil {
		t.Fatal("oversized fixture", e, closeErr)
	}
	for _, readOnly := range []bool{true, false} {
		db, e := open(oversized, readOnly)
		if db != nil {
			db.Close()
			t.Fatal("oversized file mapped")
		}
		if e != ErrInvalid {
			t.Fatal("oversized file guard", e)
		}
	}
	path, first := fixture(t)
	raw := release(t, 1)
	p, e := Verify(raw, "example.tools/pull-reader", pub(1))
	if e != nil {
		t.Fatal(e)
	}
	p.Bundle = bytes.Repeat([]byte("x"), 256<<10)
	raw, e = Sign(p, key(1))
	if e != nil {
		t.Fatal(e)
	}
	p, e = Verify(raw, p.ID, p.Publisher)
	if e != nil {
		t.Fatal(e)
	}
	db, e := open(path, false)
	if e != nil {
		t.Fatal(e)
	}
	if db.MaxSize != maxCatalogSize {
		t.Fatal("bbolt growth not bounded")
	}
	// Exercise bbolt's real commit-time growth guard with a small test budget.
	db.MaxSize = 64 << 10
	db.AllocSize = 4 << 10
	got, e := mutateWithUpdate(db.Update, first.Checkpoint, p.ID, &p, raw, pinset())
	db.Close()
	if e != ErrCapacity || got.Checkpoint != "" {
		t.Fatal("physical growth limit receipt", e)
	}
	after, e := Read(path, first.Checkpoint, pinset())
	if e != nil || after.Checkpoint != first.Checkpoint || after.Sequence != 1 {
		t.Fatal("growth failure changed head", e)
	}
}
