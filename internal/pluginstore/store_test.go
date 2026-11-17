package pluginstore

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"

	bolt "go.etcd.io/bbolt"
)

func pinset() Pins                  { return Pins{"example.tools/pull-reader": pub(1)} }
func key(n byte) ed25519.PrivateKey { return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{n}, 32)) }
func pub(n byte) string             { return hex.EncodeToString(key(n).Public().(ed25519.PublicKey)) }
func release(t *testing.T, v uint64) []byte {
	t.Helper()
	raw, e := Sign(Release{Schema: 1, ID: "example.tools/pull-reader", Version: v, Runtime: "bun-1.4.4/bundled-v1", Capabilities: []string{"github.pulls.get"}, Dependencies: []Dependency{}, Bundle: []byte("console.log('synthetic proposal');")}, key(1))
	if e != nil {
		t.Fatal(e)
	}
	return raw
}
func fixture(t *testing.T) (string, Status) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "catalog.db")
	s, e := Create(path)
	if e != nil {
		t.Fatal(e)
	}
	return path, s
}

func TestSignedCatalogLifecycle(t *testing.T) {
	path, first := fixture(t)
	raw := release(t, 1)
	installed, e := Install(path, first.Checkpoint, "example.tools/pull-reader", pub(1), Digest(raw), raw, pinset())
	if e != nil {
		t.Fatal(e)
	}
	if installed.Execution != "disabled" || len(installed.Plugins) != 1 || installed.Plugins[0].Version != 1 {
		t.Fatal("installed view")
	}
	if _, e = Install(path, installed.Checkpoint, "example.tools/pull-reader", pub(1), Digest(raw), raw, pinset()); e != ErrVersion {
		t.Fatal("same version", e)
	}
	p, e := Verify(raw, "example.tools/pull-reader", pub(1))
	if e != nil {
		t.Fatal(e)
	}
	p.Bundle = []byte("console.log('different same-version code')")
	changed, e := Sign(p, key(1))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Install(path, installed.Checkpoint, p.ID, p.Publisher, Digest(changed), changed, pinset()); e != ErrVersion {
		t.Fatal("same version substituted", e)
	}
	old := bytes.Clone(raw)
	raw = release(t, 2)
	upgraded, e := Install(path, installed.Checkpoint, "example.tools/pull-reader", pub(1), Digest(raw), raw, pinset())
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Install(path, upgraded.Checkpoint, p.ID, p.Publisher, Digest(old), old, pinset()); e != ErrVersion {
		t.Fatal("downgrade", e)
	}
	if _, e = Read(path, first.Checkpoint, pinset()); e != nil {
		t.Fatal("ancestor checkpoint", e)
	}
	if _, e = Install(path, installed.Checkpoint, "example.tools/pull-reader", pub(1), Digest(raw), raw, pinset()); e != ErrConflict {
		t.Fatal("stale parent", e)
	}
	revoked, e := Revoke(path, upgraded.Checkpoint, "example.tools/pull-reader", pinset())
	if e != nil {
		t.Fatal(e)
	}
	if !revoked.Plugins[0].Revoked || revoked.Plugins[0].Version != 2 {
		t.Fatal("revocation tombstone")
	}
	raw = release(t, 3)
	if _, e = Install(path, revoked.Checkpoint, "example.tools/pull-reader", pub(1), Digest(raw), raw, pinset()); e != ErrRevoked {
		t.Fatal("revoked reinstall", e)
	}
	events, e := Audit(path, revoked.Checkpoint, pinset())
	if e != nil || len(events) != 4 || events[3].Action != "plugin.revoke" {
		t.Fatal("audit", e)
	}
	if _, e = Create(path); e != ErrExists {
		t.Fatal("overwritten catalog", e)
	}
	db, e := open(path, true)
	if e != nil {
		t.Fatal(e)
	}
	e = db.View(func(tx *bolt.Tx) error {
		if tx.Bucket(packagesBucket).Get([]byte("example.tools/pull-reader")) == nil {
			t.Fatal("revoked signature evidence lost")
		}
		return nil
	})
	db.Close()
	if e != nil {
		t.Fatal(e)
	}
}

func TestPackageSignatureAndPinning(t *testing.T) {
	raw := release(t, 1)
	if _, e := Verify(raw, "example.tools/pull-reader", pub(1)); e != nil {
		t.Fatal(e)
	}
	for _, bad := range [][]byte{append(append([]byte(nil), raw...), '\n'), bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":2`), 1), bytes.Replace(raw, []byte(`"schema":1`), []byte(`"schema":1,"schema":1`), 1)} {
		if _, e := Verify(bad, "example.tools/pull-reader", pub(1)); e != ErrInvalid {
			t.Fatal("noncanonical or forged package", e)
		}
	}
	if _, e := Verify(raw, "other.tools/pull-reader", pub(1)); e != ErrInvalid {
		t.Fatal("ID substitution", e)
	}
	if _, e := Verify(raw, "example.tools/pull-reader", pub(2)); e != ErrInvalid {
		t.Fatal("publisher substitution", e)
	}
	p, e := Verify(raw, "example.tools/pull-reader", pub(1))
	if e != nil {
		t.Fatal(e)
	}
	p.Capabilities = []string{"shell"}
	if _, e = Sign(p, key(1)); e != ErrInvalid {
		t.Fatal("unknown capability", e)
	}
	p.Capabilities = []string{"github.pulls.get"}
	p.Dependencies = []Dependency{{Name: "test-package", Version: "latest", SHA256: hex.EncodeToString(make([]byte, 32))}}
	if _, e = Sign(p, key(1)); e != ErrInvalid {
		t.Fatal("floating dependency", e)
	}
	path, s := fixture(t)
	if _, e = Install(path, s.Checkpoint, "example.tools/pull-reader", pub(1), Digest([]byte("changed")), raw, pinset()); e != ErrInvalid {
		t.Fatal("changed inspected source", e)
	}
}

func TestCatalogRollbackAndConcurrentCAS(t *testing.T) {
	path, first := fixture(t)
	saved, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	raw := release(t, 1)
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, e := Install(path, first.Checkpoint, "example.tools/pull-reader", pub(1), Digest(raw), raw, pinset())
			errs <- e
		}()
	}
	wg.Wait()
	close(errs)
	success, conflict := 0, 0
	for e := range errs {
		if e == nil {
			success++
		} else if e == ErrConflict {
			conflict++
		} else {
			t.Fatal(e)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatal("CAS")
	}
	current, e := Read(path, first.Checkpoint, pinset())
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(path, saved, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = Read(path, current.Checkpoint, pinset()); e != ErrInvalid {
		t.Fatal("disk rollback", e)
	}
}

func TestCatalogTransactionAndCloseFailure(t *testing.T) {
	path, s := fixture(t)
	raw := release(t, 1)
	p, e := Verify(raw, "example.tools/pull-reader", pub(1))
	if e != nil {
		t.Fatal(e)
	}
	db, e := open(path, false)
	if e != nil {
		t.Fatal(e)
	}
	injected := errors.New("injected")
	result, e := mutateWithUpdate(func(fn func(*bolt.Tx) error) error {
		return db.Update(func(tx *bolt.Tx) error {
			if e := fn(tx); e != nil {
				return e
			}
			return injected
		})
	}, s.Checkpoint, p.ID, &p, raw, pinset())
	db.Close()
	if e != ErrStorage || !reflect.DeepEqual(result, Status{}) {
		t.Fatal("rollback receipt", e)
	}
	after, e := Read(path, s.Checkpoint, pinset())
	if e != nil || !reflect.DeepEqual(after, s) {
		t.Fatal("partial transaction", e)
	}
	result, e = withClose(func() (Status, error) {
		return Install(path, s.Checkpoint, p.ID, p.Publisher, Digest(raw), raw, pinset())
	}, func() error { return injected })
	if e != ErrStorage || !reflect.DeepEqual(result, Status{}) {
		t.Fatal("close receipt", e)
	}
	after, e = Read(path, s.Checkpoint, pinset())
	if e != nil || after.Sequence != 2 {
		t.Fatal("lost receipt recovery", e)
	}
}

// TestMutationReplaysCatalogOnce pins the #102 accept criterion: a mutation
// replays the catalog events and re-verifies package signatures once, and its
// receipt equals a fresh Read of the committed head.
func TestMutationReplaysCatalogOnce(t *testing.T) {
	path, first := fixture(t)
	raw := release(t, 1)
	var loads int
	loadObserver = func() { loads++ }
	defer func() { loadObserver = nil }()
	installed, e := Install(path, first.Checkpoint, "example.tools/pull-reader", pub(1), Digest(raw), raw, pinset())
	if e != nil {
		t.Fatal(e)
	}
	if loads != 1 {
		t.Fatalf("install replayed the catalog %d times", loads)
	}
	loads = 0
	upgraded, e := Install(path, installed.Checkpoint, "example.tools/pull-reader", pub(1), Digest(release(t, 2)), release(t, 2), pinset())
	if e != nil {
		t.Fatal(e)
	}
	if loads != 1 {
		t.Fatalf("upgrade replayed the catalog %d times", loads)
	}
	loads = 0
	revoked, e := Revoke(path, upgraded.Checkpoint, "example.tools/pull-reader", pinset())
	if e != nil {
		t.Fatal(e)
	}
	if loads != 1 {
		t.Fatalf("revoke replayed the catalog %d times", loads)
	}
	read, e := Read(path, revoked.Checkpoint, pinset())
	if e != nil || !reflect.DeepEqual(read, revoked) {
		t.Fatal("mutation receipt diverged from a fresh replay", e)
	}
}
