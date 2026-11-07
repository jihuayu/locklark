package personal

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/vault"
	bolt "go.etcd.io/bbolt"
)

func cacheOf(s *Session) *auditCache {
	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	return s.audit
}

func openTestSession(t *testing.T, path string, key []byte) *Session {
	t.Helper()
	s, err := UnlockSession(path, []byte("fixture"), key, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func mutateVault(t *testing.T, path string, fn func(*bolt.Bucket) error) {
	t.Helper()
	db, err := existing(path)
	if err != nil {
		t.Fatal(err)
	}
	err = db.Update(func(tx *bolt.Tx) error { return fn(tx.Bucket(bucket)) })
	closeErr := db.Close()
	if err != nil {
		t.Fatal(err)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
}

func eventRawBytes(t *testing.T, path string) uint64 {
	t.Helper()
	db, err := existing(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n uint64
	if err = db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucket).Bucket(eventsKey).ForEach(func(_, raw []byte) error {
			n += uint64(len(raw))
			return nil
		})
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestAuditCacheWarmEquivalentAndMutableResults(t *testing.T) {
	path, key, _ := revealFixture(t)
	s := openTestSession(t, path, key)
	defer s.Lock()

	items1, revs1, err := s.ReadAuthenticatedItems(false)
	if err != nil {
		t.Fatal(err)
	}
	first := cacheOf(s)
	if first == nil || first.count == 0 || first.prefix == ([32]byte{}) {
		t.Fatal("first authenticated read did not publish a cache")
	}
	items2, revs2, err := s.ReadAuthenticatedItems(false)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(items1, items2) || !reflect.DeepEqual(revs1, revs2) {
		t.Fatal("warm result differs from cold result")
	}
	second := cacheOf(s)
	if second == nil || second.count != first.count || second.last != first.last {
		t.Fatal("warm read did not reuse/refresh the verified prefix")
	}

	// Caller mutation of the returned revision map must not reach the cache.
	for id := range revs2 {
		revs2[id] = "caller-mutated"
		break
	}
	_, revs3, err := s.ReadAuthenticatedItems(false)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(revs1, revs3) {
		t.Fatal("returned revision map aliases the cache")
	}

	s.clearAuditCache()
	itemsCold, revsCold, err := s.ReadAuthenticatedItems(false)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(items1, itemsCold) || !reflect.DeepEqual(revs1, revsCold) {
		t.Fatal("forced cold result differs from warm result")
	}

	rows1, err := s.List("active")
	if err != nil {
		t.Fatal(err)
	}
	rows2, err := s.List("active")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(rows1, rows2) {
		t.Fatal("warm session list differs")
	}
}

func TestAuditCacheMiddleAndShapeTampering(t *testing.T) {
	cases := []struct {
		name string
		fn   func(*bolt.Bucket) error
	}{
		{"corrupt-middle", func(b *bolt.Bucket) error {
			events := b.Bucket(eventsKey)
			key := eventKey(2)
			raw := bytes.Clone(events.Get(key))
			raw[len(raw)-1] ^= 1
			return events.Put(key, raw)
		}},
		{"delete-middle", func(b *bolt.Bucket) error { return b.Bucket(eventsKey).Delete(eventKey(2)) }},
		{"reorder-middle", func(b *bolt.Bucket) error {
			events := b.Bucket(eventsKey)
			a, c := bytes.Clone(events.Get(eventKey(2))), bytes.Clone(events.Get(eventKey(3)))
			if err := events.Put(eventKey(2), c); err != nil {
				return err
			}
			return events.Put(eventKey(3), a)
		}},
		{"truncate-tail", func(b *bolt.Bucket) error {
			events := b.Bucket(eventsKey)
			return events.Delete(eventKey(4))
		}},
		{"extra-event", func(b *bolt.Bucket) error {
			events := b.Bucket(eventsKey)
			_, last := events.Cursor().Last()
			return events.Put(eventKey(6), bytes.Clone(last))
		}},
		{"empty-value", func(b *bolt.Bucket) error { return b.Bucket(eventsKey).Put(eventKey(2), []byte{}) }},
		{"nested-bucket", func(b *bolt.Bucket) error { _, err := b.Bucket(eventsKey).CreateBucket(eventKey(6)); return err }},
		{"old-snapshot", func(b *bolt.Bucket) error {
			// The fixture's current snapshot was re-sealed for two items; a
			// captured one-event-era snapshot has the wrong signature/epoch.
			raw := bytes.Clone(b.Get(snapshotKey))
			// Replacing only the epoch leaves the tip mismatch check in force.
			var s vault.Snapshot
			if jsonErr := json.Unmarshal(raw, &s); jsonErr != nil {
				return jsonErr
			}
			s.Epoch++
			out, jsonErr := json.Marshal(s)
			if jsonErr != nil {
				return jsonErr
			}
			return b.Put(snapshotKey, out)
		}},
		{"bad-tip", func(b *bolt.Bucket) error { return b.Put(tipKey, []byte("bad")) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path, key, _ := revealFixture(t)
			s := openTestSession(t, path, key)
			defer s.Lock()
			if _, _, err := s.ReadAuthenticatedItems(false); err != nil {
				t.Fatal(err)
			}
			if cacheOf(s) == nil {
				t.Fatal("no warm cache")
			}
			mutateVault(t, path, tc.fn)
			if _, _, err := s.ReadAuthenticatedItems(false); !errors.Is(err, invalid) {
				t.Fatalf("accepted tampered history: %v", err)
			}
		})
	}
}

func TestAuditCacheRestoredChainTampering(t *testing.T) {
	pw, key := "fixture", bytes.Repeat([]byte{4}, 16)
	src := filepath.Join(t.TempDir(), "src.ll")
	if err := Create(src, pw, key); err != nil {
		t.Fatal(err)
	}
	for _, title := range []string{"one", "two", "three"} {
		if _, err := AddLogin(src, pw, key, title, "user", "value-"+title); err != nil {
			t.Fatal(err)
		}
	}
	archive := filepath.Join(t.TempDir(), "history.llb")
	kit, err := Backup(src, archive, pw, key)
	if err != nil {
		t.Fatal(err)
	}
	newKey := bytes.Repeat([]byte{8}, 16)
	for _, kind := range []string{"altered", "malformed"} {
		t.Run(kind, func(t *testing.T) {
			restored := filepath.Join(t.TempDir(), "restored.ll")
			if err := Restore(archive, restored, pw, key, kit, newKey); err != nil {
				t.Fatal(err)
			}
			s := openTestSession(t, restored, newKey)
			defer s.Lock()
			if _, _, err := s.ReadAuthenticatedItems(false); err != nil {
				t.Fatal(err)
			}
			c := cacheOf(s)
			if c == nil || !c.archiveValid {
				t.Fatal("restored archive was not verified and cached")
			}
			chains, err := ArchivedAudit(restored, pw, newKey)
			if err != nil || len(chains) == 0 {
				t.Fatal("audit.archived lost restored chains", err)
			}
			mutateVault(t, restored, func(b *bolt.Bucket) error {
				if kind == "malformed" {
					return b.Put(archiveKey, []byte("bad archive"))
				}
				raw := bytes.Clone(b.Get(archiveKey))
				raw[len(raw)-1] ^= 1
				return b.Put(archiveKey, raw)
			})
			if _, _, err := s.ReadAuthenticatedItems(false); !errors.Is(err, invalid) {
				t.Fatalf("accepted %s archive: %v", kind, err)
			}
		})
	}
}

func TestAuditCacheAnotherSessionTailUpdatesRevisions(t *testing.T) {
	path, key, _ := revealFixture(t)
	s1 := openTestSession(t, path, key)
	defer s1.Lock()
	items, _, err := s1.ReadAuthenticatedItems(false)
	if err != nil {
		t.Fatal(err)
	}
	before := cacheOf(s1)
	if before == nil {
		t.Fatal("no cache")
	}
	s2 := openTestSession(t, path, key)
	defer s2.Lock()
	id, err := s2.AddLogin("from-another-session", "new-user", "new-password")
	if err != nil {
		t.Fatal(err)
	}
	items2, revs2, err := s1.ReadAuthenticatedItems(false)
	if err != nil {
		t.Fatal(err)
	}
	if len(items2) != len(items)+1 || revs2[id] == "" {
		t.Fatal("other session tail was not replayed")
	}
	after := cacheOf(s1)
	if after == nil || after.count <= before.count || after.last == before.last {
		t.Fatal("cache did not advance to the committed tail")
	}
}

func TestAuditCacheRollbackDoesNotPoison(t *testing.T) {
	path, key, _ := revealFixture(t)
	s := openTestSession(t, path, key)
	defer s.Lock()
	if _, _, err := s.ReadAuthenticatedItems(false); err != nil {
		t.Fatal(err)
	}
	before := cacheOf(s).clone()
	db, err := existing(path)
	if err != nil {
		t.Fatal(err)
	}
	injected := errors.New("injected rollback after cache candidate")
	_, err = commandWithUpdate(func(fn func(*bolt.Tx) error) error {
		return db.Update(func(tx *bolt.Tx) error {
			if err := fn(tx); err != nil {
				return err
			}
			return injected
		})
	}, "", nil, "item.list", vault.Item{}, nil, commandOption{unlocked: s})
	closeErr := db.Close()
	if !errors.Is(err, injected) || closeErr != nil {
		t.Fatalf("rollback injection: %v / %v", err, closeErr)
	}
	after := cacheOf(s)
	if after == nil || after.count != before.count || after.last != before.last {
		t.Fatal("rolled-back transaction poisoned the cache")
	}
	items, revs, err := s.ReadAuthenticatedItems(false)
	if err != nil || len(items) != len(before.revisions) || len(revs) != len(before.revisions) {
		t.Fatal("cache unusable after rollback", err)
	}
}

func TestAuditCacheLockDropsAndLatePopulationRefused(t *testing.T) {
	path, key, _ := revealFixture(t)
	s := openTestSession(t, path, key)
	if _, _, err := s.ReadAuthenticatedItems(false); err != nil {
		t.Fatal(err)
	}
	cached := cacheOf(s).clone()
	if cached == nil {
		t.Fatal("no cache")
	}
	s.Lock()
	if cacheOf(s) != nil {
		t.Fatal("lock retained audit cache")
	}
	if len(s.material) != 0 {
		t.Fatal("lock retained material")
	}
	s2 := openTestSession(t, path, key)
	if cacheOf(s2) != nil {
		t.Fatal("new session inherited cache")
	}
	s2.RequestLock()
	s2.setAuditCache(cached)
	if cacheOf(s2) != nil {
		t.Fatal("late population resurrected cache after RequestLock")
	}
	s2.Lock()
}

func TestAuditCacheHoldsNoSecretMaterial(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret.ll")
	key := bytes.Repeat([]byte{5}, 16)
	if err := Create(path, "fixture", key); err != nil {
		t.Fatal(err)
	}
	const sentinel = "SENTINEL-secret-password-value"
	if _, err := AddLogin(path, "fixture", key, "sentinel", "sentinel-user", sentinel); err != nil {
		t.Fatal(err)
	}
	s := openTestSession(t, path, key)
	defer s.Lock()
	if _, _, err := s.ReadAuthenticatedItems(false); err != nil {
		t.Fatal(err)
	}
	c := cacheOf(s)
	if c == nil {
		t.Fatal("no cache")
	}
	if strings.Contains(fmt.Sprintf("%+v", *c), sentinel) {
		t.Fatal("cache contains secret sentinel")
	}
	typ := reflect.TypeOf(*c)
	for i := 0; i < typ.NumField(); i++ {
		if k := typ.Field(i).Type.Kind(); k == reflect.Slice || k == reflect.Interface {
			t.Fatalf("cache stores variable-length field %s", typ.Field(i).Name)
		}
	}
	for id, rev := range c.revisions {
		if !idOK(id) || !digestOK(rev) {
			t.Fatal("cache revision entry is not an opaque ID/hash pair")
		}
	}
}

func TestAuditCacheWarmReadStillHashesEveryStoredByte(t *testing.T) {
	path, key, _ := revealFixture(t)
	s := openTestSession(t, path, key)
	defer s.Lock()
	want := eventRawBytes(t, path)
	if _, _, err := s.ReadAuthenticatedItems(false); err != nil {
		t.Fatal(err)
	}
	if got := cacheOf(s).hashedBytes; got != want {
		t.Fatalf("cold hash pass saw %d bytes, want %d", got, want)
	}
	if _, _, err := s.ReadAuthenticatedItems(false); err != nil {
		t.Fatal(err)
	}
	if got := cacheOf(s).hashedBytes; got != want {
		t.Fatalf("warm hash pass saw %d bytes, want %d (constant-time claim)", got, want)
	}
}

func TestAuditConsumersRetainCompleteHistory(t *testing.T) {
	path, key, _ := revealFixture(t)
	s := openTestSession(t, path, key)
	defer s.Lock()
	if _, _, err := s.ReadAuthenticatedItems(false); err != nil {
		t.Fatal(err)
	}
	// Warm normal action, then the audit consumer must still get every event.
	events, err := s.Audit()
	if err != nil {
		t.Fatal(err)
	}
	foundCreate, foundList := false, false
	for _, ev := range events {
		foundCreate = foundCreate || ev.Action == "vault.create"
		foundList = foundList || ev.Action == "audit.list"
	}
	if !foundCreate || !foundList {
		t.Fatal("audit.list lost history after cache warm")
	}
	// A full backup consumer must also verify and carry the history.
	archive := filepath.Join(t.TempDir(), "backup.llb")
	kit, err := Backup(path, archive, "fixture", key)
	if err != nil {
		t.Fatal(err)
	}
	restored := filepath.Join(t.TempDir(), "restored.ll")
	if err = Restore(archive, restored, "fixture", key, kit, bytes.Repeat([]byte{3}, 16)); err != nil {
		t.Fatal(err)
	}
	chains, err := ArchivedAudit(restored, "fixture", bytes.Repeat([]byte{3}, 16))
	if err != nil || len(chains) == 0 || len(chains[0].Events) < 2 {
		t.Fatal("backup/restore lost verified chain history", err)
	}
}
