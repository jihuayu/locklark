package vaultfilejournal

import (
	"bytes"
	"errors"
	"testing"

	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	bolt "go.etcd.io/bbolt"
)

// emptyBootstrapState is the exact state an empty-only bootstrap establishes:
// one pair of identical sealed bytes and the revision they were read at.
func emptyBootstrapState(seed byte) State {
	r := opaque(4096+int(seed), seed)
	return State{
		BaseBytes:      r,
		RemoteRevision: vaultfilebackend.Revision(`"bootstrap-etag-7"`),
		WorkingBytes:   bytes.Clone(r),
	}
}

// rawJournalSnapshot copies every raw key of every bucket, recursing into
// nested buckets, so a rejected call can be shown to have preserved every
// stored byte exactly, including the shape of a key that holds a bucket.
func rawJournalSnapshot(t *testing.T, j *Journal) map[string]map[string][]byte {
	t.Helper()
	j.mu.Lock()
	defer j.mu.Unlock()
	out := map[string]map[string][]byte{}
	err := j.db.View(func(tx *bolt.Tx) error {
		return tx.ForEach(func(name []byte, b *bolt.Bucket) error {
			return snapshotBucket(string(name), b, out)
		})
	})
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	return out
}

func snapshotBucket(prefix string, b *bolt.Bucket, out map[string]map[string][]byte) error {
	entries := map[string][]byte{}
	out[prefix] = entries
	return b.ForEach(func(k, v []byte) error {
		key := prefix + "\x00" + string(k)
		if nb := b.Bucket(k); nb != nil {
			return snapshotBucket(key, nb, out)
		}
		entries[key] = bytes.Clone(v)
		return nil
	})
}

func sameSnapshot(a, b map[string]map[string][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for name, entries := range a {
		other, ok := b[name]
		if !ok || len(entries) != len(other) {
			return false
		}
		for k, v := range entries {
			if !bytes.Equal(other[k], v) {
				return false
			}
		}
	}
	return true
}

// rawPut stores an arbitrary key/value directly, for fixtures the public API
// cannot produce (an unknown key, a deliberately corrupt record).
func rawPut(t *testing.T, j *Journal, bucket, key string, value []byte) {
	t.Helper()
	if err := rawUpdate(j, func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(bucket))
		if err != nil {
			return err
		}
		return b.Put([]byte(key), value)
	}); err != nil {
		t.Fatalf("rawPut: %v", err)
	}
}

// rawBucket stores a nested bucket, with one marker entry, under key in bucket.
// bbolt returns no value for such a key, which is exactly the shape a known
// record key must not be mistaken for an absent record.
func rawBucket(t *testing.T, j *Journal, bucket, key string) {
	t.Helper()
	if err := rawUpdate(j, func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(bucket))
		if err != nil {
			return err
		}
		nb, err := b.CreateBucket([]byte(key))
		if err != nil {
			return err
		}
		return nb.Put([]byte("nested"), []byte("synthetic-nested-bucket"))
	}); err != nil {
		t.Fatalf("rawBucket: %v", err)
	}
}

// rawUpdate runs fn in one write transaction on the open handle.
func rawUpdate(j *Journal, fn func(tx *bolt.Tx) error) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.db.Update(fn)
}

func TestInitializeEmptyStateSucceedsOnEmptyJournal(t *testing.T) {
	dir := privateDir(t)
	j := openAt(t, dir)
	s := emptyBootstrapState(1)
	if err := j.InitializeEmptyState(s); err != nil {
		t.Fatalf("InitializeEmptyState: %v", err)
	}
	assertState(t, mustLoadState(t, j), s)
	if _, err := j.Load(); !errors.Is(err, ErrEmpty) {
		t.Fatalf("Load after bootstrap = %v, want ErrEmpty", err)
	}
	if _, err := j.LoadPrepared(); !errors.Is(err, ErrEmpty) {
		t.Fatalf("LoadPrepared after bootstrap = %v, want ErrEmpty", err)
	}

	// The caller's slices are copied: mutating them cannot change the record.
	for i := range s.BaseBytes {
		s.BaseBytes[i] = 0xEE
	}
	for i := range s.WorkingBytes {
		s.WorkingBytes[i] = 0xEE
	}
	assertState(t, mustLoadState(t, j), emptyBootstrapState(1))

	// A reopened journal returns the identical record: exact bytes, the
	// opaque revision verbatim and generation 0.
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	re := openAt(t, dir)
	got := mustLoadState(t, re)
	assertState(t, got, emptyBootstrapState(1))
	if got.Generation != 0 {
		t.Fatalf("generation = %d, want 0", got.Generation)
	}
}

// TestInitializeEmptyStateRejectsExactReplay checks that an existing state is
// refused even when it is byte-for-byte the state the call would store: there
// is no exact-replay no-op, and the stored record is left untouched.
func TestInitializeEmptyStateRejectsExactReplay(t *testing.T) {
	j := openAt(t, privateDir(t))
	s := emptyBootstrapState(2)
	if err := j.InitializeEmptyState(s); err != nil {
		t.Fatalf("InitializeEmptyState: %v", err)
	}
	before := rawJournalSnapshot(t, j)
	err := j.InitializeEmptyState(s)
	if !errors.Is(err, ErrJournalNotEmpty) || !errors.Is(err, ErrStateExists) {
		t.Fatalf("exact replay = %v, want ErrJournalNotEmpty wrapping ErrStateExists", err)
	}
	if !sameSnapshot(before, rawJournalSnapshot(t, j)) {
		t.Fatal("a refused exact replay changed the stored record")
	}
	// The committed state is still exactly the one the caller stored; the
	// caller confirms it itself through LoadState.
	assertState(t, mustLoadState(t, j), s)

	// A different state that is itself a valid bootstrap state is refused the
	// same way, never overwritten.
	diff := emptyBootstrapState(5)
	if err := j.InitializeEmptyState(diff); !errors.Is(err, ErrJournalNotEmpty) {
		t.Fatalf("different state = %v, want ErrJournalNotEmpty", err)
	}
	if !sameSnapshot(before, rawJournalSnapshot(t, j)) {
		t.Fatal("a refused different state changed the stored record")
	}
	assertState(t, mustLoadState(t, j), s)
}

// TestInitializeEmptyStateRefusesAnInitializedJournalByReopening checks the
// persisted view too: a reopened journal holding exactly the same state still
// refuses it, and LoadState returns the committed record unchanged.
func TestInitializeEmptyStateRefusesAnInitializedJournalByReopening(t *testing.T) {
	dir := privateDir(t)
	j := openAt(t, dir)
	s := emptyBootstrapState(9)
	if err := j.InitializeEmptyState(s); err != nil {
		t.Fatal(err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	re := openAt(t, dir)
	if err := re.InitializeEmptyState(s); !errors.Is(err, ErrJournalNotEmpty) {
		t.Fatalf("replay after reopen = %v, want ErrJournalNotEmpty", err)
	}
	assertState(t, mustLoadState(t, re), s)
}

func TestInitializeEmptyStateRejectsExistingState(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, j *Journal)
		want  error
	}{
		{name: "working edit", setup: func(t *testing.T, j *Journal) {
			existing := baseState()
			if err := j.InitializeState(existing); err != nil {
				t.Fatal(err)
			}
			if err := j.UpdateWorking(0, opaque(2048, 31)); err != nil {
				t.Fatal(err)
			}
		}, want: ErrJournalNotEmpty},
		{name: "initialized different base", setup: func(t *testing.T, j *Journal) {
			if err := j.InitializeState(stateWithoutBase()); err != nil {
				t.Fatal(err)
			}
		}, want: ErrJournalNotEmpty},
		// An existing state is refused however it was stored: a record the
		// public API wrote and a raw record that happens to decode alike.
		{name: "state record", setup: func(t *testing.T, j *Journal) {
			writeRawState(t, j, encodeState(emptyBootstrapState(3)))
		}, want: ErrJournalNotEmpty},
		{name: "state record with other bytes", setup: func(t *testing.T, j *Journal) {
			writeRawState(t, j, encodeState(emptyBootstrapState(4)))
		}, want: ErrJournalNotEmpty},
		{name: "legacy proposal", setup: func(t *testing.T, j *Journal) {
			mustSave(t, j, Proposal{Generation: 4, OperationID: "op-0004", ExpectedRevision: `"etag-3"`, Bytes: opaque(512, 41)})
		}, want: ErrJournalNotEmpty},
		{name: "prepared proposal", setup: func(t *testing.T, j *Journal) {
			s := baseState()
			if err := j.InitializeState(s); err != nil {
				t.Fatal(err)
			}
			if err := j.Prepare(0, Proposal{Generation: 1, OperationID: "op-prep", ExpectedRevision: s.RemoteRevision, Bytes: s.WorkingBytes}); err != nil {
				t.Fatal(err)
			}
		}, want: ErrJournalNotEmpty},
		// A malformed state record is still an existing state: this API
		// never decodes it and refuses it as non-empty; LoadState is the
		// reader that reports it as ErrCorrupt.
		{name: "corrupt state", setup: func(t *testing.T, j *Journal) {
			writeRawState(t, j, []byte("not a state record"))
		}, want: ErrJournalNotEmpty},
		{name: "legacy proposal not decodable", setup: func(t *testing.T, j *Journal) {
			rawPut(t, j, bucketName, recordKey, opaque(64, 51))
		}, want: ErrJournalNotEmpty},
		{name: "prepared proposal not decodable", setup: func(t *testing.T, j *Journal) {
			rawPut(t, j, bucketName, preparedKey, opaque(64, 52))
		}, want: ErrJournalNotEmpty},
		// bbolt returns no value for a key that holds a nested bucket, so
		// each known key is a regression: the bucket must be ErrCorrupt, not
		// absent or empty.
		{name: "state key is a nested bucket", setup: func(t *testing.T, j *Journal) {
			rawBucket(t, j, bucketName, stateKey)
		}, want: ErrCorrupt},
		{name: "proposal key is a nested bucket", setup: func(t *testing.T, j *Journal) {
			rawBucket(t, j, bucketName, recordKey)
		}, want: ErrCorrupt},
		{name: "prepared key is a nested bucket", setup: func(t *testing.T, j *Journal) {
			rawBucket(t, j, bucketName, preparedKey)
		}, want: ErrCorrupt},
		{name: "unknown key", setup: func(t *testing.T, j *Journal) {
			rawPut(t, j, bucketName, "future-record", []byte{1})
		}, want: ErrJournalNotEmpty},
		{name: "unknown bucket", setup: func(t *testing.T, j *Journal) {
			rawPut(t, j, "other", "k", []byte{1})
		}, want: ErrJournalNotEmpty},
		{name: "unknown nested bucket", setup: func(t *testing.T, j *Journal) {
			rawBucket(t, j, bucketName, "future-record")
		}, want: ErrJournalNotEmpty},
	} {
		t.Run(tc.name, func(t *testing.T) {
			j := openAt(t, privateDir(t))
			tc.setup(t, j)
			before := rawJournalSnapshot(t, j)
			err := j.InitializeEmptyState(emptyBootstrapState(3))
			if !errors.Is(err, tc.want) {
				t.Fatalf("InitializeEmptyState = %v, want %v", err, tc.want)
			}
			if tc.want == ErrJournalNotEmpty && !errors.Is(err, ErrStateExists) {
				t.Fatalf("InitializeEmptyState = %v, want ErrStateExists discoverable", err)
			}
			if errors.Is(err, ErrCorrupt) != (tc.want == ErrCorrupt) {
				t.Fatalf("InitializeEmptyState = %v, ErrCorrupt mismatch for %v", err, tc.want)
			}
			if !sameSnapshot(before, rawJournalSnapshot(t, j)) {
				t.Fatal("a rejected bootstrap changed stored bytes")
			}
		})
	}
}

func TestInitializeEmptyStateRejectsMalformedInput(t *testing.T) {
	j := openAt(t, privateDir(t))
	valid := emptyBootstrapState(4)
	for _, tc := range []struct {
		name   string
		mutate func(*State)
	}{
		{"nonzero generation", func(s *State) { s.Generation = 1 }},
		{"no base", func(s *State) { s.BaseBytes = nil }},
		{"working differs", func(s *State) { s.WorkingBytes = opaque(len(s.BaseBytes), 5) }},
		{"no revision", func(s *State) { s.RemoteRevision = "" }},
		{"oversize base", func(s *State) {
			s.BaseBytes = make([]byte, MaxBaseBytes+1)
			s.WorkingBytes = s.BaseBytes
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := valid
			s.BaseBytes = bytes.Clone(valid.BaseBytes)
			s.WorkingBytes = bytes.Clone(valid.WorkingBytes)
			tc.mutate(&s)
			if err := j.InitializeEmptyState(s); !errors.Is(err, ErrInvalid) {
				t.Fatalf("InitializeEmptyState = %v, want ErrInvalid", err)
			}
		})
	}
	if before := rawJournalSnapshot(t, j); len(before) != 0 {
		t.Fatalf("rejected inputs created records: %v", before)
	}
	// A malformed call is rejected even after a valid bootstrap, before the
	// transaction, so the stored state is untouched.
	if err := j.InitializeEmptyState(valid); err != nil {
		t.Fatal(err)
	}
	before := rawJournalSnapshot(t, j)
	bad := valid
	bad.Generation = 9
	if err := j.InitializeEmptyState(bad); !errors.Is(err, ErrInvalid) {
		t.Fatalf("InitializeEmptyState = %v, want ErrInvalid", err)
	}
	if !sameSnapshot(before, rawJournalSnapshot(t, j)) {
		t.Fatal("a malformed call changed the stored state")
	}
}

func TestInitializeEmptyStateClosedJournal(t *testing.T) {
	j := openAt(t, privateDir(t))
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	if err := j.InitializeEmptyState(emptyBootstrapState(6)); !errors.Is(err, ErrClosed) {
		t.Fatalf("InitializeEmptyState on closed journal = %v, want ErrClosed", err)
	}
}

// TestInitializeEmptyStateConcurrentOnlyOneWins checks that the check and the
// write share one transaction: of several different boots racing on one empty
// journal, exactly one state is stored and every other call reports
// ErrJournalNotEmpty.
func TestInitializeEmptyStateConcurrentOnlyOneWins(t *testing.T) {
	j := openAt(t, privateDir(t))
	const n = 8
	errs := make(chan error, n)
	states := make([]State, n)
	for i := 0; i < n; i++ {
		states[i] = emptyBootstrapState(byte(10 + i))
	}
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		go func(s State) {
			<-start
			errs <- j.InitializeEmptyState(s)
		}(states[i])
	}
	close(start)
	wins := 0
	for i := 0; i < n; i++ {
		err := <-errs
		if err == nil {
			wins++
			continue
		}
		if !errors.Is(err, ErrJournalNotEmpty) {
			t.Fatalf("loser = %v, want ErrJournalNotEmpty", err)
		}
	}
	if wins != 1 {
		t.Fatalf("%d calls succeeded, want exactly 1", wins)
	}
	got := mustLoadState(t, j)
	matched := false
	for _, s := range states {
		if sameState(got, s) {
			matched = true
		}
	}
	if !matched {
		t.Fatal("stored state is not any of the raced states")
	}
}

// TestExistingAPIsKeepTheirSemantics guards the compatibility promise: the
// empty-only API does not change InitializeState, Save or Load.
func TestExistingAPIsKeepTheirSemantics(t *testing.T) {
	j := openAt(t, privateDir(t))
	s := stateWithoutBase()
	if err := j.InitializeState(s); err != nil {
		t.Fatalf("InitializeState: %v", err)
	}
	// InitializeState still accepts an exact repeat.
	if err := j.InitializeState(s); err != nil {
		t.Fatalf("InitializeState replay: %v", err)
	}
	p := Proposal{Generation: 1, OperationID: "op-1", Bytes: opaque(128, 61)}
	mustSave(t, j, p)
	if got := mustLoad(t, j); !sameProposal(got, p) {
		t.Fatal("Save/Load round trip changed")
	}
}
