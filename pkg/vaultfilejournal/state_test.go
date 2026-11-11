package vaultfilejournal

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	bolt "go.etcd.io/bbolt"
)

func baseState() State {
	return State{
		BaseBytes:      opaque(1<<10+3, 21),
		RemoteRevision: vaultfilebackend.Revision(`W/"base-etag-7"`),
		WorkingBytes:   opaque(1<<10+11, 22),
	}
}

// stateWithoutBase is the "no remote base yet" form.
func stateWithoutBase() State {
	return State{WorkingBytes: opaque(777, 23)}
}

func mustLoadState(t *testing.T, j *Journal) State {
	t.Helper()
	s, err := j.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	return s
}

func assertState(t *testing.T, got, want State) {
	t.Helper()
	if !sameState(got, want) {
		t.Fatalf("state mismatch:\n got gen=%d rev=%q base=%d working=%d\nwant gen=%d rev=%q base=%d working=%d",
			got.Generation, got.RemoteRevision, len(got.BaseBytes), len(got.WorkingBytes),
			want.Generation, want.RemoteRevision, len(want.BaseBytes), len(want.WorkingBytes))
	}
}

// writeRawState stores an arbitrary raw state record through a plain bbolt
// transaction on the open handle. It is an internal fixture for cases the
// public API cannot produce (such as generation MaxUint64).
func writeRawState(t *testing.T, j *Journal, raw []byte) {
	t.Helper()
	j.mu.Lock()
	defer j.mu.Unlock()
	err := j.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(bucketName))
		if err != nil {
			return err
		}
		return b.Put([]byte(stateKey), raw)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func resealState(raw []byte) []byte {
	body := raw[:len(raw)-stateDigest]
	sum := stateDigestOf(body)
	copy(raw[len(raw)-stateDigest:], sum[:])
	return raw
}

// setStateLengths writes raw header lengths verbatim. Every length is a uint
// so any field value (including math.MaxUint32) is expressible on all
// platforms; callers pass plain integer constants or int lengths.
func setStateLengths(raw []byte, n1 uint, n2 uint, n3 uint) {
	binary.BigEndian.PutUint32(raw[14:18], uint32(n1))
	binary.BigEndian.PutUint16(raw[18:20], uint16(n2))
	binary.BigEndian.PutUint32(raw[20:24], uint32(n3))
}

// TestStateLifecycle is the real-file lifecycle test: Open, ErrEmpty, init,
// load, working update, stale CAS rejection leaving state unchanged, close and
// reopen, and byte-exact state plus an untouched legacy proposal v1 record.
func TestStateLifecycle(t *testing.T) {
	dir := privateDir(t)
	path := filepath.Join(dir, "journal.db")

	j, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := j.LoadState(); !errors.Is(err, ErrEmpty) {
		t.Fatalf("fresh LoadState = %v, want ErrEmpty", err)
	}
	// No state record also means UpdateWorking cannot CAS.
	if err := j.UpdateWorking(0, opaque(16, 1)); !errors.Is(err, ErrEmpty) {
		t.Fatalf("UpdateWorking on empty journal = %v, want ErrEmpty", err)
	}

	// A legacy proposal v1 record saved first must survive everything below.
	proposal := baseProposal()
	mustSave(t, j, proposal)

	initial := baseState()
	if err := j.InitializeState(initial); err != nil {
		t.Fatalf("InitializeState: %v", err)
	}
	// Exact repeat is idempotent.
	if err := j.InitializeState(initial); err != nil {
		t.Fatalf("idempotent InitializeState: %v", err)
	}
	assertState(t, mustLoadState(t, j), initial)

	working1 := opaque(4099, 31)
	if err := j.UpdateWorking(0, working1); err != nil {
		t.Fatalf("UpdateWorking(0): %v", err)
	}
	s1 := initial
	s1.WorkingBytes, s1.Generation = working1, 1
	assertState(t, mustLoadState(t, j), s1)

	// A stale CAS (the old generation) is rejected and changes nothing.
	if err := j.UpdateWorking(0, opaque(4099, 32)); !errors.Is(err, ErrStateGenerationMismatch) {
		t.Fatalf("stale UpdateWorking = %v, want ErrStateGenerationMismatch", err)
	}
	// A speculative future generation is rejected too.
	if err := j.UpdateWorking(2, opaque(4099, 33)); !errors.Is(err, ErrStateGenerationMismatch) {
		t.Fatalf("future UpdateWorking = %v, want ErrStateGenerationMismatch", err)
	}
	assertState(t, mustLoadState(t, j), s1)

	working2 := opaque(2048, 34)
	if err := j.UpdateWorking(1, working2); err != nil {
		t.Fatalf("UpdateWorking(1): %v", err)
	}
	final := s1
	final.WorkingBytes, final.Generation = working2, 2
	assertState(t, mustLoadState(t, j), final)

	if err := j.Close(); err != nil {
		t.Fatal(err)
	}

	j2 := openAt(t, dir)
	got := mustLoadState(t, j2)
	assertState(t, got, final)
	if !bytes.Equal(got.BaseBytes, initial.BaseBytes) || got.RemoteRevision != initial.RemoteRevision {
		t.Fatal("reopened base/revision differ from the initialized ones")
	}
	assertProposal(t, mustLoad(t, j2), proposal)

	// A second InitializeState with different content never overwrites.
	other := baseState()
	if err := j2.InitializeState(other); !errors.Is(err, ErrStateExists) {
		t.Fatalf("re-initialize with different state = %v, want ErrStateExists", err)
	}
	assertState(t, mustLoadState(t, j2), final)
	assertProposal(t, mustLoad(t, j2), proposal)
}

// TestStateNoBaseRoundTrip covers the empty-base form through the real file.
func TestStateNoBaseRoundTrip(t *testing.T) {
	dir := privateDir(t)
	j := openAt(t, dir)
	if err := j.InitializeState(stateWithoutBase()); err != nil {
		t.Fatal(err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	s := mustLoadState(t, openAt(t, dir))
	if len(s.BaseBytes) != 0 || s.RemoteRevision != "" || s.Generation != 0 || len(s.WorkingBytes) == 0 {
		t.Fatalf("no-base state = %+v", s)
	}
}

// TestStateFaultAfterPutRollsBack injects an error in the state update after the
// bucket Put and before the Bolt commit. The transaction rolls back: within the
// open handle and after close/reopen, base, revision, working and generation are
// exactly as before, and the legacy proposal record is unchanged too.
func TestStateFaultAfterPutRollsBack(t *testing.T) {
	dir := privateDir(t)
	j := openAt(t, dir)
	proposal := baseProposal()
	mustSave(t, j, proposal)
	initial := baseState()
	if err := j.InitializeState(initial); err != nil {
		t.Fatal(err)
	}
	committed := opaque(3000, 41)
	if err := j.UpdateWorking(0, committed); err != nil {
		t.Fatal(err)
	}
	before := mustLoadState(t, j)

	fault := errors.New("injected state fault after bucket Put")
	hookRan := false
	err := j.updateWorkingWithHook(1, opaque(3000, 42), func() error {
		hookRan = true
		return fault
	})
	if !hookRan {
		t.Fatal("fault hook never ran")
	}
	if !errors.Is(err, fault) {
		t.Fatalf("UpdateWorking under fault = %v, want the injected fault", err)
	}

	// Nothing was published in the still-open handle.
	assertState(t, mustLoadState(t, j), before)
	assertProposal(t, mustLoad(t, j), proposal)

	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	j2 := openAt(t, dir)
	assertState(t, mustLoadState(t, j2), before)
	assertProposal(t, mustLoad(t, j2), proposal)

	// The rolled-back generation is free for a real retry.
	if err := j2.UpdateWorking(1, opaque(3000, 42)); err != nil {
		t.Fatalf("retry after rollback: %v", err)
	}
	if got := mustLoadState(t, j2); got.Generation != 2 {
		t.Fatalf("retry generation = %d, want 2", got.Generation)
	}
}

// TestStateAndProposalCoexistAcrossReopen saves legacy proposal v1, then adds
// and edits state, and after reopen both records match byte for byte. The raw
// proposal value in bbolt is also unchanged, proving the state path never
// rewrote or migrated it.
func TestStateAndProposalCoexistAcrossReopen(t *testing.T) {
	dir := privateDir(t)
	j := openAt(t, dir)
	proposal := baseProposal()
	proposal.ExpectedRevision = ""
	mustSave(t, j, proposal)
	rawProposalBefore := rawKey(t, j, recordKey)
	if !bytes.Equal(rawProposalBefore, encodeRecord(proposal)) {
		t.Fatal("raw proposal is not the v1 encoding")
	}

	initial := baseState()
	initial.BaseBytes = opaque(MaxBaseBytes, 51) // full-size base
	if err := j.InitializeState(initial); err != nil {
		t.Fatal(err)
	}
	for gen := uint64(0); gen < 3; gen++ {
		if err := j.UpdateWorking(gen, opaque(int(gen)+1, byte(60+gen))); err != nil {
			t.Fatal(err)
		}
	}
	if err := j.InitializeState(initial); !errors.Is(err, ErrStateExists) {
		t.Fatalf("re-initialize after edits = %v, want ErrStateExists", err)
	}
	if raw := rawKey(t, j, recordKey); !bytes.Equal(raw, rawProposalBefore) {
		t.Fatal("state writes changed the proposal record")
	}
	wantState := mustLoadState(t, j)
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}

	j2 := openAt(t, dir)
	assertProposal(t, mustLoad(t, j2), proposal)
	assertState(t, mustLoadState(t, j2), wantState)
	if raw := rawKey(t, j2, recordKey); !bytes.Equal(raw, rawProposalBefore) {
		t.Fatal("reopened proposal record differs")
	}
	if wantState.Generation != 3 || !bytes.Equal(wantState.BaseBytes, initial.BaseBytes) {
		t.Fatalf("reopened state = gen %d", wantState.Generation)
	}

	// The proposal API still refuses to step on a same-generation edit, and a
	// proposal update leaves the state alone.
	next := proposal
	next.Generation++
	if err := j2.Save(next); err != nil {
		t.Fatal(err)
	}
	assertState(t, mustLoadState(t, j2), wantState)
}

// rawKey returns the raw value stored at key inside the journal bucket.
func rawKey(t *testing.T, j *Journal, key string) []byte {
	t.Helper()
	j.mu.Lock()
	defer j.mu.Unlock()
	var out []byte
	err := j.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucketName))
		if b == nil {
			return nil
		}
		out = bytes.Clone(b.Get([]byte(key)))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestStateGenerationOverflow proves generation MaxUint64 (planted with a raw
// fixture) is refused without changing the state.
func TestStateGenerationOverflow(t *testing.T) {
	dir := privateDir(t)
	j := openAt(t, dir)
	maxed := baseState()
	maxed.Generation = math.MaxUint64
	writeRawState(t, j, encodeState(maxed))
	assertState(t, mustLoadState(t, j), maxed)

	err := j.UpdateWorking(math.MaxUint64, opaque(64, 71))
	var overflow *StateGenerationOverflowError
	if !errors.As(err, &overflow) || !errors.Is(err, ErrStateGenerationOverflow) {
		t.Fatalf("UpdateWorking(MaxUint64) = %v, want *StateGenerationOverflowError", err)
	}
	if overflow.Generation != math.MaxUint64 {
		t.Fatalf("overflow reports generation %d", overflow.Generation)
	}
	assertState(t, mustLoadState(t, j), maxed)

	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	assertState(t, mustLoadState(t, openAt(t, dir)), maxed)
}

// TestStateCASMismatchErrorDetail checks the typed mismatch detail.
func TestStateCASMismatchErrorDetail(t *testing.T) {
	j := openAt(t, privateDir(t))
	if err := j.InitializeState(baseState()); err != nil {
		t.Fatal(err)
	}
	for gen := uint64(0); gen < 2; gen++ {
		if err := j.UpdateWorking(gen, opaque(32, 80)); err != nil {
			t.Fatal(err)
		}
	}
	err := j.UpdateWorking(0, opaque(32, 81))
	var mismatch *StateCASMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("err = %v, want *StateCASMismatchError", err)
	}
	if mismatch.Expected != 0 || mismatch.Stored != 2 {
		t.Fatalf("mismatch = %+v", mismatch)
	}
}

// TestStateRejectsInvalidInput checks every input bound without writing.
func TestStateRejectsInvalidInput(t *testing.T) {
	j := openAt(t, privateDir(t))
	initOK := func() State {
		s := baseState()
		s.Generation = 0
		return s
	}
	cases := map[string]func(*State){
		"nonzero-generation": func(s *State) { s.Generation = 1 },
		"empty-working":      func(s *State) { s.WorkingBytes = nil },
		"working-too-large":  func(s *State) { s.WorkingBytes = make([]byte, MaxWorkingBytes+1) },
		"base-too-large":     func(s *State) { s.BaseBytes = make([]byte, MaxBaseBytes+1) },
		"base-without-rev":   func(s *State) { s.RemoteRevision = "" },
		"rev-without-base": func(s *State) {
			s.BaseBytes = nil
		},
		"rev-too-long": func(s *State) {
			s.RemoteRevision = vaultfilebackend.Revision(strings.Repeat("r", MaxStateRevisionBytes+1))
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			s := initOK()
			mutate(&s)
			if err := j.InitializeState(s); !errors.Is(err, ErrInvalid) {
				t.Fatalf("InitializeState = %v, want ErrInvalid", err)
			}
		})
	}
	if _, err := j.LoadState(); !errors.Is(err, ErrEmpty) {
		t.Fatalf("LoadState after rejected inits = %v, want ErrEmpty", err)
	}

	if err := j.InitializeState(initOK()); err != nil {
		t.Fatal(err)
	}
	before := mustLoadState(t, j)
	for name, working := range map[string][]byte{
		"nil":   nil,
		"empty": {},
		"huge":  make([]byte, MaxWorkingBytes+1),
	} {
		t.Run("working-"+name, func(t *testing.T) {
			if err := j.UpdateWorking(0, working); !errors.Is(err, ErrInvalid) {
				t.Fatalf("UpdateWorking = %v, want ErrInvalid", err)
			}
		})
	}
	assertState(t, mustLoadState(t, j), before)

	// Inclusive boundaries are accepted.
	max := State{
		BaseBytes:      make([]byte, MaxBaseBytes),
		RemoteRevision: vaultfilebackend.Revision(strings.Repeat("r", MaxStateRevisionBytes)),
		WorkingBytes:   make([]byte, MaxWorkingBytes),
	}
	if err := j.InitializeState(max); !errors.Is(err, ErrStateExists) {
		t.Fatalf("max-size init over existing state = %v, want ErrStateExists", err)
	}
	if !validStateGeneration(max) {
		t.Fatal("maximum-size state rejected by the validator")
	}
	if MaxStateRecordBytes < stateRecordLen(MaxBaseBytes, MaxStateRevisionBytes, MaxWorkingBytes) {
		t.Fatal("MaxStateRecordBytes does not cover the maximum field lengths")
	}
}

// TestStateDeepCopies proves InitializeState does not retain the caller's
// slices, UpdateWorking does not retain the caller's working slice, and
// LoadState returns copies.
func TestStateDeepCopies(t *testing.T) {
	j := openAt(t, privateDir(t))
	init := baseState()
	want := baseState()
	if err := j.InitializeState(init); err != nil {
		t.Fatal(err)
	}
	init.BaseBytes[0] ^= 0xff
	init.WorkingBytes[0] ^= 0xff
	assertState(t, mustLoadState(t, j), want)

	working := opaque(128, 90)
	wantWorking := bytes.Clone(working)
	if err := j.UpdateWorking(0, working); err != nil {
		t.Fatal(err)
	}
	working[0] ^= 0xff
	got := mustLoadState(t, j)
	if !bytes.Equal(got.WorkingBytes, wantWorking) || got.Generation != 1 {
		t.Fatal("UpdateWorking retained the caller's slice")
	}
	got.WorkingBytes[0] ^= 0xff
	got.BaseBytes[0] ^= 0xff
	assertState(t, mustLoadState(t, j), State{
		BaseBytes:      want.BaseBytes,
		RemoteRevision: want.RemoteRevision,
		WorkingBytes:   wantWorking,
		Generation:     1,
	})
}

// TestStateClosed checks every state method after Close.
func TestStateClosed(t *testing.T) {
	j, err := Open(filepath.Join(privateDir(t), "journal.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := j.LoadState(); !errors.Is(err, ErrClosed) {
		t.Fatalf("LoadState = %v, want ErrClosed", err)
	}
	if err := j.InitializeState(baseState()); !errors.Is(err, ErrClosed) {
		t.Fatalf("InitializeState = %v, want ErrClosed", err)
	}
	if err := j.UpdateWorking(0, opaque(8, 1)); !errors.Is(err, ErrClosed) {
		t.Fatalf("UpdateWorking = %v, want ErrClosed", err)
	}
}

// TestDecodeStateMalformed feeds every class of malformed state record and
// requires ErrCorrupt with no partial result.
func TestDecodeStateMalformed(t *testing.T) {
	good := encodeState(baseState())
	if _, err := decodeState(good); err != nil {
		t.Fatalf("decode good state: %v", err)
	}
	clone := func() []byte { return bytes.Clone(good) }
	n1, n2, n3 := len(baseState().BaseBytes), len(baseState().RemoteRevision), len(baseState().WorkingBytes)

	cases := map[string][]byte{
		"nil":              nil,
		"empty":            {},
		"short":            good[:stateOverhead-1],
		"prefix-only":      good[:statePrefix],
		"truncated-by-one": good[:len(good)-1],
		"truncated-digest": good[:len(good)-stateDigest],
		"proposal-magic":   func() []byte { r := clone(); copy(r[0:4], recordMagic); return resealState(r) }(),
		"bad-magic":        func() []byte { r := clone(); r[0] = 'X'; return resealState(r) }(),
		"bad-version-0":    func() []byte { r := clone(); binary.BigEndian.PutUint16(r[4:6], 0); return resealState(r) }(),
		"bad-version-2":    func() []byte { r := clone(); binary.BigEndian.PutUint16(r[4:6], 2); return resealState(r) }(),
		"bad-version-max":  func() []byte { r := clone(); binary.BigEndian.PutUint16(r[4:6], math.MaxUint16); return resealState(r) }(),
		"zero-working-len": func() []byte { r := clone(); setStateLengths(r, uint(n1), uint(n2), 0); return resealState(r) }(),
		"working-too-long": func() []byte {
			r := clone()
			setStateLengths(r, uint(n1), uint(n2), MaxWorkingBytes+1)
			return resealState(r)
		}(),
		"base-too-long": func() []byte {
			r := clone()
			setStateLengths(r, MaxBaseBytes+1, uint(n2), uint(n3))
			return resealState(r)
		}(),
		"revision-too-long": func() []byte {
			r := clone()
			setStateLengths(r, uint(n1), MaxStateRevisionBytes+1, uint(n3))
			return resealState(r)
		}(),
		"base-without-rev": func() []byte { r := clone(); setStateLengths(r, uint(n1), 0, uint(n3)); return resealState(r) }(),
		"rev-without-base": func() []byte { r := clone(); setStateLengths(r, 0, uint(n2), uint(n3)); return resealState(r) }(),
		"length-runs-past": func() []byte { r := clone(); setStateLengths(r, uint(n1), uint(n2), uint(n3+1)); return resealState(r) }(),
		"length-short":     func() []byte { r := clone(); setStateLengths(r, uint(n1), uint(n2), uint(n3-1)); return resealState(r) }(),
		"header-only-huge": func() []byte {
			r := bytes.Clone(good[:stateOverhead])
			setStateLengths(r, MaxBaseBytes, MaxStateRevisionBytes, math.MaxUint32)
			return resealState(r)
		}(),
		"trailing-byte":   append(clone(), 0),
		"trailing-bytes":  append(clone(), bytes.Repeat([]byte{0xee}, 64)...),
		"huge-appended":   append(clone(), make([]byte, MaxStateRecordBytes)...),
		"digest-bit-flip": func() []byte { r := clone(); r[len(r)-1] ^= 0x01; return r }(),
		"body-bit-flip":   func() []byte { r := clone(); r[statePrefix] ^= 0x01; return r }(),
		"length-bit-flip": func() []byte { r := clone(); r[20] ^= 0x01; return r }(),
		// The proposal record's digest (and its domain) is not accepted for a
		// state record.
		"proposal-domain": func() []byte {
			r := clone()
			sum := recordDigestOf(r[:len(r)-stateDigest])
			copy(r[len(r)-stateDigest:], sum[:])
			return r
		}(),
		// An undomained SHA-256 is not accepted either.
		"undomained-digest": func() []byte {
			r := clone()
			sum := sha256.Sum256(r[:len(r)-stateDigest])
			copy(r[len(r)-stateDigest:], sum[:])
			return r
		}(),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			s, err := decodeState(raw)
			if !errors.Is(err, ErrCorrupt) {
				t.Fatalf("decodeState err = %v, want ErrCorrupt", err)
			}
			if !sameState(s, State{}) {
				t.Fatalf("decodeState returned a partial state: %+v", s)
			}
		})
	}
}

// TestDecodeStateBoundsBeforeAllocation ensures hostile headers are rejected
// from the fixed header and the actual length without allocation derived from
// the claimed lengths.
func TestDecodeStateBoundsBeforeAllocation(t *testing.T) {
	good := encodeState(baseState())
	var cal countingAllocator
	cal.stop = startAllocTracking(&cal)
	in := bytes.Clone(good)
	s, err := decodeState(in)
	got := cal.stop()
	if err != nil || got < int64(len(s.BaseBytes)+len(s.WorkingBytes)) {
		t.Fatalf("valid decode allocated %d bytes (%v)", got, err)
	}

	hostile := []struct {
		name string
		raw  []byte
	}{
		{"max-uint32-working", func() []byte {
			r := bytes.Clone(good[:stateOverhead])
			setStateLengths(r, 0, 0, math.MaxUint32)
			return resealState(r)
		}()},
		{"max-uint32-base", func() []byte {
			r := bytes.Clone(good[:stateOverhead])
			setStateLengths(r, math.MaxUint32, MaxStateRevisionBytes, 1)
			return resealState(r)
		}()},
		// Field lengths are within their caps, but the actual record is far
		// shorter than the declared base + revision + working total.
		{"declared-past-end", func() []byte {
			raw := bytes.Clone(good[:stateOverhead])
			setStateLengths(raw, MaxBaseBytes, MaxStateRevisionBytes, 1)
			return resealState(raw)
		}()},
		{"oversize-record", make([]byte, MaxStateRecordBytes+1)},
	}
	for _, h := range hostile {
		for _, grow := range []int{0, 4096} {
			raw := bytes.Clone(h.raw)
			if grow > 0 {
				raw = append(raw, make([]byte, grow)...)
			}
			var a countingAllocator
			a.stop = startAllocTracking(&a)
			s, err := decodeState(raw)
			got := a.stop()
			if !errors.Is(err, ErrCorrupt) || s.BaseBytes != nil || s.WorkingBytes != nil {
				t.Fatalf("%s: decodeState = %v, want ErrCorrupt and no result", h.name, err)
			}
			if got > 1024 {
				t.Fatalf("%s (len %d, +%d): corrupt record allocated %d bytes before rejection", h.name, len(h.raw), grow, got)
			}
		}
	}
}

// TestDecodeStateUint32LengthsNoWrap pins the exact hostile headers found in
// review. Their lengths, converted to int on a 32-bit platform, would be
// negative and slip past the cap checks, so the decoder must compare in uint64
// and reject them as ErrCorrupt on every architecture without panicking.
func TestDecodeStateUint32LengthsNoWrap(t *testing.T) {
	// baseLen=0xffffffff, revisionLen=1, workingLen=1, rawLen=57: the base and
	// revision pairing holds and a naive int comparison would accept it.
	makeRaw := func(generation uint64) []byte {
		raw := make([]byte, stateOverhead+1)
		copy(raw[0:4], stateMagic)
		binary.BigEndian.PutUint16(raw[4:6], stateVersion)
		binary.BigEndian.PutUint64(raw[6:14], generation)
		setStateLengths(raw, math.MaxUint32, 1, 1)
		raw[statePrefix] = 0x01 // revision byte
		raw[statePrefix+1] = 0x02
		return resealState(raw)
	}
	raw := makeRaw(0)
	if len(raw) != 57 {
		t.Fatalf("fixture length = %d, want 57", len(raw))
	}

	for name, in := range map[string][]byte{
		"exact":      raw,
		"generation": makeRaw(math.MaxUint64),
		"trailing":   append(bytes.Clone(raw), 0x00),
	} {
		t.Run(name, func(t *testing.T) {
			s, err := decodeState(in)
			if !errors.Is(err, ErrCorrupt) {
				t.Fatalf("decodeState(len %d) err = %v, want ErrCorrupt", len(in), err)
			}
			if !sameState(s, State{}) {
				t.Fatalf("decodeState returned a partial state: %+v", s)
			}
		})
	}

	// The same header through the public path is ErrCorrupt too, and never a
	// panic, leaving the stored value untouched.
	j := openAt(t, privateDir(t))
	writeRawState(t, j, raw)
	if _, err := j.LoadState(); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("LoadState = %v, want ErrCorrupt", err)
	}
	if err := j.InitializeState(baseState()); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("InitializeState over wrapped-length header = %v, want ErrCorrupt", err)
	}
	if after := rawKey(t, j, stateKey); !bytes.Equal(after, raw) {
		t.Fatal("rejected operations replaced the corrupt state")
	}
}

// TestLoadStateCorruptRecord proves an altered stored state record is reported
// as ErrCorrupt and is never silently replaced or repaired, while the proposal
// record remains readable.
func TestLoadStateCorruptRecord(t *testing.T) {
	j := openAt(t, privateDir(t))
	proposal := baseProposal()
	mustSave(t, j, proposal)
	if err := j.InitializeState(baseState()); err != nil {
		t.Fatal(err)
	}
	raw := rawKey(t, j, stateKey)
	raw[statePrefix+1] ^= 0x40
	writeRawState(t, j, raw)

	if _, err := j.LoadState(); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("LoadState = %v, want ErrCorrupt", err)
	}
	if err := j.UpdateWorking(0, opaque(8, 1)); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("UpdateWorking over corrupt state = %v, want ErrCorrupt", err)
	}
	if err := j.InitializeState(baseState()); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("InitializeState over corrupt state = %v, want ErrCorrupt", err)
	}
	if after := rawKey(t, j, stateKey); !bytes.Equal(after, raw) {
		t.Fatal("rejected operations repaired or replaced the corrupt state")
	}
	assertProposal(t, mustLoad(t, j), proposal)

	// A state key holding a proposal-format value is not misinterpreted.
	writeRawState(t, j, encodeRecord(proposal))
	if _, err := j.LoadState(); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("LoadState(proposal value) = %v, want ErrCorrupt", err)
	}
}
