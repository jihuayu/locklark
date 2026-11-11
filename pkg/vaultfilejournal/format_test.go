package vaultfilejournal

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	bolt "go.etcd.io/bbolt"
)

// countingAllocator counts bytes allocated while an allocation tracking record
// is active (see startAllocTracking in the allocation test).
type countingAllocator struct {
	bytes atomic.Int64
	stop  func() int64
}

func startAllocTracking(a *countingAllocator) func() int64 {
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	return func() int64 {
		runtime.ReadMemStats(&after)
		got := int64(after.TotalAlloc - before.TotalAlloc)
		a.bytes.Store(got)
		return got
	}
}

func reseal(raw []byte) []byte {
	body := raw[:len(raw)-recordDigest]
	sum := recordDigestOf(body)
	copy(raw[len(raw)-recordDigest:], sum[:])
	return raw
}

func setLengths(raw []byte, n1 int, n2 int, n3 uint32) {
	raw[14] = byte(n1)
	binary.BigEndian.PutUint16(raw[15:17], uint16(n2))
	binary.BigEndian.PutUint32(raw[17:21], n3)
}

// TestDecodeRecordMalformed feeds every class of malformed envelope and
// requires ErrCorrupt with no partial result.
func TestDecodeRecordMalformed(t *testing.T) {
	good := encodeRecord(baseProposal())
	if _, err := decodeRecord(good); err != nil {
		t.Fatalf("decode good record: %v", err)
	}
	clone := func() []byte { return bytes.Clone(good) }

	cases := map[string][]byte{
		"nil":               nil,
		"empty":             {},
		"short":             good[:recordOverhead-1],
		"prefix-only":       good[:recordPrefix],
		"truncated-by-one":  good[:len(good)-1],
		"truncated-digest":  good[:len(good)-recordDigest],
		"bad-magic":         func() []byte { r := clone(); r[0] = 'X'; return reseal(r) }(),
		"bad-version-0":     func() []byte { r := clone(); binary.BigEndian.PutUint16(r[4:6], 0); return reseal(r) }(),
		"bad-version-2":     func() []byte { r := clone(); binary.BigEndian.PutUint16(r[4:6], 2); return reseal(r) }(),
		"bad-version-max":   func() []byte { r := clone(); binary.BigEndian.PutUint16(r[4:6], math.MaxUint16); return reseal(r) }(),
		"zero-generation":   func() []byte { r := clone(); binary.BigEndian.PutUint64(r[6:14], 0); return reseal(r) }(),
		"zero-op-length":    func() []byte { r := clone(); r[14] = 0; return reseal(r) }(),
		"op-length-too-big": func() []byte { r := clone(); r[14] = MaxOperationIDBytes + 1; return reseal(r) }(),
		"revision-too-long": func() []byte {
			r := clone()
			binary.BigEndian.PutUint16(r[15:17], MaxExpectedRevisionBytes+1)
			return reseal(r)
		}(),
		"zero-bytes-length": func() []byte { r := clone(); binary.BigEndian.PutUint32(r[17:21], 0); return reseal(r) }(),
		"bytes-too-long": func() []byte {
			r := clone()
			binary.BigEndian.PutUint32(r[17:21], MaxProposalBytes+1)
			return reseal(r)
		}(),
		"header-only-huge": func() []byte {
			r := good[:recordOverhead]
			setLengths(r, 64, MaxExpectedRevisionBytes, math.MaxUint32)
			return reseal(r)
		}(),
		"length-runs-past": func() []byte {
			r := clone()
			setLengths(r, len("op-2026-11-11:test_run.1"), len(`"9c1f-etag"`), uint32(len(baseProposal().Bytes)+1))
			return reseal(r)
		}(),
		"length-short": func() []byte {
			r := clone()
			setLengths(r, len("op-2026-11-11:test_run.1"), len(`"9c1f-etag"`), uint32(len(baseProposal().Bytes)-1))
			return reseal(r)
		}(),
		"bad-operation-id": func() []byte { r := clone(); r[recordPrefix] = 'A'; return reseal(r) }(),
		"trailing-byte":    append(clone(), 0),
		"trailing-bytes":   append(clone(), bytes.Repeat([]byte{0xee}, 64)...),
		"huge-appended":    append(clone(), make([]byte, maxRecordLen)...),
		"digest-bit-flip":  func() []byte { r := clone(); r[len(r)-1] ^= 0x01; return r }(),
		"body-bit-flip":    func() []byte { r := clone(); r[recordPrefix] ^= 0x01; return r }(),
		"length-bit-flip":  func() []byte { r := clone(); r[17] ^= 0x01; return r }(),
		// An undomained SHA-256 of the body is not accepted: the record digest
		// is domain separated.
		"domain-separation": func() []byte {
			r := clone()
			sum := sha256.Sum256(r[:len(r)-recordDigest])
			copy(r[len(r)-recordDigest:], sum[:])
			return r
		}(),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			p, err := decodeRecord(raw)
			if !errors.Is(err, ErrCorrupt) {
				t.Fatalf("decodeRecord err = %v, want ErrCorrupt", err)
			}
			if !sameProposal(p, Proposal{}) {
				t.Fatalf("decodeRecord returned a partial proposal: %+v", p)
			}
		})
	}
}

// TestDecodeBoundsBeforeAllocation ensures a corrupt header claiming large
// lengths is rejected from the fixed header and the actual record length,
// with no allocation derived from the claimed lengths. Every hostile input is
// sized so that a single length-derived allocation would be large and
// observable.
func TestDecodeBoundsBeforeAllocation(t *testing.T) {
	good := encodeRecord(baseProposal())

	// Calibrate: a valid record allocates a copy of its bytes, proving the
	// counter observes allocations made inside its lifetime. Inputs are
	// separately allocated so small results are not stack-allocated.
	var cal countingAllocator
	cal.stop = startAllocTracking(&cal)
	in := bytes.Clone(good)
	p, err := decodeRecord(in)
	got := cal.stop()
	if err != nil || got < int64(len(p.Bytes)) || cal.bytes.Load() < int64(len(p.Bytes)) {
		t.Fatalf("valid decode allocated %d bytes, want at least the %d-byte copy (%v)", got, len(p.Bytes), err)
	}

	hostile := []struct {
		name string
		raw  []byte
	}{
		// Declared lengths exceed the caps and a claimed 4 GiB body.
		{"max-uint32-bytes", func() []byte {
			r := bytes.Clone(good[:recordOverhead])
			setLengths(r, 64, MaxExpectedRevisionBytes, math.MaxUint32)
			return reseal(r)
		}()},
		// Declared revision length exceeds MaxRevisionSize.
		{"max-revision-length", func() []byte {
			r := bytes.Clone(good[:recordOverhead])
			setLengths(r, 64, math.MaxUint16, 1)
			return reseal(r)
		}()},
		// Every length in bounds but the record is shorter than declared.
		{"declared-past-end", func() []byte {
			raw := append(bytes.Clone(good[:recordOverhead]), make([]byte, MaxOperationIDBytes+MaxExpectedRevisionBytes+MaxProposalBytes+recordDigest)...)
			setLengths(raw, MaxOperationIDBytes, MaxExpectedRevisionBytes, MaxProposalBytes)
			return reseal(raw)
		}()},
		// A record one byte over the absolute maximum.
		{"oversize-record", make([]byte, maxRecordLen+1)},
		// Valid lengths whose body is followed by extra bytes: the digest no
		// longer matches the full record.
		{"extra-body-bad-digest", reseal(append(bytes.Clone(good), make([]byte, 1024)...))},
	}
	for _, h := range hostile {
		for _, grow := range []int{0, 4096} {
			raw := bytes.Clone(h.raw)
			if grow > 0 {
				raw = append(raw, make([]byte, grow)...)
			}
			var a countingAllocator
			a.stop = startAllocTracking(&a)
			p, err := decodeRecord(raw)
			got := a.stop()
			if !errors.Is(err, ErrCorrupt) || p.Bytes != nil {
				t.Fatalf("%s: decodeRecord = %v, want ErrCorrupt and no result", h.name, err)
			}
			// Only the ReadMemStats bookkeeping itself may allocate here.
			if got > 1024 {
				t.Fatalf("%s (len %d, +%d): corrupt record allocated %d bytes before rejection", h.name, len(h.raw), grow, got)
			}
		}
	}
}

// TestLoadCorruptRecord proves an altered stored record is reported as
// ErrCorrupt through the public API and is never silently replaced.
func TestLoadCorruptRecord(t *testing.T) {
	dir := privateDir(t)
	j := openAt(t, dir)
	mustSave(t, j, baseProposal())
	corruptStoredRecord(t, j, func(raw []byte) []byte {
		r := bytes.Clone(raw)
		r[recordPrefix+1] ^= 0x40
		return r
	})
	if _, err := j.Load(); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Load = %v, want ErrCorrupt", err)
	}
	p := baseProposal()
	p.Generation++
	if err := j.Save(p); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Save over corrupt record = %v, want ErrCorrupt", err)
	}
}

// TestLoadRejectsForeignRecordVersion stores a record claiming a future
// version with a matching digest; it must not be interpreted.
func TestLoadRejectsForeignRecordVersion(t *testing.T) {
	dir := privateDir(t)
	j := openAt(t, dir)
	mustSave(t, j, baseProposal())
	corruptStoredRecord(t, j, func(raw []byte) []byte {
		r := bytes.Clone(raw)
		binary.BigEndian.PutUint16(r[4:6], formatVersion+1)
		return reseal(r)
	})
	if _, err := j.Load(); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Load = %v, want ErrCorrupt", err)
	}
}

// TestLoadNoTrailingBytes stores a valid record with one appended byte.
func TestLoadNoTrailingBytes(t *testing.T) {
	dir := privateDir(t)
	j := openAt(t, dir)
	mustSave(t, j, baseProposal())
	corruptStoredRecord(t, j, func(raw []byte) []byte {
		return append(bytes.Clone(raw), 0)
	})
	if _, err := j.Load(); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Load = %v, want ErrCorrupt", err)
	}
}

// corruptStoredRecord rewrites the raw record through the same bucket and key,
// using a plain bbolt transaction while the Journal's own handle is open.
func corruptStoredRecord(t *testing.T, j *Journal, mutate func([]byte) []byte) {
	t.Helper()
	j.mu.Lock()
	defer j.mu.Unlock()
	err := j.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(bucketName))
		if err != nil {
			return err
		}
		cur := b.Get([]byte(recordKey))
		if cur == nil {
			return ErrEmpty
		}
		return b.Put([]byte(recordKey), mutate(cur))
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestValidProposalBounds(t *testing.T) {
	p := baseProposal()
	if !validProposal(p) {
		t.Fatal("base proposal invalid")
	}
	for c := 0; c < 256; c++ {
		want := c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == ':' || c == '-'
		if got := validOperationID(string(rune(c))); got != want {
			t.Fatalf("operation ID byte %q: valid = %v, want %v", rune(c), got, want)
		}
	}
	if !validOperationID(strings.Repeat("a", MaxOperationIDBytes)) ||
		validOperationID(strings.Repeat("a", MaxOperationIDBytes+1)) ||
		validOperationID("") {
		t.Fatal("operation ID length bound is wrong")
	}

	max := p
	max.ExpectedRevision = vaultfilebackend.Revision(strings.Repeat("r", MaxExpectedRevisionBytes))
	max.Bytes = make([]byte, MaxProposalBytes)
	if !validProposal(max) {
		t.Fatal("maximum-size proposal rejected")
	}
	if max.ExpectedRevision = vaultfilebackend.Revision(strings.Repeat("r", MaxExpectedRevisionBytes+1)); validProposal(max) {
		t.Fatal("oversize revision accepted")
	}
	if max.ExpectedRevision, max.Bytes = "", nil; validProposal(max) {
		t.Fatal("empty bytes accepted")
	}
	if max.Bytes = make([]byte, MaxProposalBytes+1); validProposal(max) {
		t.Fatal("oversize bytes accepted")
	}
	if max.Bytes, max.Generation = p.Bytes, 0; validProposal(max) {
		t.Fatal("zero generation accepted")
	}
}
