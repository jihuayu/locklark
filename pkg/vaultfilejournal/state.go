package vaultfilejournal

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"

	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	bolt "go.etcd.io/bbolt"
)

// This file adds a second, independent record to the same bbolt bucket: the
// local file state (#110 checkpoint). It never reads, rewrites, migrates or
// deletes the existing proposal record under recordKey; the two keys live side
// by side and each is decoded only by its own versioned format.
//
// StateRecord holds:
//
//   - BaseBytes: the last known sealed complete single file (the remote base).
//     Empty means there is no remote base yet.
//   - RemoteRevision: the opaque backend revision that base was read at or
//     written as. It is empty iff BaseBytes is empty. It is opaque and stored
//     verbatim; this package never parses it and never compares it with the
//     proposal's expected revision.
//   - WorkingBytes: the sealed complete single file being edited or published
//     locally. Always non-empty.
//   - Generation: the local CAS generation; 0 until UpdateWorking has run.
//
// The bytes are sealed, opaque ciphertext: no plaintext payload, private key
// or protocol field is represented, and this package does not decrypt,
// encrypt, authenticate, authorize or talk to a backend. The record checksum
// detects malformed or accidentally corrupted local state; it is not a
// signature and does not stop an attacker who can also rewrite it.
//
// Generation is a purely local compare-and-swap counter guarded by one bbolt
// write transaction per update. It orders local working edits; it does not
// represent, and must not be read as, a remote publication outcome.
//
// State record layout (version 1), all integers big-endian:
//
//	offset  size  field
//	0       4     magic "LLVS"
//	4       2     format version (1)
//	6       8     generation
//	14      4     base bytes length          0..MaxValueSize (0 = no base)
//	18      2     remote revision length     0..MaxRevisionSize
//	20      4     working bytes length      1..MaxValueSize
//	24      n1    base bytes, opaque and stored verbatim
//	24+n1   n2    remote revision, opaque and stored verbatim
//	24+n1+n2 n3   working bytes, opaque and stored verbatim
//	last    32    SHA-256 of the magic through the working bytes (domain separated)
//
// There are no trailing bytes. The decoder validates the total length, then
// every declared length against its cap and the exact derived total, then the
// base/revision pairing, then the checksum; only after all of that does it
// allocate the copies it returns.
const (
	stateMagic    = "LLVS"
	stateVersion  = uint16(1)
	statePrefix   = 4 + 2 + 8 + 4 + 2 + 4
	stateDigest   = sha256.Size
	stateOverhead = statePrefix + stateDigest

	// MaxBaseBytes and MaxWorkingBytes are the largest sealed base and working
	// files the state record stores, each equal to vaultfilebackend.MaxValueSize.
	MaxBaseBytes = vaultfilebackend.MaxValueSize
	// MaxWorkingBytes is the largest sealed working file; see MaxBaseBytes.
	MaxWorkingBytes = vaultfilebackend.MaxValueSize
	// MaxStateRevisionBytes bounds the opaque remote revision of the state
	// record, equal to vaultfilebackend.MaxRevisionSize. It is empty exactly
	// when there is no base.
	MaxStateRevisionBytes = vaultfilebackend.MaxRevisionSize

	// MaxStateRecordBytes is the absolute upper bound of one encoded state
	// record; any longer stored value is rejected from its length alone.
	MaxStateRecordBytes = stateOverhead + MaxBaseBytes + MaxStateRevisionBytes + MaxWorkingBytes

	stateDigestDomain = "locklark vault-file journal state v1\x00"

	stateKey = "state"
)

// State is a decoded local file state. Base and working carry deep copies.
//
// BaseBytes/RemoteRevision are opaque sealed bytes and an opaque revision;
// WorkingBytes is the sealed working file; Generation is the local CAS
// generation. None of them indicates whether a remote publication happened.
type State struct {
	BaseBytes      []byte
	RemoteRevision vaultfilebackend.Revision
	WorkingBytes   []byte
	Generation     uint64
}

// StateCASMismatchError reports an UpdateWorking whose expectedGeneration is
// not the stored generation. The stored state is unchanged. It satisfies
// errors.Is(err, ErrStateGenerationMismatch).
type StateCASMismatchError struct {
	Expected uint64
	Stored   uint64
}

func (e *StateCASMismatchError) Error() string {
	return fmt.Sprintf("vault file journal: state generation mismatch: expected %d, stored %d", e.Expected, e.Stored)
}

func (e *StateCASMismatchError) Is(target error) bool { return target == ErrStateGenerationMismatch }

// StateGenerationOverflowError reports an UpdateWorking against generation
// MaxUint64, where no next generation exists. The stored state is unchanged.
// It satisfies errors.Is(err, ErrStateGenerationOverflow).
type StateGenerationOverflowError struct {
	Generation uint64
}

func (e *StateGenerationOverflowError) Error() string {
	return fmt.Sprintf("vault file journal: state generation %d cannot be incremented", e.Generation)
}

func (e *StateGenerationOverflowError) Is(target error) bool {
	return target == ErrStateGenerationOverflow
}

func validStateGeneration(s State) bool {
	if len(s.BaseBytes) > MaxBaseBytes || len(s.WorkingBytes) == 0 || len(s.WorkingBytes) > MaxWorkingBytes {
		return false
	}
	if len(s.BaseBytes) == 0 {
		return len(s.RemoteRevision) == 0
	}
	return len(s.RemoteRevision) > 0 && len(s.RemoteRevision) <= MaxStateRevisionBytes
}

// validWorkingBytes reports whether bytes may become a working file.
func validWorkingBytes(b []byte) bool {
	return len(b) > 0 && len(b) <= MaxWorkingBytes
}

// stateRecordLen derives the exact encoded length for the given field lengths.
func stateRecordLen(n1, n2, n3 int) int {
	return stateOverhead + n1 + n2 + n3
}

func encodeState(s State) []byte {
	if !validStateGeneration(s) {
		panic("vaultfilejournal: encodeState called with invalid state")
	}
	n1, n2, n3 := len(s.BaseBytes), len(s.RemoteRevision), len(s.WorkingBytes)
	buf := make([]byte, stateRecordLen(n1, n2, n3))
	copy(buf[0:4], stateMagic)
	binary.BigEndian.PutUint16(buf[4:6], stateVersion)
	binary.BigEndian.PutUint64(buf[6:14], s.Generation)
	binary.BigEndian.PutUint32(buf[14:18], uint32(n1))
	binary.BigEndian.PutUint16(buf[18:20], uint16(n2))
	binary.BigEndian.PutUint32(buf[20:24], uint32(n3))
	off := statePrefix
	off += copy(buf[off:], s.BaseBytes)
	off += copy(buf[off:], s.RemoteRevision)
	off += copy(buf[off:], s.WorkingBytes)
	sum := stateDigestOf(buf[:off])
	copy(buf[off:], sum[:])
	return buf
}

func stateDigestOf(body []byte) [sha256.Size]byte {
	h := sha256.New()
	h.Write([]byte(stateDigestDomain))
	h.Write(body)
	var sum [sha256.Size]byte
	h.Sum(sum[:0])
	return sum
}

// decodeState validates raw completely and returns the stored state with
// freshly allocated copies. Any deviation from the exact layout is ErrCorrupt.
func decodeState(raw []byte) (State, error) {
	var s State
	if len(raw) < stateOverhead || len(raw) > MaxStateRecordBytes {
		return s, ErrCorrupt
	}
	if !bytes.Equal(raw[0:4], []byte(stateMagic)) {
		return s, ErrCorrupt
	}
	if binary.BigEndian.Uint16(raw[4:6]) != stateVersion {
		return s, ErrCorrupt
	}
	// Validate every declared length against its cap and the actual length
	// before using any of them.
	n1 := int(binary.BigEndian.Uint32(raw[14:18]))
	n2 := int(binary.BigEndian.Uint16(raw[18:20]))
	n3 := int(binary.BigEndian.Uint32(raw[20:24]))
	if n1 > MaxBaseBytes ||
		n2 > MaxStateRevisionBytes ||
		n3 == 0 || n3 > MaxWorkingBytes ||
		stateRecordLen(n1, n2, n3) != len(raw) {
		return s, ErrCorrupt
	}
	if (n1 == 0) != (n2 == 0) {
		return s, ErrCorrupt
	}
	body := raw[:len(raw)-stateDigest]
	sum := stateDigestOf(body)
	if !bytes.Equal(sum[:], raw[len(raw)-stateDigest:]) {
		return s, ErrCorrupt
	}
	off := statePrefix
	base := bytes.Clone(raw[off : off+n1])
	off += n1
	rev := vaultfilebackend.Revision(string(raw[off : off+n2]))
	off += n2
	working := bytes.Clone(raw[off : off+n3])
	return State{
		BaseBytes:      base,
		RemoteRevision: rev,
		WorkingBytes:   working,
		Generation:     binary.BigEndian.Uint64(raw[6:14]),
	}, nil
}

// sameState compares every field byte for byte.
func sameState(a, b State) bool {
	return a.Generation == b.Generation &&
		a.RemoteRevision == b.RemoteRevision &&
		bytes.Equal(a.BaseBytes, b.BaseBytes) &&
		bytes.Equal(a.WorkingBytes, b.WorkingBytes)
}

// readStateTx decodes the state record inside an open transaction. It returns
// found=false when no record exists; the result is already copied.
func readStateTx(tx *bolt.Tx) (State, bool, error) {
	b := tx.Bucket([]byte(bucketName))
	if b == nil {
		return State{}, false, nil
	}
	raw := b.Get([]byte(stateKey))
	if raw == nil {
		return State{}, false, nil
	}
	s, err := decodeState(raw)
	if err != nil {
		return State{}, false, err
	}
	return s, true, nil
}

// wrapStateErr keeps sentinel errors identifiable and wraps anything else.
func wrapStateErr(op string, err error) error {
	if errors.Is(err, ErrCorrupt) ||
		errors.Is(err, ErrStateGenerationMismatch) ||
		errors.Is(err, ErrStateGenerationOverflow) {
		return err
	}
	return fmt.Errorf("vault file journal: %s: %w", op, err)
}

// LoadState returns a copy of the stored local state, or ErrEmpty when it has
// not been initialized. A stored record that fails validation is ErrCorrupt.
func (j *Journal) LoadState() (State, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return State{}, ErrClosed
	}
	var s State
	found := false
	err := j.db.View(func(tx *bolt.Tx) error {
		var err error
		s, found, err = readStateTx(tx)
		return err
	})
	if err != nil {
		return State{}, wrapStateErr("load state", err)
	}
	if !found {
		return State{}, ErrEmpty
	}
	return s, nil
}

// InitializeState stores the initial local state in one transaction. It
// succeeds only when no state record exists; an exact repeat of an already
// stored state is an idempotent no-op, and any other difference is rejected
// with ErrStateExists without replacing the stored record. It never touches
// the proposal record.
//
// The initial generation is 0. Callers supply the base and working sealed
// bytes; the revision is stored verbatim.
func (j *Journal) InitializeState(s State) error {
	if s.Generation != 0 || !validStateGeneration(s) {
		return fmt.Errorf("%w: malformed initial state", ErrInvalid)
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return ErrClosed
	}
	err := j.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(bucketName))
		if err != nil {
			return err
		}
		if cur, found, err := readStateTx(tx); err != nil {
			return err
		} else if found {
			if sameState(cur, s) {
				return nil
			}
			return ErrStateExists
		}
		return b.Put([]byte(stateKey), encodeState(s))
	})
	if err != nil {
		return wrapStateErr("initialize state", err)
	}
	return nil
}

// UpdateWorking atomically replaces the working bytes when the stored
// generation equals expectedGeneration, and increments the generation by one.
// BaseBytes and RemoteRevision are carried over unchanged. It allocates no
// new base and performs no remote I/O.
//
// A missing state record is ErrEmpty. A stale or otherwise different expected
// generation is a *StateCASMismatchError matching ErrStateGenerationMismatch;
// a stored generation of MaxUint64 is a *StateGenerationOverflowError matching
// ErrStateGenerationOverflow. In every rejected case the stored state is
// unchanged. An empty or oversize working byte slice is ErrInvalid and is
// rejected before the transaction starts.
//
// If an error other than those is returned the outcome may be unknown; do not
// invent it, but reopen and LoadState and compare exactly.
func (j *Journal) UpdateWorking(expectedGeneration uint64, working []byte) error {
	return j.updateWorking(expectedGeneration, working, nil)
}

// updateWorkingWithHook is UpdateWorking with a fault-injection hook that runs
// after the bucket Put and before the Bolt commit (tests only).
func (j *Journal) updateWorkingWithHook(expectedGeneration uint64, working []byte, hook func() error) error {
	return j.updateWorking(expectedGeneration, working, hook)
}

func (j *Journal) updateWorking(expectedGeneration uint64, working []byte, hook func() error) error {
	if !validWorkingBytes(working) {
		return fmt.Errorf("%w: working bytes must be 1..%d bytes", ErrInvalid, MaxWorkingBytes)
	}
	// Copy before taking the lock and starting the transaction so the encoded
	// record never references the caller's slice.
	working = bytes.Clone(working)
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return ErrClosed
	}
	err := j.db.Update(func(tx *bolt.Tx) error {
		b, found, err := readStateTx(tx)
		if err != nil {
			return err
		}
		if !found {
			return ErrEmpty
		}
		if b.Generation != expectedGeneration {
			return &StateCASMismatchError{Expected: expectedGeneration, Stored: b.Generation}
		}
		if b.Generation == math.MaxUint64 {
			return &StateGenerationOverflowError{Generation: b.Generation}
		}
		next := State{
			BaseBytes:      b.BaseBytes,
			RemoteRevision: b.RemoteRevision,
			WorkingBytes:   working,
			Generation:     b.Generation + 1,
		}
		tb := tx.Bucket([]byte(bucketName))
		if err := tb.Put([]byte(stateKey), encodeState(next)); err != nil {
			return err
		}
		if hook != nil {
			return hook()
		}
		return nil
	})
	if err != nil {
		return wrapStateErr("update working", err)
	}
	return nil
}
