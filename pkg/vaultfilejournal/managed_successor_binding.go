package vaultfilejournal

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	bolt "go.etcd.io/bbolt"
)

// This file adds one narrow, operation-specific metadata record to the same
// journal bucket. It is written in the same bbolt transaction as the managed
// successor Prepare (state, prepared proposal and immutable rebase audit), so a
// caller can never observe a prepared operation without the exact protected
// backend identity it was prepared against. The record contains only a
// generation, the operation ID and a fixed non-revealing identity digest. It
// never contains a pathname, ciphertext or opaque backend revision.
//
// The existing legacy proposal, state, prepared and audit formats are
// unchanged. Generic RebaseAndPrepare refuses to run while this record exists,
// and Ack never deletes or rewrites it, so it survives settlement as durable
// evidence for reopen.

const (
	managedBindingMagic      = "LLVB"
	managedBindingVersion    = uint16(1)
	managedBindingKey        = "managed-successor-binding"
	managedBindingDigestSize = sha256.Size

	// managedBindingPrefix is magic, version, generation, target digest and
	// the one-byte operation ID length.
	managedBindingPrefix = 4 + 2 + 8 + managedBindingDigestSize + 1
	managedBindingDigest = sha256.Size
	// MaxManagedBindingBytes is the absolute upper bound of one encoded
	// binding record.
	MaxManagedBindingBytes = managedBindingPrefix + MaxOperationIDBytes + managedBindingDigest

	managedBindingDomain = "locklark vault-file journal managed successor binding v1\x00"
)

// ManagedSuccessorBinding binds one prepared managed-successor generation and
// operation to the exact established local backend target. TargetDigest is a
// caller-computed fixed digest over the verified backend identity and exact
// name; it is not a path, a raw identity value or a digest of only bytes and
// revision.
type ManagedSuccessorBinding struct {
	Generation   uint64
	OperationID  string
	TargetDigest [sha256.Size]byte
}

func validManagedSuccessorBinding(b ManagedSuccessorBinding) bool {
	return b.Generation > 0 && validOperationID(b.OperationID) &&
		b.TargetDigest != ([sha256.Size]byte{})
}

func encodeManagedSuccessorBinding(b ManagedSuccessorBinding) []byte {
	if !validManagedSuccessorBinding(b) {
		panic("vaultfilejournal: encodeManagedSuccessorBinding called with invalid binding")
	}
	n := len(b.OperationID)
	buf := make([]byte, managedBindingPrefix+n+managedBindingDigest)
	copy(buf[0:4], managedBindingMagic)
	binary.BigEndian.PutUint16(buf[4:6], managedBindingVersion)
	binary.BigEndian.PutUint64(buf[6:14], b.Generation)
	copy(buf[14:14+managedBindingDigestSize], b.TargetDigest[:])
	buf[14+managedBindingDigestSize] = byte(n)
	copy(buf[managedBindingPrefix:], b.OperationID)
	sum := managedBindingDigestOf(buf[:managedBindingPrefix+n])
	copy(buf[managedBindingPrefix+n:], sum[:])
	return buf
}

func managedBindingDigestOf(body []byte) [sha256.Size]byte {
	h := sha256.New()
	h.Write([]byte(managedBindingDomain))
	h.Write(body)
	var sum [sha256.Size]byte
	h.Sum(sum[:0])
	return sum
}

func decodeManagedSuccessorBinding(raw []byte) (ManagedSuccessorBinding, error) {
	var out ManagedSuccessorBinding
	if len(raw) < managedBindingPrefix+1+managedBindingDigest ||
		len(raw) > MaxManagedBindingBytes {
		return out, ErrCorrupt
	}
	if !bytes.Equal(raw[0:4], []byte(managedBindingMagic)) ||
		binary.BigEndian.Uint16(raw[4:6]) != managedBindingVersion {
		return out, ErrCorrupt
	}
	digest := raw[14 : 14+managedBindingDigestSize]
	n := int(raw[14+managedBindingDigestSize])
	if n == 0 || n > MaxOperationIDBytes {
		return out, ErrCorrupt
	}
	want := managedBindingPrefix + n + managedBindingDigest
	if len(raw) != want {
		return out, ErrCorrupt
	}
	body := raw[:managedBindingPrefix+n]
	sum := managedBindingDigestOf(body)
	if !bytes.Equal(sum[:], raw[managedBindingPrefix+n:]) {
		return out, ErrCorrupt
	}
	operationID := string(raw[managedBindingPrefix : managedBindingPrefix+n])
	if !validOperationID(operationID) {
		return out, ErrCorrupt
	}
	copy(out.TargetDigest[:], digest)
	out.Generation = binary.BigEndian.Uint64(raw[6:14])
	out.OperationID = operationID
	if !validManagedSuccessorBinding(out) {
		return ManagedSuccessorBinding{}, ErrCorrupt
	}
	return out, nil
}

// LoadManagedSuccessorBinding returns the durable target binding written by
// RebaseAndPrepareManagedSuccessor. It returns ErrEmpty when no binding exists,
// and ErrCorrupt for a malformed value or nested bucket. It never repairs or
// rewrites the record.
func (j *Journal) LoadManagedSuccessorBinding() (ManagedSuccessorBinding, error) {
	if j == nil {
		return ManagedSuccessorBinding{}, ErrClosed
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return ManagedSuccessorBinding{}, ErrClosed
	}
	var out ManagedSuccessorBinding
	found := false
	err := j.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucketName))
		if b == nil {
			return nil
		}
		if b.Bucket([]byte(managedBindingKey)) != nil {
			return ErrCorrupt
		}
		raw := b.Get([]byte(managedBindingKey))
		if raw == nil {
			return nil
		}
		decoded, err := decodeManagedSuccessorBinding(raw)
		if err != nil {
			return err
		}
		out, found = decoded, true
		return nil
	})
	if err != nil {
		return ManagedSuccessorBinding{}, err
	}
	if !found {
		return ManagedSuccessorBinding{}, ErrEmpty
	}
	return out, nil
}

// RebaseAndPrepareManagedSuccessor is RebaseAndPrepare plus one exact target
// binding written atomically in the same transaction. The binding generation
// must be the new local generation and its operation ID must equal the prepared
// proposal operation. A journal that already has a managed binding is refused
// by the same pending-record check as a legacy/prepared record; it is never
// overwritten.
//
// All state, prepared, audit and error semantics are those of
// RebaseAndPrepare. On any rejected call no state, prepared, audit or binding
// record changes.
func (j *Journal) RebaseAndPrepareManagedSuccessor(expected State, remoteBase []byte,
	remoteRevision vaultfilebackend.Revision, proposal Proposal,
	binding ManagedSuccessorBinding) error {
	if !validManagedSuccessorBinding(binding) ||
		binding.OperationID != proposal.OperationID ||
		expected.Generation == ^uint64(0) ||
		binding.Generation != expected.Generation+1 {
		return fmt.Errorf("%w: malformed managed successor binding", ErrInvalid)
	}
	return j.rebaseAndPrepare(expected, remoteBase, remoteRevision, proposal, &binding, nil)
}
