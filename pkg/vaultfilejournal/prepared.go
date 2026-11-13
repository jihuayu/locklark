package vaultfilejournal

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	bolt "go.etcd.io/bbolt"
)

// This file adds the durable prepared-proposal checkpoint between saving a
// proposal and observing its remote acknowledgement (or rejection).
//
// It lives under its own bucket key, preparedKey, and never reads, rewrites or
// deletes the legacy proposal record under recordKey. A prepared proposal is an
// outer wrapper carrying:
//
//   - WorkingGeneration: the local state generation the proposal was prepared
//     against. It is a local CAS value; the proposal's own Generation is the
//     legacy record field and is never used in its place.
//   - ProposalRecord: the proposal encoded by the legacy LLVJ v1 record codec,
//     stored verbatim, byte for byte.
//
// Prepared record layout (version 1), all integers big-endian:
//
//	offset  size  field
//	0       4     magic "LLVP"
//	4       2     format version (1)
//	6       8     working generation
//	14      4     embedded proposal record length   1..maxRecordLen
//	18      n     embedded LLVJ v1 proposal record, verbatim
//	18+n    32    SHA-256 of magic through proposal record (domain separated)
//
// There are no trailing bytes. The decoder rejects a declared length against
// its fixed cap and derives the exact total length in uint64 before
// converting any length to int, checks the exact total and the checksum, and
// only then decodes the inner LLVJ v1 record and allocates the copies it
// returns. It never repairs a damaged record.
const (
	preparedMagic    = "LLVP"
	preparedVersion  = uint16(1)
	preparedPrefix   = 4 + 2 + 8 + 4
	preparedDigest   = sha256.Size
	preparedOverhead = preparedPrefix + preparedDigest

	// MaxPreparedRecordBytes is the absolute upper bound of one encoded
	// prepared record (wrapper overhead plus the largest LLVJ v1 record); any
	// longer stored value is rejected from its length alone.
	MaxPreparedRecordBytes = preparedOverhead + maxRecordLen

	preparedDigestDomain = "locklark vault-file journal prepared v1\x00"

	preparedKey = "prepared"
)

// PreparedProposal is one durably prepared, not yet locally acknowledged
// proposal. WorkingGeneration is the state generation it was prepared against;
// Proposal is the exact legacy proposal.
type PreparedProposal struct {
	WorkingGeneration uint64
	Proposal          Proposal
}

// preparedMismatchError reports a Prepare or Ack whose input disagrees with
// the stored state or prepared record, or whose state no longer matches the
// prepared proposal. The stored records are unchanged. It satisfies
// errors.Is(err, ErrPreparedMismatch).
type preparedMismatchError struct {
	reason string
}

func (e *preparedMismatchError) Error() string {
	return "vault file journal: prepared mismatch: " + e.reason
}

func (e *preparedMismatchError) Is(target error) bool { return target == ErrPreparedMismatch }

func mismatchf(format string, args ...any) error {
	return &preparedMismatchError{reason: fmt.Sprintf(format, args...)}
}

func encodePrepared(pp PreparedProposal) []byte {
	inner := encodeRecord(pp.Proposal)
	buf := make([]byte, preparedOverhead+len(inner))
	copy(buf[0:4], preparedMagic)
	binary.BigEndian.PutUint16(buf[4:6], preparedVersion)
	binary.BigEndian.PutUint64(buf[6:14], pp.WorkingGeneration)
	binary.BigEndian.PutUint32(buf[14:18], uint32(len(inner)))
	copy(buf[preparedPrefix:], inner)
	sum := preparedDigestOf(buf[:preparedPrefix+len(inner)])
	copy(buf[preparedPrefix+len(inner):], sum[:])
	return buf
}

func preparedDigestOf(body []byte) [sha256.Size]byte {
	h := sha256.New()
	h.Write([]byte(preparedDigestDomain))
	h.Write(body)
	var sum [sha256.Size]byte
	h.Sum(sum[:0])
	return sum
}

// decodePrepared validates raw completely and returns the prepared proposal
// with freshly allocated copies. Any deviation from the exact layout is
// ErrCorrupt.
func decodePrepared(raw []byte) (PreparedProposal, error) {
	var pp PreparedProposal
	if len(raw) < preparedOverhead || len(raw) > MaxPreparedRecordBytes {
		return pp, ErrCorrupt
	}
	if !bytes.Equal(raw[0:4], []byte(preparedMagic)) {
		return pp, ErrCorrupt
	}
	if binary.BigEndian.Uint16(raw[4:6]) != preparedVersion {
		return pp, ErrCorrupt
	}
	// Check the declared length against its cap and the exact derived total
	// in uint64 before converting it to int, so a length near MaxUint32 cannot
	// wrap to a negative int on 32-bit platforms.
	u := binary.BigEndian.Uint32(raw[14:18])
	if u == 0 || uint64(u) > maxRecordLen {
		return pp, ErrCorrupt
	}
	want := uint64(preparedOverhead) + uint64(u)
	if want != uint64(len(raw)) {
		return pp, ErrCorrupt
	}
	n := int(u)
	end := preparedPrefix + n
	sum := preparedDigestOf(raw[:end])
	if !bytes.Equal(sum[:], raw[end:]) {
		return pp, ErrCorrupt
	}
	inner, err := decodeRecord(raw[preparedPrefix:end])
	if err != nil {
		return pp, err
	}
	return PreparedProposal{
		WorkingGeneration: binary.BigEndian.Uint64(raw[6:14]),
		Proposal:          inner,
	}, nil
}

// samePrepared compares the generation and every proposal field byte for byte.
func samePrepared(a, b PreparedProposal) bool {
	return a.WorkingGeneration == b.WorkingGeneration && sameProposal(a.Proposal, b.Proposal)
}

// readPreparedTx decodes the prepared record inside an open transaction. It
// returns found=false when no record exists; the result is already copied.
func readPreparedTx(tx *bolt.Tx) (PreparedProposal, bool, error) {
	b := tx.Bucket([]byte(bucketName))
	if b == nil {
		return PreparedProposal{}, false, nil
	}
	raw := b.Get([]byte(preparedKey))
	if raw == nil {
		return PreparedProposal{}, false, nil
	}
	pp, err := decodePrepared(raw)
	if err != nil {
		return PreparedProposal{}, false, err
	}
	return pp, true, nil
}

// wrapPreparedErr keeps sentinel errors identifiable and wraps anything else.
func wrapPreparedErr(op string, err error) error {
	if errors.Is(err, ErrCorrupt) ||
		errors.Is(err, ErrEmpty) ||
		errors.Is(err, ErrPreparedExists) ||
		errors.Is(err, ErrPreparedMismatch) {
		return err
	}
	return fmt.Errorf("vault file journal: %s: %w", op, err)
}

// LoadPrepared returns a deep copy of the durably prepared proposal, or
// ErrEmpty when none is prepared. A stored record that fails validation is
// ErrCorrupt and is never repaired.
func (j *Journal) LoadPrepared() (PreparedProposal, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return PreparedProposal{}, ErrClosed
	}
	var pp PreparedProposal
	found := false
	err := j.db.View(func(tx *bolt.Tx) error {
		var err error
		pp, found, err = readPreparedTx(tx)
		return err
	})
	if err != nil {
		return PreparedProposal{}, wrapPreparedErr("load prepared", err)
	}
	if !found {
		return PreparedProposal{}, ErrEmpty
	}
	return pp, nil
}

// Prepare durably records p as the prepared proposal for the state generation
// expectedWorkingGeneration, in one transaction that first re-reads the state.
// It requires that:
//
//   - a state record exists and its Generation equals expectedWorkingGeneration;
//   - p.ExpectedRevision equals the stored RemoteRevision;
//   - p.Bytes equals the stored WorkingBytes byte for byte;
//   - p is a valid LLVJ v1 proposal (positive Generation, valid operation ID,
//     bounded expected revision and non-empty bounded bytes).
//
// An exact replay of the already prepared proposal is an idempotent no-op. A
// different outstanding prepared proposal is rejected with ErrPreparedExists
// and is never overwritten. Every other disagreement is a
// *preparedMismatchError matching ErrPreparedMismatch; a missing state is
// ErrEmpty; a malformed p is ErrInvalid before the transaction starts.
// Rejected calls change no record.
//
// Prepare never reads or writes the legacy proposal record.
func (j *Journal) Prepare(expectedWorkingGeneration uint64, p Proposal) error {
	return j.prepare(expectedWorkingGeneration, p, nil)
}

// prepareWithHook is Prepare with a fault-injection hook that runs after the
// prepared record is written and before the Bolt commit (tests only).
func (j *Journal) prepareWithHook(expectedWorkingGeneration uint64, p Proposal, hook func() error) error {
	return j.prepare(expectedWorkingGeneration, p, hook)
}

func (j *Journal) prepare(expectedWorkingGeneration uint64, p Proposal, hook func() error) error {
	if !validProposal(p) {
		return fmt.Errorf("%w: malformed proposal", ErrInvalid)
	}
	// Copy before taking the lock so the encoded record never references the
	// caller's slices.
	p.OperationID = string(bytes.Clone([]byte(p.OperationID)))
	p.ExpectedRevision = vaultfilebackend.Revision(bytes.Clone([]byte(p.ExpectedRevision)))
	p.Bytes = bytes.Clone(p.Bytes)
	pp := PreparedProposal{WorkingGeneration: expectedWorkingGeneration, Proposal: p}
	rec := encodePrepared(pp)
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
		s, found, err := readStateTx(tx)
		if err != nil {
			return err
		}
		if !found {
			return ErrEmpty
		}
		if s.Generation != expectedWorkingGeneration {
			return mismatchf("state generation %d is not expected %d", s.Generation, expectedWorkingGeneration)
		}
		if p.ExpectedRevision != s.RemoteRevision {
			return mismatchf("proposal expected revision does not match state revision")
		}
		if !bytes.Equal(p.Bytes, s.WorkingBytes) {
			return mismatchf("proposal bytes do not match state working bytes")
		}
		if cur, found, err := readPreparedTx(tx); err != nil {
			return err
		} else if found {
			if samePrepared(cur, pp) {
				return nil
			}
			return ErrPreparedExists
		}
		if err := b.Put([]byte(preparedKey), rec); err != nil {
			return err
		}
		if hook != nil {
			return hook()
		}
		return nil
	})
	if err != nil {
		return wrapPreparedErr("prepare", err)
	}
	return nil
}

// Ack durably promotes the prepared proposal for operationID to the local base
// after the caller has observed a remote success, in one transaction that
// re-reads the state and the prepared record. It requires that:
//
//   - a prepared record exists (else ErrEmpty);
//   - its OperationID equals operationID (else ErrPreparedMismatch);
//   - exactProposalBytes, the sealed proposal file bytes the backend or caller
//     read, equal the prepared Proposal.Bytes byte for byte (else
//     ErrPreparedMismatch). Pass those raw file bytes as read: do not wrap them
//     in the LLVJ v1 record encoding nor in the prepared wrapper. The stored
//     prepared record itself still embeds the exact LLVJ v1 encoding of the
//     proposal;
//   - its ExpectedRevision still equals the stored RemoteRevision (else
//     ErrPreparedMismatch);
//   - newRevision is non-empty and at most MaxStateRevisionBytes (else
//     ErrInvalid, rejected before the transaction starts);
//   - the prepared WorkingGeneration is not greater than the state Generation
//     (else ErrPreparedMismatch); when they are equal the stored WorkingBytes
//     must still equal the proposal bytes (else ErrPreparedMismatch).
//
// On success BaseBytes and RemoteRevision become the prepared proposal bytes
// and newRevision, the current working bytes and Generation are kept as they
// are, and the prepared record is deleted. When the generation is unchanged the
// working file equals the new base, so the state is clean; when it is newer it
// carries an unsynced edit that is preserved. The legacy proposal record is
// never read, rewritten or deleted.
//
// Ack validates only local durable state: that the prepared proposal and the
// supplied operation ID and sealed proposal bytes agree, and that it is still
// based on the current remote base. It does not verify a remote
// acknowledgement's signature, perform crypto or policy authorization, or
// contact a remote. The
// caller must verify the remote result outside this package; calling Ack is not
// evidence that a remote publication happened. A rejected call changes no
// record, and once acknowledged a repeated Ack returns ErrEmpty.
//
// If an error other than the sentinels above is returned the outcome may be
// unknown; reopen and compare the state and prepared record exactly.
func (j *Journal) Ack(operationID string, exactProposalBytes []byte, newRevision vaultfilebackend.Revision) error {
	return j.ack(operationID, exactProposalBytes, newRevision, nil)
}

// ackWithHook is Ack with a fault-injection hook that runs after the state Put
// and the prepared delete and before the Bolt commit (tests only).
// exactProposalBytes has the same meaning as in Ack.
func (j *Journal) ackWithHook(operationID string, exactProposalBytes []byte, newRevision vaultfilebackend.Revision, hook func() error) error {
	return j.ack(operationID, exactProposalBytes, newRevision, hook)
}

func (j *Journal) ack(operationID string, exactProposalBytes []byte, newRevision vaultfilebackend.Revision, hook func() error) error {
	if len(newRevision) == 0 || len(newRevision) > MaxStateRevisionBytes {
		return fmt.Errorf("%w: new revision must be 1..%d bytes", ErrInvalid, MaxStateRevisionBytes)
	}
	newRevision = vaultfilebackend.Revision(bytes.Clone([]byte(newRevision)))
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return ErrClosed
	}
	err := j.db.Update(func(tx *bolt.Tx) error {
		s, found, err := readStateTx(tx)
		if err != nil {
			return err
		}
		if !found {
			return ErrEmpty
		}
		pp, found, err := readPreparedTx(tx)
		if err != nil {
			return err
		}
		if !found {
			return ErrEmpty
		}
		if pp.Proposal.OperationID != operationID {
			return mismatchf("operation ID does not match prepared proposal")
		}
		if !bytes.Equal(pp.Proposal.Bytes, exactProposalBytes) {
			return mismatchf("sealed proposal bytes do not match prepared proposal")
		}
		if pp.Proposal.ExpectedRevision != s.RemoteRevision {
			return mismatchf("prepared proposal expected revision is no longer the state revision")
		}
		if pp.WorkingGeneration > s.Generation {
			return mismatchf("prepared generation %d is newer than state generation %d", pp.WorkingGeneration, s.Generation)
		}
		if pp.WorkingGeneration == s.Generation && !bytes.Equal(s.WorkingBytes, pp.Proposal.Bytes) {
			return mismatchf("state working bytes no longer match prepared proposal")
		}
		tb := tx.Bucket([]byte(bucketName))
		if err := tb.Put([]byte(stateKey), encodeState(State{
			BaseBytes:      pp.Proposal.Bytes,
			RemoteRevision: newRevision,
			WorkingBytes:   s.WorkingBytes,
			Generation:     s.Generation,
		})); err != nil {
			return err
		}
		if err := tb.Delete([]byte(preparedKey)); err != nil {
			return err
		}
		if hook != nil {
			return hook()
		}
		return nil
	})
	if err != nil {
		return wrapPreparedErr("ack", err)
	}
	return nil
}
