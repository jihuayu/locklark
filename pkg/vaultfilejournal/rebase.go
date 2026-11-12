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

// This file adds the atomic rebase-and-prepare primitive and its immutable
// audit trail.
//
// RebaseAndPrepare replaces the local base with a caller-supplied remote base R
// and revision Rrev, makes the proposal bytes M the new working file, bumps the
// local state generation once, and records M as the prepared proposal, all in
// one bbolt write transaction. The proposal's own Generation is an independent
// caller field and is preserved verbatim.
//
// The audit trail is append-only. One audit record is written for every
// successful rebase under a nested bucket keyed by the new generation as an
// 8-byte big-endian integer. It records everything needed to recover or verify
// the transition offline: the full old state, the new remote base and revision,
// the new generation and the exact proposal that was prepared.
//
// Audit record layout (version 1), all integers big-endian:
//
//	offset  size  field
//	0       4     magic "LLVA"
//	4       2     format version (1)
//	6       8     old state generation
//	14      8     new generation
//	22      4     old base bytes length            0..MaxBaseBytes
//	26      2     old remote revision length       0..MaxStateRevisionBytes
//	28      4     old working bytes length         1..MaxWorkingBytes
//	32      4     new remote base length           1..MaxBaseBytes
//	36      2     new remote revision length       1..MaxStateRevisionBytes
//	38      4     proposal bytes length            1..MaxProposalBytes
//	42      2     proposal operation ID length     1..MaxOperationIDBytes
//	44      2     proposal expected revision length 0..MaxExpectedRevisionBytes
//	46      8     proposal generation
//	54      n1    old base bytes, opaque and stored verbatim
//	54+n1   n2    old remote revision, opaque and stored verbatim
//	...           old working, new remote base, new remote revision,
//	              proposal bytes and proposal operation ID, in that order
//	last    32    SHA-256 of the magic through the operation ID (domain separated)
//
// There are no trailing bytes. The decoder validates the versions, every
// declared length against its fixed cap, the exact total in uint64 before any
// conversion to int, the base/revision pairings, the checksum and the decoded
// invariants (including proposal.ExpectedRevision == remote revision); only
// then does it allocate the copies it returns. The audit format is independent
// of LLVJ, LLVS and LLVP, whose layouts are unchanged.
const (
	auditMagic    = "LLVA"
	auditVersion  = uint16(1)
	auditPrefix   = 4 + 2 + 8 + 8 + 4 + 2 + 4 + 4 + 2 + 4 + 2 + 2 + 8
	auditDigest   = sha256.Size
	auditOverhead = auditPrefix + auditDigest

	// MaxAuditRecordBytes is the absolute upper bound of one encoded audit
	// record; any longer stored value is rejected from its length alone.
	MaxAuditRecordBytes = auditOverhead +
		MaxBaseBytes + MaxStateRevisionBytes + MaxWorkingBytes +
		MaxBaseBytes + MaxStateRevisionBytes + MaxProposalBytes +
		MaxOperationIDBytes + MaxExpectedRevisionBytes

	auditDigestDomain = "locklark vault-file journal rebase audit v1\x00"

	auditBucketName = "rebase-audit"
)

// RebaseAudit is one immutable record of a successful RebaseAndPrepare. OldState
// is the complete state the call replaced, RemoteBase and RemoteRevision are the
// new base and revision, NewGeneration is the resulting local generation, and
// Proposal is the exact proposal that was prepared, including its independent
// caller-supplied Generation. Every byte slice is owned by the value.
type RebaseAudit struct {
	OldState       State
	RemoteBase     []byte
	RemoteRevision vaultfilebackend.Revision
	NewGeneration  uint64
	Proposal       Proposal
}

func validRebaseAudit(a RebaseAudit) bool {
	if !validStateGeneration(a.OldState) || a.OldState.Generation == math.MaxUint64 {
		return false
	}
	if a.NewGeneration != a.OldState.Generation+1 {
		return false
	}
	if len(a.RemoteBase) == 0 || len(a.RemoteBase) > MaxBaseBytes {
		return false
	}
	if len(a.RemoteRevision) == 0 || len(a.RemoteRevision) > MaxStateRevisionBytes {
		return false
	}
	if !validProposal(a.Proposal) {
		return false
	}
	return a.Proposal.ExpectedRevision == a.RemoteRevision
}

// auditRecordLen derives the exact encoded length for the field lengths.
func auditRecordLen(n1, n2, n3, n4, n5, n6, n7, n8 int) int {
	return auditOverhead + n1 + n2 + n3 + n4 + n5 + n6 + n7 + n8
}

func auditKey(generation uint64) []byte {
	key := make([]byte, 8)
	binary.BigEndian.PutUint64(key, generation)
	return key
}

func encodeRebaseAudit(a RebaseAudit) []byte {
	if !validRebaseAudit(a) {
		panic("vaultfilejournal: encodeRebaseAudit called with invalid audit")
	}
	n1 := len(a.OldState.BaseBytes)
	n2 := len(a.OldState.RemoteRevision)
	n3 := len(a.OldState.WorkingBytes)
	n4 := len(a.RemoteBase)
	n5 := len(a.RemoteRevision)
	n6 := len(a.Proposal.Bytes)
	n7 := len(a.Proposal.OperationID)
	n8 := len(a.Proposal.ExpectedRevision)
	buf := make([]byte, auditRecordLen(n1, n2, n3, n4, n5, n6, n7, n8))
	copy(buf[0:4], auditMagic)
	binary.BigEndian.PutUint16(buf[4:6], auditVersion)
	binary.BigEndian.PutUint64(buf[6:14], a.OldState.Generation)
	binary.BigEndian.PutUint64(buf[14:22], a.NewGeneration)
	binary.BigEndian.PutUint32(buf[22:26], uint32(n1))
	binary.BigEndian.PutUint16(buf[26:28], uint16(n2))
	binary.BigEndian.PutUint32(buf[28:32], uint32(n3))
	binary.BigEndian.PutUint32(buf[32:36], uint32(n4))
	binary.BigEndian.PutUint16(buf[36:38], uint16(n5))
	binary.BigEndian.PutUint32(buf[38:42], uint32(n6))
	binary.BigEndian.PutUint16(buf[42:44], uint16(n7))
	binary.BigEndian.PutUint16(buf[44:46], uint16(n8))
	binary.BigEndian.PutUint64(buf[46:54], a.Proposal.Generation)
	off := auditPrefix
	off += copy(buf[off:], a.OldState.BaseBytes)
	off += copy(buf[off:], a.OldState.RemoteRevision)
	off += copy(buf[off:], a.OldState.WorkingBytes)
	off += copy(buf[off:], a.RemoteBase)
	off += copy(buf[off:], a.RemoteRevision)
	off += copy(buf[off:], a.Proposal.Bytes)
	off += copy(buf[off:], a.Proposal.OperationID)
	off += copy(buf[off:], a.Proposal.ExpectedRevision)
	sum := auditDigestOf(buf[:off])
	copy(buf[off:], sum[:])
	return buf
}

func auditDigestOf(body []byte) [sha256.Size]byte {
	h := sha256.New()
	h.Write([]byte(auditDigestDomain))
	h.Write(body)
	var sum [sha256.Size]byte
	h.Sum(sum[:0])
	return sum
}

// decodeRebaseAudit validates raw completely and returns the audit record with
// freshly allocated copies. Any deviation from the exact layout is ErrCorrupt.
func decodeRebaseAudit(raw []byte) (RebaseAudit, error) {
	var a RebaseAudit
	if len(raw) < auditOverhead || len(raw) > MaxAuditRecordBytes {
		return a, ErrCorrupt
	}
	if !bytes.Equal(raw[0:4], []byte(auditMagic)) {
		return a, ErrCorrupt
	}
	if binary.BigEndian.Uint16(raw[4:6]) != auditVersion {
		return a, ErrCorrupt
	}
	// Keep every declared length in uint64 and check it against its fixed cap
	// and the exact derived total before converting any length to int, so a
	// length near MaxUint32 cannot wrap on a 32-bit platform.
	u1 := uint64(binary.BigEndian.Uint32(raw[22:26]))
	u2 := uint64(binary.BigEndian.Uint16(raw[26:28]))
	u3 := uint64(binary.BigEndian.Uint32(raw[28:32]))
	u4 := uint64(binary.BigEndian.Uint32(raw[32:36]))
	u5 := uint64(binary.BigEndian.Uint16(raw[36:38]))
	u6 := uint64(binary.BigEndian.Uint32(raw[38:42]))
	u7 := uint64(binary.BigEndian.Uint16(raw[42:44]))
	u8 := uint64(binary.BigEndian.Uint16(raw[44:46]))
	// The old base and old remote revision are non-empty exactly together and
	// are bounded by the new remote pair check below; the working bytes, new
	// remote base, new remote revision, proposal bytes and operation ID are
	// required non-empty by validRebaseAudit's length checks.
	if u1 > MaxBaseBytes ||
		u2 > MaxStateRevisionBytes ||
		u3 == 0 || u3 > MaxWorkingBytes ||
		u8 > MaxExpectedRevisionBytes {
		return a, ErrCorrupt
	}
	want := uint64(auditOverhead) + u1 + u2 + u3 + u4 + u5 + u6 + u7 + u8
	if want != uint64(len(raw)) {
		return a, ErrCorrupt
	}
	body := raw[:len(raw)-auditDigest]
	sum := auditDigestOf(body)
	if !bytes.Equal(sum[:], raw[len(raw)-auditDigest:]) {
		return a, ErrCorrupt
	}
	// The total now fits in an int and each field length fits within it.
	n1, n2, n3 := int(u1), int(u2), int(u3)
	n4, n5, n6 := int(u4), int(u5), int(u6)
	n7, n8 := int(u7), int(u8)
	if (n1 == 0) != (n2 == 0) {
		return a, ErrCorrupt
	}
	// Check every remaining semantic invariant against the raw header and
	// spans before allocating any payload copy.
	oldGen := binary.BigEndian.Uint64(raw[6:14])
	newGen := binary.BigEndian.Uint64(raw[14:22])
	if oldGen == math.MaxUint64 || newGen != oldGen+1 {
		return a, ErrCorrupt
	}
	if binary.BigEndian.Uint64(raw[46:54]) == 0 {
		return a, ErrCorrupt
	}
	if n4 == 0 || n5 == 0 || n6 == 0 || n7 == 0 {
		return a, ErrCorrupt
	}
	off := auditPrefix
	oldBaseRaw := raw[off : off+n1]
	off += n1
	oldRevRaw := raw[off : off+n2]
	off += n2
	oldWorkingRaw := raw[off : off+n3]
	off += n3
	newBaseRaw := raw[off : off+n4]
	off += n4
	newRevRaw := raw[off : off+n5]
	off += n5
	proposalBytesRaw := raw[off : off+n6]
	off += n6
	operationIDRaw := raw[off : off+n7]
	off += n7
	expectedRevRaw := raw[off : off+n8]
	if !validOperationID(string(operationIDRaw)) {
		return a, ErrCorrupt
	}
	if !bytes.Equal(expectedRevRaw, newRevRaw) {
		return a, ErrCorrupt
	}
	// Every semantic invariant holds, so allocate the owned copies. validRebaseAudit
	// below re-checks the assembled record as a defense in depth.
	a = RebaseAudit{
		OldState: State{
			BaseBytes:      bytes.Clone(oldBaseRaw),
			RemoteRevision: vaultfilebackend.Revision(string(oldRevRaw)),
			WorkingBytes:   bytes.Clone(oldWorkingRaw),
			Generation:     oldGen,
		},
		RemoteBase:     bytes.Clone(newBaseRaw),
		RemoteRevision: vaultfilebackend.Revision(string(newRevRaw)),
		NewGeneration:  newGen,
		Proposal: Proposal{
			Generation:       binary.BigEndian.Uint64(raw[46:54]),
			OperationID:      string(operationIDRaw),
			ExpectedRevision: vaultfilebackend.Revision(string(expectedRevRaw)),
			Bytes:            bytes.Clone(proposalBytesRaw),
		},
	}
	if !validRebaseAudit(a) {
		return RebaseAudit{}, ErrCorrupt
	}
	return a, nil
}

// validateAuditEntries fails closed on any malformed audit key or value. It
// never rewrites anything.
func validateAuditEntries(ab *bolt.Bucket) error {
	return ab.ForEach(func(k, v []byte) error {
		if len(k) != 8 {
			return ErrCorrupt
		}
		if v == nil || ab.Bucket(k) != nil {
			// A nested bucket where an audit record belongs.
			return ErrCorrupt
		}
		a, err := decodeRebaseAudit(v)
		if err != nil {
			return err
		}
		if a.NewGeneration != binary.BigEndian.Uint64(k) {
			return ErrCorrupt
		}
		return nil
	})
}

// checkNoPendingRecords refuses a legacy proposal or prepared proposal record,
// whether stored as a value or as a nested bucket. It never reads a value's
// contents, so the bytes stay untouched.
func checkNoPendingRecords(tb *bolt.Bucket) error {
	for _, key := range []string{recordKey, preparedKey} {
		if tb.Bucket([]byte(key)) != nil || tb.Get([]byte(key)) != nil {
			return fmt.Errorf("%w: %s record is present", ErrPendingRecords, key)
		}
	}
	return nil
}

// LoadRebaseAudit returns the immutable audit record for newGeneration, or
// ErrEmpty when no audit exists for that generation. It returns ErrCorrupt for
// a malformed top-level audit bucket shape, or for a malformed value stored
// under, or a nested bucket stored at, the requested generation key; such
// entries are never repaired. Unrelated sibling entries under the audit bucket
// are not scanned.
func (j *Journal) LoadRebaseAudit(newGeneration uint64) (RebaseAudit, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return RebaseAudit{}, ErrClosed
	}
	var a RebaseAudit
	found := false
	err := j.db.View(func(tx *bolt.Tx) error {
		tb := tx.Bucket([]byte(bucketName))
		if tb == nil {
			return nil
		}
		if tb.Get([]byte(auditBucketName)) != nil {
			return ErrCorrupt
		}
		ab := tb.Bucket([]byte(auditBucketName))
		if ab == nil {
			return nil
		}
		key := auditKey(newGeneration)
		if ab.Bucket(key) != nil {
			return ErrCorrupt
		}
		raw := ab.Get(key)
		if raw == nil {
			return nil
		}
		decoded, err := decodeRebaseAudit(raw)
		if err != nil {
			return err
		}
		if decoded.NewGeneration != newGeneration {
			return ErrCorrupt
		}
		a, found = decoded, true
		return nil
	})
	if err != nil {
		return RebaseAudit{}, wrapRebaseErr("load rebase audit", err)
	}
	if !found {
		return RebaseAudit{}, ErrEmpty
	}
	return a, nil
}

// RebaseAndPrepare atomically performs one local rebase and prepares the
// proposal in the same transaction. It requires that:
//
//   - expected is a valid state and equals the stored state in every field
//     (BaseBytes, RemoteRevision, WorkingBytes and Generation);
//   - no legacy proposal record and no prepared proposal record exists;
//   - remoteBase and remoteRevision are non-empty and within their bounds;
//   - proposal is a valid LLVJ v1 proposal and proposal.ExpectedRevision equals
//     remoteRevision. proposal.Bytes is both the new working bytes M and the
//     exact proposal bytes P.
//
// proposal.Generation is preserved exactly; it is independent of the local
// state generation and is not required to equal either expected.Generation or
// the new generation. On success the stored state becomes
// {BaseBytes: remoteBase, RemoteRevision: remoteRevision,
// WorkingBytes: proposal.Bytes, Generation: expected.Generation + 1}, the
// prepared record becomes {WorkingGeneration: expected.Generation + 1,
// Proposal: proposal}, and one audit record is appended under the audit bucket
// keyed by the new generation.
//
// A missing stored state is ErrEmpty. A stale or partially different expected
// state, including a same-generation state whose base bytes, remote revision or
// working bytes changed, is ErrStateMismatch. A present legacy or prepared
// record is ErrPendingRecords. An existing audit for the new generation is
// ErrAuditCollision. A generation of MaxUint64 is a
// *StateGenerationOverflowError matching ErrStateGenerationOverflow. Malformed
// inputs are ErrInvalid before the transaction starts; malformed stored audit
// shapes are ErrCorrupt. In every rejected case the state, legacy record,
// prepared record and all prior audits are unchanged.
//
// The primitive is local only: it does not verify a remote base, decrypt bytes,
// contact a backend or decide whether a publication succeeded. If the returned
// error is a storage error the transaction may have committed before the error
// surfaced, so do not claim success or failure; reopen and compare the state,
// prepared record and audit exactly.
func (j *Journal) RebaseAndPrepare(expected State, remoteBase []byte, remoteRevision vaultfilebackend.Revision, proposal Proposal) error {
	return j.rebaseAndPrepare(expected, remoteBase, remoteRevision, proposal, nil)
}

// rebaseAndPrepareWithHook is RebaseAndPrepare with a fault-injection hook that
// runs after the audit, state and prepared Puts and before the Bolt commit
// (tests only).
func (j *Journal) rebaseAndPrepareWithHook(expected State, remoteBase []byte, remoteRevision vaultfilebackend.Revision, proposal Proposal, hook func() error) error {
	return j.rebaseAndPrepare(expected, remoteBase, remoteRevision, proposal, hook)
}

func (j *Journal) rebaseAndPrepare(expected State, remoteBase []byte, remoteRevision vaultfilebackend.Revision, proposal Proposal, hook func() error) error {
	if !validStateGeneration(expected) {
		return fmt.Errorf("%w: malformed expected state", ErrInvalid)
	}
	if len(remoteBase) == 0 || len(remoteBase) > MaxBaseBytes {
		return fmt.Errorf("%w: remote base must be 1..%d bytes", ErrInvalid, MaxBaseBytes)
	}
	if len(remoteRevision) == 0 || len(remoteRevision) > MaxStateRevisionBytes {
		return fmt.Errorf("%w: remote revision must be 1..%d bytes", ErrInvalid, MaxStateRevisionBytes)
	}
	if !validProposal(proposal) {
		return fmt.Errorf("%w: malformed proposal", ErrInvalid)
	}
	if proposal.ExpectedRevision != remoteRevision {
		return fmt.Errorf("%w: proposal expected revision does not match remote revision", ErrInvalid)
	}
	// Own every source byte before the transaction starts, so neither the
	// encoded records nor the stored state can alias a caller slice.
	expected = State{
		BaseBytes:      bytes.Clone(expected.BaseBytes),
		RemoteRevision: vaultfilebackend.Revision(bytes.Clone([]byte(expected.RemoteRevision))),
		WorkingBytes:   bytes.Clone(expected.WorkingBytes),
		Generation:     expected.Generation,
	}
	remoteBase = bytes.Clone(remoteBase)
	remoteRevision = vaultfilebackend.Revision(bytes.Clone([]byte(remoteRevision)))
	proposal.OperationID = string(bytes.Clone([]byte(proposal.OperationID)))
	proposal.ExpectedRevision = vaultfilebackend.Revision(bytes.Clone([]byte(proposal.ExpectedRevision)))
	proposal.Bytes = bytes.Clone(proposal.Bytes)

	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return ErrClosed
	}
	err := j.db.Update(func(tx *bolt.Tx) error {
		stored, found, err := readStateTx(tx)
		if err != nil {
			return err
		}
		if !found {
			return ErrEmpty
		}
		if !sameState(stored, expected) {
			return fmt.Errorf("%w: stored generation %d differs", ErrStateMismatch, stored.Generation)
		}
		if stored.Generation == math.MaxUint64 {
			return &StateGenerationOverflowError{Generation: stored.Generation}
		}
		tb := tx.Bucket([]byte(bucketName))
		if tb == nil {
			return ErrEmpty
		}
		if err := checkNoPendingRecords(tb); err != nil {
			return err
		}
		// A value where the audit bucket belongs is a malformed shape.
		if tb.Get([]byte(auditBucketName)) != nil {
			return ErrCorrupt
		}
		ab := tb.Bucket([]byte(auditBucketName))
		next := stored.Generation + 1
		// Any audit entry at the target generation is a collision, whatever
		// its contents; it is never decoded, replaced or deleted.
		if ab != nil && ab.Get(auditKey(next)) != nil {
			return fmt.Errorf("%w: generation %d", ErrAuditCollision, next)
		}
		if ab != nil {
			if err := validateAuditEntries(ab); err != nil {
				return err
			}
		}
		if ab == nil {
			ab, err = tb.CreateBucket([]byte(auditBucketName))
			if err != nil {
				return err
			}
		}
		audit := RebaseAudit{
			OldState:       stored,
			RemoteBase:     remoteBase,
			RemoteRevision: remoteRevision,
			NewGeneration:  next,
			Proposal:       proposal,
		}
		if err := ab.Put(auditKey(next), encodeRebaseAudit(audit)); err != nil {
			return err
		}
		if err := tb.Put([]byte(stateKey), encodeState(State{
			BaseBytes:      remoteBase,
			RemoteRevision: remoteRevision,
			WorkingBytes:   proposal.Bytes,
			Generation:     next,
		})); err != nil {
			return err
		}
		if err := tb.Put([]byte(preparedKey), encodePrepared(PreparedProposal{
			WorkingGeneration: next,
			Proposal:          proposal,
		})); err != nil {
			return err
		}
		if hook != nil {
			return hook()
		}
		return nil
	})
	if err != nil {
		return wrapRebaseErr("rebase and prepare", err)
	}
	return nil
}

// wrapRebaseErr keeps sentinel errors identifiable and wraps anything else.
func wrapRebaseErr(op string, err error) error {
	if errors.Is(err, ErrCorrupt) ||
		errors.Is(err, ErrEmpty) ||
		errors.Is(err, ErrInvalid) ||
		errors.Is(err, ErrStateMismatch) ||
		errors.Is(err, ErrStateGenerationOverflow) ||
		errors.Is(err, ErrPendingRecords) ||
		errors.Is(err, ErrAuditCollision) {
		return err
	}
	return fmt.Errorf("vault file journal: %s: %w", op, err)
}
