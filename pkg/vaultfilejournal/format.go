package vaultfilejournal

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"

	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
)

// formatVersion is the only record version this package reads or writes.
const formatVersion uint16 = 1

// Record layout (version 1), all integers big-endian:
//
//	offset  size  field
//	0       4     magic "LLVJ"
//	4       2     format version (1)
//	6       8     generation                 > 0
//	14      1     operation ID length        > 0
//	15      2     expected revision length   (0 means create)
//	17      4     proposal bytes length      > 0
//	21      n1    operation ID
//	21+n1   n2    expected revision, opaque and stored verbatim
//	21+n1+n2 n3   sealed proposal bytes, opaque and stored verbatim
//	last    32    SHA-256 of every preceding byte (domain separated)
//
// There are no trailing bytes. Nothing in the decoder allocates before the
// version, every declared length (checked against its fixed cap), the exact
// total record length and the digest have all been validated; the only
// allocation it makes is the copy of a checksum-validated proposal.
const (
	recordMagic    = "LLVJ"
	recordPrefix   = 4 + 2 + 8 + 1 + 2 + 4
	recordDigest   = sha256.Size
	recordOverhead = recordPrefix + recordDigest

	// MaxProposalBytes is the largest sealed proposal this journal stores,
	// equal to vaultfilebackend.MaxValueSize. Bytes are opaque; the journal
	// never parses, normalizes or re-encodes them.
	MaxProposalBytes = vaultfilebackend.MaxValueSize
	// MaxOperationIDBytes bounds the operation ID, which must be non-empty and
	// match [a-z0-9._:-].
	MaxOperationIDBytes = 64
	// MaxExpectedRevisionBytes bounds the opaque expected remote revision; the
	// empty revision means "create".
	MaxExpectedRevisionBytes = vaultfilebackend.MaxRevisionSize

	maxRecordLen = recordOverhead + MaxOperationIDBytes + MaxExpectedRevisionBytes + MaxProposalBytes

	digestDomain = "locklark vault-file journal record v1\x00"

	bucketName = "journal"
	recordKey  = "proposal"
)

// Proposal is the single durable proposal record. It binds one generation to
// its exact operation ID, the exact remote revision the proposal expects
// (opaque; empty when creating), and the exact sealed proposal bytes.
//
// Bytes carries the already sealed/encrypted single-file proposal. No
// plaintext payload, private key or protocol field is represented here; wire
// validation belongs to the state-machine integration.
type Proposal struct {
	Generation       uint64
	OperationID      string
	ExpectedRevision vaultfilebackend.Revision
	Bytes            []byte
}

func validOperationID(s string) bool {
	if len(s) == 0 || len(s) > MaxOperationIDBytes {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == ':' || c == '-' {
			continue
		}
		return false
	}
	return true
}

func validProposal(p Proposal) bool {
	return p.Generation > 0 &&
		validOperationID(p.OperationID) &&
		len(p.ExpectedRevision) <= MaxExpectedRevisionBytes &&
		len(p.Bytes) > 0 && len(p.Bytes) <= MaxProposalBytes
}

func encodeRecord(p Proposal) []byte {
	if !validProposal(p) {
		panic("vaultfilejournal: encodeRecord called with invalid proposal")
	}
	n1, n2, n3 := len(p.OperationID), len(p.ExpectedRevision), len(p.Bytes)
	buf := make([]byte, recordOverhead+n1+n2+n3)
	copy(buf[0:4], recordMagic)
	binary.BigEndian.PutUint16(buf[4:6], formatVersion)
	binary.BigEndian.PutUint64(buf[6:14], p.Generation)
	buf[14] = byte(n1)
	binary.BigEndian.PutUint16(buf[15:17], uint16(n2))
	binary.BigEndian.PutUint32(buf[17:21], uint32(n3))
	off := recordPrefix
	off += copy(buf[off:], p.OperationID)
	off += copy(buf[off:], p.ExpectedRevision)
	off += copy(buf[off:], p.Bytes)
	sum := recordDigestOf(buf[:off])
	copy(buf[off:], sum[:])
	return buf
}

func recordDigestOf(body []byte) [sha256.Size]byte {
	h := sha256.New()
	h.Write([]byte(digestDomain))
	h.Write(body)
	var sum [sha256.Size]byte
	h.Sum(sum[:0])
	return sum
}

// decodeRecord validates raw completely and returns the stored proposal with a
// freshly allocated copy of the bytes. Any deviation from the exact layout is
// ErrCorrupt.
//
// Every declared length is kept in its unsigned wire type and checked against
// its fixed cap, the zero-length rules and the exact total length computed in
// uint64 before any of them is converted to int. On a 32-bit platform a
// proposal length near MaxUint32 would otherwise wrap negative and let the
// total-length check pass; nothing is sliced until every check has passed.
func decodeRecord(raw []byte) (Proposal, error) {
	var p Proposal
	if len(raw) < recordOverhead || len(raw) > maxRecordLen {
		return p, ErrCorrupt
	}
	if !bytes.Equal(raw[0:4], []byte(recordMagic)) {
		return p, ErrCorrupt
	}
	if binary.BigEndian.Uint16(raw[4:6]) != formatVersion {
		return p, ErrCorrupt
	}
	// Validate every declared length against its cap before using any of them.
	u1 := uint(raw[14])
	u2 := uint(binary.BigEndian.Uint16(raw[15:17]))
	u3 := uint64(binary.BigEndian.Uint32(raw[17:21]))
	if u1 == 0 || u1 > MaxOperationIDBytes ||
		u2 > MaxExpectedRevisionBytes ||
		u3 == 0 || u3 > MaxProposalBytes {
		return p, ErrCorrupt
	}
	want := uint64(recordOverhead) + uint64(u1) + uint64(u2) + u3
	if want != uint64(len(raw)) {
		return p, ErrCorrupt
	}
	n1, n2, n3 := int(u1), int(u2), int(u3)
	body := raw[:len(raw)-recordDigest]
	sum := recordDigestOf(body)
	if !bytes.Equal(sum[:], raw[len(raw)-recordDigest:]) {
		return p, ErrCorrupt
	}
	off := recordPrefix
	op := string(raw[off : off+n1])
	off += n1
	rev := vaultfilebackend.Revision(string(raw[off : off+n2]))
	off += n2
	p = Proposal{
		Generation:       binary.BigEndian.Uint64(raw[6:14]),
		OperationID:      op,
		ExpectedRevision: rev,
		Bytes:            bytes.Clone(raw[off : off+n3]),
	}
	if !validProposal(p) {
		return Proposal{}, ErrCorrupt
	}
	return p, nil
}

// sameProposal reports whether a and b serialize to the identical exact
// record, so a same-generation replay replaces nothing.
func sameProposal(a, b Proposal) bool {
	return a.Generation == b.Generation &&
		a.OperationID == b.OperationID &&
		a.ExpectedRevision == b.ExpectedRevision &&
		bytes.Equal(a.Bytes, b.Bytes)
}
