package vaultfilejournal

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"

	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	bolt "go.etcd.io/bbolt"
)

const (
	ownedFirstSuccessorVersion uint16 = 2
	ownedStateHeader                  = len(stateMagic) + 2
	ownedStatePrefix                  = ownedStateHeader + 4 + 2 + 4 + 2
	ownedStateOverhead                = ownedStatePrefix + stateDigest
	maxOwnedStateBytes                = ownedStateOverhead + MaxBaseBytes + MaxWorkingBytes + 2*MaxStateRevisionBytes
)

// OwnedGenesisPin binds the original sealed genesis to the caller's trusted
// creation identity. The backend revision is opaque and is pinned separately
// with those exact bytes in the journal transaction.
type OwnedGenesisPin struct {
	Root         vaultfile.GenesisRootPin
	SealedSHA256 [sha256.Size]byte
	OperationID  string
}

// OwnedFirstSuccessor holds the authenticated endpoints of the first content
// transition and their recorded backend revisions. The caller owns the byte
// slices and must compare the successor with a fresh read of the named backend.
// This record carries no live account or device authorization.
type OwnedFirstSuccessor struct {
	GenesisBytes      []byte
	GenesisRevision   vaultfilebackend.Revision
	SuccessorBytes    []byte
	SuccessorRevision vaultfilebackend.Revision
}

func isOwnedFirstSuccessorRecord(raw []byte) bool {
	return len(raw) >= ownedStateHeader &&
		string(raw[:len(stateMagic)]) == stateMagic &&
		binary.BigEndian.Uint16(raw[len(stateMagic):]) == ownedFirstSuccessorVersion
}

func validOwnedFirstSuccessor(record OwnedFirstSuccessor) bool {
	return len(record.GenesisBytes) > 0 && len(record.GenesisBytes) <= MaxBaseBytes &&
		validWorkingBytes(record.SuccessorBytes) &&
		len(record.GenesisRevision) > 0 && len(record.GenesisRevision) <= MaxStateRevisionBytes &&
		len(record.SuccessorRevision) > 0 && len(record.SuccessorRevision) <= MaxStateRevisionBytes &&
		record.GenesisRevision != record.SuccessorRevision
}

func encodeOwnedFirstSuccessor(record OwnedFirstSuccessor) []byte {
	buf := make([]byte, 0, ownedStateOverhead+len(record.GenesisBytes)+len(record.GenesisRevision)+
		len(record.SuccessorBytes)+len(record.SuccessorRevision))
	buf = append(buf, stateMagic...)
	buf = binary.BigEndian.AppendUint16(buf, ownedFirstSuccessorVersion)
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(record.GenesisBytes)))
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(record.GenesisRevision)))
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(record.SuccessorBytes)))
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(record.SuccessorRevision)))
	buf = append(buf, record.GenesisBytes...)
	buf = append(buf, record.GenesisRevision...)
	buf = append(buf, record.SuccessorBytes...)
	buf = append(buf, record.SuccessorRevision...)
	sum := stateDigestOf(buf)
	return append(buf, sum[:]...)
}

func decodeOwnedFirstSuccessor(raw []byte) (OwnedFirstSuccessor, error) {
	if len(raw) < ownedStateOverhead || len(raw) > maxOwnedStateBytes || !isOwnedFirstSuccessorRecord(raw) {
		return OwnedFirstSuccessor{}, ErrCorrupt
	}
	lengths := raw[ownedStateHeader:ownedStatePrefix]
	genesisLen := uint64(binary.BigEndian.Uint32(lengths))
	genesisRevLen := uint64(binary.BigEndian.Uint16(lengths[4:]))
	successorLen := uint64(binary.BigEndian.Uint32(lengths[6:]))
	successorRevLen := uint64(binary.BigEndian.Uint16(lengths[10:]))
	if genesisLen == 0 || genesisLen > MaxBaseBytes ||
		genesisRevLen == 0 || genesisRevLen > MaxStateRevisionBytes ||
		successorLen == 0 || successorLen > MaxWorkingBytes ||
		successorRevLen == 0 || successorRevLen > MaxStateRevisionBytes ||
		uint64(ownedStateOverhead)+genesisLen+genesisRevLen+successorLen+successorRevLen != uint64(len(raw)) {
		return OwnedFirstSuccessor{}, ErrCorrupt
	}
	body := raw[:len(raw)-stateDigest]
	sum := stateDigestOf(body)
	if !bytes.Equal(sum[:], raw[len(body):]) {
		return OwnedFirstSuccessor{}, ErrCorrupt
	}

	genesisEnd := ownedStatePrefix + int(genesisLen)
	genesisRevEnd := genesisEnd + int(genesisRevLen)
	successorEnd := genesisRevEnd + int(successorLen)
	genesisRev := vaultfilebackend.Revision(body[genesisEnd:genesisRevEnd])
	successorRev := vaultfilebackend.Revision(body[successorEnd:])
	if genesisRev == successorRev {
		return OwnedFirstSuccessor{}, ErrCorrupt
	}
	return OwnedFirstSuccessor{
		GenesisBytes:      bytes.Clone(body[ownedStatePrefix:genesisEnd]),
		GenesisRevision:   genesisRev,
		SuccessorBytes:    bytes.Clone(body[genesisRevEnd:successorEnd]),
		SuccessorRevision: successorRev,
	}, nil
}

func verifyOwnedFirstSuccessor(record OwnedFirstSuccessor, pin OwnedGenesisPin) (string, error) {
	if sha256.Sum256(record.GenesisBytes) != pin.SealedSHA256 || !validOperationID(pin.OperationID) {
		return "", ErrCorrupt
	}
	checkpoint, err := vaultfile.VerifyGenesis(record.GenesisBytes, &pin.Root)
	if err != nil {
		return "", ErrCorrupt
	}
	genesis, err := vaultfile.ParseFile(record.GenesisBytes)
	if err != nil || genesis.Header.OpID != pin.OperationID {
		return "", ErrCorrupt
	}
	if err := vaultfile.VerifyContentTransition(record.GenesisBytes, record.SuccessorBytes, checkpoint); err != nil {
		return "", ErrCorrupt
	}
	successor, err := vaultfile.ParseFile(record.SuccessorBytes)
	if err != nil {
		return "", ErrCorrupt
	}
	return successor.Header.OpID, nil
}

func ownedFirstSuccessorBucket(tx *bolt.Tx, preparing bool) (*bolt.Bucket, error) {
	if err := checkOnlyJournalBucket(tx); err != nil {
		return nil, ErrCorrupt
	}
	if genesisIntentPresent(tx) {
		return nil, ErrPendingGenesisIntent
	}
	b := tx.Bucket([]byte(bucketName))
	if b == nil || b.Get([]byte(stateKey)) == nil {
		return nil, ErrEmpty
	}
	if err := b.ForEach(func(key, value []byte) error {
		if value == nil {
			return ErrCorrupt
		}
		switch string(key) {
		case stateKey:
			return nil
		case preparedKey:
			if preparing {
				return nil
			}
			return ErrPendingRecords
		case recordKey:
			return ErrPendingRecords
		default:
			return ErrCorrupt
		}
	}); err != nil {
		return nil, err
	}
	return b, nil
}

func loadOwnedFirstSuccessorTx(tx *bolt.Tx) (OwnedFirstSuccessor, error) {
	b, err := ownedFirstSuccessorBucket(tx, false)
	if err != nil {
		return OwnedFirstSuccessor{}, err
	}
	return decodeOwnedFirstSuccessor(b.Get([]byte(stateKey)))
}

// ReadOwnedFirstSuccessor opens an existing journal and returns its sole
// settled owned successor after authenticating both endpoints against pin.
func ReadOwnedFirstSuccessor(path string, pin OwnedGenesisPin) (OwnedFirstSuccessor, error) {
	var record OwnedFirstSuccessor
	j, err := openExisting(path, func(tx *bolt.Tx) error {
		var err error
		record, err = loadOwnedFirstSuccessorTx(tx)
		return err
	})
	if err != nil {
		return OwnedFirstSuccessor{}, err
	}
	if err := j.Close(); err != nil {
		return OwnedFirstSuccessor{}, err
	}
	if _, err := verifyOwnedFirstSuccessor(record, pin); err != nil {
		return OwnedFirstSuccessor{}, err
	}
	return record, nil
}

// LoadOwnedFirstSuccessor returns the sole settled owned successor from this
// already-open journal and authenticates both endpoints against pin. It reuses
// the existing exclusive lock and handle: it never opens, creates, locks or
// closes another journal path.
func (j *Journal) LoadOwnedFirstSuccessor(pin OwnedGenesisPin) (OwnedFirstSuccessor, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return OwnedFirstSuccessor{}, ErrClosed
	}
	var record OwnedFirstSuccessor
	err := j.db.View(func(tx *bolt.Tx) error {
		var err error
		record, err = loadOwnedFirstSuccessorTx(tx)
		return err
	})
	if err != nil {
		clear(record.GenesisBytes)
		clear(record.SuccessorBytes)
		return OwnedFirstSuccessor{}, err
	}
	if _, err := verifyOwnedFirstSuccessor(record, pin); err != nil {
		clear(record.GenesisBytes)
		clear(record.SuccessorBytes)
		return OwnedFirstSuccessor{}, err
	}
	return record, nil
}

// AckOwnedFirstSuccessor replaces an exact first prepared transition from the
// caller's pristine genesis snapshot. The caller supplies independently
// authorized scope and the exact backend readback and revision. Both endpoint
// pairs and deletion of the prepared proposal settle in one transaction.
func (j *Journal) AckOwnedFirstSuccessor(origin State, pin OwnedGenesisPin, proposal Proposal, readback []byte, revision vaultfilebackend.Revision) error {
	return j.ackOwnedFirstSuccessorWithUpdate(origin, pin, proposal, readback, revision, nil)
}

func (j *Journal) ackOwnedFirstSuccessorWithUpdate(origin State, pin OwnedGenesisPin, proposal Proposal, readback []byte, revision vaultfilebackend.Revision, update func(func(*bolt.Tx) error) error) error {
	record := OwnedFirstSuccessor{
		GenesisBytes:      origin.BaseBytes,
		GenesisRevision:   origin.RemoteRevision,
		SuccessorBytes:    readback,
		SuccessorRevision: revision,
	}
	if !validInitialState(origin) || !validOwnedFirstSuccessor(record) ||
		!validProposal(proposal) || proposal.Generation != origin.Generation+1 {
		return ErrInvalid
	}
	if proposal.ExpectedRevision != origin.RemoteRevision || !bytes.Equal(proposal.Bytes, readback) {
		return ErrPreparedMismatch
	}

	record.GenesisBytes = bytes.Clone(record.GenesisBytes)
	record.SuccessorBytes = bytes.Clone(record.SuccessorBytes)
	op, err := verifyOwnedFirstSuccessor(record, pin)
	if err != nil || op != proposal.OperationID {
		return ErrPreparedMismatch
	}
	proposal.Bytes = record.SuccessorBytes
	want := State{
		BaseBytes:      record.GenesisBytes,
		RemoteRevision: record.GenesisRevision,
		WorkingBytes:   record.SuccessorBytes,
		Generation:     proposal.Generation,
	}
	prepared := PreparedProposal{WorkingGeneration: want.Generation, Proposal: proposal}

	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return ErrClosed
	}
	if update == nil {
		update = j.db.Update
	}
	return update(func(tx *bolt.Tx) error {
		b, err := ownedFirstSuccessorBucket(tx, true)
		if err != nil {
			return err
		}
		current, err := decodeState(b.Get([]byte(stateKey)))
		if err != nil {
			return err
		}
		if !sameState(current, want) {
			return ErrStateMismatch
		}
		stored, found, err := readPreparedTx(tx)
		if err != nil {
			return err
		}
		if !found || !samePrepared(stored, prepared) {
			return ErrPreparedMismatch
		}
		if err := b.Put([]byte(stateKey), encodeOwnedFirstSuccessor(record)); err != nil {
			return err
		}
		return b.Delete([]byte(preparedKey))
	})
}
