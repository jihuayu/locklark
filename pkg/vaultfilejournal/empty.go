package vaultfilejournal

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	bolt "go.etcd.io/bbolt"
)

// This file adds the atomic empty-only bootstrap initializer. Unlike
// InitializeState it never fills the state of a journal that already has any
// durable record: it succeeds only when the journal carries no record at all,
// and it decides that in one bbolt write transaction that also holds the state
// Put. A caller that reads with Load/LoadState/LoadPrepared and then writes
// would race another writer between the read and the write; this API has no
// such window.
//
// Having any record is enough to refuse: the legacy proposal record
// (recordKey), the state record (stateKey), the prepared record (preparedKey),
// any other key in the journal bucket, any other top-level bucket. A known
// record is never decoded, compared with the proposed state or treated as
// absent: an existing record is non-empty however it is shaped. A known record
// key that actually holds a nested bucket rather than a value is ErrCorrupt,
// because bbolt's Get would otherwise report it as an absent value.

// ErrJournalNotEmpty reports an InitializeEmptyState call on a journal that
// already holds any record: a state, a legacy proposal, a prepared proposal,
// an unknown key in the journal bucket or an unknown top-level bucket. The
// stored records are unchanged. A record that already exists is refused even
// when its bytes are exactly the state this call would store: there is no
// exact-replay no-op. It always wraps ErrStateExists, so callers that already
// handle ErrStateExists keep matching. A known record key that holds a nested
// bucket is reported as ErrCorrupt instead.
var ErrJournalNotEmpty = fmt.Errorf("%w: journal is not empty", ErrStateExists)

// InitializeEmptyState stores the first local state of a journal bootstrap in
// one transaction, and only if the journal is empty.
//
// s must be exactly the state a bootstrap establishes: Generation 0, BaseBytes
// and WorkingBytes equal to each other and non-empty, and a non-empty
// RemoteRevision within MaxStateRevisionBytes. Anything else is ErrInvalid
// before the transaction starts. The bytes are stored by copy; the revision is
// stored verbatim.
//
// It succeeds only when, inside the same write transaction, the journal carries
// no record at all: no journal bucket, an empty one, or no bucket other than
// the one this call creates. The state is then the only record written.
//
// It fails, changing nothing, when:
//
//   - a state record exists, whatever its bytes and even if they equal s:
//     ErrJournalNotEmpty; an initialized journal is never re-initialized;
//   - a legacy proposal record, a prepared record, an unknown key in the
//     journal bucket or an unknown top-level bucket exists: ErrJournalNotEmpty;
//   - a known record key in the journal bucket holds a nested bucket instead
//     of a record value: ErrCorrupt, never repaired and never treated as
//     absent;
//   - the journal is closed: ErrClosed.
//
// A caller that only has the ErrJournalNotEmpty from a repeated call must read
// the committed state with LoadState and compare it exactly with s itself; this
// API does not confirm or compare it.
//
// The error never carries a stored value. InitializeState, Save, Load,
// UpdateWorking, Prepare, Ack and every other existing API keep their own
// semantics; this API is the only one that checks the whole journal before its
// first write.
//
// A returned error identifies the outcome: a refused call (the errors above)
// commits nothing. Any other error, such as an I/O or commit failure, may leave
// the outcome unknown: reopen the journal and call LoadState, then compare the
// result exactly with s. This package observes no caller context and there is
// none to observe; a committed state is always visible in full and never
// partially.
func (j *Journal) InitializeEmptyState(s State) error {
	if s.Generation != 0 ||
		len(s.BaseBytes) == 0 ||
		len(s.RemoteRevision) == 0 ||
		!bytes.Equal(s.BaseBytes, s.WorkingBytes) ||
		!validStateGeneration(s) {
		return fmt.Errorf("%w: initial state must be generation 0 with matching non-empty base and working bytes and a revision", ErrInvalid)
	}
	// Copy before taking the lock and starting the transaction so the encoded
	// record never references the caller's slices.
	s.BaseBytes = bytes.Clone(s.BaseBytes)
	s.WorkingBytes = bytes.Clone(s.WorkingBytes)
	s.RemoteRevision = vaultfilebackend.Revision(bytes.Clone([]byte(s.RemoteRevision)))
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return ErrClosed
	}
	err := j.db.Update(func(tx *bolt.Tx) error {
		if err := checkOnlyJournalBucket(tx); err != nil {
			return err
		}
		if b := tx.Bucket([]byte(bucketName)); b != nil {
			if err := checkKnownRecords(b); err != nil {
				return err
			}
			if err := b.ForEach(func(k, _ []byte) error {
				switch string(k) {
				case recordKey, stateKey, preparedKey:
					return nil
				}
				return fmt.Errorf("%w: unknown record key", ErrJournalNotEmpty)
			}); err != nil {
				return err
			}
		}
		// Creating the bucket inside this transaction is atomic: an error
		// rolls the whole transaction back.
		nb, err := tx.CreateBucketIfNotExists([]byte(bucketName))
		if err != nil {
			return err
		}
		return nb.Put([]byte(stateKey), encodeState(s))
	})
	if err != nil {
		return wrapEmptyErr("initialize empty state", err)
	}
	return nil
}

// checkOnlyJournalBucket rejects any top-level bucket this package does not
// know, so a future or foreign record format is never ignored or overwritten.
// A top-level entry is always a bucket when bbolt enumerates it here, so the
// journal bucket needs no further shape check; its known keys are checked by
// checkKnownRecords.
func checkOnlyJournalBucket(tx *bolt.Tx) error {
	return tx.ForEach(func(name []byte, _ *bolt.Bucket) error {
		if !bytes.Equal(name, []byte(bucketName)) {
			return fmt.Errorf("%w: unknown bucket", ErrJournalNotEmpty)
		}
		return nil
	})
}

// checkKnownRecords classifies the three keys this package owns inside the
// journal bucket. Any of them is a non-empty finding: an existing record is
// never decoded, compared with the new state or treated as absent, so even an
// exact copy of the proposed state is ErrJournalNotEmpty. bbolt's Get returns
// nil both for an absent key and for a key that holds a nested bucket; a nested
// bucket is refused as ErrCorrupt rather than reported as empty.
func checkKnownRecords(b *bolt.Bucket) error {
	for _, key := range []string{recordKey, stateKey, preparedKey} {
		if b.Get([]byte(key)) != nil {
			return fmt.Errorf("%w: existing %s record", ErrJournalNotEmpty, key)
		}
		if b.Bucket([]byte(key)) != nil {
			return fmt.Errorf("%w: %s is a bucket, not a record", ErrCorrupt, key)
		}
	}
	return nil
}

// wrapEmptyErr keeps the sentinel errors identifiable and wraps anything else
// as a journal error.
func wrapEmptyErr(op string, err error) error {
	if errors.Is(err, ErrJournalNotEmpty) ||
		errors.Is(err, ErrCorrupt) ||
		errors.Is(err, ErrClosed) {
		return err
	}
	return fmt.Errorf("vault file journal: %s: %w", op, err)
}
