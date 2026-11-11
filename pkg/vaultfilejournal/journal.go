// Package vaultfilejournal is a durable, local, single-record checkpoint for
// the vault-file publication (#110). It binds one generation to the exact
// operation ID, the exact expected remote revision and the exact sealed
// proposal bytes so a restarted process can reconcile that proposal rather
// than sign a new one.
//
// The journal stores only opaque sealed bytes, an opaque revision and an
// operation ID. It does not parse protocol structures, hold plaintext or
// private keys, perform cryptography, talk to a network, or decide whether a
// remote publication succeeded. That state machine belongs to a later
// integration.
//
// State lives in one bbolt database file. A bbolt read-write transaction gives
// crash-atomic updates with normal sync semantics (NoSync=false), and it does
// so without passing the record through the vaultfilebackend MaxValueSize cap
// as part of a larger metadata envelope.
//
// Every record carries an unkeyed SHA-256 checksum over its exact bytes. It
// detects malformed or accidentally corrupted local state; it is not a
// signature and does not stop a deliberate attacker who can also rewrite the
// checksum. Authenticity of the sealed proposal is the later wire/signature
// layer's concern, not this package's.
//
// When Save returns an error the outcome may be unknown: the transaction may
// have committed before the error surfaced. Never invent an outcome. Resolve
// it after reopening by loading the record and comparing it exactly with the
// proposal that was attempted.
package vaultfilejournal

import (
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Sentinel errors classify every failure; callers test them with errors.Is.
var (
	// ErrEmpty reports that no proposal has been saved yet.
	ErrEmpty = errors.New("vault file journal: empty")
	// ErrInvalid reports that a proposal or path argument was rejected
	// before anything was written: for example a zero generation, a malformed
	// operation ID, an oversize or empty sealed proposal, an oversize expected
	// revision, a relative path, a symlinked or non-regular database file, or
	// a parent directory that is not private.
	ErrInvalid = errors.New("vault file journal: invalid")
	// ErrCorrupt reports that a stored record cannot be trusted: a malformed
	// envelope, an unsupported version or a checksum mismatch. The checksum is
	// unkeyed SHA-256, so it detects malformed or accidentally corrupted
	// records, not deliberate tampering; an attacker who can rewrite the
	// database can also recompute it. Validation of the sealed wire content's
	// signature belongs to the later state-machine integration. The journal is
	// not overwritten by guess.
	ErrCorrupt = errors.New("vault file journal: corrupt")
	// ErrStaleGeneration reports that Save was asked to store a generation
	// lower than the stored one. The stored record is unchanged.
	ErrStaleGeneration = errors.New("vault file journal: stale generation")
	// ErrClosed reports use of a journal after Close.
	ErrClosed = errors.New("vault file journal: closed")
	// ErrLocked reports that Open could not take the database's exclusive
	// file lock within the lock timeout, for example because another
	// process (or another Journal in this process) holds it. It also matches
	// bbolt's own ErrTimeout.
	ErrLocked = errors.New("vault file journal: locked by another writer")
)

// SavedGenerationConflictError reports a Save whose generation equals the
// stored generation but whose record differs. The stored record is unchanged.
// It satisfies errors.Is(err, ErrInvalid).
type SavedGenerationConflictError struct {
	Generation  uint64
	OperationID string
}

func (e *SavedGenerationConflictError) Error() string {
	return fmt.Sprintf("vault file journal: generation %d already saved with a different proposal (operation %q)", e.Generation, e.OperationID)
}

func (e *SavedGenerationConflictError) Is(target error) bool { return target == ErrInvalid }

// Journal is an open local proposal journal. It is safe for concurrent use by
// multiple goroutines. One process at a time may open a given file; bbolt holds
// an exclusive file lock for the lifetime of the Journal. Opening a file that
// another writer holds fails with ErrLocked after a short timeout.
type Journal struct {
	mu     sync.Mutex
	db     *bolt.DB
	closed bool

	// afterPut, when non-nil, runs inside the Save transaction after the
	// bucket Put and before commit. It exists only for fault-injection tests.
	afterPut func() error
}

// lockTimeout bounds how long Open waits for another writer's lock. It is
// short so a misplaced second Open fails visibly rather than hanging.
const lockTimeout = 2 * time.Second

// Open opens (creating if absent) the journal database at path. path must be
// absolute and name a regular file, not a symlink or reparse point. The
// database file is created with mode 0600 (POSIX) or a protected DACL
// (Windows), and the parent directory must already exist and be private:
// Open never creates or tightens it, and rejects one that is not private.
// On POSIX a private directory is a real directory with no group or other
// permission bits; an existing database with such bits is rejected, never
// chmodded. On Windows it is a local fixed-drive path whose whole component
// chain is free of reparse points, is owned by a trusted principal and whose
// DACL grants no untrusted principal the rights to delete or replace a
// component, rewrite an ACL or write metadata, and whose immediate parent
// additionally grants no untrusted principal list, read, traverse, add-child,
// delete or ACL access; an existing database must be a regular, non-reparse
// file whose DACL grants no untrusted principal read, write, delete or ACL
// access.
//
// Open holds an exclusive lock on the file for the lifetime of the Journal; a
// concurrent opener of the same path fails with ErrLocked after the bbolt lock
// timeout, lockTimeout.
func Open(path string) (*Journal, error) {
	if path == "" || !filepath.IsAbs(path) {
		return nil, fmt.Errorf("%w: path must be absolute", ErrInvalid)
	}
	parent := filepath.Dir(path)
	if err := checkPrivateDir(parent); err != nil {
		return nil, err
	}
	missing, err := checkDBPath(path)
	if err != nil {
		return nil, err
	}
	return openDatabase(path, parent, missing)
}

// Close closes the journal. Later calls to Load and Save return ErrClosed.
// Close is idempotent.
func (j *Journal) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return nil
	}
	j.closed = true
	if err := j.db.Close(); err != nil {
		return fmt.Errorf("vault file journal: close: %w", err)
	}
	return nil
}

// Load returns a copy of the stored proposal, or ErrEmpty when no proposal has
// been saved. A stored record that fails validation is ErrCorrupt.
func (j *Journal) Load() (Proposal, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return Proposal{}, ErrClosed
	}
	var p Proposal
	found := false
	err := j.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucketName))
		if b == nil {
			return nil
		}
		raw := b.Get([]byte(recordKey))
		if raw == nil {
			return nil
		}
		// decodeRecord copies everything it returns before the read
		// transaction ends.
		decoded, err := decodeRecord(raw)
		if err != nil {
			return err
		}
		p, found = decoded, true
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrCorrupt) {
			return Proposal{}, err
		}
		return Proposal{}, fmt.Errorf("vault file journal: load: %w", err)
	}
	if !found {
		return Proposal{}, ErrEmpty
	}
	return p, nil
}

// Save durably stores p in one atomic transaction. It rejects a generation
// lower than the stored one with ErrStaleGeneration and permits an exact
// replay of the stored generation as a no-op. A same-generation record with
// different contents does not replace the stored record.
//
// If Save returns an error other than ErrInvalid, ErrStaleGeneration or a
// *SavedGenerationConflictError, the outcome may be unknown: the transaction
// may have committed before the error was observed. Do not invent an outcome;
// Close, reopen and Load, then compare the record exactly with p.
func (j *Journal) Save(p Proposal) error {
	if !validProposal(p) {
		return fmt.Errorf("%w: malformed proposal", ErrInvalid)
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return ErrClosed
	}
	return j.save(p, j.afterPut)
}

// save is the unexported transaction; hook runs after the bucket Put and before
// the Bolt commit. It exists so tests can inject failures at that point.
func (j *Journal) save(p Proposal, hook func() error) error {
	rec := encodeRecord(p)
	err := j.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(bucketName))
		if err != nil {
			return err
		}
		if cur := b.Get([]byte(recordKey)); cur != nil {
			old, err := decodeRecord(cur)
			if err != nil {
				return err
			}
			if p.Generation < old.Generation {
				return fmt.Errorf("%w: generation %d is below stored generation %d", ErrStaleGeneration, p.Generation, old.Generation)
			}
			if p.Generation == old.Generation {
				if sameProposal(old, p) {
					return nil
				}
				return &SavedGenerationConflictError{Generation: p.Generation, OperationID: old.OperationID}
			}
		}
		if err := b.Put([]byte(recordKey), rec); err != nil {
			return err
		}
		if hook != nil {
			return hook()
		}
		return nil
	})
	if err != nil {
		var conflict *SavedGenerationConflictError
		if errors.As(err, &conflict) || errors.Is(err, ErrStaleGeneration) || errors.Is(err, ErrCorrupt) {
			return err
		}
		return fmt.Errorf("vault file journal: save: %w", err)
	}
	return nil
}
