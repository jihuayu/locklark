package vaultfilejournal

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	bolt "go.etcd.io/bbolt"
)

// ErrUnsupported reports an existing-only open on a platform without a safe
// descriptor-based implementation. Open retains its original platform policy.
var ErrUnsupported = errors.New("vault file journal: existing-only open unsupported")

// OpenExisting opens an existing, nonempty private journal containing a valid
// state record. It never creates a file, initializes a baseline or repairs the
// on-disk freelist. Missing, empty, unsafe or uninitialized journals are refused.
// The validated descriptor is passed directly to bbolt and the configured name
// is checked again after bbolt acquires its exclusive lock. Subsequent explicit
// journal operations retain the normal synchronous commit behavior.
//
// This is implemented for Darwin, Linux and Windows. Like Open, it coordinates
// cooperating writers; it does not isolate a journal from an owner or
// administrator performing arbitrary writes outside the locking protocol.
func OpenExisting(path string) (*Journal, error) {
	return openExisting(path, validateExistingState)
}

func openExisting(path string, validateState func(*bolt.Tx) error) (*Journal, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrInvalid
	}
	if err := checkPrivateDir(filepath.Dir(path)); err != nil {
		return nil, ErrInvalid
	}
	return openExistingOnlyDatabase(path, validateState)
}

// openExistingValidated never opens a name. The platform opener owns file until
// the one permitted OpenFile handoff; bbolt owns and closes it from then on.
func validateExistingState(tx *bolt.Tx) error {
	if genesisIntentPresent(tx) {
		return ErrPendingGenesisIntent
	}
	_, found, err := readStateTx(tx)
	if err != nil {
		return err
	}
	if !found {
		return ErrEmpty
	}
	return nil
}

// OpenExistingSettledShape opens an existing, nonempty private journal only
// when its stored shape is structurally settled: exactly the pristine
// generation-zero state (base equals working, nonempty remote revision, no
// pending record), or exactly the owned first-successor state with no pending
// record. It is an existing-only structural opener; it does not authenticate
// ownership, pin, checkpoint, signature or transition authority. Callers must
// still use the typed pristine/owned-successor readers. Like OpenExisting, it
// never creates, initializes or repairs the file and retains bbolt's exclusive
// lock for the Journal lifetime.
func OpenExistingSettledShape(path string) (*Journal, error) {
	return openExisting(path, validateSettledShape)
}

func validateSettledShape(tx *bolt.Tx) error {
	if genesisIntentPresent(tx) {
		return ErrPendingGenesisIntent
	}
	if err := checkOnlyJournalBucket(tx); err != nil {
		return ErrCorrupt
	}
	b := tx.Bucket([]byte(bucketName))
	if b == nil {
		return ErrInvalid
	}
	raw := b.Get([]byte(stateKey))
	if raw == nil {
		if err := checkNoPendingRecords(b); err != nil {
			return err
		}
		if b.Bucket([]byte(stateKey)) != nil {
			return ErrCorrupt
		}
		return ErrEmpty
	}
	if isOwnedFirstSuccessorRecord(raw) {
		if _, err := ownedFirstSuccessorBucket(tx, false); err != nil {
			return err
		}
		_, err := decodeOwnedFirstSuccessor(raw)
		return err
	}
	if err := checkNoPendingRecords(b); err != nil {
		return err
	}
	if err := b.ForEach(func(key, value []byte) error {
		if !bytes.Equal(key, []byte(stateKey)) || value == nil {
			return ErrCorrupt
		}
		return nil
	}); err != nil {
		return err
	}
	state, found, err := readStateTx(tx)
	if err != nil {
		return err
	}
	if !found {
		return ErrEmpty
	}
	if state.Generation != 0 || len(state.BaseBytes) == 0 ||
		len(state.RemoteRevision) == 0 || !bytes.Equal(state.BaseBytes, state.WorkingBytes) {
		return ErrCorrupt
	}
	return nil
}

// RevalidateExistingPath checks that the configured path still names the exact
// regular file whose descriptor this already-locked existing journal owns. It
// performs only a static Lstat comparison and never opens, locks, creates or
// modifies another handle. Open-created journals have no retained existing-only
// identity and are refused.
func (j *Journal) RevalidateExistingPath() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return ErrClosed
	}
	if j.existingPath == "" || j.existingInfo == nil {
		return ErrInvalid
	}
	current, err := os.Lstat(j.existingPath)
	if err != nil || current.Mode()&os.ModeSymlink != 0 || !current.Mode().IsRegular() ||
		!os.SameFile(j.existingInfo, current) {
		return ErrInvalid
	}
	return nil
}

func openExistingValidated(path string, file *os.File, validateLocked func() error, validateState func(*bolt.Tx) error) (*Journal, error) {
	if file == nil {
		return nil, ErrInvalid
	}
	handedOff := false
	defer func() {
		if !handedOff {
			_ = file.Close()
		}
	}()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, ErrInvalid
	}
	db, err := bolt.Open(path, 0600, &bolt.Options{
		NoSync:         false,
		NoFreelistSync: true,
		Timeout:        lockTimeout,
		OpenFile: func(name string, flag int, _ os.FileMode) (*os.File, error) {
			// bbolt supplies O_CREATE in write mode. It is declarative only:
			// no flags are forwarded to a syscall and no second open occurs.
			if handedOff || name != path || flag&os.O_TRUNC != 0 || flag&(os.O_WRONLY|os.O_RDWR) != os.O_RDWR {
				return nil, ErrInvalid
			}
			info, err := file.Stat()
			if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
				// NoFreelistSync does not disable bbolt's zero-file init.
				return nil, ErrInvalid
			}
			handedOff = true
			return file, nil
		},
	})
	if err != nil {
		if errors.Is(err, bolt.ErrTimeout) {
			return nil, fmt.Errorf("%w: %w", ErrLocked, bolt.ErrTimeout)
		}
		return nil, ErrInvalid
	}
	refuse := func(err error) (*Journal, error) {
		_ = db.Close()
		return nil, err
	}
	if err := validateLocked(); err != nil {
		return refuse(ErrInvalid)
	}
	if err := db.View(validateState); err != nil {
		if errors.Is(err, ErrCorrupt) || errors.Is(err, ErrEmpty) || errors.Is(err, ErrPendingGenesisIntent) || errors.Is(err, ErrPendingRecords) {
			return refuse(err)
		}
		return refuse(ErrInvalid)
	}
	// Merely changing this option writes nothing. A later explicit mutation
	// will use the same durable freelist policy as Open; opening/refusal did not
	// run bbolt's automatic freelist-rebuild commit.
	db.NoFreelistSync = false
	return &Journal{db: db, existingPath: path, existingInfo: info}, nil
}
