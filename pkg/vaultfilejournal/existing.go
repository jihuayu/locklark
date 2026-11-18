package vaultfilejournal

import (
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
	return &Journal{db: db}, nil
}
