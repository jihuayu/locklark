//go:build darwin || linux

package vaultfilejournal

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unicode/utf8"

	"github.com/jihuayu/locklark/internal/localpath"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/sys/unix"
)

type newStateStage uint8

const (
	newStateParentBound newStateStage = iota
	newStateFileCreated
	newStateDatabaseLocked
	newStateCommitted
	newStateBeforeParentSync
	newStateDatabaseClosed
)

func createNewState(path string, state State) error {
	return createNewStateWith(path, state, nil)
}

// probe is a private deterministic negative-test seam, never a product hook.
func createNewStateWith(path string, state State, probe func(newStateStage) error) (retErr error) {
	if !validInitialState(state) || path == "" || len(path) > 4096 || !utf8.ValidString(path) || strings.ContainsRune(path, 0) ||
		!filepath.IsAbs(path) || filepath.Clean(path) != path {
		return ErrInvalid
	}
	// Own the sealed bytes for the whole create/initialize attempt.
	state.BaseBytes = bytes.Clone(state.BaseBytes)
	state.WorkingBytes = state.BaseBytes
	defer clear(state.BaseBytes)
	originalParent := filepath.Dir(path)
	if checkPrivateDir(originalParent) != nil {
		return ErrInvalid
	}
	canonical, err := localpath.TrustedTemporaryParent(originalParent)
	if err != nil {
		return ErrInvalid
	}
	before, err := os.Lstat(canonical)
	if err != nil {
		return ErrInvalid
	}
	parentFD, err := unix.Open(canonical, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return ErrInvalid
	}
	parent := os.NewFile(uintptr(parentFD), "vaultfile-new-parent")
	if parent == nil {
		_ = unix.Close(parentFD)
		return ErrInvalid
	}
	created := false
	defer func() {
		if parent.Close() != nil && retErr == nil {
			if created {
				retErr = ErrCreateUnknown
			} else {
				retErr = ErrInvalid
			}
		}
	}()
	heldParent, err := parent.Stat()
	if err != nil || !os.SameFile(before, heldParent) || validateNewParent(parent, canonical, originalParent) != nil {
		return ErrInvalid
	}
	step := func(stage newStateStage) error {
		if probe != nil {
			return probe(stage)
		}
		return nil
	}
	if step(newStateParentBound) != nil || validateNewParent(parent, canonical, originalParent) != nil {
		return ErrInvalid
	}
	name := filepath.Base(path)
	fd, err := unix.Openat(parentFD, name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0600)
	if errors.Is(err, unix.EEXIST) {
		return ErrTargetExists
	}
	if err != nil {
		// An unclassified creation syscall failure is never guessed away.
		return ErrCreateUnknown
	}
	created = true
	file := os.NewFile(uintptr(fd), "vaultfile-new-journal")
	if file == nil {
		_ = unix.Close(fd)
		return ErrCreateUnknown
	}
	handedOff := false
	defer func() {
		if !handedOff && file.Close() != nil {
			retErr = ErrCreateUnknown
		}
	}()
	if step(newStateFileCreated) != nil {
		return ErrCreateUnknown
	}
	// Scope this change to our newly created inode. A restrictive inherited
	// umask must not leave a falsely successful, owner-unreadable journal.
	if unix.Fchmod(fd, 0600) != nil || validateNewFile(file, parentFD, name, path) != nil ||
		validateNewParent(parent, canonical, originalParent) != nil {
		return ErrCreateUnknown
	}
	db, err := bolt.Open(path, 0600, &bolt.Options{NoSync: false, Timeout: lockTimeout,
		OpenFile: func(got string, flags int, _ os.FileMode) (*os.File, error) {
			if handedOff || got != path || flags&os.O_TRUNC != 0 || flags&(os.O_WRONLY|os.O_RDWR) != os.O_RDWR {
				return nil, ErrInvalid
			}
			// Only this O_EXCL-proven new descriptor may be zero length.
			// OpenExisting's zero-length/state refusals are unchanged.
			if validateNewFile(file, parentFD, name, path) != nil {
				return nil, ErrInvalid
			}
			handedOff = true
			return file, nil
		}})
	if err != nil {
		return ErrCreateUnknown
	}
	journal := &Journal{db: db}
	defer func() {
		if journal.Close() != nil {
			retErr = ErrCreateUnknown
		}
	}()
	validate := func() error {
		if validateNewParent(parent, canonical, originalParent) != nil {
			return ErrInvalid
		}
		return validateNewFile(file, parentFD, name, path)
	}
	if step(newStateDatabaseLocked) != nil || validate() != nil {
		return ErrCreateUnknown
	}
	if journal.InitializeEmptyState(state) != nil {
		return ErrCreateUnknown
	}
	if step(newStateCommitted) != nil || validate() != nil || step(newStateBeforeParentSync) != nil || parent.Sync() != nil || validate() != nil {
		return ErrCreateUnknown
	}
	if journal.Close() != nil || step(newStateDatabaseClosed) != nil {
		return ErrCreateUnknown
	}
	return nil
}

func validateNewParent(parent *os.File, canonical, original string) error {
	held, err := parent.Stat()
	if err != nil || !held.IsDir() || held.Mode().Perm() != 0700 {
		return ErrInvalid
	}
	stat, ok := held.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return ErrInvalid
	}
	for _, path := range []string{canonical, original} {
		current, err := os.Lstat(path)
		if err != nil || !current.IsDir() || current.Mode()&os.ModeSymlink != 0 || !os.SameFile(held, current) {
			return ErrInvalid
		}
	}
	return nil
}

func validateNewFile(file *os.File, parentFD int, name, path string) error {
	var held, current unix.Stat_t
	fd := int(file.Fd())
	if unix.Fstat(fd, &held) != nil || held.Mode&unix.S_IFMT != unix.S_IFREG || held.Mode&07777 != 0600 ||
		held.Uid != uint32(os.Geteuid()) || held.Nlink != 1 {
		return ErrInvalid
	}
	flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_ACCMODE != unix.O_RDWR ||
		unix.Fstatat(parentFD, name, &current, unix.AT_SYMLINK_NOFOLLOW) != nil ||
		current.Mode&unix.S_IFMT != unix.S_IFREG || current.Dev != held.Dev || current.Ino != held.Ino {
		return ErrInvalid
	}
	info, err := file.Stat()
	if err != nil {
		return ErrInvalid
	}
	named, err := os.Lstat(path)
	if err != nil || !named.Mode().IsRegular() || !os.SameFile(info, named) {
		return ErrInvalid
	}
	return nil
}
