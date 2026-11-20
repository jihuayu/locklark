package vaultfilebackend

import (
	"context"
	"errors"
	"os"
	"sync"
)

// ProtectedReadView is the read-only capability exposed by
// Dir.WithProtectedRead. It is valid only for the duration of that call's
// callback and exposes exactly one operation: reading a named committed record
// and its opaque revision. It has no listing, path, lock, raw-file or write
// operation. The view is also bounded by the outer WithProtectedRead context:
// canceling that context invalidates the view even when a per-read context is
// still live.
//
// The zero value, a nil view and any view saved after its callback returned all
// fail with ErrDenied. A Read that starts before the scope is withdrawn is
// allowed to finish under the held lock; the scope does not release the lock
// until every such read has returned.
type ProtectedReadView struct {
	scope *protectedReadScope
}

// protectedReadScope is shared by every copy of one view. ctx is the outer
// WithProtectedRead context and bounds every view Read for the whole callback.
// active is set while the callback is running and cleared before the OS lock is
// released. Reads take the read side for their whole duration, so release waits
// for in-flight reads and a read that starts after withdrawal cannot observe a
// released lock.
type protectedReadScope struct {
	dir    *Dir
	ctx    context.Context
	mu     sync.RWMutex
	active bool
}

// contextErr reports whether either the retained outer context or the supplied
// per-read context is done. The outer context is checked first, so a per-read
// context can restrict a read but can never extend the scope's authority.
func (s *protectedReadScope) contextErr(ctx context.Context) error {
	if err := s.ctx.Err(); err != nil {
		return deniedMsg(err, "protected read scope cancelled")
	}
	if err := ctx.Err(); err != nil {
		return deniedMsg(err, "protected read cancelled")
	}
	return nil
}

func (s *protectedReadScope) enter() bool {
	s.mu.RLock()
	if !s.active {
		s.mu.RUnlock()
		return false
	}
	return true
}

func (s *protectedReadScope) leave() { s.mu.RUnlock() }

// stop withdraws the view and waits for reads already in progress. It is
// idempotent.
func (s *protectedReadScope) stop() {
	s.mu.Lock()
	s.active = false
	s.mu.Unlock()
}

// WithProtectedRead runs fn synchronously while holding the same in-process
// semaphore and whole-file OS lock that CreateIfAbsent and ReplaceIfVersion
// require. It revalidates the exact namespace and lock inode identities captured
// by OpenDir before fn, before every view Read, and before reporting success.
// fn receives the only read capability for the held scope.
//
// The view is withdrawn before the lock is released. A view saved past fn, the
// zero view, or a read racing the withdrawal fails with ErrDenied; reads that
// began while the scope was active finish under the still-held lock. The lock is
// released on normal return, a callback error, cancellation and panic.
//
// Acquisition shares the normal operation deadline: caller cancellation is
// ErrDenied wrapping the context cause, and an exhausted lock wait is a definite
// ErrConflict. The scope retains the outer context for its entire lifetime:
// every view Read checks both the outer context and its own supplied context
// before record access and again before returning a record, so a per-read
// context may restrict but never extend authority. Cancellation is also
// observed before success is reported. The callback itself is synchronous and
// is not preempted: a callback that ignores cancellation keeps the lock until it
// returns, so it must be bounded by the caller. A callback must not call a
// normal Dir method that acquires the lock; that nested wait times out as
// ErrConflict.
//
// The scope is deliberately non-mutating. It does not list names, create a path
// or lock file, resolve a ticket, sweep temporary files, open a second lock
// descriptor, or expose any write operation. A view Read reads the exact named
// record directly under the held lock rather than entering the ordinary Read
// path. Static identity checks retain the package threat model's limits: a
// same-UID process that replaces a checked path between the check and the use is
// outside the claim.
//
// The guarantee covers cooperating writer operations that share this exact live
// local-directory lock on one machine. It does not stop off-device or remote
// writers, prove the absence of unknown offline drafts, implement a
// workspace-level stop-workflow, import a destination or authorize cutover. If
// Close runs during fn, later view Reads and the final scope result fail with
// ErrDenied, but Close does not release the lock while fn is still running.
func (d *Dir) WithProtectedRead(ctx context.Context, fn func(*ProtectedReadView) error) error {
	if d == nil {
		return deniedMsg(nil, "protected read on a nil directory")
	}
	if fn == nil {
		return deniedMsg(nil, "protected read callback is nil")
	}
	if err := ctx.Err(); err != nil {
		return deniedMsg(err, "protected read")
	}
	if err := d.closedErr(); err != nil {
		return err
	}
	if _, err := d.dir(); err != nil {
		return err
	}

	_, release, err := d.lockHandle(ctx)
	if err != nil {
		return err
	}
	defer release()

	// The lock may have been granted just as cancellation arrived. Nothing has
	// been read or written in that case, so report ErrDenied before the callback.
	if err := ctx.Err(); err != nil {
		return deniedMsg(err, "protected read cancelled after acquiring the lock")
	}
	if err := d.closedErr(); err != nil {
		return err
	}
	if err := d.protectedReadable(); err != nil {
		return err
	}

	scope := &protectedReadScope{dir: d, ctx: ctx, active: true}
	defer scope.stop()

	view := &ProtectedReadView{scope: scope}
	if err := fn(view); err != nil {
		return err
	}
	// Withdraw immediately after the callback returns, before the final gates.
	// The deferred stop is then a no-op; on panic it is the release path.
	scope.stop()

	if err := ctx.Err(); err != nil {
		return deniedMsg(err, "protected read cancelled")
	}
	// Close during the callback invalidates the snapshot even when the callback
	// itself returned success. The lock is not released early.
	if err := d.closedErr(); err != nil {
		return err
	}
	if err := d.protectedReadable(); err != nil {
		return err
	}
	return nil
}

// Read returns the exact committed bytes and the opaque revision of one valid
// named record. It is valid only while the WithProtectedRead callback is
// running and only while both the scope's outer context and the supplied
// per-read context remain live. It never lists names and never exposes the
// underlying path.
func (v *ProtectedReadView) Read(ctx context.Context, name string) (ReadResult, error) {
	if err := ctx.Err(); err != nil {
		return ReadResult{}, deniedMsg(err, "protected read")
	}
	if v == nil || v.scope == nil || !v.scope.enter() {
		return ReadResult{}, deniedMsg(nil, "protected read scope is closed")
	}
	defer v.scope.leave()

	// The outer context is part of the live authority. Check it together with
	// the per-read context before touching any record state.
	if err := v.scope.contextErr(ctx); err != nil {
		return ReadResult{}, err
	}
	d := v.scope.dir
	if err := d.closedErr(); err != nil {
		return ReadResult{}, err
	}
	if !ValidName(name) {
		return ReadResult{}, deniedMsg(nil, "invalid name")
	}
	// Keep using the exact captured root and lock identity for every read. A
	// path or inode swapped before this check is refused; the check and the
	// read below do not share a descriptor, matching the package threat model.
	if err := d.protectedReadable(); err != nil {
		return ReadResult{}, err
	}
	if err := v.scope.contextErr(ctx); err != nil {
		return ReadResult{}, err
	}
	rec, err := readRecord(d.dataPath(name))
	if errors.Is(err, os.ErrNotExist) {
		return ReadResult{}, ErrNotFound
	}
	if err != nil {
		return ReadResult{}, err
	}
	// Cancellation on either context after the record was read must not release
	// its bytes or revision. The scope still holds the lock until this bounded
	// read returns.
	if err := v.scope.contextErr(ctx); err != nil {
		return ReadResult{}, err
	}
	// Close may have landed while the record was read. Do not hand the caller a
	// snapshot after the backend was closed.
	if err := d.closedErr(); err != nil {
		return ReadResult{}, err
	}
	return ReadResult{Bytes: rec.value, Revision: Revision(rec.version)}, nil
}

// protectedReadable revalidates the captured namespace directories and the
// exact lock inode path without opening the lock file. Opening and closing
// another descriptor for the lock inode would release this process's POSIX
// record lock, so the check is path-based and uses no descriptor.
func (d *Dir) protectedReadable() error {
	if _, err := d.dir(); err != nil {
		return err
	}
	if d.lockID == nil {
		return deniedMsg(nil, "lock file identity is missing")
	}
	st, err := os.Lstat(d.lock)
	if err != nil {
		return deniedMsg(err, "lock file")
	}
	if st.Mode()&os.ModeSymlink != 0 || !privateFile(st) {
		return deniedMsg(nil, "lock file is not a private regular file")
	}
	if !sameIdentity(d.lockID, st) {
		return deniedMsg(nil, "lock file is not the inode opened")
	}
	return nil
}
