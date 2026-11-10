package vaultfilebackend

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Directory layout below the configured root. Every directory is 0700; the
// lock file, temporary files and data files are 0600 and are never followed
// through symlinks.
//
//	<root>/vaultfile-backend/v1/.locklark-vaultfile.lock  shared lock inode
//	<root>/vaultfile-backend/v1/tmp/    write-once temporary files
//	<root>/vaultfile-backend/v1/data/   one committed file per Name
//
// Threat model. The checks below defend cooperating processes of the same
// machine against a misconfigured or replaced namespace: a symlink or a
// non-directory where <root>/vaultfile-backend, v1, tmp or data is expected,
// or one of those directories loosened past 0700, is refused instead of
// followed, and the whole namespace is re-validated on every path-based
// operation and compared with the directory identity captured by OpenDir, so a
// component swapped after OpenDir for another real directory of acceptable
// mode and owner is refused instead of silently redirecting the store. These
// are static checks: they do not defend against a same-UID process that races
// arbitrary replacement of these components between a check and the use that
// follows it; closing that gap needs directory-descriptor-relative operations,
// which this driver does not use.
//
// Crash handling. The lock inode carries the kernel lock plus an owner ticket
// naming the temporary file of the write in progress. A dead holder releases
// the kernel lock; its owner ticket remains, and the next writer removes the
// named temporary file before clearing the ticket (see resolve). The lock
// inode itself is never removed or renamed, so every process locks the same
// file for the whole lifetime of the store; a replaced or symlinked lock file
// is refused with ErrDenied instead of being recreated.
const (
	dirSubdir = "vaultfile-backend"
	dirVer    = "v1"
	lockName  = ".locklark-vaultfile.lock"
	tmpName   = "tmp"
	dataName  = "data"

	ticketHolder = "holder"
	ticketFree   = "free"

	lockPoll     = 2 * time.Millisecond
	ticketMaxLen = 256

	// recordMagic and recordVersion frame the header that precedes the
	// stored bytes: magic, length-prefixed version, length-prefixed digest,
	// then the value itself.
	recordMagic      = "LLVFREV1"
	recordVersionMax = 64
	recordHeaderMax  = len(recordMagic) + 4 + recordVersionMax + 4 + sha256.Size
)

// Dir is a local-directory Backend storing one value per Name.
//
// It is implemented and tested on darwin and linux only. Multi-writer safety is
// claimed only for cooperating processes on one machine that open the same
// directory on a local file system. Multi-writer support over network,
// virtualized or desktop-synced file systems is not claimed: advisory record
// locks and directory renames are not coherent across machines there.
//
// Each committed file stores the caller's opaque value preceded by a header
// holding a random per-commit version and the SHA-256 digest of the value. The
// Revision handed out is the random version, so reading back the same record
// returns the same Revision and equal bytes written twice get different
// Revisions. Every mutation re-reads the same record under the shared lock and
// compares the version verbatim: there is no unconditional overwrite.
//
// List and history are not part of the contract; List returns ErrUnsupported,
// or ErrDenied after Close.
type Dir struct {
	// cfgRoot is the resolved configured root, ns is <root>/vaultfile-backend
	// and root is its v1 directory. All three are re-validated by dir before
	// every operation: ns and root are paths below cfgRoot, so the root itself
	// must stay a real directory for those checks to mean anything.
	cfgRoot string
	ns      string
	root    string
	lock    string
	// lockID is the identity of the lock inode captured from the descriptor
	// OpenDir opened. Every operation refuses a lock path that now names a
	// different inode, so an instance never locks a replacement file.
	lockID os.FileInfo
	// identity holds the directory identity of each protected component as
	// OpenDir validated it. dir compares every later Lstat against it, so a
	// component replaced by another real directory is refused even when the
	// replacement has an acceptable mode and owner.
	identity componentIdentities

	mu     sync.Mutex
	closed bool
	// timeout bounds the combined lock wait of one operation: the
	// in-process and OS lock waits share one deadline, so a busy process
	// cannot extend a waiter past it.
	timeout time.Duration
	// inProc serializes goroutines of this process on the shared inode.
	// POSIX record locks do not exclude threads of one process, so the
	// kernel lock alone would let same-process writers race.
	inProc *inProcLock
}

// inProcLock serializes same-process writers per lock inode across all Dir
// instances and roots opened by this process. Unlike sync.Mutex its wait can
// be bounded by a deadline or abandoned on cancellation.
type inProcLock struct {
	sem chan struct{}
}

var inProcRegistry sync.Map // resolved lock path -> *inProcLock

func inProcFor(path string) *inProcLock {
	v, _ := inProcRegistry.LoadOrStore(path, &inProcLock{sem: make(chan struct{}, 1)})
	return v.(*inProcLock)
}

// acquire takes the lock, waiting until deadline. A zero deadline waits
// without limit.
func (l *inProcLock) acquire(ctx context.Context, deadline time.Time) error {
	select {
	case l.sem <- struct{}{}:
		return nil
	default:
	}
	var timeout <-chan time.Time
	if !deadline.IsZero() {
		t := time.NewTimer(time.Until(deadline))
		defer t.Stop()
		timeout = t.C
	}
	select {
	case l.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-timeout:
		return errLockTimeout
	}
}

func (l *inProcLock) release() { <-l.sem }

var errLockTimeout = errors.New("lock wait exceeded its deadline")

// componentIdentities are the directory identities captured by OpenDir, in the
// order dir validates the components. An empty identity means it was not
// captured, and identity checks are then skipped.
type componentIdentities struct {
	root os.FileInfo
	ns   os.FileInfo
	v1   os.FileInfo
	tmp  os.FileInfo
	data os.FileInfo
}

// captureIdentity records the identity of d, which must already have passed the
// matching check, so a failed OpenDir cannot leave a half-captured namespace in
// service.
func captureIdentity(d, label string) (os.FileInfo, error) {
	st, err := os.Lstat(d)
	if err != nil {
		return nil, deniedMsg(err, label)
	}
	return st, nil
}

// sameIdentity reports whether a later Lstat st is the directory OpenDir opened.
// os.SameFile compares device and inode (or volume and file id), so a rename
// within the same file system keeps the identity while a different directory,
// including one moved into the old path, does not.
func sameIdentity(want, got os.FileInfo) bool {
	if want == nil {
		return true
	}
	return got != nil && os.SameFile(want, got)
}

// OpenDir prepares root and opens a private namespace below it. Any wait it
// performs, including the wait for the process-wide lock-file semaphore, is
// bounded by DefaultLockTimeout and reports ErrConflict when it runs out.
func OpenDir(root string) (*Dir, error) {
	if !dirSupported {
		return nil, fmt.Errorf("%w: the local directory backend is implemented for darwin and linux only", ErrUnsupported)
	}
	if root == "" {
		return nil, deniedMsg(nil, "empty root")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, deniedMsg(err, "root")
	}
	real, err := prepareRoot(abs)
	if err != nil {
		return nil, err
	}
	// The namespace component under the root is accepted only as a real
	// private directory, whether it already exists or is created here: an
	// existing symlink, a non-directory or a loosened directory is refused
	// before anything is created below it.
	ns := filepath.Join(real, dirSubdir)
	base := filepath.Join(ns, dirVer)
	tmpDir := filepath.Join(base, tmpName)
	dataDir := filepath.Join(base, dataName)
	var ids componentIdentities
	// The configured root keeps its own policy (any mode that is not group or
	// world writable), so it is validated with checkRootIdentity rather than as
	// a private 0700 directory.
	if ids.root, err = captureIdentity(real, "root"); err != nil {
		return nil, err
	}
	if err := checkRootIdentity(real, ids.root); err != nil {
		return nil, err
	}
	for _, c := range []struct {
		path  string
		label string
		out   *os.FileInfo
	}{
		{ns, "storage namespace", &ids.ns},
		{base, "version directory", &ids.v1},
		{tmpDir, "data directory", &ids.tmp},
		{dataDir, "data directory", &ids.data},
	} {
		if err := makePrivateDir(c.path, c.label); err != nil {
			return nil, err
		}
		// Capture the identity of the exact directory just validated, so
		// every later operation can detect a replacement, not only a symlink
		// or a loosened mode.
		st, err := captureIdentity(c.path, c.label)
		if err != nil {
			return nil, err
		}
		*c.out = st
	}
	lock := filepath.Join(base, lockName)
	// POSIX record locks belong to the process, not to a descriptor, and
	// closing any descriptor for the lock inode releases every lock the
	// process holds on it. The descriptor opened here exists only to create
	// and validate the lock file, so it is closed while holding the same
	// in-process semaphore as operations: an in-flight operation of this
	// process keeps owning its lock until it releases the semaphore, and the
	// close can never drop that lock underneath it. The wait is bounded so an
	// operation that is stuck does not hang OpenDir; a timeout is a definite
	// ErrConflict, as for any other lock wait.
	pl := inProcFor(lock)
	deadline := time.Now().Add(DefaultLockTimeout)
	if err := pl.acquire(context.Background(), deadline); err != nil {
		return nil, lockWaitError(err)
	}
	f, err := openLockFile(lock)
	if err != nil {
		pl.release()
		return nil, err
	}
	// The identity comes from the opened descriptor, so it names exactly the
	// inode this Dir is pinned to rather than whatever a later path lookup
	// would find. The descriptor is then closed under the semaphore (see
	// above) and later opens are compared against this identity.
	var lockID os.FileInfo
	if lockID, err = f.Stat(); err != nil {
		f.Close()
		pl.release()
		return nil, deniedMsg(err, "lock file")
	}
	_ = f.Close()
	pl.release()
	return &Dir{cfgRoot: real, ns: ns, root: base, lock: lock, lockID: lockID, identity: ids, timeout: DefaultLockTimeout, inProc: inProcFor(lock)}, nil
}

// makePrivateDir creates d with 0700 when it is missing and then validates it
// with checkPrivateDir. An existing entry is never replaced.
func makePrivateDir(d, label string) error {
	if err := checkPrivateDir(d, label); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Mkdir(d, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return deniedMsg(err, "create "+label)
	}
	return checkPrivateDir(d, label)
}

// checkPrivateDir Lstats d without following it and accepts only a real
// directory owned by the effective user that is not group/world writable and
// has exactly 0700. A symlink, a non-directory, a looser mode or a foreign
// owner is ErrDenied; a missing entry is returned as os.ErrNotExist. Ownership
// is checked here, not in privateDir, which also covers trusted ancestors such
// as /usr that are legitimately owned by root.
func checkPrivateDir(d, label string) error {
	st, err := os.Lstat(d)
	if err != nil {
		return deniedMsg(err, label)
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.IsDir() {
		return deniedMsg(nil, label+" is a symlink or not a directory")
	}
	if !privateDir(st) || st.Mode().Perm() != 0700 {
		return deniedMsg(nil, label+" is not a private 0700 directory")
	}
	if !ownedByEUID(st) {
		return deniedMsg(nil, label+" is not owned by the current user")
	}
	return nil
}

// prepareRoot creates a missing root with 0700, refuses a root that is a
// symlink or not a directory, and checks the real path chain: every ancestor
// must be trusted (not group/world writable, or a system sticky directory). It
// returns the root with symlinked ancestors resolved (for example
// /var -> /private/var on macOS). The resolved path is a fixed absolute path
// that later lexical checks rely on.
func prepareRoot(abs string) (string, error) {
	if _, err := os.Lstat(abs); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(abs, 0700); err != nil {
			return "", deniedMsg(err, "create root")
		}
	}
	st, err := os.Lstat(abs)
	if err != nil {
		return "", deniedMsg(err, "root")
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.IsDir() {
		return "", deniedMsg(nil, "root is not a real directory")
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		return "", deniedMsg(err, "resolve root")
	}
	real := filepath.Join(parent, filepath.Base(abs))
	for cur := real; ; cur = filepath.Dir(cur) {
		info, err := os.Stat(cur)
		if err != nil || !info.IsDir() || !trustedAncestor(info) {
			return "", deniedMsg(nil, "root ancestors are not trusted")
		}
		if filepath.Dir(cur) == cur {
			return real, nil
		}
	}
}

// trustedAncestor applies exactly the policy of privateDir, which is what
// OpenDir used to check the root and its ancestors: a directory is accepted
// only when it is not group/world writable, or when it is a root-owned system
// sticky directory such as /tmp. A sticky directory owned by anyone else is
// refused. Like OpenDir, it follows symlinks: OpenDir resolves the root path,
// and Dir.dir re-checks the resolved root by identity.
func trustedAncestor(info os.FileInfo) bool {
	return privateDir(info)
}

// checkRootIdentity confirms that the configured root is still the real
// directory OpenDir opened, without following the final component and without
// changing the root policy. OpenDir accepts a root of any mode as long as the
// root and its ancestors are not group/world writable, so a relinked or loose
// root fails if it is a symlink, no longer a directory, writable by group or
// others, or a different directory than the one opened (a nil want skips the
// identity comparison). Ownership is not required: a root such as /var/tmp may
// legitimately belong to root.
func checkRootIdentity(p string, want os.FileInfo) error {
	st, err := os.Lstat(p)
	if err != nil {
		return deniedMsg(err, "root")
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.IsDir() {
		return deniedMsg(nil, "root is not a real directory")
	}
	if !trustedAncestor(st) {
		return deniedMsg(nil, "root is writable by group or others")
	}
	if !sameIdentity(want, st) {
		return deniedMsg(nil, "root is not the directory opened")
	}
	return nil
}

// dir re-validates every component of the namespace on every operation: the
// configured root, <root>/vaultfile-backend, its v1 directory, and the tmp and
// data directories. Each component is Lstat-ed on its own path, so a component
// replaced by a symlink or loosened to group/world-writable since OpenDir is
// refused before any path below it is used, rather than followed to wherever it
// points. Checking the root first matters because ns and root are paths below
// it: without that check, a root swapped for a symlink would make the Lstat of
// every other component follow the link into an outside tree. A component that
// moved, was linked, loosened or replaced by a different directory fails with
// ErrDenied: each component must have the identity OpenDir captured, so a
// replacement that happens to have an acceptable mode and owner still does not
// redirect the store. These are static checks of each path's final component;
// the check and the later use do not share a descriptor, so a replacement
// between them is not prevented (see the threat model above).
func (d *Dir) dir() (string, error) {
	if err := checkRootIdentity(d.cfgRoot, d.identity.root); err != nil {
		return "", err
	}
	dataDir := filepath.Join(d.root, dataName)
	parts := []struct {
		path  string
		want  os.FileInfo
		label string
	}{
		{d.ns, d.identity.ns, "storage namespace"},
		{d.root, d.identity.v1, "version directory"},
		{filepath.Join(d.root, tmpName), d.identity.tmp, "temporary directory"},
		{dataDir, d.identity.data, "data directory"},
	}
	for _, p := range parts {
		if err := checkPrivateDir(p.path, p.label); err != nil {
			return "", err
		}
		st, err := os.Lstat(p.path)
		if err != nil {
			return "", deniedMsg(err, p.label)
		}
		if !sameIdentity(p.want, st) {
			return "", deniedMsg(nil, p.label+" is not the directory opened")
		}
	}
	return dataDir, nil
}

func (d *Dir) dataPath(name string) string {
	sum := sha256.Sum256([]byte(name))
	return filepath.Join(d.root, dataName, hex.EncodeToString(sum[:]))
}

func (d *Dir) closedErr() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return deniedMsg(nil, "backend closed")
	}
	return nil
}

// Read returns the committed bytes and the revision of the same record. It
// takes the shared lock so the pair is read atomically with respect to
// writers, including writers in other processes.
func (d *Dir) Read(ctx context.Context, name string) (ReadResult, error) {
	if err := ctx.Err(); err != nil {
		return ReadResult{}, deniedMsg(err, "read")
	}
	if !ValidName(name) {
		return ReadResult{}, deniedMsg(nil, "invalid name")
	}
	if err := d.closedErr(); err != nil {
		return ReadResult{}, err
	}
	if _, err := d.dir(); err != nil {
		return ReadResult{}, err
	}
	_, release, err := d.lockHandle(ctx)
	if err != nil {
		return ReadResult{}, err
	}
	defer release()
	if err := ctx.Err(); err != nil {
		return ReadResult{}, deniedMsg(err, "read")
	}
	rec, err := readRecord(d.dataPath(name))
	if errors.Is(err, os.ErrNotExist) {
		return ReadResult{}, ErrNotFound
	}
	if err != nil {
		return ReadResult{}, err
	}
	if err := ctx.Err(); err != nil {
		return ReadResult{}, deniedMsg(err, "read")
	}
	return ReadResult{Bytes: rec.value, Revision: Revision(rec.version)}, nil
}

// CreateIfAbsent commits value when name has no committed version. An existing
// name, valid or corrupt, is ErrConflict. Publication is link(2), so even a
// process that does not use this driver cannot have its file overwritten.
func (d *Dir) CreateIfAbsent(ctx context.Context, name string, value []byte) error {
	return d.write(ctx, name, Revision(""), value, true)
}

// ReplaceIfVersion commits value when the current revision is expected. A
// missing name and any different revision are ErrConflict; a zero or oversize
// expected revision is malformed and ErrDenied. Publication is rename(2) over
// the data file while the shared lock is held, after re-reading the record
// under that lock and comparing its version verbatim.
func (d *Dir) ReplaceIfVersion(ctx context.Context, name string, expected Revision, value []byte) error {
	if err := ctx.Err(); err != nil {
		return deniedMsg(err, "replace")
	}
	if !validExpectedRevision(expected) {
		return deniedMsg(nil, "replace requires a non-zero, bounded expected revision")
	}
	return d.write(ctx, name, expected, value, false)
}

// List is not supported, and neither is history. Like every method it is
// refused with ErrDenied once the backend is closed.
func (d *Dir) List(context.Context) ([]string, error) {
	if err := d.closedErr(); err != nil {
		return nil, err
	}
	return nil, ErrUnsupported
}

// Close refuses later calls. Data and the lock file stay in place.
func (d *Dir) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closed = true
	return nil
}

// lockDeadline returns the single deadline shared by the in-process and the
// OS lock wait of one operation.
func (d *Dir) lockDeadline() time.Time {
	if d.timeout <= 0 {
		return time.Time{}
	}
	return time.Now().Add(d.timeout)
}

// lockHandle takes the in-process lock and then the OS lock on the shared lock
// inode. Both waits share one deadline: when it passes before the OS lock is
// granted nothing has been written and the caller reports ErrConflict, while
// cancellation reports ErrDenied. The returned handle stays valid while the
// lock is held, so ticket I/O always touches the exact inode that is locked.
// The returned function releases both.
func (d *Dir) lockHandle(ctx context.Context) (*os.File, func(), error) {
	deadline := d.lockDeadline()
	if err := d.inProc.acquire(ctx, deadline); err != nil {
		return nil, nil, lockWaitError(err)
	}
	f, err := d.lockHandleOS(ctx, deadline)
	if err != nil {
		d.inProc.release()
		return nil, nil, err
	}
	return f, func() {
		_ = unlock(f)
		_ = f.Close()
		d.inProc.release()
	}, nil
}

// lockHandleOS opens the existing lock file, checks that it is still the inode
// OpenDir captured, and only then takes the OS lock on that descriptor. It
// never creates the lock file: a lock removed after OpenDir is refused with
// ErrDenied rather than silently recreated, and no descriptor for a different
// inode is ever locked. The check and the later use do not share a path lookup,
// so a same-UID process replacing the path between them is not defended against
// (see the package threat model); the lock handle itself still refers to the
// inode that passed the check.
func (d *Dir) lockHandleOS(ctx context.Context, deadline time.Time) (*os.File, error) {
	f, err := openExistingLockFile(d.lock)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, deniedMsg(err, "lock file")
	}
	if !sameIdentity(d.lockID, st) {
		_ = f.Close()
		return nil, deniedMsg(nil, "lock file is not the inode opened")
	}
	if err := pollLock(ctx, f, deadline); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

// pollLock takes the OS lock on f, waiting until deadline.
func pollLock(ctx context.Context, f *os.File, deadline time.Time) error {
	for {
		if err := ctx.Err(); err != nil {
			return deniedMsg(err, "lock")
		}
		ok, err := tryLock(f)
		if err != nil {
			return deniedMsg(err, "lock")
		}
		if ok {
			return nil
		}
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			return lockWaitError(errLockTimeout)
		}
		wait := lockPoll
		if !deadline.IsZero() {
			if left := time.Until(deadline); left < wait {
				wait = left
			}
		}
		if err := sleep(ctx, wait); err != nil {
			return deniedMsg(err, "lock")
		}
	}
}

// lockWaitError classifies a failed lock wait. Nothing has been written, so a
// cancellation is ErrDenied (the context error stays discoverable) and an
// exhausted deadline is a definite ErrConflict, never ErrUnknown.
func lockWaitError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return deniedMsg(err, "lock")
	}
	return fmt.Errorf("%w: lock is held by another writer", ErrConflict)
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// ownerTicket is the owner record stored in the lock file while a writer holds
// the lock. The token is the operation id of the write.
type ownerTicket struct {
	kind  string
	token string
}

// readTicket parses the owner ticket. An empty file has no ticket.
func readTicket(f *os.File) (ownerTicket, error) {
	raw, err := readLockFile(f, ticketMaxLen+1)
	if err != nil {
		return ownerTicket{}, deniedMsg(err, "read lock ticket")
	}
	if len(raw) == 0 {
		return ownerTicket{kind: ticketFree}, nil
	}
	if len(raw) > ticketMaxLen || raw[len(raw)-1] != '\n' {
		return ownerTicket{}, deniedMsg(nil, "lock ticket is corrupt")
	}
	body := strings.TrimSuffix(string(raw), "\n")
	if body == ticketFree {
		return ownerTicket{kind: ticketFree}, nil
	}
	parts := strings.Split(body, " ")
	if len(parts) != 2 || parts[0] != ticketHolder || len(parts[1]) != 32 || !hexClean(parts[1]) {
		return ownerTicket{}, deniedMsg(nil, "lock ticket is corrupt")
	}
	return ownerTicket{kind: ticketHolder, token: parts[1]}, nil
}

func isTicketKind(k string) bool {
	switch k {
	case ticketHolder, ticketFree:
		return true
	}
	return false
}

func hexClean(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func encodeTicket(t ownerTicket) []byte {
	if t.kind == ticketFree {
		return nil
	}
	return []byte(t.kind + " " + t.token + "\n")
}

func writeTicket(f *os.File, t ownerTicket) error {
	if f == nil {
		return deniedMsg(nil, "lock file changed")
	}
	if err := writeLockFile(f, encodeTicket(t)); err != nil {
		return deniedMsg(err, "write lock ticket")
	}
	if err := f.Sync(); err != nil {
		return deniedMsg(err, "sync lock ticket")
	}
	return nil
}

func newOpID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// newVersion mints a random version identifier for one commit.
func newVersion() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// record is one committed version as stored on disk: the random version, the
// SHA-256 digest of the value, and the value itself.
type record struct {
	version string
	digest  [sha256.Size]byte
	value   []byte
}

func (r record) revision() Revision { return Revision(r.version) }

// encode renders the on-disk record.
func (r record) encode() []byte {
	out := make([]byte, 0, len(recordMagic)+4+len(r.version)+4+sha256.Size+len(r.value))
	out = append(out, recordMagic...)
	out = append(out, byte(len(r.version)), byte(len(r.version)>>8), byte(len(r.version)>>16), byte(len(r.version)>>24))
	out = append(out, r.version...)
	out = append(out, byte(sha256.Size), 0, 0, 0)
	out = append(out, r.digest[:]...)
	out = append(out, r.value...)
	return out
}

// decodeRecord parses and authenticates an on-disk record. Any framing error,
// zero or oversize revision, or digest mismatch is ErrCorrupt.
func decodeRecord(raw []byte) (record, error) {
	corrupt := func(why string) (record, error) {
		return record{}, fmt.Errorf("%w: %s", ErrCorrupt, why)
	}
	if len(raw) < len(recordMagic)+4 || string(raw[:len(recordMagic)]) != recordMagic {
		return corrupt("missing or foreign record header")
	}
	p := len(recordMagic)
	vlen := int(raw[p]) | int(raw[p+1])<<8 | int(raw[p+2])<<16 | int(raw[p+3])<<24
	p += 4
	if vlen == 0 || vlen > recordVersionMax || vlen > MaxRevisionSize || p+vlen+4 > len(raw) {
		return corrupt("invalid stored revision")
	}
	version := string(raw[p : p+vlen])
	p += vlen
	dlen := int(raw[p]) | int(raw[p+1])<<8 | int(raw[p+2])<<16 | int(raw[p+3])<<24
	p += 4
	if dlen != sha256.Size || p+dlen > len(raw) {
		return corrupt("invalid stored digest")
	}
	var rec record
	rec.version = version
	copy(rec.digest[:], raw[p:p+dlen])
	p += dlen
	if len(raw)-p <= 0 || len(raw)-p > MaxValueSize {
		return corrupt("stored value has an invalid size")
	}
	rec.value = append([]byte(nil), raw[p:]...)
	if sha256.Sum256(rec.value) != rec.digest {
		return corrupt("stored value does not match its digest")
	}
	return rec, nil
}

// readRecord reads and authenticates one committed record. The file must be a
// private regular file; the size cap is enforced before and after reading.
func readRecord(path string) (record, error) {
	f, err := openPrivateFile(path)
	if err != nil {
		return record{}, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return record{}, deniedMsg(err, "stat data file")
	}
	if st.Size() <= 0 || st.Size() > int64(MaxValueSize+recordHeaderMax) {
		return record{}, fmt.Errorf("%w: stored record has an invalid size", ErrCorrupt)
	}
	raw, err := io.ReadAll(io.LimitReader(f, int64(MaxValueSize+recordHeaderMax+1)))
	if err != nil {
		return record{}, fmt.Errorf("%w: read stored record: %w", ErrCorrupt, err)
	}
	if int64(len(raw)) != st.Size() {
		return record{}, fmt.Errorf("%w: stored record changed while reading", ErrCorrupt)
	}
	return decodeRecord(raw)
}

func removeQuiet(path string) { _ = os.Remove(path) }
