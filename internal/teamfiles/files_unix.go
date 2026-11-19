//go:build unix

package teamfiles

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

func chain(path string, file, private bool) error {
	first := file
	for current := path; ; current = filepath.Dir(current) {
		st, err := os.Lstat(current)
		if err != nil {
			return ErrFile
		}
		owner, ok := st.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != uint32(os.Geteuid()) && owner.Uid != 0 {
			return ErrFile
		}
		if first {
			mask := os.FileMode(0022)
			if private {
				mask = 0077
			}
			if !st.Mode().IsRegular() || owner.Nlink != 1 || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&mask != 0 {
				return ErrFile
			}
		} else if st.Mode()&os.ModeSymlink == 0 {
			if !st.IsDir() || st.Mode().Perm()&0022 != 0 && !(owner.Uid == 0 && st.Mode()&os.ModeSticky != 0) {
				return ErrFile
			}
		}
		first = false
		if filepath.Dir(current) == current {
			return nil
		}
	}
}
func trustedParent(path string) error {
	if chain(path, false, true) != nil {
		return ErrFile
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return ErrFile
	}
	return chain(resolved, false, true)
}
func trustedFile(path string, private bool) error {
	if chain(path, true, private) != nil {
		return ErrFile
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return ErrFile
	}
	return chain(resolved, true, private)
}
func createLocalFile(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, err
	}
	owned, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, ErrFile
	}
	// The process umask may strip the owner's read bit from the newly
	// created inode. Correct only this O_EXCL-owned descriptor before any
	// bytes are published, then verify the exact mode on that descriptor.
	if err := f.Chmod(0600); err != nil {
		f.Close()
		if current, statErr := os.Lstat(path); statErr == nil && os.SameFile(owned, current) {
			os.Remove(path)
		}
		return nil, ErrFile
	}
	current, err := f.Stat()
	if err != nil || !os.SameFile(owned, current) || !current.Mode().IsRegular() || current.Mode().Perm() != 0600 {
		f.Close()
		if atPath, statErr := os.Lstat(path); statErr == nil && os.SameFile(owned, atPath) {
			os.Remove(path)
		}
		return nil, ErrFile
	}
	return f, nil
}
func equalPath(a, b string) bool    { return a == b }
func validPlatformPath(string) bool { return true }

// localParent holds one accepted parent directory for the whole operation.
// Root operations are relative to this handle, so a later rename or
// replacement of the caller's parent path cannot redirect staging, publishing
// or cleanup. bindingValid separately proves the caller's path still names the
// held inode around irreversible publication.
type localParent struct {
	root *os.Root
	path string
	held os.FileInfo
}

func openLocalParent(path string, afterCapture func() error) (*localParent, error) {
	// Capture the exact target identity before any path validation or open.
	// Every later step is compared with this identity, so a substitution that
	// happens during validation cannot become the opened parent.
	before, err := os.Stat(path)
	if err != nil || !before.IsDir() {
		return nil, ErrFile
	}
	if trustedParent(path) != nil {
		return nil, ErrFile
	}
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, ErrFile
	}
	canonical = filepath.Clean(canonical)
	if trustedParent(canonical) != nil {
		return nil, ErrFile
	}
	canonicalInfo, err := os.Lstat(canonical)
	if err != nil || canonicalInfo.Mode()&os.ModeSymlink != 0 ||
		!canonicalInfo.IsDir() || !os.SameFile(before, canonicalInfo) {
		return nil, ErrFile
	}
	if afterCapture != nil {
		if err := afterCapture(); err != nil {
			return nil, ErrFile
		}
	}
	root, err := os.OpenRoot(canonical)
	if err != nil {
		return nil, ErrFile
	}
	held, err := root.Stat(".")
	if err != nil || !held.IsDir() || !os.SameFile(before, held) {
		root.Close()
		return nil, ErrFile
	}
	parent := &localParent{root: root, path: path, held: held}
	if err := parent.bindingValid(); err != nil {
		root.Close()
		return nil, ErrFile
	}
	return parent, nil
}

func (p *localParent) Close() error {
	if p == nil || p.root == nil {
		return nil
	}
	return p.root.Close()
}

func (p *localParent) bindingValid() error {
	if p == nil || p.root == nil || p.held == nil || trustedParent(p.path) != nil {
		return ErrFile
	}
	current, err := os.Stat(p.path)
	if err != nil || !current.IsDir() || !os.SameFile(p.held, current) {
		return ErrFile
	}
	heldNow, err := p.root.Stat(".")
	if err != nil || !os.SameFile(p.held, heldNow) {
		return ErrFile
	}
	return nil
}

func (p *localParent) createStaging(name string) (*os.File, error) {
	f, err := p.root.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, ErrFile
	}
	owned, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, ErrFile
	}
	if err := f.Chmod(0600); err != nil {
		f.Close()
		p.discardOwned(name, owned)
		return nil, ErrFile
	}
	current, err := f.Stat()
	if err != nil || ownedFileInfo(current, true, 1) != nil {
		f.Close()
		p.discardOwned(name, owned)
		return nil, ErrFile
	}
	return f, nil
}

func (p *localParent) discardOwned(name string, owned os.FileInfo) {
	current, err := p.root.Lstat(name)
	if err == nil && current.Mode().IsRegular() && os.SameFile(owned, current) {
		_ = p.root.Remove(name)
	}
}

func (p *localParent) openRead(name string) (*os.File, error) {
	f, err := p.root.OpenFile(name, os.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, ErrFile
	}
	return f, nil
}

func (p *localParent) verifyFile(name string, owned os.FileInfo, private bool, wantLinks uint64) error {
	current, err := p.root.Lstat(name)
	if err != nil || !os.SameFile(owned, current) {
		return ErrFile
	}
	return ownedFileInfo(current, private, wantLinks)
}

func (p *localParent) removeOwned(name string, owned os.FileInfo, wantLinks uint64) error {
	current, err := p.root.Lstat(name)
	if err != nil || !os.SameFile(owned, current) {
		return ErrFile
	}
	if err := ownedFileInfo(current, true, wantLinks); err != nil {
		return err
	}
	return p.root.Remove(name)
}

func (p *localParent) sync() error {
	f, err := p.root.Open(".")
	if err != nil {
		return err
	}
	syncErr := f.Sync()
	if closeErr := f.Close(); syncErr == nil {
		syncErr = closeErr
	}
	return syncErr
}

func ownedFileInfo(info os.FileInfo, private bool, wantLinks uint64) error {
	if info == nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return ErrFile
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || (stat.Uid != uint32(os.Geteuid()) && stat.Uid != 0) ||
		uint64(stat.Nlink) != wantLinks {
		return ErrFile
	}
	mask := os.FileMode(0022)
	if private {
		mask = 0077
	}
	if info.Mode().Perm()&mask != 0 {
		return ErrFile
	}
	return nil
}

func writeNewAtPath(ctx context.Context, path string, raw []byte, staging string,
	hooks localWriteHooks) (retErr error) {
	parent, err := openLocalParent(filepath.Dir(path), nil)
	if err != nil {
		return ErrFile
	}
	defer parent.Close()
	name := filepath.Base(path)
	if name == "." || name == string(filepath.Separator) {
		return ErrFile
	}
	if _, err := parent.root.Lstat(name); !os.IsNotExist(err) {
		return ErrFile
	}
	f, err := parent.createStaging(staging)
	if err != nil {
		return ErrFile
	}
	owned, err := f.Stat()
	if err != nil {
		f.Close()
		return ErrFile
	}
	finalLinked := false
	stagingRemoved := false
	defer func() {
		if stagingRemoved {
			return
		}
		wantLinks := uint64(1)
		if finalLinked {
			wantLinks = 2
		}
		_ = parent.removeOwned(staging, owned, wantLinks)
	}()
	n, writeErr := f.Write(raw)
	syncErr := f.Sync()
	closeErr := f.Close()
	if writeErr != nil || n != len(raw) || syncErr != nil || closeErr != nil {
		return ErrFile
	}
	if err := parent.verifyFile(staging, owned, true, 1); err != nil {
		return ErrFile
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if hooks.beforeLink != nil {
		if err := hooks.beforeLink(); err != nil {
			return ErrFile
		}
	}
	// Re-prove the caller's parent binding after the seam and immediately
	// before the irreversible new link.
	if err := parent.bindingValid(); err != nil {
		return ErrFile
	}
	if final, statErr := parent.root.Lstat(name); statErr == nil {
		if os.SameFile(owned, final) {
			// The owned inode is already visible at the final name, possibly
			// through an external link. Never remove it and never claim a
			// definite failure.
			finalLinked = true
			if cleanupOwnedStage(parent, staging, name, owned) == nil {
				stagingRemoved = true
			}
			return ErrPublicationUnknown
		}
		return ErrFile
	} else if !os.IsNotExist(statErr) {
		return ErrFile
	}
	// This seam sits after the last binding and destination checks so a test
	// can cancel at the actual pre-link boundary.
	if hooks.beforeCommit != nil {
		if err := hooks.beforeCommit(); err != nil {
			return ErrFile
		}
	}
	// A cancellation observed after the last binding and destination checks
	// must refuse the irreversible link before it is issued. The deferred
	// cleanup removes only the owned staged name; no final binding appears.
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := parent.root.Link(staging, name); err != nil {
		final, statErr := parent.root.Lstat(name)
		if statErr == nil && os.SameFile(owned, final) {
			finalLinked = true
			if cleanupOwnedStage(parent, staging, name, owned) == nil {
				stagingRemoved = true
			}
			return ErrPublicationUnknown
		}
		if statErr == nil {
			// A different inode is definitely visible at the final name. That is
			// an ordinary no-replace refusal, not an uncertain publication.
			return ErrFile
		}
		if os.IsNotExist(statErr) {
			// The final name is verified absent, so the failed link did not
			// publish the owned staging inode.
			return ErrFile
		}
		// The final-name probe itself failed (for example an access or I/O
		// error). Without a verified absent or different final name, the failed
		// link cannot be distinguished from one that made the owned inode
		// visible. Do not authorize an overwrite or recovery retry; the deferred
		// cleanup can remove only a still-one-link owned staging name, never an
		// unverified final name.
		return ErrPublicationUnknown
	}
	finalLinked = true
	// Prove the final link is the owned inode and that no external link has
	// appeared before touching the staged name. An extra link is never
	// accepted or used to salvage an uncertain state.
	if err := parent.verifyFile(name, owned, true, 2); err != nil {
		return ErrPublicationUnknown
	}
	// Any later failure still tries to remove only the owned staged name. The
	// final name is never removed, replaced or reissued.
	if hooks.afterLink != nil {
		if err := hooks.afterLink(); err != nil {
			abortAfterFinalLink(parent, staging, name, owned)
			return ErrPublicationUnknown
		}
	}
	if err := parent.bindingValid(); err != nil {
		abortAfterFinalLink(parent, staging, name, owned)
		return ErrPublicationUnknown
	}
	if err := parent.verifyFile(name, owned, true, 2); err != nil {
		return ErrPublicationUnknown
	}
	if hooks.afterPublish != nil {
		if err := hooks.afterPublish(); err != nil {
			abortAfterFinalLink(parent, staging, name, owned)
			return ErrPublicationUnknown
		}
	}
	if ctx.Err() != nil {
		abortAfterFinalLink(parent, staging, name, owned)
		return ErrPublicationUnknown
	}
	if err := parent.removeOwned(staging, owned, 2); err != nil {
		return ErrPublicationUnknown
	}
	stagingRemoved = true
	if hooks.afterUnlink != nil {
		if err := hooks.afterUnlink(); err != nil {
			return ErrPublicationUnknown
		}
	}
	if ctx.Err() != nil {
		return ErrPublicationUnknown
	}
	if hooks.beforeFinalSync != nil {
		if err := hooks.beforeFinalSync(); err != nil {
			return ErrPublicationUnknown
		}
	}
	// One durability barrier covers the final link and the owned-stage unlink.
	// The staged file data was synced before the link, so an intermediate
	// parent sync is both unnecessary and harmful: a failure here no longer
	// strands a second link on the final inode.
	if err := parent.sync(); err != nil {
		return ErrPublicationUnknown
	}
	if ctx.Err() != nil {
		return ErrPublicationUnknown
	}
	if hooks.afterFinalSync != nil {
		if err := hooks.afterFinalSync(); err != nil {
			return ErrPublicationUnknown
		}
	}
	if ctx.Err() != nil {
		return ErrPublicationUnknown
	}
	if err := parent.bindingValid(); err != nil {
		return ErrPublicationUnknown
	}
	if _, err := parent.root.Lstat(staging); !os.IsNotExist(err) {
		return ErrPublicationUnknown
	}
	if err := parent.verifyFile(name, owned, true, 1); err != nil {
		return ErrPublicationUnknown
	}
	return nil
}

// cleanupOwnedStage removes the staged name only when the final name still
// proves to be the same owned inode. The caller never removes or replaces the
// final name, and removeOwned refuses any link count other than two.
func cleanupOwnedStage(parent *localParent, staging, name string, owned os.FileInfo) error {
	final, err := parent.root.Lstat(name)
	if err != nil || !os.SameFile(owned, final) {
		return ErrFile
	}
	staged, err := parent.root.Lstat(staging)
	if os.IsNotExist(err) {
		return parent.verifyFile(name, owned, true, 1)
	}
	if err != nil || !os.SameFile(owned, staged) {
		return ErrFile
	}
	return parent.removeOwned(staging, owned, 2)
}

// abortAfterFinalLink makes a best effort to leave a one-link final file after
// a post-visibility failure. A cleanup or sync failure still returns an
// uncertain state; the caller reports ErrPublicationUnknown either way.
func abortAfterFinalLink(parent *localParent, staging, name string, owned os.FileInfo) {
	if done := cleanupOwnedStage(parent, staging, name, owned); done == nil {
		_ = parent.sync()
	}
}

func readBoundedAtPath(ctx context.Context, path string, limit int64, private bool,
	hooks localReadHooks) ([]byte, error) {
	parent, err := openLocalParent(filepath.Dir(path), hooks.afterCapture)
	if err != nil {
		return nil, ErrFile
	}
	defer parent.Close()
	name := filepath.Base(path)
	if name == "." || name == string(filepath.Separator) {
		return nil, ErrFile
	}
	f, err := parent.openRead(name)
	if err != nil {
		return nil, ErrFile
	}
	owned, err := f.Stat()
	if err != nil || ownedFileInfo(owned, private, 1) != nil {
		f.Close()
		return nil, ErrFile
	}
	if err := parent.verifyFile(name, owned, private, 1); err != nil {
		f.Close()
		return nil, ErrFile
	}
	raw, readErr := io.ReadAll(io.LimitReader(f, limit+1))
	closeErr := f.Close()
	if readErr != nil || closeErr != nil || int64(len(raw)) > limit {
		clear(raw)
		return nil, ErrFile
	}
	if hooks.afterOpen != nil {
		if err := hooks.afterOpen(); err != nil {
			clear(raw)
			return nil, ErrFile
		}
	}
	if ctx.Err() != nil {
		clear(raw)
		return nil, ctx.Err()
	}
	// The bytes came from the pinned inode. Do not return them under the old
	// caller path unless that parent is still bound and the final name still
	// resolves to the same one-link inode.
	if err := parent.bindingValid(); err != nil {
		clear(raw)
		return nil, ErrFile
	}
	if err := parent.verifyFile(name, owned, private, 1); err != nil {
		clear(raw)
		return nil, ErrFile
	}
	named, err := os.Lstat(path)
	if err != nil || !named.Mode().IsRegular() || !os.SameFile(owned, named) {
		clear(raw)
		return nil, ErrFile
	}
	return raw, nil
}
