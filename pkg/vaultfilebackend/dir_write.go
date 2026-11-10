package vaultfilebackend

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// writeOp is one mutation, fully configured before the write starts. The
// expected revision is empty for CreateIfAbsent.
type writeOp struct {
	name     string
	create   bool
	expected Revision
	value    []byte

	tmp    string
	tmpID  string
	digest [sha256.Size]byte
}

func (o *writeOp) final(d *Dir) string { return d.dataPath(o.name) }

// write is the single mutation path. It holds the shared lock across the
// version read, the revision comparison, temporary-file creation and fsync,
// publication and directory sync, so concurrent processes and goroutines
// serialize on the same inode.
//
// Failure classification: a lock wait that exceeds the deadline, a missing
// name, or a different committed revision fails with ErrConflict before
// anything is written; an interrupted or cancelled wait, like every other
// failure or cancellation before publication starts, is ErrDenied and leaves
// the stored version untouched; once publication starts, a failure of unknown
// or unconfirmed effect is ErrUnknown and callers resolve it with Read.
func (d *Dir) write(ctx context.Context, name string, expected Revision, value []byte, create bool) error {
	if err := ctx.Err(); err != nil {
		return deniedMsg(err, "write")
	}
	if !create && !validExpectedRevision(expected) {
		return deniedMsg(nil, "malformed expected revision")
	}
	if !ValidName(name) || !validValue(value) {
		return deniedMsg(nil, "invalid name or value")
	}
	if err := d.closedErr(); err != nil {
		return err
	}
	if _, err := d.dir(); err != nil {
		return err
	}
	op := writeOp{name: name, create: create, expected: expected, value: value, digest: sha256.Sum256(value)}
	return d.run(ctx, &op)
}

func (d *Dir) run(ctx context.Context, op *writeOp) error {
	lockFile, release, err := d.lockHandle(ctx)
	if err != nil {
		return err
	}
	defer release()

	// Recover the ticket of a writer that died while it held the lock.
	if err := d.resolve(lockFile); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return deniedMsg(err, "write cancelled before comparison")
	}
	if err := d.classify(op); err != nil {
		return err
	}
	// Stage the complete temporary file, then take the holder ticket naming
	// it: a crash after the ticket exists leaves a ticket whose temporary
	// file this writer never published; the next writer removes it.
	tmp, err := d.stage(ctx, op, lockFile)
	if err != nil {
		return err
	}
	discard := func() {
		removeQuiet(tmp)
		_ = writeTicket(lockFile, ownerTicket{kind: ticketFree})
	}
	if err := interrupt(ctx, *op); err != nil {
		discard()
		return deniedMsg(err, "interrupted before publication")
	}
	if err := ctx.Err(); err != nil {
		discard()
		return deniedMsg(err, "cancelled before publication")
	}
	err = publish(d, op, tmp)
	if err != nil {
		discard()
		return err
	}
	_ = writeTicket(lockFile, ownerTicket{kind: ticketFree})
	return nil
}

// classify re-reads the committed record under the lock and compares its
// version verbatim. A mismatching, missing or (for create) existing name fails
// with ErrConflict and writes nothing. A record that exists but cannot be
// trusted is reported as ErrCorrupt, or as ErrDenied when it is not a private
// regular file.
func (d *Dir) classify(op *writeOp) error {
	final := op.final(d)
	if op.create {
		st, err := os.Lstat(final)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return deniedMsg(err, "inspect data file")
		}
		if !st.Mode().IsRegular() || st.Mode()&os.ModeSymlink != 0 || !privateFile(st) {
			return deniedMsg(nil, "data path is not a private regular file")
		}
		return fmt.Errorf("%w: name already has a committed version", ErrConflict)
	}
	rec, err := readRecord(final)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%w: no committed version", ErrConflict)
	}
	if err != nil {
		return err
	}
	if rec.revision() != op.expected {
		return fmt.Errorf("%w: committed revision differs", ErrConflict)
	}
	return nil
}

// stage writes the complete record to a new private temporary file, fsyncs it,
// records the holder ticket and fsyncs the lock file before returning. It
// refuses to run when ctx is already done and never publishes by itself.
func (d *Dir) stage(ctx context.Context, op *writeOp, lockFile *os.File) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", deniedMsg(err, "write cancelled before staging")
	}
	version, err := newVersion()
	if err != nil {
		return "", deniedMsg(err, "version")
	}
	id, err := newOpID()
	if err != nil {
		return "", deniedMsg(err, "temporary name")
	}
	op.tmpID = id
	tmp := d.tmpPath(id)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", deniedMsg(err, "create temporary file")
	}
	if err := f.Chmod(0600); err != nil {
		_ = f.Close()
		removeQuiet(tmp)
		return "", deniedMsg(err, "make temporary file private")
	}
	op.tmp = tmp
	fail := func(e error) (string, error) {
		_ = f.Close()
		removeQuiet(tmp)
		return "", deniedMsg(e, "write temporary file")
	}
	rec := record{version: version, digest: op.digest, value: op.value}
	if _, err := f.Write(rec.encode()); err != nil {
		return fail(err)
	}
	if err := f.Sync(); err != nil {
		return fail(err)
	}
	if err := f.Close(); err != nil {
		removeQuiet(tmp)
		return "", deniedMsg(err, "close temporary file")
	}
	// A writer whose cancellation arrived while staging never publishes.
	if err := ctx.Err(); err != nil {
		removeQuiet(tmp)
		return "", deniedMsg(err, "write cancelled while staging")
	}
	if err := writeTicket(lockFile, ownerTicket{kind: ticketHolder, token: id}); err != nil {
		removeQuiet(tmp)
		return "", err
	}
	return tmp, nil
}

// publish makes tmp visible atomically: link(2) for create and an exchange
// rename for replace (both fail if a competing writer removed or created the
// name meanwhile), followed by fsync of the data directory and a check that
// the visible record is this write's. A successful link is create's commit
// point, so create never reports ErrUnknown after it; a replace failure once
// the rename started may or may not have committed and is ErrUnknown.
func publish(d *Dir, op *writeOp, tmp string) error {
	if hookErr, hooked := runCommitHook(d, *op); hooked {
		return hookErr
	}
	final := op.final(d)
	dir, err := os.Open(filepath.Join(d.root, dataName))
	if err != nil {
		return deniedMsg(err, "open data directory")
	}
	defer dir.Close()
	if op.create {
		if err := linkNoReplace(tmp, final); err != nil {
			if errors.Is(err, os.ErrExist) {
				return fmt.Errorf("%w: name already has a committed version", ErrConflict)
			}
			return fmt.Errorf("%w: publish create: %w", ErrUnknown, err)
		}
		removeQuiet(tmp)
		// A successful link is the commit point for create: the value is
		// visible now and CreateIfAbsent never reports ErrUnknown after it.
		// The directory sync is best-effort durability only.
		_ = dir.Sync()
		return nil
	}
	if err := renameNoReplace(tmp, final); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// The compared version vanished before publication; nothing was
			// published, so this is a definite conflict, not an unknown.
			return fmt.Errorf("%w: no committed version at publication", ErrConflict)
		}
		return fmt.Errorf("%w: publish replace: %w", ErrUnknown, err)
	}
	// The exchange moved the previous record to the temporary path.
	removeQuiet(tmp)
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("%w: directory sync failed after publication", ErrUnknown)
	}
	if err := d.verifyReplaced(op); err != nil {
		return err
	}
	return nil
}

// verifyReplaced re-reads the record after a replace publication and confirms
// it carries this write's digest.
func (d *Dir) verifyReplaced(op *writeOp) error {
	if op.create {
		return nil
	}
	rec, err := readRecord(op.final(d))
	if err != nil {
		return fmt.Errorf("%w: replaced record unreadable: %w", ErrUnknown, err)
	}
	if rec.digest != op.digest {
		return fmt.Errorf("%w: replaced record was overwritten by a competing writer", ErrUnknown)
	}
	return nil
}
