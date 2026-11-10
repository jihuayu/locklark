package vaultfilebackend

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// resolve runs under the OS lock and handles the owner ticket a previous
// writer left behind.
//
// Kernel record locks are released when a process exits or is killed, so a
// ticket still present after this writer obtained the lock belongs to a
// process that is gone (a live holder blocks in the kernel). Its operation id
// names its temporary file "op-<id>" in the tmp directory; publication is a
// rename of that file, which keeps the name until the rename. The crashed
// writer can no longer rename that file (it is gone), so the ticket is cleared
// and the leftover temporary file is removed. A writer stopped by SIGSTOP and
// later resumed can only publish its own file after taking the lock again, by
// which time this writer has cleared the ticket and moved on under the lock it
// still holds.
func (d *Dir) resolve(f *os.File) error {
	cur, err := readTicket(f)
	if err != nil {
		return err
	}
	if cur.kind == ticketFree {
		// A free ticket means no cooperating writer is staging: resolve runs
		// under the OS lock this process just took. A staged file present now
		// was left by a writer that died after creating and syncing it but
		// before recording its holder ticket, so it is an orphan and is swept
		// exactly like the untracked files left after a recovered ticket.
		return d.sweepTmp()
	}
	tmp := d.tmpPath(cur.token)
	removeQuiet(tmp)
	if _, err := os.Lstat(tmp); err == nil {
		return fmt.Errorf("%w: an interrupted writer still owns a temporary file", ErrUnknown)
	} else if !errors.Is(err, os.ErrNotExist) {
		return deniedMsg(err, "inspect interrupted writer temporary file")
	}
	if err := writeTicket(f, ownerTicket{kind: ticketFree}); err != nil {
		return err
	}
	return d.sweepTmp()
}

// sweepTmp removes staged temporary files that no ticket names. It runs under
// the shared lock, so no cooperating writer can be staging: every "op-" file
// present here was left by a writer that died between creating its temporary
// file and recording its ticket, and its bytes were never published.
func (d *Dir) sweepTmp() error {
	dir := filepath.Join(d.root, tmpName)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return deniedMsg(err, "scan temporary files")
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "op-") || len(name) != 3+32 || !hexClean(name[3:]) {
			return deniedMsg(nil, "unexpected entry in the temporary directory")
		}
		if err := os.Remove(filepath.Join(dir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return deniedMsg(err, "remove orphan temporary file")
		}
	}
	return nil
}

// lockInterrupt is a test-only interruption point that runs while the caller
// holds the OS lock, immediately before publication. It lets a test interrupt
// a writer exactly between staging and publication. Production builds leave
// it nil.
var lockInterrupt func(ctx context.Context, op writeOp) error

func interrupt(ctx context.Context, op writeOp) error {
	if lockInterrupt == nil {
		return nil
	}
	return lockInterrupt(ctx, op)
}

// commitHook is a test-only interruption point that runs after staging and
// instead of the publication step. Production builds leave it nil.
var commitHook func(d *Dir, op writeOp) error

func runCommitHook(d *Dir, op writeOp) (error, bool) {
	if commitHook == nil {
		return nil, false
	}
	return commitHook(d, op), true
}

func (d *Dir) tmpPath(opID string) string {
	return filepath.Join(d.root, tmpName, "op-"+opID)
}
