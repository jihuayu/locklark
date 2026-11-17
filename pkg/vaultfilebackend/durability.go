package vaultfilebackend

import (
	"context"
	"errors"
	"fmt"
	"os"
)

// ErrDurabilityUnproven distinguishes a publication whose directory entry was
// observed from one whose parent-directory durability barrier succeeded.
var ErrDurabilityUnproven = errors.New("vault file backend: publication durability unproven")

// DurabilityProver is the optional backend capability used only after a
// readback matches a prepared proposal. It must not publish, overwrite, or
// change the expected revision.
type DurabilityProver interface {
	ProveDurable(ctx context.Context, name string, expected Revision) error
}

func durabilityUnproven(cause error) error {
	return fmt.Errorf("%w: %w: %v", ErrUnknown, ErrDurabilityUnproven, cause)
}

// ProveDurable re-reads the exact committed revision under the normal backend
// lock and fsyncs the same data directory used by publication. Any mismatch or
// sync failure remains unknown; it never reports a confirmed commit.
func (d *Dir) ProveDurable(ctx context.Context, name string, expected Revision) error {
	if err := ctx.Err(); err != nil {
		return deniedMsg(err, "prove durable")
	}
	if !ValidName(name) {
		return deniedMsg(nil, "prove durable requires a valid name")
	}
	if expected.Zero() {
		return deniedMsg(nil, "prove durable requires a revision")
	}
	if err := d.closedErr(); err != nil {
		return err
	}
	dataDir, err := d.dir()
	if err != nil {
		return err
	}
	_, release, err := d.lockHandle(ctx)
	if err != nil {
		return err
	}
	defer release()
	if err := ctx.Err(); err != nil {
		return deniedMsg(err, "prove durable")
	}
	rec, err := readRecord(d.dataPath(name))
	if err != nil {
		return durabilityUnproven(err)
	}
	if rec.revision() != expected {
		return durabilityUnproven(fmt.Errorf("%w: revision changed", ErrConflict))
	}
	dir, err := os.Open(dataDir)
	if err != nil {
		return durabilityUnproven(err)
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return durabilityUnproven(err)
	}
	if err := ctx.Err(); err != nil {
		return deniedMsg(err, "prove durable")
	}
	return nil
}
