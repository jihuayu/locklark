//go:build darwin || linux

package vaultfilebackend

import (
	"context"
	"errors"
	"testing"
)

func TestDirProveDurableExactRevisionAndStale(t *testing.T) {
	ctx := context.Background()
	dir := openAt(t, t.TempDir()).(*Dir)
	if err := dir.CreateIfAbsent(ctx, "durable", []byte("v1")); err != nil {
		t.Fatal("DURABILITY_WRITE_FAILED")
	}
	first, err := dir.Read(ctx, "durable")
	if err != nil {
		t.Fatal("DURABILITY_READ_FAILED")
	}
	if err := dir.ProveDurable(ctx, "durable", first.Revision); err != nil {
		t.Fatal("DURABILITY_EXACT_PROOF_FAILED")
	}
	if err := dir.ReplaceIfVersion(ctx, "durable", first.Revision, []byte("v2")); err != nil {
		t.Fatal("DURABILITY_REPLACE_FAILED")
	}
	second, err := dir.Read(ctx, "durable")
	if err != nil || second.Revision == first.Revision {
		t.Fatal("DURABILITY_REVISION_UNCHANGED")
	}
	if err := dir.ProveDurable(ctx, "durable", first.Revision); !errors.Is(err, ErrUnknown) ||
		!errors.Is(err, ErrDurabilityUnproven) {
		t.Fatal("DURABILITY_STALE_PROOF_NOT_UNKNOWN")
	}
	if err := dir.ProveDurable(ctx, "durable", second.Revision); err != nil {
		t.Fatal("DURABILITY_CURRENT_PROOF_FAILED")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := dir.ProveDurable(canceled, "durable", second.Revision); !errors.Is(err, ErrDenied) {
		t.Fatal("DURABILITY_CANCELED_PROOF_NOT_DENIED")
	}
}
