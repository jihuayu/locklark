package vaultfilepublish

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
)

func TestPublicationDurabilityUnknownImmediateProofFailureKeepsPrepared(t *testing.T) {
	f := newFixture(t)
	f.backend.onReplace = applyThenFail(proposalData, readbackRevision, vaultfilebackend.ErrUnknown)
	f.backend.durability = &fakeDurability{
		err: fmt.Errorf("%w: injected immediate proof failure", vaultfilebackend.ErrDurabilityUnproven),
	}
	ctx := context.Background()
	err := f.coord.PrepareAndPublish(ctx, f.pull(t), f.proposal, f.pinPullVerifier(proposalData))
	if err == nil {
		t.Fatal("unknown publication was acknowledged without a durability proof")
	}
	if !errors.Is(err, vaultfilebackend.ErrUnknown) {
		t.Fatalf("error does not retain ErrUnknown: %v", err)
	}
	if !errors.Is(err, vaultfilebackend.ErrDurabilityUnproven) {
		t.Fatalf("error does not retain ErrDurabilityUnproven: %v", err)
	}
	if f.backend.durability.calls != 1 {
		t.Fatalf("durability calls = %d, want 1", f.backend.durability.calls)
	}
	if f.backend.durability.last != readbackRevision {
		t.Fatalf("proof revision = %q, want %q", f.backend.durability.last, readbackRevision)
	}
	assertPrepared(t, loadPrepared(t, f.j), f.prepared)
	assertState(t, loadState(t, f.j), f.initial)
}

func TestPublicationDurabilityUnknownImmediateProofAcksOnce(t *testing.T) {
	f := newFixture(t)
	f.backend.onReplace = applyThenFail(proposalData, readbackRevision, vaultfilebackend.ErrUnknown)
	f.backend.durability = &fakeDurability{}
	ctx := context.Background()
	if err := f.coord.PrepareAndPublish(ctx, f.pull(t), f.proposal, f.pinPullVerifier(proposalData)); err != nil {
		t.Fatalf("PrepareAndPublish with valid durability proof: %v", err)
	}
	if f.backend.durability.calls != 1 {
		t.Fatalf("durability calls = %d, want 1", f.backend.durability.calls)
	}
	want := f.initial
	want.BaseBytes = own(proposalData)
	want.RemoteRevision = readbackRevision
	assertState(t, loadState(t, f.j), want)
	assertNoPrepared(t, f.j)
}

func TestPublicationDurabilityUnknownResumeProofFailureKeepsPrepared(t *testing.T) {
	f := newFixture(t)
	f.backend.replaceErr = vaultfilebackend.ErrUnknown
	ctx := context.Background()
	if err := f.coord.PrepareAndPublish(ctx, f.pull(t), f.proposal, f.pinPullVerifier(proposalData)); !errors.Is(err, ErrUnknownWrite) {
		t.Fatalf("PrepareAndPublish error = %v, want ErrUnknownWrite", err)
	}
	f.reopen(t)
	f.backend.set(proposalData, readbackRevision)
	f.backend.durability = &fakeDurability{
		err: fmt.Errorf("%w: injected resume proof failure", vaultfilebackend.ErrDurabilityUnproven),
	}
	err := f.coord.ResumePrepared(ctx, f.pull(t), f.pinPullVerifier(proposalData))
	if err == nil {
		t.Fatal("resumed applied proposal was acknowledged without a durability proof")
	}
	if !errors.Is(err, vaultfilebackend.ErrUnknown) {
		t.Fatalf("resume error does not retain ErrUnknown: %v", err)
	}
	if !errors.Is(err, vaultfilebackend.ErrDurabilityUnproven) {
		t.Fatalf("resume error does not retain ErrDurabilityUnproven: %v", err)
	}
	if f.backend.durability.calls != 1 {
		t.Fatalf("durability calls = %d, want 1", f.backend.durability.calls)
	}
	assertPrepared(t, loadPrepared(t, f.j), f.prepared)
	assertState(t, loadState(t, f.j), f.initial)
}

func TestPublicationDurabilityUnknownResumeProofAcksOnce(t *testing.T) {
	f := newFixture(t)
	f.backend.replaceErr = vaultfilebackend.ErrUnknown
	ctx := context.Background()
	if err := f.coord.PrepareAndPublish(ctx, f.pull(t), f.proposal, f.pinPullVerifier(proposalData)); !errors.Is(err, ErrUnknownWrite) {
		t.Fatalf("PrepareAndPublish error = %v, want ErrUnknownWrite", err)
	}
	f.reopen(t)
	f.backend.set(proposalData, readbackRevision)
	f.backend.durability = &fakeDurability{}
	writes := f.backend.replaces
	if err := f.coord.ResumePrepared(ctx, f.pull(t), f.pinPullVerifier(proposalData)); err != nil {
		t.Fatalf("ResumePrepared with valid durability proof: %v", err)
	}
	if f.backend.replaces != writes {
		t.Fatalf("resume wrote %d times, want no CAS", f.backend.replaces-writes)
	}
	if f.backend.durability.calls != 1 {
		t.Fatalf("durability calls = %d, want 1", f.backend.durability.calls)
	}
	want := f.initial
	want.BaseBytes = own(proposalData)
	want.RemoteRevision = readbackRevision
	assertState(t, loadState(t, f.j), want)
	assertNoPrepared(t, f.j)
}

func TestPublicationDurabilityUnknownConfirmedPathSkipsProof(t *testing.T) {
	f := newFixture(t)
	f.backend.durability = &fakeDurability{err: errors.New("proof must not be called")}
	ctx := context.Background()
	if err := f.coord.PrepareAndPublish(ctx, f.pull(t), f.proposal, f.pinPullVerifier(proposalData)); err != nil {
		t.Fatalf("confirmed PrepareAndPublish: %v", err)
	}
	if f.backend.durability.calls != 0 {
		t.Fatalf("confirmed path durability calls = %d, want 0", f.backend.durability.calls)
	}
	assertNoPrepared(t, f.j)
}
