package personal

import (
	"errors"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func TestPasskeyTransferExportLockedRefusesWithoutAudit(t *testing.T) {
	s, target, _, _, _ := passkeyMultiFixture(t)
	receiver, public := exportTestReceiver(t)
	invite, err := receiver.NewPasskeyTransferInvitation(5*time.Minute, dailyGate(t, receiver))
	if err != nil {
		t.Fatal(err)
	}
	targets := exportTestTargets(t, s, target.ID)
	totalBefore := rawAuditCountNoSession(t, s.path)
	g := dailyGate(t, s)
	s.Lock()
	out, err := s.ExportPasskeyTransfer(invite.Raw, public.Fingerprint, targets, g)
	if !errors.Is(err, ErrMutationCancelled) {
		t.Fatalf("locked export returned %v", err)
	}
	if out.Raw != nil || out.PacketID != "" {
		t.Fatal("locked export returned output")
	}
	if rawAuditCountNoSession(t, s.path) != totalBefore {
		t.Fatal("locked export appended audit")
	}
}

func TestPasskeyTransferExportCommitThenLockIsUnknown(t *testing.T) {
	s, target, path, key := exportTestSource(t)
	if _, err := s.PerformPasskey(target, false, dailyGate(t, s)); err != nil {
		t.Fatal(err)
	}
	receiver, public := exportTestReceiver(t)
	invite, err := receiver.NewPasskeyTransferInvitation(5*time.Minute, dailyGate(t, receiver))
	if err != nil {
		t.Fatal(err)
	}
	targets := exportTestTargets(t, s, target.ID)
	g := dailyGate(t, s)
	out, err := s.exportPasskeyTransfer(invite.Raw, public.Fingerprint, targets, g, s.RequestLock, nil)
	if !errors.Is(err, ErrMutationUnknown) || out.Raw != nil || out.PacketID != "" || !g.CommitWon() || s.Unlocked() {
		t.Fatalf("commit-then-lock: err=%v raw=%d id=%q won=%v unlocked=%v", err, len(out.Raw), out.PacketID, g.CommitWon(), s.Unlocked())
	}
	fresh, err := UnlockSession(path, []byte("fixture"), key, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Lock()
	if rawAuditActionCount(t, fresh, passkeyTransferExportAction) != 1 {
		t.Fatal("committed export intent was not durable")
	}
}

func TestPasskeyTransferExportCloseFailureIsUnknown(t *testing.T) {
	s, target, path, key := exportTestSource(t)
	if _, err := s.PerformPasskey(target, false, dailyGate(t, s)); err != nil {
		t.Fatal(err)
	}
	receiver, public := exportTestReceiver(t)
	invite, err := receiver.NewPasskeyTransferInvitation(5*time.Minute, dailyGate(t, receiver))
	if err != nil {
		t.Fatal(err)
	}
	targets := exportTestTargets(t, s, target.ID)
	g := dailyGate(t, s)
	out, err := s.exportPasskeyTransfer(invite.Raw, public.Fingerprint, targets, g, nil, func(*bolt.DB) error { return errors.New("synthetic close failure") })
	if !errors.Is(err, ErrMutationUnknown) || out.Raw != nil || out.PacketID != "" || !g.CommitWon() {
		t.Fatalf("close failure: err=%v raw=%d id=%q won=%v", err, len(out.Raw), out.PacketID, g.CommitWon())
	}
	fresh, err := UnlockSession(path, []byte("fixture"), key, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Lock()
	if rawAuditActionCount(t, fresh, passkeyTransferExportAction) != 1 {
		t.Fatal("committed export intent was not durable after close failure")
	}
}
