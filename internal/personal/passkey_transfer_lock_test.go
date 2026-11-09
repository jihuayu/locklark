package personal

import (
	"errors"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func TestPasskeyTransferInvitationCommitThenLockIsUnknown(t *testing.T) {
	path, key, _ := revealFixture(t)
	s, err := UnlockSession(path, []byte("fixture"), key, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	g := dailyGate(t, s)
	invite, err := s.newPasskeyTransferInvitation(time.Minute, g, s.RequestLock, nil)
	if !errors.Is(err, ErrMutationUnknown) || invite.Raw != nil || !g.CommitWon() || s.Unlocked() {
		t.Fatalf("commit-then-lock returned %v, raw=%d, won=%v", err, len(invite.Raw), g.CommitWon())
	}
	fresh, err := UnlockSession(path, []byte("fixture"), key, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Lock()
	if rawAuditActionCount(t, fresh, passkeyTransferInviteAction) != 1 {
		t.Fatal("committed invitation audit was not durable")
	}
}

func TestPasskeyTransferInvitationCloseFailureIsUnknown(t *testing.T) {
	path, key, _ := revealFixture(t)
	s, err := UnlockSession(path, []byte("fixture"), key, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Lock()
	g := dailyGate(t, s)
	invite, err := s.newPasskeyTransferInvitation(time.Minute, g, nil, func(*bolt.DB) error { return errors.New("synthetic close failure") })
	if !errors.Is(err, ErrMutationUnknown) || invite.Raw != nil || !g.CommitWon() {
		t.Fatalf("close failure returned %v, raw=%d, won=%v", err, len(invite.Raw), g.CommitWon())
	}
}
