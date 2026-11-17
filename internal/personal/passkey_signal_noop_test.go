package personal

import (
	"bytes"
	"testing"

	bolt "go.etcd.io/bbolt"
)

func signalSnapshotBytes(t *testing.T, s *Session) (snapshot, tip []byte) {
	t.Helper()
	db, err := existingWithReadOnly(s.path, true)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		snapshot = bytes.Clone(b.Get(snapshotKey))
		tip = bytes.Clone(b.Get(tipKey))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return snapshot, tip
}

// TestPasskeySignalPreviewAndNoopDoNotReseal pins the #102 accept criterion for
// the personal passkey signal path: a review (preview) and an empty change list
// neither seal a new snapshot nor append an audit event, so the authenticated
// snapshot bytes and linked tip are untouched.
func TestPasskeySignalPreviewAndNoopDoNotReseal(t *testing.T) {
	s, fill := browserFixture(t)
	account := signalCreate(t, s, fill.Context, "dXNlcjE", "one", "One")
	beforeSnapshot, beforeTip := signalSnapshotBytes(t, s)
	beforeEvents := rawAuditCountNoSession(t, s.path)

	// A review listing every stored credential is a read-only preview.
	proposal, err := s.ReviewPasskeySignal(signalAccepted("https://example.test", "example.test", account.UserID, account.CredentialID))
	if err != nil {
		t.Fatal(err)
	}
	if len(proposal.Changes) != 0 {
		t.Fatalf("fully accepted review proposed changes: %#v", proposal.Changes)
	}
	if _, err := s.ApplyPasskeySignal(signalAccepted("https://example.test", "example.test", account.UserID, account.CredentialID), nil, dailyGate(t, s)); err == nil {
		t.Fatal("empty signal batch was applied")
	}

	afterSnapshot, afterTip := signalSnapshotBytes(t, s)
	if !bytes.Equal(beforeSnapshot, afterSnapshot) || !bytes.Equal(beforeTip, afterTip) {
		t.Fatal("preview or no-op signal resealed the snapshot or tip")
	}
	if after := rawAuditCountNoSession(t, s.path); after != beforeEvents {
		t.Fatalf("preview or no-op signal appended audit events: %d -> %d", beforeEvents, after)
	}
}
