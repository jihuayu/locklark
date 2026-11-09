package personal

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/jihuayu/locklark/internal/passkeytransfer"
)

func exportTestReceiver(t *testing.T) (*Session, publicTransferIdentity) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "receiver.ll")
	key := bytes.Repeat([]byte{9}, 16)
	if err := Create(path, "fixture", key); err != nil {
		t.Fatal(err)
	}
	s, err := UnlockSession(path, []byte("fixture"), key, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Lock)
	return s, transferTestPublic(t, s)
}

func exportTestTargets(t *testing.T, s *Session, itemID string) []PasskeyTransferTarget {
	t.Helper()
	metadata, err := s.ReadManagedPasskeysMetadata(false)
	if err != nil {
		t.Fatal(err)
	}
	revision := suggestionsRevision(t, s, itemID)
	values := metadata[itemID]
	if len(values) == 0 {
		t.Fatalf("no credentials for item %q", itemID)
	}
	targets := make([]PasskeyTransferTarget, 0, len(values))
	for _, value := range values {
		targets = append(targets, PasskeyTransferTarget{ItemID: itemID, Revision: revision, CredentialID: value.CredentialID, CredentialRevision: value.Revision})
	}
	return targets
}

func exportTestRecipient(t *testing.T, s *Session) *age.X25519Identity {
	t.Helper()
	var value identity
	if err := json.Unmarshal(s.material, &value); err != nil {
		t.Fatal(err)
	}
	defer value.clear()
	recipient, err := age.ParseX25519Identity(value.Device)
	if err != nil {
		t.Fatal(err)
	}
	return recipient
}

func exportTestExpiredInvite(t *testing.T, receiver *Session, pin string) []byte {
	t.Helper()
	var value identity
	if err := json.Unmarshal(receiver.material, &value); err != nil {
		t.Fatal(err)
	}
	defer value.clear()
	device, err := age.ParseX25519Identity(value.Device)
	if err != nil {
		t.Fatal(err)
	}
	raw, _, err := passkeytransfer.CreateInvite(device.Recipient(), value.Audit, time.Now().Add(-10*time.Minute), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := passkeytransfer.VerifyInvitation(raw, pin, time.Now()); err == nil {
		t.Fatal("expired invitation verified")
	}
	return raw
}

func exportTestEvent(t *testing.T, s *Session, action string) Event {
	t.Helper()
	events, err := s.Audit()
	if err != nil {
		t.Fatal(err)
	}
	for i := len(events) - 1; i >= 0; i-- {
		if events[i].Action == action {
			return events[i]
		}
	}
	t.Fatalf("audit action %q missing", action)
	return Event{}
}

func exportCloneTargets(targets []PasskeyTransferTarget) []PasskeyTransferTarget {
	return append([]PasskeyTransferTarget(nil), targets...)
}
