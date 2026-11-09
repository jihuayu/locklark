package personal

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func signedTransferEvent(t *testing.T, s *Session, action string) Event {
	t.Helper()
	var i identity
	if err := json.Unmarshal(s.material, &i); err != nil {
		t.Fatal(err)
	}
	defer i.clear()
	priv := ed25519.NewKeyFromSeed(i.Audit)
	defer clear(priv)
	ev := Event{
		Sequence: 2,
		UTC:      time.Now().UTC().Format(time.RFC3339Nano),
		Session:  strings.Repeat("a", 32),
		Actor:    "local-owner",
		Action:   action,
		Item:     strings.Repeat("b", 32),
		Result:   "succeeded",
		Link:     strings.Repeat("c", 64),
	}
	ev.Signature = ed25519.Sign(priv, ev.proof())
	return ev
}

func TestPasskeyTransferKnownActionWhitelistStaysFixed(t *testing.T) {
	path, key, _ := revealFixture(t)
	s, err := UnlockSession(path, []byte("fixture"), key, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Lock()
	var i identity
	if err := json.Unmarshal(s.material, &i); err != nil {
		t.Fatal(err)
	}
	defer i.clear()
	priv := ed25519.NewKeyFromSeed(i.Audit)
	defer clear(priv)
	pub := priv.Public().(ed25519.PublicKey)
	if err = signedTransferEvent(t, s, passkeyTransferInviteAction).verify(pub, 2, ""); err != nil {
		t.Fatalf("known invitation action was refused: %v", err)
	}
	for _, unknown := range []string{"vault.passkey.transfer.unknown", "vault.passkey.transfer.invite.extra", "item.passkey.transfer.invite"} {
		if err = signedTransferEvent(t, s, unknown).verify(pub, 2, ""); err == nil {
			t.Fatalf("unknown action %q was accepted", unknown)
		}
	}
}

func TestPasskeyTransferAuditTamperFailsClosed(t *testing.T) {
	path, key, _ := revealFixture(t)
	s, err := UnlockSession(path, []byte("fixture"), key, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	invite, err := s.NewPasskeyTransferInvitation(time.Minute, dailyGate(t, s))
	if err != nil {
		t.Fatal(err)
	}
	var i identity
	if err := json.Unmarshal(s.material, &i); err != nil {
		t.Fatal(err)
	}
	defer i.clear()
	db, err := existing(s.path)
	if err != nil {
		t.Fatal(err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		events := tx.Bucket(bucket).Bucket(eventsKey)
		var lastKey, lastRaw []byte
		if err := events.ForEach(func(k, raw []byte) error {
			lastKey, lastRaw = bytes.Clone(k), bytes.Clone(raw)
			return nil
		}); err != nil || lastKey == nil {
			return invalid
		}
		cipher, err := auditCipher(i)
		if err != nil {
			return err
		}
		var event Event
		if readSealed(cipher, eventLabel(lastKey), lastRaw, &event) != nil || event.Action != passkeyTransferInviteAction {
			return invalid
		}
		event.Link = strings.Repeat("d", 64)
		raw, err := sealedJSON(cipher, eventLabel(lastKey), event)
		if err != nil {
			return err
		}
		return events.Put(lastKey, raw)
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	totalBefore := rawAuditCountNoSession(t, path)
	gate := dailyGate(t, s)
	if err = s.RevokePasskeyTransferInvitation(invite.Raw, gate); err == nil || gate.CommitWon() {
		t.Fatalf("tampered audit chain returned %v, won=%v", err, gate.CommitWon())
	}
	if !errors.Is(err, ErrMutationCancelled) && !errors.Is(err, ErrMutationRefused) {
		t.Fatalf("tampered audit chain returned %v", err)
	}
	if _, err = UnlockSession(path, []byte("fixture"), key, time.Minute); !errors.Is(err, invalid) {
		t.Fatalf("tampered chain did not fail normal unlock: %v", err)
	}
	if rawAuditCountNoSession(t, path) != totalBefore {
		t.Fatal("tampered audit chain appended a revocation")
	}
}
