package personal

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/jihuayu/locklark/internal/vault"
)

// authenticateState must admit any snapshot the vault can seal: items below
// MaxPayload can produce a KDBX above the old 8 MiB bound, and the stored JSON
// adds base64 overhead on top of it.
func TestStoredSnapshotAboveLegacyBoundAuthenticates(t *testing.T) {
	s, path, key := v2Session(t)
	id, revision, err := s.AddItem(v2LoginItem(), v2Gate(t, s))
	if err != nil {
		t.Fatal(err)
	}
	for n := 0; n < 5; n++ {
		content := make([]byte, vault.MaxAttachmentSize)
		if _, err := rand.Read(content); err != nil {
			t.Fatal(err)
		}
		_, revision, err = s.AddAttachment(id, revision, "synthetic.bin", "application/octet-stream", content, v2Gate(t, s))
		clear(content)
		if err != nil {
			t.Fatalf("synthetic attachment %d failed: %v", n, err)
		}
	}
	detail, err := s.GetItemDetail(id, revision, false)
	if err != nil || len(detail.Attachments) != 5 {
		t.Fatalf("synthetic attachments missing: %d %v", len(detail.Attachments), err)
	}
	s.Lock()

	// Positive control: the persisted value must actually exceed the legacy
	// 8 MiB bound, otherwise this test would pass for the old limit too.
	db, err := existingWithReadOnly(path, true)
	if err != nil {
		t.Fatal(err)
	}
	var state []byte
	err = db.View(func(tx *bolt.Tx) error {
		if raw := tx.Bucket([]byte(bucket)).Get(snapshotKey); raw != nil {
			state = bytes.Clone(raw)
		}
		return nil
	})
	db.Close()
	if err != nil || len(state) == 0 {
		t.Fatalf("stored snapshot value missing: %v", err)
	}
	if len(state) <= 8<<20 {
		t.Fatalf("persisted snapshot value is %d bytes, not above the legacy bound", len(state))
	}
	clear(state)

	reopened, err := UnlockSession(path, []byte("v2-fixture"), key, time.Minute)
	if err != nil {
		t.Fatalf("reopen of a snapshot above the legacy bound failed: %v", err)
	}
	defer reopened.Lock()
	if got, err := reopened.GetItemDetail(id, revision, false); err != nil || len(got.Attachments) != 5 {
		t.Fatalf("reopened large snapshot lost attachments: %d %v", len(got.Attachments), err)
	}
}
