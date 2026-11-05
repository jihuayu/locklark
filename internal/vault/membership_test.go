package vault

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"filippo.io/age"
)

// Exercise the storage consequence of a membership decision. Directory
// authorization, provenance and crash-safe distribution are separate operations.
func TestRemovingMemberExcludesEveryDevice(t *testing.T) {
	pub, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var devices []*age.X25519Identity
	var recipients []*age.X25519Recipient
	for i := 0; i < 4; i++ {
		d, err := age.GenerateX25519Identity()
		if err != nil {
			t.Fatal(err)
		}
		devices = append(devices, d)
		recipients = append(recipients, d.Recipient())
	}
	v1, err := Seal([]byte("first"), 7, recipients, signer)
	if err != nil {
		t.Fatal(err)
	}
	// Devices 0 and 1 belong to the leaving member, devices 2 and 3 remain.
	v2, err := Seal([]byte("private update for remaining members"), 8, recipients[2:], signer)
	if err != nil {
		t.Fatal(err)
	}
	for i, d := range devices {
		if _, err := Open(v1, d, pub, 7); err != nil {
			t.Fatal("old snapshot lost", i, err)
		}
		data, err := Open(v2, d, pub, 8)
		if i < 2 && err == nil {
			t.Fatal("former member opened new snapshot", i)
		}
		if i >= 2 && (err != nil || string(data) != "private update for remaining members") {
			t.Fatal("active member cannot read update", i, err)
		}
	}
	v2.Envelope = v1.Envelope
	if _, err := Open(v2, devices[2], pub, 8); err == nil {
		t.Fatal("mixed-generation envelope accepted")
	}
}
