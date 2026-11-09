package passkeytransfer

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/passkey"
)

func TestRoundTripPreservesCredential(t *testing.T) {
	f := newFixture(t)
	at := testTime(time.Minute)
	raw := f.seal(t, at)
	decoded, err := f.open(raw, at)
	if err != nil {
		t.Fatal("valid packet refused")
	}
	defer clearDecoded(decoded)
	if len(decoded) != len(f.records) {
		t.Fatal("record count changed")
	}
	for i, got := range decoded {
		want := f.records[i]
		if got.SourceItemID != want.SourceItemID || got.SourceRevision != want.SourceRevision ||
			got.CredentialID != want.CredentialID || got.CredentialRevision != want.CredentialRevision ||
			got.Title != want.Title {
			t.Fatal("selection metadata changed")
		}
		original, err := passkey.Load(want.Record)
		if err != nil {
			t.Fatal("fixture record invalid")
		}
		migrated, err := passkey.Load(got.Record)
		if err != nil {
			original.Clear()
			t.Fatal("decoded record invalid")
		}
		same := original.ID == migrated.ID && original.RPID == migrated.RPID &&
			original.UserID == migrated.UserID && bytes.Equal(original.PrivateKey, migrated.PrivateKey)
		original.Clear()
		migrated.Clear()
		if !same {
			t.Fatal("credential ID or private bytes changed")
		}
		if !verifyAssertion(t, want.Title, want.CredentialID, f.rpPublic[want.CredentialID], got.Record) {
			t.Fatal("independent relying party rejected migrated assertion")
		}
	}
}

func TestDecodedOutputIsRedactedAndClearable(t *testing.T) {
	f := newFixture(t)
	at := testTime(time.Minute)
	decoded, err := f.open(f.seal(t, at), at)
	if err != nil {
		t.Fatal("valid packet refused")
	}
	if decoded[0].String() != "[private passkey transfer record]" || decoded[0].GoString() != "[private passkey transfer record]" {
		t.Fatal("decoded record not redacted")
	}
	if _, err := json.Marshal(decoded[0]); err == nil {
		t.Fatal("decoded record exported to JSON")
	}
	owned := decoded[0].Record
	decoded[0].Clear()
	if decoded[0].Record != nil {
		t.Fatal("clear did not release record slice")
	}
	for _, b := range owned {
		if b != 0 {
			t.Fatal("clear did not zero owned bytes")
		}
	}
	clearDecoded(decoded)
}

func rawPacket(t *testing.T, h packetHeader, signature []byte) []byte {
	t.Helper()
	p := Packet{h.Version, h.ID, h.InvitationID, h.InvitationDigest, h.SourceRecipient,
		h.SourceAuditPublic, h.TargetFingerprint, h.IssuedAt, h.ExpiresAt, h.Ciphertext,
		encodeStd(signature)}
	raw, err := json.Marshal(p)
	if err != nil || len(raw) > maxPacket {
		t.Fatal("packet encode failed")
	}
	return raw
}

// TestHeaderPayloadBinding proves a correctly signed packet is still refused
// when the encrypted payload does not bind every outer identity field.
func TestHeaderPayloadBinding(t *testing.T) {
	f := newFixture(t)
	at := testTime(time.Minute)
	inv := mustVerify(t, f.invitation, f.targetPin, at)
	key, _ := auditKey(f.sourceSeed)
	pub := auditPublic(key)
	digest := invitationDigest(f.invitation)
	id, _ := newID()
	h := packetHeader{
		Version: version, ID: id, InvitationID: inv.ID, InvitationDigest: digest,
		SourceRecipient: f.source.Recipient().String(), SourceAuditPublic: encodeStd(pub),
		TargetFingerprint: f.targetPin, IssuedAt: at.Unix(), ExpiresAt: inv.ExpiresAt,
	}
	otherPin := fingerprint(f.source.Recipient().String(), pub)
	mutations := map[string]func(*packetHeader){
		"packet-id":       func(h *packetHeader) { h.ID = hexID(9) },
		"invitation-id":   func(h *packetHeader) { h.InvitationID = hexID(9) },
		"invitation-hash": func(h *packetHeader) { h.InvitationDigest = hexID(9) },
		"source":          func(h *packetHeader) { h.SourceRecipient = f.receiver.Recipient().String() },
		"source-audit":    func(h *packetHeader) { h.SourceAuditPublic = encodeStd(randomBytes(t, 32)) },
		"target":          func(h *packetHeader) { h.TargetFingerprint = otherPin },
	}
	for name, edit := range mutations {
		bound := h
		edit(&bound)
		plaintext, err := newPayload(bound, f.records)
		if err != nil {
			t.Fatal("payload build failed")
		}
		ciphertext, err := encryptTo(inv.Recipient, plaintext)
		clear(plaintext)
		if err != nil {
			t.Fatal("encrypt failed")
		}
		h.Ciphertext = encodeStd(ciphertext)
		raw := rawPacket(t, h, signWithKey(key, mustMessage(t, h)))
		if _, err := f.open(raw, at); err == nil {
			t.Fatalf("%s mismatch accepted", name)
		} else {
			mustRefuse(t, err)
		}
	}
	clear(key)
}
