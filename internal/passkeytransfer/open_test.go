package passkeytransfer

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
)

// tripwireIdentity fails loudly if OpenSelection ever reaches decryption.
type tripwireIdentity struct {
	recipient *age.X25519Recipient
}

func (t tripwireIdentity) Unwrap([]*age.Stanza) ([]byte, error) { panic("decryption attempted") }
func (t tripwireIdentity) Recipient() *age.X25519Recipient {
	return t.recipient
}

func mutatePacket(t *testing.T, raw []byte, edit func(*Packet)) []byte {
	t.Helper()
	var p Packet
	if json.Unmarshal(raw, &p) != nil {
		t.Fatal("packet decode failed")
	}
	edit(&p)
	out, err := json.Marshal(p)
	if err != nil {
		t.Fatal("packet encode failed")
	}
	return out
}

func TestOpenRequiresExplicitPinsAndIdentity(t *testing.T) {
	f := newFixture(t)
	at := testTime(time.Minute)
	raw := f.seal(t, at)
	other, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal("identity generation failed")
	}
	otherPin := strings.Repeat("b", 64)
	cases := []struct {
		name           string
		identity       RecipientIdentity
		target, source string
	}{
		{"empty-target", f.receiver, "", f.sourcePin},
		{"wrong-target", f.receiver, otherPin, f.sourcePin},
		{"empty-source", f.receiver, f.targetPin, ""},
		{"wrong-source", f.receiver, f.targetPin, otherPin},
		{"wrong-identity", other, f.targetPin, f.sourcePin},
		{"nil-identity", nil, f.targetPin, f.sourcePin},
	}
	for _, c := range cases {
		if _, err := OpenSelection(raw, f.invitation, c.identity, c.target, c.source, at); err == nil {
			t.Fatalf("%s accepted", c.name)
		} else {
			mustRefuse(t, err)
		}
	}
	if _, err := OpenSelection(raw, f.invitation, f.receiver, f.targetPin, f.sourcePin, testTime(11*time.Minute)); err == nil {
		t.Fatal("expired open accepted")
	}
	if _, err := OpenSelection(raw, f.invitation, f.receiver, f.targetPin, f.sourcePin, testTime(-time.Second)); err == nil {
		t.Fatal("early open accepted")
	}
}

func TestOpenRefusesTamperedPacket(t *testing.T) {
	f := newFixture(t)
	at := testTime(time.Minute)
	raw := f.seal(t, at)
	flipCiphertext := f.resign(t, raw, func(p *Packet) {
		ct, err := base64.StdEncoding.DecodeString(p.Ciphertext)
		if err != nil || len(ct) == 0 {
			t.Fatal("ciphertext invalid")
		}
		ct[len(ct)/2] ^= 1
		p.Ciphertext = base64.StdEncoding.EncodeToString(ct)
	})
	flipSignature := mutatePacket(t, raw, func(p *Packet) {
		sig, err := base64.StdEncoding.DecodeString(p.Signature)
		if err != nil {
			t.Fatal("signature invalid")
		}
		sig[0] ^= 1
		p.Signature = base64.StdEncoding.EncodeToString(sig)
	})
	cases := map[string][]byte{
		"version":      mutatePacket(t, raw, func(p *Packet) { p.Version = 2 }),
		"id":           mutatePacket(t, raw, func(p *Packet) { p.ID = strings.Repeat("0", 32) }),
		"future":       mutatePacket(t, raw, func(p *Packet) { p.IssuedAt = at.Unix() + 60 }),
		"overlong":     mutatePacket(t, raw, func(p *Packet) { p.ExpiresAt = f.inv.ExpiresAt + 1 }),
		"expired":      mutatePacket(t, raw, func(p *Packet) { p.ExpiresAt = at.Unix() }),
		"target-pin":   mutatePacket(t, raw, func(p *Packet) { p.TargetFingerprint = strings.Repeat("a", 64) }),
		"source-audit": mutatePacket(t, raw, func(p *Packet) { p.SourceAuditPublic = encodeStd(randomBytes(t, 32)) }),
		"empty-ct":     mutatePacket(t, raw, func(p *Packet) { p.Ciphertext = "" }),
		"ct-base64":    f.resign(t, raw, func(p *Packet) { p.Ciphertext += "\n" }),
		"ciphertext":   flipCiphertext,
		"ct-trailing": f.resign(t, raw, func(p *Packet) {
			ct, _ := base64.StdEncoding.DecodeString(p.Ciphertext)
			p.Ciphertext = base64.StdEncoding.EncodeToString(append(ct, 0))
		}),
		"ct-truncated": f.resign(t, raw, func(p *Packet) {
			ct, _ := base64.StdEncoding.DecodeString(p.Ciphertext)
			p.Ciphertext = base64.StdEncoding.EncodeToString(ct[:len(ct)-1])
		}),
		"signature": flipSignature,
		"unknown":   []byte(strings.Replace(string(raw), "{", `{"extra":1,`, 1)),
		"duplicate": []byte(strings.Replace(string(raw), "{", `{"v":1,`, 1)),
		"trailing":  append(append([]byte{}, raw...), []byte("x")...),
		"oversize":  append(append([]byte{}, raw...), []byte(strings.Repeat(" ", maxPacket))...),
	}
	for name, mutated := range cases {
		if _, err := f.open(mutated, at); err == nil {
			t.Fatalf("%s packet accepted", name)
		} else {
			mustRefuse(t, err)
		}
	}
	other := newFixture(t)
	if _, err := OpenSelection(raw, other.invitation, other.receiver, other.targetPin, f.sourcePin, at); err == nil {
		t.Fatal("foreign invitation accepted")
	}
	// A tampered signature must be rejected before any age decryption.
	trip := tripwireIdentity{f.receiver.Recipient()}
	func() {
		defer func() {
			if recover() != nil {
				t.Fatal("decrypted before signature verification")
			}
		}()
		if _, err := OpenSelection(flipSignature, f.invitation, trip, f.targetPin, f.sourcePin, at); err == nil {
			t.Fatal("tampered signature accepted")
		}
	}()
}
