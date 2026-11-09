package passkeytransfer

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func mustRefuse(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, ErrRefused) || err.Error() != ErrRefused.Error() {
		t.Fatalf("error category leaked or wrong")
	}
}

func mustVerify(t *testing.T, raw []byte, pin string, at time.Time) *Invitation {
	t.Helper()
	inv, err := VerifyInvitation(raw, pin, at)
	if err != nil {
		t.Fatal("valid invitation refused")
	}
	return inv
}

func TestInvitationVerifyAndPinPolicy(t *testing.T) {
	f := newFixture(t)
	now := testTime(0)
	inv := mustVerify(t, f.invitation, f.targetPin, now)
	if inv.ID != f.inv.ID || inv.Recipient != f.receiver.Recipient().String() || inv.ExpiresAt <= now.Unix() {
		t.Fatal("invitation fields changed")
	}
	if inv.Fingerprint() != f.targetPin {
		t.Fatal("fingerprint not reproducible")
	}
	for _, pin := range []string{"", "not-a-pin", strings.Repeat("A", 64), f.targetPin + "0"} {
		if _, err := VerifyInvitation(f.invitation, pin, now); err == nil {
			t.Fatalf("invalid pin accepted")
		} else {
			mustRefuse(t, err)
		}
	}
	otherSeed := randomBytes(t, 32)
	otherPin := fingerprint(f.receiver.Recipient().String(), auditPublic(ed25519.NewKeyFromSeed(otherSeed)))
	if _, err := VerifyInvitation(f.invitation, otherPin, now); err == nil {
		t.Fatal("wrong target pin accepted")
	}
}

func TestInvitationRefusesTamperVersionAndTime(t *testing.T) {
	f := newFixture(t)
	now := testTime(0)
	var inv Invitation
	if err := json.Unmarshal(f.invitation, &inv); err != nil {
		t.Fatal("fixture invitation invalid")
	}
	mutate := func(edit func(*Invitation)) []byte {
		copied := inv
		edit(&copied)
		raw, err := json.Marshal(copied)
		if err != nil {
			t.Fatal("mutated invitation encode failed")
		}
		return raw
	}
	signature := []byte(inv.Signature)
	signature[0] ^= 1
	bad := mutate(func(i *Invitation) { i.Signature = base64.StdEncoding.EncodeToString(signature) })
	cases := map[string][]byte{
		"signature":    bad,
		"version":      mutate(func(i *Invitation) { i.Version = 2 }),
		"recipient":    mutate(func(i *Invitation) { i.Recipient = f.source.Recipient().String() }),
		"audit-public": mutate(func(i *Invitation) { i.AuditPublic = encodeStd(randomBytes(t, 32)) }),
		"id":           mutate(func(i *Invitation) { i.ID = strings.Repeat("0", 32) }),
		"unknown":      []byte(strings.Replace(string(f.invitation), "{", `{"extra":1,`, 1)),
		"trailing":     append(append([]byte{}, f.invitation...), []byte("garbage")...),
		"base64":       mutate(func(i *Invitation) { i.Signature = strings.TrimRight(i.Signature, "=") }),
	}
	for name, raw := range cases {
		if _, err := VerifyInvitation(raw, f.targetPin, now); err == nil {
			t.Fatalf("%s tamper accepted", name)
		} else {
			mustRefuse(t, err)
		}
	}
	expired := testTime(11 * time.Minute)
	if _, err := VerifyInvitation(f.invitation, f.targetPin, expired); err == nil {
		t.Fatal("expired invitation accepted")
	}
	future := testTime(-1 * time.Second)
	if _, err := VerifyInvitation(f.invitation, f.targetPin, future); err == nil {
		t.Fatal("future-issued invitation accepted")
	}
}

func TestCreateInviteBounds(t *testing.T) {
	f := newFixture(t)
	now := testTime(0)
	for _, ttl := range []time.Duration{0, -time.Second, maxInvitationTTL + time.Second} {
		if _, _, err := CreateInvite(f.receiver.Recipient(), f.receiverSeed, now, ttl); err == nil {
			t.Fatal("out-of-bounds TTL accepted")
		} else {
			mustRefuse(t, err)
		}
	}
	if _, _, err := CreateInvite(f.receiver.Recipient(), f.receiverSeed[:31], now, time.Minute); err == nil {
		t.Fatal("short audit seed accepted")
	}
	if _, _, err := CreateInvite(nil, f.receiverSeed, now, time.Minute); err == nil {
		t.Fatal("nil recipient accepted")
	}
	first, _, err := CreateInvite(f.receiver.Recipient(), f.receiverSeed, now, time.Minute)
	if err != nil {
		t.Fatal("invite create failed")
	}
	second, _, err := CreateInvite(f.receiver.Recipient(), f.receiverSeed, now, time.Minute)
	if err != nil || string(first) == string(second) {
		t.Fatal("invitation nonce not random")
	}
}
