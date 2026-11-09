package passkeytransfer

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/jihuayu/locklark/internal/passkey"
)

const testNow = int64(1700000000)

func testTime(offset time.Duration) time.Time {
	return time.Unix(testNow, 0).Add(offset)
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal("random source unavailable")
	}
	return b
}

// newPasskey creates a real software passkey record and returns its native
// JSON, credential ID and the RP-visible public key from registration.
func newPasskey(t *testing.T, rp string) ([]byte, string, []byte) {
	t.Helper()
	challenge := base64.RawURLEncoding.EncodeToString(randomBytes(t, 32))
	user := base64.RawURLEncoding.EncodeToString(randomBytes(t, 16))
	options, err := json.Marshal(map[string]any{
		"challenge": challenge,
		"rp":        map[string]string{"id": rp, "name": "Transfer"},
		"user":      map[string]string{"id": user, "name": "user", "displayName": "User"},
		"pubKeyCredParams": []map[string]any{
			{"type": "public-key", "alg": -7},
		},
	})
	if err != nil {
		t.Fatal("options encode failed")
	}
	req, err := passkey.Parse("https://"+rp, true, options)
	if err != nil {
		t.Fatal("passkey options refused")
	}
	raw, response, err := passkey.Create(req, true)
	if err != nil {
		t.Fatal("passkey create failed")
	}
	public, err := base64.RawURLEncoding.DecodeString(response.Response.PublicKey)
	if err != nil {
		t.Fatal("passkey public key decode failed")
	}
	return raw, response.ID, public
}

type fixture struct {
	receiver     *age.X25519Identity
	receiverSeed []byte
	source       *age.X25519Identity
	sourceSeed   []byte
	invitation   []byte
	inv          *Invitation
	targetPin    string
	sourcePin    string
	records      []Selection
	rpPublic     map[string][]byte
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	receiver, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal("receiver identity failed")
	}
	source, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal("source identity failed")
	}
	f := &fixture{
		receiver:     receiver,
		receiverSeed: randomBytes(t, 32),
		source:       source,
		sourceSeed:   randomBytes(t, 32),
		rpPublic:     map[string][]byte{},
	}
	now := testTime(0)
	f.invitation, f.inv, err = CreateInvite(receiver.Recipient(), f.receiverSeed, now, 10*time.Minute)
	if err != nil {
		t.Fatal("invitation create failed")
	}
	f.targetPin = f.inv.Fingerprint()
	if f.targetPin == "" {
		t.Fatal("invitation fingerprint missing")
	}
	sourcePub := auditPublic(ed25519.NewKeyFromSeed(f.sourceSeed))
	f.sourcePin = fingerprint(f.source.Recipient().String(), sourcePub)
	for i, rp := range []string{"login.example", "second.example"} {
		record, credential, public := newPasskey(t, rp)
		f.rpPublic[credential] = public
		f.records = append(f.records, Selection{
			SourceItemID:       hexID(byte(i + 1)),
			SourceRevision:     opaqueRevision("source-" + rp),
			CredentialID:       credential,
			CredentialRevision: opaqueRevision("credential-" + credential),
			Title:              rp,
			Record:             record,
		})
	}
	return f
}

func hexID(fill byte) string {
	return hex.EncodeToString(bytes.Repeat([]byte{fill}, 16))
}

// opaqueRevision returns a 64-lowercase-hex opaque revision shaped like the
// personal-layer HMAC revision digests. It is deliberately not a counter: the
// codec must transport these strings byte-for-byte.
func opaqueRevision(label string) string {
	d := sha256.Sum256([]byte("locklark/passkey-transfer/test/revision\x00" + label))
	return hex.EncodeToString(d[:])
}

func (f *fixture) seal(t *testing.T, at time.Time) []byte {
	t.Helper()
	raw, err := SealSelection(f.invitation, f.targetPin, f.source.Recipient(), f.sourceSeed, f.records, at)
	if err != nil {
		t.Fatal("seal failed")
	}
	if len(raw) == 0 || len(raw) > maxPacket {
		t.Fatal("sealed packet out of bounds")
	}
	return raw
}

func (f *fixture) open(raw []byte, at time.Time) ([]Decoded, error) {
	return OpenSelection(raw, f.invitation, f.receiver, f.targetPin, f.sourcePin, at)
}

// verifyAssertion acts as an independent RP: it verifies a fresh assertion
// made by the migrated private key against the public key from registration.
func verifyAssertion(t *testing.T, rp, credential string, public []byte, record []byte) bool {
	t.Helper()
	parsed, err := passkey.Load(record)
	if err != nil {
		return false
	}
	defer parsed.Clear()
	challenge := base64.RawURLEncoding.EncodeToString(randomBytes(t, 32))
	options, err := json.Marshal(map[string]any{
		"challenge":        challenge,
		"rpId":             rp,
		"allowCredentials": []map[string]string{{"type": "public-key", "id": credential}},
		"userVerification": "required",
	})
	if err != nil {
		return false
	}
	req, err := passkey.Parse("https://"+rp, false, options)
	if err != nil {
		return false
	}
	response, err := passkey.Get(req, parsed, true)
	if err != nil {
		return false
	}
	client, err := base64.RawURLEncoding.DecodeString(response.Response.ClientDataJSON)
	if err != nil {
		return false
	}
	authData, err := base64.RawURLEncoding.DecodeString(response.Response.AuthenticatorData)
	if err != nil {
		return false
	}
	signature, err := base64.RawURLEncoding.DecodeString(response.Response.Signature)
	if err != nil {
		return false
	}
	key, err := x509.ParsePKIXPublicKey(public)
	ecdsaKey, ok := key.(*ecdsa.PublicKey)
	if err != nil || !ok {
		return false
	}
	digest := sha256.Sum256(client)
	signed := append(append([]byte{}, authData...), digest[:]...)
	message := sha256.Sum256(signed)
	return ecdsa.VerifyASN1(ecdsaKey, message[:], signature)
}

func invitationDigest(raw []byte) string {
	d := sha256.Sum256(raw)
	return hex.EncodeToString(d[:])
}

func signWithKey(key ed25519.PrivateKey, msg []byte) []byte {
	return ed25519.Sign(key, msg)
}

func mustMessage(t *testing.T, h packetHeader) []byte {
	t.Helper()
	msg, err := packetMessage(h)
	if err != nil {
		t.Fatal("packet message failed")
	}
	return msg
}

func (f *fixture) resign(t *testing.T, raw []byte, edit func(*Packet)) []byte {
	t.Helper()
	p := mutatePacket(t, raw, edit)
	var parsed Packet
	if json.Unmarshal(p, &parsed) != nil {
		t.Fatal("packet decode failed")
	}
	key, _ := auditKey(f.sourceSeed)
	parsed.Signature = encodeStd(ed25519.Sign(key, mustMessage(t, parsed.header())))
	clear(key)
	out, err := json.Marshal(parsed)
	if err != nil {
		t.Fatal("resign encode failed")
	}
	return out
}
