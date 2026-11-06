package passkey

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"strings"
	"testing"
)

func creation(t *testing.T) *Request {
	t.Helper()
	r, e := Parse("https://login.example.com", true, []byte(`{"challenge":"Y2hhbGxlbmdlLTAxMjM0NTY3ODk","rp":{"id":"example.com","name":"Example"},"user":{"id":"dXNlcjE","name":"alice","displayName":"Alice"},"pubKeyCredParams":[{"type":"public-key","alg":-7}],"authenticatorSelection":{"residentKey":"required","userVerification":"required"},"extensions":{"credProps":true}}`))
	if e != nil {
		t.Fatal(e)
	}
	return r
}
func TestCredentialRoundTripAndIndependentSignature(t *testing.T) {
	r := creation(t)
	if _, _, e := Create(r, false); e == nil {
		t.Fatal("UV required was ignored")
	}
	raw, created, e := Create(r, true)
	if e != nil {
		t.Fatal(e)
	}
	record, e := Load(raw)
	if e != nil {
		t.Fatal(e)
	}
	defer record.Clear()
	pubDER, _ := b64.DecodeString(created.Response.PublicKey)
	pub, e := x509.ParsePKIXPublicKey(pubDER)
	if e != nil {
		t.Fatal(e)
	}
	auth, _ := b64.DecodeString(created.Response.AuthenticatorData)
	rp := sha256.Sum256([]byte("example.com"))
	if string(auth[:32]) != string(rp[:]) || auth[32] != 0x4d {
		t.Fatalf("incorrect attested flags %x", auth[32])
	}
	if created.Extensions["credProps"].(map[string]bool)["rk"] != true {
		t.Fatal("missing resident property")
	}
	options := `{"rpId":"example.com","challenge":"bmV3LWNoYWxsZW5nZS0wMTIzNDU2","userVerification":"required","allowCredentials":[{"type":"public-key","id":"` + record.ID + `"}]}`
	request, e := Parse(r.Origin, false, []byte(options))
	if e != nil {
		t.Fatal(e)
	}
	signed, e := Get(request, record, true)
	if e != nil {
		t.Fatal(e)
	}
	auth, _ = b64.DecodeString(signed.Response.AuthenticatorData)
	client, _ := b64.DecodeString(signed.Response.ClientDataJSON)
	sig, _ := b64.DecodeString(signed.Response.Signature)
	var data map[string]any
	if json.Unmarshal(client, &data) != nil || data["origin"] != r.Origin || data["type"] != "webauthn.get" || data["challenge"] != request.Options.Challenge {
		t.Fatal("client data binding")
	}
	h := sha256.Sum256(client)
	digest := sha256.Sum256(append(auth, h[:]...))
	if !ecdsa.VerifyASN1(pub.(*ecdsa.PublicKey), digest[:], sig) {
		t.Fatal("invalid assertion")
	}
	if auth[32] != 0x0d || signed.Response.UserHandle != record.UserID {
		t.Fatal("assertion flags/user")
	}
	digest[0] ^= 1
	if ecdsa.VerifyASN1(pub.(*ecdsa.PublicKey), digest[:], sig) {
		t.Fatal("signature accepted changed challenge")
	}
	request.Options.Allow[0].ID = b64.EncodeToString([]byte("different-id"))
	if _, e = Get(request, record, true); e == nil {
		t.Fatal("wrong credential signed")
	}
}
func TestRPAndOptionsRefusals(t *testing.T) {
	for _, pair := range [][2]string{{"https://alice.github.io", "github.io"}, {"https://evil-example.com", "example.com"}, {"https://example.com", "com"}, {"https://example.com", "evil.com"}, {"http://example.com", "example.com"}} {
		if ValidRP(pair[0], pair[1]) {
			t.Fatal("unsafe RP", pair)
		}
	}
	for _, pair := range [][2]string{{"https://a.example.com", "example.com"}, {"https://alice.github.io", "alice.github.io"}} {
		if !ValidRP(pair[0], pair[1]) {
			t.Fatal("valid RP", pair)
		}
	}
	base := `{"rpId":"example.com","challenge":"Y2hhbGxlbmdlLTAxMjM0NTY3ODk"}`
	for _, raw := range []string{strings.Replace(base, "example.com", "github.io", 1), base + `{}`, strings.Replace(base, `"rpId":"example.com"`, `"rpId":"example.com","rpId":"example.com"`, 1), strings.Replace(base, `"rpId":"example.com"`, `"rpId":"example.com","extensions":{"prf":{}}`, 1)} {
		if _, e := Parse("https://example.com", false, []byte(raw)); e == nil {
			t.Fatal("invalid accepted", raw)
		}
	}
}
