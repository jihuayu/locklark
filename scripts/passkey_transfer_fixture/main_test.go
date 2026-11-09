package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/jihuayu/locklark/internal/passkey"
	"github.com/jihuayu/locklark/internal/personal"
)

func TestParseSecretRoundTripAndRefusal(t *testing.T) {
	key, err := personal.NewSecret()
	if err != nil {
		t.Fatalf("new secret: %v", err)
	}
	text := personal.FormatSecret(key)
	parsed, err := parseSecret(text)
	if err != nil || string(parsed) != string(key) {
		t.Fatalf("parse secret round trip failed")
	}
	for _, bad := range []string{"", "LL1-", text + "A", "LL1-!!!!"} {
		if _, err := parseSecret(bad); err == nil {
			t.Fatalf("parse secret accepted malformed input")
		}
	}
}

// TestPrivateRoot exercises the fixture's private-root policy with native
// platform fixtures: an owner-private directory is accepted and the same
// directory made group/Everyone readable is refused. Windows creates and
// checks real DACLs (see root_windows.go and fixture_windows_test.go) instead
// of the POSIX mode bits it ignores.
func TestPrivateRoot(t *testing.T) {
	root := passkeyTransferPrivateRootFixture(t)
	if err := privateRoot(root); err != nil {
		t.Fatalf("private root refused: %v", err)
	}
	passkeyTransferMakeRootShared(t, root)
	if err := privateRoot(root); err == nil {
		t.Fatal("group-readable root accepted")
	}
	if err := privateRoot("relative"); err == nil {
		t.Fatal("relative root accepted")
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	if err := privateRoot(link); err == nil {
		t.Fatal("symlink root accepted")
	}
}

func TestVerifyAssertion(t *testing.T) {
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicRaw, err := x509.MarshalPKIXPublicKey(&private.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	creationPublicKey := base64.RawURLEncoding.EncodeToString(publicRaw)
	authData := make([]byte, 37)
	if _, err := rand.Read(authData); err != nil {
		t.Fatal(err)
	}
	clientData := []byte(`{"type":"webauthn.get","challenge":"Y2hhbGxlbmdl","origin":"https://example.test"}`)
	clientHash := sha256.Sum256(clientData)
	signed := append(append([]byte{}, authData...), clientHash[:]...)
	digest := sha256.Sum256(signed)
	signature, err := ecdsa.SignASN1(rand.Reader, private, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	response := passkey.Response{Response: passkey.AuthenticatorResponse{
		AuthenticatorData: base64.RawURLEncoding.EncodeToString(authData),
		ClientDataJSON:    base64.RawURLEncoding.EncodeToString(clientData),
		Signature:         base64.RawURLEncoding.EncodeToString(signature),
	}}
	if !verifyAssertion(creationPublicKey, response) {
		t.Fatal("valid assertion refused")
	}
	response.Response.Signature = base64.RawURLEncoding.EncodeToString(append([]byte{}, signature...))
	tampered := append([]byte{}, signature...)
	tampered[len(tampered)-1] ^= 0x01
	response.Response.Signature = base64.RawURLEncoding.EncodeToString(tampered)
	if verifyAssertion(creationPublicKey, response) {
		t.Fatal("tampered assertion accepted")
	}
}

func TestStateProjectionHelpers(t *testing.T) {
	rows := []personal.Row{{ID: "item", Revision: "rev", Title: "Title"}}
	if rowRevision(rows, "item") != "rev" || rowRevision(rows, "missing") != "" {
		t.Fatal("row revision projection mismatch")
	}
	if rowTitle(rows, "item") != "Title" || rowTitle(rows, "missing") != "" {
		t.Fatal("row title projection mismatch")
	}
	metadata := map[string][]personal.ManagedPasskeyMetadata{
		"item": {{CredentialID: "cred", Revision: "child"}},
	}
	if credentialRevision(metadata, "item", "cred") != "child" || credentialRevision(metadata, "item", "other") != "" {
		t.Fatal("credential revision projection mismatch")
	}
	if !hasCredential(metadata, "item", "cred") || hasCredential(metadata, "item", "other") {
		t.Fatal("credential presence mismatch")
	}
	events := []personal.Event{{Action: transferInviteAction}, {Action: transferExportAction}, {Action: transferInviteAction}}
	if actionCount(events, transferInviteAction) != 2 || actionCount(events, transferConsumeAction) != 0 {
		t.Fatal("action count mismatch")
	}
}
