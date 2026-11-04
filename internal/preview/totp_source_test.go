package preview

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"path/filepath"
	"testing"

	"filippo.io/age"
	"github.com/jihuayu/locklark/internal/reference"
	"github.com/jihuayu/locklark/internal/totp"
)

// This is a test-only trusted read/calculation, not a production use endpoint.
// The witnessed event proves the synthetic source, not a disclosure fact.
func TestTOTPAuthenticatedSourceAndAuditPrivacy(t *testing.T) {
	m, items, _ := nativeReferenceFixture(t)
	seed := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))
	items[0].OTP = "otpauth://totp/RFC:synthetic?secret=" + seed + "&issuer=RFC&digits=8"
	p := payload{layout: m.Layout, items: items}
	pub, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(signer)
	auditPub, auditKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(auditKey)
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	device, bundle := filepath.Join(root, "device"), filepath.Join(root, "epoch-1")
	if err = saveDevice(device, id, pub, bytes.Repeat([]byte{3}, 16), bytes.Repeat([]byte{4}, 16)); err != nil {
		t.Fatal(err)
	}
	if err = write(device, "audit.pub", auditPub); err != nil {
		t.Fatal(err)
	}
	p.signedRecord(auditKey, "otp-vector", "owner", "fixture.import", "load public RFC vector", "imported")
	cp, err := makeCheckpoint(p, auditKey)
	if err != nil {
		t.Fatal(err)
	}
	if err = writeJSON(root, "witness.json", cp); err != nil {
		t.Fatal(err)
	}
	if err = saveEpoch(bundle, p, 1, []*age.X25519Recipient{id.Recipient()}, signer); err != nil {
		t.Fatal(err)
	}
	p, err = readPayload(bundle, device, 1)
	if err != nil {
		t.Fatal(err)
	}
	metadata := nativeReferenceJSON(t, nativeMeta{1, p.layout, p.Events, p.Proofs})
	catalog, err := ProjectFixtureReferenceMetadata(metadata, p.items, p.pin)
	if err != nil {
		t.Fatal(err)
	}
	target, err := reference.Resolve(FixtureRef, catalog)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := BindFixtureReferenceMetadata(metadata, p.items, p.pin, target)
	if err != nil || bound.Type != reference.TypeOTP || bound.Slot != reference.SlotOTP {
		t.Fatal("authenticated source did not bind as OTP configuration", err)
	}
	report, err := VerifyAudit(bundle, device, 1, filepath.Join(root, "witness.json"))
	if err != nil || report.Events != 1 || report.Witnessed != 1 {
		t.Fatal("source checkpoint/audit was changed or not verified", err)
	}
	var sourceOTP string
	for _, item := range p.items {
		if item.ID == bound.Target.ItemID && item.Kind == "login" {
			sourceOTP = item.OTP
			break
		}
	}
	config, err := totp.Parse(sourceOTP)
	if err != nil {
		t.Fatal(err)
	}
	code, err := config.At(59)
	if err != nil || code.Value() != "94287082" {
		t.Fatal("encrypted native OTP source changed RFC result", err)
	}
	raw, err := json.Marshal([]any{p.Events, report, bound, config, code})
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{seed, "12345678901234567890", "otpauth://", code.Value()} {
		if bytes.Contains(raw, []byte(marker)) {
			t.Fatal("source audit or ordinary serialization leaked OTP material")
		}
	}
}
