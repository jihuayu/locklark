package passkeytransfer

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/passkey"
)

// numericRevisionField rewrites one quoted revision digest as a JSON number, so
// version-counter style wire input is proven to be refused instead of coerced.
func numericRevisionField(t *testing.T, raw []byte, field, value string) []byte {
	t.Helper()
	quoted := `"` + field + `":"` + value + `"`
	mutated := strings.Replace(string(raw), quoted, `"`+field+`":1`, 1)
	if mutated == string(raw) {
		t.Fatal("revision field not found for numeric mutation")
	}
	return []byte(mutated)
}

func checkNoSecret(t *testing.T, label, text string, needles []string) {
	t.Helper()
	for _, needle := range needles {
		if needle == "" {
			continue
		}
		if strings.Contains(text, needle) {
			t.Fatalf("%s leaked private record bytes", label)
		}
	}
}

func canarySelection(t *testing.T, rp string) (Selection, []string) {
	t.Helper()
	record, credential, _ := newPasskey(t, rp)
	parsed, err := passkey.Load(record)
	if err != nil {
		t.Fatal("canary record invalid")
	}
	secret := append([]byte(nil), parsed.PrivateKey...)
	parsed.Clear()
	if len(secret) == 0 {
		t.Fatal("canary private key missing")
	}
	t.Cleanup(func() { clear(secret) })
	needles := []string{
		string(secret),
		base64.StdEncoding.EncodeToString(secret),
		base64.RawURLEncoding.EncodeToString(secret),
		hex.EncodeToString(secret),
	}
	return Selection{
		SourceItemID:       hexID(3),
		SourceRevision:     opaqueRevision("source-canary-" + rp),
		CredentialID:       credential,
		CredentialRevision: opaqueRevision("credential-canary-" + credential),
		Title:              rp,
		Record:             record,
	}, needles
}

// TestOpaqueRevisionsTravelVerbatim proves the revision digests are transported
// as exact strings through newPayload, sealing and opening.
func TestOpaqueRevisionsTravelVerbatim(t *testing.T) {
	f := newFixture(t)
	at := testTime(time.Minute)
	for _, s := range f.records {
		for _, rev := range []string{s.SourceRevision, s.CredentialRevision} {
			if !validateRevision(rev) || len(rev) != 64 {
				t.Fatal("fixture revision is not a canonical 64-lowercase-hex digest")
			}
		}
	}
	raw := f.seal(t, at)
	decoded, err := f.open(raw, at)
	if err != nil {
		t.Fatal("valid packet refused")
	}
	defer clearDecoded(decoded)
	if len(decoded) != len(f.records) {
		t.Fatal("record count changed")
	}
	for i := range decoded {
		if decoded[i].SourceRevision != f.records[i].SourceRevision {
			t.Fatal("source revision bytes changed in transit")
		}
		if decoded[i].CredentialRevision != f.records[i].CredentialRevision {
			t.Fatal("credential revision bytes changed in transit")
		}
	}
	inv := mustVerify(t, f.invitation, f.targetPin, at)
	key, ok := auditKey(f.sourceSeed)
	if !ok {
		t.Fatal("audit key unavailable")
	}
	defer clear(key)
	h := packetHeader{
		Version: version, ID: hexID(7), InvitationID: inv.ID, InvitationDigest: invitationDigest(f.invitation),
		SourceRecipient: f.source.Recipient().String(), SourceAuditPublic: encodeStd(auditPublic(key)),
		TargetFingerprint: f.targetPin, IssuedAt: at.Unix(), ExpiresAt: inv.ExpiresAt,
	}
	plaintext, err := newPayload(h, f.records)
	if err != nil {
		t.Fatal("payload build failed")
	}
	defer clear(plaintext)
	var parsed payload
	if json.Unmarshal(plaintext, &parsed) != nil {
		t.Fatal("payload decode failed")
	}
	if len(parsed.Records) != len(f.records) {
		t.Fatal("wire record count changed")
	}
	for i := range parsed.Records {
		if parsed.Records[i].SourceRevision != f.records[i].SourceRevision ||
			parsed.Records[i].CredentialRevision != f.records[i].CredentialRevision {
			t.Fatal("wire payload changed revision bytes")
		}
		if !strings.Contains(string(plaintext), `"source_revision":"`+f.records[i].SourceRevision+`"`) {
			t.Fatal("wire payload did not carry the source revision verbatim")
		}
		if !strings.Contains(string(plaintext), `"credential_revision":"`+f.records[i].CredentialRevision+`"`) {
			t.Fatal("wire payload did not carry the credential revision verbatim")
		}
	}
}

// TestRevisionFormatIsDigestOnly proves the codec enforces only the canonical
// 64-lowercase-hex digest format: counters, decimals, uppercase, non-hex and
// wrong-length values are refused, never parsed or truncated.
func TestRevisionFormatIsDigestOnly(t *testing.T) {
	f := newFixture(t)
	at := testTime(time.Minute)
	record, credential, _ := newPasskey(t, "format.example")
	good := Selection{
		SourceItemID:       hexID(5),
		SourceRevision:     opaqueRevision("source-format"),
		CredentialID:       credential,
		CredentialRevision: opaqueRevision("credential-format"),
		Title:              "format",
		Record:             record,
	}
	if !validateRevision(good.SourceRevision) || !validateRevision(good.CredentialRevision) {
		t.Fatal("canonical digest rejected by the format check")
	}
	if _, err := SealSelection(f.invitation, f.targetPin, f.source.Recipient(), f.sourceSeed, []Selection{good}, at); err != nil {
		t.Fatal("canonical digest selection refused")
	}
	bad := map[string]string{
		"empty":      "",
		"counter":    "1",
		"zero":       "0",
		"decimal":    "1234567890",
		"nonhex":     strings.Repeat("g", 64),
		"uppercase":  strings.ToUpper(good.SourceRevision),
		"short":      good.SourceRevision[:63],
		"long":       good.SourceRevision + "0",
		"whitespace": good.SourceRevision[:63] + " ",
		"base64":     base64.RawURLEncoding.EncodeToString([]byte(good.SourceRevision)),
	}
	for name, value := range bad {
		if validateRevision(value) {
			t.Fatalf("%s revision accepted by the format check", name)
		}
		source := good
		source.SourceRevision = value
		if _, err := SealSelection(f.invitation, f.targetPin, f.source.Recipient(), f.sourceSeed, []Selection{source}, at); err == nil {
			t.Fatalf("%s source revision accepted", name)
		} else {
			mustRefuse(t, err)
		}
		cred := good
		cred.CredentialRevision = value
		if _, err := SealSelection(f.invitation, f.targetPin, f.source.Recipient(), f.sourceSeed, []Selection{cred}, at); err == nil {
			t.Fatalf("%s credential revision accepted", name)
		} else {
			mustRefuse(t, err)
		}
	}
}

// TestSelectionFmtAndJSONRedaction proves fmt and encoding/json can never
// export the borrowed private record bytes.
func TestSelectionFmtAndJSONRedaction(t *testing.T) {
	sel, needles := canarySelection(t, "canary.example")
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		if got := fmt.Sprintf(verb, sel); got != redactedSelection {
			t.Fatalf("%s did not redact the selection", verb)
		}
		if got := fmt.Sprintf(verb, &sel); got != redactedSelection {
			t.Fatalf("%s did not redact the selection pointer", verb)
		}
	}
	forms := map[string]any{
		"slice":   []Selection{sel},
		"struct":  struct{ Selection Selection }{sel},
		"pointer": &sel,
		"map":     map[string]Selection{"s": sel},
	}
	for name, form := range forms {
		for _, verb := range []string{"%v", "%+v", "%#v", "%q", "%x"} {
			checkNoSecret(t, name+" "+verb, fmt.Sprintf(verb, form), needles)
		}
	}
	for _, verb := range []string{"%q", "%x"} {
		checkNoSecret(t, "selection "+verb, fmt.Sprintf(verb, sel), needles)
	}
	for name, form := range map[string]any{
		"selection": sel,
		"pointer":   &sel,
		"slice":     []Selection{sel},
		"struct":    struct{ Selection Selection }{sel},
	} {
		out, err := json.Marshal(form)
		if err == nil {
			t.Fatalf("%s exported to JSON", name)
		}
		if !errors.Is(err, ErrRefused) {
			t.Fatalf("%s JSON refusal lost the error category", name)
		}
		checkNoSecret(t, name+" json", err.Error()+string(out), needles)
	}
}

// TestDecodedRedactionStillHolds keeps the existing Decoded guard honest after
// the revision type change.
func TestDecodedRedactionStillHolds(t *testing.T) {
	sel, needles := canarySelection(t, "decoded.example")
	dec := Decoded{
		SourceItemID: sel.SourceItemID, SourceRevision: sel.SourceRevision,
		CredentialID: sel.CredentialID, CredentialRevision: sel.CredentialRevision,
		Title: sel.Title, Record: sel.Record,
	}
	if dec.String() != redactedSelection || dec.GoString() != redactedSelection {
		t.Fatal("decoded record not redacted")
	}
	for _, verb := range []string{"%v", "%+v", "%#v"} {
		if got := fmt.Sprintf(verb, dec); got != redactedSelection {
			t.Fatalf("%s did not redact the decoded record", verb)
		}
		checkNoSecret(t, "decoded "+verb, fmt.Sprintf(verb, []Decoded{dec}), needles)
	}
	if out, err := json.Marshal(dec); err == nil {
		t.Fatalf("decoded record exported to JSON: %s", out)
	} else if !errors.Is(err, ErrRefused) {
		t.Fatal("decoded JSON refusal lost the error category")
	}
	if dec.SourceRevision != sel.SourceRevision || dec.CredentialRevision != sel.CredentialRevision {
		t.Fatal("decoded revisions changed")
	}
}

// TestCodecNeverClearsBorrowedRecords proves sealing and clearing decoded
// copies never touches the caller-owned selection buffers.
func TestCodecNeverClearsBorrowedRecords(t *testing.T) {
	f := newFixture(t)
	borrowed := make([][]byte, len(f.records))
	for i := range f.records {
		borrowed[i] = append([]byte(nil), f.records[i].Record...)
	}
	at := testTime(time.Minute)
	raw := f.seal(t, at)
	if _, err := SealSelection(f.invitation, strings.Repeat("c", 64), f.source.Recipient(), f.sourceSeed, f.records, at); err == nil {
		t.Fatal("wrong pin accepted")
	}
	for i := range f.records {
		if !bytes.Equal(f.records[i].Record, borrowed[i]) {
			t.Fatal("codec mutated or cleared a borrowed caller record")
		}
	}
	decoded, err := f.open(raw, at)
	if err != nil {
		t.Fatal("valid packet refused")
	}
	decoded[0].Clear()
	if !bytes.Equal(f.records[0].Record, borrowed[0]) {
		t.Fatal("clearing a decoded record touched the caller record")
	}
	clearDecoded(decoded)
	for i := range f.records {
		if !bytes.Equal(f.records[i].Record, borrowed[i]) {
			t.Fatal("codec mutated a caller record")
		}
	}
}

// TestSelectionClearOnlyZeroesCallerOwnedCopy documents that Clear is optional
// and only for buffers the caller owns.
func TestSelectionClearOnlyZeroesCallerOwnedCopy(t *testing.T) {
	record, credential, _ := newPasskey(t, "clear.example")
	owned := append([]byte(nil), record...)
	sel := Selection{
		SourceItemID:       hexID(6),
		SourceRevision:     opaqueRevision("source-clear"),
		CredentialID:       credential,
		CredentialRevision: opaqueRevision("credential-clear"),
		Title:              "clear",
		Record:             owned,
	}
	sel.Clear()
	if sel.Record != nil {
		t.Fatal("clear did not release the record slice")
	}
	for _, b := range owned {
		if b != 0 {
			t.Fatal("clear did not zero the caller-owned bytes")
		}
	}
	var nilSelection *Selection
	nilSelection.Clear()
}
