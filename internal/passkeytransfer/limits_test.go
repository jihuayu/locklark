package passkeytransfer

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/passkey"
)

func testSelection(item byte, raw []byte, credential string) Selection {
	return Selection{
		SourceItemID:       hexID(item),
		SourceRevision:     opaqueRevision("source-" + hexID(item)),
		CredentialID:       credential,
		CredentialRevision: opaqueRevision("credential-" + credential),
		Title:              "limit",
		Record:             raw,
	}
}

// withSourceRevision returns a copy of s with SourceRevision replaced.
func withSourceRevision(s Selection, value string) Selection {
	s.SourceRevision = value
	return s
}

// withCredentialRevision returns a copy of s with CredentialRevision replaced.
func withCredentialRevision(s Selection, value string) Selection {
	s.CredentialRevision = value
	return s
}

func TestSealRefusesInvalidSelection(t *testing.T) {
	f := newFixture(t)
	at := testTime(time.Minute)
	record, credential, _ := newPasskey(t, "limit.example")
	good := testSelection(1, record, credential)
	many := make([]Selection, 0, maxRecords+1)
	for i := 0; i <= maxRecords; i++ {
		raw, id, _ := newPasskey(t, "limit.example")
		many = append(many, testSelection(byte(i+1), raw, id))
	}
	badRecord := []byte(`{"version":1,"id":"","unknown":true}`)
	padded := credential + strings.Repeat("=", (4-len(credential)%4)%4)
	mismatch := good
	mismatch.CredentialID = many[0].CredentialID
	oversize := good
	oversize.Record = make([]byte, passkey.MaxOptions+1)
	shortSeed := append([]byte{}, f.sourceSeed[:31]...)
	cases := []struct {
		name string
		raw  []byte
		pin  string
		src  []Selection
		seed []byte
		when time.Time
	}{
		{"empty-pin", f.invitation, "", []Selection{good}, f.sourceSeed, at},
		{"wrong-pin", f.invitation, strings.Repeat("c", 64), []Selection{good}, f.sourceSeed, at},
		{"expired", f.invitation, f.targetPin, []Selection{good}, f.sourceSeed, testTime(11 * time.Minute)},
		{"short-seed", f.invitation, f.targetPin, []Selection{good}, shortSeed, at},
		{"no-records", f.invitation, f.targetPin, nil, f.sourceSeed, at},
		{"too-many", f.invitation, f.targetPin, many, f.sourceSeed, at},
		{"duplicate-cred", f.invitation, f.targetPin, []Selection{good, many[0], good}, f.sourceSeed, at},
		{"bad-item", f.invitation, f.targetPin, []Selection{func() Selection { s := good; s.SourceItemID = "XYZ"; return s }()}, f.sourceSeed, at},
		{"empty-source-revision", f.invitation, f.targetPin, []Selection{withSourceRevision(good, "")}, f.sourceSeed, at},
		{"counter-source-revision", f.invitation, f.targetPin, []Selection{withSourceRevision(good, "1")}, f.sourceSeed, at},
		{"uppercase-source-revision", f.invitation, f.targetPin, []Selection{withSourceRevision(good, strings.ToUpper(good.SourceRevision))}, f.sourceSeed, at},
		{"nonhex-source-revision", f.invitation, f.targetPin, []Selection{withSourceRevision(good, strings.Repeat("z", 64))}, f.sourceSeed, at},
		{"short-source-revision", f.invitation, f.targetPin, []Selection{withSourceRevision(good, good.SourceRevision[:63])}, f.sourceSeed, at},
		{"long-source-revision", f.invitation, f.targetPin, []Selection{withSourceRevision(good, good.SourceRevision+"0")}, f.sourceSeed, at},
		{"empty-credential-revision", f.invitation, f.targetPin, []Selection{withCredentialRevision(good, "")}, f.sourceSeed, at},
		{"counter-credential-revision", f.invitation, f.targetPin, []Selection{withCredentialRevision(good, "2")}, f.sourceSeed, at},
		{"uppercase-credential-revision", f.invitation, f.targetPin, []Selection{withCredentialRevision(good, strings.ToUpper(good.CredentialRevision))}, f.sourceSeed, at},
		{"nonhex-credential-revision", f.invitation, f.targetPin, []Selection{withCredentialRevision(good, strings.Repeat("z", 64))}, f.sourceSeed, at},
		{"short-credential-revision", f.invitation, f.targetPin, []Selection{withCredentialRevision(good, good.CredentialRevision[:63])}, f.sourceSeed, at},
		{"long-credential-revision", f.invitation, f.targetPin, []Selection{withCredentialRevision(good, good.CredentialRevision+"0")}, f.sourceSeed, at},
		{"bad-cred", f.invitation, f.targetPin, []Selection{func() Selection { s := good; s.CredentialID = padded; return s }()}, f.sourceSeed, at},
		{"mismatch-cred", f.invitation, f.targetPin, []Selection{mismatch}, f.sourceSeed, at},
		{"empty-record", f.invitation, f.targetPin, []Selection{func() Selection { s := good; s.Record = nil; return s }()}, f.sourceSeed, at},
		{"oversize-record", f.invitation, f.targetPin, []Selection{oversize}, f.sourceSeed, at},
		{"bad-record-json", f.invitation, f.targetPin, []Selection{func() Selection { s := good; s.Record = badRecord; return s }()}, f.sourceSeed, at},
		{"long-title", f.invitation, f.targetPin, []Selection{func() Selection { s := good; s.Title = strings.Repeat("t", 1025); return s }()}, f.sourceSeed, at},
	}
	for _, c := range cases {
		if _, err := SealSelection(c.raw, c.pin, f.source.Recipient(), c.seed, c.src, c.when); err == nil {
			t.Fatalf("%s accepted", c.name)
		} else {
			mustRefuse(t, err)
		}
	}
	if _, err := SealSelection(f.invitation, f.targetPin, nil, f.sourceSeed, []Selection{good}, at); err == nil {
		t.Fatal("nil source recipient accepted")
	}
	optional := good
	optional.Title = ""
	raw, err := SealSelection(f.invitation, f.targetPin, f.source.Recipient(), f.sourceSeed, []Selection{optional}, at)
	if err != nil {
		t.Fatal("optional title rejected")
	}
	if decoded, err := f.open(raw, at); err != nil || len(decoded) != 1 || decoded[0].Title != "" {
		t.Fatal("optional title roundtrip failed")
	}
}

func TestPayloadStrictDecoding(t *testing.T) {
	f := newFixture(t)
	at := testTime(time.Minute)
	inv := mustVerify(t, f.invitation, f.targetPin, at)
	key, _ := auditKey(f.sourceSeed)
	defer clear(key)
	h := packetHeader{
		Version: version, ID: hexID(1), InvitationID: inv.ID, InvitationDigest: invitationDigest(f.invitation),
		SourceRecipient: f.source.Recipient().String(), SourceAuditPublic: encodeStd(auditPublic(key)),
		TargetFingerprint: f.targetPin, IssuedAt: at.Unix(), ExpiresAt: inv.ExpiresAt,
	}
	valid, err := newPayload(h, f.records)
	if err != nil {
		t.Fatal("payload build failed")
	}
	var decoded payload
	if json.Unmarshal(valid, &decoded) != nil {
		t.Fatal("payload decode failed")
	}
	mutate := func(edit func(*payload)) []byte {
		copied := decoded
		copied.Records = append([]wireRecord{}, decoded.Records...)
		edit(&copied)
		raw, err := json.Marshal(copied)
		if err != nil {
			t.Fatal("payload encode failed")
		}
		return raw
	}
	cases := map[string][]byte{
		"unknown":                       []byte(strings.Replace(string(valid), "{", `{"extra":1,`, 1)),
		"duplicate":                     []byte(strings.Replace(string(valid), "{", `{"v":1,`, 1)),
		"trailing":                      append(append([]byte{}, valid...), []byte("x")...),
		"version":                       mutate(func(p *payload) { p.Version = 2 }),
		"empty":                         mutate(func(p *payload) { p.Records = nil }),
		"too-many":                      mutate(func(p *payload) { p.Records = make([]wireRecord, maxRecords+1) }),
		"target-pin":                    mutate(func(p *payload) { p.TargetFingerprint = "nope" }),
		"bad-record":                    mutate(func(p *payload) { p.Records[0].Record = "!!!!" }),
		"source-revision-empty":         mutate(func(p *payload) { p.Records[0].SourceRevision = "" }),
		"source-revision-counter":       mutate(func(p *payload) { p.Records[0].SourceRevision = "1" }),
		"source-revision-uppercase":     mutate(func(p *payload) { p.Records[0].SourceRevision = strings.ToUpper(p.Records[0].SourceRevision) }),
		"source-revision-nonhex":        mutate(func(p *payload) { p.Records[0].SourceRevision = strings.Repeat("z", 64) }),
		"source-revision-short":         mutate(func(p *payload) { p.Records[0].SourceRevision = p.Records[0].SourceRevision[:63] }),
		"source-revision-long":          mutate(func(p *payload) { p.Records[0].SourceRevision += "0" }),
		"source-revision-number":        numericRevisionField(t, valid, "source_revision", decoded.Records[0].SourceRevision),
		"credential-revision-empty":     mutate(func(p *payload) { p.Records[0].CredentialRevision = "" }),
		"credential-revision-counter":   mutate(func(p *payload) { p.Records[0].CredentialRevision = "2" }),
		"credential-revision-uppercase": mutate(func(p *payload) { p.Records[0].CredentialRevision = strings.ToUpper(p.Records[0].CredentialRevision) }),
		"credential-revision-nonhex":    mutate(func(p *payload) { p.Records[0].CredentialRevision = strings.Repeat("z", 64) }),
		"credential-revision-short":     mutate(func(p *payload) { p.Records[0].CredentialRevision = p.Records[0].CredentialRevision[:63] }),
		"credential-revision-long":      mutate(func(p *payload) { p.Records[0].CredentialRevision += "0" }),
		"credential-revision-number":    numericRevisionField(t, valid, "credential_revision", decoded.Records[0].CredentialRevision),
		"bad-base64":                    mutate(func(p *payload) { p.Records[0].Record = base64.StdEncoding.EncodeToString([]byte("{}")) }),
	}
	for name, raw := range cases {
		parsed, err := parsePayload(raw)
		if err == nil {
			_, err = convertPayload(parsed)
		}
		if err == nil {
			t.Fatalf("%s payload accepted", name)
		}
		mustRefuse(t, err)
	}
}
