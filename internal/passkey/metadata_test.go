package passkey

import (
	"encoding/json"
	"strings"
	"testing"
)

func metadataFixture(t *testing.T) []byte {
	t.Helper()
	request, err := Parse("https://login.example.com", true, []byte(`{"challenge":"Y2hhbGxlbmdlLTAxMjM0NTY3ODk","rp":{"id":"example.com","name":"Example"},"user":{"id":"dXNlcjE","name":"alice","displayName":"Alice Example"},"pubKeyCredParams":[{"type":"public-key","alg":-7}]}`))
	if err != nil {
		t.Fatal(err)
	}
	raw, _, err := Create(request, false)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestMetadataProjectsOnlyPublicRecordFields(t *testing.T) {
	raw := metadataFixture(t)
	record, err := Load(raw)
	if err != nil {
		t.Fatal(err)
	}
	want := Metadata{CredentialID: record.ID, RPID: record.RPID, UserName: record.Name, DisplayName: record.DisplayName}
	private := append([]byte(nil), record.PrivateKey...)
	record.Clear()
	metadata, err := MetadataFromRecord(raw)
	if err != nil {
		t.Fatal(err)
	}
	if metadata != want {
		t.Fatalf("metadata mismatch: %#v", metadata)
	}
	if !ValidCredentialID(metadata.CredentialID) {
		t.Fatal("canonical credential id refused")
	}
	encoded, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	for _, forbidden := range []string{"private_key", "user_id", "userHandle", "private", string(private), `"id"`} {
		if forbidden != "" && strings.Contains(text, forbidden) {
			t.Fatalf("metadata leaked %q: %s", forbidden, text)
		}
	}
	for _, field := range []string{`"credential_id"`, `"rp_id"`, `"user_name"`, `"display_name"`} {
		if !strings.Contains(text, field) {
			t.Fatalf("metadata missing %s: %s", field, text)
		}
	}
}

func TestMetadataRejectsInvalidRecordsAndSelectors(t *testing.T) {
	for _, raw := range [][]byte{nil, []byte("{}"), []byte(`{"version":1}`), []byte(`{"version":1,"id":"bad"}`)} {
		if _, err := MetadataFromRecord(raw); err == nil {
			t.Fatal("invalid record projected")
		}
	}
	valid := metadataFixture(t)
	record, err := Load(valid)
	if err != nil {
		t.Fatal(err)
	}
	id := record.ID
	record.Clear()
	for _, candidate := range []string{"", id + "=", id[:len(id)-1], strings.Replace(id, "_", "/", 1), " " + id, id + " "} {
		if candidate == id {
			continue
		}
		if ValidCredentialID(candidate) {
			t.Fatalf("non-canonical selector accepted: %q", candidate)
		}
	}
}
