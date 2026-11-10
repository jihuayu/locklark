package vaultfile

import (
	"strings"
	"testing"
)

// escapedDigits is the JSON escape spelling of "01", equivalent to it but not
// the spelling the canonical encoder emits.
var escapedDigits = func() string {
	bs := string([]byte{92})
	return bs + "u0030" + bs + "u0031"
}()

// nonCanonicalSpellings returns rewrites of canonical bytes that decode to the
// same value: surrounding and inter-member whitespace, a reordered first two
// members, and a string escape that spells the same character.
func nonCanonicalSpellings(t *testing.T, in []byte) []struct {
	name string
	out  []byte
} {
	t.Helper()
	s := string(in)
	quote, comma := byte('"'), byte(',')
	end := 0
	for s[end] != ':' {
		end++
	}
	end++
	if s[end] == quote {
		end++
		for s[end] != quote {
			end++
		}
	} else {
		for s[end] != comma {
			end++
		}
	}
	end++
	next := end
	for s[next] != ':' {
		next++
	}
	next++
	for s[next] != comma {
		next++
	}
	reordered := "{" + s[end+1:next] + s[end:end+1] + s[1:end] + s[next:]
	escaped := strings.Replace(s, "\"vault-01\"", "\"vault-"+escapedDigits+"\"", 1)
	if escaped == s {
		t.Fatal("escape rewrite did not apply")
	}
	return []struct {
		name string
		out  []byte
	}{
		{"leading whitespace", []byte("\n" + s)},
		{"trailing whitespace", []byte(s + " ")},
		{"inter-member whitespace", []byte(strings.Replace(s, `,"version":`, ",\n \"version\": ", 1))},
		{"reordered members", []byte(reordered)},
		{"equivalent escape", []byte(escaped)},
	}
}

func TestParseFileRequiresCanonicalBytes(t *testing.T) {
	enc := mustEncode(t)
	// The canonical file itself round-trips.
	f, err := ParseFile(enc)
	if err != nil {
		t.Fatal(err)
	}
	again, err := EncodeFile(f)
	if err != nil {
		t.Fatal(err)
	}
	if string(again) != string(enc) {
		t.Fatal("canonical file did not round-trip byte for byte")
	}
	for _, c := range nonCanonicalSpellings(t, enc) {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParseFile(c.out)
			wantCode(t, err, CodeNonCanonical)
		})
	}
}

func TestParsePolicyDocumentRequiresCanonicalBytes(t *testing.T) {
	doc := mustEncodeDoc(t)
	p, err := ParsePolicyDocument(doc)
	if err != nil {
		t.Fatal(err)
	}
	again, err := EncodePolicyDocument(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(again) != string(doc) {
		t.Fatal("canonical policy document did not round-trip byte for byte")
	}
	for _, c := range nonCanonicalSpellings(t, doc) {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParsePolicyDocument(c.out)
			wantCode(t, err, CodeNonCanonical)
		})
	}
}

// A proof whose document member carries a non-canonical spelling of the
// policy the proof also carries by value is rejected as non_canonical: SealFile
// and ValidateFile reject it outright, and ParseFile rejects a file that
// carries it even when its content signature is shaped correctly.
func TestProofWithNonCanonicalDocumentRejected(t *testing.T) {
	draft := buildDraft(t)
	canon := draft.SignedPolicyProofs[0].Document
	badDoc := []byte(strings.Replace(string(canon),
		"\"vault-01\"", "\"vault-"+escapedDigits+"\"", 1))
	// The spelling decodes to the same policy; only its bytes differ.
	p, err := ParsePolicyDocument(badDoc)
	wantCode(t, err, CodeNonCanonical)
	if p != nil {
		t.Fatal("non-canonical policy document returned with an error")
	}
	if !boolEqualPolicy(mustParsePolicy(t, canon), &draft.SignedPolicyProofs[0].Policy) {
		t.Fatal("the two spellings decode to different policies")
	}

	// The proof names exactly these bytes while carrying the same policy the
	// header digest binds.
	draft.SignedPolicyProofs[0].Document = badDoc
	wantCode(t, ValidateFile(draft), CodeNonCanonical)
	draft.ContentSignature = Signature{
		SignerID: draft.Header.AuthorDeviceID,
		Alg:      SigAlgEd25519,
		Sig:      shapedSignature(),
	}
	if _, err := SealFile(draft, &draft.ContentSignature); err == nil {
		t.Fatal("SealFile emitted a file with a non-canonical proof")
	}

	// A wire-shaped file carrying the proof is rejected by ParseFile after
	// structural validation: the proof document is not canonical.
	_, err = ParseFile([]byte(mustEncodeWith(t, draft)))
	wantCode(t, err, CodeNonCanonical)
}

func mustParsePolicy(t *testing.T, doc []byte) *Policy {
	t.Helper()
	p, err := ParsePolicyDocument(doc)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
