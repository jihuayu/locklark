package vaultfile

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// The tests here pin the frozen v1 preimages and the two file states against
// exact JSON member sets. Bytes are shaped, never verified.

// jsonMembers decodes one complete JSON object and returns its member names in
// wire order. It fails on a duplicate so member removal cannot hide behind
// one.
func jsonMembers(t *testing.T, data []byte) []string {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		t.Fatalf("not a JSON object: %v", err)
	}
	var names []string
	seen := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			t.Fatal(err)
		}
		name, ok := tok.(string)
		if !ok {
			t.Fatalf("member name is %T", tok)
		}
		if seen[name] {
			t.Fatalf("duplicate member %q", name)
		}
		seen[name] = true
		names = append(names, name)
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := dec.Token(); err != nil {
		t.Fatal(err)
	}
	if dec.More() {
		t.Fatal("trailing data")
	}
	return names
}

// headerOf returns the raw header member of an encoded file.
func headerOf(t *testing.T, enc []byte) []byte {
	t.Helper()
	var v struct {
		Header json.RawMessage `json:"header"`
	}
	if err := json.Unmarshal(enc, &v); err != nil {
		t.Fatal(err)
	}
	return v.Header
}

var (
	sealedFileMembers = []string{
		"format", "version", "header", "signed_policy_proofs",
		"content_encoding", "kdbx_ciphertext", "vuk_device_slots", "cek_slot",
		"content_signature",
	}
	sealedHeaderMembers = []string{
		"vault_id", "key_epoch", "content_seq", "revision_id", "prev_digest",
		"op_id", "policy_seq", "policy_digest", "author_device_id",
	}
	// The RevisionID preimage omits header.revision_id itself.
	revisionHeaderMembers = []string{
		"vault_id", "key_epoch", "content_seq", "prev_digest",
		"op_id", "policy_seq", "policy_digest", "author_device_id",
	}
)

func wantMembers(t *testing.T, what string, got, want []string) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s members = %q, want %q", what, got, want)
	}
}

// TestRevisionPreimageOmitsRevisionID is the regression for a revision input
// that wrote "revision_id":"" instead of omitting the member: both files carry
// the same content, so both must derive the same revision id.
func TestRevisionPreimageOmitsRevisionID(t *testing.T) {
	sealed := buildFile(t)
	draft := unsignedFile(t)

	input, err := revisionDomainInput(sealed)
	if err != nil {
		t.Fatal(err)
	}
	wantMembers(t, "revision input file", jsonMembers(t, input),
		sealedFileMembers[:len(sealedFileMembers)-1])
	wantMembers(t, "revision input header", jsonMembers(t, headerOf(t, input)), revisionHeaderMembers)

	// The empty-placeholder form is exactly one member longer, and it is a
	// different input: a derived id must never be computed this way.
	placeholder, err := encodeFileWire(sealed, fileEncoding{revisionID: new(string), omitSignature: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(placeholder) != len(input)+len(`,"revision_id":""`) || !bytes.Contains(placeholder, []byte(`"revision_id":""`)) {
		t.Fatalf("placeholder input is not the omitted input plus an empty member")
	}
	if bytes.Equal(DomainSeparated(DomainRevision, placeholder), DomainSeparated(DomainRevision, input)) {
		t.Fatal("empty revision_id preimage collides with the omitted preimage")
	}

	// A sealed file and its draft share one identity.
	sealedRev, err := RevisionID(sealed)
	if err != nil {
		t.Fatal(err)
	}
	draftRev, err := RevisionID(draft)
	if err != nil {
		t.Fatal(err)
	}
	if sealedRev != draftRev {
		t.Fatalf("revision identities differ: sealed %s draft %s", sealedRev, draftRev)
	}
	if sealed.Header.RevisionID != sealedRev {
		t.Fatalf("sealed revision_id = %q, want %s", sealed.Header.RevisionID, sealedRev)
	}
	if draft.Header.RevisionID != "" {
		t.Fatalf("draft carries revision_id %q", draft.Header.RevisionID)
	}
	// Both states hash from identical bytes.
	draftInput, err := revisionDomainInput(draft)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(input, draftInput) {
		t.Fatal("draft and sealed revision inputs differ")
	}

	// Reordering a slot changes the input, so a stale id is rejected.
	reordered := deepCopyFile(sealed)
	reordered.VUKDeviceSlots[0], reordered.VUKDeviceSlots[1] = reordered.VUKDeviceSlots[1], reordered.VUKDeviceSlots[0]
	if _, err := EncodeFile(reordered); err == nil {
		t.Fatal("file with a stale revision id accepted")
	}
}

// TestContentSigningPreimage pins the content-signature preimage: the revision
// member is present and the signature member is absent, in both states.
func TestContentSigningPreimage(t *testing.T) {
	sealed := buildFile(t)
	draft := unsignedFile(t)
	csb, err := ContentSigningBytes(draft)
	if err != nil {
		t.Fatal(err)
	}
	sealedCSB, err := ContentSigningBytes(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(csb, sealedCSB) {
		t.Fatal("draft and sealed content signing inputs differ")
	}
	wantMembers(t, "content signing file", jsonMembers(t, csb),
		sealedFileMembers[:len(sealedFileMembers)-1])
	hdr := headerOf(t, csb)
	wantMembers(t, "content signing header", jsonMembers(t, hdr), sealedHeaderMembers)

	rev, err := RevisionID(draft)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(hdr, []byte(`"revision_id":"`+rev+`"`)) {
		t.Fatal("content signing header does not name the derived revision")
	}
	// The preimage is the signed file minus exactly its signature member.
	enc, err := EncodeFile(sealed)
	if err != nil {
		t.Fatal(err)
	}
	cut := string(enc)
	start := strings.Index(cut, `,"content_signature":{`)
	if start < 0 || !strings.HasSuffix(cut, `}}`) {
		t.Fatal("unexpected sealed encoding shape")
	}
	without := cut[:start] + "}"
	if without != string(csb) {
		t.Fatal("content signing input is not the sealed file minus content_signature")
	}
}

// TestSealFileStates pins SealFile's two outcomes: nil gives the only valid
// unsigned draft, and a non-nil signature gives the sealed file with exactly
// its derived revision id.
func TestSealFileStates(t *testing.T) {
	base := buildFile(t)

	// The source file may carry stale values; sealing replaces them.
	src := buildFile(t)
	src.Header.RevisionID = strings.Repeat("a", sha256.Size*2)

	// Nil: the unsigned draft.
	enc, err := SealFile(src, nil)
	if err != nil {
		t.Fatalf("SealFile(nil): %v", err)
	}
	draft, err := ParseFile(enc)
	if err != nil {
		t.Fatalf("unsigned draft rejected: %v", err)
	}
	if draft.Header.RevisionID != "" {
		t.Fatalf("draft revision_id = %q", draft.Header.RevisionID)
	}
	if draft.ContentSignature.SignerID != "" || draft.ContentSignature.Alg != "" || draft.ContentSignature.Sig != nil {
		t.Fatalf("draft signature = %+v", draft.ContentSignature)
	}
	if !bytes.Contains(enc, []byte(`"revision_id":""`)) || !bytes.Contains(enc, []byte(`"content_signature":{"signer_id":"","alg":"","sig":null}`)) {
		t.Fatal("draft is not the exact unsigned shape")
	}

	// Non-nil: the sealed file.
	sealedEnc, err := SealFile(src, &src.ContentSignature)
	if err != nil {
		t.Fatalf("SealFile(sig): %v", err)
	}
	sealed, err := ParseFile(sealedEnc)
	if err != nil {
		t.Fatalf("sealed file rejected: %v", err)
	}
	if sealed.Header.RevisionID != base.Header.RevisionID {
		t.Fatalf("sealed revision_id = %s, want %s", sealed.Header.RevisionID, base.Header.RevisionID)
	}
	if !bytes.Equal(sealed.ContentSignature.Sig, src.ContentSignature.Sig) {
		t.Fatal("sealed signature bytes were not kept")
	}
	if bytes.Contains(sealedEnc, []byte(`"revision_id":""`)) {
		t.Fatal("sealed file carries an empty revision id")
	}
	if _, err := ParseFile(enc); err != nil {
		t.Fatalf("draft no longer parses: %v", err)
	}
	// Sealing is idempotent on an already sealed file.
	again, err := SealFile(sealed, &sealed.ContentSignature)
	if err != nil || !bytes.Equal(again, sealedEnc) {
		t.Fatalf("resealing a sealed file is not byte-stable: %v", err)
	}

	// A draft carrying a revision id is rejected.
	bad := deepCopyFile(draft)
	bad.Header.RevisionID = sealed.Header.RevisionID
	_, err = EncodeFile(bad)
	wantCodeAt(t, err, CodeInvalidValue, "revision_id")

	// A non-null signature without a revision id is rejected.
	noRev := deepCopyFile(sealed)
	noRev.Header.RevisionID = ""
	_, err = EncodeFile(noRev)
	wantCodeAt(t, err, CodeMissingField, "revision_id")

	// A stale revision id under a signature is rejected.
	stale := deepCopyFile(base)
	stale.Header.OpID = "op-0043"
	_, err = EncodeFile(stale)
	wantCodeAt(t, err, CodeInvalidValue, "revision_id")

	// A null signature with a non-empty signer or algorithm is rejected.
	for _, mutate := range []func(*Signature){
		func(s *Signature) { s.SignerID = "device-1" },
		func(s *Signature) { s.Alg = SigAlgEd25519 },
	} {
		bad := deepCopyFile(draft)
		mutate(&bad.ContentSignature)
		_, err = EncodeFile(bad)
		wantCode(t, err, CodeSignatureInvalid)
	}
}

func wantCodeAt(t *testing.T, err error, code, path string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s at %s, got nil", code, path)
	}
	e, ok := AsError(err)
	if !ok || e.Code != code || e.Path != path {
		t.Fatalf("expected %s at %s, got %v", code, path, err)
	}
}

// TestSealedEncodingMembers pins the exact members of a normally encoded file:
// the revision member stays in the header and no header_sig exists.
func TestSealedEncodingMembers(t *testing.T) {
	enc := mustEncode(t)
	wantMembers(t, "sealed file", jsonMembers(t, enc), sealedFileMembers)
	wantMembers(t, "sealed header", jsonMembers(t, headerOf(t, enc)), sealedHeaderMembers)
	draft, err := SealFile(buildFile(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	wantMembers(t, "draft file", jsonMembers(t, draft), sealedFileMembers)
	wantMembers(t, "draft header", jsonMembers(t, headerOf(t, draft)), sealedHeaderMembers)

	// header_sig is not a v1 member in either state.
	withHeaderSig := strings.Replace(string(enc), `,"signed_policy_proofs":`,
		`,"header_sig":{"signer_id":"","alg":"","sig":null},"signed_policy_proofs":`, 1)
	_, err = ParseFile([]byte(withHeaderSig))
	wantCodeAt(t, err, CodeUnknownField, "header_sig")
}

// TestRevisionPreimageFixedVector pins one revision input and id literally, so
// an implementation that changes member order or placeholder bytes fails even
// after regenerating the vector file.
func TestRevisionPreimageFixedVector(t *testing.T) {
	f := unsignedFile(t)
	rev, err := RevisionID(f)
	if err != nil {
		t.Fatal(err)
	}
	if rev != fixedRevisionID {
		t.Fatalf("revision id = %s, want fixed %s", rev, fixedRevisionID)
	}
	sum, err := revisionDomainInput(f)
	if err != nil {
		t.Fatal(err)
	}
	if got := sha256Hex(sum); got != fixedRevisionInputSHA256 {
		t.Fatalf("revision input sha256 = %s, want %s", got, fixedRevisionInputSHA256)
	}
	raw, err := hex.DecodeString(fixedRevisionID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(DomainSeparated(DomainRevision, sum), raw) {
		t.Fatal("fixed revision id does not hash from the fixed input")
	}
}

const (
	// Fixed values of the synthetic unsigned-draft vector (see
	// testdata/vaultfile-v1-vectors.json, entry "v1-unsigned-draft").
	fixedRevisionInputSHA256 = "e80510b9592680ec31a776ba0593edb00d0b080da788a42133cf20428e2767a3"
	fixedRevisionID          = "930c61862a60a3070b4cef23cee7711e086913f678c861dbf25d63b0ff128b5d"
)
