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

// The tests here pin the frozen v1 preimages, the one valid wire state and
// the separate in-memory draft path against exact JSON member sets. Bytes are
// shaped, never verified.

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
	draft := buildDraft(t)

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

	// The draft is not a wire file: its identity is still derived, but it
	// never encodes, parses or digests.
	if _, err := EncodeFile(draft); err == nil {
		t.Fatal("draft encoded as a wire file")
	}
	if _, err := FileDigest(draft); err == nil {
		t.Fatal("draft hashed as a sealed file")
	}
	if err := ValidateFile(draft); err == nil {
		t.Fatal("draft validated as a wire file")
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
	draft := buildDraft(t)
	// The writer drafts with the signature it is about to set; the revision
	// id is still absent.
	signed := draftWithSignature(t)
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
	signedCSB, err := ContentSigningBytes(signed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(csb, signedCSB) {
		t.Fatal("pre-signature draft and sealed content signing inputs differ")
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

// TestSealFileSealed pins SealFile's one outcome: a non-nil signature gives
// the sealed file with exactly its derived revision id.
func TestSealFileSealed(t *testing.T) {
	base := buildFile(t)

	// The source draft may carry a stale revision id; sealing replaces it.
	src := draftWithSignature(t)
	src.Header.RevisionID = strings.Repeat("a", sha256.Size*2)

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
	if bytes.Contains(sealedEnc, []byte(`"sig":null`)) {
		t.Fatal("sealed file carries a null signature")
	}
	// Sealing is idempotent on an already sealed file.
	again, err := SealFile(sealed, &sealed.ContentSignature)
	if err != nil || !bytes.Equal(again, sealedEnc) {
		t.Fatalf("resealing a sealed file is not byte-stable: %v", err)
	}

	// A non-null signature without a revision id in the input is fine: the
	// revision id is always replaced by the derived one, never required.
	noRev := draftWithSignature(t)
	noRev.Header.RevisionID = ""
	if _, err := parseSealedOnly(t, noRev, &noRev.ContentSignature); err != nil {
		t.Fatalf("draft without revision id did not seal: %v", err)
	}

	// A stale revision id under a signature is rejected.
	stale := deepCopyFile(base)
	stale.Header.OpID = "op-0043"
	_, err = EncodeFile(stale)
	wantCodeAt(t, err, CodeInvalidValue, "revision_id")

	// A sealed file with no revision id is rejected as missing.
	noRevSealed := deepCopyFile(base)
	noRevSealed.Header.RevisionID = ""
	_, err = EncodeFile(noRevSealed)
	wantCodeAt(t, err, CodeMissingField, "revision_id")
}

// parseSealedOnly seals draft with sig and parses the result back.
func parseSealedOnly(t *testing.T, draft *File, sig *Signature) (*File, error) {
	t.Helper()
	enc, err := SealFile(draft, sig)
	if err != nil {
		return nil, err
	}
	return ParseFile(enc)
}

// TestSealFileNilRejected is the regression that SealFile(f, nil) must never
// return bytes that look like a wire file: a null-sig draft is not one.
func TestSealFileNilRejected(t *testing.T) {
	for _, f := range []*File{buildDraft(t), buildFile(t), draftWithSignature(t)} {
		enc, err := SealFile(f, nil)
		wantCodeAt(t, err, CodeInvalidValue, "content_signature")
		if enc != nil {
			t.Fatalf("SealFile(f, nil) returned %d bytes", len(enc))
		}
	}
	// A signature whose value is null is the same draft request.
	sig := Signature{SignerID: "device-1", Alg: SigAlgEd25519}
	_, err := SealFile(buildDraft(t), &sig)
	wantCodeAt(t, err, CodeInvalidValue, "content_signature")
}

// TestDraftRejectedByWire is the regression that ParseFile, EncodeFile,
// FileBytes, ValidateFile and FileDigest accept only sealed files. The draft
// JSON below is the exact shape the old encoder used to emit for it and must
// never come back as a valid wire record.
func TestDraftRejectedByWire(t *testing.T) {
	draft := buildDraft(t)

	// The historical draft document: null sig, empty signer/alg, empty
	// revision id, complete otherwise.
	draftJSON, err := encodeFileWire(draft, fileEncoding{})
	if err != nil {
		t.Fatal(err)
	}
	for _, needle := range []string{
		`"revision_id":""`,
		`"content_signature":{"signer_id":"","alg":"","sig":null}`,
	} {
		if !bytes.Contains(draftJSON, []byte(needle)) {
			t.Fatalf("draft fixture lacks %s", needle)
		}
	}

	// ParseFile rejects the draft document.
	_, err = ParseFile(draftJSON)
	wantCodeAt(t, err, CodeInvalidValue, "content_signature")

	// The same document with a revision id added is still a draft.
	withRev, err := encodeFileWire(draft, fileEncoding{revisionID: new(string)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = ParseFile(withRev)
	wantCodeAt(t, err, CodeInvalidValue, "content_signature")

	// EncodeFile and FileBytes reject the typed draft.
	if _, err := EncodeFile(draft); err == nil {
		t.Fatal("EncodeFile accepted a draft")
	}
	if _, err := FileBytes(draft); err == nil {
		t.Fatal("FileBytes accepted a draft")
	}
	if err := ValidateFile(draft); err == nil {
		t.Fatal("ValidateFile accepted a draft")
	}

	// FileDigest cannot hash a draft, in any in-memory draft shape.
	nullSig := buildFile(t)
	nullSig.ContentSignature.Sig = nil
	for name, f := range map[string]*File{
		"building":      draft,
		"pre-signature": draftWithSignature(t),
		"null sig":      nullSig,
	} {
		if fd, err := FileDigest(f); err == nil || fd != "" {
			t.Fatalf("%s: FileDigest = %q, %v; want error", name, fd, err)
		}
	}

	// Only the preimage path accepts the draft.
	if _, err := ContentSigningBytes(draft); err != nil {
		t.Fatalf("ContentSigningBytes(draft): %v", err)
	}
	if _, err := RevisionID(draft); err != nil {
		t.Fatalf("RevisionID(draft): %v", err)
	}
	// The content-signing input never reads the carried revision id, so a
	// stale one on the pre-signature draft gives the same preimage.
	partial := draftWithSignature(t)
	partial.Header.RevisionID = strings.Repeat("b", sha256.Size*2)
	partialCSB, err := ContentSigningBytes(partial)
	if err != nil {
		t.Fatalf("ContentSigningBytes(pre-signature draft): %v", err)
	}
	if !bytes.Equal(partialCSB, mustContentSigning(t, draft)) {
		t.Fatal("stale revision id changed the content signing input")
	}
}

// TestDraftShapeRules pins the shapes the private draft path accepts: the
// builder draft and the sealed file.
func TestDraftShapeRules(t *testing.T) {
	draft := buildDraft(t)
	if err := validateDraft(draft); err != nil {
		t.Fatalf("builder draft rejected: %v", err)
	}
	if err := validateDraft(buildFile(t)); err != nil {
		t.Fatalf("sealed file rejected as draft: %v", err)
	}

	// Null sig with a non-empty signer or algorithm is not a draft shape the
	// writer holds, on either preimage path.
	for _, mutate := range []func(*Signature){
		func(s *Signature) { s.SignerID = "device-1" },
		func(s *Signature) { s.Alg = SigAlgEd25519 },
	} {
		bad := deepCopyFile(draft)
		mutate(&bad.ContentSignature)
		if err := validateDraft(bad); err == nil {
			t.Fatal("malformed draft validated")
		}
		if _, err := RevisionID(bad); err == nil {
			t.Fatal("malformed draft reached the revision path")
		}
	}
	// A null sig with a revision id is not a draft shape either.
	bad := deepCopyFile(draft)
	bad.Header.RevisionID = buildFile(t).Header.RevisionID
	_, err := RevisionID(bad)
	wantCodeAt(t, err, CodeInvalidValue, "revision_id")
}

// mustContentSigning returns the content signing input of f or fails.
func mustContentSigning(t *testing.T, f *File) []byte {
	t.Helper()
	b, err := ContentSigningBytes(f)
	if err != nil {
		t.Fatal(err)
	}
	return b
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
	// The draft preimages keep the same member sets: the revision input
	// drops revision_id, the content signing input keeps it.
	draft := buildDraft(t)
	revInput, err := revisionDomainInput(draft)
	if err != nil {
		t.Fatal(err)
	}
	wantMembers(t, "draft revision input", jsonMembers(t, revInput), sealedFileMembers[:len(sealedFileMembers)-1])
	wantMembers(t, "draft revision input header", jsonMembers(t, headerOf(t, revInput)), revisionHeaderMembers)
	csb, err := ContentSigningBytes(draft)
	if err != nil {
		t.Fatal(err)
	}
	wantMembers(t, "draft content signing input", jsonMembers(t, csb), sealedFileMembers[:len(sealedFileMembers)-1])
	wantMembers(t, "draft content signing header", jsonMembers(t, headerOf(t, csb)), sealedHeaderMembers)

	// header_sig is not a v1 member of a sealed file.
	withHeaderSig := strings.Replace(string(enc), `,"signed_policy_proofs":`,
		`,"header_sig":{"signer_id":"","alg":"","sig":null},"signed_policy_proofs":`, 1)
	_, err = ParseFile([]byte(withHeaderSig))
	wantCodeAt(t, err, CodeUnknownField, "header_sig")
}

// TestRevisionPreimageFixedVector pins one revision input and id literally, so
// an implementation that changes member order or placeholder bytes fails even
// after regenerating the vector file.
func TestRevisionPreimageFixedVector(t *testing.T) {
	f := buildDraft(t)
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
	// Fixed values shared by the in-memory builder draft and the sealed
	// vector (see testdata/vaultfile-v1-vectors.json, entry "v1-canonical").
	fixedRevisionInputSHA256 = "e80510b9592680ec31a776ba0593edb00d0b080da788a42133cf20428e2767a3"
	fixedRevisionID          = "930c61862a60a3070b4cef23cee7711e086913f678c861dbf25d63b0ff128b5d"
)
