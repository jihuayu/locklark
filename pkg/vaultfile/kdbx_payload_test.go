package vaultfile

import (
	"bytes"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	kdbx "github.com/jihuayu/locklark/third_party/gokeepasslib"
	"github.com/jihuayu/locklark/third_party/gokeepasslib/wrappers"
)

// These tests exercise the public low-level KDBX payload API only. Every
// fixture is a genuine KDBX 4.1 database in the natural unlocked state that
// Open and the internal writer produce: protected values are plaintext and
// nothing is pre-locked before Seal. Targeted negatives prove the valid
// fixture first.

const (
	payloadProtectedSecret = "correct horse battery staple"
	payloadAttachmentName  = "doc.bin"
)

var payloadAttachmentBytes = []byte{0x00, 0x01, 0xff, 0xfe, 'a', 0x00, 'b', 0xff}

// payloadFixtureDB builds an unlocked KDBX 4.1 database with one protected
// password field, one unprotected title and one real binary attachment.
func payloadFixtureDB(t *testing.T) *kdbx.Database {
	t.Helper()
	db := kdbx.NewDatabase(kdbx.WithDatabaseKDBXVersion41())
	group := kdbx.NewGroup()
	group.Name = "Locklark"
	entry := kdbx.NewEntry()
	entry.Values = []kdbx.ValueData{
		{Key: "Title", Value: kdbx.V{Content: "fixture"}},
		{Key: "Password", Value: kdbx.V{Content: payloadProtectedSecret, Protected: wrappers.NewBoolWrapper(true)}},
	}
	ref := kdbx.NewBinaryReference(payloadAttachmentName, payloadFixtureRawBinary(db, payloadAttachmentBytes, 0).ID)
	entry.Binaries = []kdbx.BinaryReference{ref}
	group.Entries = []kdbx.Entry{entry}
	db.Content.Root.Groups = []kdbx.Group{group}
	return db
}

// payloadFixtureRawBinary stores content as one raw KDBX4 inner-header binary
// without re-encoding it, and returns it. The encoder gzip-stores every
// inner-header binary on write, so such bytes are only ever part of a test
// fixture.
func payloadFixtureRawBinary(db *kdbx.Database, content []byte, protection byte) kdbx.Binary {
	binaries := db.Content.InnerHeader.Binaries
	binary := kdbx.Binary{ID: len(binaries), MemoryProtection: protection, Content: content}
	db.Content.InnerHeader.Binaries = append(binaries, binary)
	return binary
}

// payloadFixtureReference appends a binary of content bytes to db's fixture
// entry and references it by name, so the encoder's binary cleanup keeps it.
// The binary is not exported, so for incompressible content its encoded size
// is its raw size plus gzip garbage rather than a compressed copy.
func payloadFixtureReference(db *kdbx.Database, name string, content []byte) kdbx.BinaryReference {
	binary := payloadFixtureRawBinary(db, content, 0)
	ref := kdbx.NewBinaryReference(name, binary.ID)
	entry := &db.Content.Root.Groups[0].Entries[0]
	entry.Binaries = append(entry.Binaries, ref)
	return ref
}

func payloadFixtureCEK(t *testing.T) []byte {
	t.Helper()
	cek := make([]byte, CEKSize)
	if _, err := rand.Read(cek); err != nil {
		t.Fatal(err)
	}
	return cek
}

// sealedFixture seals a fresh fixture and returns the encoded bytes.
func sealedFixture(t *testing.T, db *kdbx.Database, cek []byte) []byte {
	t.Helper()
	sealed, err := SealKDBXPayload(db, cek)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if int64(len(sealed)) > MaxKDBXCiphertextBytes {
		t.Fatalf("Seal returned %d bytes, above cap", len(sealed))
	}
	return sealed
}

func wantPayloadCode(t *testing.T, err error, code string) {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) || e.Code != code {
		t.Fatalf("err = %v, want *Error with code %q", err, code)
	}
}

func TestKDBXPayloadSealOpenRoundTrip(t *testing.T) {
	cek := payloadFixtureCEK(t)
	db := payloadFixtureDB(t)
	// Seal accepts the natural unlocked state: the protected value is
	// plaintext before encoding, because the API locks it itself.
	if got := db.Content.Root.Groups[0].Entries[0].GetContent("Password"); got != payloadProtectedSecret {
		t.Fatalf("fixture is not in unlocked state: %q", got)
	}
	cekCopy := bytes.Clone(cek)
	salt := db.Header.FileHeaders.KdfParameters.Salt

	sealed := sealedFixture(t, db, cek)

	if !isKDBX41(sealed) {
		t.Fatal("sealed payload does not start with the KDBX 4.1 signature")
	}
	if !bytes.Equal(db.Header.FileHeaders.KdfParameters.Salt[:], salt[:]) {
		t.Fatal("Seal replaced the existing random salt")
	}
	if !bytes.Equal(cek, cekCopy) {
		t.Fatal("Seal modified the caller's CEK")
	}

	opened, err := OpenKDBXPayload(sealed, cek)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if opened.Header.Signature == nil || *opened.Header.Signature != kdbx.DefaultKDBX41Sig {
		t.Fatalf("opened signature = %+v, want KDBX 4.1", opened.Header.Signature)
	}
	if p := opened.Header.FileHeaders.KdfParameters; p == nil ||
		!bytes.Equal(p.UUID, kdbx.KdfArgon2id) || p.Version != 0x13 ||
		p.Memory != 16<<20 || p.Iterations != 3 || p.Parallelism != 2 || p.Rounds != 0 ||
		len(p.SecretKey) != 0 || len(p.AssocData) != 0 {
		t.Fatalf("opened KDF parameters = %+v, want fixed Argon2id profile", p)
	}
	if !bytes.Equal(opened.Header.FileHeaders.KdfParameters.Salt[:], salt[:]) {
		t.Fatal("opened salt differs from the preserved random salt")
	}
	entry := opened.Content.Root.Groups[0].Entries[0]
	if !entry.Values[1].Value.Protected.Bool {
		t.Fatal("protected flag lost")
	}
	if got := entry.GetContent("Password"); got != payloadProtectedSecret {
		t.Fatalf("protected value = %q, want round trip", got)
	}
	if got := entry.GetContent("Title"); got != "fixture" {
		t.Fatalf("title = %q", got)
	}
	if bytes.Contains(sealed, []byte(payloadProtectedSecret)) || bytes.Contains(sealed, []byte("fixture")) {
		t.Fatal("sealed payload carries plaintext")
	}
	if len(entry.Binaries) != 1 || entry.Binaries[0].Name != payloadAttachmentName {
		t.Fatalf("binary references = %+v", entry.Binaries)
	}
	binary := opened.FindBinary(entry.Binaries[0].Value.ID)
	if binary == nil || !bytes.Equal(binary.Content, payloadAttachmentBytes) {
		t.Fatalf("attachment bytes did not round trip: %v", binary)
	}
	// Unlocked protected values are the precondition Seal accepts.
	if got := opened.Content.Root.Groups[0].Entries[0].GetContent("Password"); got != payloadProtectedSecret {
		t.Fatal("Open did not leave protected values unlocked")
	}
	if c := opened.Credentials; c != nil && (c.Passphrase != nil || c.Key != nil || c.Windows != nil) {
		t.Fatal("opened database retains credentials")
	}
}

// openUnbounded decodes sealed with no limit, which keeps its content as the
// encoder wrote it: the logical body followed by its PKCS#7 cipher padding.
func openUnbounded(t *testing.T, sealed, cek []byte) *kdbx.Database {
	t.Helper()
	opened := kdbx.NewDatabase()
	opened.Credentials = &kdbx.DBCredentials{Key: bytes.Clone(cek)}
	if err := kdbx.NewDecoder(bytes.NewReader(sealed)).Decode(opened); err != nil {
		t.Fatalf("unbounded decode of a sealed payload: %v", err)
	}
	return opened
}

// trailingCipherPadding reports the length of the 1..16-byte repeated-count
// cipher padding that ends raw, as the encoder appends it, or 0 when raw does
// not end with such a sequence.
func trailingCipherPadding(raw []byte) int {
	if len(raw) == 0 {
		return 0
	}
	n := int(raw[len(raw)-1])
	if n < 1 || n > 16 || n > len(raw) {
		return 0
	}
	for _, b := range raw[len(raw)-n:] {
		if int(b) != n {
			return 0
		}
	}
	return n
}

// TestKDBXPayloadSealOpenNoCompressionRoundTrip checks that the plaintext
// budget of a NoCompressionFlag AES payload counts the logical body and not
// the PKCS#7 cipher padding the encoder appends after it. A body of exactly
// MaxPlaintextBytes seals and opens with the padding removed, one byte more is
// rejected by Seal, and both values round-trip.
func TestKDBXPayloadSealOpenNoCompressionRoundTrip(t *testing.T) {
	cek := payloadFixtureCEK(t)

	// The exact-MaxPlaintextBytes boundary is pinned with AES, whose PKCS#7
	// suffix Open removes before applying the budget. The KDBX 4 default
	// header is ChaCha20, for which the writer padding counts, so the
	// fixture selects AES and its 16-byte IV explicitly.
	withTitle := func(title string) *kdbx.Database {
		db := payloadFixtureDB(t)
		db.Header.FileHeaders.CompressionFlags = kdbx.NoCompressionFlag
		db.Header.FileHeaders.CipherID = kdbx.CipherAES
		db.Header.FileHeaders.EncryptionIV = make([]byte, 16)
		for i := range db.Header.FileHeaders.EncryptionIV {
			db.Header.FileHeaders.EncryptionIV[i] = byte(i + 1)
		}
		db.Content.Root.Groups[0].Entries[0].Values[0].Value.Content = title
		return db
	}

	// One baseline Seal gives the fixture's logical body length, and one
	// gives the serialized size of an unprotected ASCII value. The XML
	// document ends each value with its own tag, so a Title of grow more
	// bytes than "fixture" grows the logical body by grow.
	baseline := withTitle("fixture")
	raw := openUnbounded(t, sealedFixture(t, baseline, cek), cek).Content.RawData
	pad := trailingCipherPadding(raw)
	if pad == 0 {
		t.Fatalf("baseline RawData of %d bytes does not end with cipher padding", len(raw))
	}
	bodyLen := len(raw) - pad
	grow := int(MaxPlaintextBytes) - bodyLen
	if grow <= 0 {
		t.Fatalf("baseline body of %d bytes already reaches MaxPlaintextBytes", bodyLen)
	}
	title := strings.Repeat("a", grow+len("fixture"))
	sealed := sealedFixture(t, withTitle(title), cek)
	if cipher := openUnbounded(t, sealed, cek).Header.FileHeaders.CipherID; !bytes.Equal(cipher, kdbx.CipherAES) {
		t.Fatalf("sealed payload cipher = %x, want AES", cipher)
	}
	opened, err := OpenKDBXPayload(sealed, cek)
	if err != nil {
		t.Fatalf("Open of a %d-byte body: %v", MaxPlaintextBytes, err)
	}
	if got := opened.Content.RawData; int64(len(got)) != MaxPlaintextBytes ||
		trailingCipherPadding(got) != 0 {
		t.Fatalf("opened RawData of %d bytes, want %d without padding", len(got), MaxPlaintextBytes)
	}
	entry := &opened.Content.Root.Groups[0].Entries[0]
	if got := entry.GetContent("Password"); got != payloadProtectedSecret {
		t.Fatalf("protected value = %q, want the sealed value", got)
	}
	if got := entry.GetContent("Title"); got != title {
		t.Fatalf("title of %d bytes did not round trip: got %d", len(title), len(got))
	}

	// One byte more is rejected before any output is returned.
	out, err := SealKDBXPayload(withTitle(title+"a"), cek)
	wantPayloadCode(t, err, CodeKDBXPayloadTooLarge)
	if out != nil {
		t.Fatalf("Seal of a %d-byte body returned %d bytes", MaxPlaintextBytes+1, len(out))
	}
}

// TestKDBXPayloadSealOpenEmptyBinary checks the empty attachment round trip
// through the public API: AddBinary([]byte{}) stores a flag-only inner-header
// binary (no content bytes), which Seal emits and Open's bounded decoder must
// accept as valid rather than reject as too large.
func TestKDBXPayloadSealOpenEmptyBinary(t *testing.T) {
	cek := payloadFixtureCEK(t)
	db := payloadFixtureDB(t)
	const name = "empty.bin"
	binary := db.AddBinary([]byte{})
	entry := &db.Content.Root.Groups[0].Entries[0]
	entry.Binaries = append(entry.Binaries, binary.CreateReference(name))

	sealed := sealedFixture(t, db, cek)

	opened, err := OpenKDBXPayload(sealed, cek)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	openedEntry := opened.Content.Root.Groups[0].Entries[0]
	var ref kdbx.BinaryReference
	found := false
	for _, r := range openedEntry.Binaries {
		if r.Name == name {
			ref, found = r, true
			break
		}
	}
	if !found {
		t.Fatalf("empty attachment reference missing: %+v", openedEntry.Binaries)
	}
	openedBinary := opened.FindBinary(ref.Value.ID)
	if openedBinary == nil || openedBinary.Content == nil || len(openedBinary.Content) != 0 {
		t.Fatalf("empty attachment did not round trip intact: %v", openedBinary)
	}
	// The other fixture attachment is unaffected.
	if other := opened.FindBinary(openedEntry.Binaries[0].Value.ID); other == nil || !bytes.Equal(other.Content, payloadAttachmentBytes) {
		t.Fatalf("existing attachment did not round trip: %v", other)
	}
}

func TestKDBXPayloadSealAppliesProfileAndPreservesSalt(t *testing.T) {
	cek := payloadFixtureCEK(t)
	db := payloadFixtureDB(t)
	salt := db.Header.FileHeaders.KdfParameters.Salt
	// Prior non-profile KDF settings are replaced; the random salt stays.
	db.Header.FileHeaders.KdfParameters.UUID = kdbx.KdfArgon2
	db.Header.FileHeaders.KdfParameters.Version = 0x10
	db.Header.FileHeaders.KdfParameters.Memory = 64 << 20
	db.Header.FileHeaders.KdfParameters.Iterations = 1
	db.Header.FileHeaders.KdfParameters.Parallelism = 1

	sealed := sealedFixture(t, db, cek)
	if p := db.Header.FileHeaders.KdfParameters; p.Version != 0x13 || p.Memory != 16<<20 ||
		p.Iterations != 3 || p.Parallelism != 2 || !bytes.Equal(p.UUID, kdbx.KdfArgon2id) ||
		p.Salt != salt {
		t.Fatalf("sealed header KDF = %+v", p)
	}
	if _, err := OpenKDBXPayload(sealed, cek); err != nil {
		t.Fatalf("Open: %v", err)
	}
}

func TestKDBXPayloadSealInstallsMissingKDFParameters(t *testing.T) {
	cek := payloadFixtureCEK(t)
	db := payloadFixtureDB(t)
	db.Header.FileHeaders.KdfParameters = nil
	sealed := sealedFixture(t, db, cek)
	p := db.Header.FileHeaders.KdfParameters
	if p == nil || p.Salt == [32]byte{} || p.Version != 0x13 {
		t.Fatalf("Seal did not install the profile: %+v", p)
	}
	if _, err := OpenKDBXPayload(sealed, cek); err != nil {
		t.Fatalf("Open: %v", err)
	}
}

func TestKDBXPayloadSealGeneratesSaltWhenUnset(t *testing.T) {
	cek := payloadFixtureCEK(t)
	db := payloadFixtureDB(t)
	db.Header.FileHeaders.KdfParameters.Salt = [32]byte{}
	if _, err := SealKDBXPayload(db, cek); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if db.Header.FileHeaders.KdfParameters.Salt == [32]byte{} {
		t.Fatal("Seal left an all-zero salt")
	}
}

func TestKDBXPayloadSealRandomSaltAndOutput(t *testing.T) {
	cek := payloadFixtureCEK(t)
	first := payloadFixtureDB(t)
	second := payloadFixtureDB(t)
	a := sealedFixture(t, first, cek)
	b := sealedFixture(t, second, cek)
	if first.Header.FileHeaders.KdfParameters.Salt == second.Header.FileHeaders.KdfParameters.Salt {
		t.Fatal("two new databases received the same random salt")
	}
	if bytes.Equal(a, b) {
		t.Fatal("two seals of fresh databases produced identical output")
	}
}

func TestKDBXPayloadSealReplacesAndRestoresPasswordCredentials(t *testing.T) {
	cek := payloadFixtureCEK(t)
	db := payloadFixtureDB(t)
	prior := kdbx.NewPasswordCredentials("prior password")
	priorBytes := bytes.Clone(prior.Passphrase)
	db.Credentials = prior

	sealed := sealedFixture(t, db, cek)

	if db.Credentials != prior {
		t.Fatal("Seal did not restore the exact prior credentials pointer")
	}
	if !bytes.Equal(prior.Passphrase, priorBytes) {
		t.Fatal("Seal modified the prior password credentials")
	}
	if _, err := OpenKDBXPayload(sealed, cek); err != nil {
		t.Fatalf("payload is not bound to the CEK: %v", err)
	}
	// The prior password is not a second credential of the payload.
	if _, err := OpenKDBXPayload(sealed, priorBytes); err == nil {
		t.Fatal("payload opened with the prior password credential")
	}
}

func TestKDBXPayloadSealReplacesAndRestoresKeyCredentials(t *testing.T) {
	cek := payloadFixtureCEK(t)
	db := payloadFixtureDB(t)
	otherKey := make([]byte, CEKSize)
	if _, err := rand.Read(otherKey); err != nil {
		t.Fatal(err)
	}
	prior, err := kdbx.NewKeyDataCredentials(otherKey)
	if err != nil {
		t.Fatal(err)
	}
	priorBytes := bytes.Clone(prior.Key)
	db.Credentials = prior

	sealed := sealedFixture(t, db, cek)

	if db.Credentials != prior {
		t.Fatal("Seal did not restore the exact prior credentials pointer")
	}
	if !bytes.Equal(prior.Key, priorBytes) {
		t.Fatal("Seal modified the prior key credentials")
	}
	if _, err := OpenKDBXPayload(sealed, cek); err != nil {
		t.Fatalf("payload is not bound to the CEK: %v", err)
	}
	if _, err := OpenKDBXPayload(sealed, priorBytes); err == nil {
		t.Fatal("payload opened with the prior key credential")
	}
}

// TestKDBXPayloadXMLShapedCEKIsRawKeyMaterial proves that a CEK whose exact
// 32 bytes are a valid XML document is treated as raw key material, not parsed
// as a keyfile: Seal and Open round-trip under those exact bytes.
func TestKDBXPayloadXMLShapedCEKIsRawKeyMaterial(t *testing.T) {
	cek := xmlShapedCEK(t)
	cekCopy := bytes.Clone(cek)

	sealed := sealedFixture(t, payloadFixtureDB(t), cek)
	if !bytes.Equal(cek, cekCopy) {
		t.Fatal("Seal modified the caller's XML-shaped CEK")
	}

	opened, err := OpenKDBXPayload(sealed, cek)
	if err != nil {
		t.Fatalf("Open with XML-shaped CEK: %v", err)
	}
	if got := opened.Content.Root.Groups[0].Entries[0].GetContent("Password"); got != payloadProtectedSecret {
		t.Fatalf("opened protected value = %q", got)
	}
	if !bytes.Equal(cek, cekCopy) {
		t.Fatal("Open modified the caller's XML-shaped CEK")
	}
}

// xmlShapedCEK returns the bytes of "<KeyFile></KeyFile>" padded with XML
// whitespace to exactly CEKSize bytes. It is a syntactically valid XML
// document, so gokeepasslib's keyfile parse tries and rejects it.
func xmlShapedCEK(t *testing.T) []byte {
	t.Helper()
	const doc = "<KeyFile></KeyFile>"
	cek := make([]byte, CEKSize)
	n := copy(cek, doc)
	for ; n < len(cek); n++ {
		cek[n] = ' '
	}
	if _, err := kdbx.ParseKeyData(cek); err == nil {
		t.Fatal("fixture CEK is not rejected by keyfile parsing")
	}
	return cek
}

func TestKDBXPayloadSealRestoresCredentialsOnError(t *testing.T) {
	cek := payloadFixtureCEK(t)
	cases := map[string]struct {
		mutate func(*kdbx.Database) []byte
		code   string
	}{
		"wrong cek length": {
			mutate: func(*kdbx.Database) []byte { return make([]byte, 31) },
			code:   CodeKDBXPayloadInvalid,
		},
		"encoder failure": {
			mutate: func(db *kdbx.Database) []byte {
				db.Content.Root.Groups = nil
				return cek
			},
			code: CodeKDBXPayloadInvalid,
		},
		"too large": {
			mutate: func(db *kdbx.Database) []byte {
				payloadFixtureOversized(t, db)
				return cek
			},
			code: CodeKDBXPayloadTooLarge,
		},
	}
	priors := map[string]func(t *testing.T) *kdbx.DBCredentials{
		"password": func(t *testing.T) *kdbx.DBCredentials {
			return kdbx.NewPasswordCredentials("prior password")
		},
		"key": func(t *testing.T) *kdbx.DBCredentials {
			creds, err := kdbx.NewKeyDataCredentials(payloadFixtureCEK(t))
			if err != nil {
				t.Fatal(err)
			}
			return creds
		},
	}
	for name, c := range cases {
		for kind, makePrior := range priors {
			t.Run(name+"/"+kind, func(t *testing.T) {
				prior := makePrior(t)
				priorBytes := append(bytes.Clone(prior.Passphrase), prior.Key...)
				db := payloadFixtureDB(t)
				db.Credentials = prior
				out, err := SealKDBXPayload(db, c.mutate(db))
				wantPayloadCode(t, err, c.code)
				if out != nil {
					t.Fatalf("failed Seal returned %d bytes", len(out))
				}
				if db.Credentials != prior {
					t.Fatal("Seal did not restore the prior credentials pointer on error")
				}
				if got := append(bytes.Clone(prior.Passphrase), prior.Key...); !bytes.Equal(got, priorBytes) {
					t.Fatal("Seal modified the prior credentials on error")
				}
			})
		}
	}
}

func TestKDBXPayloadSealRejectsNilAndMalformedShape(t *testing.T) {
	cek := payloadFixtureCEK(t)
	cases := map[string]func() *kdbx.Database{
		"nil database": func() *kdbx.Database { return nil },
		"nil header":   func() *kdbx.Database { db := payloadFixtureDB(t); db.Header = nil; return db },
		"nil signature": func() *kdbx.Database {
			db := payloadFixtureDB(t)
			db.Header.Signature = nil
			return db
		},
		"nil file headers": func() *kdbx.Database {
			db := payloadFixtureDB(t)
			db.Header.FileHeaders = nil
			return db
		},
		"nil hashes": func() *kdbx.Database { db := payloadFixtureDB(t); db.Hashes = nil; return db },
		"nil content": func() *kdbx.Database {
			db := payloadFixtureDB(t)
			db.Content = nil
			return db
		},
		"nil meta": func() *kdbx.Database {
			db := payloadFixtureDB(t)
			db.Content.Meta = nil
			return db
		},
		"nil root": func() *kdbx.Database {
			db := payloadFixtureDB(t)
			db.Content.Root = nil
			return db
		},
		"nil inner header": func() *kdbx.Database {
			db := payloadFixtureDB(t)
			db.Content.InnerHeader = nil
			return db
		},
		"inner header without stream key": func() *kdbx.Database {
			db := payloadFixtureDB(t)
			db.Content.InnerHeader.InnerRandomStreamKey = nil
			return db
		},
		"no root group": func() *kdbx.Database {
			db := payloadFixtureDB(t)
			db.Content.Root.Groups = nil
			return db
		},
		"two root groups": func() *kdbx.Database {
			db := payloadFixtureDB(t)
			db.Content.Root.Groups = append(db.Content.Root.Groups, kdbx.Group{Name: "second"})
			return db
		},
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			db := build()
			prior := kdbx.NewPasswordCredentials("prior password")
			if db != nil {
				db.Credentials = prior
			}
			out, err := SealKDBXPayload(db, cek)
			wantPayloadCode(t, err, CodeKDBXPayloadInvalid)
			if out != nil {
				t.Fatal("rejected Seal returned output")
			}
			// The shape check precedes every modification.
			if db != nil && db.Credentials != prior {
				t.Fatal("rejected Seal changed db.Credentials")
			}
		})
	}
	if errKDBXPayloadInvalid() == errKDBXPayloadInvalid() ||
		errKDBXPayloadTooLarge() == errKDBXPayloadTooLarge() {
		t.Fatal("*Error values are shared between calls")
	}
}

// cipherForIVLength returns the supported cipher IDs and the exact IV length
// each requires.
var supportedCipherIVLengths = map[string]struct {
	id    []byte
	ivLen int
}{
	"aes":      {id: kdbx.CipherAES, ivLen: 16},
	"twofish":  {id: kdbx.CipherTwoFish, ivLen: 16},
	"chacha20": {id: kdbx.CipherChaCha20, ivLen: 12},
}

func TestKDBXPayloadSealRejectsInvalidCipherIV(t *testing.T) {
	cek := payloadFixtureCEK(t)

	// The reported reproducer: an AES cipher ID with a missing IV used to
	// panic in CBC setup inside the encoder.
	t.Run("reproducer AES with missing IV", func(t *testing.T) {
		payloadAssertSealRejectedUnmodified(t, cek, func(db *kdbx.Database) {
			db.Header.FileHeaders.CipherID = bytes.Clone(kdbx.CipherAES)
			db.Header.FileHeaders.EncryptionIV = nil
		})
	})

	cases := map[string]struct {
		cipherID []byte
		iv       []byte
	}{
		"nil cipher ID":       {nil, payloadIV(12)},
		"unknown cipher ID":   {payloadUnknownCipherID(), payloadIV(16)},
		"aes nil IV":          {kdbx.CipherAES, nil},
		"aes 12-byte IV":      {kdbx.CipherAES, payloadIV(12)},
		"aes 15-byte IV":      {kdbx.CipherAES, payloadIV(15)},
		"aes 17-byte IV":      {kdbx.CipherAES, payloadIV(17)},
		"twofish nil IV":      {kdbx.CipherTwoFish, nil},
		"twofish 12-byte IV":  {kdbx.CipherTwoFish, payloadIV(12)},
		"twofish 32-byte IV":  {kdbx.CipherTwoFish, payloadIV(32)},
		"chacha20 nil IV":     {kdbx.CipherChaCha20, nil},
		"chacha20 8-byte IV":  {kdbx.CipherChaCha20, payloadIV(8)},
		"chacha20 16-byte IV": {kdbx.CipherChaCha20, payloadIV(16)},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			cipherID, iv := c.cipherID, c.iv
			payloadAssertSealRejectedUnmodified(t, cek, func(db *kdbx.Database) {
				db.Header.FileHeaders.CipherID = bytes.Clone(cipherID)
				db.Header.FileHeaders.EncryptionIV = bytes.Clone(iv)
			})
		})
	}

	// Exact IV lengths are accepted, so the table above rejects only
	// genuinely invalid inputs.
	for name, c := range supportedCipherIVLengths {
		t.Run("accepts "+name, func(t *testing.T) {
			db := payloadFixtureDB(t)
			db.Header.FileHeaders.CipherID = bytes.Clone(c.id)
			db.Header.FileHeaders.EncryptionIV = payloadIV(c.ivLen)
			sealed, err := SealKDBXPayload(db, cek)
			if err != nil {
				t.Fatalf("Seal: %v", err)
			}
			opened, err := OpenKDBXPayload(sealed, cek)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if got := opened.Content.Root.Groups[0].Entries[0].GetContent("Password"); got != payloadProtectedSecret {
				t.Fatalf("protected value = %q, want round trip", got)
			}
		})
	}
}

func payloadIV(n int) []byte {
	iv := make([]byte, n)
	if _, err := rand.Read(iv); err != nil {
		panic(err)
	}
	return iv
}

func payloadUnknownCipherID() []byte {
	return []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	}
}

// payloadAssertSealRejectedUnmodified mutates a fresh fixture with mutate,
// seals it and asserts the generic invalid error with nil output and a
// database left exactly as it was: prior credential pointer, header values
// and protected plaintext.
func payloadAssertSealRejectedUnmodified(t *testing.T, cek []byte, mutate func(*kdbx.Database)) {
	t.Helper()
	db := payloadFixtureDB(t)
	prior := kdbx.NewPasswordCredentials("prior password")
	db.Credentials = prior
	mutate(db)

	headers := db.Header.FileHeaders
	cipherID := bytes.Clone(headers.CipherID)
	iv := bytes.Clone(headers.EncryptionIV)
	kdf := *headers.KdfParameters
	salt := kdf.Salt
	signature := *db.Header.Signature

	entry := db.Content.Root.Groups[0].Entries[0]
	if got := entry.GetContent("Password"); got != payloadProtectedSecret {
		t.Fatalf("fixture is not in unlocked state: %q", got)
	}

	out, err := SealKDBXPayload(db, cek)
	wantPayloadCode(t, err, CodeKDBXPayloadInvalid)
	if out != nil {
		t.Fatalf("rejected Seal returned %d bytes", len(out))
	}

	if db.Credentials != prior {
		t.Fatal("rejected Seal changed the prior credentials pointer")
	}
	if got := headers.CipherID; !bytes.Equal(got, cipherID) {
		t.Fatalf("rejected Seal changed CipherID to %x", got)
	}
	if !bytes.Equal(headers.EncryptionIV, iv) {
		t.Fatal("rejected Seal changed EncryptionIV")
	}
	if p := headers.KdfParameters; p == nil || !bytes.Equal(p.UUID, kdf.UUID) ||
		p.Version != kdf.Version || p.Memory != kdf.Memory ||
		p.Iterations != kdf.Iterations || p.Parallelism != kdf.Parallelism ||
		p.Rounds != kdf.Rounds || p.Salt != salt {
		t.Fatalf("rejected Seal changed KDF parameters: %+v", p)
	}
	if *db.Header.Signature != signature {
		t.Fatal("rejected Seal changed the header signature")
	}
	if got := entry.GetContent("Password"); got != payloadProtectedSecret {
		t.Fatalf("rejected Seal changed the protected plaintext to %q", got)
	}
	if !entry.Values[1].Value.Protected.Bool {
		t.Fatal("rejected Seal cleared the protected flag")
	}
}

func TestKDBXPayloadSealRejectsWrongVersionAndCEK(t *testing.T) {
	cek := payloadFixtureCEK(t)
	for name, cek := range map[string][]byte{"nil": nil, "empty": {}, "short": make([]byte, 31), "long": make([]byte, 33)} {
		t.Run("cek "+name, func(t *testing.T) {
			db := payloadFixtureDB(t)
			prior := kdbx.NewPasswordCredentials("prior password")
			db.Credentials = prior
			if out, err := SealKDBXPayload(db, cek); out != nil {
				t.Fatal("rejected Seal returned output")
			} else {
				wantPayloadCode(t, err, CodeKDBXPayloadInvalid)
			}
			if db.Credentials != prior {
				t.Fatal("rejected Seal modified db.Credentials")
			}
		})
	}
	for name, sig := range map[string]kdbx.Signature{"kdbx 3.1": kdbx.DefaultKDBX3Sig, "kdbx 4.0": kdbx.DefaultKDBX40Sig} {
		t.Run(name, func(t *testing.T) {
			db := payloadFixtureDB(t)
			s := sig
			db.Header.Signature = &s
			if out, err := SealKDBXPayload(db, cek); out != nil {
				t.Fatal("rejected Seal returned output")
			} else {
				wantPayloadCode(t, err, CodeKDBXPayloadInvalid)
			}
		})
	}
}

// payloadOpenRejected asserts that Open fails with the generic invalid code
// and returns no database.
func payloadOpenRejected(t *testing.T, ciphertext, cek []byte) {
	t.Helper()
	db, err := OpenKDBXPayload(ciphertext, cek)
	wantPayloadCode(t, err, CodeKDBXPayloadInvalid)
	if db != nil {
		t.Fatal("failed Open returned a database")
	}
}

func TestKDBXPayloadOpenRejectsWrongCEK(t *testing.T) {
	cek := payloadFixtureCEK(t)
	sealed := sealedFixture(t, payloadFixtureDB(t), cek)
	wrong := bytes.Clone(cek)
	wrong[0] ^= 0x01
	payloadOpenRejected(t, sealed, wrong)
	other := payloadFixtureCEK(t)
	payloadOpenRejected(t, sealed, other)
}

// payloadFirstContentBlock is the offset of the first byte of the first KDBX
// content block, which is its 32-byte HMAC. KDBX4 blocks are laid out as
// HMAC(32) | length(4) | data and start right after the 32-byte header SHA-256
// and the 32-byte header HMAC. For every other header field except the KDF
// parameters the field is 13 bytes: 1-byte type, 4-byte length and 8-byte
// value (the 2-byte Comment length and the 16-byte EncryptionIV included). The
// KDF parameters are this profile's three Argon2id groups: `$argon2id`
// (13 + 9), `M` memory (13 + 8), `P` parallelism (13 + 4), `I` iterations
// (13 + 8), `S` salt (13 + 32), `V` version (13 + 8); 60 bytes plus one
// AjIV lifetime record (5 + 8) and two 36-byte group terminators. The block
// offset is therefore 12 + 196 + 4*13 + 33 + 60 + 13 + 72 + 64 = 489.
const payloadFirstContentBlock = 489

func TestKDBXPayloadOpenRejectsTamperedContent(t *testing.T) {
	cek := payloadFixtureCEK(t)
	sealed := sealedFixture(t, payloadFixtureDB(t), cek)
	if len(sealed) <= payloadFirstContentBlock+36 {
		t.Fatalf("sealed payload of %d bytes has no content block", len(sealed))
	}
	// The HMAC of the terminator block that the encoder appends after the
	// last content block is not compared by the decoder, so the trailing
	// bytes are not a place to tamper. A single flipped byte in the
	// authenticated HMAC of the first content block must be rejected.
	tampered := bytes.Clone(sealed)
	tampered[payloadFirstContentBlock] ^= 0x01
	changed := 0
	for i := range tampered {
		if tampered[i] != sealed[i] {
			changed++
		}
	}
	if changed != 1 {
		t.Fatalf("tampered input changed %d bytes, want exactly 1", changed)
	}
	payloadOpenRejected(t, tampered, cek)

	// A single flipped byte in the content data of that block is rejected by
	// the same block authentication.
	tampered = bytes.Clone(sealed)
	tampered[payloadFirstContentBlock+36] ^= 0x01
	payloadOpenRejected(t, tampered, cek)
}

func TestKDBXPayloadOpenPrechecks(t *testing.T) {
	cek := payloadFixtureCEK(t)
	sealed := sealedFixture(t, payloadFixtureDB(t), cek)
	notKDBX := bytes.Clone(sealed)
	notKDBX[3] ^= 0xff
	// A valid KDBX 4.1 signature with a cap crossing input proves the size
	// precheck runs before any parsing.
	oversizedValidHeader := append(bytes.Clone(sealed), make([]byte, MaxKDBXCiphertextBytes-len(sealed)+1)...)

	cases := map[string]struct {
		ciphertext []byte
		cek        []byte
		code       string
	}{
		"empty":             {nil, cek, CodeKDBXPayloadInvalid},
		"short":             {sealed[:11], cek, CodeKDBXPayloadInvalid},
		"bad signature":     {notKDBX, cek, CodeKDBXPayloadInvalid},
		"nil cek":           {sealed, nil, CodeKDBXPayloadInvalid},
		"empty cek":         {sealed, []byte{}, CodeKDBXPayloadInvalid},
		"short cek":         {sealed, cek[:31], CodeKDBXPayloadInvalid},
		"long cek":          {sealed, append(bytes.Clone(cek), 0), CodeKDBXPayloadInvalid},
		"oversized":         {oversizedValidHeader, cek, CodeKDBXPayloadTooLarge},
		"oversized garbage": {make([]byte, MaxKDBXCiphertextBytes+1), nil, CodeKDBXPayloadTooLarge},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			db, err := OpenKDBXPayload(c.ciphertext, c.cek)
			wantPayloadCode(t, err, c.code)
			if db != nil {
				t.Fatal("failed Open returned a database")
			}
		})
	}
}

// payloadIncompressible returns n pseudo-random bytes, used where a size
// budget must be reached by data gzip cannot shrink.
func payloadIncompressible(t *testing.T, n int) []byte {
	t.Helper()
	content := make([]byte, n)
	if _, err := rand.Read(content); err != nil {
		t.Fatal(err)
	}
	return content
}

// payloadOversizeBinaryBytes is the size of the referenced incompressible
// binary that makes Seal output exceed MaxKDBXCiphertextBytes. A sealed
// fixture of 1 MiB encodes to 1,050,281 bytes, so the fixed framing stays
// under 4 KiB; a binary 4 KiB below the cap therefore cannot be compressed
// enough to fit.
const payloadOversizeBinaryBytes = MaxKDBXCiphertextBytes - 4096

// payloadFixtureOversized adds a referenced binary whose encoded size pushes
// Seal output past MaxKDBXCiphertextBytes.
func payloadFixtureOversized(t *testing.T, db *kdbx.Database) {
	t.Helper()
	payloadFixtureReference(db, "huge.bin", payloadIncompressible(t, payloadOversizeBinaryBytes))
}

// TestKDBXPayloadOpenRejectsExpandedBodyOverBudget documents the bounded
// decoder's expanded-body budget through the public API. Seal now bounds the
// plaintext body Open expands, so a payload over MaxPlaintextBytes by a
// registered attachment can no longer be sealed: Seal reports
// CodeKDBXPayloadTooLarge with nil output instead. The decoder's own
// expanded-body rejection is covered by the vendored decoder tests.
func TestKDBXPayloadOpenRejectsExpandedBodyOverBudget(t *testing.T) {
	cek := payloadFixtureCEK(t)
	db := payloadFixtureDB(t)
	// An attachment just past MaxPlaintextBytes makes the InnerHeader plus
	// document plaintext over budget; its incompressible content would have
	// gzipped stored it well under MaxKDBXCiphertextBytes.
	payloadFixtureReference(db, "large.bin", payloadIncompressible(t, MaxPlaintextBytes+1))
	prior := kdbx.NewPasswordCredentials("prior password")
	db.Credentials = prior
	out, err := SealKDBXPayload(db, cek)
	wantPayloadCode(t, err, CodeKDBXPayloadTooLarge)
	if out != nil {
		t.Fatalf("over-budget Seal returned %d bytes", len(out))
	}
	if db.Credentials != prior {
		t.Fatal("Seal did not restore the prior credentials after the plaintext budget")
	}
}

// TestKDBXPayloadSealRejectsOversizedOutput checks Seal's end-to-end rejection
// of a fixture whose annotated output would exceed MaxKDBXCiphertextBytes.
// With the plaintext budget in force this incompressible attachment now
// exceeds MaxPlaintextBytes first, so this test fails on the plaintext limit
// and does not reach the ciphertext collector: that cap is proven directly by
// TestBoundedKDBXBufferCiphertextCap.
func TestKDBXPayloadSealRejectsOversizedOutput(t *testing.T) {
	cek := payloadFixtureCEK(t)
	db := payloadFixtureDB(t)
	payloadFixtureOversized(t, db)
	prior := kdbx.NewPasswordCredentials("prior password")
	db.Credentials = prior
	out, err := SealKDBXPayload(db, cek)
	wantPayloadCode(t, err, CodeKDBXPayloadTooLarge)
	if out != nil {
		t.Fatalf("oversized Seal returned %d bytes", len(out))
	}
	if db.Credentials != prior {
		t.Fatal("Seal did not restore the prior credentials after the cap")
	}
}

// TestBoundedKDBXBufferCiphertextCap proves Seal's output collector directly,
// at exactly its cap and one byte over. An over-cap Seal cannot reach the
// collector through the public API any more: an incompressible attachment
// large enough to overflow it exceeds MaxPlaintextBytes first, as
// TestKDBXPayloadSealRejectsOversizedOutput now fails on the plaintext limit.
// The collector is therefore exercised on the writer Seal uses, with a small
// cap: every byte within the cap is retained, exactly the cap included, and a
// write crossing it clears what was retained and is then accepted and
// discarded with every later byte.
func TestBoundedKDBXBufferCiphertextCap(t *testing.T) {
	// Three chunk-sized writes are the cap, so the cap lands on a write
	// boundary; the over-cap stream adds one more chunk.
	const (
		capBytes     = 3 * kdbxChunkBytes
		overCapBytes = capBytes + kdbxChunkBytes
	)
	data := make([]byte, overCapBytes)
	for i := range data {
		data[i] = byte(i)
	}
	// writeAll feeds n bytes in encoder-sized writes.
	writeAll := func(b *boundedKDBXBuffer, n int) {
		t.Helper()
		for off := 0; off < n; off += kdbxChunkBytes {
			end := min(off+kdbxChunkBytes, n)
			if got, err := b.Write(data[off:end]); err != nil || got != end-off {
				t.Fatalf("write returned %d, %v; want %d, nil", got, err, end-off)
			}
		}
	}

	t.Run("exact limit", func(t *testing.T) {
		b := &boundedKDBXBuffer{max: capBytes}
		writeAll(b, capBytes)
		if b.exceeded || b.kept != capBytes {
			t.Fatalf("kept %d bytes, exceeded %v, want exactly %d", b.kept, b.exceeded, capBytes)
		}
		// Seal takes the bytes on success and still releases the collector
		// on return: the returned bytes must survive that release.
		got := b.take()
		b.release()
		if !bytes.Equal(got, data[:capBytes]) {
			t.Fatalf("collector returned %d bytes that differ from the %d written", len(got), capBytes)
		}
	})

	t.Run("one byte over", func(t *testing.T) {
		b := &boundedKDBXBuffer{max: capBytes - 1}
		writeAll(b, capBytes)
		if !b.exceeded || b.kept != capBytes {
			t.Fatalf("kept %d bytes, exceeded %v, want the cap crossed", b.kept, b.exceeded)
		}
		if n := b.buf.Len(); n != 0 {
			t.Fatalf("over-cap collector retains %d bytes", n)
		}
		// Later writes are still accepted and discarded without reviving
		// the buffer.
		writeAll(b, overCapBytes)
		if b.buf.Len() != 0 || b.kept != capBytes+overCapBytes {
			t.Fatalf("after the cap collector retains %d bytes of %d", b.buf.Len(), b.kept)
		}
		b.release()
		if got := b.take(); len(got) != 0 {
			t.Fatalf("over-cap collector returned %d bytes", len(got))
		}
	})
}

// TestKDBXPayloadSealRejectsCompressiblePlaintextOverBudget is the regression
// for the plaintext budget: a valid, unprotected Notes value of
// MaxPlaintextBytes-2 bytes makes the KDBX4 plaintext body (InnerHeader plus
// XML) exceed MaxPlaintextBytes, while the old Encode gzipped that body to a
// few dozen kilobytes and wrote it. Seal must report CodeKDBXPayloadTooLarge
// with nil bytes before it compresses or encrypts that body.
func TestKDBXPayloadSealRejectsCompressiblePlaintextOverBudget(t *testing.T) {
	cek := payloadFixtureCEK(t)
	db := payloadFixtureDB(t)
	notes := payloadAlternatingASCII(MaxPlaintextBytes - 2)
	db.Content.Root.Groups[0].Entries[0].Values = append(
		db.Content.Root.Groups[0].Entries[0].Values, kdbx.ValueData{Key: "Notes", Value: kdbx.V{Content: notes}},
	)
	prior := kdbx.NewPasswordCredentials("prior password")
	db.Credentials = prior
	out, err := SealKDBXPayload(db, cek)
	wantPayloadCode(t, err, CodeKDBXPayloadTooLarge)
	if out != nil {
		t.Fatalf("over-budget Seal returned %d bytes", len(out))
	}
	if db.Credentials != prior {
		t.Fatal("Seal did not restore the prior credentials after the plaintext budget")
	}

	// The same fixture with a small Notes value is accepted, so the budget
	// rejects only the expanded document.
	plain := payloadFixtureDB(t)
	plain.Content.Root.Groups[0].Entries[0].Values = append(
		plain.Content.Root.Groups[0].Entries[0].Values, kdbx.ValueData{Key: "Notes", Value: kdbx.V{Content: "compact value"}},
	)
	if sealed, err := SealKDBXPayload(plain, cek); err != nil || sealed == nil {
		t.Fatalf("fixture within budget rejected: %v", err)
	}
}

// payloadAlternatingASCII returns n bytes alternating "ab", a valid string
// value that gzip shrinks to about a thousandth of its size.
func payloadAlternatingASCII(n int) string {
	var b strings.Builder
	b.Grow(n)
	for i := 0; i < n; i++ {
		b.WriteByte("ab"[i%2])
	}
	return b.String()
}
