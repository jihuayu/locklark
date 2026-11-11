package gokeepasslib

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"math"
	"strings"
	"testing"

	"github.com/jihuayu/locklark/third_party/gokeepasslib/wrappers"
)

// encoderLimitTestNoteBytes is the size of the highly compressible Notes
// value of the entry encoderLimitTestDatabase builds.
const encoderLimitTestNoteBytes = 1 << 20

// encoderLimitTestPassword is the known plaintext of the protected Password
// value of encoderLimitTestDatabase.
const encoderLimitTestPassword = "correct horse battery staple"

// encoderLimitTestDatabase is a valid KDBX 4.1 database with a protected
// Password value and an unprotected, highly compressible Notes value of
// encoderLimitTestNoteBytes bytes. The Notes value keeps the serialized
// plaintext far above any practical budget while its gzip output stays tiny,
// which is the case a ciphertext size check alone cannot catch. The returned
// database is in the natural unlocked state (protected values in plaintext):
// Encoder.Encode and EncodeWithLimits lock protected entries themselves, so a
// fixture passed to either of them directly must be pre-locked with
// lockEncoderLimitFixture first.
func encoderLimitTestDatabase(t *testing.T) *Database {
	t.Helper()
	db := NewDatabase(WithDatabaseKDBXVersion41())
	db.Header.FileHeaders.KdfParameters = limitTestKDF()
	group := NewGroup()
	group.Name = "Locklark encoder limits"
	entry := NewEntry()
	entry.Values = []ValueData{
		{Key: "Title", Value: V{Content: "bounded encode"}},
		{Key: "Password", Value: V{Content: encoderLimitTestPassword, Protected: wrappers.NewBoolWrapper(true)}},
		{Key: "Notes", Value: V{Content: strings.Repeat("a", encoderLimitTestNoteBytes)}},
	}
	group.Entries = []Entry{entry}
	db.Content.Root.Groups = []Group{group}
	// A real, registered attachment so binary cleanup keeps it.
	ref := db.AddBinary([]byte("attachment")).CreateReference("attachment.bin")
	db.Content.Root.Groups[0].Entries[0].Binaries = append(db.Content.Root.Groups[0].Entries[0].Binaries, ref)
	db.Credentials = limitTestCredentials(t)
	return db
}

// lockEncoderLimitFixture puts a fixture in the state the encoder requires of
// its direct callers: protected values locked. The encoder unlocks and relocks
// them itself, and an unlocked input would be locked twice, hiding the
// protected value from decoders.
func lockEncoderLimitFixture(t *testing.T, db *Database) *Database {
	t.Helper()
	if err := db.LockProtectedEntries(); err != nil {
		t.Fatalf("locking fixture: %v", err)
	}
	return db
}

// countWriter records how many bytes were written to it.
type countWriter struct{ n int64 }

func (c *countWriter) Write(p []byte) (int, error) {
	c.n += int64(len(p))
	return len(p), nil
}

// streamedXMLContent is the XML document the encoder's streaming path writes
// for content: the XML header followed by one xml.Encoder write configured as
// xml.MarshalIndent configures it.
func streamedXMLContent(t *testing.T, content *DBContent) []byte {
	t.Helper()
	var b bytes.Buffer
	b.Write(xmlHeader)
	enc := xml.NewEncoder(&b)
	enc.Indent("", "\t")
	if err := enc.Encode(content); err != nil {
		t.Fatal(err)
	}
	if err := enc.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// encodedDocument runs a locked db through encode and returns the XML
// document the encoder serialized: it decodes the encoded database, whose
// protected values the decoder leaves locked as the encoder wrote them, and
// streams the document of that content.
func encodedDocument(t *testing.T, db *Database, encode func(*Encoder, *Database) error) ([]byte, error) {
	t.Helper()
	var out bytes.Buffer
	if err := encode(NewEncoder(&out), db); err != nil {
		return nil, err
	}
	decoded := NewDatabase()
	decoded.Credentials = db.Credentials
	if err := NewDecoder(bytes.NewReader(out.Bytes())).Decode(decoded); err != nil {
		return nil, err
	}
	return streamedXMLContent(t, decoded.Content), nil
}

// maxXMLContent is the XML document marshalXMLContent wrote: the XML header
// followed by xml.MarshalIndent of content. It is the reference the streaming
// path must reproduce byte for byte.
func maxXMLContent(t *testing.T, content DBContent) []byte {
	t.Helper()
	rawContent, err := xml.MarshalIndent(content, "", "\t")
	if err != nil {
		t.Fatal(err)
	}
	return append(append([]byte(nil), xmlHeader...), rawContent...)
}

// TestEncodeStreamsXMLIdenticalToMarshalIndent proves the encoder's streaming
// XML write is byte-for-byte the xml.MarshalIndent form, on representative
// KDBX content: the full fixture, the minimal database, a database with
// groups, histories, metadata and inner-header binaries, and KDBX 3.1 content.
// The production pipeline is driven twice, once through EncodeWithLimits, so
// the comparison covers the path Seal uses, and once through the collector.
func TestEncodeStreamsXMLIdenticalToMarshalIndent(t *testing.T) {
	nested := limitTestDatabase(t)
	child := NewGroup()
	child.Name = "child <&> \"quoted\""
	entry := NewEntry()
	entry.Values = []ValueData{
		{Key: "Title", Value: V{Content: "line one\nline two\ttabbed"}},
		{Key: "UserName", Value: V{Content: "ünïcödé \u2028 separator</Note><Note>"}},
	}
	history := NewEntry()
	history.Values = []ValueData{{Key: "Title", Value: V{Content: "older"}}}
	entry.Histories = []History{{Entries: []Entry{history}}}
	child.Entries = []Entry{entry}
	child.Groups = []Group{NewGroup()}
	child.Groups[0].Name = "grandchild"
	nested.Content.Root.Groups = append(nested.Content.Root.Groups, child)
	nested.Content.Meta.Binaries = Binaries{}
	nested.AddBinary([]byte{0, 1, 2, 0xff})

	kdbx31 := NewDatabase()
	kdbx31.Header.FileHeaders.KdfParameters = limitTestKDF()
	group31 := NewGroup()
	group31.Name = "v3.1"
	entry31 := NewEntry()
	entry31.Values = []ValueData{{Key: "Title", Value: V{Content: "legacy"}}}
	group31.Entries = []Entry{entry31}
	kdbx31.Content.Root.Groups = []Group{group31}
	kdbx31.Credentials = limitTestCredentials(t)

	for name, db := range map[string]*Database{
		"fixture":  encoderLimitTestDatabase(t),
		"minimal":  limitTestDatabase(t),
		"nested":   nested,
		"kdbx 3.1": kdbx31,
	} {
		t.Run(name, func(t *testing.T) {
			lockEncoderLimitFixture(t, db)
			if db.Header.IsKdbx4() {
				// The encoder clears this before it serializes.
				db.Content.Meta.HeaderHash = ""
			} else {
				db.Content.Meta.HeaderHash = "kdbx 3.1 keeps its base64 header hash"
			}
			want := maxXMLContent(t, *db.Content)
			if got := streamedXMLContent(t, db.Content); !bytes.Equal(got, want) {
				t.Fatalf("streaming helper output of %d bytes differs from xml.MarshalIndent (%d bytes)", len(got), len(want))
			}
			plaintext, err := newPlaintextContent(db.Content.InnerHeader, db.Header.IsKdbx4(), 0)
			if err != nil {
				t.Fatal(err)
			}
			if err := plaintext.writeDocument(db.Content); err != nil {
				t.Fatal(err)
			}
			if got := plaintext.document.Bytes(); !bytes.Equal(got, want) {
				t.Fatalf("streamed XML of %d bytes differs from xml.MarshalIndent (%d bytes)", len(got), len(want))
			}

			// The same content through the whole encoder: the document it
			// writes is the reference MarshalIndent form, whether or not it
			// runs under a budget.
			for name, encode := range map[string]func(*Encoder, *Database) error{
				"encode": func(e *Encoder, db *Database) error { return e.Encode(db) },
				"bounded": func(e *Encoder, db *Database) error {
					return e.EncodeWithLimits(db, EncodeLimits{MaxPlaintextBytes: 1 << 24})
				},
			} {
				document, err := encodedDocument(t, db, encode)
				if err != nil {
					t.Fatalf("%s: %v", name, err)
				}
				// The encoder serializes the normalized content with its
				// protected values locked, which is the state it leaves db
				// in after encoding, so the reference is its streaming
				// form.
				if want := streamedXMLContent(t, db.Content); !bytes.Equal(document, want) {
					t.Fatalf("%s: document of %d bytes differs from xml.MarshalIndent (%d bytes)", name, len(document), len(want))
				}
			}
		})
	}
}

// encoderLimitTestPlaintext returns the exact plaintext body size of db as
// EncodeWithLimits measures it, without the Encoder's test hooks and without
// relying on it to prove the budget: it runs the encoder's normalization on
// db, exactly as the encoder does, and assembles the InnerHeader and the
// document with the collector itself. The plaintext body is a function of the
// locked content, so db is in the state the encoder requires of a direct
// caller, and it stays in it: that is the state the encoder serializes.
func encoderLimitTestPlaintext(t *testing.T, db *Database) uint64 {
	t.Helper()
	if err := db.UnlockProtectedEntries(); err != nil {
		t.Fatal(err)
	}
	if err := db.LockProtectedEntries(); err != nil {
		t.Fatal(err)
	}
	if err := db.ensureRequiredKdbxFormatVersion(); err != nil {
		t.Fatal(err)
	}
	db.ensureKdbxFormatVersion()

	plaintext, err := newPlaintextContent(db.Content.InnerHeader, db.Header.IsKdbx4(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := plaintext.writeDocument(db.Content); err != nil {
		t.Fatal(err)
	}
	return uint64(plaintext.written)
}

func TestEncodeWithLimitsRejectsCompressiblePlaintextOverBudget(t *testing.T) {
	// The unbounded Encode of the same database succeeds and is far smaller
	// than the plaintext it is built from.
	var unbounded bytes.Buffer
	if err := NewEncoder(&unbounded).Encode(lockEncoderLimitFixture(t, encoderLimitTestDatabase(t))); err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if unbounded.Len() >= encoderLimitTestNoteBytes/4 {
		t.Fatalf("fixture output of %d bytes is not highly compressible", unbounded.Len())
	}

	// One byte under the exact body size is rejected: the budget covers the
	// whole InnerHeader plus XML body. The fixture gets its own exact size,
	// because the metadata timestamps in the document have a
	// representation-dependent length.
	db := lockEncoderLimitFixture(t, encoderLimitTestDatabase(t))
	plaintext := encoderLimitTestPlaintext(t, db)
	if plaintext <= encoderLimitTestNoteBytes {
		t.Fatalf("fixture plaintext is %d bytes, want more than the Notes value", plaintext)
	}
	assertEncodeRejected(t, db, plaintext-1, unbounded.Len())
}

// assertEncodeRejected checks that EncodeWithLimits with budget rejects a
// locked db for its plaintext size and writes nothing beyond the header that
// Encode's established write order emits first.
func assertEncodeRejected(t *testing.T, db *Database, budget uint64, encodedLen int) {
	t.Helper()
	var out countWriter
	err := NewEncoder(&out).EncodeWithLimits(db, EncodeLimits{MaxPlaintextBytes: int64(budget)})
	if !errors.Is(err, ErrEncodeLimitExceeded) {
		t.Fatalf("EncodeWithLimits err = %v, want ErrEncodeLimitExceeded", err)
	}
	if out.n == 0 || out.n >= int64(encodedLen) {
		t.Fatalf("rejected encode wrote %d bytes, want only its header", out.n)
	}
}

// TestEncodeWithLimitsCollectsWithoutOneExtraByte pins the plaintext
// collector: a streaming XML write that would cross the budget retains
// nothing, the collected length never passes max, and the InnerHeader is
// accepted up to exactly its encoded size.
func TestEncodeWithLimitsCollectsWithoutOneExtraByte(t *testing.T) {
	// A large Notes value makes the streaming writes reach the budget as
	// they are produced. Fixtures are compared by the body they measured, not
	// by an absolute byte count: the KDBX4 SettingsChanged timestamp has
	// one-second precision, so two fixtures are not guaranteed to serialize to
	// the same length. Each budget is checked against the fixture it runs on,
	// for both the exact size and one byte over it.
	newFixture := func() *Database { return lockEncoderLimitFixture(t, encoderLimitTestDatabase(t)) }

	cases := map[string]struct {
		collect bool
		over    bool
	}{
		"exact":     {collect: true},
		"one over":  {collect: true, over: true},
		"one under": {},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			db := newFixture()
			size := int64(encoderLimitTestPlaintext(t, db))
			budget := size
			if !c.collect {
				budget -= 1
			} else if c.over {
				budget += 1
			}
			plaintext, err := newPlaintextContent(db.Content.InnerHeader, db.Header.IsKdbx4(), budget)
			if err != nil {
				t.Fatal(err)
			}
			err = plaintext.writeDocument(db.Content)
			if c.collect {
				if err != nil {
					t.Fatalf("budget %d of exact %d: %v", budget, size, err)
				}
				if plaintext.written != size {
					t.Fatalf("collected %d bytes, want %d", plaintext.written, size)
				}
			} else {
				if !errors.Is(err, ErrEncodeLimitExceeded) {
					t.Fatalf("budget %d of exact %d err = %v, want ErrEncodeLimitExceeded", budget, size, err)
				}
				if plaintext.written > budget {
					t.Fatalf("rejected collector holds %d bytes, above its budget %d", plaintext.written, budget)
				}
			}
			if int64(plaintext.document.Len()) != plaintext.written-int64(plaintext.headers.Len()) {
				t.Fatalf("document holds %d bytes, written %d with a %d-byte header",
					plaintext.document.Len(), plaintext.written, plaintext.headers.Len())
			}
		})
	}
}

// TestEncodeWithLimitsInnerHeaderBoundary pins the InnerHeader's exact
// over-budget boundary: it reserves and appends into its destination buffer,
// and a budget one byte under its encoded size rejects it without retaining a
// byte.
func TestEncodeWithLimitsInnerHeaderBoundary(t *testing.T) {
	ih := binaryInnerHeader(t, 64)
	size := ih.encodedSize()
	if size <= 64+1 {
		t.Fatalf("fixture inner header of %d bytes", size)
	}

	for name, c := range map[string]struct {
		budget int64
		accept bool
	}{
		"exact":      {size, true},
		"one under":  {size - 1, false},
		"one over":   {size + 1, true},
		"well under": {size / 2, false},
	} {
		t.Run(name, func(t *testing.T) {
			plaintext, err := newPlaintextContent(ih, true, c.budget)
			if c.accept {
				if err != nil {
					t.Fatalf("budget %d of %d bytes: %v", c.budget, size, err)
				}
				if plaintext.written != size || int64(plaintext.headers.Len()) != size {
					t.Fatalf("collected %d/%d bytes, want %d", plaintext.written, plaintext.headers.Len(), size)
				}
				if !bytes.Equal(plaintext.headers.Bytes(), innerHeaderBytes(t, ih)) {
					t.Fatal("InnerHeader bytes differ from writeTo")
				}
			} else {
				if !errors.Is(err, ErrEncodeLimitExceeded) {
					t.Fatalf("budget %d of %d bytes err = %v, want ErrEncodeLimitExceeded", c.budget, size, err)
				}
				if plaintext != nil {
					t.Fatal("rejected InnerHeader returned a collector")
				}
			}
		})
	}
}

// TestInnerHeaderWriteToBoundedDestinationAllocation checks that a
// zero-capacity destination makes at most two allocations: writeToBounded
// reserves dst's capacity before appending, so no complete header is staged in
// a temporary slice and copied in by Write. With the current Go toolchain the
// test observes one allocation on a normal build and two on a race build.
// Without the Grow, it observes five on a normal build and six on a race build,
// both above this bound.
func TestInnerHeaderWriteToBoundedDestinationAllocation(t *testing.T) {
	ih := binaryInnerHeader(t, 64)
	size := ih.encodedSize()
	want := innerHeaderBytes(t, ih)

	allocs := testing.AllocsPerRun(100, func() {
		var dst bytes.Buffer
		if err := ih.writeToBounded(&dst, size, 0); err != nil {
			t.Fatal(err)
		}
	})
	// One allocation on a normal build and two on a race build, so the bound
	// is two in both, as the test's comment explains.
	if allocs > 2 {
		t.Fatalf("writeToBounded made %v allocations, want at most 2", allocs)
	}

	var dst bytes.Buffer
	if err := ih.writeToBounded(&dst, size, size); err != nil {
		t.Fatalf("exact budget: %v", err)
	}
	if !bytes.Equal(dst.Bytes(), want) {
		t.Fatal("InnerHeader bytes differ from writeTo")
	}
}

// unlockedOnceFixture decodes an encoded fixture and unlocks its protected
// values exactly once, with the credentials it was decoded with. The decoder
// leaves protected values locked and database.UnlockProtectedEntries takes no
// credentials, so the StreamManager of the decoded database is used. The
// decoded content is returned and Meta.HeaderHash is checked afterwards, once
// the values are unlocked.
func unlockedOnceFixture(t *testing.T, encoded []byte) (Entry, string) {
	t.Helper()
	decoded := NewDatabase()
	decoded.Credentials = limitTestCredentials(t)
	if err := NewDecoder(bytes.NewReader(encoded)).Decode(decoded); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := decoded.Content.Root.Groups[0].Entries[0].GetContent("Password"); got == encoderLimitTestPassword {
		t.Fatal("decoder returned the protected password in plaintext")
	}
	manager, err := decoded.GetStreamManager()
	if err != nil {
		t.Fatal(err)
	}
	manager.UnlockProtectedGroups(decoded.Content.Root.Groups)
	if got := decoded.Content.Root.Groups[0].Entries[0].GetContent("Password"); got != encoderLimitTestPassword {
		t.Fatalf("unlocked Password = %q, want the known original", got)
	}
	return decoded.Content.Root.Groups[0].Entries[0], decoded.Content.Meta.HeaderHash
}

// assertEncoderLimitEntry checks an entry unlocked once after decoding: its
// protected flag and the known original password.
func assertEncoderLimitEntry(t *testing.T, entry Entry) {
	t.Helper()
	if len(entry.Values) < 2 || !entry.Values[1].Value.Protected.Bool {
		t.Fatalf("protected flag lost: %+v", entry.Values)
	}
	if got := entry.GetContent("Password"); got != encoderLimitTestPassword {
		t.Fatalf("Password = %q, want the known original", got)
	}
	if got := entry.GetContent("Notes"); len(got) != encoderLimitTestNoteBytes {
		t.Fatalf("Notes length = %d, want %d", len(got), encoderLimitTestNoteBytes)
	}
	if got := entry.GetContent("Title"); got != "bounded encode" {
		t.Fatalf("Title = %q", got)
	}
}

func TestEncodeWithLimitsAcceptsExactAndLargerBudget(t *testing.T) {
	// Each budget is checked against the fixture it encodes, for the reason
	// TestEncodeWithLimitsCollectsWithoutOneExtraByte gives.
	for name, extra := range map[string]int64{
		"exact":  0,
		"larger": 1,
	} {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			db := lockEncoderLimitFixture(t, encoderLimitTestDatabase(t))
			budget := int64(encoderLimitTestPlaintext(t, db)) + extra
			if err := NewEncoder(&out).EncodeWithLimits(
				db, EncodeLimits{MaxPlaintextBytes: budget},
			); err != nil {
				t.Fatalf("EncodeWithLimits: %v", err)
			}
			entry, headerHash := unlockedOnceFixture(t, out.Bytes())
			if headerHash != "" {
				t.Fatalf("encoded Meta.HeaderHash = %q, want it cleared", headerHash)
			}
			assertEncoderLimitEntry(t, entry)
		})
	}
}

// TestEncodeWithLimitsUncompressedDecodesAtExactBudget pins the plaintext
// budget of an uncompressed KDBX4 encoding: EncodeWithLimits measures the
// logical body before the encoder appends its 1..16 repeated-count block
// padding, and the bounded decoder budgets that logical body, not the padded
// one. The exact-size bounded decode therefore succeeds with the padding
// removed from RawData, and one byte less rejects it before RawData is kept.
func TestEncodeWithLimitsUncompressedDecodesAtExactBudget(t *testing.T) {
	db := lockEncoderLimitFixture(t, encoderLimitTestDatabase(t))
	db.Header.FileHeaders.CompressionFlags = NoCompressionFlag
	logical := int64(encoderLimitTestPlaintext(t, db))

	var out bytes.Buffer
	if err := NewEncoder(&out).EncodeWithLimits(db, EncodeLimits{MaxPlaintextBytes: logical}); err != nil {
		t.Fatalf("EncodeWithLimits at exactly the logical body size: %v", err)
	}
	encoded := out.Bytes()

	// The encoder always pads, so the decoded content carries the logical
	// body followed by this test's guard against a vacuous fixture.
	unbounded := NewDatabase()
	unbounded.Credentials = limitTestCredentials(t)
	if err := NewDecoder(bytes.NewReader(encoded)).Decode(unbounded); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if raw := unbounded.Content.RawData; len(raw) <= int(logical) || int64(len(raw))-logical >= 16 {
		t.Fatalf("decoded %d bytes for a %d-byte body, want cipher padding after it", len(raw), logical)
	}

	decode := func(budget int64) (*Database, error) {
		db := newLimitTestDatabase()
		err := decodeWithLimits(db, encoded, limitTestKey(), DecodeLimits{
			MaxEncodedBytes:   int64(len(encoded)),
			MaxPlaintextBytes: budget,
		})
		return db, err
	}

	// The exact logical size is accepted: the padding is not body.
	opened, err := decode(logical)
	if err != nil {
		t.Fatalf("decode at the exact logical body size %d: %v", logical, err)
	}
	if got := int64(len(opened.Content.RawData)); got != logical {
		t.Fatalf("RawData of %d bytes, want the %d-byte logical body without padding", got, logical)
	}
	manager, err := opened.GetStreamManager()
	if err != nil {
		t.Fatal(err)
	}
	manager.UnlockProtectedGroups(opened.Content.Root.Groups)
	assertEncoderLimitEntry(t, opened.Content.Root.Groups[0].Entries[0])

	// One byte less is rejected before the body is retained.
	rejected, err := decode(logical - 1)
	if !errors.Is(err, ErrDecodeLimitExceeded) {
		t.Fatalf("decode one byte under: err = %v, want ErrDecodeLimitExceeded", err)
	}
	if rejected.Content == nil || rejected.Content.RawData != nil {
		t.Fatalf("over-budget decode retained %d RawData bytes", len(rejected.Content.RawData))
	}
}

// TestEncodeAndEncodeWithLimitsSharePipeline checks that both entry points
// write the established normalized output: a decodable payload whose
// Meta.HeaderHash was cleared before the XML document was serialized, whether
// or not the plaintext is bounded. Both fixtures are pre-locked, as the
// encoder requires of a direct caller.
func TestEncodeAndEncodeWithLimitsSharePipeline(t *testing.T) {
	cases := map[string]func(*Encoder, *Database) error{
		"encode": func(e *Encoder, db *Database) error { return e.Encode(db) },
		"bounded": func(e *Encoder, db *Database) error {
			return e.EncodeWithLimits(db, EncodeLimits{MaxPlaintextBytes: int64(encoderLimitTestNoteBytes) * 8})
		},
	}
	for name, encode := range cases {
		t.Run(name, func(t *testing.T) {
			db := lockEncoderLimitFixture(t, encoderLimitTestDatabase(t))
			db.Content.Meta.HeaderHash = "stale header hash"
			var out bytes.Buffer
			if err := encode(NewEncoder(&out), db); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if db.Content.Meta.HeaderHash != "" {
				t.Fatalf("Meta.HeaderHash = %q after %s, want it cleared", db.Content.Meta.HeaderHash, name)
			}
			entry, headerHash := unlockedOnceFixture(t, out.Bytes())
			if headerHash != "" {
				t.Fatalf("%s encoded Meta.HeaderHash = %q", name, headerHash)
			}
			assertEncoderLimitEntry(t, entry)
		})
	}
}

// TestEncodeWithLimitsBoundsInnerHeader checks that the InnerHeader binaries
// count against the same budget as the XML document.
func TestEncodeWithLimitsBoundsInnerHeader(t *testing.T) {
	// withBinary builds a minimal database, with a 64-byte attachment when
	// attached. The attachment is registered by the database it belongs to:
	// AddBinary returns a pointer into that database's binaries.
	withBinary := func(attached bool) *Database {
		db := lockEncoderLimitFixture(t, limitTestDatabase(t))
		if attached {
			entry := &db.Content.Root.Groups[0].Entries[0]
			entry.Binaries = append(entry.Binaries,
				db.AddBinary(bytes.Repeat([]byte{1}, 64)).CreateReference("fixed.bin"))
		}
		return db
	}

	// The binary grows the plaintext, and each database is compared with its
	// own size: the plaintext carries a one-second-precision timestamp.
	xmlOnly := withBinary(false)
	withAttachment := withBinary(true)
	size := int64(encoderLimitTestPlaintext(t, xmlOnly))
	binarySize := int64(encoderLimitTestPlaintext(t, withAttachment))
	if binarySize <= size {
		t.Fatalf("binary did not grow the plaintext: %d -> %d", size, binarySize)
	}

	// The XML-only size, which the InnerHeader plus XML size exceeds, is
	// accepted without the binary and rejected with it.
	limits := EncodeLimits{MaxPlaintextBytes: size}
	if err := NewEncoder(io.Discard).EncodeWithLimits(xmlOnly, limits); err != nil {
		t.Fatalf("XML-only database rejected: %v", err)
	}
	var out countWriter
	err := NewEncoder(&out).EncodeWithLimits(withAttachment, limits)
	if !errors.Is(err, ErrEncodeLimitExceeded) {
		t.Fatalf("EncodeWithLimits err = %v, want ErrEncodeLimitExceeded", err)
	}
}

func TestEncodeWithLimitsRejectsInvalidLimits(t *testing.T) {
	for name, limit := range map[string]int64{
		"zero":      0,
		"negative":  -1,
		"max int64": math.MaxInt64,
	} {
		t.Run(name, func(t *testing.T) {
			var out countWriter
			db := lockEncoderLimitFixture(t, encoderLimitTestDatabase(t))
			err := NewEncoder(&out).EncodeWithLimits(db, EncodeLimits{MaxPlaintextBytes: limit})
			if !errors.Is(err, ErrEncodeLimitExceeded) {
				t.Fatalf("EncodeWithLimits err = %v, want ErrEncodeLimitExceeded", err)
			}
			if out.n != 0 {
				t.Fatalf("invalid limits wrote %d bytes", out.n)
			}
			// The limit is checked before db is modified.
			if db.Content.Meta.HeaderHash != "" {
				t.Fatal("invalid limits modified the database")
			}
		})
	}
}
