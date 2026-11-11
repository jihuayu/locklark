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

// encoderLimitTestDatabase is a valid KDBX 4.1 database with a protected
// Password value and an unprotected, highly compressible Notes value of
// encoderLimitTestNoteBytes bytes. The Notes value keeps the serialized
// plaintext far above any practical budget while its gzip output stays tiny,
// which is the case a ciphertext size check alone cannot catch. The returned
// database is in the natural unlocked state (protected values in plaintext),
// because Encoder.EncodeWithLimits, like Encode, locks protected entries
// itself and requires them unlocked on input.
func encoderLimitTestDatabase(t *testing.T) *Database {
	t.Helper()
	db := NewDatabase(WithDatabaseKDBXVersion41())
	db.Header.FileHeaders.KdfParameters = limitTestKDF()
	group := NewGroup()
	group.Name = "Locklark encoder limits"
	entry := NewEntry()
	entry.Values = []ValueData{
		{Key: "Title", Value: V{Content: "bounded encode"}},
		{Key: "Password", Value: V{Content: "correct horse battery staple", Protected: wrappers.NewBoolWrapper(true)}},
		{Key: "Notes", Value: V{Content: strings.Repeat("a", encoderLimitTestNoteBytes)}},
	}
	group.Entries = []Entry{entry}
	db.Content.Root.Groups = []Group{group}
	// A real, registered attachment so binary cleanup keeps it.
	db.Content.Root.Groups[0].Entries[0].Binaries = append(entry.Binaries,
		db.AddBinary([]byte("attachment")).CreateReference("attachment.bin"))
	db.Credentials = limitTestCredentials(t)
	return db
}

// countWriter records how many bytes were written to it.
type countWriter struct{ n int64 }

func (c *countWriter) Write(p []byte) (int, error) {
	c.n += int64(len(p))
	return len(p), nil
}

// exactXMLContent is the XML document marshalXMLContent writes: the XML
// header followed by xml.MarshalIndent of content. The content is marshaled
// once per call, exactly as encodeRawContent does after its one
// map-iteration-dependent metadata pass. Nothing is locked or unlocked here,
// which would write to random inner stream positions and change the length
// of the protected values.
func exactXMLContent(t *testing.T, content DBContent) []byte {
	t.Helper()
	rawContent, err := xml.MarshalIndent(content, "", "\t")
	if err != nil {
		t.Fatal(err)
	}
	return append(append([]byte(nil), xmlHeader...), rawContent...)
}

// encoderLimitTestPlaintext returns the exact serialized plaintext size of db
// as EncodeWithLimits measures it, for a fresh unlocked fixture that has not
// been encoded. It runs the encoder's own normalization and one encrypted
// serialization of the content on a scratch writer, without touching db's
// write target.
func encoderLimitTestPlaintext(t *testing.T, db *Database) uint64 {
	t.Helper()
	var plaintext int64 = -1
	e := NewEncoder(io.Discard)
	e.measure = func(n int64) { plaintext = n }
	limits := EncodeLimits{MaxPlaintextBytes: math.MaxInt64 - 1}
	if err := e.EncodeWithLimits(db, limits); err != nil {
		t.Fatalf("measuring encode: %v", err)
	}
	if plaintext < 0 {
		t.Fatal("measuring encode did not report its plaintext size")
	}
	return uint64(plaintext)
}

func TestEncodeWithLimitsRejectsCompressiblePlaintextOverBudget(t *testing.T) {
	// The unbounded Encode of the same database succeeds and is far smaller
	// than the plaintext it is built from.
	var unbounded bytes.Buffer
	if err := NewEncoder(&unbounded).Encode(encoderLimitTestDatabase(t)); err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if unbounded.Len() >= encoderLimitTestNoteBytes/4 {
		t.Fatalf("fixture output of %d bytes is not highly compressible", unbounded.Len())
	}

	// One byte under the exact body size is rejected: the budget covers the
	// whole InnerHeader plus XML body. The fixture gets its own exact size,
	// because the metadata timestamps in the document have a
	// representation-dependent length.
	db := encoderLimitTestDatabase(t)
	plaintext := encoderLimitTestPlaintext(t, db)
	if plaintext <= encoderLimitTestNoteBytes {
		t.Fatalf("fixture plaintext is %d bytes, want more than the Notes value", plaintext)
	}
	assertEncodeRejected(t, db, plaintext-1, unbounded.Len())
}

// assertEncodeRejected checks that EncodeWithLimits with budget rejects db
// for its plaintext size and writes nothing beyond the header that Encode's
// established write order emits first.
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
// collector: a write that would cross the budget retains nothing, the
// collected length never passes max, and the InnerHeader reserve charges its
// exact size before any of it is retained.
func TestEncodeWithLimitsCollectsWithoutOneExtraByte(t *testing.T) {
	c := newPlaintextContent(true, true, 8)
	if _, err := c.Write([]byte("12345678")); err != nil {
		t.Fatalf("exact-budget write: %v", err)
	}
	if _, err := c.Write([]byte("9")); !errors.Is(err, ErrEncodeLimitExceeded) {
		t.Fatalf("over-budget write err = %v, want ErrEncodeLimitExceeded", err)
	}
	if c.document.Len() != 8 {
		t.Fatalf("collector holds %d bytes, want exactly the budget", c.document.Len())
	}
	if err := c.reserve(1); !errors.Is(err, ErrEncodeLimitExceeded) {
		t.Fatalf("reserve over budget err = %v, want ErrEncodeLimitExceeded", err)
	}
	if err := c.check(); !errors.Is(err, ErrEncodeLimitExceeded) {
		t.Fatalf("check err = %v, want ErrEncodeLimitExceeded", err)
	}

	ih := testInnerHeader()
	if ih.encodedSize() <= 1 {
		t.Fatalf("fixture inner header of %d bytes", ih.encodedSize())
	}
	c = newPlaintextContent(true, true, ih.encodedSize())
	if _, err := c.Write([]byte("1")); err != nil {
		t.Fatalf("write within budget: %v", err)
	}
	if err := c.writeInnerHeader(ih); !errors.Is(err, ErrEncodeLimitExceeded) {
		t.Fatalf("inner header over budget err = %v, want ErrEncodeLimitExceeded", err)
	}
	if c.headers.Len() != 0 {
		t.Fatalf("over-budget inner header retained %d bytes", c.headers.Len())
	}

	// The same InnerHeader is accepted at exactly its encoded size.
	c = newPlaintextContent(true, true, ih.encodedSize())
	if err := c.writeInnerHeader(ih); err != nil {
		t.Fatalf("exact inner header budget: %v", err)
	}
	if int64(c.headers.Len()) != ih.encodedSize() {
		t.Fatalf("inner header of %d bytes, want %d", c.headers.Len(), ih.encodedSize())
	}
}

// openLimitTestDatabase decodes an encoded fixture in the unbounded,
// explicitly unlocked state, which is the contract direct encoder fixtures
// follow: protected values are in plaintext, not left locked by the decoder.
// It also checks that the encoded document carries no Meta.HeaderHash.
func openLimitTestDatabase(t *testing.T, encoded []byte) *Database {
	t.Helper()
	decoded := NewDatabase()
	decoded.Credentials = limitTestCredentials(t)
	if err := NewDecoder(bytes.NewReader(encoded)).Decode(decoded); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if err := decoded.UnlockProtectedEntries(); err != nil {
		t.Fatal(err)
	}
	if decoded.Content.Meta.HeaderHash != "" {
		t.Fatalf("encoded Meta.HeaderHash = %q, want it cleared", decoded.Content.Meta.HeaderHash)
	}
	return decoded
}

func TestEncodeWithLimitsAcceptsExactAndLargerBudget(t *testing.T) {
	plaintext := encoderLimitTestPlaintext(t, encoderLimitTestDatabase(t))

	for name, budget := range map[string]uint64{
		"exact":  plaintext,
		"larger": plaintext + 1,
	} {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			if err := NewEncoder(&out).EncodeWithLimits(
				encoderLimitTestDatabase(t), EncodeLimits{MaxPlaintextBytes: int64(budget)},
			); err != nil {
				t.Fatalf("EncodeWithLimits: %v", err)
			}
			entry := openLimitTestDatabase(t, out.Bytes()).Content.Root.Groups[0].Entries[0]
			if got := entry.GetContent("Notes"); len(got) != encoderLimitTestNoteBytes {
				t.Fatalf("Notes length = %d, want %d", len(got), encoderLimitTestNoteBytes)
			}
			if got := entry.GetContent("Title"); got != "bounded encode" {
				t.Fatalf("Title = %q", got)
			}
			assertProtected(t, entry)
		})
	}
}

// TestEncodeAndEncodeWithLimitsSharePipeline checks that both entry points
// write the established normalized output: a decodable payload whose
// Meta.HeaderHash was cleared before the XML document was marshaled, whether
// or not the plaintext is bounded.
func TestEncodeAndEncodeWithLimitsSharePipeline(t *testing.T) {
	cases := map[string]func(*Encoder, *Database) error{
		"encode": func(e *Encoder, db *Database) error { return e.Encode(db) },
		"bounded": func(e *Encoder, db *Database) error {
			return e.EncodeWithLimits(db, EncodeLimits{MaxPlaintextBytes: int64(encoderLimitTestNoteBytes) * 8})
		},
	}
	for name, encode := range cases {
		t.Run(name, func(t *testing.T) {
			db := encoderLimitTestDatabase(t)
			db.Content.Meta.HeaderHash = "stale header hash"
			var out bytes.Buffer
			if err := encode(NewEncoder(&out), db); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if db.Content.Meta.HeaderHash != "" {
				t.Fatalf("Meta.HeaderHash = %q after %s, want it cleared", db.Content.Meta.HeaderHash, name)
			}
			opened := openLimitTestDatabase(t, out.Bytes())
			if opened.Content.Meta.HeaderHash != "" {
				t.Fatalf("%s encoded Meta.HeaderHash = %q", name, opened.Content.Meta.HeaderHash)
			}
			entry := opened.Content.Root.Groups[0].Entries[0]
			assertProtected(t, entry)
			if got := entry.GetContent("Title"); got != "bounded encode" {
				t.Fatalf("%s Title = %q", name, got)
			}
		})
	}
}

// TestEncodeWithLimitsBoundsInnerHeader checks that the InnerHeader binaries
// count against the same budget as the XML document.
func TestEncodeWithLimitsBoundsInnerHeader(t *testing.T) {
	small := limitTestDatabase
	plain := encoderLimitTestPlaintext(t, small(t))

	binDB := small(t)
	binary := binDB.AddBinary(bytes.Repeat([]byte{1}, 64))
	entry := &binDB.Content.Root.Groups[0].Entries[0]
	entry.Binaries = append(entry.Binaries, binary.CreateReference("fixed.bin"))
	plainWithBinary := encoderLimitTestPlaintext(t, binDB)
	if plainWithBinary <= plain {
		t.Fatalf("binary did not grow the plaintext: %d -> %d", plain, plainWithBinary)
	}

	// A budget between the XML-only size and the InnerHeader plus XML size is
	// accepted without the binary and rejected with it.
	limits := EncodeLimits{MaxPlaintextBytes: int64(plain + (plainWithBinary-plain)/2)}
	if err := NewEncoder(io.Discard).EncodeWithLimits(small(t), limits); err != nil {
		t.Fatalf("XML-only database rejected: %v", err)
	}
	var out countWriter
	err := NewEncoder(&out).EncodeWithLimits(binDB, limits)
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
			err := NewEncoder(&out).EncodeWithLimits(
				encoderLimitTestDatabase(t), EncodeLimits{MaxPlaintextBytes: limit},
			)
			if !errors.Is(err, ErrEncodeLimitExceeded) {
				t.Fatalf("EncodeWithLimits err = %v, want ErrEncodeLimitExceeded", err)
			}
			if out.n != 0 {
				t.Fatalf("invalid limits wrote %d bytes", out.n)
			}
		})
	}
}

// assertProtected checks that a decoded entry keeps its protected flag and its
// password. The protected password is not compared to its plaintext: the
// protected value stream is not restored by the decoder, so its content is
// only known to be present.
func assertProtected(t *testing.T, entry Entry) {
	t.Helper()
	if len(entry.Values) < 2 || !entry.Values[1].Value.Protected.Bool {
		t.Fatalf("protected flag lost: %+v", entry.Values)
	}
	if got := entry.GetContent("Password"); got == "" {
		t.Fatal("protected password is empty")
	}
}
