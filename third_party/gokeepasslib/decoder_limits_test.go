package gokeepasslib

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"math"
	"testing"
)

// limitTestKDF is a valid Argon2id profile with the smallest memory and
// iteration count the KDF guard accepts, so decode tests stay cheap.
func limitTestKDF() *KdfParameters {
	k := NewKDBX4FileHeaders().KdfParameters
	k.UUID = KdfArgon2id
	k.Version = 0x13
	k.Iterations = 1
	k.Parallelism = 1
	k.Memory = 8 << 10
	return k
}

func limitTestKey() []byte { return bytes.Repeat([]byte{7}, 32) }

func limitTestCredentials(t *testing.T) *DBCredentials {
	t.Helper()
	creds, err := NewKeyDataCredentials(limitTestKey())
	if err != nil {
		t.Fatal(err)
	}
	return creds
}

// limitTestDatabase is a small valid KDBX 4.1 database.
func limitTestDatabase(t *testing.T) *Database {
	t.Helper()
	db := NewDatabase(WithDatabaseKDBXVersion41())
	db.Header.FileHeaders.KdfParameters = limitTestKDF()
	group := NewGroup()
	group.Name = "Locklark test"
	entry := NewEntry()
	entry.Values = []ValueData{{Key: "Title", Value: V{Content: "roundtrip"}}}
	group.Entries = []Entry{entry}
	db.Content.Root.Groups = []Group{group}
	db.Credentials = limitTestCredentials(t)
	return db
}

func encodeLimitTestDatabase(t *testing.T, db *Database) []byte {
	t.Helper()
	var out bytes.Buffer
	if err := NewEncoder(&out).Encode(db); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func newLimitTestDatabase() *Database { return NewDatabase(WithDatabaseKDBXVersion41()) }

// rawKDBX41 assembles a KDBX 4.1 file whose decrypted content is exactly
// decrypted, with the package header, hash, block and cipher helpers.
func rawKDBX41(t *testing.T, kdf *KdfParameters, key, decrypted []byte) []byte {
	t.Helper()
	return rawKDBX41Flags(t, kdf, key, NoCompressionFlag, decrypted)
}

func rawKDBX41Flags(t *testing.T, kdf *KdfParameters, key []byte, flags uint32, decrypted []byte) []byte {
	t.Helper()
	db := NewDatabase(WithDatabaseKDBXVersion41())
	db.Header.FileHeaders.KdfParameters = kdf
	db.Header.FileHeaders.CompressionFlags = flags
	db.Credentials, _ = NewKeyDataCredentials(key)
	transformedKey, err := db.getTransformedKey()
	if err != nil {
		t.Fatal(err)
	}
	manager, err := NewEncrypterManager(
		db.Header.FileHeaders.CipherID,
		buildMasterKey(db, transformedKey),
		db.Header.FileHeaders.EncryptionIV,
	)
	if err != nil {
		t.Fatal(err)
	}
	encrypted := manager.Encrypter.Encrypt(decrypted)

	var out bytes.Buffer
	if err := db.Header.writeTo(&out); err != nil {
		t.Fatal(err)
	}
	db.Hashes = NewHashes(db.Header)
	db.Hashes.Hmac = db.Header.GetHmacSha256(buildHmacKey(db, transformedKey))
	if err := db.Hashes.writeTo(&out); err != nil {
		t.Fatal(err)
	}
	composeContentBlocks4(&out, encrypted, db.Header.FileHeaders.MasterSeed, transformedKey)
	return out.Bytes()
}

func gzipCompress(data []byte) []byte {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	_, _ = w.Write(data)
	_ = w.Close()
	return b.Bytes()
}

func testInnerHeader() *InnerHeader {
	ih := &InnerHeader{InnerRandomStreamID: ChaChaStreamID, InnerRandomStreamKey: make([]byte, 19)}
	for i := range ih.InnerRandomStreamKey {
		ih.InnerRandomStreamKey[i] = byte(i)
	}
	return ih
}

func innerHeaderBytes(t *testing.T, ih *InnerHeader) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := ih.writeTo(&b); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// binaryInnerHeader is a valid inner header whose single binary (with its
// protection flag) is stored before the terminator, as writeTo lays it out.
func binaryInnerHeader(t *testing.T, content int) *InnerHeader {
	t.Helper()
	ih := testInnerHeader()
	ih.Binaries = Binaries{{
		ID:               0,
		MemoryProtection: 1,
		Content:          bytes.Repeat([]byte{0xA5}, content),
		isKDBX4:          true,
	}}
	return ih
}

func decodeWithLimits(db *Database, encoded, key []byte, limits DecodeLimits) error {
	db.Credentials, _ = NewKeyDataCredentials(key)
	return NewDecoder(bytes.NewReader(encoded)).DecodeWithLimits(db, limits)
}

func decodeUnbounded(db *Database, encoded, key []byte) error {
	db.Credentials, _ = NewKeyDataCredentials(key)
	return NewDecoder(bytes.NewReader(encoded)).Decode(db)
}

// countReader counts the bytes read from r.
type countReader struct {
	r   io.Reader
	saw int
}

func (c *countReader) Read(p []byte) (int, error) {
	k, err := c.r.Read(p)
	c.saw += k
	return k, err
}

func TestDecodeWithLimitsAcceptsWithinBudget(t *testing.T) {
	encoded := encodeLimitTestDatabase(t, limitTestDatabase(t))
	key := limitTestKey()

	db := newLimitTestDatabase()
	if err := decodeWithLimits(db, encoded, key, DecodeLimits{
		MaxEncodedBytes:   int64(len(encoded)),
		MaxPlaintextBytes: 1 << 20,
	}); err != nil {
		t.Fatalf("within-budget decode failed: %v", err)
	}
	if got := db.Content.Root.Groups[0].Entries[0].GetContent("Title"); got != "roundtrip" {
		t.Fatalf("title = %q", got)
	}

	// Decode is unchanged and still reads the same input unbounded.
	plain := newLimitTestDatabase()
	if err := decodeUnbounded(plain, encoded, key); err != nil {
		t.Fatalf("Decode: %v", err)
	}
}

func TestDecodeWithLimitsRejectsInputBeforeParserAndKDF(t *testing.T) {
	// No KDBX header at all: only the input-size check can reject this, so
	// the budget error proves the input reader was bounded before the
	// parser saw a header.
	src := &countReader{r: bytes.NewReader(make([]byte, 4096))}
	err := NewDecoder(src).DecodeWithLimits(newLimitTestDatabase(), DecodeLimits{
		MaxEncodedBytes:   1024,
		MaxPlaintextBytes: 1 << 20,
	})
	if !errors.Is(err, ErrDecodeLimitExceeded) {
		t.Fatalf("err = %v, want ErrDecodeLimitExceeded", err)
	}
	if src.saw != 1025 {
		t.Fatalf("read %d bytes, want exactly the budget plus one", src.saw)
	}

	// A real KDBX one byte above the input budget must not reach the KDF or
	// the header parser either; the wrong credentials would otherwise
	// produce a different error and the decoder would replace the header.
	encoded := encodeLimitTestDatabase(t, limitTestDatabase(t))
	db := newLimitTestDatabase()
	db.Credentials = NewPasswordCredentials("wrong")
	hdr := db.Header
	err = NewDecoder(bytes.NewReader(encoded)).DecodeWithLimits(db, DecodeLimits{
		MaxEncodedBytes:   int64(len(encoded)) - 1,
		MaxPlaintextBytes: 1 << 20,
	})
	if !errors.Is(err, ErrDecodeLimitExceeded) {
		t.Fatalf("err = %v, want ErrDecodeLimitExceeded", err)
	}
	if db.Header != hdr {
		t.Fatal("header was parsed before the input budget was checked")
	}
}

func TestDecodeWithLimitsRejectsInvalidLimits(t *testing.T) {
	for _, limits := range []DecodeLimits{
		{},
		{MaxEncodedBytes: -1, MaxPlaintextBytes: 1},
		{MaxEncodedBytes: 1, MaxPlaintextBytes: 0},
		{MaxEncodedBytes: math.MaxInt64, MaxPlaintextBytes: 1},
		{MaxEncodedBytes: 1, MaxPlaintextBytes: math.MaxInt64},
		{MaxEncodedBytes: math.MaxInt64, MaxPlaintextBytes: math.MaxInt64},
	} {
		err := NewDecoder(bytes.NewReader(nil)).DecodeWithLimits(newLimitTestDatabase(), limits)
		if !errors.Is(err, ErrDecodeLimitExceeded) {
			t.Fatalf("limits %+v: err = %v, want ErrDecodeLimitExceeded", limits, err)
		}
	}
}

func TestDecodeWithLimitsRejectsGzipExpansionOverBudget(t *testing.T) {
	const expanded = 200 << 10
	plain := bytes.Repeat([]byte{'x'}, expanded)
	gzipBytes := gzipCompress(plain)
	budget := int64(len(gzipBytes) + 4096)
	if budget >= int64(len(plain)) {
		t.Fatalf("fixture is not a compression bomb: budget %d", budget)
	}
	key := limitTestKey()
	// The decoder expands the content after decryption, so the gzip stream
	// is carried as the whole content.
	encoded := rawKDBX41Flags(t, limitTestKDF(), key, GzipCompressionFlag, gzipBytes)

	db := newLimitTestDatabase()
	err := decodeWithLimits(db, encoded, key, DecodeLimits{
		MaxEncodedBytes:   int64(len(encoded)),
		MaxPlaintextBytes: budget,
	})
	if !errors.Is(err, ErrDecodeLimitExceeded) {
		t.Fatalf("err = %v, want the gzip expansion limit", err)
	}

	// The same file within a larger budget is not rejected by the limits:
	// it reaches the XML decoder on the non-XML expanded body.
	db = newLimitTestDatabase()
	err = decodeWithLimits(db, encoded, key, DecodeLimits{
		MaxEncodedBytes:   int64(len(encoded)),
		MaxPlaintextBytes: budget + expanded,
	})
	if err == nil || errors.Is(err, ErrDecodeLimitExceeded) {
		t.Fatalf("within budget: err = %v", err)
	}
	if len(db.Content.RawData) != expanded {
		t.Fatalf("expanded %d bytes, want %d", len(db.Content.RawData), expanded)
	}
}

func TestDecodeWithLimitsRejectsUncompressedBodyOverBudget(t *testing.T) {
	innerHeader := innerHeaderBytes(t, testInnerHeader())
	whole := append(append([]byte(nil), innerHeader...), "<KeePassFile/>"...)
	key := limitTestKey()
	encoded := rawKDBX41(t, limitTestKDF(), key, whole)

	db := newLimitTestDatabase()
	err := decodeWithLimits(db, encoded, key, DecodeLimits{
		MaxEncodedBytes:   int64(len(encoded)),
		MaxPlaintextBytes: int64(len(whole)) - 1,
	})
	if !errors.Is(err, ErrDecodeLimitExceeded) || db.Content.RawData != nil {
		t.Fatalf("err = %v, want the plaintext limit before XML decode", err)
	}

	// Within budget the same file decodes into a database.
	db = newLimitTestDatabase()
	if err := decodeWithLimits(db, encoded, key, DecodeLimits{
		MaxEncodedBytes:   int64(len(encoded)),
		MaxPlaintextBytes: int64(len(whole)),
	}); err != nil {
		t.Fatalf("within budget: %v", err)
	}
}

// TestInnerHeaderBinaryAggregateLimit exercises the bounded InnerHeader
// parser directly: the whole-content and binary budgets share the same schema
// maximum, so a full Decode may hit the body budget first, while the parser
// must reject an over-budget binary before reading any of its bytes.
func TestInnerHeaderBinaryAggregateLimit(t *testing.T) {
	const content = 64
	header := innerHeaderBytes(t, binaryInnerHeader(t, content))
	payload := int64(1 + content) // protection flag plus content

	// One byte below the binary payload: the field is valid and readable,
	// so only the aggregate budget can reject it.
	src := &countReader{r: bytes.NewReader(header)}
	ih := new(InnerHeader)
	err := ih.readFromWithLimits(src, payload-1)
	if !errors.Is(err, ErrDecodeLimitExceeded) {
		t.Fatalf("err = %v, want ErrDecodeLimitExceeded", err)
	}
	if len(ih.Binaries) != 0 {
		t.Fatalf("over-budget binary was kept: %d binaries", len(ih.Binaries))
	}
	// The framing up to the binary's field header is read; neither the
	// protection flag nor any content byte is.
	// The count covers the whole inner header framing except the binary
	// payload itself.
	if got, want := int64(src.saw), int64(len(header))-payload; got > want {
		t.Fatalf("read %d bytes, want at most %d: the over-budget binary was read", got, want)
	}
	if src.saw == 0 {
		t.Fatal("no framing was read")
	}

	// The exact aggregate budget accepts the binary and the header.
	ih = new(InnerHeader)
	if err := ih.readFromWithLimits(bytes.NewReader(header), payload); err != nil {
		t.Fatalf("exact budget: %v", err)
	}
	if len(ih.Binaries) != 1 || ih.Binaries[0].MemoryProtection != 1 || len(ih.Binaries[0].Content) != content {
		t.Fatalf("binaries = %v", ih.Binaries)
	}

	// Two binaries share the aggregate.
	two := binaryInnerHeader(t, 10)
	two.Binaries = append(Binaries{{ID: 1, Content: bytes.Repeat([]byte{0xB6}, 20), isKDBX4: true}}, two.Binaries...)
	raw := innerHeaderBytes(t, two)
	ih = new(InnerHeader)
	if err := ih.readFromWithLimits(bytes.NewReader(raw), 21+11); err != nil {
		t.Fatalf("two binaries within budget: %v", err)
	}
	ih = new(InnerHeader)
	if err := ih.readFromWithLimits(bytes.NewReader(raw), 21+10); !errors.Is(err, ErrDecodeLimitExceeded) {
		t.Fatalf("two binaries over budget: %v", err)
	}
	// Bounded mode rejects empty, flag-only and negative binary lengths
	// before allocating anything.
	for name, field := range map[string][]byte{
		"empty binary": {InnerHeaderBinary, 0, 0, 0, 0},
		"flag only":    {InnerHeaderBinary, 1, 0, 0, 0, 1},
		"negative":     {InnerHeaderBinary, 0xff, 0xff, 0xff, 0xff},
	} {
		ih := new(InnerHeader)
		if err := ih.readFromWithLimits(bytes.NewReader(field), 1<<20); !errors.Is(err, ErrDecodeLimitExceeded) || len(ih.Binaries) != 0 {
			t.Fatalf("%s: err = %v, binaries = %v", name, err, ih.Binaries)
		}
	}
}

// TestInnerHeaderUnboundedCompatibility checks that the unbounded parser
// keeps its original behavior: an empty field is accepted with zero bytes and
// a one-byte binary is kept with no content. The bounded parser rejects a
// one-byte binary before allocating any content.
func TestInnerHeaderUnboundedCompatibility(t *testing.T) {
	// An empty field is read as zero bytes and leaves the key empty; the
	// following terminator ends the header.
	empty := []byte{InnerHeaderIRSKey, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	// A one-byte binary is kept with no content, then the terminator.
	flagOnly := []byte{InnerHeaderBinary, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0}

	h := new(InnerHeader)
	if err := h.readFrom(bytes.NewReader(empty)); err != nil {
		t.Fatalf("unbounded empty field: %v", err)
	}
	if h.InnerRandomStreamKey == nil || len(h.InnerRandomStreamKey) != 0 {
		t.Fatalf("unbounded empty field key = %v", h.InnerRandomStreamKey)
	}

	h = new(InnerHeader)
	if err := h.readFrom(bytes.NewReader(flagOnly)); err != nil {
		t.Fatalf("unbounded flag-only binary: %v", err)
	}
	if len(h.Binaries) != 1 || h.Binaries[0].MemoryProtection != 1 || len(h.Binaries[0].Content) != 0 {
		t.Fatalf("unbounded binaries = %v", h.Binaries)
	}

	for name, data := range map[string][]byte{"flag only": flagOnly} {
		ih := new(InnerHeader)
		if err := ih.readFromWithLimits(bytes.NewReader(data), 1<<20); !errors.Is(err, ErrDecodeLimitExceeded) || len(ih.Binaries) != 0 {
			t.Fatalf("%s: err = %v, binaries = %v, want ErrDecodeLimitExceeded", name, err, ih.Binaries)
		}
	}

	// A valid header with a binary before the terminator decodes in both
	// modes to the same contents.
	header := innerHeaderBytes(t, binaryInnerHeader(t, 8))
	for name, read := range map[string]func(*InnerHeader) error{
		"unbounded": func(ih *InnerHeader) error { return ih.readFrom(bytes.NewReader(header)) },
		"bounded": func(ih *InnerHeader) error {
			return ih.readFromWithLimits(bytes.NewReader(header), 1<<20)
		},
	} {
		ih := new(InnerHeader)
		if err := read(ih); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if ih.InnerRandomStreamID != ChaChaStreamID || len(ih.InnerRandomStreamKey) != 19 ||
			len(ih.Binaries) != 1 || ih.Binaries[0].MemoryProtection != 1 || !bytes.Equal(ih.Binaries[0].Content, bytes.Repeat([]byte{0xA5}, 8)) {
			t.Fatalf("%s: header = %v", name, ih)
		}
	}
}

func TestDecodeLimitErrorDoesNotEmbedInput(t *testing.T) {
	secret := bytes.Repeat([]byte("PASSW0RD"), 128)
	err := NewDecoder(bytes.NewReader(secret)).DecodeWithLimits(newLimitTestDatabase(), DecodeLimits{
		MaxEncodedBytes:   1,
		MaxPlaintextBytes: 1,
	})
	if !errors.Is(err, ErrDecodeLimitExceeded) || bytes.Contains([]byte(err.Error()), []byte("PASSW0RD")) {
		t.Fatalf("err = %q", err)
	}
}
