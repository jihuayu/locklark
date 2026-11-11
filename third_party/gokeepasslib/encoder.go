package gokeepasslib

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math"
)

// Header to be put before xml content in kdbx file
var xmlHeader = []byte(`<?xml version="1.0" encoding="utf-8" standalone="yes"?>` + "\n")

// Encoder is used to automaticaly encrypt and write a database to a file, network, etc
type Encoder struct {
	w io.Writer
}

// NewEncoder creates a new encoder with writer w, identical to gokeepasslib.Encoder{w}
func NewEncoder(w io.Writer) *Encoder {
	return &Encoder{w: w}
}

// ErrEncodeLimitExceeded is returned by EncodeWithLimits when the serialized
// plaintext content exceeds the EncodeLimits budget. The error never embeds
// database content.
var ErrEncodeLimitExceeded = errors.New("gokeepasslib: database exceeds encode limits")

// EncodeLimits bounds the plaintext a bounded encode may serialize.
type EncodeLimits struct {
	// MaxPlaintextBytes bounds the plaintext content: the InnerHeader
	// followed by the XML document, exactly as it is compressed and
	// encrypted, but without the cipher block padding the encoder appends
	// before encryption (1..16 bytes, also with NoCompressionFlag), so a
	// body whose padded plaintext is up to 16 bytes longer still fits. It
	// is enforced on every write of the plaintext collector, the
	// InnerHeader's and the streaming XML document's alike, so a write that
	// would cross it is rejected before a byte beyond it is retained.
	MaxPlaintextBytes int64
}

func (l EncodeLimits) validate() error {
	if l.MaxPlaintextBytes <= 0 || l.MaxPlaintextBytes == math.MaxInt64 {
		return fmt.Errorf("%w: every limit must be positive and below MaxInt64", ErrEncodeLimitExceeded)
	}
	return nil
}

// Encode writes db to e's internal writer
func (e *Encoder) Encode(db *Database) error {
	return e.encode(db, 0)
}

// EncodeWithLimits writes db to e's internal writer exactly like Encode, and
// additionally rejects plaintext content (the InnerHeader followed by the XML
// document) larger than limits.MaxPlaintextBytes with ErrEncodeLimitExceeded.
// The content is measured after the same normalization as Encode (binary
// cleanup, format version, protected entry unlock and relock order, header
// and hash updates) and before it is compressed, padded or encrypted. The
// budget is the logical body and excludes the cipher block padding the
// encoder always appends, so a NoCompressionFlag body of exactly
// limits.MaxPlaintextBytes still decodes with DecodeWithLimits and the same
// budget when its padded content is 16-byte aligned, as every writer output
// is.
//
// The content is serialized exactly as Encode serializes it, and its budget
// is enforced on the plaintext collector's writes before a byte beyond the
// budget is retained, so an over-budget content is rejected without one extra
// byte. The encoder keeps Encode's write order, so the KDBX header and hashes
// have been written to e's writer before the content is serialized: a
// database rejected here has already had them written, and its content is
// never compressed, padded, encrypted or written.
//
// EncodeLimits with a non-positive or MaxInt64 limit is reported as
// ErrEncodeLimitExceeded before db is modified. Errors never embed database
// content.
func (e *Encoder) EncodeWithLimits(db *Database, limits EncodeLimits) error {
	if err := limits.validate(); err != nil {
		return err
	}
	return e.encode(db, limits.MaxPlaintextBytes)
}

// encode is the ordered encode pipeline shared by Encode and EncodeWithLimits.
// A zero maxPlaintext is an unbounded Encode; a positive one bounds the
// plaintext content.
func (e *Encoder) encode(db *Database, maxPlaintext int64) error {
	db.cleanupBinaries()

	// Unlock protected entries ensuring that we have them prepared in the order that is matching
	// the xml unmarshalling order
	err := db.UnlockProtectedEntries()
	if err != nil {
		return err
	}
	// Re-Lock the protected values mapping to ensure that they are locked in memory and
	// follow the order in which they would be written again
	err = db.LockProtectedEntries()
	if err != nil {
		return err
	}

	// ensure the file format version is able to hold the content of the database
	if err = db.ensureRequiredKdbxFormatVersion(); err != nil {
		return err
	}

	// ensure timestamps will be formatted correctly
	db.ensureKdbxFormatVersion()

	// Calculate transformed key to make HMAC and encrypt
	transformedKey, err := db.getTransformedKey()
	if err != nil {
		return err
	}

	// Write header then hashes before decode content (necessary to update HeaderHash)
	// db.Header writeTo will change its hash
	if err = db.Header.writeTo(e.w); err != nil {
		return err
	}

	// Update header hash into db.Hashes then write the data
	hash := db.Header.GetSha256()
	if db.Header.IsKdbx4() {
		db.Hashes.Sha256 = hash

		hmacKey := buildHmacKey(db, transformedKey)
		hmacHash := db.Header.GetHmacSha256(hmacKey)
		db.Hashes.Hmac = hmacHash

		if err = db.Hashes.writeTo(e.w); err != nil {
			return err
		}

		// Comment as taken from the original KDBX source:
		// > The header hash is typically only stored in
		// > KDBX <= 3.1 files, not in KDBX >= 4 files
		// > (here, the header is verified via a HMAC),
		// > but we also support it for KDBX >= 4 files
		// > (i.e. if it's present, we check it)
		// That means that for KDBXv4 files we can unset the hash to make sure that it is blank.
		// Additionally it has to happen somewhere before `xml.MarshalIndent` and this is
		// the perfect spot just before it specific to KDBXv4 files.
		db.Content.Meta.HeaderHash = ""
	} else {
		db.Content.Meta.HeaderHash = base64.StdEncoding.EncodeToString(hash[:])
	}

	// Serialize the InnerHeader (Kdbx v4) and then the XML document, each
	// once, through the plaintext collector: a bounded encode charges both
	// against one plaintext budget before the content is compressed.
	plaintext, err := newPlaintextContent(db.Content.InnerHeader, db.Header.IsKdbx4(), maxPlaintext)
	if err != nil {
		return err
	}
	if err = plaintext.writeDocument(db.Content); err != nil {
		return err
	}

	// Encode raw content
	encodedContent, err := encodeRawContent(db, plaintext.reader(), transformedKey)
	if err != nil {
		return err
	}

	// Writes the encrypted database content
	_, err = e.w.Write(encodedContent)
	return err
}

// plaintextContent is the plaintext of one encode: the KDBX4 InnerHeader
// followed by the XML document, each collected once. A positive max is a
// plaintext budget, enforced on every write of either before a byte beyond it
// is retained.
type plaintextContent struct {
	headers  bytes.Buffer
	document bytes.Buffer
	written  int64
	max      int64
}

// newPlaintextContent creates the collector of one encode and writes the
// InnerHeader into it, before the document is serialized, so a budget smaller
// than the InnerHeader is reported without serializing the document.
func newPlaintextContent(innerHeader *InnerHeader, isKdbx4 bool, max int64) (*plaintextContent, error) {
	c := &plaintextContent{max: max}
	if !isKdbx4 || innerHeader == nil {
		return c, nil
	}
	// The InnerHeader's bytes go straight into the destination buffer, which
	// receives them within the same budget as the document.
	size := innerHeader.encodedSize()
	if err := innerHeader.writeToBounded(&c.headers, size, max); err != nil {
		return nil, err
	}
	if int64(c.headers.Len()) != size {
		return nil, fmt.Errorf("gokeepasslib: inner header of %d bytes, want %d", c.headers.Len(), size)
	}
	c.written = size
	return c, nil
}

// writeDocument writes the XML header and then the document with one
// streaming xml.Encoder into the collector. The encoder is configured exactly
// as xml.MarshalIndent(content, "", "\t") configures it, so the bytes are the
// same, but they reach the collector as they are produced: the collector
// rejects a write that would cross the budget before retaining any of it, and
// the encoder stops at that write, so nothing beyond the budget is written.
func (c *plaintextContent) writeDocument(content *DBContent) error {
	dst := &limitedWriter{w: &c.document, max: c.max, written: &c.written}
	if _, err := dst.Write(xmlHeader); err != nil {
		return err
	}
	enc := xml.NewEncoder(dst)
	enc.Indent("", "\t")
	// Encode flushes the encoder before it returns, and Close flushes it
	// again and reports a write error, exactly as MarshalIndent does.
	if err := enc.Encode(content); err != nil {
		return err
	}
	return enc.Close()
}

// reader returns the InnerHeader followed by the document as one stream, over
// the two collected buffers: neither is copied or concatenated with the
// other. The gzip path streams that reader, and the no-compression path makes
// the single full plaintext allocation its encryptor needs.
func (c *plaintextContent) reader() io.Reader {
	return io.MultiReader(&c.headers, &c.document)
}

// limitedWriter appends writes to w within a positive max, counting every
// collected byte in written. A write that would bring the collected length
// above max fails before any of its bytes are written, so neither the
// collector nor its budget ever holds a byte beyond max.
type limitedWriter struct {
	w       io.Writer
	max     int64
	written *int64
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if l.max > 0 && *l.written+int64(len(p)) > l.max {
		return 0, errPlaintextBudget()
	}
	n, err := l.w.Write(p)
	*l.written += int64(n)
	if err == nil && n != len(p) {
		return n, io.ErrShortWrite
	}
	return n, err
}

func errPlaintextBudget() error {
	return fmt.Errorf("%w: plaintext budget exceeded", ErrEncodeLimitExceeded)
}

// encodeRawContent compresses, pads and encrypts the plaintext content read
// from raw.
func encodeRawContent(
	db *Database,
	raw io.Reader,
	transformedKey []byte,
) ([]byte, error) {
	var content []byte
	// Compress if the header compression flag is 1 (gzip)
	if db.Header.FileHeaders.CompressionFlags == GzipCompressionFlag {
		b := new(bytes.Buffer)
		w := gzip.NewWriter(b)

		if _, err := io.Copy(w, raw); err != nil {
			w.Close()
			return nil, err
		}

		// Close() needs to be explicitly called to write Gzip stream footer,
		// Flush() is not enough. some gzip decoders treat missing footer as error
		// while some don't). internally Close() also does flush.
		if err := w.Close(); err != nil {
			return nil, err
		}

		content = b.Bytes()
	} else {
		var err error
		if content, err = io.ReadAll(raw); err != nil {
			return nil, err
		}
	}

	// Compose blocks (Kdbx v3.1)
	if !db.Header.IsKdbx4() {
		var blocks bytes.Buffer
		composeContentBlocks31(&blocks, content)

		// Append blocks to StreamStartBytes
		content = append(db.Header.FileHeaders.StreamStartBytes, blocks.Bytes()...)
	}

	// Always add padding, so that decoders that check for the last bytes can work correctly.
	// This is PKCS#7 for the CBC ciphers, while the KDBX 4 spec leaves
	// ChaCha20 unpadded; the writer appends it for every cipher anyway, so
	// writer output is always 16-byte aligned.
	padding := make([]byte, 16-(len(content)%16))
	for i := range len(padding) {
		padding[i] = byte(len(padding))
	}
	content = append(content, padding...)

	// Encrypt content
	// Decrypt content
	encrypter, err := db.GetEncrypterManager(transformedKey)
	if err != nil {
		return nil, err
	}
	encrypted := encrypter.Encrypt(content)

	// Compose blocks (Kdbx v4)
	if db.Header.IsKdbx4() {
		var blocks bytes.Buffer
		composeContentBlocks4(&blocks, encrypted, db.Header.FileHeaders.MasterSeed, transformedKey)

		encrypted = blocks.Bytes()
	}
	return encrypted, nil
}
