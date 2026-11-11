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

	// measure, when set, receives the exact plaintext size of the content
	// once it has been serialized within budget.
	measure func(int64)
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
	// encrypted. It is enforced on the plaintext collector's writes before a
	// byte beyond it is retained. The XML document is marshaled as a whole
	// before the budget applies to it, so the budget cannot prevent a large
	// database from being marshaled; it rejects the database before its
	// content is compressed, padded or encrypted.
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
// and hash updates) and before it is compressed, padded or encrypted.
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

	// Encode xml and the InnerHeader (Kdbx v4) through one plaintext
	// collector: both are serialized exactly once, and a bounded encode
	// charges both against one plaintext budget before the content is
	// compressed.
	raw := newPlaintextContent(db.Header.IsKdbx4(), maxPlaintext > 0, maxPlaintext)
	if err = raw.writeDocument(db.Content); err != nil {
		return err
	}
	if err = raw.writeInnerHeader(db.Content.InnerHeader); err != nil {
		return err
	}

	if e.measure != nil {
		e.measure(raw.measure)
	}

	// Encode raw content
	encodedContent, err := encodeRawContent(db, raw.reader(), transformedKey)
	if err != nil {
		return err
	}

	// Writes the encrypted database content
	_, err = e.w.Write(encodedContent)
	return err
}

// plaintextContent is the plaintext of one encode: the KDBX4 InnerHeader
// followed by the XML document. A positive max is a plaintext budget, which is
// enforced on writes before a byte beyond it is retained.
type plaintextContent struct {
	headers  bytes.Buffer
	document bytes.Buffer
	isKdbx4  bool
	max      int64
	measure  int64
	exceeded bool
}

func newPlaintextContent(isKdbx4, bounded bool, max int64) *plaintextContent {
	if !bounded {
		max = 0
	}
	return &plaintextContent{isKdbx4: isKdbx4, max: max}
}

// Write collects p. A write that would bring the collected length above max
// fails before any of its bytes are retained.
func (c *plaintextContent) Write(p []byte) (int, error) {
	if c.max > 0 && c.measure+int64(len(p)) > c.max {
		c.exceeded = true
		return 0, c.limitError()
	}
	c.measure += int64(len(p))
	return c.document.Write(p)
}

// writeDocument marshals the XML document exactly as marshalXMLContent did,
// the XML header included.
func (c *plaintextContent) writeDocument(content *DBContent) error {
	rawContent, err := xml.MarshalIndent(content, "", "\t")
	if err != nil {
		return err
	}
	if _, err = c.Write(xmlHeader); err != nil {
		return c.checkErr(err)
	}
	if _, err = c.Write(rawContent); err != nil {
		return c.checkErr(err)
	}
	return c.check()
}

// writeInnerHeader places the KDBX4 InnerHeader in front of the document. It
// is charged against the budget as a whole, from its encoded size, before any
// of it is retained.
func (c *plaintextContent) writeInnerHeader(ih *InnerHeader) error {
	if !c.isKdbx4 {
		return nil
	}
	if err := c.reserve(ih.encodedSize()); err != nil {
		return err
	}
	// The InnerHeader is written through a wrapper, whose bytes are copied
	// back: a bytes.Buffer must not be copied by value once written.
	header := &boundedContentBuffer{max: c.max, limit: c.limitError}
	err := ih.writeTo(header)
	c.headers.Write(header.buf.Bytes())
	if err != nil {
		return c.checkErr(err)
	}
	return c.check()
}

// reader returns the collected InnerHeader followed by the document as one
// body, without copying the document when there is no InnerHeader.
func (c *plaintextContent) reader() io.Reader {
	document := c.document.Bytes()
	if c.headers.Len() == 0 {
		return bytes.NewReader(document)
	}
	payload := make([]byte, 0, c.headers.Len()+len(document))
	payload = append(payload, c.headers.Bytes()...)
	return bytes.NewReader(append(payload, document...))
}

// reserve charges n bytes that are about to be collected as a whole.
func (c *plaintextContent) reserve(n int64) error {
	if c.max > 0 && c.measure+n > c.max {
		c.exceeded = true
		return c.limitError()
	}
	c.measure += n
	return nil
}

// checkErr prefers the budget error once a write was rejected over budget.
func (c *plaintextContent) checkErr(err error) error {
	if c.exceeded {
		return c.limitError()
	}
	return err
}

// check reports the budget error once a write was rejected over budget.
func (c *plaintextContent) check() error { return c.checkErr(nil) }

func (c *plaintextContent) limitError() error {
	return fmt.Errorf("%w: plaintext budget exceeded", ErrEncodeLimitExceeded)
}

// boundedContentBuffer collects writes in buf up to a positive max. A write
// that would bring the collected length above max fails before any of its
// bytes are retained.
type boundedContentBuffer struct {
	buf   bytes.Buffer
	max   int64
	limit func() error
}

func (b *boundedContentBuffer) Write(p []byte) (int, error) {
	if b.max > 0 && int64(b.buf.Len())+int64(len(p)) > b.max {
		return 0, b.limit()
	}
	return b.buf.Write(p)
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

	// Always add padding, so that decoders that check for the last bytes can work correctly
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
