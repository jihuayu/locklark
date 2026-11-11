package gokeepasslib

import (
	"bytes"
	"compress/gzip"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math"
)

var (
	errInvalidHMACKey          = errors.New("Wrong password? HMAC-SHA256 of header mismatching")
	errDatabaseIntegrityFailed = errors.New("Wrong password? Database integrity check failed")
)

// ErrDecodeLimitExceeded is returned by DecodeWithLimits when the input or a
// decoded body exceeds a DecodeLimits budget. The error never embeds input
// data.
var ErrDecodeLimitExceeded = errors.New("gokeepasslib: database exceeds decode limits")

// DecodeLimits bounds the input and the decoded bodies of DecodeWithLimits.
// Both fields must be positive and below MaxInt64.
type DecodeLimits struct {
	// MaxEncodedBytes bounds the total KDBX input: header, hashes and
	// content blocks alike. The reader is read at most MaxEncodedBytes+1
	// bytes, so an over-limit input is rejected before the header is parsed
	// and before any key derivation runs.
	MaxEncodedBytes int64
	// MaxPlaintextBytes bounds the decrypted content (the KDBX4 InnerHeader
	// followed by the XML document), not counting cipher padding, and,
	// within it, the aggregate bytes of every KDBX4 InnerHeader binary,
	// memory protection flag included.
	//
	// This budget can only be evaluated after key derivation and content
	// decryption, so it is not checked before key derivation. It is enforced
	// on the verified and decrypted content blocks and, when gzip is
	// selected, on the expansion (reading at most the budget plus one byte)
	// before XML decoding starts. With NoCompressionFlag a valid 1..16-byte
	// repeated-count cipher padding that the writer emitted is removed
	// before the logical-body limit is applied; content without such a
	// sequence is left unchanged. When content is not compressed both
	// bounds apply to the same bytes, so the aggregate binary budget can
	// only take effect for a binary inside an expanded body.
	MaxPlaintextBytes int64
}

func (l DecodeLimits) validate() error {
	if l.MaxEncodedBytes <= 0 || l.MaxPlaintextBytes <= 0 ||
		l.MaxEncodedBytes == math.MaxInt64 || l.MaxPlaintextBytes == math.MaxInt64 {
		return fmt.Errorf("%w: every limit must be positive and below MaxInt64", ErrDecodeLimitExceeded)
	}
	return nil
}

// Decoder stores a reader which is expected to be in kdbx format
type Decoder struct {
	r io.Reader
}

// NewDecoder creates a new decoder with reader r, identical to gokeepasslib.Decoder{r}
func NewDecoder(r io.Reader) *Decoder {
	return &Decoder{r: r}
}

// Decode populates given database with the data of Decoder reader.
//
// Decode reads the whole input and the whole decompressed content without a
// size budget. Use DecodeWithLimits for untrusted input.
func (d *Decoder) Decode(db *Database) error {
	return d.decode(db, decodeBudget{})
}

// DecodeWithLimits populates db from the Decoder reader under limits. It
// shares the parser, block and decryption path with Decode, and additionally:
//
//  1. reads the input at most limits.MaxEncodedBytes+1 bytes and rejects an
//     over-limit input with ErrDecodeLimitExceeded before the KDBX header is
//     parsed and before key derivation; a header that is not KDBX 4 is
//     rejected with ErrCorruptedDatabase right after parsing;
//  2. bounds the verified and decrypted content blocks by
//     limits.MaxEncodedBytes, so a damaged block length cannot allocate more
//     than the input budget admits;
//  3. bounds the content handed on for parsing (the decrypted content, or
//     its gzip expansion when the header selects gzip) by
//     limits.MaxPlaintextBytes, detected with one extra byte, and rejects an
//     over-budget body with ErrDecodeLimitExceeded before XML decoding.
//     Cipher padding is not part of the budget: without compression a valid
//     1..16-byte repeated-count padding that the writer emitted is removed
//     before the logical-body limit is applied, and content without such a
//     sequence is left unchanged;
//  4. parses the KDBX4 InnerHeader in bounded mode, which rejects a binary
//     that would bring the aggregate binary bytes (protection flags
//     included) over limits.MaxPlaintextBytes before copying it. A one-byte
//     binary is a valid empty binary: its protection flag alone, with no
//     content, and that flag byte is charged against the budget. A binary
//     without a protection flag (length 0) or a negative binary length is
//     malformed and rejected with ErrCorruptedDatabase.
//
// The key derivation function stays guarded by the DBCredentials KDF check,
// which rejects unsupported algorithms and parameters before any Argon2
// allocation. The plaintext budgets of points 3 and 4 can only be evaluated
// after key derivation and content decryption, never before it.
//
// DecodeLimits with a non-positive or MaxInt64 limit is reported as
// ErrDecodeLimitExceeded. Errors never embed input data.
func (d *Decoder) DecodeWithLimits(db *Database, limits DecodeLimits) error {
	if err := limits.validate(); err != nil {
		return err
	}
	return d.decode(db, decodeBudget{
		bounded:   true,
		encoded:   limits.MaxEncodedBytes,
		plaintext: limits.MaxPlaintextBytes,
	})
}

// decodeBudget is the active budget of one decode. With bounded unset every
// read is unbounded, which is the Decode behavior.
type decodeBudget struct {
	bounded   bool
	encoded   int64
	plaintext int64
}

// readAtMost reads r until EOF, at most max+1 bytes, without preallocating
// them, so memory only grows with the data actually read. Exactly max bytes
// are accepted; one more byte rejects the input with ErrDecodeLimitExceeded.
func readAtMost(r io.Reader, max int64, what string) ([]byte, error) {
	var data []byte
	var buf [32 << 10]byte
	for {
		remaining := max + 1 - int64(len(data))
		if remaining <= 0 {
			return nil, fmt.Errorf("%w: %s budget exceeded", ErrDecodeLimitExceeded, what)
		}
		chunk := int64(len(buf))
		if remaining < chunk {
			chunk = remaining
		}
		k, err := r.Read(buf[:chunk])
		data = append(data, buf[:k]...)
		if int64(len(data)) > max {
			return nil, fmt.Errorf("%w: %s budget exceeded", ErrDecodeLimitExceeded, what)
		}
		if err == io.EOF {
			return data, nil
		}
		if err != nil {
			return nil, err
		}
	}
}

// decode is the single decode path of Decode and DecodeWithLimits. An
// unbounded Decode reads its input with io.ReadAll, as before.
func (d *Decoder) decode(db *Database, budget decodeBudget) error {
	r := d.r
	if budget.bounded {
		// Read at most the encoded limit plus one byte, so an over-limit
		// input is rejected before the header is parsed and before the
		// key derivation runs.
		input, err := readAtMost(d.r, budget.encoded, "encoded input")
		if err != nil {
			return err
		}
		r = bytes.NewReader(input)
	}

	// Read header
	db.Header = new(DBHeader)
	if err := db.Header.readFrom(r); err != nil {
		return err
	}

	// The bounded path only decodes KDBX4 content. KDBX 3.1 key derivation
	// runs an AES loop over the header TransformRounds, which untrusted input
	// can set to an unbounded value, so it is rejected before the header
	// hash is read and before any key derivation.
	if budget.bounded && !db.Header.IsKdbx4() {
		return fmt.Errorf("%w: bounded decoding supports KDBX 4 only", ErrCorruptedDatabase)
	}

	// Read hashes and validate the header hash (Kdbx v4)
	// The header is validated before calculating the transformed key, so the
	// key derivation never runs on the parameters of a corrupted header
	if db.Header.IsKdbx4() {
		db.Hashes = new(DBHashes)
		err := db.Hashes.readFrom(r)
		if err != nil {
			return err
		}

		if db.Options.ValidateHashes {
			err = db.Header.ValidateSha256(db.Hashes.Sha256)
			if err != nil {
				return err
			}
		}
	}

	// Calculate transformed key to decrypt and calculate HMAC
	transformedKey, err := db.getTransformedKey()
	if err != nil {
		return err
	}

	// Validate the header HMAC (Kdbx v4)
	if db.Header.IsKdbx4() {
		if db.Options.ValidateHashes {
			hmacKey := buildHmacKey(db, transformedKey)
			err = db.Header.ValidateHmacSha256(hmacKey, db.Hashes.Hmac)
			if err != nil {
				return errInvalidHMACKey
			}
		}
	}

	// Decode raw content
	// A bounded input was already limited to the encoded budget, and the
	// content cannot exceed it.
	rawContent, err := io.ReadAll(r)
	if err != nil {
		return err
	}

	if err := decodeRawContent(db, rawContent, transformedKey, budget); err != nil {
		return err
	}

	contentReader := bytes.NewReader(db.Content.RawData)

	// Read InnerHeader (Kdbx v4)
	if db.Header.IsKdbx4() {
		db.Content.InnerHeader = new(InnerHeader)
		if budget.bounded {
			err = db.Content.InnerHeader.readFromWithLimits(contentReader, budget.plaintext)
		} else {
			err = db.Content.InnerHeader.readFrom(contentReader)
		}
		if err != nil {
			return err
		}
	}

	// Decode xml
	xmlDecoder := xml.NewDecoder(contentReader)
	return xmlDecoder.Decode(db.Content)
}

// readBytes reads exactly length bytes from r.
// Unlike allocating length bytes upfront, the result only grows with the data
// actually read, so a damaged length cannot cause a huge allocation
func readBytes(r io.Reader, length int64) ([]byte, error) {
	if length < 0 {
		return nil, fmt.Errorf("%w: negative length %d", ErrCorruptedDatabase, length)
	}

	data, err := io.ReadAll(io.LimitReader(r, length))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != length {
		return nil, io.ErrUnexpectedEOF
	}
	return data, nil
}

func decodeRawContent(db *Database, content []byte, transformedKey []byte, budget decodeBudget) error {
	var err error
	// Initialize content
	db.Content = new(DBContent)

	if db.Header.IsKdbx4() {
		// Decompose content blocks
		// In Kdbx v4 you must parse blocks before decrypt
		reader := bytes.NewReader(content)
		content, err = decomposeContentBlocks4(reader, db.Header.FileHeaders.MasterSeed, transformedKey)
		if err != nil {
			return err
		}
	} else {
		// In Kdbx v3.1 you must decrypt before parse blocks
		reader := bytes.NewReader(content)
		content, err = io.ReadAll(reader)
		if err != nil {
			return err
		}
	}

	if budget.bounded && int64(len(content)) > budget.encoded {
		return fmt.Errorf("%w: decrypted content budget exceeded", ErrDecodeLimitExceeded)
	}

	// Decrypt content
	encrypter, err := db.GetEncrypterManager(transformedKey)
	if err != nil {
		return err
	}

	// Block ciphers in CBC mode panic on an IV which is not a single block
	// and can only decrypt whole blocks, which a truncated file lacks
	blockSize := cipherBlockSize(db.Header.FileHeaders.CipherID)
	if blockSize > 0 && len(db.Header.FileHeaders.EncryptionIV) != blockSize {
		return fmt.Errorf(
			"%w: encryption IV of %d bytes does not match the cipher block size",
			ErrCorruptedDatabase,
			len(db.Header.FileHeaders.EncryptionIV),
		)
	}
	if blockSize > 0 && len(content)%blockSize != 0 {
		return fmt.Errorf(
			"%w: encrypted content of %d bytes is no multiple of the cipher block size",
			ErrCorruptedDatabase,
			len(content),
		)
	}
	decryptedContent := encrypter.Decrypt(content)

	// Check for StreamStartBytes (Kdbx v3.1)
	if !db.Header.IsKdbx4() {
		startBytes := db.Header.FileHeaders.StreamStartBytes
		if !bytes.HasPrefix(decryptedContent, startBytes) {
			return errDatabaseIntegrityFailed
		}

		decryptedContent = decryptedContent[len(startBytes):]
	}

	// Decompose content blocks and update reader
	// Kdbx v3.1 content must be read after decryption
	if !db.Header.IsKdbx4() {
		reader := bytes.NewReader(decryptedContent)
		decryptedContent, err = decomposeContentBlocks31(reader)
		if err != nil {
			return err
		}
	}

	// Decompress if the header compression flag is 1 (gzip)
	if db.Header.FileHeaders.CompressionFlags == GzipCompressionFlag {
		reader := bytes.NewReader(decryptedContent)
		r, err := gzip.NewReader(reader)
		if err != nil {
			return err
		}
		defer r.Close()

		// KeePass writes a single gzip stream. The content of a block cipher
		// is followed by its padding, which must not be read as another stream
		r.Multistream(false)

		if budget.bounded {
			// Reading in small chunks keeps every allocation proportional
			// to the data actually inflated, so a compression bomb is
			// detected with one byte over the budget instead of being
			// allocated first.
			decryptedContent, err = readAtMost(r, budget.plaintext, "decompressed content")
		} else {
			decryptedContent, err = io.ReadAll(r)
		}
		if err != nil {
			return err
		}
	} else if budget.bounded {
		// Without compression the decrypted content is the plaintext body
		// followed by the cipher block padding the writer appends. The
		// budget is the logical body, so a valid writer-emitted padding
		// sequence is dropped before it is measured, and an over-budget
		// body is rejected before it is handed on for parsing.
		decryptedContent = trimCipherPadding(decryptedContent)
		if int64(len(decryptedContent)) > budget.plaintext {
			return fmt.Errorf("%w: decrypted content budget exceeded", ErrDecodeLimitExceeded)
		}
	}

	db.Content.RawData = decryptedContent
	return nil
}

// trimCipherPadding removes the trailing cipher block padding from an
// uncompressed KDBX4 content, which is the body followed by 1..16 bytes that
// each hold the padding length, as encodeRawContent appends them. Content
// without such a sequence is returned unchanged, so a file that carries none
// keeps its bytes.
func trimCipherPadding(content []byte) []byte {
	if len(content) == 0 {
		return content
	}
	n := int(content[len(content)-1])
	if n < 1 || n > 16 || n > len(content) {
		return content
	}
	for _, b := range content[len(content)-n:] {
		if int(b) != n {
			return content
		}
	}
	return content[:len(content)-n]
}
