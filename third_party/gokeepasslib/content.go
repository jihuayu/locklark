package gokeepasslib

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
)

// Inner header bytes
const (
	InnerHeaderTerminator byte = 0x00 // Inner header terminator byte
	InnerHeaderIRSID      byte = 0x01 // Inner header InnerRandomStreamID byte
	InnerHeaderIRSKey     byte = 0x02 // Inner header InnerRandomStreamKey byte
	InnerHeaderBinary     byte = 0x03 // Inner header binary byte

	innerRandomStreamKeyLength = 64
)

// InnerHeader is the container of crypt options and binaries, only for Kdbx v4
type InnerHeader struct {
	InnerRandomStreamID  uint32
	InnerRandomStreamKey []byte
	Binaries             Binaries
}

// DBContent is a container for all elements of a keepass database
type DBContent struct {
	RawData     []byte       `xml:"-"` // XML encoded original data
	InnerHeader *InnerHeader `xml:"-"`
	XMLName     xml.Name     `xml:"KeePassFile"`
	Meta        *MetaData    `xml:"Meta"`
	Root        *RootData    `xml:"Root"`
}

func (c *DBContent) setKdbxFormatVersion(version formatVersion) {
	c.Meta.setKdbxFormatVersion(version)
	c.Root.setKdbxFormatVersion(version)
}

// kdbx41Field returns the name of the first field of the content which can only
// be represented in KDBX 4.1 files, or an empty string if there is none
func (c *DBContent) kdbx41Field() string {
	if c.Meta != nil {
		if field := c.Meta.kdbx41Field(); field != "" {
			return field
		}
	}

	if c.Root != nil {
		return c.Root.kdbx41Field()
	}

	return ""
}

type DBContentOption func(*DBContent)

func WithDBContentFormattedTime(formatted bool) DBContentOption {
	return func(content *DBContent) {
		WithMetaDataFormattedTime(formatted)(content.Meta)
		WithRootDataFormattedTime(formatted)(content.Root)
	}
}

func withDBContentKDBX4InnerHeader(content *DBContent) {
	innerRandomStreamKey := make([]byte, innerRandomStreamKeyLength)
	rand.Read(innerRandomStreamKey)

	content.InnerHeader = &InnerHeader{
		InnerRandomStreamID:  ChaChaStreamID,
		InnerRandomStreamKey: innerRandomStreamKey,
	}
}

// NewContent creates a new database content with some good defaults
func NewContent(options ...DBContentOption) *DBContent {
	// Not necessary create InnerHeader because this will be a KDBX v3.1
	content := &DBContent{
		Meta: NewMetaData(),
		Root: NewRootData(),
	}

	for _, option := range options {
		option(content)
	}

	return content
}

// readFrom reads the InnerHeader from an io.Reader
func (ih *InnerHeader) readFrom(r io.Reader) error {
	return ih.parse(r, 0)
}

// readFromWithLimits reads the InnerHeader from an io.Reader in bounded mode.
// The aggregate bytes of every InnerHeaderBinary payload, memory protection
// flag included, are charged against maxBinaryBytes, and a binary field which
// cannot fit the remaining budget is rejected with ErrDecodeLimitExceeded
// before any of it is copied.
//
// A one-byte binary (protection flag, no content) is a valid empty binary and
// is accepted; its flag byte is charged against maxBinaryBytes like any other
// binary byte. Bounded mode also rejects malformed fields which the unbounded
// parser tolerates: a binary field of 0 bytes (no protection flag), an inner
// random stream id field which is not exactly 4 bytes, and negative binary
// lengths. Unbounded readFrom keeps its original behavior exactly.
func (ih *InnerHeader) readFromWithLimits(r io.Reader, maxBinaryBytes int64) error {
	return ih.parse(r, maxBinaryBytes)
}

// parse reads the InnerHeader from r. With maxBinaryBytes positive the
// aggregate binary bytes are charged against it before each binary is read.
func (ih *InnerHeader) parse(r io.Reader, maxBinaryBytes int64) error {
	aggregate := int64(0) // Aggregate binary bytes, flag included
	bounded := maxBinaryBytes > 0
	binaryCount := 0 // Var used to count and index every binary
ForLoop:
	for {
		var headerType byte
		var length int32

		if err := binary.Read(r, binary.LittleEndian, &headerType); err != nil {
			return err
		}
		if err := binary.Read(r, binary.LittleEndian, &length); err != nil {
			return err
		}
		if bounded && headerType == InnerHeaderIRSID && length != 4 {
			// The inner random stream id is read as a uint32 and must not
			// reach that conversion with a short payload.
			return fmt.Errorf("%w: inner random stream id of %d bytes", ErrCorruptedDatabase, int64(length))
		}
		if bounded && headerType == InnerHeaderBinary {
			// The payload is the memory protection flag byte followed by
			// the content, so one byte is an empty binary and zero bytes
			// is missing the required flag.
			if length < 0 {
				return fmt.Errorf("%w: negative inner header binary length", ErrCorruptedDatabase)
			}
			if int64(length) > maxBinaryBytes-aggregate {
				return fmt.Errorf("%w: inner header binary budget exceeded", ErrDecodeLimitExceeded)
			}
			if length < 1 {
				return fmt.Errorf("%w: inner header binary of %d bytes has no protection flag", ErrCorruptedDatabase, int64(length))
			}
			aggregate += int64(length)
		}
		data, err := readBytes(r, int64(length))
		if err != nil {
			return err
		}

		switch headerType {
		case InnerHeaderTerminator:
			// End of inner header
			break ForLoop
		case InnerHeaderIRSID:
			// Found InnerRandomStream ID
			ih.InnerRandomStreamID = binary.LittleEndian.Uint32(data)
		case InnerHeaderIRSKey:
			// Found InnerRandomStream Key
			ih.InnerRandomStreamKey = data
		case InnerHeaderBinary:
			// Found a binary
			var protection byte
			reader := bytes.NewReader(data)

			binary.Read(reader, binary.LittleEndian, &protection) // Read memory protection flag
			content, _ := io.ReadAll(reader)                      // Read content

			ih.Binaries = append(
				ih.Binaries,
				Binary{
					ID:               binaryCount,
					MemoryProtection: protection,
					Content:          content,
					// Ensure that loading the binary data
					// correctly considers the encoding/decoding of binary data
					isKDBX4: true,
				},
			)

			binaryCount = binaryCount + 1
		default:
			return ErrUnknownInnerHeaderID(headerType)
		}
	}
	return nil
}

// innerHeaderItemSize is the exact size writeToInnerHeader writes for one
// inner header item: its 1-byte type, 4-byte value length and value, or zero
// for an empty value, which writes no item.
func innerHeaderItemSize(dataLen int) int64 {
	if dataLen == 0 {
		return 0
	}
	return int64(1 + 4 + dataLen)
}

const (
	// innerHeaderItemHeaderSize is the size of the type and length fields
	// that writeToInnerHeader writes before an item's data.
	innerHeaderItemHeaderSize = 1 + 4
	// innerHeaderTerminatorSize is the size of the inner header terminator.
	innerHeaderTerminatorSize = 1 + 4
)

// encodedSize returns the exact number of bytes writeTo writes for the
// InnerHeader, without serializing it: the 4-byte inner random stream id item,
// the inner random stream key item, one item per binary and the terminator.
func (ih *InnerHeader) encodedSize() int64 {
	size := int64(innerHeaderTerminatorSize)
	size += innerHeaderItemSize(4)
	size += innerHeaderItemSize(len(ih.InnerRandomStreamKey))
	for _, item := range ih.Binaries {
		size += innerHeaderItemSize(1 + len(item.Content))
	}
	return size
}

// writeTo the InnerHeader to the given io.Writer. Every item and the
// terminator are written with one write of exactly their encoded size, so a
// bounded writer sees the exact size of each and can enforce a size limit
// without retaining a byte beyond it.
func (ih *InnerHeader) writeTo(w io.Writer) error {
	irsID := make([]byte, 4)
	binary.LittleEndian.PutUint32(irsID, ih.InnerRandomStreamID)

	if err := writeToInnerHeader(w, InnerHeaderIRSID, irsID); err != nil {
		return err
	}
	if err := writeToInnerHeader(w, InnerHeaderIRSKey, ih.InnerRandomStreamKey); err != nil {
		return err
	}

	for _, item := range ih.Binaries {
		buf := make([]byte, 0, 1+len(item.Content))
		buf = append(buf, item.MemoryProtection)
		buf = append(buf, item.Content...)
		if err := writeToInnerHeader(w, InnerHeaderBinary, buf); err != nil {
			return err
		}
	}
	// End inner header
	_, err := w.Write(binary.LittleEndian.AppendUint32([]byte{InnerHeaderTerminator}, 0))
	return err
}

// writeToInnerHeader is an helper to write an inner header item to the given
// io.Writer, in one write of the item's exact size.
func writeToInnerHeader(w io.Writer, id uint8, data []byte) error {
	if len(data) > 0 {
		item := make([]byte, 0, innerHeaderItemSize(len(data)))
		item = append(item, id)
		item = binary.LittleEndian.AppendUint32(item, uint32(len(data)))
		item = append(item, data...)
		if _, err := w.Write(item); err != nil {
			return err
		}
	}
	return nil
}

// writeToBounded appends the InnerHeader in encodedSize bytes to dst, which
// receives it directly: no item is staged and no buffer is copied. When the
// append grows dst's capacity, the budget is checked before the allocation,
// so dst of capacity size receives nothing on a budget error.
func (ih *InnerHeader) writeToBounded(dst *bytes.Buffer, size, max int64) error {
	if max > 0 && int64(dst.Len())+size > max {
		return errPlaintextBudget()
	}
	// The slice is captured once: dst must not be copied by value after its
	// buffer is written.
	buf := ih.appendTo(dst.AvailableBuffer())
	if _, err := dst.Write(buf); err != nil {
		return err
	}
	return nil
}

// appendTo appends the InnerHeader's encoding to buf, one item at a time,
// without staging an item in its own buffer.
func (ih *InnerHeader) appendTo(buf []byte) []byte {
	var irsID [4]byte
	binary.LittleEndian.PutUint32(irsID[:], ih.InnerRandomStreamID)

	buf = appendInnerHeaderItem(buf, InnerHeaderIRSID, irsID[:])
	buf = appendInnerHeaderItem(buf, InnerHeaderIRSKey, ih.InnerRandomStreamKey)
	for _, item := range ih.Binaries {
		// A binary is always written, its protection flag alone for an
		// empty one, as writeTo writes it.
		buf = appendInnerHeaderItemHeader(buf, InnerHeaderBinary, 1+len(item.Content))
		buf = append(buf, item.MemoryProtection)
		buf = append(buf, item.Content...)
	}
	return appendInnerHeaderTerminator(buf)
}

// appendInnerHeaderItem appends one item, the same bytes writeToInnerHeader
// writes for it.
func appendInnerHeaderItem(buf []byte, id uint8, data []byte) []byte {
	if len(data) == 0 {
		return buf
	}
	buf = appendInnerHeaderItemHeader(buf, id, len(data))
	return append(buf, data...)
}

// appendInnerHeaderItemHeader appends an item's type and length fields.
func appendInnerHeaderItemHeader(buf []byte, id uint8, dataLen int) []byte {
	buf = append(buf, id)
	return binary.LittleEndian.AppendUint32(buf, uint32(dataLen))
}

// appendInnerHeaderTerminator appends the type and length fields of the
// terminator, which writeTo writes as one 5-byte write.
func appendInnerHeaderTerminator(buf []byte) []byte {
	return binary.LittleEndian.AppendUint32(append(buf, InnerHeaderTerminator), 0)
}

func (ih InnerHeader) String() string {
	return fmt.Sprintf(
		"1) InnerRandomStreamID: %d\n"+
			"2) InnerRandomStreamKey: %x\n"+
			"3) Binaries: %s\n",
		ih.InnerRandomStreamID,
		ih.InnerRandomStreamKey,
		ih.Binaries,
	)
}

// ErrEndOfInnerHeaders is the error returned when the end of inner header is read
var ErrEndOfInnerHeaders = errors.New("gokeepasslib: inner header id was 0, end of inner headers")

// ErrUnknownInnerHeaderID is the error returned if an unknown inner header is read
type ErrUnknownInnerHeaderID byte

func (e ErrUnknownInnerHeaderID) Error() string {
	return fmt.Sprintf("gokeepasslib: unknown inner header ID of %d", int(e))
}
