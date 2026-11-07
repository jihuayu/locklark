package browserhost

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jihuayu/locklark/internal/personal"
)

const (
	// MaxAttachmentBytes mirrors the durable vault's per-attachment bound. The
	// native message bounds MaxInput/MaxOutput stay at 256KiB; a full 2MiB file
	// only ever travels as bounded chunks.
	MaxAttachmentBytes        = 2 << 20
	maxAttachmentChunk        = 64 << 10
	maxAttachmentChunkEncoded = (maxAttachmentChunk+2)/3*4 + 4
	attachmentUploadTTL       = 120 * time.Second
	attachmentCommitWindow    = 30 * time.Second
	maxAttachmentCount        = 16
)

// stagedAttachment is the one connection-memory upload allowed at a time. It is
// bound to one session pointer/epoch and one exact item revision. Every byte is
// cleared on commit, cancel, expiry, lock, disconnect or capability loss.
type stagedAttachment struct {
	id       string
	session  *personal.Session
	epoch    uint64
	itemID   string
	revision string
	fileName string
	mimeType string
	size     int64
	sha256   string
	buf      []byte
	offset   int64
	until    time.Time
	timer    *time.Timer
}

func (*stagedAttachment) String() string               { return "[private staged attachment upload]" }
func (*stagedAttachment) GoString() string             { return "[private staged attachment upload]" }
func (*stagedAttachment) MarshalJSON() ([]byte, error) { return nil, ErrProtocol }

func (u *stagedAttachment) clear() {
	if u == nil {
		return
	}
	if u.timer != nil {
		u.timer.Stop()
		u.timer = nil
	}
	clear(u.buf)
	u.buf, u.offset = nil, 0
}

func (c *Connection) clearUpload() {
	if c.upload != nil {
		c.upload.clear()
		c.upload = nil
	}
}

func (c *Connection) expireUpload() {
	if c.upload != nil && !c.now().Before(c.upload.until) {
		c.clearUpload()
	}
}

// findUpload returns the live staged upload for one token. A stale token drops
// the staged bytes instead of resurrecting them.
func (c *Connection) findUpload(id string) *stagedAttachment {
	up := c.upload
	if up == nil || up.id != id {
		return nil
	}
	if !c.now().Before(up.until) {
		c.clearUpload()
		return nil
	}
	return up
}

// validAttachmentFileName enforces a single safe display/download name: no
// separators, no control characters, no dot-only names and no edge whitespace.
func validAttachmentFileName(name string) bool {
	if name == "" || len(name) > 255 || name == "." || name == ".." || !utf8.ValidString(name) {
		return false
	}
	if strings.ContainsAny(name, "/\\") || strings.TrimSpace(name) != name {
		return false
	}
	return !strings.ContainsFunc(name, func(r rune) bool {
		return unicode.IsControl(r) || r == 0xfffe || r == 0xffff
	})
}

func validAttachmentMime(mime string) bool {
	if mime == "" {
		return true
	}
	if len(mime) > 256 || !utf8.ValidString(mime) {
		return false
	}
	return !strings.ContainsFunc(mime, func(r rune) bool {
		return r < 32 || r == 0x7f || r == 0xfffe || r == 0xffff
	})
}

// attachmentSelector mirrors the durable attachment selector alphabet.
func attachmentSelector(s string) bool {
	if s == "" || len(s) > 256 {
		return false
	}
	for _, c := range []byte(s) {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' {
			continue
		}
		return false
	}
	return true
}

// attachmentFrameIdle rejects the item, file and origin fields that no
// dedicated attachment payload frame may carry.
func attachmentFrameIdle(r Request) bool {
	return r.ItemID == "" && r.Revision == "" && r.FileName == "" && r.Size == nil && r.SHA256 == "" &&
		r.MimeType == "" && r.AttachmentID == "" && r.Length == 0 && r.Origin == "" && r.TabID == 0 && r.DocumentID == ""
}

func attachmentReadType(kind string) bool { return kind == "attachment-read" }

// newTransferID returns 32 lowercase hex characters.
func newTransferID() (string, error) {
	var value [16]byte
	if _, e := rand.Read(value[:]); e != nil {
		return "", ErrProtocol
	}
	return hex.EncodeToString(value[:]), nil
}

// decodeAttachmentChunk strictly decodes one bounded base64 chunk. It never
// returns a partially decoded buffer for an invalid frame.
func decodeAttachmentChunk(data string) []byte {
	if data == "" || len(data) > maxAttachmentChunkEncoded {
		return nil
	}
	raw, e := base64.StdEncoding.Strict().DecodeString(data)
	if e != nil || len(raw) == 0 || len(raw) > maxAttachmentChunk {
		clear(raw)
		return nil
	}
	return raw
}
