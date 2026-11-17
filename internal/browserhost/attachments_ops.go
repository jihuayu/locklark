package browserhost

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/vault"
)

// attachmentMessage dispatches the six capability-bounded attachment
// operations. Connection.Handle already holds c.mu, so every staged pointer
// transition below is serialized with lock/invalidate/expire.
func (c *Connection) attachmentMessage(r Request) (bool, error) {
	switch r.Type {
	case "attachment-begin":
		return true, c.attachmentBegin(r)
	case "attachment-chunk":
		return true, c.attachmentChunk(r)
	case "attachment-commit":
		return true, c.attachmentCommit(r)
	case "attachment-cancel":
		return true, c.attachmentCancel(r)
	case "attachment-read":
		return true, c.attachmentRead(r)
	case "attachment-remove":
		return true, c.attachmentRemove(r)
	}
	return false, nil
}

func attachmentSummary(meta vault.AttachmentMeta) *BrowserAttachment {
	return &BrowserAttachment{
		ID:        meta.ID,
		FileName:  meta.FileName,
		Size:      meta.Size,
		MIMEType:  meta.MIMEType,
		SHA256:    meta.SHA256,
		Protected: meta.Protected,
	}
}

func (c *Connection) transferResponse(id, transfer string, up *stagedAttachment) error {
	return c.response(Response{ID: id, Type: "attachment-transfer", TransferID: transfer, Offset: up.offset, Size: up.size, ExpiresInSeconds: int(up.until.Sub(c.now()) / time.Second)})
}

func (c *Connection) attachmentBegin(r Request) error {
	c.expireUpload()
	// Only one connection-memory upload exists at a time; a live one refuses
	// replacement until it is committed, cancelled or expires.
	if c.upload != nil || r.Size == nil {
		return c.refuse(r.ID)
	}
	s := c.session.Load()
	if s == nil || !s.Unlocked() || *r.Size > MaxAttachmentBytes {
		return c.refuse(r.ID)
	}
	items, revisions, e := s.ReadAuthenticatedItems(true)
	if e != nil || !s.Unlocked() {
		return c.refuse(r.ID)
	}
	it, ok := c.findItem(items, r.ItemID)
	if !ok || revisions[it.ID] != r.Revision || it.State == "trashed" || len(it.Attachments) >= maxAttachmentCount {
		return c.refuse(r.ID)
	}
	transfer, e := newTransferID()
	if e != nil {
		return c.refuse(r.ID)
	}
	until := minTime(c.until, c.now().Add(attachmentUploadTTL))
	up := &stagedAttachment{
		id:       transfer,
		session:  s,
		epoch:    c.epoch,
		itemID:   it.ID,
		revision: r.Revision,
		fileName: r.FileName,
		mimeType: r.MimeType,
		size:     *r.Size,
		sha256:   r.SHA256,
		buf:      make([]byte, 0, int(*r.Size)),
		until:    until,
	}
	c.upload = up
	// Deterministic against the connection clock, never the wall clock.
	up.timer = time.AfterFunc(until.Sub(c.now()), func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		defer c.changed()
		if c.upload == up {
			c.clearUpload()
		}
	})
	return c.transferResponse(r.ID, transfer, up)
}

func (c *Connection) attachmentChunk(r Request) error {
	up := c.findUpload(r.TransferID)
	if up == nil {
		return c.refuse(r.ID)
	}
	if up.session != c.session.Load() || up.epoch != c.epoch || !up.session.Unlocked() {
		c.clearUpload()
		return c.refuse(r.ID)
	}
	raw := decodeAttachmentChunk(r.Data)
	// A refused chunk wipes the staged bytes: a malformed or replayed stream
	// must be restarted from begin instead of being probed further.
	if raw == nil {
		c.clearUpload()
		return c.refuse(r.ID)
	}
	defer clear(raw)
	// Exact sequential offsets only: no replay, gap, overlap or overflow.
	if r.Offset != up.offset || r.Offset+int64(len(raw)) > up.size {
		c.clearUpload()
		return c.refuse(r.ID)
	}
	up.buf = append(up.buf, raw...)
	up.offset += int64(len(raw))
	return c.transferResponse(r.ID, up.id, up)
}

func (c *Connection) attachmentCommit(r Request) error {
	up := c.findUpload(r.TransferID)
	if up == nil {
		return c.refuse(r.ID)
	}
	// The staged bytes are deleted on commit success and on every failure.
	defer c.clearUpload()
	s := c.session.Load()
	if s == nil || s != up.session || c.epoch != up.epoch || !s.Unlocked() {
		return c.refuse(r.ID)
	}
	if up.offset != up.size || int64(len(up.buf)) != up.size {
		return c.refuse(r.ID)
	}
	sum := sha256.Sum256(up.buf)
	if hex.EncodeToString(sum[:]) != up.sha256 {
		return c.refuse(r.ID)
	}
	// Revalidate the bound item and its exact revision immediately before the
	// mutation gate is registered.
	items, revisions, e := s.ReadAuthenticatedItems(false)
	if e != nil || !s.Unlocked() || s != up.session {
		return c.refuse(r.ID)
	}
	it, ok := c.findItem(items, up.itemID)
	if !ok || revisions[it.ID] != up.revision || it.State == "trashed" {
		return c.refuse(r.ID)
	}
	gate := personal.NewMutationGate(minTime(c.until, c.now().Add(attachmentCommitWindow)))
	if s.RegisterMutation(gate) != nil {
		return c.refuse(r.ID)
	}
	content := up.buf
	up.buf, up.offset = nil, 0
	defer clear(content)
	attID, rev, e := s.AddAttachment(up.itemID, up.revision, up.fileName, up.mimeType, content, gate)
	if e != nil || s != c.session.Load() || !s.Unlocked() {
		return c.refuse(r.ID)
	}
	return c.response(Response{ID: r.ID, Type: "attachment-saved", ItemID: up.itemID, Revision: rev, Attachment: &BrowserAttachment{
		ID:       attID,
		FileName: up.fileName,
		Size:     up.size,
		MIMEType: up.mimeType,
		SHA256:   up.sha256,
	}})
}

func (c *Connection) attachmentCancel(r Request) error {
	up := c.findUpload(r.TransferID)
	if up == nil {
		return c.refuse(r.ID)
	}
	transfer := up.id
	c.clearUpload()
	return c.response(Response{ID: r.ID, Type: "attachment-cancelled", TransferID: transfer})
}

// attachmentRead is stateless: every chunk re-reads the authenticated item and
// audit path, rechecks the exact revision and clears the whole returned body.
func (c *Connection) attachmentRead(r Request) error {
	s := c.session.Load()
	if s == nil || !s.Unlocked() {
		return c.refuse(r.ID)
	}
	meta, body, e := s.GetAttachment(r.ItemID, r.Revision, r.AttachmentID)
	defer clear(body)
	if e != nil || meta.ID == "" || int64(len(body)) != meta.Size || s != c.session.Load() || !s.Unlocked() {
		return c.refuse(r.ID)
	}
	offset, size := r.Offset, meta.Size
	if offset < 0 || offset > size || offset == size && size != 0 {
		return c.refuse(r.ID)
	}
	end := offset + int64(r.Length)
	if end > size {
		end = size
	}
	data := base64.StdEncoding.EncodeToString(body[offset:end])
	return c.response(Response{ID: r.ID, Type: "attachment-data", ItemID: r.ItemID, Revision: r.Revision, Attachment: attachmentSummary(meta), Offset: offset, NextOffset: end, Done: end == size, Data: data})
}

// attachmentRemove runs the approved removal under the exact mutation slot the
// native review reserved; it never registers or releases that slot itself.
func (c *Connection) attachmentRemove(r Request) error {
	s := c.session.Load()
	if s == nil || !s.Unlocked() {
		return c.refuse(r.ID)
	}
	gate := r.v2Reserved
	if gate == nil {
		return c.refuse(r.ID)
	}
	rev, e := s.RemoveAttachment(r.ItemID, r.Revision, r.AttachmentID, gate)
	if e != nil || s != c.session.Load() || !s.Unlocked() {
		return c.refuse(r.ID)
	}
	return c.response(Response{ID: r.ID, Type: "attachment-removed", ItemID: r.ItemID, Revision: rev, AttachmentID: r.AttachmentID})
}
