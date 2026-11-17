package browserhost

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"testing"
)

// lastFrame returns the newest response frame as raw JSON so wire shapes can be
// asserted exactly, including zero-valued keys.
func lastFrame(t *testing.T, out *memoryPipe) map[string]any {
	t.Helper()
	out.Lock()
	raw := bytes.Clone(out.Bytes())
	out.Unlock()
	var payload []byte
	for len(raw) > 0 {
		if len(raw) < 4 {
			t.Fatal("short frame")
		}
		n := int(binary.NativeEndian.Uint32(raw))
		raw = raw[4:]
		if n > len(raw) || n == 0 {
			t.Fatal("bad frame")
		}
		payload = raw[:n]
		raw = raw[n:]
	}
	if payload == nil {
		t.Fatal("no response frame")
	}
	var value map[string]any
	if e := json.Unmarshal(payload, &value); e != nil {
		t.Fatalf("bad response json: %v", e)
	}
	return value
}

type attachmentDriver struct {
	t   *testing.T
	c   *Connection
	out *memoryPipe
	cap string
	n   int
}

func (d *attachmentDriver) nextID() string {
	d.n++
	return reqID(1000 + d.n)
}

// call sends one well-formed native frame through the real ReadRequest path.
func (d *attachmentDriver) call(value map[string]any) Response {
	d.t.Helper()
	value["v"] = 1
	value["capability"] = d.cap
	value["id"] = d.nextID()
	return v2Handle(d.t, d.c, d.out, value)
}

// destructive sends a removal and approves its own native review. Even a
// quick-fill connection may not delete an attachment without that review.
func (d *attachmentDriver) destructive(value map[string]any) Response {
	d.t.Helper()
	value["v"] = 1
	value["capability"] = d.cap
	value["id"] = d.nextID()
	return destructiveCall(d.t, d.c, d.out, value)
}

// protocolReject asserts the strict request reader refuses a frame.
func (d *attachmentDriver) protocolReject(value map[string]any) {
	d.t.Helper()
	value["v"] = 1
	value["capability"] = d.cap
	value["id"] = d.nextID()
	raw, e := json.Marshal(value)
	if e != nil {
		d.t.Fatal(e)
	}
	if r, e := ReadRequest(bytes.NewReader(frame(string(raw)))); e == nil {
		d.t.Fatalf("protocol accepted %s (%s)", raw, r.Type)
	}
}

func attachmentFixture(t *testing.T) (*attachmentDriver, string, string) {
	t.Helper()
	c, out, _, cap := v2Fixture(t)
	d := &attachmentDriver{t: t, c: c, out: out, cap: cap}
	created := d.call(map[string]any{"type": "item-create", "item_json": `{"category":"login","title":"Attachment host","username":"host-user","password":"host-secret"}`})
	if created.Type != "item-saved" || created.ItemID == "" || created.Revision == "" {
		t.Fatalf("create item: %#v", created)
	}
	return d, created.ItemID, created.Revision
}

func attachmentContent(size int) []byte {
	content := make([]byte, size)
	for i := range content {
		content[i] = byte(i*7 + i/251)
	}
	return content
}

func hexSum(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

// uploadAttachment runs begin + sequential 64KiB chunks and returns the live
// transfer id plus the last transfer response.
func uploadAttachment(t *testing.T, d *attachmentDriver, itemID, rev, name, mime string, content []byte) (string, Response) {
	t.Helper()
	begin := d.call(map[string]any{"type": "attachment-begin", "item_id": itemID, "revision": rev, "file_name": name, "size": len(content), "sha256": hexSum(content), "mime_type": mime})
	if begin.Type != "attachment-transfer" || len(begin.TransferID) != 32 || begin.Size != int64(len(content)) {
		t.Fatalf("begin: %#v", begin)
	}
	last := begin
	for offset := 0; offset < len(content); offset += maxAttachmentChunk {
		end := offset + maxAttachmentChunk
		if end > len(content) {
			end = len(content)
		}
		last = d.call(map[string]any{"type": "attachment-chunk", "transfer_id": begin.TransferID, "offset": offset, "data": base64.StdEncoding.EncodeToString(content[offset:end])})
		if last.Type != "attachment-transfer" || last.Offset != int64(end) || last.Size != int64(len(content)) {
			t.Fatalf("chunk at %d: %#v", offset, last)
		}
	}
	return begin.TransferID, last
}

func TestAttachmentTransferRoundTrip2MiB(t *testing.T) {
	d, itemID, rev := attachmentFixture(t)
	content := attachmentContent(MaxAttachmentBytes)
	wantHash := hexSum(content)
	begin := d.call(map[string]any{"type": "attachment-begin", "item_id": itemID, "revision": rev, "file_name": "archive.bin", "size": len(content), "sha256": wantHash, "mime_type": "application/octet-stream"})
	raw := lastFrame(t, d.out)
	if raw["type"] != "attachment-transfer" || raw["transfer_id"] != begin.TransferID || raw["offset"] != float64(0) || raw["size"] != float64(len(content)) {
		t.Fatalf("transfer wire shape: %v", raw)
	}
	if begin.ExpiresInSeconds <= 0 || begin.ExpiresInSeconds > 120 {
		t.Fatalf("expiry: %d", begin.ExpiresInSeconds)
	}
	// Only one connection-memory upload may exist at a time.
	if again := d.call(map[string]any{"type": "attachment-begin", "item_id": itemID, "revision": rev, "file_name": "other.bin", "size": 1, "sha256": hexSum([]byte{1})}); again.Type != "error" {
		t.Fatalf("replacement upload accepted: %#v", again)
	}
	for offset := 0; offset < len(content); offset += maxAttachmentChunk {
		end := offset + maxAttachmentChunk
		if end > len(content) {
			end = len(content)
		}
		chunk := d.call(map[string]any{"type": "attachment-chunk", "transfer_id": begin.TransferID, "offset": offset, "data": base64.StdEncoding.EncodeToString(content[offset:end])})
		if chunk.Type != "attachment-transfer" || chunk.Offset != int64(end) {
			t.Fatalf("chunk at %d: %#v", offset, chunk)
		}
	}
	saved := d.call(map[string]any{"type": "attachment-commit", "transfer_id": begin.TransferID})
	if saved.Type != "attachment-saved" || saved.ItemID != itemID || saved.Revision == "" || saved.Revision == rev || saved.Attachment == nil {
		t.Fatalf("commit: %#v", saved)
	}
	if saved.Attachment.ID == "" || saved.Attachment.FileName != "archive.bin" || saved.Attachment.Size != int64(len(content)) || saved.Attachment.SHA256 != wantHash || saved.Attachment.MIMEType != "application/octet-stream" {
		t.Fatalf("attachment metadata: %#v", saved.Attachment)
	}
	newRev := saved.Revision
	detail := d.call(map[string]any{"type": "item-get", "item_id": itemID, "revision": newRev})
	if detail.Item == nil || len(detail.Item.Attachments) != 1 {
		t.Fatalf("detail attachments: %#v", detail.Item)
	}
	att := detail.Item.Attachments[0]
	if att.ID != saved.Attachment.ID || att.FileName != "archive.bin" || att.SHA256 != wantHash || att.Size != int64(len(content)) || att.MIMEType != "application/octet-stream" {
		t.Fatalf("detail metadata: %#v", att)
	}
	detailRaw, e := json.Marshal(detail.Item)
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(detailRaw, content[:64]) {
		t.Fatal("item detail leaked attachment bytes")
	}
	var got bytes.Buffer
	offset := int64(0)
	for {
		chunk := d.call(map[string]any{"type": "attachment-read", "item_id": itemID, "revision": newRev, "attachment_id": att.ID, "offset": offset, "length": maxAttachmentChunk})
		if chunk.Type != "attachment-data" || chunk.Offset != offset || chunk.Attachment == nil || chunk.Attachment.ID != att.ID {
			t.Fatalf("read at %d: %#v", offset, chunk)
		}
		if !chunk.Done && chunk.NextOffset-chunk.Offset > maxAttachmentChunk {
			t.Fatalf("read chunk exceeded bound: %#v", chunk)
		}
		part, e := base64.StdEncoding.DecodeString(chunk.Data)
		if e != nil {
			t.Fatalf("read data: %v", e)
		}
		got.Write(part)
		if chunk.Done {
			break
		}
		if chunk.NextOffset <= offset {
			t.Fatalf("read made no progress: %#v", chunk)
		}
		offset = chunk.NextOffset
	}
	if got.Len() != len(content) || hexSum(got.Bytes()) != wantHash {
		t.Fatalf("downloaded %d bytes with the wrong digest", got.Len())
	}
	removed := d.destructive(map[string]any{"type": "attachment-remove", "item_id": itemID, "revision": newRev, "attachment_id": att.ID})
	if removed.Type != "attachment-removed" || removed.ItemID != itemID || removed.AttachmentID != att.ID || removed.Revision == newRev {
		t.Fatalf("remove: %#v", removed)
	}
	after := d.call(map[string]any{"type": "item-get", "item_id": itemID, "revision": removed.Revision})
	if after.Item == nil || len(after.Item.Attachments) != 0 {
		t.Fatalf("attachments after remove: %#v", after.Item)
	}
	// A stale revision can never read the removed bytes again.
	if stale := d.call(map[string]any{"type": "attachment-read", "item_id": itemID, "revision": newRev, "attachment_id": att.ID, "offset": 0, "length": 1}); stale.Type != "error" {
		t.Fatalf("stale read accepted: %#v", stale)
	}
}

func TestAttachmentEmptyFileReadIsDoneImmediately(t *testing.T) {
	d, itemID, rev := attachmentFixture(t)
	begin := d.call(map[string]any{"type": "attachment-begin", "item_id": itemID, "revision": rev, "file_name": "empty.txt", "size": 0, "sha256": hexSum(nil)})
	if begin.Type != "attachment-transfer" || begin.Size != 0 || begin.Offset != 0 || len(begin.TransferID) != 32 {
		t.Fatalf("zero-size begin: %#v", begin)
	}
	raw := lastFrame(t, d.out)
	if raw["offset"] != float64(0) || raw["size"] != float64(0) || raw["transfer_id"] != begin.TransferID {
		t.Fatalf("zero fields missing from the transfer frame: %v", raw)
	}
	saved := d.call(map[string]any{"type": "attachment-commit", "transfer_id": begin.TransferID})
	if saved.Type != "attachment-saved" || saved.Attachment == nil || saved.Attachment.Size != 0 || saved.Attachment.SHA256 != hexSum(nil) {
		t.Fatalf("zero-size commit: %#v", saved)
	}
	read := d.call(map[string]any{"type": "attachment-read", "item_id": itemID, "revision": saved.Revision, "attachment_id": saved.Attachment.ID, "offset": 0, "length": 1})
	if read.Type != "attachment-data" || !read.Done || read.Data != "" || read.NextOffset != 0 || read.Offset != 0 {
		t.Fatalf("empty read: %#v", read)
	}
	if beyond := d.call(map[string]any{"type": "attachment-read", "item_id": itemID, "revision": saved.Revision, "attachment_id": saved.Attachment.ID, "offset": 1, "length": 1}); beyond.Type != "error" {
		t.Fatalf("offset past an empty file accepted: %#v", beyond)
	}
}
