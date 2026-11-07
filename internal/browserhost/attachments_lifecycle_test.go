package browserhost

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestAttachmentRejectsUnsafeFramesAndStaleUploads(t *testing.T) {
	d, itemID, rev := attachmentFixture(t)
	content := []byte("hello attachment world")
	good := hexSum(content)
	begin := func() string {
		resp := d.call(map[string]any{"type": "attachment-begin", "item_id": itemID, "revision": rev, "file_name": "note.txt", "size": len(content), "sha256": good})
		if resp.Type != "attachment-transfer" {
			t.Fatalf("begin: %#v", resp)
		}
		return resp.TransferID
	}
	chunk := func(transfer string, offset int, raw []byte) Response {
		return d.call(map[string]any{"type": "attachment-chunk", "transfer_id": transfer, "offset": offset, "data": base64.StdEncoding.EncodeToString(raw)})
	}
	expectWiped := func(what string) {
		t.Helper()
		if d.c.upload != nil {
			t.Fatalf("%s kept the staged upload", what)
		}
	}

	// Strict request shapes: oversize, bad digest, unsafe name, missing size,
	// unexpected keys and out-of-range read/chunk lengths.
	d.protocolReject(map[string]any{"type": "attachment-begin", "item_id": itemID, "revision": rev, "file_name": "big.bin", "size": MaxAttachmentBytes + 1, "sha256": good})
	d.protocolReject(map[string]any{"type": "attachment-begin", "item_id": itemID, "revision": rev, "file_name": "big.bin", "size": 1, "sha256": strings.Repeat("A", 64)})
	d.protocolReject(map[string]any{"type": "attachment-begin", "item_id": itemID, "revision": rev, "file_name": "../escape.bin", "size": 1, "sha256": good})
	d.protocolReject(map[string]any{"type": "attachment-begin", "item_id": itemID, "revision": rev, "file_name": " leading.bin", "size": 1, "sha256": good})
	d.protocolReject(map[string]any{"type": "attachment-begin", "item_id": itemID, "revision": rev, "file_name": "ok.bin", "size": 1, "sha256": good, "origin": "https://evil.example"})
	d.protocolReject(map[string]any{"type": "attachment-begin", "item_id": itemID, "revision": rev, "file_name": "ok.bin", "size": -1, "sha256": good})
	d.protocolReject(map[string]any{"type": "attachment-chunk", "transfer_id": strings.Repeat("a", 32), "offset": 0, "data": ""})
	d.protocolReject(map[string]any{"type": "attachment-read", "item_id": itemID, "revision": rev, "attachment_id": "abc", "offset": 0, "length": 0})
	d.protocolReject(map[string]any{"type": "attachment-read", "item_id": itemID, "revision": rev, "attachment_id": "abc", "offset": 0, "length": maxAttachmentChunk + 1})
	d.protocolReject(map[string]any{"type": "attachment-remove", "item_id": itemID, "revision": rev, "attachment_id": "a/b"})
	d.protocolReject(map[string]any{"type": "attachment-commit", "transfer_id": "short"})

	// A stale revision cannot start an upload at all.
	if stale := d.call(map[string]any{"type": "attachment-begin", "item_id": itemID, "revision": strings.Repeat("a", 64), "file_name": "note.txt", "size": len(content), "sha256": good}); stale.Type != "error" {
		t.Fatalf("stale begin accepted: %#v", stale)
	}
	if d.c.upload != nil {
		t.Fatal("stale begin staged an upload")
	}

	// Invalid base64 wipes the staged bytes.
	transfer := begin()
	if bad := d.call(map[string]any{"type": "attachment-chunk", "transfer_id": transfer, "offset": 0, "data": "not base64!"}); bad.Type != "error" {
		t.Fatalf("invalid base64 accepted: %#v", bad)
	}
	expectWiped("invalid base64")
	if afterBad := chunk(transfer, 0, content[:1]); afterBad.Type != "error" {
		t.Fatalf("invalid chunk kept the transfer alive: %#v", afterBad)
	}

	// An oversized chunk is refused and wipes the stage.
	if big := chunk(begin(), 0, attachmentContent(maxAttachmentChunk+1)); big.Type != "error" {
		t.Fatalf("oversized chunk accepted: %#v", big)
	}
	expectWiped("oversized chunk")

	// Non-sequential offsets (gap, replay, overlap, overflow) are refused.
	if reordered := chunk(begin(), 4, content[4:]); reordered.Type != "error" {
		t.Fatalf("reordered chunk accepted: %#v", reordered)
	}
	expectWiped("reordered chunk")
	tr := begin()
	if first := chunk(tr, 0, content[:5]); first.Type != "attachment-transfer" || first.Offset != 5 {
		t.Fatalf("first chunk: %#v", first)
	}
	if replay := chunk(tr, 0, content[:5]); replay.Type != "error" {
		t.Fatalf("replayed chunk accepted: %#v", replay)
	}
	expectWiped("replayed chunk")
	tr = begin()
	if first := chunk(tr, 0, content[:5]); first.Type != "attachment-transfer" {
		t.Fatalf("first chunk: %#v", first)
	}
	if overlap := chunk(tr, 3, content[3:5]); overlap.Type != "error" {
		t.Fatalf("overlapping chunk accepted: %#v", overlap)
	}
	tr = begin()
	if first := chunk(tr, 0, content[:5]); first.Type != "attachment-transfer" {
		t.Fatalf("first chunk: %#v", first)
	}
	if overflow := chunk(tr, 5, append(append([]byte(nil), content[5:]...), 'x')); overflow.Type != "error" {
		t.Fatalf("overflowing chunk accepted: %#v", overflow)
	}
	expectWiped("overflowing chunk")

	// An incomplete or wrong-hash upload commits nothing and the stage dies.
	tr = begin()
	if first := chunk(tr, 0, content[:5]); first.Type != "attachment-transfer" {
		t.Fatalf("first chunk: %#v", first)
	}
	if incomplete := d.call(map[string]any{"type": "attachment-commit", "transfer_id": tr}); incomplete.Type != "error" {
		t.Fatalf("incomplete commit accepted: %#v", incomplete)
	}
	expectWiped("incomplete commit")
	if afterCommit := chunk(tr, 5, content[5:]); afterCommit.Type != "error" {
		t.Fatalf("failed commit kept the staged bytes: %#v", afterCommit)
	}
	tr = d.call(map[string]any{"type": "attachment-begin", "item_id": itemID, "revision": rev, "file_name": "note.txt", "size": len(content), "sha256": hexSum([]byte("different bytes"))}).TransferID
	if tr == "" {
		t.Fatal("wrong-hash begin refused too early")
	}
	if last := chunk(tr, 0, content); last.Type != "attachment-transfer" || last.Offset != int64(len(content)) {
		t.Fatalf("chunks: %#v", last)
	}
	if badHash := d.call(map[string]any{"type": "attachment-commit", "transfer_id": tr}); badHash.Type != "error" {
		t.Fatalf("bad hash commit accepted: %#v", badHash)
	}
	expectWiped("bad hash commit")
	detail := d.call(map[string]any{"type": "item-get", "item_id": itemID, "revision": rev})
	if detail.Item == nil || len(detail.Item.Attachments) != 0 {
		t.Fatalf("refused commits changed the item: %#v", detail.Item)
	}

	// Cancellation wipes the staged bytes.
	tr = begin()
	cancelled := d.call(map[string]any{"type": "attachment-cancel", "transfer_id": tr})
	if cancelled.Type != "attachment-cancelled" || cancelled.TransferID != tr {
		t.Fatalf("cancel: %#v", cancelled)
	}
	expectWiped("cancel")
	if afterCancel := chunk(tr, 0, content); afterCancel.Type != "error" {
		t.Fatalf("cancelled transfer still accepted chunks: %#v", afterCancel)
	}

	// An upload expires after 120 seconds and loses its bytes.
	now := d.c.now
	start := now()
	d.c.now = func() time.Time { return start.Add(attachmentUploadTTL + time.Second) }
	tr = begin()
	d.c.now = func() time.Time { return start.Add(attachmentUploadTTL + 3*time.Minute) }
	if expired := chunk(tr, 0, content); expired.Type != "error" {
		t.Fatalf("expired upload accepted a chunk: %#v", expired)
	}
	expectWiped("expiry")
	d.c.now = now

	// Lock wipes the staged upload before any further output.
	tr = begin()
	d.c.Invalidate()
	expectWiped("lock")
	d.c.Handle(mustReadRequest(t, map[string]any{"v": 1, "id": reqID(4001), "type": "attachment-chunk", "capability": d.cap, "transfer_id": tr, "offset": 0, "data": base64.StdEncoding.EncodeToString(content)}))
	expectWiped("locked chunk")
}
