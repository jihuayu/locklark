package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/vault"
)

func TestCreateTypedPersonalDocumentTwoBinaryAttachmentsRoundtrip(t *testing.T) {
	dir := t.TempDir()
	firstPath := filepath.Join(dir, "first.bin")
	secondPath := filepath.Join(dir, "second.bin")
	first := []byte{0x00, 0x01, 0xff, 0xfe, 'A', 0x00, 0x7f, 0x80}
	second := []byte("second\x00body\xff\n")
	writePrivateTypedFixture(t, firstPath, first)
	writePrivateTypedFixture(t, secondPath, second)
	document := typedAttachmentDocument("document", "Binary contract",
		typedAttachmentJSON(t, firstPath, "first.bin", "application/octet-stream"),
		typedAttachmentJSON(t, secondPath, "second.bin", ""))
	vaultPath, inputPath, pw, key := typedCreateFixture(t, document)

	var prompt bytes.Buffer
	asked := 0
	response, err := createTypedPersonal(vaultPath, inputPath, pw, key, func(string) ([]byte, error) {
		asked++
		return []byte("SAVE"), nil
	}, &prompt)
	if err != nil {
		t.Fatalf("create document with two files: %v", err)
	}
	if asked != 1 || len(response) != 3 || response["status"] != "created" || response["id"] == "" || response["revision"] == "" {
		t.Fatalf("unexpected consent/receipt: asked=%d response=%+v", asked, response)
	}
	if want := "2 个附件共 21 字节"; !strings.Contains(prompt.String(), want) {
		t.Fatalf("prompt did not show attachment count/bytes: %q", prompt.String())
	}
	for _, secret := range []string{dir, "first.bin", "second.bin", "Binary contract"} {
		if strings.Contains(prompt.String(), secret) {
			t.Fatalf("prompt echoed attachment or item data %q: %q", secret, prompt.String())
		}
	}

	session, err := personal.UnlockSession(vaultPath, pw, key, time.Minute)
	if err != nil {
		t.Fatalf("reopen encrypted vault: %v", err)
	}
	defer session.Lock()
	detail, err := session.GetItemDetail(response["id"], response["revision"], true)
	if err != nil {
		t.Fatalf("read created document detail: %v", err)
	}
	if detail.Category != vault.CategoryDocument || len(detail.Attachments) != 2 {
		t.Fatalf("document attachments were not persisted: %+v", detail)
	}
	for n, want := range [][]byte{first, second} {
		meta, got, err := session.GetAttachment(response["id"], response["revision"], detail.Attachments[n].ID)
		if err != nil {
			t.Fatalf("get attachment %d: %v", n, err)
		}
		defer clear(got)
		if !bytes.Equal(got, want) {
			t.Fatalf("attachment %d bytes changed: want %x got %x", n, want, got)
		}
		if meta.Size != int64(len(want)) || meta.SHA256 != vault.AttachmentSHA256(want) || meta.FileName != []string{"first.bin", "second.bin"}[n] {
			t.Fatalf("attachment %d metadata: %+v", n, meta)
		}
	}
}
