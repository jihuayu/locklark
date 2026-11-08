package main

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jihuayu/locklark/internal/vault"
)

func typedAbsoluteTestPath(t *testing.T, name string) string {
	t.Helper()
	path, err := filepath.Abs(name)
	if err != nil {
		t.Fatalf("absolute test path: %v", err)
	}
	return path
}

func typedAttachmentJSON(t *testing.T, file, name, mime string) string {
	t.Helper()
	if mime == "" {
		return fmt.Sprintf(`{"file":%q,"file_name":%q}`, file, name)
	}
	return fmt.Sprintf(`{"file":%q,"file_name":%q,"mime_type":%q}`, file, name, mime)
}

func typedAttachmentDocument(category, title string, entries ...string) string {
	return fmt.Sprintf(`{"category":%q,"title":%q,"attachments":[%s]}`, category, title, strings.Join(entries, ","))
}

func TestDecodeTypedPersonalDocumentAttachmentRequests(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "scan.pdf")
	second := filepath.Join(dir, "empty.bin")
	raw := typedAttachmentDocument("document", "Contract",
		typedAttachmentJSON(t, first, "scan.pdf", "application/pdf"),
		typedAttachmentJSON(t, second, "empty.bin", ""))
	item, requests, err := decodeTypedPersonalDocument([]byte(raw))
	if err != nil {
		t.Fatalf("decode document with attachments: %v", err)
	}
	if item.Category != vault.CategoryDocument || item.Kind != "document" || item.Title != "Contract" {
		t.Fatalf("unexpected document identity: %+v", item)
	}
	// A v2 document carries its bytes as attachments and leaves the legacy
	// Filename/Attachment pair empty; native hasV2Extension keeps it valid.
	if item.Filename != "" || item.Attachment != nil {
		t.Fatalf("document must not synthesize legacy attachment bytes: %+v", item)
	}
	if len(requests) != 2 || requests[0].file != first || requests[1].file != second {
		t.Fatalf("unresolved requests: %+v", requests)
	}
	if len(item.Attachments) != 2 {
		t.Fatalf("decoded attachment metadata: %+v", item.Attachments)
	}
	for n, metadata := range item.Attachments {
		if metadata.FileName != []string{"scan.pdf", "empty.bin"}[n] || metadata.Content == nil || len(metadata.Content) != 0 {
			t.Fatalf("attachment %d metadata: %+v", n, metadata)
		}
		if metadata.ID != "" || metadata.Size != 0 || metadata.SHA256 != "" {
			t.Fatalf("decoder must leave native attachment fields for normalization: %+v", metadata)
		}
	}
	if item.Attachments[0].MIMEType != "application/pdf" || item.Attachments[1].MIMEType != "" {
		t.Fatalf("attachment MIME types: %+v", item.Attachments)
	}
	// The item-only wrapper has no file resolver and must refuse instead of
	// returning an item with forgotten attachment requests.
	if _, err := decodeTypedPersonalInput([]byte(raw)); !errors.Is(err, errTypedInputRefused) {
		t.Fatalf("item-only wrapper accepted unresolved attachments: %v", err)
	}
}

func TestDecodeTypedPersonalDocumentAllowsAttachmentsOnOtherCategories(t *testing.T) {
	file := typedAbsoluteTestPath(t, "receipt.png")
	raw := typedAttachmentDocument("login", "Example", typedAttachmentJSON(t, file, "receipt.png", "image/png"))
	item, requests, err := decodeTypedPersonalDocument([]byte(raw))
	if err != nil {
		t.Fatalf("decode login with attachment: %v", err)
	}
	if item.Category != vault.CategoryLogin || len(item.Attachments) != 1 || len(requests) != 1 {
		t.Fatalf("unexpected login attachment item: %+v requests=%+v", item, requests)
	}
}

func TestDecodeTypedPersonalDocumentRefusesBadAttachmentDescriptors(t *testing.T) {
	abs := typedAbsoluteTestPath(t, "item.bin")
	tooMany := make([]string, 0, maxTypedAttachments+1)
	for n := 0; n <= maxTypedAttachments; n++ {
		tooMany = append(tooMany, typedAttachmentJSON(t, abs, fmt.Sprintf("f%d.bin", n), ""))
	}
	cases := map[string]string{
		"relative-file":     typedAttachmentDocument("login", "x", typedAttachmentJSON(t, "item.bin", "item.bin", "")),
		"empty-file":        `{"title":"x","attachments":[{"file":"","file_name":"a"}]}`,
		"control-in-file":   `{"title":"x","attachments":[{"file":"/tmp/a\u0000b","file_name":"a"}]}`,
		"document-no-files": `{"category":"document","title":"doc"}`,
		"document-notes":    typedAttachmentDocument("document", "doc", typedAttachmentJSON(t, abs, "a.bin", "")),
		"document-url":      typedAttachmentDocument("document", "doc", typedAttachmentJSON(t, abs, "a.bin", "")),
		"ssh-key":           typedAttachmentDocument("ssh_key", "key", typedAttachmentJSON(t, abs, "a.bin", "")),
		"too-many-files":    typedAttachmentDocument("login", "x", tooMany...),
		"dot-name":          typedAttachmentDocument("login", "x", typedAttachmentJSON(t, abs, ".", "")),
		"dotdot-name":       typedAttachmentDocument("login", "x", typedAttachmentJSON(t, abs, "..", "")),
		"empty-name":        typedAttachmentDocument("login", "x", typedAttachmentJSON(t, abs, "", "")),
		"slash-name":        typedAttachmentDocument("login", "x", typedAttachmentJSON(t, abs, "a/b", "")),
		"backslash-name":    typedAttachmentDocument("login", "x", typedAttachmentJSON(t, abs, `a\b`, "")),
		"control-name":      typedAttachmentDocument("login", "x", typedAttachmentJSON(t, abs, "a\u0001b", "")),
		"long-name":         typedAttachmentDocument("login", "x", typedAttachmentJSON(t, abs, strings.Repeat("a", maxTypedAttachmentName+1), "")),
		"control-mime":      typedAttachmentDocument("login", "x", typedAttachmentJSON(t, abs, "a", "text/\u0001plain")),
		"long-mime":         typedAttachmentDocument("login", "x", typedAttachmentJSON(t, abs, "a", strings.Repeat("a", maxTypedAttachmentMIME+1))),
		"raw-content":       fmt.Sprintf(`{"title":"x","attachments":[{"file":%q,"file_name":"a","content":"AAAA"}]}`, abs),
		"raw-body":          fmt.Sprintf(`{"title":"x","attachments":[{"file":%q,"file_name":"a","body":"AAAA"}]}`, abs),
		"raw-base64":        fmt.Sprintf(`{"title":"x","attachments":[{"file":%q,"file_name":"a","base64":"AAAA"}]}`, abs),
		"raw-id":            fmt.Sprintf(`{"title":"x","attachments":[{"file":%q,"file_name":"a","id":"0123456789abcdef"}]}`, abs),
		"raw-digest":        fmt.Sprintf(`{"title":"x","attachments":[{"file":%q,"file_name":"a","sha256":"%s"}]}`, abs, strings.Repeat("0", 64)),
		"raw-size":          fmt.Sprintf(`{"title":"x","attachments":[{"file":%q,"file_name":"a","size":1}]}`, abs),
		"raw-provenance":    fmt.Sprintf(`{"title":"x","attachments":[{"file":%q,"file_name":"a","provenance":"P"}]}`, abs),
		"duplicate-name":    fmt.Sprintf(`{"title":"x","attachments":[{"file":%q,"file_name":"a","File_Name":"b"}]}`, abs),
		"non-ascii-key":     fmt.Sprintf(`{"title":"x","attachments":[{"file":%q,"file_name":"a","f\u0131le":"b"}]}`, abs),
		"surrogate-name":    fmt.Sprintf(`{"title":"x","attachments":[{"file":%q,"file_name":"a\ud800"}]}`, abs),
	}
	// The two document cases need an extra field to exercise that specific
	// refusal; they are built separately so every other case stays minimal.
	cases["document-notes"] = fmt.Sprintf(`{"category":"document","title":"doc","notes":"n","attachments":[%s]}`, typedAttachmentJSON(t, abs, "a.bin", ""))
	cases["document-url"] = fmt.Sprintf(`{"category":"document","title":"doc","url":"https://example.test","attachments":[%s]}`, typedAttachmentJSON(t, abs, "a.bin", ""))
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			item, requests, err := decodeTypedPersonalDocument([]byte(raw))
			if !errors.Is(err, errTypedInputRefused) || requests != nil || item.Attachments != nil {
				t.Fatalf("expected fixed refusal without requests, got item=%+v requests=%+v err=%v", item, requests, err)
			}
			if text := err.Error(); strings.Contains(text, abs) || strings.Contains(text, "AAAA") {
				t.Fatalf("refusal echoed a descriptor value: %q", text)
			}
		})
	}
}
