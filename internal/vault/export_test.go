package vault

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestExportKDBXIndependentReader(t *testing.T) {
	items := []Item{{ID: "login", Kind: "login", State: "archived", Title: "重复标题", Username: "synthetic-user", Password: "synthetic-password", OTP: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"}, {ID: "doc", Kind: "document", Title: "重复标题", Filename: "fixture.bin", Attachment: []byte{0, 255, 1}, AttachmentProtected: true}}
	items = append(items, Item{ID: "empty", Kind: "login", Title: "empty"}, Item{ID: "doc-unprotected", Kind: "document", Title: "duplicate bytes", Filename: "fixture.bin", Attachment: []byte{0, 255, 1}})
	raw, err := ExportKDBX(items, "synthetic-export-password")
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{items[0].Password, items[0].OTP, items[0].Title, "synthetic-export-password"} {
		if bytes.Contains(raw, []byte(s)) {
			t.Fatal("export not encrypted")
		}
	}
	python := os.Getenv("LOCKLARK_TEST_PYKEEPASS")
	if python == "" {
		t.Skip("set LOCKLARK_TEST_PYKEEPASS for independent reader")
	}
	path := filepath.Join(t.TempDir(), "export.kdbx")
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	want, _ := json.Marshal(items)
	cmd := exec.Command(python, "testdata/export_peer.py", path)
	cmd.Stdin = bytes.NewReader(want)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("independent reader failed: %s %v", out, err)
	}
	if _, err := ExportKDBX(items, "short"); err == nil {
		t.Fatal("weak export password accepted")
	}
}

func TestExportPasswordBoundaries(t *testing.T) {
	for _, pw := range []string{"", "12345678901", "密码密码密码", string([]byte{0xff}), "            ", string(bytes.Repeat([]byte("x"), 1025))} {
		if ValidateExportPassword(pw) == nil {
			t.Fatal("invalid export password accepted")
		}
	}
	if err := ValidateExportPassword("密码密码密码密码密码密码"); err != nil {
		t.Fatal("12 rune password rejected", err)
	}
}
