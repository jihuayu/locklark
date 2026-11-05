package preview

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"path/filepath"
	"testing"
)

func readNativeZIP(t *testing.T, data []byte) map[string][]byte {
	t.Helper()
	z, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{}
	for _, f := range z.File {
		r, e := f.Open()
		if e != nil {
			t.Fatal(e)
		}
		files[f.Name], e = io.ReadAll(r)
		r.Close()
		if e != nil {
			t.Fatal(e)
		}
	}
	return files
}
func TestDemoUsesNativeItems(t *testing.T) {
	root := filepath.Join(t.TempDir(), "demo")
	if err := Create(root, "native-test", "verify fixture items"); err != nil {
		t.Fatal(err)
	}
	device := filepath.Join(root, "clients", "B")
	p, err := readPayload(filepath.Join(root, "share", "epoch-2"), device, 2)
	if err != nil || len(p.items) != 2 || p.layout == nil {
		t.Fatal("demo did not open as native entries", err)
	}
	find := func(p payload, id string) int {
		for i, it := range p.items {
			if it.ID == id {
				return i
			}
		}
		t.Fatal("missing native ID")
		return -1
	}
	a, b := find(p, "login-sample"), find(p, "document-sample")
	if p.items[a].Title != p.items[b].Title || p.items[a].Password == "" || p.items[a].OTP == "" || !bytes.Equal(p.items[b].Attachment, []byte{0, 1, 2, 255}) {
		t.Fatal("native mapping incorrect")
	}
	layout, _ := json.Marshal(p.layout)
	if bytes.Contains(layout, []byte(p.items[a].Password)) || bytes.Contains(layout, []byte("otpauth://")) {
		t.Fatal("migration metadata duplicates native secrets")
	}
	// Read in different item order, edit native fields, and verify ZIP contents come from them.
	p.items[a].Password = "synthetic changed password"
	p.items[b].Attachment = []byte("QUJD")
	p.items[0], p.items[1] = p.items[1], p.items[0]
	data, err := nativeArchive(p.layout, p.items)
	if err != nil {
		t.Fatal(err)
	}
	files := readNativeZIP(t, data)
	if !bytes.Contains(files["export.data"], []byte("synthetic changed password")) || !bytes.Equal(files[attachmentPath], []byte("QUJD")) {
		t.Fatal("reconstruction ignored edited native values")
	}
	p.layout.Slots[0], p.layout.Slots[1] = p.layout.Slots[1], p.layout.Slots[0]
	if _, err := nativeArchive(p.layout, p.items); err == nil {
		t.Fatal("layout rebound a native value to another source field")
	}
}
