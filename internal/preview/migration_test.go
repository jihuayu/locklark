package preview

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestEditedFixtureExport(t *testing.T) {
	root := filepath.Join(t.TempDir(), "case")
	if err := Create(root, "example", "exercise"); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	bundle := filepath.Join(root, "share", "epoch-3")
	a, b := filepath.Join(root, "clients", "A"), filepath.Join(root, "clients", "B")
	out := filepath.Join(dir, "result.1pux")
	if ExportFixture(bundle, a, 3, out) == nil {
		t.Fatal("revoked device exported fixture")
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("unauthorized export left output")
	}
	if err := ExportFixture(bundle, b, 3, out); err != nil {
		t.Fatal(err)
	}
	z, err := zip.OpenReader(out)
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	wantJSON := bytes.Replace(exportData, []byte("同名示例"), []byte("轮换后的演练登录"), 1)
	wantJSON = bytes.Replace(wantJSON, []byte("secret=MZXW6"), []byte("secret=MZXW6YTBOI"), 1)
	orig, err := fixtureArchive()
	if err != nil {
		t.Fatal(err)
	}
	original, err := zip.NewReader(bytes.NewReader(orig), int64(len(orig)))
	if err != nil {
		t.Fatal(err)
	}
	if len(z.File) != len(original.File) {
		t.Fatal("archive member count changed")
	}
	for _, f := range original.File {
		read := func(r *zip.Reader) []byte {
			v, e := r.Open(f.Name)
			if e != nil {
				t.Fatal(e)
			}
			defer v.Close()
			x, e := io.ReadAll(v)
			if e != nil {
				t.Fatal(e)
			}
			return x
		}
		got := read(&z.Reader)
		if f.Name != "export.data" {
			if !bytes.Equal(got, read(original)) {
				t.Fatal("non-data member changed", f.Name)
			}
			continue
		}
		var want, actual any
		if json.Unmarshal(wantJSON, &want) != nil || json.Unmarshal(got, &actual) != nil || !reflect.DeepEqual(want, actual) {
			t.Fatal("unexpected field changes")
		}
	}
	if err := ExportFixture(filepath.Join(root, "share", "epoch-2"), b, 2, out); err == nil {
		t.Fatal("replaced existing output")
	}
	p, err := readPayload(filepath.Join(root, "share", "epoch-2"), b, 2)
	if err != nil || !bytes.Equal(p.Archive, orig) {
		t.Fatal("old fixture modified")
	}
}
