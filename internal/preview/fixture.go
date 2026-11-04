package preview

import (
	"archive/zip"
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

//go:embed testdata/export.json
var exportData []byte

const attachmentPath = "files/doc-sample___样本.bin"

func fixtureArchive() ([]byte, error) {
	var out bytes.Buffer
	w := zip.NewWriter(&out)
	for _, f := range []struct {
		name string
		data []byte
	}{
		{"export.attributes", []byte(`{"version":3,"description":"1Password Unencrypted Export","createdAt":0}`)},
		{"export.data", exportData}, {attachmentPath, []byte{0, 1, 2, 255}},
	} {
		z, err := w.Create(f.name)
		if err != nil {
			return nil, err
		}
		if _, err = z.Write(f.data); err != nil {
			return nil, err
		}
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

type Summary struct {
	Epoch       uint64 `json:"epoch"`
	Items       int    `json:"items"`
	Attachments int    `json:"attachments"`
}

var errFixture = errors.New("invalid synthetic archive")

// Only the bundled fixture is supported. No user archives or paths are extracted.
func summarize(archive []byte, epoch uint64) (Summary, error) {
	var s Summary
	s.Epoch = epoch
	if len(archive) > 1<<20 {
		return s, errFixture
	}
	z, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil || len(z.File) != 3 {
		return s, errFixture
	}
	seen := map[string]bool{}
	for _, f := range z.File {
		if seen[f.Name] || f.UncompressedSize64 > 1<<20 {
			return s, errFixture
		}
		seen[f.Name] = true
		if f.Name != "export.attributes" && f.Name != "export.data" && f.Name != attachmentPath {
			return s, errFixture
		}
		r, err := f.Open()
		if err != nil {
			return s, err
		}
		data, err := io.ReadAll(io.LimitReader(r, (1<<20)+1))
		r.Close()
		if err != nil || len(data) > 1<<20 {
			return s, errFixture
		}
		switch f.Name {
		case "export.attributes":
			var a struct{ Version int }
			if json.Unmarshal(data, &a) != nil || a.Version != 3 {
				return s, errFixture
			}
		case "export.data":
			var e struct {
				Accounts []struct {
					Vaults []struct{ Items []struct{ UUID string } }
				}
			}
			if json.Unmarshal(data, &e) != nil {
				return s, errFixture
			}
			for _, a := range e.Accounts {
				for _, v := range a.Vaults {
					seenID := map[string]bool{}
					for _, i := range v.Items {
						if strings.TrimSpace(i.UUID) == "" || seenID[i.UUID] {
							return s, errFixture
						}
						seenID[i.UUID] = true
						s.Items++
					}
				}
			}
		case attachmentPath:
			s.Attachments++
		}
	}
	return s, nil
}
