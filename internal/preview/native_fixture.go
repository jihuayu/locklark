package preview

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"slices"
	"strconv"
	"strings"

	"github.com/jihuayu/locklark/internal/vault"
)

// The residual contains literal JSON between native slots, never their values.
// Only the built-in, versioned 1PUX layout is accepted by this preview adapter.
type nativeLayout struct {
	Parts   []string
	Slots   []string
	Compact bool
}
type nativeMeta struct {
	Version int
	Layout  *nativeLayout
	Events  []Event
	Proofs  [][]byte
}

const slotCount = 6

// Resolve source paths through stable 1PUX identifiers, never by title or the
// position in which an item happens to occur.
func fixturePaths(data []byte) (map[string]string, error) {
	type attrs struct{ UUID string }
	type item struct {
		UUID, CategoryUUID string
		Details            struct {
			LoginFields []struct{ Name, Designation string }
			Sections    []struct {
				Name   string
				Fields []struct{ ID string }
			}
			DocumentAttributes struct{ DocumentID string }
		}
	}
	var tree struct {
		Accounts []struct {
			Attrs  attrs
			Vaults []struct {
				Attrs attrs
				Items []item
			}
		}
	}
	if json.Unmarshal(data, &tree) != nil || len(tree.Accounts) != 1 || tree.Accounts[0].Attrs.UUID != "synthetic-account" || len(tree.Accounts[0].Vaults) != 1 {
		return nil, errFixture
	}
	v := tree.Accounts[0].Vaults[0]
	if v.Attrs.UUID != "synthetic-vault" || len(v.Items) != 2 {
		return nil, errFixture
	}
	paths := map[string]string{}
	seen := map[string]bool{}
	for i, it := range v.Items {
		if seen[it.UUID] {
			return nil, errFixture
		}
		seen[it.UUID] = true
		path := "/accounts/0/vaults/0/items/" + strconv.Itoa(i)
		switch it.UUID {
		case "login-sample":
			d := it.Details
			if it.CategoryUUID != "001" || len(d.LoginFields) != 1 || d.LoginFields[0].Designation != "password" || d.LoginFields[0].Name != "password" || len(d.Sections) != 1 || d.Sections[0].Name != "ops" || len(d.Sections[0].Fields) != 1 || d.Sections[0].Fields[0].ID != "otp-demo" {
				return nil, errFixture
			}
			paths[path+"/overview/title"] = "login.title"
			paths[path+"/details/loginFields/0/value"] = "login.password"
			paths[path+"/details/sections/0/fields/0/value/totp"] = "login.ops.otp-demo"
		case "document-sample":
			if it.CategoryUUID != "114" || it.Details.DocumentAttributes.DocumentID != "doc-sample" {
				return nil, errFixture
			}
			paths[path+"/overview/title"] = "document.title"
			paths[path+"/details/documentAttributes/fileName"] = "document.filename"
			paths[path+"/details/documentAttributes/decryptedSize"] = "document.size"
		default:
			return nil, errFixture
		}
	}
	return paths, nil
}

func projectFixture(p *payload) error {
	ok, err := knownOriginal(p.Archive)
	if err != nil || !ok {
		return errFixture
	}
	z, err := zip.NewReader(bytes.NewReader(p.Archive), int64(len(p.Archive)))
	if err != nil {
		return errFixture
	}
	readPart := func(name string) ([]byte, error) {
		f, err := z.Open(name)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		return io.ReadAll(io.LimitReader(f, 1<<20))
	}
	data, err := readPart("export.data")
	if err != nil {
		return err
	}
	attachment, err := readPart(attachmentPath)
	if err != nil {
		return err
	}
	layout, values, err := splitFixture(data)
	if err != nil {
		return err
	}
	p.layout = layout
	p.items = []vault.Item{
		{ID: "login-sample", Kind: "login", Title: values["login.title"], Password: values["login.password"], OTP: values["login.ops.otp-demo"]},
		{ID: "document-sample", Kind: "document", Title: values["document.title"], Filename: values["document.filename"], Attachment: attachment, AttachmentProtected: true},
	}
	roundtrip, err := nativeArchive(layout, p.items)
	if err != nil || !bytes.Equal(roundtrip, p.Archive) {
		return errFixture
	}
	return nil
}

// Decode JSON tokens to locate exact value spans. Bound to the known sample;
// never perform global text replacement on titles, passwords or filenames.
func splitFixture(data []byte) (*nativeLayout, map[string]string, error) {
	fixtureSlots, err := fixturePaths(data)
	if err != nil {
		return nil, nil, err
	}
	layout := &nativeLayout{}
	values := map[string]string{}
	cut := 0
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var visit func(string) error
	visit = func(path string) error {
		start := int(d.InputOffset())
		token, err := d.Token()
		if err != nil {
			return err
		}
		end := int(d.InputOffset())
		if slot, ok := fixtureSlots[path]; ok {
			if _, dup := values[slot]; dup {
				return errFixture
			}
			switch v := token.(type) {
			case string:
				if slot == "document.size" {
					return errFixture
				}
				values[slot] = v
			case json.Number:
				if slot != "document.size" {
					return errFixture
				}
				values[slot] = string(v)
			default:
				return errFixture
			}
			for start < end && strings.ContainsRune(" \t\r\n:,", rune(data[start])) {
				start++
			}
			layout.Parts = append(layout.Parts, string(data[cut:start]))
			layout.Slots = append(layout.Slots, slot)
			cut = end
			return nil
		}
		switch token {
		case json.Delim('{'):
			for d.More() {
				key, e := d.Token()
				if e != nil {
					return e
				}
				s, ok := key.(string)
				if !ok {
					return errFixture
				}
				if err := visit(path + "/" + s); err != nil {
					return err
				}
			}
			_, err = d.Token()
		case json.Delim('['):
			for n := 0; d.More(); n++ {
				if err := visit(path + "/" + strconv.Itoa(n)); err != nil {
					return err
				}
			}
			_, err = d.Token()
		}
		return err
	}
	if err := visit(""); err != nil || len(values) != len(fixtureSlots) {
		return nil, nil, errFixture
	}
	layout.Parts = append(layout.Parts, string(data[cut:]))
	return layout, values, nil
}

func nativeArchive(l *nativeLayout, items []vault.Item) ([]byte, error) {
	if l == nil || len(items) != 2 || len(l.Slots) != slotCount || len(l.Parts) != len(l.Slots)+1 {
		return nil, errFixture
	}
	var login, doc *vault.Item
	for i := range items {
		it := &items[i]
		switch {
		case it.Kind == "login" && it.ID == "login-sample":
			login = it
		case it.Kind == "document" && it.ID == "document-sample":
			doc = it
		default:
			return nil, errFixture
		}
	}
	if login == nil || doc == nil || doc.Filename == "" || strings.ContainsAny(doc.Filename, "/\\") {
		return nil, errFixture
	}
	values := map[string]any{"login.title": login.Title, "login.password": login.Password, "login.ops.otp-demo": login.OTP, "document.title": doc.Title, "document.filename": doc.Filename, "document.size": len(doc.Attachment)}
	var b bytes.Buffer
	for i, slot := range l.Slots {
		v, ok := values[slot]
		if !ok {
			return nil, errFixture
		}
		delete(values, slot)
		raw, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		b.WriteString(l.Parts[i])
		b.Write(raw)
	}
	b.WriteString(l.Parts[len(l.Slots)])
	raw := b.Bytes()
	if len(raw) > 1<<20 || !json.Valid(raw) {
		return nil, errFixture
	}
	// The stored layout must bind each hole to the same source identity on read.
	projected, _, err := splitFixture(raw)
	if err != nil || !slices.Equal(projected.Parts, l.Parts) || !slices.Equal(projected.Slots, l.Slots) {
		return nil, errFixture
	}
	if l.Compact {
		var tree any
		d := json.NewDecoder(bytes.NewReader(raw))
		d.UseNumber()
		if err := d.Decode(&tree); err != nil {
			return nil, err
		}
		var err error
		raw, err = json.Marshal(tree)
		if err != nil {
			return nil, err
		}
	}
	return packFixtureDocument(raw, "files/doc-sample___"+doc.Filename, doc.Attachment)
}
func editNativeFixture(p *payload) error {
	if p.layout == nil {
		return errFixture
	}
	for i := range p.items {
		if p.items[i].ID == "login-sample" && p.items[i].Kind == "login" {
			p.items[i].Title = "轮换后的演练登录"
			p.items[i].OTP = "otpauth://totp/Synthetic?secret=MZXW6YTBOI"
			p.layout.Compact = true
			var err error
			p.Archive, err = nativeArchive(p.layout, p.items)
			return err
		}
	}
	return errFixture
}
