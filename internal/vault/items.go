package vault

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"filippo.io/age"
	kdbx "github.com/jihuayu/locklark/third_party/gokeepasslib"
	"github.com/jihuayu/locklark/third_party/gokeepasslib/wrappers"
	"strings"
	"unicode/utf8"
)

// Item is the first native schema: login and document values have one owner.
type Item struct {
	ID, Kind, Title, Password, OTP, Filename string
	Attachment                               []byte
}

const itemGroup = "Locklark items v1"

func itemUUID(id string) kdbx.UUID {
	h := sha256.Sum256([]byte("locklark/kdbx/item/v1\x00" + id))
	return kdbx.UUID(h[:16])
}
func xmlText(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 32 && r != '\t' && r != '\n' && r != '\r' || r == 0xfffe || r == 0xffff {
			return false
		}
	}
	return true
}
func validItems(items []Item, size int) bool {
	if len(items) == 0 || len(items) > 256 {
		return false
	}
	seen := map[string]bool{}
	for _, it := range items {
		if it.ID == "" || len(it.ID) > 256 || seen[it.ID] {
			return false
		}
		seen[it.ID] = true
		for _, s := range []string{it.ID, it.Kind, it.Title, it.Password, it.OTP, it.Filename} {
			if len(s) > MaxPayload-size || !xmlText(s) {
				return false
			}
			size += len(s)
		}
		if len(it.Attachment) > MaxPayload-size {
			return false
		}
		size += len(it.Attachment)
		switch it.Kind {
		case "login":
			if it.Filename != "" || it.Attachment != nil {
				return false
			}
		case "document":
			if it.Password != "" || it.OTP != "" || it.Filename == "" || it.Filename == "." || it.Filename == ".." || strings.ContainsAny(it.Filename, "/\\") {
				return false
			}
		default:
			return false
		}
	}
	return true
}
func SealItems(metadata []byte, items []Item, epoch uint64, recipients []*age.X25519Recipient, signer ed25519.PrivateKey) (Snapshot, error) {
	if !validItems(items, len(metadata)) {
		return Snapshot{}, ErrSnapshot
	}
	return seal(metadata, items, epoch, recipients, signer)
}
func slot(key, value string, protected bool) kdbx.ValueData {
	return kdbx.ValueData{Key: key, Value: kdbx.V{Content: value, Protected: wrappers.NewBoolWrapper(protected)}}
}
func writeItems(db *kdbx.Database, metadata []byte, items []Item) error {
	g := kdbx.NewGroup()
	g.Name = itemGroup
	m := kdbx.NewEntry()
	m.UUID = itemUUID("")
	m.Values = []kdbx.ValueData{slot("Title", "Locklark metadata v1", false), slot("Notes", base64.StdEncoding.EncodeToString(metadata), true)}
	g.Entries = []kdbx.Entry{m}
	for _, it := range items {
		e := kdbx.NewEntry()
		e.UUID = itemUUID(it.ID)
		e.Values = []kdbx.ValueData{slot("Title", it.Title, false), slot("Locklark.ID", it.ID, false), slot("Locklark.Kind", it.Kind, false)}
		if it.Kind == "login" {
			e.Values = append(e.Values, slot("Password", it.Password, true), slot("otp", it.OTP, true))
		} else {
			ref := db.AddBinary(it.Attachment).CreateReference(it.Filename)
			e.Binaries = []kdbx.BinaryReference{ref}
		}
		g.Entries = append(g.Entries, e)
	}
	db.Content.Root.Groups = []kdbx.Group{g}
	return nil
}
func readItems(db *kdbx.Database, g kdbx.Group) ([]byte, []Item, error) {
	if len(g.Groups) != 0 || len(g.Entries) < 2 || len(g.Entries) > 257 || db.Content.InnerHeader == nil {
		return nil, nil, ErrSnapshot
	}
	var metadata []byte
	var items []Item
	foundMeta := false
	used := map[int]bool{}
	for _, e := range g.Entries {
		fields := map[string]kdbx.V{}
		for _, v := range e.Values {
			if _, ok := fields[v.Key]; ok {
				return nil, nil, ErrSnapshot
			}
			protected := v.Key == "Notes" || v.Key == "Password" || v.Key == "otp"
			if v.Value.Protected.Bool != protected {
				return nil, nil, ErrSnapshot
			}
			fields[v.Key] = v.Value
		}
		if len(e.Histories) > 0 || len(e.CustomData) > 0 || e.Tags != "" {
			return nil, nil, ErrSnapshot
		}
		if e.UUID == itemUUID("") {
			if foundMeta || len(fields) != 2 || fields["Title"].Content != "Locklark metadata v1" || !fields["Notes"].Protected.Bool || len(e.Binaries) > 0 {
				return nil, nil, ErrSnapshot
			}
			var err error
			metadata, err = base64.StdEncoding.DecodeString(fields["Notes"].Content)
			if err != nil || len(metadata) > MaxPayload {
				return nil, nil, ErrSnapshot
			}
			foundMeta = true
			continue
		}
		it := Item{ID: fields["Locklark.ID"].Content, Kind: fields["Locklark.Kind"].Content, Title: fields["Title"].Content}
		if _, ok := fields["Title"]; !ok || e.UUID != itemUUID(it.ID) {
			return nil, nil, ErrSnapshot
		}
		switch it.Kind {
		case "login":
			if len(fields) != 5 || !fields["Password"].Protected.Bool || !fields["otp"].Protected.Bool || len(e.Binaries) != 0 {
				return nil, nil, ErrSnapshot
			}
			it.Password, it.OTP = fields["Password"].Content, fields["otp"].Content
		case "document":
			if len(fields) != 3 || len(e.Binaries) != 1 {
				return nil, nil, ErrSnapshot
			}
			ref := e.Binaries[0]
			b := db.FindBinary(ref.Value.ID)
			if b == nil || len(b.Content) > MaxPayload {
				return nil, nil, ErrSnapshot
			}
			// KDBX 4 inner-header binaries are raw octets, even when their
			// content happens to be valid base64 text.
			it.Attachment = b.Content
			it.Filename = ref.Name
			used[ref.Value.ID] = true
		default:
			return nil, nil, ErrSnapshot
		}
		items = append(items, it)
	}
	if !foundMeta || len(used) != len(db.Content.InnerHeader.Binaries) || !validItems(items, len(metadata)) {
		return nil, nil, ErrSnapshot
	}
	return metadata, items, nil
}
