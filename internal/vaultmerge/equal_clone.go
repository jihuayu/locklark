package vaultmerge

import (
	"bytes"
	"time"

	"github.com/jihuayu/locklark/internal/vault"
)

// itemEqualPresent reports whole-item equality of two present items. Field
// order and nil-versus-empty slice distinction both matter: a nil slice never
// equals an empty one, matching how the vault model distinguishes the two. The
// item model holds only comparable scalars, byte/string slices and pointers to
// structs of comparable scalars (no maps), so equality is exact for every
// field.
func itemEqualPresent(a, b vault.Item) bool {
	return a.ID == b.ID &&
		a.Kind == b.Kind &&
		a.Title == b.Title &&
		a.Username == b.Username &&
		a.Password == b.Password &&
		a.OTP == b.OTP &&
		a.Filename == b.Filename &&
		bytes.Equal(a.Attachment, b.Attachment) &&
		(a.Attachment == nil) == (b.Attachment == nil) &&
		a.AttachmentProtected == b.AttachmentProtected &&
		a.State == b.State &&
		a.URL == b.URL &&
		a.PreviousState == b.PreviousState &&
		bytes.Equal(a.ImportSource, b.ImportSource) &&
		(a.ImportSource == nil) == (b.ImportSource == nil) &&
		a.Notes == b.Notes &&
		bytes.Equal(a.SSHSeed, b.SSHSeed) &&
		(a.SSHSeed == nil) == (b.SSHSeed == nil) &&
		bytes.Equal(a.SSHPublicKey, b.SSHPublicKey) &&
		(a.SSHPublicKey == nil) == (b.SSHPublicKey == nil) &&
		bytes.Equal(a.Passkey, b.Passkey) &&
		(a.Passkey == nil) == (b.Passkey == nil) &&
		passkeysEqual(a.Passkeys, b.Passkeys) &&
		a.Category == b.Category &&
		a.VaultID == b.VaultID &&
		a.Favorite == b.Favorite &&
		boolPtrEqual(a.AutoSubmit, b.AutoSubmit) &&
		stringsEqual(a.Tags, b.Tags) &&
		(a.URLs == nil) == (b.URLs == nil) && slicesEqual(a.URLs, b.URLs) &&
		sectionsEqual(a.Sections, b.Sections) &&
		(a.CreditCard == nil) == (b.CreditCard == nil) && (a.CreditCard == nil || *a.CreditCard == *b.CreditCard) &&
		(a.Identity == nil) == (b.Identity == nil) && (a.Identity == nil || *a.Identity == *b.Identity) &&
		historyEqual(a.History, b.History) &&
		attachmentsEqual(a.Attachments, b.Attachments) &&
		timePtrEqual(a.TrashedAt, b.TrashedAt) &&
		a.CreatedAt == b.CreatedAt &&
		a.UpdatedAt == b.UpdatedAt
}

func boolPtrEqual(a, b *bool) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func timePtrEqual(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Equal(*b)
}

func passkeysEqual(a, b [][]byte) bool {
	if (a == nil) != (b == nil) || len(a) != len(b) {
		return false
	}
	for i := range a {
		if (a[i] == nil) != (b[i] == nil) || !bytes.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}

func stringsEqual(a, b []string) bool {
	return (a == nil) == (b == nil) && slicesEqual(a, b)
}

func slicesEqual[T comparable](a, b []T) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func sectionsEqual(a, b []vault.ItemSection) bool {
	if (a == nil) != (b == nil) || len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].ID != b[i].ID || a[i].Title != b[i].Title ||
			(a[i].Fields == nil) != (b[i].Fields == nil) || !slicesEqual(a[i].Fields, b[i].Fields) {
			return false
		}
	}
	return true
}

func historyEqual(a, b []vault.ItemHistoryEntry) bool {
	if (a == nil) != (b == nil) || len(a) != len(b) {
		return false
	}
	for i := range a {
		x, y := a[i], b[i]
		if x.Timestamp != y.Timestamp || x.Action != y.Action || x.Password != y.Password ||
			x.Title != y.Title || x.Username != y.Username || x.Notes != y.Notes ||
			!sectionsEqual(x.Sections, y.Sections) {
			return false
		}
	}
	return true
}

func attachmentsEqual(a, b []vault.AttachmentMeta) bool {
	if (a == nil) != (b == nil) || len(a) != len(b) {
		return false
	}
	for i := range a {
		x, y := a[i], b[i]
		if x.ID != y.ID || x.FileName != y.FileName || x.Size != y.Size || x.MIMEType != y.MIMEType ||
			x.SHA256 != y.SHA256 || x.Protected != y.Protected ||
			(x.Content == nil) != (y.Content == nil) || !bytes.Equal(x.Content, y.Content) {
			return false
		}
	}
	return true
}

// cloneItem returns a deep copy of it: every byte slice, nested slice, pointer
// target, passkey record and attachment body lives in fresh memory. Nil versus
// empty is preserved for every slice.
func cloneItem(it vault.Item) vault.Item {
	c := it
	c.Attachment = cloneBytes(it.Attachment)
	c.ImportSource = cloneBytes(it.ImportSource)
	c.SSHSeed = cloneBytes(it.SSHSeed)
	c.SSHPublicKey = cloneBytes(it.SSHPublicKey)
	c.Passkey = cloneBytes(it.Passkey)
	if it.Passkeys != nil {
		c.Passkeys = make([][]byte, len(it.Passkeys))
		for i, pk := range it.Passkeys {
			c.Passkeys[i] = cloneBytes(pk)
		}
	}
	if it.AutoSubmit != nil {
		v := *it.AutoSubmit
		c.AutoSubmit = &v
	}
	c.Tags = cloneStringSlice(it.Tags)
	c.URLs = cloneSlice(it.URLs)
	if it.Sections != nil {
		c.Sections = make([]vault.ItemSection, len(it.Sections))
		for i, sec := range it.Sections {
			c.Sections[i] = sec
			if sec.Fields != nil {
				c.Sections[i].Fields = append([]vault.CustomField{}, sec.Fields...)
			}
		}
	}
	if it.CreditCard != nil {
		v := *it.CreditCard
		c.CreditCard = &v
	}
	if it.Identity != nil {
		v := *it.Identity
		c.Identity = &v
	}
	if it.History != nil {
		c.History = make([]vault.ItemHistoryEntry, len(it.History))
		for i, h := range it.History {
			c.History[i] = h
			if h.Sections != nil {
				c.History[i].Sections = make([]vault.ItemSection, len(h.Sections))
				for j, sec := range h.Sections {
					c.History[i].Sections[j] = sec
					if sec.Fields != nil {
						c.History[i].Sections[j].Fields = append([]vault.CustomField{}, sec.Fields...)
					}
				}
			}
		}
	}
	if it.Attachments != nil {
		c.Attachments = make([]vault.AttachmentMeta, len(it.Attachments))
		for i, a := range it.Attachments {
			c.Attachments[i] = a
			c.Attachments[i].Content = cloneBytes(a.Content)
		}
	}
	if it.TrashedAt != nil {
		t := *it.TrashedAt
		c.TrashedAt = &t
	}
	return c
}

func cloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	return append([]byte{}, b...)
}

func cloneStringSlice(s []string) []string {
	if s == nil {
		return nil
	}
	return append([]string{}, s...)
}

func cloneSlice[T any](s []T) []T {
	if s == nil {
		return nil
	}
	return append([]T{}, s...)
}
