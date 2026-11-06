package vault

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"filippo.io/age"
	"github.com/jihuayu/locklark/internal/passkey"
	kdbx "github.com/jihuayu/locklark/third_party/gokeepasslib"
	"github.com/jihuayu/locklark/third_party/gokeepasslib/wrappers"
	"golang.org/x/crypto/ssh"
)

// Item is the encrypted native schema supporting v1 (login, document, ssh-key)
// and v2 (all categories, sections, custom fields, multi-URL, tags, favorites,
// history, attachments, Recently Deleted TrashedAt, and sub-vaults).
type Item struct {
	ID, Kind, Title, Username, Password, OTP, Filename string
	Attachment                                         []byte
	AttachmentProtected                                bool
	State                                              string `json:",omitempty"`
	URL                                                string `json:",omitempty"`
	PreviousState                                      string `json:",omitempty"`
	// ImportSource is an encrypted provenance record, never executable metadata.
	ImportSource []byte `json:",omitempty"`
	Notes        string `json:",omitempty"`
	// SSH material is part of the encrypted internal model, never a public DTO.
	SSHSeed      []byte `json:",omitempty"`
	SSHPublicKey []byte `json:",omitempty"`
	// Passkey material from PR #40 (ES256 WebAuthn credential record).
	Passkey []byte `json:",omitempty"`

	// --- Item Model v2 Extensions ---
	Category    ItemCategory       `json:"category,omitempty"`
	VaultID     string             `json:"vault_id,omitempty"` // "" or "personal" => default personal vault
	Favorite    bool               `json:"favorite,omitempty"`
	AutoSubmit  *bool              `json:"auto_submit,omitempty"`
	Tags        []string           `json:"tags,omitempty"`
	URLs        []ItemURL          `json:"urls,omitempty"`
	Sections    []ItemSection      `json:"sections,omitempty"`
	CreditCard  *CreditCardDetails `json:"credit_card,omitempty"`
	Identity    *IdentityDetails   `json:"identity,omitempty"`
	History     []ItemHistoryEntry `json:"history,omitempty"`
	Attachments []AttachmentMeta   `json:"attachments,omitempty"`
	TrashedAt   *time.Time         `json:"trashed_at,omitempty"`
	CreatedAt   int64              `json:"created_at,omitempty"`
	UpdatedAt   int64              `json:"updated_at,omitempty"`
}

const MaxNotes = 64 << 10

// ValidNotes accepts only lossless KDBX/XML plain text. It does not trim or
// normalize Unicode, whitespace, or line endings.
func ValidNotes(s string) bool { return len(s) <= MaxNotes && xmlText(s) }

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
	if items == nil || len(items) > 256 {
		return false
	}
	seen := map[string]bool{}
	for _, it := range items {
		if it.ID == "" || len(it.ID) > 256 || seen[it.ID] {
			return false
		}
		seen[it.ID] = true
		charge := func(n int) bool {
			if n < 0 || n > MaxPayload-size {
				return false
			}
			size += n
			return true
		}
		for _, s := range []string{it.ID, it.Kind, it.Title, it.Username, it.Password, it.OTP, it.Filename, it.State, it.URL, it.PreviousState, it.Notes, it.VaultID} {
			if !charge(len(s)) || !xmlText(s) {
				return false
			}
		}
		if !charge(len(it.Attachment)) {
			return false
		}
		if !charge(len(it.ImportSource)) {
			return false
		}
		if !charge(len(it.SSHSeed)) || !charge(len(it.SSHPublicKey)) {
			return false
		}
		if !charge(len(it.Passkey)) || len(it.Passkey) > 0 && !passkey.ValidRecord(it.Passkey) {
			return false
		}
		cat, ok := CategoryFromKind(it.Kind, it.Category)
		if !ok {
			return false
		}
		if it.State != "" && it.State != "archived" && it.State != "trashed" {
			return false
		}
		if it.PreviousState != "" && (it.State != "trashed" || it.PreviousState != "archived") {
			return false
		}
		if it.Notes != "" && !ValidNotes(it.Notes) {
			return false
		}
		if it.URL != "" && !validURL(it.URL) {
			return false
		}
		if it.VaultID != "" && it.VaultID != DefaultVaultID && !selectorID(it.VaultID) {
			return false
		}
		if it.CreatedAt < 0 || it.UpdatedAt < 0 {
			return false
		}
		if it.TrashedAt != nil && it.State != "trashed" {
			return false
		}
		if len(it.Tags) > 64 {
			return false
		}
		tags := map[string]bool{}
		for _, t := range it.Tags {
			if !validTag(t) || !charge(len(t)) || tags[strings.ToLower(t)] {
				return false
			}
			tags[strings.ToLower(t)] = true
		}
		if len(it.URLs) > 64 {
			return false
		}
		urls := map[string]bool{}
		for _, u := range it.URLs {
			if !validURL(u.URL) || !validMatchMode(u.MatchMode) || !xmlText(u.Label) || len(u.Label) > 256 || urls[u.URL] {
				return false
			}
			urls[u.URL] = true
			if !charge(len(u.URL) + len(u.Label)) {
				return false
			}
		}
		if len(it.Sections) > 0 {
			if !validSections(it.Sections) {
				return false
			}
			for _, s := range it.Sections {
				if !charge(len(s.ID) + len(s.Title)) {
					return false
				}
				for _, f := range s.Fields {
					if !charge(len(f.ID) + len(f.Label) + len(f.Value) + len(f.Purpose)) {
						return false
					}
				}
			}
		}
		if !validCreditCard(it.CreditCard) || !validIdentity(it.Identity) {
			return false
		}
		if len(it.History) > 100 {
			return false
		}
		for _, h := range it.History {
			if h.Timestamp < 0 || !xmlText(h.Action) || len(h.Action) > 64 || !utf8.ValidString(h.Password) || !utf8.ValidString(h.Title) || !utf8.ValidString(h.Username) || !utf8.ValidString(h.Notes) {
				return false
			}
			if len(h.Sections) > 0 && !validSections(h.Sections) {
				return false
			}
			if !charge(len(h.Action) + len(h.Password) + len(h.Title) + len(h.Username) + len(h.Notes)) {
				return false
			}
			for _, s := range h.Sections {
				for _, f := range s.Fields {
					if !charge(len(f.Value)) {
						return false
					}
				}
			}
		}
		if len(it.Attachments) > 16 {
			return false
		}
		atts := map[string]bool{}
		for _, att := range it.Attachments {
			if !selectorID(att.ID) || atts[strings.ToLower(att.ID)] || !validAttachmentName(att.FileName) || att.Size < 0 || att.Size > MaxAttachmentSize || int64(len(att.Content)) != att.Size || !validHexDigest(att.SHA256) || att.SHA256 != AttachmentSHA256(att.Content) || len(att.MIMEType) > 256 || !xmlText(att.MIMEType) {
				return false
			}
			atts[strings.ToLower(att.ID)] = true
			if !charge(int(att.Size)) {
				return false
			}
		}

		// SSH material is only meaningful for the ssh_key category. A v1
		// "ssh-key" requires a complete Ed25519 key pair; a v2 "ssh_key" may
		// carry arbitrary typed sections instead.
		if it.Kind == "ssh-key" || cat == CategorySSHKey && (len(it.SSHSeed) > 0 || len(it.SSHPublicKey) > 0) {
			if len(it.SSHSeed) != ed25519.SeedSize || len(it.SSHPublicKey) == 0 {
				return false
			}
			private := ed25519.NewKeyFromSeed(it.SSHSeed)
			public, err := ssh.NewPublicKey(private.Public())
			clear(private)
			if err != nil || !bytes.Equal(public.Marshal(), it.SSHPublicKey) {
				return false
			}
		} else if cat != CategorySSHKey && (it.SSHSeed != nil || it.SSHPublicKey != nil) {
			return false
		}
		if len(it.Passkey) > 0 && cat != CategoryLogin {
			return false
		}
		if cat == CategoryDocument {
			if it.Filename != "" && (it.Filename == "." || it.Filename == ".." || !validAttachmentName(it.Filename)) {
				return false
			}
			if it.Attachment != nil && it.Filename == "" {
				return false
			}
			if !hasV2Extension(it) {
				if it.Filename == "" || it.Notes != "" || it.URL != "" || it.Username != "" || it.Password != "" || it.OTP != "" || it.Passkey != nil {
					return false
				}
			}
		} else {
			if it.Filename != "" || it.Attachment != nil || it.AttachmentProtected {
				return false
			}
			if it.Kind == "ssh-key" && (it.Username != "" || it.Password != "" || it.OTP != "" || it.URL != "" || it.Notes != "" || it.ImportSource != nil || it.Passkey != nil) {
				return false
			}
			if cat == CategorySSHKey && it.Kind == "ssh-key" && len(it.SSHSeed) != ed25519.SeedSize {
				return false
			}
		}
	}
	return true
}
func SealItems(metadata []byte, items []Item, epoch uint64, recipients []*age.X25519Recipient, signer ed25519.PrivateKey) (Snapshot, error) {
	if err := ValidateItems(metadata, items); err != nil {
		return Snapshot{}, err
	}
	return seal(metadata, items, epoch, recipients, signer)
}

// ValidateItems checks the same bounds and schema used by SealItems without
// generating keys or writing a snapshot.
func ValidateItems(metadata []byte, items []Item) error {
	if !validItems(items, len(metadata)) {
		return ErrSnapshot
	}
	return nil
}
func slot(key, value string, protected bool) kdbx.ValueData {
	return kdbx.ValueData{Key: key, Value: kdbx.V{Content: value, Protected: wrappers.NewBoolWrapper(protected)}}
}

type binaryKey struct {
	hash      [32]byte
	protected bool
}

// binaryRef deduplicates raw bytes into KDBX InnerHeader.Binaries.
func binaryRef(db *kdbx.Database, refs map[binaryKey]int, content []byte, protected bool) int {
	k := binaryKey{sha256.Sum256(content), protected}
	if ref, ok := refs[k]; ok {
		return ref
	}
	ref := len(db.Content.InnerHeader.Binaries)
	b := kdbx.Binary{ID: ref, Content: content}
	if protected {
		b.MemoryProtection = 1
	}
	db.Content.InnerHeader.Binaries = append(db.Content.InnerHeader.Binaries, b)
	refs[k] = ref
	return ref
}

func writeItems(db *kdbx.Database, metadata []byte, items []Item) error {
	g := kdbx.NewGroup()
	g.Name = itemGroup
	m := kdbx.NewEntry()
	m.UUID = itemUUID("")
	m.Values = []kdbx.ValueData{slot("Title", "Locklark metadata v1", false), slot("Notes", base64.StdEncoding.EncodeToString(metadata), true)}
	g.Entries = []kdbx.Entry{m}
	refs := map[binaryKey]int{}
	for _, it := range items {
		e := kdbx.NewEntry()
		e.UUID = itemUUID(it.ID)
		e.Values = []kdbx.ValueData{slot("Title", it.Title, false), slot("Locklark.ID", it.ID, false), slot("Locklark.Kind", it.Kind, false)}
		if len(it.ImportSource) > 0 {
			e.Values = append(e.Values, slot("Locklark.ImportSource", base64.StdEncoding.EncodeToString(it.ImportSource), true))
		}
		if it.State != "" {
			e.Values = append(e.Values, slot("Locklark.State", it.State, false))
		}
		if it.PreviousState != "" {
			e.Values = append(e.Values, slot("Locklark.PreviousState", it.PreviousState, false))
		}
		if !hasV2Extension(it) {
			// Legacy v1 layout, byte-for-byte compatible with the original
			// Locklark native KDBX profile.
			if it.Kind == "login" {
				if len(it.Passkey) != 0 {
					e.Values = append(e.Values, slot("Locklark.Passkey", base64.StdEncoding.EncodeToString(it.Passkey), true))
				}
				if it.Notes != "" {
					e.Values = append(e.Values, slot("Notes", it.Notes, true))
				}
				if it.URL != "" {
					e.Values = append(e.Values, slot("URL", it.URL, true))
				}
				e.Values = append(e.Values, slot("Password", it.Password, true), slot("otp", it.OTP, true))
				if it.Username != "" {
					e.Values = append(e.Values, slot("UserName", it.Username, true))
				}
			} else if it.Kind == "ssh-key" {
				e.Values = append(e.Values, slot("Locklark.SSHSeed", base64.StdEncoding.EncodeToString(it.SSHSeed), true), slot("Locklark.SSHPublicKey", base64.StdEncoding.EncodeToString(it.SSHPublicKey), false))
			} else {
				ref := binaryRef(db, refs, it.Attachment, it.AttachmentProtected)
				e.Binaries = []kdbx.BinaryReference{kdbx.NewBinaryReference(it.Filename, ref)}
			}
			g.Entries = append(g.Entries, e)
			continue
		}

		cat := it.EffectiveCategory()
		switch {
		case cat == CategorySSHKey && (it.Kind == "ssh-key" || len(it.SSHSeed) > 0):
			e.Values = append(e.Values, slot("Locklark.SSHSeed", base64.StdEncoding.EncodeToString(it.SSHSeed), true), slot("Locklark.SSHPublicKey", base64.StdEncoding.EncodeToString(it.SSHPublicKey), false))
		case cat == CategoryDocument:
			if it.Filename != "" || it.Attachment != nil {
				ref := binaryRef(db, refs, it.Attachment, it.AttachmentProtected)
				e.Binaries = append(e.Binaries, kdbx.NewBinaryReference(it.Filename, ref))
			}
		default:
			if len(it.Passkey) != 0 {
				e.Values = append(e.Values, slot("Locklark.Passkey", base64.StdEncoding.EncodeToString(it.Passkey), true))
			}
			if it.Notes != "" {
				e.Values = append(e.Values, slot("Notes", it.Notes, true))
			}
			if it.URL != "" {
				e.Values = append(e.Values, slot("URL", it.URL, true))
			}
			e.Values = append(e.Values, slot("Password", it.Password, true), slot("otp", it.OTP, true))
			if it.Username != "" {
				e.Values = append(e.Values, slot("UserName", it.Username, true))
			}
		}
		env := itemV2Envelope{
			Version:     2,
			Category:    it.Category,
			VaultID:     it.VaultID,
			Favorite:    it.Favorite,
			AutoSubmit:  it.AutoSubmit,
			Tags:        it.Tags,
			URLs:        it.URLs,
			Sections:    it.Sections,
			CreditCard:  it.CreditCard,
			Identity:    it.Identity,
			History:     it.History,
			Attachments: it.Attachments,
			TrashedAt:   it.TrashedAt,
			CreatedAt:   it.CreatedAt,
			UpdatedAt:   it.UpdatedAt,
		}
		raw, err := json.Marshal(env)
		if err != nil {
			return err
		}
		e.Values = append(e.Values, slot(itemV2Slot, base64.StdEncoding.EncodeToString(raw), true))
		for _, att := range it.Attachments {
			ref := binaryRef(db, refs, att.Content, att.Protected)
			e.Binaries = append(e.Binaries, kdbx.NewBinaryReference(attachmentRefPrefix+att.ID+"/"+att.FileName, ref))
		}
		g.Entries = append(g.Entries, e)
	}
	db.Content.Root.Groups = []kdbx.Group{g}
	return nil
}
func supportedTimes(t kdbx.TimeData) bool {
	// These snapshots generate new creation/access timestamps on reseal. An
	// expiration or usage counter is meaningful state we cannot drop.
	return !t.Expires.Bool && t.ExpiryTime == nil && t.UsageCount == 0
}
func supportedGroup(g kdbx.Group) bool {
	return supportedTimes(g.Times) && g.Notes == "" && g.Tags == "" && len(g.CustomData) == 0 && g.IconID == 0 && g.CustomIconUUID.IsZero() && g.PreviousParentGroup == nil && g.DefaultAutoTypeSequence == "" && g.EnableAutoType == wrappers.NewNullableBoolWrapper(true) && g.EnableSearching == wrappers.NewNullableBoolWrapper(true)
}
func supportedEntry(e kdbx.Entry) bool {
	a := e.AutoType
	return supportedTimes(e.Times) && len(e.Histories) == 0 && len(e.CustomData) == 0 && e.Tags == "" && e.OverrideURL == "" && e.IconID == 0 && e.CustomIconUUID.IsZero() && e.ForegroundColor == "" && e.BackgroundColor == "" && e.PreviousParentGroup == nil && e.QualityCheck == nil && !a.Enabled.Bool && a.DataTransferObfuscation == 0 && a.DefaultSequence == "" && len(a.Associations) == 0
}

func decodeItemV2Envelope(content string) (itemV2Envelope, error) {
	var env itemV2Envelope
	raw, err := base64.StdEncoding.Strict().DecodeString(content)
	if err != nil || len(raw) == 0 || len(raw) > MaxPayload || base64.StdEncoding.EncodeToString(raw) != content {
		return env, ErrSnapshot
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&env); err != nil {
		return itemV2Envelope{}, ErrSnapshot
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return itemV2Envelope{}, ErrSnapshot
	}
	if env.Version != 2 || env.Category != "" && !ValidCategory(env.Category) {
		return itemV2Envelope{}, ErrSnapshot
	}
	return env, nil
}

func applyItemV2Envelope(it *Item, env itemV2Envelope) error {
	it.Category = env.Category
	it.VaultID = env.VaultID
	it.Favorite = env.Favorite
	it.AutoSubmit = env.AutoSubmit
	it.Tags = env.Tags
	it.URLs = env.URLs
	it.Sections = env.Sections
	it.CreditCard = env.CreditCard
	it.Identity = env.Identity
	it.History = env.History
	it.Attachments = env.Attachments
	it.TrashedAt = env.TrashedAt
	it.CreatedAt = env.CreatedAt
	it.UpdatedAt = env.UpdatedAt
	if _, ok := CategoryFromKind(it.Kind, it.Category); !ok {
		return ErrSnapshot
	}
	return nil
}

func readItems(db *kdbx.Database, g kdbx.Group) ([]byte, []Item, error) {
	if !supportedGroup(g) || len(db.Content.Root.DeletedObjects) != 0 {
		return nil, nil, ErrSnapshot
	}
	if len(g.Groups) != 0 || len(g.Entries) < 1 || len(g.Entries) > 257 || db.Content.InnerHeader == nil {
		return nil, nil, ErrSnapshot
	}
	var metadata []byte
	items := make([]Item, 0, len(g.Entries)-1)
	foundMeta := false
	used := map[int]bool{}
	for _, e := range g.Entries {
		fields := map[string]kdbx.V{}
		for _, v := range e.Values {
			if _, ok := fields[v.Key]; ok {
				return nil, nil, ErrSnapshot
			}
			protected := v.Key == "UserName" || v.Key == "Notes" || v.Key == "Password" || v.Key == "otp" || v.Key == "URL" || v.Key == "Locklark.ImportSource" || v.Key == "Locklark.SSHSeed" || v.Key == "Locklark.Passkey" || v.Key == itemV2Slot
			if v.Value.Protected.Bool != protected {
				return nil, nil, ErrSnapshot
			}
			fields[v.Key] = v.Value
		}
		if !supportedEntry(e) {
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
		extra := 0
		if source, ok := fields["Locklark.ImportSource"]; ok {
			var err error
			it.ImportSource, err = base64.StdEncoding.Strict().DecodeString(source.Content)
			if err != nil || len(it.ImportSource) == 0 || base64.StdEncoding.EncodeToString(it.ImportSource) != source.Content {
				return nil, nil, ErrSnapshot
			}
			extra++
		}
		if state, ok := fields["Locklark.State"]; ok {
			if state.Content != "archived" && state.Content != "trashed" {
				return nil, nil, ErrSnapshot
			}
			it.State = state.Content
			extra++
		}
		if previous, ok := fields["Locklark.PreviousState"]; ok {
			if it.State != "trashed" || previous.Content != "archived" {
				return nil, nil, ErrSnapshot
			}
			it.PreviousState = previous.Content
			extra++
		}

		env, hasV2 := itemV2Envelope{}, false
		if v, ok := fields[itemV2Slot]; ok {
			var err error
			env, err = decodeItemV2Envelope(v.Content)
			if err != nil {
				return nil, nil, ErrSnapshot
			}
			hasV2 = true
		}
		if !hasV2 {
			switch it.Kind {
			case "ssh-key":
				if len(fields) != 5+extra || len(e.Binaries) != 0 {
					return nil, nil, ErrSnapshot
				}
				var err error
				it.SSHSeed, err = base64.StdEncoding.Strict().DecodeString(fields["Locklark.SSHSeed"].Content)
				if err != nil || base64.StdEncoding.EncodeToString(it.SSHSeed) != fields["Locklark.SSHSeed"].Content {
					return nil, nil, ErrSnapshot
				}
				it.SSHPublicKey, err = base64.StdEncoding.Strict().DecodeString(fields["Locklark.SSHPublicKey"].Content)
				if err != nil || base64.StdEncoding.EncodeToString(it.SSHPublicKey) != fields["Locklark.SSHPublicKey"].Content {
					return nil, nil, ErrSnapshot
				}
			case "login":
				expected := 5 + extra
				if v, ok := fields["Locklark.Passkey"]; ok {
					var err error
					it.Passkey, err = base64.StdEncoding.Strict().DecodeString(v.Content)
					if err != nil || len(it.Passkey) == 0 || base64.StdEncoding.EncodeToString(it.Passkey) != v.Content {
						return nil, nil, ErrSnapshot
					}
					expected++
				}
				if v, ok := fields["Notes"]; ok {
					if v.Content == "" || !ValidNotes(v.Content) {
						return nil, nil, ErrSnapshot
					}
					it.Notes = v.Content
					expected++
				}
				if v, ok := fields["URL"]; ok {
					if v.Content == "" {
						return nil, nil, ErrSnapshot
					}
					it.URL = v.Content
					expected++
				}
				if v, ok := fields["UserName"]; ok {
					it.Username = v.Content
					expected++
				}
				if len(fields) != expected || !fields["Password"].Protected.Bool || !fields["otp"].Protected.Bool || len(e.Binaries) != 0 {
					return nil, nil, ErrSnapshot
				}
				it.Password, it.OTP = fields["Password"].Content, fields["otp"].Content
			case "document":
				if len(fields) != 3+extra || len(e.Binaries) != 1 {
					return nil, nil, ErrSnapshot
				}
				ref := e.Binaries[0]
				b := db.FindBinary(ref.Value.ID)
				if b == nil || b.MemoryProtection > 1 || len(b.Content) > MaxPayload {
					return nil, nil, ErrSnapshot
				}
				// KDBX 4 inner-header binaries are raw octets, even when their
				// content happens to be valid base64 text.
				it.AttachmentProtected = b.MemoryProtection == 1
				it.Attachment = b.Content
				it.Filename = ref.Name
				used[ref.Value.ID] = true
			default:
				return nil, nil, ErrSnapshot
			}
			items = append(items, it)
			continue
		}

		// --- Item Model v2 entry ---
		if err := applyItemV2Envelope(&it, env); err != nil {
			return nil, nil, ErrSnapshot
		}
		if !hasV2Extension(it) {
			return nil, nil, ErrSnapshot
		}
		cat := it.EffectiveCategory()
		switch {
		case cat == CategorySSHKey && (it.Kind == "ssh-key" || len(fields["Locklark.SSHSeed"].Content) > 0):
			if len(fields) != 6+extra || len(e.Binaries) != 0 {
				return nil, nil, ErrSnapshot
			}
			var err error
			it.SSHSeed, err = base64.StdEncoding.Strict().DecodeString(fields["Locklark.SSHSeed"].Content)
			if err != nil || base64.StdEncoding.EncodeToString(it.SSHSeed) != fields["Locklark.SSHSeed"].Content {
				return nil, nil, ErrSnapshot
			}
			it.SSHPublicKey, err = base64.StdEncoding.Strict().DecodeString(fields["Locklark.SSHPublicKey"].Content)
			if err != nil || base64.StdEncoding.EncodeToString(it.SSHPublicKey) != fields["Locklark.SSHPublicKey"].Content {
				return nil, nil, ErrSnapshot
			}
		case cat == CategoryDocument:
			if len(fields) != 4+extra {
				return nil, nil, ErrSnapshot
			}
			if len(e.Binaries) > 1 {
				return nil, nil, ErrSnapshot
			}
			if len(e.Binaries) == 1 {
				ref := e.Binaries[0]
				if strings.HasPrefix(ref.Name, attachmentRefPrefix) {
					return nil, nil, ErrSnapshot
				}
				b := db.FindBinary(ref.Value.ID)
				if b == nil || b.MemoryProtection > 1 || len(b.Content) > MaxPayload {
					return nil, nil, ErrSnapshot
				}
				it.AttachmentProtected = b.MemoryProtection == 1
				it.Attachment = b.Content
				it.Filename = ref.Name
				used[ref.Value.ID] = true
			}
		default:
			expected := 6 + extra
			if v, ok := fields["Locklark.Passkey"]; ok {
				var err error
				it.Passkey, err = base64.StdEncoding.Strict().DecodeString(v.Content)
				if err != nil || len(it.Passkey) == 0 || base64.StdEncoding.EncodeToString(it.Passkey) != v.Content {
					return nil, nil, ErrSnapshot
				}
				expected++
			}
			if v, ok := fields["Notes"]; ok {
				if v.Content == "" || !ValidNotes(v.Content) {
					return nil, nil, ErrSnapshot
				}
				it.Notes = v.Content
				expected++
			}
			if v, ok := fields["URL"]; ok {
				if v.Content == "" {
					return nil, nil, ErrSnapshot
				}
				it.URL = v.Content
				expected++
			}
			if v, ok := fields["UserName"]; ok {
				it.Username = v.Content
				expected++
			}
			if len(fields) != expected || !fields["Password"].Protected.Bool || !fields["otp"].Protected.Bool {
				return nil, nil, ErrSnapshot
			}
			it.Password, it.OTP = fields["Password"].Content, fields["otp"].Content
		}

		refsByName := map[string]kdbx.BinaryReference{}
		for _, ref := range e.Binaries {
			if _, ok := refsByName[ref.Name]; ok {
				return nil, nil, ErrSnapshot
			}
			refsByName[ref.Name] = ref
		}
		for n := range it.Attachments {
			att := &it.Attachments[n]
			name := attachmentRefPrefix + att.ID + "/" + att.FileName
			ref, ok := refsByName[name]
			if !ok {
				return nil, nil, ErrSnapshot
			}
			b := db.FindBinary(ref.Value.ID)
			if b == nil || b.MemoryProtection > 1 || len(b.Content) > MaxAttachmentSize {
				return nil, nil, ErrSnapshot
			}
			att.Protected = b.MemoryProtection == 1
			att.Content = append([]byte(nil), b.Content...)
			used[ref.Value.ID] = true
			delete(refsByName, name)
		}
		for name, ref := range refsByName {
			if cat != CategoryDocument || strings.HasPrefix(name, attachmentRefPrefix) {
				return nil, nil, ErrSnapshot
			}
			// The already-resolved primary document binary is accounted for.
			if it.Filename != name {
				return nil, nil, ErrSnapshot
			}
			_ = ref
		}
		items = append(items, it)
	}
	if !foundMeta || len(used) != len(db.Content.InnerHeader.Binaries) || !validItems(items, len(metadata)) {
		return nil, nil, ErrSnapshot
	}
	return metadata, items, nil
}
