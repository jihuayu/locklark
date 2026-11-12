package vault

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"
	"testing"

	kdbx "github.com/jihuayu/locklark/third_party/gokeepasslib"
	"github.com/jihuayu/locklark/third_party/gokeepasslib/wrappers"
)

// The synthetic credentials below exist only to prove that the adapter's
// unlocked database survives a real encode/decode/unlock cycle. The API never
// sets, reads or uses credentials.
const itemDatabasePassword = "synthetic item database password"

// auxiliaryMetadata is non-empty because the legacy writer used for fixtures
// is not how the adapter receives external input.
var auxiliaryMetadata = []byte("auxiliary")

var itemDatabaseKey = []byte{0x4c, 0x6f, 0x63, 0x6b, 0x6c, 0x61, 0x72, 0x6b, 0x20, 0x69, 0x74, 0x65, 0x6d, 0x20, 0x64, 0x62, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x6b, 0x65, 0x79}

func itemDatabaseCredentials(t *testing.T) *kdbx.DBCredentials {
	t.Helper()
	credentials, err := kdbx.NewPasswordAndKeyDataCredentials(itemDatabasePassword, itemDatabaseKey)
	if err != nil {
		t.Fatalf("synthetic test credentials: %v", err)
	}
	return credentials
}

// itemDatabaseRoundTrip seals the adapter output the way SealItems and
// ExportKDBX do (LockProtectedEntries), encodes it as a real KDBX file under
// synthetic test credentials, then decodes it into a fresh database and
// unlocks it, exactly as an external caller would before ReadItemDatabase.
func itemDatabaseRoundTrip(t *testing.T, db *kdbx.Database) *kdbx.Database {
	t.Helper()
	if err := db.LockProtectedEntries(); err != nil {
		t.Fatalf("seal item database: %v", err)
	}
	callerCredentials := db.Credentials
	db.Credentials = itemDatabaseCredentials(t)
	var raw bytes.Buffer
	if err := kdbx.NewEncoder(&raw).Encode(db); err != nil {
		t.Fatalf("encode item database: %v", err)
	}
	db.Credentials = callerCredentials
	opened := kdbx.NewDatabase()
	opened.Credentials = itemDatabaseCredentials(t)
	if err := kdbx.NewDecoder(bytes.NewReader(raw.Bytes())).Decode(opened); err != nil {
		t.Fatalf("decode item database: %v", err)
	}
	if err := opened.UnlockProtectedEntries(); err != nil {
		t.Fatalf("unlock item database: %v", err)
	}
	return opened
}

// itemDatabaseGroup returns the single root group the layout requires.
func itemDatabaseGroup(t *testing.T, db *kdbx.Database) *kdbx.Group {
	t.Helper()
	if db.Content == nil || db.Content.Root == nil || len(db.Content.Root.Groups) != 1 {
		t.Fatal("database does not have exactly one root group")
	}
	return &db.Content.Root.Groups[0]
}

// mustItemDatabase writes the item layout without strict validation, the way a
// legacy writer did. It only guards the test fixture itself.
func mustItemDatabase(t *testing.T, metadata []byte, items []Item) *kdbx.Database {
	t.Helper()
	db := newSnapshotDatabase()
	if err := writeItems(db, metadata, items); err != nil {
		t.Fatalf("legacy fixture write: %v", err)
	}
	return db
}

// fingerprint captures every buffer the read path could touch so the tests can
// prove a read neither mutated nor aliased the supplied database.
func fingerprint(db *kdbx.Database) []byte {
	var b bytes.Buffer
	if db.Content == nil || db.Content.Root == nil {
		return nil
	}
	for _, g := range db.Content.Root.Groups {
		fingerprintGroup(&b, &g)
	}
	if db.Content.InnerHeader == nil {
		return b.Bytes()
	}
	for _, binary := range db.Content.InnerHeader.Binaries {
		b.Write(binary.Content)
	}
	return b.Bytes()
}

func fingerprintGroup(b *bytes.Buffer, g *kdbx.Group) {
	for _, e := range g.Entries {
		b.Write(e.UUID[:])
		for _, v := range e.Values {
			b.WriteString(v.Key + "\x00" + v.Value.Content + "\x00")
		}
		for _, ref := range e.Binaries {
			b.WriteString(ref.Name + "\x00")
		}
	}
}

func sharesByte(b []byte, others ...[]byte) bool {
	for _, other := range others {
		if len(b) > 0 && len(other) > 0 && &b[0] == &other[0] {
			return true
		}
	}
	return false
}

// binaryDigests lets the tests compare database binaries by content without
// keeping a second alias to every buffer.
func binaryDigests(db *kdbx.Database) []string {
	out := make([]string, len(db.Content.InnerHeader.Binaries))
	for n, binary := range db.Content.InnerHeader.Binaries {
		out[n] = fmt.Sprintf("%d/%d/%x", binary.ID, binary.MemoryProtection, sha256.Sum256(binary.Content))
	}
	return out
}

func itemDatabaseBinaries(db *kdbx.Database) [][]byte {
	out := make([][]byte, len(db.Content.InnerHeader.Binaries))
	for n, binary := range db.Content.InnerHeader.Binaries {
		out[n] = binary.Content
	}
	return out
}

func TestItemDatabaseNewIsUnlockedSnapshotProfile(t *testing.T) {
	metadata := []byte(`{"layout":"item-database","revision":7}`)
	items := v2FixtureItems(t)
	if err := ValidateItems(metadata, items); err != nil {
		t.Fatalf("fixture items are invalid: %v", err)
	}
	db, err := NewItemDatabase(metadata, items)
	if err != nil {
		t.Fatalf("NewItemDatabase: %v", err)
	}

	if db.Header == nil || db.Header.Signature == nil || !db.Header.IsKdbx41() {
		t.Fatal("adapter database is not KDBX 4.1")
	}
	if db.Credentials != nil && (db.Credentials.Passphrase != nil || db.Credentials.Key != nil || db.Credentials.Windows != nil) {
		t.Fatal("adapter set credentials")
	}
	// The exact established personal snapshot KDF profile, shared with seal.
	want := newSnapshotDatabase().Header.FileHeaders.KdfParameters
	p := db.Header.FileHeaders.KdfParameters
	if !bytes.Equal(p.UUID, []byte{0x9e, 0x29, 0x8b, 0x19, 0x56, 0xdb, 0x47, 0x73, 0xb2, 0x3d, 0xfc, 0x3e, 0xc6, 0xf0, 0xa1, 0xe6}) ||
		!bytes.Equal(p.UUID, want.UUID) || p.Memory != 16<<20 || p.Memory != want.Memory ||
		p.Iterations != 3 || p.Iterations != want.Iterations || p.Parallelism != 2 ||
		p.Parallelism != want.Parallelism || p.Version != 19 || p.Version != want.Version ||
		p.Rounds != want.Rounds || len(p.SecretKey) != 0 || len(p.AssocData) != 0 {
		t.Fatalf("KDF profile drifted: %+v", p)
	}

	// Exactly the existing root group, metadata entry and one entry per item.
	g := itemDatabaseGroup(t, db)
	if g.Name != itemGroup || len(g.Groups) != 0 || len(g.Entries) != len(items)+1 {
		t.Fatalf("unexpected shape: group %q, %d groups, %d entries", g.Name, len(g.Groups), len(g.Entries))
	}
	meta := g.Entries[0]
	if meta.GetContent("Title") != "Locklark metadata v1" {
		t.Fatal("metadata entry title changed")
	}
	decoded, err := base64.StdEncoding.DecodeString(meta.GetContent("Notes"))
	if err != nil || !bytes.Equal(decoded, metadata) {
		t.Fatalf("metadata = %q", decoded)
	}
	for _, v := range meta.Values {
		if v.Key == "Notes" && !v.Value.Protected.Bool {
			t.Fatal("metadata is not protected")
		}
	}

	// New returns the unlocked layout: protected values still carry plaintext.
	for _, id := range []string{"v1-login", "item-login"} {
		for _, e := range g.Entries {
			if e.GetContent("Locklark.ID") != id {
				continue
			}
			if got := e.GetContent("Password"); got != "p" && got != "password" {
				t.Fatalf("%s: password slot is not unlocked plaintext", id)
			}
		}
	}
	for _, e := range g.Entries {
		for _, v := range e.Values {
			if v.Key == "Locklark.V2" {
				if !v.Value.Protected.Bool {
					t.Fatal("v2 slot lost its protected flag")
				}
				if _, err := decodeItemV2Envelope(v.Value.Content); err != nil {
					t.Fatal("v2 slot is not unlocked plaintext")
				}
			}
		}
	}
}

func TestItemDatabaseRoundTrip(t *testing.T) {
	metadata := []byte(`{"layout":"item-database","revision":7}`)
	want := v2FixtureItems(t)
	if err := ValidateItems(metadata, want); err != nil {
		t.Fatalf("fixture items are invalid: %v", err)
	}
	db, err := NewItemDatabase(metadata, want)
	if err != nil {
		t.Fatalf("NewItemDatabase: %v", err)
	}
	gotMetadata, got, err := ReadItemDatabase(itemDatabaseRoundTrip(t, db))
	if err != nil {
		t.Fatalf("ReadItemDatabase: %v", err)
	}
	if !bytes.Equal(gotMetadata, metadata) {
		t.Fatalf("metadata = %q, want %q", gotMetadata, metadata)
	}
	if len(got) != len(want) {
		t.Fatalf("read %d items, want %d", len(got), len(want))
	}
	for n := range want {
		// The established v2 layout does not persist URL/Notes for ssh_key and
		// document entries (the sealed snapshot path drops them the same way),
		// so the adapter is compared against the snapshot read of the same
		// items for those two fields only.
		if v2LayoutDropsURLNotes(want[n]) {
			want[n].URL, want[n].Notes = "", ""
		}
		if !reflect.DeepEqual(want[n], got[n]) {
			t.Fatalf("item %d %q changed:\nwant %+v\ngot  %+v", n, want[n].ID, want[n], got[n])
		}
	}
}

// v2LayoutDropsURLNotes reports item entries whose URL and Notes slots the
// established layout never writes.
func v2LayoutDropsURLNotes(it Item) bool {
	if !hasV2Extension(it) {
		return false
	}
	cat := it.EffectiveCategory()
	return cat == CategorySSHKey || cat == CategoryDocument
}

func TestItemDatabaseEmptyItemsRoundTripNonNil(t *testing.T) {
	for name, metadata := range map[string][]byte{"empty metadata": {}, "metadata": []byte("meta")} {
		db, err := NewItemDatabase(metadata, []Item{})
		if err != nil {
			t.Fatalf("%s: NewItemDatabase: %v", name, err)
		}
		if entries := itemDatabaseGroup(t, db).Entries; len(entries) != 1 {
			t.Fatalf("%s: empty item list wrote %d entries", name, len(entries))
		}
		gotMetadata, got, err := ReadItemDatabase(itemDatabaseRoundTrip(t, db))
		if err != nil {
			t.Fatalf("%s: ReadItemDatabase: %v", name, err)
		}
		if got == nil || len(got) != 0 {
			t.Fatalf("%s: items = %#v, want non-nil empty", name, got)
		}
		if gotMetadata == nil || !bytes.Equal(metadata, gotMetadata) {
			t.Fatalf("%s: metadata = %q", name, gotMetadata)
		}
	}
}

func TestItemDatabaseNewRejectsInvalidInput(t *testing.T) {
	valid := v2FixtureItems(t)
	badHash := CloneItem(valid[3])
	badHash.Attachments[0].SHA256 = AttachmentSHA256([]byte("other"))
	legacy := legacyControlItem("legacy-ctrl", "login")
	duplicate := append([]Item{valid[0]}, CloneItem(valid[0]))
	for name, tc := range map[string]struct {
		metadata []byte
		items    []Item
	}{
		"nil items":     {[]byte{}, nil},
		"nil metadata":  {nil, []Item{valid[0]}},
		"oversize meta": {make([]byte, MaxPayload+1), []Item{}},
		"at bound":      {make([]byte, MaxPayload), []Item{valid[0]}},
		"empty id":      {nil, []Item{{ID: "", Kind: "login", Title: "t"}}},
		"duplicate id":  {nil, duplicate},
		"unknown kind":  {nil, []Item{{ID: "x", Kind: "unknown", Title: "t"}}},
		"control title": {nil, []Item{{ID: "x", Kind: "login", Title: "bad\x01"}}},
		"too many":      {nil, make([]Item, MaxItems+1)},
		"legacy value":  {nil, []Item{legacy}},
		"bad hash":      {nil, []Item{badHash}},
	} {
		db, err := NewItemDatabase(tc.metadata, tc.items)
		if !errors.Is(err, ErrSnapshot) || db != nil {
			t.Fatalf("%s: NewItemDatabase = %v, %v; want nil, ErrSnapshot", name, db, err)
		}
	}
	// Control: the same fixture under the bound is accepted unchanged.
	if err := ValidateItems(nil, []Item{valid[0]}); err != nil {
		t.Fatalf("fixture control invalid: %v", err)
	}
	if _, err := NewItemDatabase([]byte{}, []Item{valid[0]}); err != nil {
		t.Fatalf("control write rejected: %v", err)
	}
}

func TestItemDatabaseNewRejectsLegacyReadOnlyValues(t *testing.T) {
	legacy := map[string]Item{
		"credit card": func() Item {
			it := legacyControlItem("legacy-ctrl", "")
			it.Kind = "login"
			return it
		}(),
		"identity": {ID: "legacy-identity", Kind: "", Category: CategoryIdentity, Title: "Legacy", Identity: &IdentityDetails{FirstName: legacyControlText}},
		"history":  {ID: "legacy-history", Kind: "login", Title: "Legacy", History: []ItemHistoryEntry{{Timestamp: 1, Action: "edit", Notes: legacyControlText}}},
	}
	for name, it := range legacy {
		if validItems([]Item{it}, 0) || !validLegacyItems([]Item{it}, 0) {
			t.Fatalf("%s: fixture is not legacy-read-only", name)
		}
		before := CloneItem(it)
		db, err := NewItemDatabase(nil, []Item{it})
		if !errors.Is(err, ErrSnapshot) || db != nil {
			t.Fatalf("%s: NewItemDatabase = %v; legacy-read-only value was accepted", name, err)
		}
		if !reflect.DeepEqual(before, it) {
			t.Fatalf("%s: NewItemDatabase normalized the caller's value", name)
		}
	}
}

func TestItemDatabaseReadRejectsUnsupportedInput(t *testing.T) {
	items := []Item{CloneItem(v2FixtureItems(t)[0]), CloneItem(v2FixtureItems(t)[3])}
	newOpened := func(t *testing.T) *kdbx.Database {
		t.Helper()
		db, err := NewItemDatabase([]byte("meta"), items)
		if err != nil {
			t.Fatalf("fixture database: %v", err)
		}
		return itemDatabaseRoundTrip(t, db)
	}
	for name, db := range map[string]func(*testing.T) *kdbx.Database{
		"nil":         func(*testing.T) *kdbx.Database { return nil },
		"nil content": func(t *testing.T) *kdbx.Database { d := newOpened(t); d.Content = nil; return d },
		"nil meta":    func(t *testing.T) *kdbx.Database { d := newOpened(t); d.Content.Meta = nil; return d },
		"nil root": func(t *testing.T) *kdbx.Database {
			d := newOpened(t)
			d.Content.Root = nil
			return d
		},
		"nil inner header": func(t *testing.T) *kdbx.Database {
			d := newOpened(t)
			d.Content.InnerHeader = nil
			return d
		},
		"nil stream key": func(t *testing.T) *kdbx.Database {
			d := newOpened(t)
			d.Content.InnerHeader.InnerRandomStreamKey = nil
			return d
		},
		"nil header":   func(t *testing.T) *kdbx.Database { d := newOpened(t); d.Header = nil; return d },
		"nil sig":      func(t *testing.T) *kdbx.Database { d := newOpened(t); d.Header.Signature = nil; return d },
		"nil files":    func(t *testing.T) *kdbx.Database { d := newOpened(t); d.Header.FileHeaders = nil; return d },
		"not kdbx 4.1": func(t *testing.T) *kdbx.Database { d := newOpened(t); d.Header.Signature.MajorVersion = 3; return d },
		"rootless": func(t *testing.T) *kdbx.Database {
			d := newOpened(t)
			d.Content.Root.Groups = nil
			return d
		},
		"multi-group": func(t *testing.T) *kdbx.Database {
			d := newOpened(t)
			d.Content.Root.Groups = append(d.Content.Root.Groups, kdbx.NewGroup())
			return d
		},
		"wrong group": func(t *testing.T) *kdbx.Database {
			d := newOpened(t)
			d.Content.Root.Groups[0].Name = "Other"
			return d
		},
		"legacy preview group": func(t *testing.T) *kdbx.Database {
			d := newOpened(t)
			g := kdbx.NewGroup()
			g.Name = "Locklark"
			d.Content.Root.Groups = []kdbx.Group{g}
			return d
		},
		"subgroup": func(t *testing.T) *kdbx.Database {
			d := newOpened(t)
			d.Content.Root.Groups[0].Groups = []kdbx.Group{kdbx.NewGroup()}
			return d
		},
		"missing metadata": func(t *testing.T) *kdbx.Database {
			d := newOpened(t)
			d.Content.Root.Groups[0].Entries = d.Content.Root.Groups[0].Entries[1:]
			return d
		},
		"unknown field": func(t *testing.T) *kdbx.Database {
			d := newOpened(t)
			e := &d.Content.Root.Groups[0].Entries[1]
			e.Values = append(e.Values, slot("Locklark.Extra", "x", false))
			return d
		},
		"unprotected password": func(t *testing.T) *kdbx.Database {
			d := newOpened(t)
			e := &d.Content.Root.Groups[0].Entries[1]
			for n := range e.Values {
				if e.Values[n].Key == "Password" {
					e.Values[n].Value.Protected = wrappers.NewBoolWrapper(false)
				}
			}
			return d
		},
		"orphan binary": func(t *testing.T) *kdbx.Database {
			d := newOpened(t)
			n := len(d.Content.InnerHeader.Binaries)
			d.Content.InnerHeader.Binaries = append(d.Content.InnerHeader.Binaries, kdbx.Binary{ID: n, Content: []byte("orphan")})
			return d
		},
		"legacy-read-only value": func(t *testing.T) *kdbx.Database {
			return itemDatabaseRoundTrip(t, mustItemDatabase(t, auxiliaryMetadata, []Item{legacyControlItem("legacy-ctrl", "login")}))
		},
		"legacy-read-only value after document": func(t *testing.T) *kdbx.Database {
			// The document entry is decoded (and its binary read) before the
			// legacy item fails the strict final check.
			d := itemDatabaseRoundTrip(t, mustItemDatabase(t, auxiliaryMetadata, []Item{legacyControlItem("legacy-ctrl", ""), items[1]}))
			return d
		},
	} {
		t.Run(name, func(t *testing.T) {
			supplied := db(t)
			before := []byte(nil)
			if supplied != nil {
				before = fingerprint(supplied)
			}
			metadata, got, err := ReadItemDatabase(supplied)
			if !errors.Is(err, ErrSnapshot) || metadata != nil || got != nil {
				t.Fatalf("%s: ReadItemDatabase = %q, %d items, %v; want nil, nil, ErrSnapshot", name, metadata, len(got), err)
			}
			if before != nil && !bytes.Equal(before, fingerprint(supplied)) {
				t.Fatalf("%s: rejected read mutated the supplied database", name)
			}
		})
	}

	// Fail after every binary was decoded, then prove no source buffer was
	// zeroed by the failure cleanup.
	d := itemDatabaseRoundTrip(t, mustItemDatabase(t, auxiliaryMetadata, []Item{items[1]}))
	legacyDB := mustItemDatabase(t, auxiliaryMetadata, []Item{legacyControlItem("legacy-ctrl", "")})
	g := itemDatabaseGroup(t, d)
	g.Entries = append(g.Entries, legacyDB.Content.Root.Groups[0].Entries[1:]...)
	before := fingerprint(d)
	binaryCount := len(d.Content.InnerHeader.Binaries)
	if binaryCount == 0 {
		t.Fatal("fixture has no binaries")
	}
	if metadata, got, err := ReadItemDatabase(d); !errors.Is(err, ErrSnapshot) || metadata != nil || got != nil {
		t.Fatalf("mixed read = %d items, %v", len(got), err)
	}
	if after := fingerprint(d); !bytes.Equal(before, after) {
		t.Fatal("failed read mutated the supplied database content")
	}

	// Control: the plain roundtrip reads back.
	if _, got, err := ReadItemDatabase(newOpened(t)); err != nil || len(got) != len(items) {
		t.Fatalf("control read: %v, %d items", err, len(got))
	}
}

func TestItemDatabaseBinaryOwnership(t *testing.T) {
	items := itemDatabaseBinaryFixture(t)
	metadata := []byte("meta")
	db, err := NewItemDatabase(metadata, items)
	if err != nil {
		t.Fatal(err)
	}

	// The database owns its metadata...
	metadata[0] = '#'
	meta := itemDatabaseGroup(t, db).Entries[0]
	if decoded, err := base64.StdEncoding.DecodeString(meta.GetContent("Notes")); err != nil || string(decoded) != "meta" {
		t.Fatalf("database metadata aliases the caller: %q", decoded)
	}
	// Equal database binaries may share one database-owned buffer, but no
	// database buffer may be the caller's.
	binaries := itemDatabaseBinaries(db)

	// ...and its attachments: clearing the caller's bytes and locking the
	// database only ever touches database-owned copies.
	callerBuffers := callerBinaryBuffers(items)
	for n := range binaries {
		if sharesByte(binaries[n], callerBuffers...) {
			t.Fatalf("binary %d aliases a caller attachment", n)
		}
	}
	snapshot := binaryDigests(db)
	for n := range items {
		clear(items[n].Attachment)
		for m := range items[n].Attachments {
			clear(items[n].Attachments[m].Content)
		}
	}
	if !reflect.DeepEqual(snapshot, binaryDigests(db)) {
		t.Fatal("clearing caller attachments changed the database")
	}
	if err := db.LockProtectedEntries(); err != nil {
		t.Fatal(err)
	}

	// Read side: every returned buffer is independent of the database, of the
	// caller's fixture and of every other returned buffer.
	fresh := itemDatabaseBinaryFixture(t)
	db, err = NewItemDatabase(metadata, fresh)
	if err != nil {
		t.Fatal(err)
	}
	opened := itemDatabaseRoundTrip(t, db)
	before := fingerprint(opened)
	callerBuffers = callerBinaryBuffers(fresh)
	_, got, err := ReadItemDatabase(opened)
	if err != nil {
		t.Fatalf("ReadItemDatabase: %v", err)
	}
	seen := itemDatabaseBinaries(opened)
	seen = append(seen, callerBuffers...)
	returned := make([][]byte, 0)
	for n := range got {
		if len(got[n].ImportSource) == 0 && n < len(fresh) {
			t.Fatalf("item %q lost its import provenance", got[n].ID)
		}
		buffers := [][]byte{got[n].Attachment, got[n].ImportSource, got[n].Passkey}
		for m := range got[n].Attachments {
			buffers = append(buffers, got[n].Attachments[m].Content)
		}
		for _, rec := range got[n].Passkeys {
			buffers = append(buffers, rec)
		}
		for _, b := range buffers {
			if len(b) == 0 {
				continue
			}
			if sharesByte(b, seen...) {
				t.Fatalf("item %q: returned buffer aliases the database, the caller or another returned buffer", got[n].ID)
			}
			seen = append(seen, b)
			returned = append(returned, b)
		}
	}
	if len(returned) == 0 {
		t.Fatal("fixture produced no returned binary buffers")
	}
	for _, b := range returned {
		clear(b)
	}
	if after := fingerprint(opened); !bytes.Equal(before, after) {
		t.Fatal("clearing returned buffers changed the database")
	}
}

// withImportSource returns a deep copy of items carrying the same provenance so
// a fixture can be reused twice.
func withImportSource(items []Item, source []byte) []Item {
	out := make([]Item, len(items))
	for n := range items {
		out[n] = CloneItem(items[n])
		out[n].ImportSource = append([]byte(nil), source...)
	}
	return out
}

func callerBinaryBuffers(items []Item) [][]byte {
	var out [][]byte
	for n := range items {
		out = append(out, items[n].Attachment, items[n].ImportSource, items[n].Passkey)
		for m := range items[n].Attachments {
			out = append(out, items[n].Attachments[m].Content)
		}
	}
	return out
}

// itemDatabaseBinaryFixture returns a v2 login and the v2 document (both carry
// attachment binaries) with import provenance.
func itemDatabaseBinaryFixture(t *testing.T) []Item {
	t.Helper()
	fixture := v2FixtureItems(t)
	return withImportSource([]Item{CloneItem(fixture[0]), CloneItem(fixture[3])}, []byte(`{"source":"synthetic"}`))
}
