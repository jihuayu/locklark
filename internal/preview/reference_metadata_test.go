package preview

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jihuayu/locklark/internal/reference"
	"github.com/jihuayu/locklark/internal/vault"
)

func nativeReferenceFixture(t testing.TB) (nativeMeta, []vault.Item, string) {
	t.Helper()
	archive, err := fixtureArchive()
	if err != nil {
		t.Fatal(err)
	}
	p := payload{Archive: archive}
	if err = projectFixture(&p); err != nil {
		t.Fatal(err)
	}
	return nativeMeta{Version: 1, Layout: p.layout}, p.items, strings.Repeat("a", 128)
}
func nativeReferenceJSON(t testing.TB, m nativeMeta) []byte {
	t.Helper()
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestFixtureReferencePreservesSourceIdentities(t *testing.T) {
	m, items, pin := nativeReferenceFixture(t)
	catalog, err := ProjectFixtureReferenceMetadata(nativeReferenceJSON(t, m), items, pin)
	if err != nil {
		t.Fatal("source metadata projection failed", err)
	}
	if len(catalog) != 1 || catalog[0].ID != "synthetic-vault" || catalog[0].Name != "演练" || len(catalog[0].Items) != 2 {
		t.Fatal("source vault or item identities lost")
	}
	for _, raw := range []string{FixtureRef, "op://synthetic-vault/login-sample/ops/TOTP", "op://synthetic-vault/login-sample/otp-demo"} {
		got, e := reference.Resolve(raw, catalog)
		want := reference.Target{VaultID: "synthetic-vault", ItemID: "login-sample", SectionID: "ops", FieldID: "otp-demo", Revision: fixtureReferenceRevision + pin}
		if e != nil || got != want {
			t.Fatal("source field identity was replaced", got, e)
		}
	}
	for _, raw := range []string{"op://synthetic-vault/login-sample/otp", "op://synthetic-vault/login-sample/username", "op://synthetic-vault/document-sample/password"} {
		if got, e := reference.Resolve(raw, catalog); !errors.Is(e, reference.ErrNotFound) || got != (reference.Target{}) {
			t.Fatal("personal or document field fallback appeared", got, e)
		}
	}
	if got, e := reference.Resolve("op://synthetic-vault/login-sample/password", catalog); e != nil || got.FieldID != "password" || got.SectionID != "" {
		t.Fatal("source password identity lost", got, e)
	}
	raw, _ := json.Marshal(catalog)
	for _, marker := range []string{items[0].Password, items[0].OTP, items[1].Filename} {
		if marker != "" && bytes.Contains(raw, []byte(marker)) {
			t.Fatal("source values leaked into metadata")
		}
	}
}

func TestFixtureReferenceIndependentOfValuesAndItemOrder(t *testing.T) {
	m, items, pin := nativeReferenceFixture(t)
	before, err := ProjectFixtureReferenceMetadata(nativeReferenceJSON(t, m), items, pin)
	if err != nil {
		t.Fatal(err)
	}
	items[0].Password = "different-password"
	items[0].OTP = "different-otp"
	items[0].Username = "not-a-source-field"
	items[1].Filename = "other-file"
	items[1].Attachment = []byte("different-bytes")
	after, err := ProjectFixtureReferenceMetadata(nativeReferenceJSON(t, m), items, pin)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("native values changed source metadata", err)
	}
	items[0], items[1] = items[1], items[0]
	catalog, err := ProjectFixtureReferenceMetadata(nativeReferenceJSON(t, m), items, pin)
	if err != nil {
		t.Fatal(err)
	}
	if target, e := reference.Resolve(FixtureRef, catalog); e != nil || target.ItemID != "login-sample" || target.FieldID != "otp-demo" {
		t.Fatal("native item order changed source binding", e)
	}
	var root map[string]any
	if err = json.Unmarshal(exportData, &root); err != nil {
		t.Fatal(err)
	}
	sourceItems := root["accounts"].([]any)[0].(map[string]any)["vaults"].([]any)[0].(map[string]any)["items"].([]any)
	sourceItems[0], sourceItems[1] = sourceItems[1], sourceItems[0]
	raw, _ := json.Marshal(root)
	m.Layout, _, err = splitFixture(raw)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err = ProjectFixtureReferenceMetadata(nativeReferenceJSON(t, m), items, pin)
	if err != nil {
		t.Fatal(err)
	}
	if target, e := reference.Resolve(FixtureRef, catalog); e != nil || target.ItemID != "login-sample" || target.FieldID != "otp-demo" {
		t.Fatal("source item order changed source binding", e)
	}
}

func TestFixtureReferenceRetainsDocumentAmbiguity(t *testing.T) {
	m, items, pin := nativeReferenceFixture(t)
	items[0].Title = "same"
	items[1].Title = "same"
	catalog, err := ProjectFixtureReferenceMetadata(nativeReferenceJSON(t, m), items, pin)
	if err != nil {
		t.Fatal(err)
	}
	if target, e := reference.Resolve("op://synthetic-vault/same/ops/otp-demo", catalog); !errors.Is(e, reference.ErrAmbiguous) || target != (reference.Target{}) {
		t.Fatal("document was skipped during ambiguity checks", e)
	}
}

func TestFixtureReferenceRejectsProfileAndRebinding(t *testing.T) {
	for _, problem := range []string{"version", "nil-layout", "missing-slot", "swap-slots", "duplicate-slot", "changed-field-id", "duplicate-key", "extra-source-field", "archived", "missing-item", "duplicate-item", "wrong-kind", "bad-pin", "control-title", "unknown-meta-key", "duplicate-version", "trailing-json"} {
		t.Run(problem, func(t *testing.T) {
			m, items, pin := nativeReferenceFixture(t)
			want := error(ErrFixtureReferenceMetadata)
			switch problem {
			case "version":
				m.Version = 2
				want = ErrFixtureReferenceProfile
			case "nil-layout":
				m.Layout = nil
				want = ErrFixtureReferenceProfile
			case "missing-slot":
				m.Layout.Slots = m.Layout.Slots[:5]
			case "swap-slots":
				m.Layout.Slots[0], m.Layout.Slots[1] = m.Layout.Slots[1], m.Layout.Slots[0]
			case "duplicate-slot":
				m.Layout.Slots[1] = m.Layout.Slots[0]
			case "changed-field-id", "duplicate-key", "extra-source-field", "archived":
				old, new := "\"id\":\"otp-demo\"", "\"id\":\"other-field\""
				if problem == "duplicate-key" {
					old, new = "\"uuid\":\"login-sample\"", "\"uuid\":\"ignored\",\"uuid\":\"login-sample\""
				}
				if problem == "extra-source-field" {
					old, new = "\"details\":{", "\"details\":{\"notesPlain\":\"private-marker\","
				}
				if problem == "archived" {
					old, new = "\"state\":\"active\"", "\"state\":\"archived\""
				}
				changed := false
				for i, part := range m.Layout.Parts {
					p := strings.Replace(part, old, new, 1)
					if p != part {
						changed = true
						m.Layout.Parts[i] = p
						break
					}
				}
				if !changed {
					t.Fatal("invalid mutation fixture")
				}
			case "missing-item":
				items = items[:1]
			case "duplicate-item":
				items[1] = items[0]
			case "wrong-kind":
				items[0].Kind = "document"
			case "bad-pin":
				pin = strings.Repeat("a", 64)
			case "control-title":
				items[0].Title = "title\nInjected"
				want = reference.ErrCatalog
			}
			raw := nativeReferenceJSON(t, m)
			if problem == "unknown-meta-key" {
				raw = append(bytes.TrimSuffix(raw, []byte("}")), []byte(`,"Future":true}`)...)
			}
			if problem == "duplicate-version" {
				raw = append(bytes.TrimSuffix(raw, []byte("}")), []byte(`,"version":1}`)...)
			}
			if problem == "trailing-json" {
				raw = append(raw, []byte(` {}`)...)
			}
			got, err := ProjectFixtureReferenceMetadata(raw, items, pin)
			if !errors.Is(err, want) || got != nil {
				t.Fatal("unsupported or rebound metadata accepted", err)
			}
			if err != nil && (strings.Contains(err.Error(), "private-marker") || strings.Contains(err.Error(), "Injected")) {
				t.Fatal("projection error echoed private source metadata")
			}
		})
	}
}

func TestFixtureReferenceBoundsMetadata(t *testing.T) {
	m, items, pin := nativeReferenceFixture(t)
	for _, raw := range [][]byte{bytes.Repeat([]byte{' '}, vault.MaxPayload+1), []byte(`{"nested":` + strings.Repeat("[", 40) + `0` + strings.Repeat("]", 40) + `}`)} {
		if got, err := ProjectFixtureReferenceMetadata(raw, items, pin); !errors.Is(err, reference.ErrLimit) || got != nil {
			t.Fatal("unbounded metadata accepted", err)
		}
	}
	m.Layout.Parts[0] = strings.Repeat(" ", 1<<20) + m.Layout.Parts[0]
	if got, err := ProjectFixtureReferenceMetadata(nativeReferenceJSON(t, m), items, pin); !errors.Is(err, reference.ErrLimit) || got != nil {
		t.Fatal("source layout capacity not enforced", err)
	}
}

func TestFixtureReferenceBindsVerifiedSnapshotAndAudit(t *testing.T) {
	root := filepath.Join(t.TempDir(), "demo")
	if err := Create(root, "reference-acceptance", "validate source metadata"); err != nil {
		t.Fatal(err)
	}
	device := filepath.Join(root, "clients", "B")
	var previous reference.Target
	for _, epoch := range []struct {
		number uint64
		path   string
	}{{2, "epoch-2"}, {3, "epoch-3"}} {
		bundle := filepath.Join(root, "share", epoch.path)
		p, err := readPayload(bundle, device, epoch.number)
		if err != nil {
			t.Fatal(err)
		}
		m := nativeMeta{1, p.layout, p.Events, p.Proofs}
		catalog, err := ProjectFixtureReferenceMetadata(nativeReferenceJSON(t, m), p.items, p.pin)
		if err != nil {
			t.Fatal(err)
		}
		target, err := reference.Resolve(FixtureRef, catalog)
		if err != nil {
			t.Fatal(err)
		}
		if target.Revision != fixtureReferenceRevision+p.pin {
			t.Fatal("reference did not bind the authenticated snapshot signature")
		}
		if previous.FieldID != "" && (target.ItemID != previous.ItemID || target.SectionID != previous.SectionID || target.FieldID != previous.FieldID || target.Revision == previous.Revision) {
			t.Fatal("source identity or snapshot version lost across rename")
		}
		previous = target
		report, err := VerifyAudit(bundle, device, epoch.number, filepath.Join(root, "witness", epoch.path+".json"))
		if err != nil || report.Events != len(p.Events) || report.Witnessed != len(p.Events) {
			t.Fatal("source audit/checkpoint chain not verified", err)
		}
	}
}

func FuzzFixtureReferenceMetadata(f *testing.F) {
	m, items, pin := nativeReferenceFixture(f)
	raw := nativeReferenceJSON(f, m)
	f.Add(raw)
	f.Add([]byte(`{"Version":2,"Layout":null}`))
	f.Add([]byte(`{"Version":1,"version":1,"Layout":null}`))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		catalog, err := ProjectFixtureReferenceMetadata(data, items, pin)
		if err != nil {
			if catalog != nil {
				t.Fatal("failed projection returned partial metadata")
			}
			return
		}
		if len(catalog) != 1 || catalog[0].ID != "synthetic-vault" || len(catalog[0].Items) != 2 {
			t.Fatal("projection invented a source identity")
		}
		target, err := reference.Resolve(FixtureRef, catalog)
		want := reference.Target{VaultID: "synthetic-vault", ItemID: "login-sample", SectionID: "ops", FieldID: "otp-demo", Revision: fixtureReferenceRevision + pin}
		if err != nil || target != want {
			t.Fatal("source binding changed under metadata mutation", err)
		}
		changed := append([]vault.Item(nil), items...)
		changed[0].Password, changed[0].OTP = "different-password", "different-otp"
		changed[1].Filename, changed[1].Attachment = "other-file", nil
		again, err := ProjectFixtureReferenceMetadata(data, changed, pin)
		if err != nil || !reflect.DeepEqual(catalog, again) {
			t.Fatal("projection depended on private native values")
		}
	})
}
