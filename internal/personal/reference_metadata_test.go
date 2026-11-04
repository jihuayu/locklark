package personal

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

func referenceFixture() ([]vault.Item, map[string]string) {
	items := []vault.Item{
		{ID: strings.Repeat("a", 32), Kind: "login", Title: "Login", Username: "synthetic-user-marker", Password: "synthetic-password-marker", OTP: "synthetic-otp-marker"},
		{ID: strings.Repeat("b", 32), Kind: "document", Title: "Document", Filename: "synthetic-filename-marker", Attachment: []byte("synthetic-attachment-marker"), AttachmentProtected: true},
	}
	return items, map[string]string{items[0].ID: strings.Repeat("1", 64), items[1].ID: strings.Repeat("2", 64)}
}

func TestProjectReferenceMetadata(t *testing.T) {
	items, revs := referenceFixture()
	before, _ := json.Marshal(items)
	catalog, err := ProjectReferenceMetadata([]byte(schema), "personal-vault", "Work", items, revs)
	if err != nil {
		t.Fatal("valid native metadata projection failed", err)
	}
	if len(catalog) != 1 || len(catalog[0].Items) != 2 || len(catalog[0].Items[0].Fields) != 3 || len(catalog[0].Items[1].Fields) != 0 {
		t.Fatal("native item identities or fields lost")
	}
	for _, field := range []string{"username", "password", "otp"} {
		got, e := reference.Resolve("op://personal-vault/"+items[0].ID+"/"+field, catalog)
		want := reference.Target{VaultID: "personal-vault", ItemID: items[0].ID, FieldID: field, Revision: revs[items[0].ID]}
		if e != nil || got != want {
			t.Fatal("native field did not bind its source identity and revision", got, e)
		}
	}
	if got, e := reference.Resolve("op://Work/Document/password", catalog); !errors.Is(e, reference.ErrNotFound) || got != (reference.Target{}) {
		t.Fatal("document gained a login field", got, e)
	}
	encoded, _ := json.Marshal(catalog)
	for _, marker := range []string{items[0].Username, items[0].Password, items[0].OTP, items[1].Filename, string(items[1].Attachment)} {
		if bytes.Contains(encoded, []byte(marker)) {
			t.Fatal("projection leaked a field value")
		}
	}
	after, _ := json.Marshal(items)
	if !bytes.Equal(before, after) {
		t.Fatal("projection modified native items")
	}
}

func TestProjectionDoesNotDependOnFieldValues(t *testing.T) {
	items, revs := referenceFixture()
	before, err := ProjectReferenceMetadata([]byte(schema), "personal-vault", "Work", items, revs)
	if err != nil {
		t.Fatal(err)
	}
	items[0].Username = ""
	items[0].Password = ""
	items[0].OTP = ""
	items[1].Filename = "other-file"
	items[1].Attachment = []byte("different synthetic bytes")
	items[1].AttachmentProtected = false
	after, err := ProjectReferenceMetadata([]byte(schema), "personal-vault", "Work", items, revs)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("field contents or presence changed metadata", err)
	}
}

func TestProjectionDoesNotSkipDocumentNameCollision(t *testing.T) {
	items, revs := referenceFixture()
	items[1].Title = items[0].Title
	catalog, err := ProjectReferenceMetadata([]byte(schema), "personal-vault", "Work", items, revs)
	if err != nil {
		t.Fatal(err)
	}
	if got, e := reference.Resolve("op://Work/Login/password", catalog); !errors.Is(e, reference.ErrAmbiguous) || got != (reference.Target{}) {
		t.Fatal("projection skipped the colliding document", got, e)
	}
}

func TestProjectionRejectsIncompleteOrUnsupportedMetadata(t *testing.T) {
	for _, problem := range []string{"nil-items", "missing-revision", "orphan-revision", "non-journal-revision", "bad-id", "duplicate-id", "unknown-kind", "control-title", "long-title", "invalid-vault"} {
		t.Run(problem, func(t *testing.T) {
			items, revs := referenceFixture()
			vaultID := "personal-vault"
			want := error(ErrReferenceMetadata)
			switch problem {
			case "nil-items":
				items = nil
				revs = nil
			case "missing-revision":
				delete(revs, items[0].ID)
			case "orphan-revision":
				revs[strings.Repeat("c", 32)] = strings.Repeat("3", 64)
			case "non-journal-revision":
				revs[items[0].ID] = "caller-claimed-version"
			case "bad-id":
				delete(revs, items[0].ID)
				items[0].ID = "not-a-personal-id"
				revs[items[0].ID] = strings.Repeat("1", 64)
			case "duplicate-id":
				items[1].ID = items[0].ID
			case "unknown-kind":
				items[1].Kind = "custom-category"
			case "control-title":
				items[0].Title = "title\nInjected"
				want = reference.ErrCatalog
			case "long-title":
				items[0].Title = strings.Repeat("x", 1025)
				want = reference.ErrCatalog
			case "invalid-vault":
				vaultID = "caller/unverified"
				want = reference.ErrCatalog
			}
			got, err := ProjectReferenceMetadata([]byte(schema), vaultID, "Work", items, revs)
			if !errors.Is(err, want) || got != nil {
				t.Fatal("bad metadata produced a partial catalog", err)
			}
			if err != nil && (strings.Contains(err.Error(), "caller") || strings.Contains(err.Error(), "Injected")) {
				t.Fatal("projection error echoed unverified metadata")
			}
		})
	}
	items, revs := referenceFixture()
	for _, profile := range [][]byte{nil, []byte(schema + " "), []byte("locklark/personal/items/v2"), []byte(`{"Version":1,"Layout":"imported-sections"}`)} {
		if got, err := ProjectReferenceMetadata(profile, "personal-vault", "Work", items, revs); !errors.Is(err, ErrReferenceProfile) || got != nil {
			t.Fatal("unknown layout was relabelled as built-in fields", err)
		}
	}
	if got, err := ProjectReferenceMetadata([]byte(schema), "personal-vault", "Work", make([]vault.Item, 257), nil); !errors.Is(err, reference.ErrLimit) || got != nil {
		t.Fatal("native item limit not enforced", err)
	}
}

func TestProjectionAcceptsEmptyAndUnicodeNamedVault(t *testing.T) {
	got, err := ProjectReferenceMetadata([]byte(schema), "personal-vault", "个人", []vault.Item{}, map[string]string{})
	if err != nil || len(got) != 1 || len(got[0].Items) != 0 {
		t.Fatal("empty native vault could not project", err)
	}
	items, revs := referenceFixture()
	items[0].Title = "中文登录"
	got, err = ProjectReferenceMetadata([]byte(schema), "personal-vault", "个人", items, revs)
	if err != nil {
		t.Fatal(err)
	}
	if target, e := reference.Resolve("op://personal-vault/"+items[0].ID+"/password", got); e != nil || target.ItemID != items[0].ID {
		t.Fatal("Unicode title broke stable ID lookup", e)
	}
}

func TestProjectionTracksRealPersonalAuditRevision(t *testing.T) {
	path, pw, key := filepath.Join(t.TempDir(), "source.ll"), "synthetic-master", bytes.Repeat([]byte{4}, 16)
	if err := Create(path, pw, key); err != nil {
		t.Fatal(err)
	}
	id, err := AddLogin(path, pw, key, "Original Login", "synthetic-user", "synthetic-private-password")
	if err != nil {
		t.Fatal(err)
	}
	var previous reference.Target
	project := func(file string, secret []byte) reference.Target {
		t.Helper()
		rows, e := List(file, pw, secret)
		if e != nil {
			t.Fatal(e)
		}
		revs := map[string]string{}
		for _, row := range rows {
			revs[row.ID] = row.Revision
		}
		items := readStoredItems(t, file, pw, secret)
		catalog, e := ProjectReferenceMetadata([]byte(schema), "personal-vault", "Work", items, revs)
		if e != nil {
			t.Fatal(e)
		}
		target, e := reference.Resolve("op://personal-vault/"+id+"/password", catalog)
		if e != nil {
			t.Fatal(e)
		}
		bound, e := BindReferenceMetadata([]byte(schema), "personal-vault", "Work", items, revs, target)
		if e != nil || bound.Target != target || bound.Slot != reference.SlotPassword || bound.Type != reference.TypePassword {
			t.Fatal("signed journal target did not bind to password slot", e)
		}
		if previous.FieldID != "" {
			if stale, e := BindReferenceMetadata([]byte(schema), "personal-vault", "Work", items, revs, previous); !errors.Is(e, reference.ErrStale) || stale != (reference.Binding{}) {
				t.Fatal("old journal target rebound after rename or restore", e)
			}
		}
		previous = target
		return target
	}
	before := project(path, key)
	revision, err := EditLogin(path, pw, key, Edit{ID: id, Revision: before.Revision, Field: "title", Value: "Renamed Login"})
	if err != nil {
		t.Fatal(err)
	}
	after := project(path, key)
	if after.ItemID != before.ItemID || after.FieldID != before.FieldID || after.Revision != revision || after.Revision == before.Revision {
		t.Fatal("native rename lost field identity or current revision")
	}
	events, err := Audit(path, pw, key)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, event := range events {
		if event.Action == "item.edit.title" && event.Item == id && event.hash() == after.Revision {
			found = true
		}
	}
	if !found {
		t.Fatal("projected revision was not the signed source edit event")
	}
	raw, _ := json.Marshal(events)
	if bytes.Contains(raw, []byte("synthetic-private-password")) || bytes.Contains(raw, []byte("synthetic-user")) {
		t.Fatal("source audit leaked field values")
	}
	archive, restored := filepath.Join(t.TempDir(), "backup.llb"), filepath.Join(t.TempDir(), "restored.ll")
	material, err := Backup(path, archive, pw, key)
	if err != nil {
		t.Fatal(err)
	}
	fresh := bytes.Repeat([]byte{5}, 16)
	if err = Restore(archive, restored, pw, key, material, fresh); err != nil {
		t.Fatal(err)
	}
	recovered := project(restored, fresh)
	if recovered.ItemID != after.ItemID || recovered.FieldID != after.FieldID || recovered.Revision == after.Revision {
		t.Fatal("restored projection lost field identity or reused the old journal revision")
	}
	events, err = Audit(restored, pw, fresh)
	if err != nil {
		t.Fatal(err)
	}
	found = false
	for _, event := range events {
		if event.Action == "item.restore" && event.Item == id && event.hash() == recovered.Revision {
			found = true
		}
	}
	if !found {
		t.Fatal("recovered projection was not bound to its new signed journal")
	}
}

func FuzzProjectReferenceMetadata(f *testing.F) {
	f.Add(schema, strings.Repeat("a", 32), strings.Repeat("1", 64), "login", "Login")
	f.Add(schema, strings.Repeat("b", 32), strings.Repeat("2", 64), "document", "Document")
	f.Add("unknown-profile", "unknown-id", "unknown-revision", "custom", "Title")
	f.Fuzz(func(t *testing.T, profile, id, revision, kind, title string) {
		it := vault.Item{ID: id, Kind: kind, Title: title}
		if kind == "document" {
			it.Filename, it.Attachment = "fixture-file", []byte("fixture-bytes")
		} else {
			it.Username, it.Password, it.OTP = "fixture-user", "fixture-password", "fixture-otp"
		}
		items := []vault.Item{it}
		revs := map[string]string{id: revision}
		catalog, err := ProjectReferenceMetadata([]byte(profile), "personal-vault", "Work", items, revs)
		if err != nil {
			if catalog != nil {
				t.Fatal("projection refused with partial metadata")
			}
			return
		}
		if len(catalog) != 1 || len(catalog[0].Items) != 1 || catalog[0].Items[0].ID != id || catalog[0].Items[0].Name != title || catalog[0].Items[0].Revision != revision {
			t.Fatal("projection changed source metadata identity")
		}
		if kind == "document" {
			items[0].Filename, items[0].Attachment = "other-file", nil
		} else {
			items[0].Username, items[0].Password, items[0].OTP = "", "different-password", ""
		}
		again, err := ProjectReferenceMetadata([]byte(profile), "personal-vault", "Work", items, revs)
		if err != nil || !reflect.DeepEqual(catalog, again) {
			t.Fatal("field values changed metadata projection")
		}
	})
}
