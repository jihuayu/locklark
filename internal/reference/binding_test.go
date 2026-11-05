package reference

import (
	"errors"
	"strings"
	"testing"
)

func TestCheckTargetUsesCanonicalIDsAndExactRevision(t *testing.T) {
	for _, raw := range []string{"op://WORK/github/PASSWORD", "op://Work/GitHub/Access Keys/token"} {
		c := catalog()
		target, err := Resolve(raw, c)
		if err != nil {
			t.Fatal(err)
		}
		if err = CheckTarget(target, c); err != nil {
			t.Fatal("resolved target was rejected", err)
		}
		// Names may become ambiguous after resolution. Binding is by the exact
		// saved IDs, never a second search by the current display labels.
		c[0].Name = "Renamed"
		c[0].Items[0].Name = "Other"
		c[0].Items = append(c[0].Items, Item{ID: "other-id", Name: "Other", Revision: "revision-7"})
		if err = CheckTarget(target, c); err != nil {
			t.Fatal("display labels changed canonical binding", err)
		}
		c[0].Items[0].Revision = "revision-8"
		if err = CheckTarget(target, c); !errors.Is(err, ErrStale) {
			t.Fatal("old revision was not rejected", err)
		}
	}
}

func TestCheckTargetDoesNotResolveAliasesOrIgnoreSections(t *testing.T) {
	base := Target{"vault-1", "item-1", "section-1", "field-token", "revision-7"}
	for _, tc := range []struct {
		part, value string
	}{
		{"vault", "Work"}, {"item", "GitHub"}, {"section", "Access Keys"}, {"field", "token"},
		{"vault", "VAULT-1"}, {"item", "ITEM-1"}, {"section", "SECTION-1"}, {"field", "FIELD-TOKEN"},
		{"section", ""}, {"field", "field-password"}, {"field", "private-marker\n"},
	} {
		target := base
		switch tc.part {
		case "vault":
			target.VaultID = tc.value
		case "item":
			target.ItemID = tc.value
		case "section":
			target.SectionID = tc.value
		case "field":
			target.FieldID = tc.value
		}
		if err := CheckTarget(target, catalog()); !errors.Is(err, ErrNotFound) || strings.Contains(err.Error(), "private-marker") {
			t.Fatal("alias or mismatched section accepted", err)
		}
	}
	if err := CheckTarget(base, nil); !errors.Is(err, ErrNotFound) {
		t.Fatal("missing catalog accepted", err)
	}
	c := catalog()
	c[0].Items[0].Sections[0].Fields = append(c[0].Items[0].Sections[0].Fields, c[0].Items[0].Sections[0].Fields[0])
	if err := CheckTarget(base, c); !errors.Is(err, ErrCatalog) {
		t.Fatal("binding skipped duplicate metadata validation", err)
	}
	if err := CheckTarget(base, make([]Vault, MaxObjects+1)); !errors.Is(err, ErrLimit) {
		t.Fatal("binding skipped capacity validation", err)
	}
}

func FuzzCheckTarget(f *testing.F) {
	f.Add("vault-1", "item-1", "", "field-password", "revision-7")
	f.Add("vault-1", "item-1", "section-1", "field-token", "revision-7")
	f.Add("Work", "GitHub", "Access Keys", "token", "revision-7")
	f.Add("vault-1", "item-1", "section-1", "field-token", "revision-6")
	f.Fuzz(func(t *testing.T, v, i, s, field, rev string) {
		target := Target{v, i, s, field, rev}
		err := CheckTarget(target, catalog())
		known := v == "vault-1" && i == "item-1" && (s == "" && field == "field-password" || s == "section-1" && field == "field-token")
		if known && rev == "revision-7" {
			if err != nil {
				t.Fatal("canonical current target refused", err)
			}
		} else if known {
			if !errors.Is(err, ErrStale) {
				t.Fatal("revision mismatch accepted", err)
			}
		} else if !errors.Is(err, ErrNotFound) {
			t.Fatal("non-canonical target accepted", err)
		}
	})
}
