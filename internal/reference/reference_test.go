package reference

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want Reference
	}{
		{"op://Work/GitHub/password", Reference{"Work", "GitHub", "", "password"}},
		{"OP://Work Space/API Login/Access Keys/client_secret", Reference{"Work Space", "API Login", "Access Keys", "client_secret"}},
		{"op://v-1/i_2/s.3/f-4", Reference{"v-1", "i_2", "s.3", "f-4"}},
		{"op://v/i/../field", Reference{"v", "i", "..", "field"}},
	} {
		got, err := Parse(tc.raw)
		if err != nil || got != tc.want {
			t.Errorf("Parse(%q) = %#v, %v", tc.raw, got, err)
		}
	}
}

func TestParseRejectsUnsupportedOrMalformedInput(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want error
	}{
		{"", ErrInvalid}, {"https://v/i/f", ErrInvalid}, {" op://v/i/f", ErrInvalid},
		{"op://v/i", ErrInvalid}, {"op://v/i/f/extra/segment", ErrInvalid},
		{"op:///i/f", ErrInvalid}, {"op://v//f", ErrInvalid}, {"op://v/i/", ErrInvalid},
		{"op://v/i/ /f", ErrInvalid}, {"op://v/i/f\n", ErrInvalid}, {"op://v/i/f\x00", ErrInvalid},
		{"op://v/i/a\tb", ErrInvalid}, {"op://v/i/f#fragment", ErrInvalid},
		{"op://v/i/p%61ssword", ErrInvalid}, {"op://v/i/a%2Fb", ErrInvalid},
		{"op://v/i/a+b", ErrInvalid}, {"op://user@host/i/f", ErrInvalid},
		{"op://工作/i/f", ErrInvalid}, {"op://v/i/\xff", ErrInvalid},
		{"op://v/i/f?", ErrUnsupported}, {"op://v/i/f?attribute=otp", ErrUnsupported},
		{"op://v/i/f?attr=type&attr=value", ErrUnsupported},
		{"op://v/i/" + strings.Repeat("x", 257), ErrLimit},
		{strings.Repeat("x", MaxReference+1), ErrLimit},
	} {
		got, err := Parse(tc.raw)
		if !errors.Is(err, tc.want) || got != (Reference{}) {
			t.Errorf("Parse(%q): %#v, %v; want %v", tc.raw, got, err, tc.want)
		}
		if err != nil && strings.Contains(err.Error(), tc.raw) && tc.raw != "" {
			t.Fatal("error echoed untrusted reference")
		}
	}
}

func catalog() []Vault {
	return []Vault{{ID: "vault-1", Name: "Work", Items: []Item{{ID: "item-1", Name: "GitHub", Revision: "revision-7",
		Fields:   []Field{{ID: "field-password", Name: "password"}},
		Sections: []Section{{ID: "section-1", Name: "Access Keys", Fields: []Field{{ID: "field-token", Name: "token"}}}},
	}}}}
}

func TestResolveNamesIDsCaseAndRename(t *testing.T) {
	for _, raw := range []string{"op://Work/GitHub/password", "op://VAULT-1/ITEM-1/FIELD-PASSWORD", "op://work/github/PASSWORD"} {
		got, err := Resolve(raw, catalog())
		want := Target{VaultID: "vault-1", ItemID: "item-1", FieldID: "field-password", Revision: "revision-7"}
		if err != nil || got != want {
			t.Fatalf("Resolve(%q) = %#v, %v", raw, got, err)
		}
	}
	for _, raw := range []string{"op://Work/GitHub/Access Keys/token", "op://vault-1/item-1/section-1/field-token", "op://Work/GitHub/field-token"} {
		got, err := Resolve(raw, catalog())
		want := Target{"vault-1", "item-1", "section-1", "field-token", "revision-7"}
		if err != nil || got != want {
			t.Fatalf("section target = %#v, %v", got, err)
		}
	}
	c := catalog()
	c[0].Name = "Renamed"
	c[0].Items[0].Name = "Renamed Item"
	c[0].Items[0].Sections[0].Name = "Other Section"
	c[0].Items[0].Sections[0].Fields[0].Name = "Other Field"
	c[0].Items[0].Revision = "revision-8"
	got, err := Resolve("op://vault-1/item-1/section-1/field-token", c)
	if err != nil || got.Revision != "revision-8" || got.FieldID != "field-token" {
		t.Fatal("stable ID lost after rename", got, err)
	}
	if got, err = Resolve("op://Work/GitHub/Access Keys/token", c); !errors.Is(err, ErrNotFound) || got != (Target{}) {
		t.Fatal("stale name accepted", got, err)
	}
}

func TestResolveNeverChoosesFirstAmbiguousTarget(t *testing.T) {
	for _, level := range []string{"vault", "item", "section", "field", "across-sections", "id-name-collision"} {
		t.Run(level, func(t *testing.T) {
			c := catalog()
			raw := "op://Work/GitHub/password"
			switch level {
			case "vault":
				c = append(c, Vault{ID: "vault-2", Name: "WORK"})
			case "item":
				c[0].Items = append(c[0].Items, Item{ID: "item-2", Name: "github", Revision: "r2"})
			case "section":
				c[0].Items[0].Sections = append(c[0].Items[0].Sections, Section{ID: "section-2", Name: "access keys"})
				raw = "op://Work/GitHub/Access Keys/token"
			case "field":
				c[0].Items[0].Fields = append(c[0].Items[0].Fields, Field{ID: "field-2", Name: "PASSWORD"})
			case "across-sections":
				c[0].Items[0].Sections[0].Fields = append(c[0].Items[0].Sections[0].Fields, Field{ID: "field-2", Name: "password"})
			case "id-name-collision":
				c[0].Items[0].Fields = append(c[0].Items[0].Fields, Field{ID: "field-2", Name: "FIELD-PASSWORD"})
				raw = "op://Work/GitHub/field-password"
			}
			got, err := Resolve(raw, c)
			if !errors.Is(err, ErrAmbiguous) || got != (Target{}) {
				t.Fatal("ambiguous reference selected a target", got, err)
			}
		})
	}
}

func TestResolveBindsSectionAndRejectsPartialTargets(t *testing.T) {
	for _, raw := range []string{"op://missing/GitHub/password", "op://Work/missing/password", "op://Work/GitHub/missing", "op://Work/GitHub/Access Keys/field-password"} {
		got, err := Resolve(raw, catalog())
		if !errors.Is(err, ErrNotFound) || got != (Target{}) {
			t.Fatal("missing target leaked partial selection", got, err)
		}
	}
}

func TestResolveRejectsInvalidMetadata(t *testing.T) {
	for _, problem := range []string{"vault-id", "item-id", "section-id", "field-id", "revision", "revision-blank", "revision-control", "invalid-id", "label-control"} {
		t.Run(problem, func(t *testing.T) {
			c := catalog()
			switch problem {
			case "vault-id":
				c = append(c, Vault{ID: "VAULT-1", Name: "Other"})
			case "item-id":
				c[0].Items = append(c[0].Items, Item{ID: "ITEM-1", Revision: "r"})
			case "section-id":
				c[0].Items[0].Sections = append(c[0].Items[0].Sections, Section{ID: "SECTION-1"})
			case "field-id":
				c[0].Items[0].Sections[0].Fields = append(c[0].Items[0].Sections[0].Fields, Field{ID: "FIELD-PASSWORD"})
			case "revision":
				c[0].Items[0].Revision = ""
			case "revision-blank":
				c[0].Items[0].Revision = "   "
			case "revision-control":
				c[0].Items[0].Revision = "revision\nInjected"
			case "invalid-id":
				c[0].Items[0].ID = "not/an/id"
			case "label-control":
				c[0].Name = "Work\nInjected"
			}
			got, err := Resolve("op://Work/GitHub/password", c)
			if !errors.Is(err, ErrCatalog) || got != (Target{}) {
				t.Fatal("invalid metadata accepted", got, err)
			}
		})
	}
	c := make([]Vault, MaxObjects+1)
	if got, err := Resolve("op://Work/GitHub/password", c); !errors.Is(err, ErrLimit) || got != (Target{}) {
		t.Fatal("unbounded metadata accepted", got, err)
	}
}

func TestResolveBoundsNestedCatalogAndText(t *testing.T) {
	c := catalog()
	c[0].Items[0].Fields = make([]Field, MaxObjects)
	if got, err := Resolve("op://Work/GitHub/password", c); !errors.Is(err, ErrLimit) || got != (Target{}) {
		t.Fatal("nested metadata escaped the object limit", got, err)
	}
	c = catalog()
	c[0].Items[0].Fields = make([]Field, 1024)
	for j := range c[0].Items[0].Fields {
		c[0].Items[0].Fields[j] = Field{ID: fmt.Sprintf("field-%d", j), Name: strings.Repeat("x", 1024)}
	}
	if got, err := Resolve("op://Work/GitHub/password", c); !errors.Is(err, ErrLimit) || got != (Target{}) {
		t.Fatal("metadata text escaped the aggregate limit", got, err)
	}
}

func TestRejectUnicodeFormatMetadata(t *testing.T) {
	for _, control := range []string{"\u202e", "\u2066", "\u200d", "\U000e0001"} {
		c := catalog()
		c[0].Items[0].Name = "visible" + control + "tail"
		if err := Validate(c); !errors.Is(err, ErrCatalog) {
			t.Fatal("format control accepted")
		}
		if got, err := Resolve("op://vault-1/item-1/field-password", c); !errors.Is(err, ErrCatalog) || got != (Target{}) {
			t.Fatal("format control catalog resolved")
		}
	}
}

func TestUnsupportedNamesUseIDsWithoutUnicodeFolding(t *testing.T) {
	c := catalog()
	c[0].Name = "工作"
	c[0].Items[0].Name = "K"
	c[0].Items[0].Fields[0].Name = "密码"
	got, err := Resolve("op://vault-1/item-1/field-password", c)
	if err != nil || got.FieldID != "field-password" {
		t.Fatal("unsupported names prevented ID lookup", got, err)
	}
	if got, err = Resolve("op://vault-1/K/field-password", c); !errors.Is(err, ErrNotFound) || got != (Target{}) {
		t.Fatal("unsupported Unicode name matched an ASCII selector", got, err)
	}
}

func TestResolvedAuditIdentityOmitsNamesAndUnverifiedInput(t *testing.T) {
	c := catalog()
	marker := "synthetic-private-label"
	c[0].Items[0].Fields[0].Name = marker
	got, err := Resolve("op://Work/GitHub/"+marker, c)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(got)
	if err != nil || strings.Contains(string(b), marker) || strings.Contains(string(b), "GitHub") || strings.Contains(string(b), "op://") {
		t.Fatal("audit projection contained selectors", string(b), err)
	}
	if got, err = Resolve("op://Work/GitHub/unverified-caller-field", c); err == nil || got != (Target{}) || strings.Contains(err.Error(), "unverified-caller-field") {
		t.Fatal("refusal echoed unverified identity", got, err)
	}
}

func FuzzParse(f *testing.F) {
	for _, s := range []string{"op://Work/GitHub/password", "op://v/i/s/f", "op://v/i/%00", "op://v/i/f?attribute=otp", "op://工作/i/f"} {
		f.Add(s)
	}
	c := catalog()
	f.Fuzz(func(t *testing.T, raw string) {
		r, err := Parse(raw)
		target, lookupErr := Resolve(raw, c)
		if lookupErr != nil && target != (Target{}) {
			t.Fatal("failed resolution returned a partial target")
		}
		if lookupErr == nil {
			if target.VaultID != "vault-1" || target.ItemID != "item-1" || target.Revision != "revision-7" ||
				!(target.FieldID == "field-password" && target.SectionID == "" || target.FieldID == "field-token" && target.SectionID == "section-1") {
				t.Fatal("resolution returned an identity outside the metadata snapshot")
			}
		}
		if err != nil {
			if r != (Reference{}) {
				t.Fatal("failed parse returned partial selectors")
			}
			return
		}
		parts := []string{r.Vault, r.Item}
		if r.Section != "" {
			parts = append(parts, r.Section)
		}
		parts = append(parts, r.Field)
		round, e := Parse("op://" + strings.Join(parts, "/"))
		if e != nil || round != r {
			t.Fatal("parsed reference changed meaning on reconstruction")
		}
	})
}
