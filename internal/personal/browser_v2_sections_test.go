package personal

import (
	"testing"

	"github.com/jihuayu/locklark/internal/vault"
)

func inputSectionsFixture() []vault.ItemSection {
	return []vault.ItemSection{{ID: "sec1", Title: "Recovery", Fields: []vault.CustomField{
		{ID: "f-secret", Label: "Code", Type: vault.FieldTypeConcealed, Value: "top-secret", Protected: true},
		{ID: "f-otp", Label: "Seed", Type: vault.FieldTypeOTP, Value: "JBSWY3DPEHPK3PXP", Protected: true},
		{ID: "f-plain", Label: "Hint", Type: vault.FieldTypeText, Value: "visible"},
	}}}
}

func inputField(sectionID, fieldID string, typ string, concealed bool, value *string) V2SectionInput {
	in := V2SectionInput{ID: sectionID, Title: "Recovery"}
	in.Fields = append(in.Fields, V2CustomFieldInput{ID: fieldID, Label: fieldID, Type: typ, Concealed: concealed, Value: value})
	return in
}

func strPtr(value string) *string { return &value }

func findInputField(t *testing.T, sections []vault.ItemSection, sectionID, fieldID string) (vault.CustomField, bool) {
	t.Helper()
	field, ok := findPreviousField(sections, sectionID, fieldID)
	return field, ok
}

func TestV2SectionsFromInputKeepsSecretClassification(t *testing.T) {
	previous := inputSectionsFixture()

	// An omitted value preserves both the durable value and its classification.
	out, e := v2SectionsFromInput(previous, []V2SectionInput{inputField("sec1", "f-secret", "concealed", true, nil)})
	if e != nil {
		t.Fatalf("omitted value refused: %v", e)
	}
	if field, ok := findInputField(t, out, "sec1", "f-secret"); !ok || field.Value != "top-secret" || !field.Protected || field.Type != vault.FieldTypeConcealed {
		t.Fatalf("omitted value changed the secret: %#v", field)
	}

	// A secret field may never be reclassified as plaintext.
	for _, tc := range []struct {
		name    string
		section V2SectionInput
	}{
		{"explicit text type", inputField("sec1", "f-secret", "text", false, nil)},
		{"empty type", inputField("sec1", "f-secret", "", false, nil)},
		{"otp to text", inputField("sec1", "f-otp", "text", false, strPtr(""))},
		{"otp to empty type", inputField("sec1", "f-otp", "", false, nil)},
	} {
		if _, e := v2SectionsFromInput(previous, []V2SectionInput{tc.section}); e == nil {
			t.Fatalf("%s: secret classification downgrade accepted", tc.name)
		}
	}

	// An omitted value for a stable id that does not exist is refused.
	if _, e := v2SectionsFromInput(previous, []V2SectionInput{inputField("sec1", "f-new", "", false, nil)}); e == nil {
		t.Fatal("omitted value for an unknown field accepted")
	}

	// A masked echo of an explicit empty value keeps the secret.
	out, e = v2SectionsFromInput(previous, []V2SectionInput{inputField("sec1", "f-secret", "concealed", true, strPtr(""))})
	if e != nil {
		t.Fatalf("masked echo refused: %v", e)
	}
	if field, _ := findInputField(t, out, "sec1", "f-secret"); field.Value != "top-secret" {
		t.Fatalf("masked echo destroyed the secret: %#v", field)
	}

	// An explicit new value replaces it.
	out, e = v2SectionsFromInput(previous, []V2SectionInput{inputField("sec1", "f-secret", "concealed", true, strPtr("rotated"))})
	if e != nil {
		t.Fatalf("explicit replacement refused: %v", e)
	}
	if field, _ := findInputField(t, out, "sec1", "f-secret"); field.Value != "rotated" || !field.Protected {
		t.Fatalf("explicit replacement failed: %#v", field)
	}

	// Omitted sections preserve every previous section.
	if out, e := v2SectionsFromInput(previous, nil); e != nil || len(out) != 1 || len(out[0].Fields) != 3 {
		t.Fatalf("omitted sections did not preserve: %#v %v", out, e)
	}

	// A supplied section removes fields it does not list.
	out, e = v2SectionsFromInput(previous, []V2SectionInput{{ID: "sec1", Title: "Recovery", Fields: []V2CustomFieldInput{{ID: "f-plain", Label: "Hint", Type: "text", Value: strPtr("visible")}}}})
	if e != nil {
		t.Fatalf("supplied section refused: %v", e)
	}
	if len(out) != 1 || len(out[0].Fields) != 1 || out[0].Fields[0].ID != "f-plain" {
		t.Fatalf("supplied section did not replace the structure: %#v", out)
	}
}
