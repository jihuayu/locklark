package onepux

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestLoginNotesMappingPreservesMultiline(t *testing.T) {
	notes := "  first line\n备注\t🙂\nlast line  "
	encoded, _ := json.Marshal(notes)
	item := strings.Replace(mappedLogin, `"loginFields":`, `"notesPlain":`+string(encoded)+`,"loginFields":`, 1)
	data := `{"accounts":[{"attrs":{"uuid":"a"},"vaults":[{"attrs":{"uuid":"v"},"items":[` + item + `]}]}]}`
	mapped, e := MapLogins(pack(t, attributes, data))
	if e != nil {
		t.Fatal("multiline login notes were refused")
	}
	raw, _ := json.Marshal(mapped.Items[0])
	var fields map[string]any
	if json.Unmarshal(raw, &fields) != nil || fields["Notes"] != notes || mapped.Report.Profile != "login-notes-v2" {
		t.Fatal("mapping lost login notes or profile")
	}
}

func TestLoginNotesLimitsTypesAndStableSourceIdentity(t *testing.T) {
	mapValue := func(value string) (MappedLogins, error) {
		item := mappedLogin
		if value != "" {
			item = strings.Replace(item, `"loginFields":`, `"notesPlain":`+value+`,"loginFields":`, 1)
		}
		return MapLogins(pack(t, attributes, `{"accounts":[{"attrs":{"uuid":"a"},"vaults":[{"attrs":{"uuid":"v"},"items":[`+item+`]}]}]}`))
	}
	old, e := mapValue("")
	if e != nil {
		t.Fatal(e)
	}
	for _, body := range []string{"", strings.Repeat("界", (64<<10)/3) + "x"} {
		raw, _ := json.Marshal(body)
		got, e := mapValue(string(raw))
		if e != nil || got.Items[0].Notes != body || got.Items[0].ID != old.Items[0].ID {
			t.Fatal("notes boundary or original source identity changed")
		}
	}
	oversize, _ := json.Marshal(strings.Repeat("x", (64<<10)+1))
	for _, raw := range []string{"null", "false", "3", "[]", "{}", string(oversize), `"bad\u0000"`} {
		got, e := mapValue(raw)
		if e == nil || len(got.Items) != 0 || strings.Contains(e.Error(), "bad") {
			t.Fatal("invalid notes type/value accepted or exposed")
		}
	}
}
