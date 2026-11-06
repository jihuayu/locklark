package onepux

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

const mappedLogin = `{"uuid":"same","categoryUuid":"001","state":"active","createdAt":123,"overview":{"title":"private-title","url":"https://example.test/login"},"details":{"loginFields":[{"id":"u","name":"email","designation":"username","fieldType":"T","value":"private-user"},{"id":"p","designation":"password","fieldType":"P","value":"private-pass"}]}}`

func TestMapLoginsScopesAndSourceRetention(t *testing.T) {
	second := strings.Replace(strings.Replace(mappedLogin, `"active"`, `"archived"`, 1), `"same"`, `"second"`, 1)
	data := `{"accounts":[{"attrs":{"uuid":"a","name":"private-account"},"vaults":[{"attrs":{"uuid":"v1"},"items":[` + mappedLogin + `,` + second + `]}]}]}`
	raw := pack(t, attributes, data)
	before := bytes.Clone(raw)
	mapped, err := MapLogins(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(mapped.Items) != 2 || mapped.Items[0].ID == mapped.Items[1].ID || mapped.Items[1].State != "archived" || !bytes.Equal(raw, before) {
		t.Fatal("scope/state/source changed")
	}
	for _, item := range mapped.Items {
		if item.Username != "private-user" || item.Password != "private-pass" || item.URL != "https://example.test/login" || !bytes.Contains(item.ImportSource, []byte("private-account")) || !bytes.Contains(item.ImportSource, []byte(`"createdAt":123`)) {
			t.Fatal("mapping lost data")
		}
	}
	again, err := MapLogins(raw)
	if err != nil || !reflect.DeepEqual(mapped, again) {
		t.Fatal("mapping is not deterministic")
	}
	for _, change := range [][2]string{{`"uuid":"v1"`, `"uuid":"v2"`}, {`"uuid":"a"`, `"uuid":"b"`}} {
		other, err := MapLogins(pack(t, attributes, strings.Replace(data, change[0], change[1], 1)))
		if err != nil || other.Items[0].ID == mapped.Items[0].ID {
			t.Fatal("source scope collapsed", err)
		}
	}
	report, _ := json.Marshal(mapped.Report)
	if strings.Contains(string(report), "private-") || mapped.Report.Items != 2 || mapped.Report.SourceDigest != "" {
		t.Fatal("unsafe report")
	}
}

func TestMapLoginsCapacityAndVaultSeparation(t *testing.T) {
	build := func(n int) string {
		items := make([]string, n)
		for i := range items {
			items[i] = strings.Replace(mappedLogin, `"same"`, fmt.Sprintf(`"id%d"`, i), 1)
		}
		return `{"accounts":[{"attrs":{"uuid":"a"},"vaults":[{"attrs":{"uuid":"v"},"items":[` + strings.Join(items, ",") + `]}]}]}`
	}
	if mapped, err := MapLogins(pack(t, attributes, build(256))); err != nil || len(mapped.Items) != 256 {
		t.Fatal("exact item limit rejected", err)
	}
	if _, err := MapLogins(pack(t, attributes, build(257))); !errors.Is(err, ErrLimit) {
		t.Fatal("item limit bypass", err)
	}
	data := strings.Replace(build(1), `"vaults":[`, `"vaults":[{"attrs":{"uuid":"second"},"items":[]},`, 1)
	if _, err := MapLogins(pack(t, attributes, data)); !errors.Is(err, ErrUnsupported) {
		t.Fatal("multiple vaults flattened", err)
	}
	data = strings.Replace(build(1), `"accounts":[`, `"accounts":[{"attrs":{"uuid":"second"},"vaults":[]},`, 1)
	if _, err := MapLogins(pack(t, attributes, data)); !errors.Is(err, ErrUnsupported) {
		t.Fatal("multiple accounts flattened", err)
	}
}

func TestMapLoginsRefusesPartialOrAmbiguousMapping(t *testing.T) {
	for _, replacement := range []struct{ old, new string }{
		{`"001"`, `"114"`}, {`"active"`, `"future"`},
		{`"fieldType":"P"`, `"fieldType":"T"`},
		{`"designation":"username"`, `"designation":"password"`},
		{`"private-pass"`, `null`},
		{`"loginFields":[`, `"notesPlain":null,"loginFields":[`},
		{`"loginFields":[`, `"sections":[{"fields":[]}],"loginFields":[`},
		{`"loginFields":[`, `"passwordHistory":[{"value":"old"}],"loginFields":[`},
		{`"title":"private-title"`, `"title":"private-title","urls":[{"url":"https://other.test"}]`},
		{`"categoryUuid":`, `"unknown":"private-extra","categoryUuid":`},
		{`"categoryUuid":`, `"favIndex":1,"categoryUuid":`},
		{`"title":"private-title"`, `"title":"private-title","tags":["private-tag"]`},
		{`https://example.test/login`, `http://example.test/login`},
		{`private-title`, "private-\u202etitle"},
		{`private-title`, "private-\u2066title"},
		{`private-title`, "private-\u200dtitle"},
		{`private-title`, "private-\u0085title"},
	} {
		t.Run(replacement.new, func(t *testing.T) {
			item := strings.Replace(mappedLogin, replacement.old, replacement.new, 1)
			data := `{"accounts":[{"attrs":{"uuid":"a"},"vaults":[{"attrs":{"uuid":"v"},"items":[` + strings.Replace(mappedLogin, `"same"`, `"first"`, 1) + `,` + item + `]}]}]}`
			got, err := MapLogins(pack(t, attributes, data))
			if err == nil || !reflect.DeepEqual(got, MappedLogins{}) || strings.Contains(err.Error(), "private") {
				t.Fatal("partial/ambiguous import accepted", err)
			}
		})
	}
	data := `{"accounts":[{"attrs":{"uuid":"a"},"vaults":[{"attrs":{"uuid":"v"},"items":[` + mappedLogin + `]}]}]}`
	if _, err := MapLogins(pack(t, attributes, data, entry{"files/extra", "secret"})); !errors.Is(err, ErrUnsupported) {
		t.Fatal("attachment ignored", err)
	}
}
