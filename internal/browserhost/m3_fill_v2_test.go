package browserhost

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

type m3Output struct{ bytes.Buffer }

func (*m3Output) Close() error { return nil }

func m3DecodeFrame(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	if len(raw) < 4 {
		t.Fatal("short frame")
	}
	size := int(binary.NativeEndian.Uint32(raw))
	if size <= 0 || size > len(raw)-4 {
		t.Fatal("bad frame size")
	}
	var value map[string]any
	if err := json.Unmarshal(raw[4:4+size], &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func m3StringMap(t *testing.T, wire map[string]any, key string) map[string]any {
	t.Helper()
	value, ok := wire[key].(map[string]any)
	if !ok {
		t.Fatalf("%s map missing from response", key)
	}
	return value
}

func TestM3IdentityResponseSerializationAndZeroing(t *testing.T) {
	id := reqID(101)
	identity := map[string]string{
		"full_name":     "Ada Lovelace",
		"first_name":    "Ada",
		"last_name":     "Lovelace",
		"email":         "ada@example.test",
		"phone":         "+1 555 0100",
		"address_line1": "12 Analytical Way",
		"city":          "London",
		"state":         "CA",
		"postal_code":   "94105",
		"country_code":  "US",
	}
	expected := make(map[string]string, len(identity))
	for key, value := range identity {
		expected[key] = value
	}
	response := Response{
		V:          1,
		ID:         id,
		Type:       "fill",
		Category:   "identity",
		Identity:   identity,
		Username:   "must-not-serialize",
		Password:   "must-not-serialize",
		Code:       "123456",
		Credential: "must-not-serialize",
	}
	raw, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err = json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	if wire["v"] != float64(1) || wire["id"] != id || wire["type"] != "fill" || wire["category"] != "identity" {
		t.Fatalf("identity envelope changed: %#v", wire)
	}
	fields := m3StringMap(t, wire, "identity")
	if len(fields) != len(identity) {
		t.Fatalf("identity field count %d, want %d", len(fields), len(identity))
	}
	for key, value := range expected {
		if fields[key] != value {
			t.Fatalf("identity[%s] = %#v, want %q", key, fields[key], value)
		}
	}
	for _, forbidden := range []string{"card", "username", "password", "code", "credential", "error"} {
		if _, ok := wire[forbidden]; ok {
			t.Fatalf("%s unexpectedly serialized", forbidden)
		}
	}
	for key, value := range identity {
		if value != "" {
			t.Fatalf("identity[%s] retained %q after serialization", key, value)
		}
	}
	response.Clear()
	if response.Identity != nil || response.Card != nil || response.Username != "" || response.Password != "" || response.Code != "" || response.Credential != "" {
		t.Fatal("Clear retained structured or credential fields")
	}
}

func TestM3CardResponseSerializationAndZeroing(t *testing.T) {
	id := reqID(102)
	card := map[string]string{
		"cardholder_name": "Ada Lovelace",
		"number":          "4242424242424242",
		"exp_month":       "12",
		"exp_year":        "2029",
		"cvv":             "123",
	}
	expected := make(map[string]string, len(card))
	for key, value := range card {
		expected[key] = value
	}
	response := Response{
		V:        1,
		ID:       id,
		Type:     "fill",
		Category: "credit_card",
		Card:     card,
		Username: "must-not-serialize",
		Password: "must-not-serialize",
	}
	out := &m3Output{}
	writer := NewWriter(out, time.Second)
	if err := writer.Write(response); err != nil {
		t.Fatal(err)
	}
	wire := m3DecodeFrame(t, out.Bytes())
	if wire["v"] != float64(1) || wire["id"] != id || wire["type"] != "fill" || wire["category"] != "credit_card" {
		t.Fatalf("card envelope changed: %#v", wire)
	}
	fields := m3StringMap(t, wire, "card")
	if len(fields) != len(card) {
		t.Fatalf("card field count %d, want %d", len(fields), len(card))
	}
	for key, value := range expected {
		if fields[key] != value {
			t.Fatalf("card[%s] = %#v, want %q", key, fields[key], value)
		}
	}
	for _, forbidden := range []string{"identity", "username", "password", "code", "credential", "error"} {
		if _, ok := wire[forbidden]; ok {
			t.Fatalf("%s unexpectedly serialized", forbidden)
		}
	}
	for key, value := range card {
		if value != "" {
			t.Fatalf("card[%s] retained %q after serialization", key, value)
		}
	}
	response.Clear()
	if response.Card != nil || response.Identity != nil || response.Username != "" || response.Password != "" {
		t.Fatal("Clear retained structured or credential fields")
	}
}

func TestM3StructuredResponseValidation(t *testing.T) {
	id := reqID(103)
	cases := []struct {
		name     string
		response Response
	}{
		{"identity with card", Response{V: 1, ID: id, Type: "fill", Category: "identity", Identity: map[string]string{"full_name": "Ada"}, Card: map[string]string{"number": "4242424242424242"}}},
		{"identity with card field", Response{V: 1, ID: id, Type: "fill", Category: "identity", Identity: map[string]string{"number": "4242424242424242"}}},
		{"card with identity field", Response{V: 1, ID: id, Type: "fill", Category: "credit_card", Card: map[string]string{"full_name": "Ada"}}},
		{"card with identity map", Response{V: 1, ID: id, Type: "fill", Category: "credit_card", Card: map[string]string{"number": "4242424242424242"}, Identity: map[string]string{"full_name": "Ada"}}},
		{"filled-identity with card", Response{V: 1, ID: id, Type: "filled-identity", Card: map[string]string{"number": "4242424242424242"}}},
		{"filled-card with identity", Response{V: 1, ID: id, Type: "filled-card", Identity: map[string]string{"full_name": "Ada"}}},
		{"filled without map", Response{V: 1, ID: id, Type: "filled"}},
		{"oversized identity value", Response{V: 1, ID: id, Type: "fill", Category: "identity", Identity: map[string]string{"full_name": strings.Repeat("x", 16385)}}},
		{"invalid UTF-8 identity value", Response{V: 1, ID: id, Type: "fill", Category: "identity", Identity: map[string]string{"full_name": string([]byte{0xff})}}},
		{"invalid category", Response{V: 1, ID: id, Type: "fill", Category: "otp", Identity: map[string]string{"full_name": "Ada"}}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := json.Marshal(testCase.response); !errors.Is(err, ErrProtocol) {
				t.Fatalf("marshal error = %v, want ErrProtocol", err)
			}
		})
	}

	secret := map[string]string{"full_name": strings.Repeat("x", 16385)}
	response := Response{V: 1, ID: id, Type: "fill", Category: "identity", Identity: secret}
	if _, err := json.Marshal(response); !errors.Is(err, ErrProtocol) {
		t.Fatalf("marshal error = %v, want ErrProtocol", err)
	}
	if secret["full_name"] != "" {
		t.Fatal("refused identity response retained its map value")
	}
}

func TestM3StructuredResponseCategoryInference(t *testing.T) {
	id := reqID(104)
	for _, testCase := range []struct {
		name     string
		response Response
		want     string
	}{
		{"identity", Response{V: 1, ID: id, Type: "filled", Identity: map[string]string{"full_name": "Ada"}}, "identity"},
		{"card", Response{V: 1, ID: id, Type: "filled", Card: map[string]string{"number": "4242424242424242"}}, "credit_card"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			raw, err := json.Marshal(testCase.response)
			if err != nil {
				t.Fatal(err)
			}
			var wire map[string]any
			if err = json.Unmarshal(raw, &wire); err != nil {
				t.Fatal(err)
			}
			if wire["category"] != testCase.want {
				t.Fatalf("category = %#v, want %q", wire["category"], testCase.want)
			}
		})
	}
}

func TestM3CategoryRequestValidation(t *testing.T) {
	capability := strings.Repeat("a", 32)
	itemID := strings.Repeat("b", 32)
	revision := strings.Repeat("c", 64)
	match := func(category string) []byte {
		return frame(`{"v":1,"id":"` + reqID(105) + `","type":"match","capability":"` + capability + `","origin":"https://example.test","tab_id":1,"document_id":"doc-1"` + func() string {
			if category == "" {
				return ""
			}
			return `,"category":"` + category + `"`
		}() + `}`)
	}
	for _, category := range []string{"", "login", "identity", "credit_card"} {
		request, err := ReadRequest(bytes.NewReader(match(category)))
		if err != nil {
			t.Fatalf("category %q refused: %v", category, err)
		}
		if request.Category != category {
			t.Fatalf("category = %q, want %q", request.Category, category)
		}
	}
	for _, category := range []string{"otp", "password", "credit-card"} {
		if _, err := ReadRequest(bytes.NewReader(match(category))); err == nil {
			t.Fatalf("invalid match category %q accepted", category)
		}
	}
	fill := frame(`{"v":1,"id":"` + reqID(106) + `","type":"fill","capability":"` + capability + `","origin":"https://example.test","tab_id":1,"document_id":"doc-1","item_id":"` + itemID + `","revision":"` + revision + `","category":"credit_card"}`)
	request, err := ReadRequest(bytes.NewReader(fill))
	if err != nil || request.Category != "credit_card" {
		t.Fatalf("identity/card fill request refused: request=%#v err=%v", request, err)
	}
	helloWithCategory := frame(`{"v":1,"id":"` + reqID(107) + `","type":"hello","category":"identity"}`)
	if _, err := ReadRequest(bytes.NewReader(helloWithCategory)); err == nil {
		t.Fatal("category on hello accepted")
	}
}
