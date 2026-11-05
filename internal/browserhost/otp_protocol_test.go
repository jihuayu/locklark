package browserhost

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/jihuayu/locklark/internal/personal"
	"strings"
	"testing"
)

func TestOTPWireStrictShapes(t *testing.T) {
	for _, wire := range []string{
		`{"v":1,"id":"11111111111111111111111111111111","type":"otp","capability":"22222222222222222222222222222222","window_id":1,"origin":"https://example.test","tab_id":1,"document_id":"doc-1","item_id":"33333333333333333333333333333333","revision":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`,
		`{"v":1,"id":"11111111111111111111111111111111","type":"otp-ack","capability":"22222222222222222222222222222222","request_id":"33333333333333333333333333333333","nonce":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`,
		`{"v":1,"id":"11111111111111111111111111111111","type":"cancel-otp","capability":"22222222222222222222222222222222","request_id":"33333333333333333333333333333333"}`,
	} {
		if _, err := ReadRequest(bytes.NewReader(frame(wire))); err != nil {
			t.Fatal("dedicated OTP DTO was refused")
		}
		for _, extra := range []string{`,"username":"private"`, `,"password":"private"`, `,"code":"123456"`, `,"x":1`} {
			bad := wire[:len(wire)-1] + extra + "}"
			if _, err := ReadRequest(bytes.NewReader(frame(bad))); err == nil {
				t.Fatal("OTP accepted an unrelated field")
			}
		}
	}
}

func TestOTPPhaseAndNumericBoundariesFailClosed(t *testing.T) {
	o := `{"v":1,"id":"11111111111111111111111111111111","type":"otp","capability":"22222222222222222222222222222222","window_id":1,"origin":"https://example.test","tab_id":1,"document_id":"doc-1","item_id":"33333333333333333333333333333333","revision":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`
	a := `{"v":1,"id":"11111111111111111111111111111111","type":"otp-ack","capability":"22222222222222222222222222222222","request_id":"33333333333333333333333333333333","nonce":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`
	c := `{"v":1,"id":"11111111111111111111111111111111","type":"cancel-otp","capability":"22222222222222222222222222222222","request_id":"33333333333333333333333333333333"}`
	add := func(raw, field string) string { return raw[:len(raw)-1] + "," + field + "}" }
	bad := []string{
		strings.Replace(o, `,"window_id":1`, "", 1), add(o, `"nonce":"`+strings.Repeat("a", 64)+`"`), add(o, `"request_id":"`+reqID(5)+`"`),
		add(a, `"window_id":1`), add(a, `"origin":"https://example.test"`), add(c, `"nonce":"`+strings.Repeat("a", 64)+`"`),
		add(c, `"document_id":"doc-1"`), add(o, `"window_id":2`), strings.Replace(a, `"request_id":"33333333333333333333333333333333"`, `"request_id":"bad"`, 1),
	}
	for _, number := range []string{"0", "-1", "9007199254740992", "1.0", "1e0", `"1"`} {
		bad = append(bad, strings.Replace(o, `"window_id":1`, `"window_id":`+number, 1))
	}
	for _, raw := range bad {
		if _, err := ReadRequest(bytes.NewReader(frame(raw))); err == nil {
			t.Fatal("mixed phase or invalid numeric selector accepted")
		}
	}
}

func TestOTPResponseCannotUseGenericValueSerialization(t *testing.T) {
	value := Response{V: 1, ID: reqID(1), Type: "otp-fill", Code: "928374", Username: "private-user", Password: "private-password"}
	if _, err := json.Marshal(value); err == nil {
		t.Fatal("generic response serialized OTP value")
	}
	if fmt.Sprintf("%#v", value) != "[native browser response]" {
		t.Fatal("response formatting exposed fields")
	}
	for _, kind := range []string{"error", "paired", "fill", "candidates", "save-ready", "otp-ready", "unknown"} {
		value.Type = kind
		value.Nonce = strings.Repeat("a", 64)
		value.Candidates = []personal.Row{{Title: "candidate"}}
		raw, err := json.Marshal(value)
		if err != nil || bytes.Contains(raw, []byte(`"code"`)) || bytes.Contains(raw, []byte("928374")) {
			t.Fatal("non-value response exposed code")
		}
		if kind == "otp-ready" && (bytes.Contains(raw, []byte("private")) || bytes.Contains(raw, []byte("candidate"))) {
			t.Fatal("OTP challenge included value fields or candidates")
		}
	}
}
