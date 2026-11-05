package browserhost

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestSaveProtocolStrictUnicodePresenceAndRedaction(t *testing.T) {
	base := `{"v":1,"id":"11111111111111111111111111111111","type":"save-new","capability":"22222222222222222222222222222222","origin":"https://example.test","tab_id":1,"window_id":1,"document_id":"doc-1","username":"","password":"synthetic-save-password"}`
	r, e := ReadRequest(bytes.NewReader(frame(base)))
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(fmt.Sprintf("%#v", r), "synthetic-save-password") {
		t.Fatal("request formatted secret")
	}
	r.Clear()
	for _, raw := range []string{strings.Replace(base, `"username":"",`, "", 1), strings.Replace(base, `"username":""`, `"username":null`, 1), strings.Replace(base, `synthetic-save-password`, `\ud800`, 1), strings.Replace(base, `synthetic-save-password`, `\udc00`, 1), strings.Replace(base, `synthetic-save-password`, strings.Repeat("x", 16385), 1)} {
		if _, e := ReadRequest(bytes.NewReader(frame(raw))); e == nil {
			t.Fatal("bad save DTO accepted")
		}
	}
	good := strings.Replace(base, `synthetic-save-password`, `\ud83d\ude00`, 1)
	r, e = ReadRequest(bytes.NewReader(frame(good)))
	if e != nil {
		t.Fatal("unicode pair", e)
	}
	r.Clear()
}
