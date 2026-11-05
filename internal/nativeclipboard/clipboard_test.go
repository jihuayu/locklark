package nativeclipboard

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestLeaseFormattingAndInvalidInput(t *testing.T) {
	p := &Lease{native: []byte("private-canary")}
	for _, value := range []any{p, *p} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if fmt.Sprintf(format, value) != "[clipboard lease]" {
				t.Fatal("lease formatting was not redacted")
			}
		}
		b, e := json.Marshal(value)
		if e != nil || string(b) != `"[clipboard lease]"` {
			t.Fatal("lease JSON was not redacted")
		}
	}
	for _, value := range [][]byte{{0xff}, []byte("prefix\x00suffix"), []byte(strings.Repeat("a", 4<<20+1))} {
		lease, e := Write(value)
		if lease != nil || e != ErrWrite {
			t.Fatal("invalid input reached native clipboard")
		}
	}
}
