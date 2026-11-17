package personal

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

func TestRestorationFormatRedactsPrivateFields(t *testing.T) {
	password := "owned-format-private-factor"
	path := "/owned/private/format-destination"
	seed := bytes.Repeat([]byte{0x7b}, 32)
	key := []byte("owned-private-key")
	r := &Restoration{dest: path, pw: password, oldKey: bytes.Clone(key),
		p: &payload{VaultFileOwners: []vaultFileOwnerRecord{{OwnerRootSeed: bytes.Clone(seed)}}}}
	defer r.Close()
	value := *r
	const redacted = "[redacted restoration]"
	for _, sample := range []struct {
		name  string
		value any
	}{
		{"value", value}, {"pointer", r},
	} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%20.4v", "%-20v"} {
			got := fmt.Sprintf(format, sample.value)
			if strings.Contains(got, password) {
				t.Fatal("RESTORATION_FORMAT_EXPOSED_FACTOR")
			}
			if strings.Contains(got, path) {
				t.Fatal("RESTORATION_FORMAT_EXPOSED_PATH")
			}
			if strings.Contains(got, base64.StdEncoding.EncodeToString(seed)) ||
				strings.Contains(got, fmt.Sprint(seed)) || strings.Contains(got, fmt.Sprintf("%#v", seed)) {
				t.Fatal("RESTORATION_FORMAT_EXPOSED_SEED")
			}
			if strings.Contains(got, fmt.Sprint(key)) || strings.Contains(got, fmt.Sprintf("%x", key)) {
				t.Fatal("RESTORATION_FORMAT_EXPOSED_KEY")
			}
			if got != redacted {
				t.Fatal("RESTORATION_FORMAT_NOT_FIXED")
			}
		}
	}
	var nilRestoration *Restoration
	for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
		got := fmt.Sprintf(format, nilRestoration)
		if got != "<nil>" && got != redacted {
			t.Fatal("RESTORATION_FORMAT_TYPED_NIL_UNEXPECTED")
		}
	}
	r.Close()
	if got := fmt.Sprintf("%+v", r); got != redacted {
		t.Fatal("RESTORATION_FORMAT_CLOSED_UNEXPECTED")
	}
	for _, got := range []string{fmt.Sprintf("%T", value), fmt.Sprintf("%p", r)} {
		if strings.Contains(got, password) || strings.Contains(got, path) || strings.Contains(got, base64.StdEncoding.EncodeToString(seed)) {
			t.Fatal("RESTORATION_FORMAT_SPECIAL_VERB_EXPOSED_SECRET")
		}
	}
}
