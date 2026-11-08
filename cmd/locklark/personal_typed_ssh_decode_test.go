package main

// Decode-phase tests for the explicit ssh_private_key_file member: ssh_key is
// the only accepted category, the path is the only accepted representation, and
// every inline key form, attachment or scalar credential is refused.

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jihuayu/locklark/internal/vault"
)

func TestDecodeTypedPersonalSSHKeyFileDocument(t *testing.T) {
	path := filepath.Join(t.TempDir(), "id_typed")
	raw := fmt.Sprintf(`{"category":"ssh_key","title":"Typed key","ssh_private_key_file":%q,"sections":[{"id":"ops","title":"Ops","fields":[{"id":"note","label":"Note","value":"visible"}]}],"tags":["infra"],"favorite":true}`, path)
	item, requests, err := decodeTypedPersonalDocument([]byte(raw))
	if err != nil {
		t.Fatalf("decode ssh_key document: %v", err)
	}
	if item.Category != vault.CategorySSHKey || item.Kind != string(vault.CategorySSHKey) || item.Title != "Typed key" {
		t.Fatalf("unexpected decoded item: %+v", item)
	}
	if len(item.Attachments) != 0 || len(item.Sections) != 1 || len(item.Tags) != 1 || !item.Favorite {
		t.Fatalf("typed ssh fields were not preserved: %+v", item)
	}
	if len(item.SSHSeed) != 0 || len(item.SSHPublicKey) != 0 {
		t.Fatal("decode phase must not carry key material")
	}
	if len(requests) != 1 || !requests[0].sshKey || requests[0].file != path {
		t.Fatalf("expected one unresolved ssh key request: %+v", requests)
	}
	if _, err := decodeTypedPersonalInput([]byte(raw)); !errors.Is(err, errTypedInputRefused) {
		t.Fatalf("item-only wrapper must refuse an unresolved key request: %v", err)
	}
}

func TestDecodeTypedPersonalSSHKeyRefusals(t *testing.T) {
	abs := filepath.Join(t.TempDir(), "id_typed")
	inlineSeed := `{"category":"ssh_key","title":"k","ssh_seed":"AAAA"}`
	cases := map[string]string{
		"missing-file":        `{"category":"ssh_key","title":"k"}`,
		"relative-file":       `{"category":"ssh_key","title":"k","ssh_private_key_file":"id_typed"}`,
		"control-file":        `{"category":"ssh_key","title":"k","ssh_private_key_file":"/tmp/a\u0000b"}`,
		"attachments":         fmt.Sprintf(`{"category":"ssh_key","title":"k","ssh_private_key_file":%q,"attachments":[{"file":%q,"file_name":"a.bin"}]}`, abs, abs),
		"username":            fmt.Sprintf(`{"category":"ssh_key","title":"k","ssh_private_key_file":%q,"username":"u"}`, abs),
		"password":            fmt.Sprintf(`{"category":"ssh_key","title":"k","ssh_private_key_file":%q,"password":"p"}`, abs),
		"otp":                 fmt.Sprintf(`{"category":"ssh_key","title":"k","ssh_private_key_file":%q,"otp":"o"}`, abs),
		"notes":               fmt.Sprintf(`{"category":"ssh_key","title":"k","ssh_private_key_file":%q,"notes":"n"}`, abs),
		"url":                 fmt.Sprintf(`{"category":"ssh_key","title":"k","ssh_private_key_file":%q,"url":"https://example.test"}`, abs),
		"wrong-category":      fmt.Sprintf(`{"category":"login","title":"k","ssh_private_key_file":%q}`, abs),
		"inline-seed":         strings.TrimSuffix(inlineSeed, "}") + fmt.Sprintf(`,"ssh_private_key_file":%q}`, abs),
		"inline-private-key":  fmt.Sprintf(`{"category":"ssh_key","title":"k","ssh_private_key_file":%q,"private_key":"AAAA"}`, abs),
		"inline-key-file-key": fmt.Sprintf(`{"category":"ssh_key","title":"k","ssh_private_key_file":%q,"key_file":%q}`, abs, abs),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			item, requests, err := decodeTypedPersonalDocument([]byte(raw))
			if !errors.Is(err, errTypedInputRefused) || requests != nil || item.Attachments != nil || item.SSHSeed != nil {
				t.Fatalf("expected fixed refusal, got item=%+v requests=%+v err=%v", item, requests, err)
			}
			if err != nil && (strings.Contains(err.Error(), abs) || strings.Contains(err.Error(), "AAAA")) {
				t.Fatalf("refusal echoed a descriptor value: %q", err)
			}
		})
	}
}
