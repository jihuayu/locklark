package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/jihuayu/locklark/internal/watchtower"
)

func TestPersonalHealthHIBPOptionIsStrict(t *testing.T) {
	cases := [][]string{
		{"health", "--file", "owner.ll", "--hibp", "false"},
		{"health", "--file", "owner.ll", "--hibp", "TRUE"},
		{"health", "--file", "owner.ll", "--hibp", "1"},
		{"health", "--file", "owner.ll", "--hibp", "true", "--hibp", "true"},
		{"health", "--file", "owner.ll", "--network", "true"},
	}
	for _, args := range cases {
		if err := runPersonal(args, &bytes.Buffer{}); err != personalUsage {
			t.Fatalf("accepted %v: %v", args, err)
		}
	}
	err := runPersonal([]string{"health", "--file", "owner.ll", "--hibp", "true"}, &bytes.Buffer{})
	if err == nil || err == personalUsage || !strings.Contains(err.Error(), "interactive terminal") {
		t.Fatalf("literal opt-in was not parsed before the terminal check: %v", err)
	}
}

func TestPersonalHIBPConsentWarningAndRefusal(t *testing.T) {
	var warning bytes.Buffer
	ask := func(prompt string) ([]byte, error) {
		if prompt != "输入 NETWORK 确认联网查询泄露前缀" {
			t.Fatalf("prompt=%q", prompt)
		}
		return []byte("no"), nil
	}
	if err := confirmPersonalHIBP(ask, &warning); !errors.Is(err, errPersonalHIBPCancelled) {
		t.Fatalf("wrong consent: %v", err)
	}
	text := warning.String()
	for _, required := range []string{
		"https://api.pwnedpasswords.com/range/",
		"Add-Padding: true",
		"SHA-1 的前 5 个十六进制字符",
		"不会发送明文密码、完整哈希或哈希后缀",
		"IP",
		"不会联网",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("warning missing %q", required)
		}
	}
	if err := confirmPersonalHIBP(func(string) ([]byte, error) { return []byte("NETWORK"), nil }, &warning); err != nil {
		t.Fatalf("exact consent: %v", err)
	}
	sentinel := errors.New("terminal cancelled")
	if err := confirmPersonalHIBP(func(string) ([]byte, error) { return nil, sentinel }, &warning); !errors.Is(err, sentinel) {
		t.Fatalf("input error hidden: %v", err)
	}
	if err := confirmPersonalHIBP(nil, &warning); !errors.Is(err, errPersonalHIBPCancelled) {
		t.Fatal("nil prompt accepted")
	}
}

func TestPersonalHealthHIBPWrongConsentNeverUnlocks(t *testing.T) {
	// The path deliberately does not exist: reaching the vault would produce a
	// different error. A fixed cancellation proves consent is checked first.
	_, err := personalHealthHIBP("/nonexistent/synthetic.ll", "pw", bytes.Repeat([]byte{1}, 16),
		func(string) ([]byte, error) { return []byte("no"), nil }, &bytes.Buffer{})
	if !errors.Is(err, errPersonalHIBPCancelled) {
		t.Fatalf("wrong consent reached the vault: %v", err)
	}
}

func TestPersonalHIBPProjectionDropsNativeDetail(t *testing.T) {
	report := watchtower.Report{
		Profile:      watchtower.Profile,
		HIBPChecked:  true,
		HIBPError:    "provider-url-and-body-must-not-leak",
		OverallScore: 10,
		Checked:      2,
		Skipped:      1,
		Findings: []watchtower.Finding{{
			ID:               "00112233445566778899aabbccddeeff",
			Revision:         strings.Repeat("a", 64),
			Title:            "private-title",
			Origin:           "https://private.example",
			Flags:            []string{"vulnerable", "weak"},
			StrengthScore:    3,
			StrengthCategory: "terrible",
			ReuseCount:       99,
			BreachCount:      42,
		}},
		Counts:       watchtower.Counts{Vulnerable: 1},
		Site:         watchtower.Site{Origin: "https://private.example"},
		SiteFindings: []watchtower.Finding{{Title: "private-title"}},
	}
	raw, err := json.Marshal(projectPersonalHIBP(report))
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"private-title", "private.example", "provider-url", "terrible", "reuse_count", "strength", "title", "origin"} {
		if bytes.Contains(raw, []byte(forbidden)) {
			t.Fatalf("projection leaked %q: %s", forbidden, raw)
		}
	}
	if !bytes.Contains(raw, []byte(`"hibp_error":"unavailable"`)) {
		t.Fatalf("HIBP error was not whitelisted: %s", raw)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"status", "hibp_checked", "hibp_error", "checked", "skipped", "findings"} {
		if _, ok := decoded[key]; !ok {
			t.Fatalf("missing %q: %s", key, raw)
		}
	}
	findings, ok := decoded["findings"].([]any)
	if !ok || len(findings) != 1 {
		t.Fatalf("findings=%v", decoded["findings"])
	}
	finding, ok := findings[0].(map[string]any)
	if !ok || len(finding) != 4 {
		t.Fatalf("finding=%v", findings[0])
	}
	for _, key := range []string{"id", "revision", "flags", "breach_count"} {
		if _, ok := finding[key]; !ok {
			t.Fatalf("missing %q: %v", key, finding)
		}
	}
}
