package preview

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestScenario(t *testing.T) {
	out := filepath.Join(t.TempDir(), "demo")
	if err := Create(out, "build-42", "核对合成令牌的访问"); err != nil {
		t.Fatal(err)
	}
	if err := Create(out, "again", "different"); err == nil {
		t.Fatal("existing output replaced")
	}
	device := func(s string) string { return filepath.Join(out, "clients", s) }
	bundle := func(s string) string { return filepath.Join(out, "share", "epoch-"+s) }
	for _, d := range []string{"A", "B"} {
		if _, err := Inspect(bundle("1"), device(d), 1); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Inspect(bundle("2"), device("A"), 2); err == nil {
		t.Fatal("revoked A opened new release")
	}
	if _, err := Inspect(bundle("1"), device("B"), 2); err == nil {
		t.Fatal("rollback allowed")
	}
	got, err := Inspect(bundle("2"), device("B"), 2)
	if err != nil {
		t.Fatal(err)
	}
	if got.Items != 2 || got.Attachments != 1 || got.Epoch != 2 {
		t.Fatalf("missing fixture records: %+v", got)
	}
	p, err := readPayload(bundle("2"), device("B"), 2)
	if err != nil {
		t.Fatal(err)
	}
	original, err := fixtureArchive()
	if err != nil || !bytes.Equal(p.Archive, original) {
		t.Fatal("1PUX archive changed")
	}
	events, err := Audit(bundle("2"), device("B"), 2, "build-42")
	if err != nil || len(events) != 1 || events[0].Result != "denied" || events[0].Reason != "核对合成令牌的访问" {
		t.Fatalf("wrong audit: %+v, %v", events, err)
	}
	other, err := Audit(bundle("2"), device("B"), 2, "build-43")
	if err != nil || len(other) != 0 {
		t.Fatal("session filter leaked events")
	}
	safe, _ := json.Marshal([]any{got, events})
	if bytes.Contains(safe, []byte("FIXTURE-VALUE")) {
		t.Fatal("secret field printed")
	}
	files, err := os.ReadDir(bundle("2"))
	if err != nil || len(files) != 3 {
		t.Fatalf("unexpected share contents: %v %v", files, err)
	}
	for _, f := range files {
		b, err := os.ReadFile(filepath.Join(bundle("2"), f.Name()))
		if err != nil || bytes.Contains(b, []byte("核对合成令牌的访问")) || bytes.Contains(b, []byte("FIXTURE-VALUE")) || bytes.Contains(b, []byte("AGE-SECRET-KEY-")) {
			t.Fatal("disclosure in share")
		}
	}
}

func TestInvalidRequestDoesNotCreateOutput(t *testing.T) {
	for _, c := range [][2]string{{"", "why"}, {"missing-reason", " "}, {"bad\nsession", "why"}} {
		p := filepath.Join(t.TempDir(), "absent")
		if Create(p, c[0], c[1]) == nil {
			t.Fatal("invalid request accepted")
		}
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatal("files created for invalid request")
		}
	}
}
