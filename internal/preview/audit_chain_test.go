package preview

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
)

func TestAuditTamperAndPrefix(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var p payload
	appendEvent := func(reason string) { t.Helper(); p.signedRecord(key, "job", "owner", "field.read", reason, "denied") }
	appendEvent("one")
	c1, err := makeCheckpoint(p, key)
	if err != nil {
		t.Fatal(err)
	}
	appendEvent("two")
	appendEvent("three")
	c3, err := makeCheckpoint(p, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = checkChain(p, pub, &c1); err != nil {
		t.Fatal("valid prefix", err)
	}
	cut := p
	cut.Events = cut.Events[:2]
	cut.Proofs = cut.Proofs[:2]
	if _, err = checkChain(cut, pub, &c3); err == nil {
		t.Fatal("witnessed suffix deletion accepted")
	}
	if _, err = checkChain(cut, pub, &c1); err != nil {
		t.Fatal("old witness cannot detect unwitnessed tail loss", err)
	}
	p.Events[1].Reason = "modified"
	if _, err = checkChain(p, pub, &c1); err == nil {
		t.Fatal("modified event accepted")
	}
	p.Events[1].Reason = "two"
	p.Events = append(p.Events[:1], p.Events[2])
	p.Proofs = append(p.Proofs[:1], p.Proofs[2])
	if _, err = checkChain(p, pub, &c1); err == nil {
		t.Fatal("middle deletion accepted")
	}
}
func TestAuditWitnessAcrossSnapshots(t *testing.T) {
	root := filepath.Join(t.TempDir(), "case")
	if err := Create(root, "goal", "exercise"); err != nil {
		t.Fatal(err)
	}
	cpDir := t.TempDir()
	copyCP := func(n string) string {
		dest := filepath.Join(cpDir, n)
		data, err := os.ReadFile(filepath.Join(root, "witness", n))
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(dest, data, 0600); err != nil {
			t.Fatal(err)
		}
		return dest
	}
	latest, early := copyCP("epoch-3.json"), copyCP("epoch-2.json")
	device := filepath.Join(root, "clients", "B")
	bundle := func(n string) string { return filepath.Join(root, "share", "epoch-"+n) }
	got, err := VerifyAudit(bundle("3"), device, 3, early)
	if err != nil || got.Witnessed != 3 || got.Events != 4 {
		t.Fatal(got, err)
	}
	if _, err = VerifyAudit(bundle("2"), device, 2, latest); err == nil {
		t.Fatal("rollback accepted")
	}
	foreign := filepath.Join(t.TempDir(), "other")
	if err = Create(foreign, "other", "other"); err != nil {
		t.Fatal(err)
	}
	if _, err = VerifyAudit(bundle("3"), device, 3, filepath.Join(foreign, "witness", "epoch-3.json")); err == nil {
		t.Fatal("foreign witness accepted")
	}
}
