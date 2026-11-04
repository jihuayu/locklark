package preview

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/jihuayu/locklark/internal/onepux"
)

func TestOnepuxInventoryFromVerifiedFixture(t *testing.T) {
	root := filepath.Join(t.TempDir(), "inventory")
	if err := Create(root, "inventory-vector", "inspect bundled synthetic source"); err != nil {
		t.Fatal(err)
	}
	bundle, device := filepath.Join(root, "share", "epoch-3"), filepath.Join(root, "clients", "B")
	proof, err := VerifyAudit(bundle, device, 3, filepath.Join(root, "witness", "epoch-3.json"))
	if err != nil || proof.Events != proof.Witnessed {
		t.Fatal("source audit/checkpoint not verified", err)
	}
	p, err := readPayload(bundle, device, 3)
	if err != nil {
		t.Fatal(err)
	}
	report, err := onepux.Inspect(p.Archive)
	if err != nil || report.Accounts != 1 || report.Vaults != 1 || report.Items != 2 || report.Files != 1 || report.UnmappedItems != 2 || report.MappingVerified {
		t.Fatal("verified fixture inventory changed or claimed migration", err)
	}
	raw, err := json.Marshal([]any{p.Events, proof, report})
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range p.items {
		for _, marker := range []string{item.Title, item.Password, item.OTP, item.Filename} {
			if marker != "" && bytes.Contains(raw, []byte(marker)) {
				t.Fatal("source audit or inventory report leaked fixture metadata/values")
			}
		}
	}
}
