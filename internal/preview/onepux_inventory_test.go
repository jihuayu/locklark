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
	// The built-in fixture supplies document attributes but no explicit path.
	// Its apparent filename pattern must not be promoted to a verified link.
	if report.FileReferences.Explicit != 0 || report.FileReferences.ItemsWithoutExplicitPath != 1 || report.FileReferences.FilesWithoutExplicitLinks != 1 {
		t.Fatal("verified source history was confused with verified file linkage")
	}
	login := report.LoginFieldInventory
	if report.PasswordHistory != (onepux.PasswordHistoryReport{}) {
		t.Fatal("inventory invented history absent from the verified source")
	}
	if login.Fields != 1 || login.PasswordDesignations != 1 || login.FieldTypeAttributes != 1 || login.TypeAttributes != 0 || login.StringValues != 1 {
		t.Fatal("source login field was lost or normalized")
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
