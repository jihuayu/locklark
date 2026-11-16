package vault

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jihuayu/locklark/pkg/vaultfile"
)

func scopedItemsCode(err error) string {
	if e, ok := vaultfile.AsError(err); ok {
		return e.Code
	}
	return ""
}

func TestScopedItemSummariesHandleLifecycle(t *testing.T) {
	fxA := newAuthItemsFixtureVault(t, "vault-scoped-items-a")
	fxB := newAuthItemsFixtureVault(t, "vault-scoped-items-b")
	metadata, items := authItemsFixtureMetadata(), authItemsFixtureItems()
	encA := sealAuthItems(t, fxA, metadata, items)
	encB := sealAuthItems(t, fxB, metadata, items)

	hA, err := vaultfile.NewScopedUnlock(encA, fxA.pin, "device-1", fxA.device)
	if err != nil {
		t.Fatalf("NewScopedUnlock(A): %v", err)
	}
	hB, err := vaultfile.NewScopedUnlock(encB, fxB.pin, "device-1", fxB.device)
	if err != nil {
		t.Fatalf("NewScopedUnlock(B): %v", err)
	}

	sumA, err := ReadScopedItemSummaries(hA, encA, ItemSummaryOptions{IncludeID: true})
	if err != nil {
		t.Fatalf("ReadScopedItemSummaries(A): %v", err)
	}
	if len(sumA) != len(items) {
		t.Fatalf("summary count = %d, want %d", len(sumA), len(items))
	}
	wantIDs := []string{"login-a", "document-b", "trashed-c"}
	wantTitles := []string{"Example login", "Binary document", "Trashed login"}
	wantCategories := []ItemCategory{CategoryLogin, CategoryDocument, CategoryLogin}
	for i := range sumA {
		if sumA[i].ID != wantIDs[i] || sumA[i].Title != wantTitles[i] || sumA[i].Category != wantCategories[i] {
			t.Fatalf("summary %d did not match the bounded projection", i)
		}
	}

	// ID is absent unless explicitly requested; title and category remain.
	sumNoID, err := ReadScopedItemSummaries(hA, encA, ItemSummaryOptions{})
	if err != nil {
		t.Fatalf("ReadScopedItemSummaries without ID: %v", err)
	}
	if len(sumNoID) != len(items) {
		t.Fatalf("no-ID summary count = %d, want %d", len(sumNoID), len(items))
	}
	for i := range sumNoID {
		if sumNoID[i].ID != "" {
			t.Fatalf("no-ID summary %d carries an ID", i)
		}
		if sumNoID[i].Title != wantTitles[i] || sumNoID[i].Category != wantCategories[i] {
			t.Fatalf("no-ID summary %d did not match the bounded projection", i)
		}
	}

	// The bounded projection never renders a secret item field.
	rendered := fmt.Sprintf("%+v", sumA)
	for _, secret := range []string{
		"synthetic-password", "synthetic-user", "otpauth://",
		"synthetic-trashed-password", "fixture.bin",
	} {
		if strings.Contains(rendered, secret) {
			t.Fatal("summary rendering contains a secret item field")
		}
	}

	// The same titles in a different vault do not let handle A read B.
	if got, err := ReadScopedItemSummaries(hA, encB, ItemSummaryOptions{IncludeID: true}); err == nil || got != nil {
		t.Fatalf("A read B: summaries=%v err=%v", got != nil, err)
	}

	// Closing A revokes its later reads, idempotently, while B stays real.
	if err := hA.Close(); err != nil {
		t.Fatalf("Close A: %v", err)
	}
	if err := hA.Close(); err != nil {
		t.Fatalf("second Close A: %v", err)
	}
	if got, err := ReadScopedItemSummaries(hA, encA, ItemSummaryOptions{IncludeID: true}); got != nil ||
		scopedItemsCode(err) != vaultfile.CodeUnlockUnavailable {
		t.Fatalf("closed A read = summaries=%v code=%q, want unavailable", got != nil, scopedItemsCode(err))
	}
	sumB, err := ReadScopedItemSummaries(hB, encB, ItemSummaryOptions{IncludeID: true})
	if err != nil {
		t.Fatalf("ReadScopedItemSummaries(B) after A close: %v", err)
	}
	if len(sumB) != len(items) {
		t.Fatalf("B summary count = %d, want %d", len(sumB), len(items))
	}
}

func TestScopedItemSummariesUsesRealItemDatabase(t *testing.T) {
	fx := newAuthItemsFixtureVault(t, "vault-scoped-items-real")
	metadata, items := authItemsFixtureMetadata(), authItemsFixtureItems()
	db, err := NewItemDatabase(metadata, items)
	if err != nil {
		t.Fatalf("NewItemDatabase: %v", err)
	}
	// A structurally valid KDBX payload with the wrong item-group name must
	// fail through the real ReadItemDatabase, not through a constant
	// projection in the bridge.
	db.Content.Root.Groups[0].Name = "not the locklark item layout"
	encoded, err := vaultfile.SealAuthenticatedFile(fx.draft, db, fx.pin, fx.vuk, fx.author)
	if err != nil {
		t.Fatalf("SealAuthenticatedFile: %v", err)
	}
	h, err := vaultfile.NewScopedUnlock(encoded, fx.pin, "device-1", fx.device)
	if err != nil {
		t.Fatalf("NewScopedUnlock: %v", err)
	}
	if got, err := ReadScopedItemSummaries(h, encoded, ItemSummaryOptions{IncludeID: true}); got != nil || !errors.Is(err, ErrSnapshot) {
		t.Fatalf("wrong item database = summaries=%v err=%v, want ErrSnapshot", got != nil, err)
	}
}
