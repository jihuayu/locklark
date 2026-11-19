package mobilecore

import "testing"

// This regression only clears staged in-memory slots, so it must run on every
// build, including platforms where the real local-directory provider is
// unsupported and the fixture-backed batch tests are excluded.
func TestMobileOwnedLocalExactBatchCleanupZeroesStagedSlots(t *testing.T) {
	shared := []OwnedLocalExactHit{
		{ID: "owned-local-batch-hit-a", Title: "owned-local-batch-title-a"},
		{ID: "owned-local-batch-hit-b", Title: "owned-local-batch-title-b"},
	}
	entries := []OwnedLocalExactBatchEntry{
		{
			VaultID:         "owned-local-batch-vault-a",
			Status:          OwnedLocalExactStatusOK,
			BackendRevision: "owned-local-batch-revision-a",
			Truncated:       true,
			hits:            shared,
		},
		{
			VaultID:         "owned-local-batch-vault-b",
			Status:          OwnedLocalExactStatusOK,
			BackendRevision: "owned-local-batch-revision-b",
			hits:            shared,
		},
		{
			VaultID: "owned-local-batch-vault-c",
			Status:  OwnedLocalExactStatusUnavailable,
		},
	}
	clearOwnedLocalExactBatchEntries(entries)
	if len(entries) != 3 || len(shared) != 2 {
		t.Fatal("MOBILE_OWNED_BATCH_CLEANUP_BOUNDS_CHANGED")
	}
	for index := range entries {
		entry := &entries[index]
		if entry.VaultID != "" || entry.Status != "" ||
			entry.BackendRevision != "" || entry.Truncated ||
			entry.hits != nil || entry.Count() != 0 {
			t.Fatal("MOBILE_OWNED_BATCH_CLEANUP_SLOT_NOT_ZEROED")
		}
	}
	for index := range shared {
		if shared[index].ID != "" || shared[index].Title != "" {
			t.Fatal("MOBILE_OWNED_BATCH_CLEANUP_ALIAS_HIT_NOT_ZEROED")
		}
	}
}
