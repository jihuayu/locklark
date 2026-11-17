//go:build darwin || linux

package vaultfileclient

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/jihuayu/locklark/internal/personal"
)

func TestLocalGenesisExactQueryRealEmptyChild(t *testing.T) {
	f := newLocalGenesisTwoVaultFixture(t)
	a, _ := f.open(t, f.firstConfig, f.firstVaultID)
	t.Cleanup(func() { _ = a.Close() })

	got, err := a.QueryExactTitle(LocalGenesisExactQuery{Title: "exact-title", Limit: 4})
	if err != nil {
		t.Fatal("real exact query failed")
	}
	if got.ConfigPath != f.firstConfig ||
		got.WorkspaceRoot != f.f.proposal.BackendRoot ||
		got.VaultID != f.firstVaultID ||
		got.JournalPath == "" ||
		got.ManifestSHA256 == "" ||
		got.JournalRevision == "" {
		t.Fatal("exact scope metadata incomplete")
	}
	if len(got.Hits) != 0 || got.Truncated {
		t.Fatal("empty real child returned a hit")
	}
}

func TestLocalGenesisExactQuerySyntheticSameNameDistinctAndBound(t *testing.T) {
	f := newLocalGenesisTwoVaultFixture(t)
	a, _ := f.open(t, f.firstConfig, f.firstVaultID)
	t.Cleanup(func() { _ = a.Close() })
	b, _ := f.open(t, f.secondConfig, f.secondVaultID)
	t.Cleanup(func() { _ = b.Close() })

	title := "same-exact-title"
	old := localGenesisExactQueryProjectionForTest
	t.Cleanup(func() { localGenesisExactQueryProjectionForTest = old })

	localGenesisExactQueryProjectionForTest = func() []personal.VaultFileBaselineItem {
		return []personal.VaultFileBaselineItem{
			{ID: "a-item-1", Title: title},
			{ID: "a-item-2", Title: title},
			{ID: "a-item-3", Title: title},
			{ID: "a-other", Title: "other-title"},
		}
	}
	gotA, err := a.QueryExactTitle(LocalGenesisExactQuery{Title: title, Limit: 2})
	if err != nil {
		t.Fatal("synthetic exact query failed")
	}
	if len(gotA.Hits) != 2 || !gotA.Truncated ||
		gotA.Hits[0].ID == "" || gotA.Hits[1].ID == "" ||
		gotA.Hits[0].ID == gotA.Hits[1].ID ||
		gotA.Hits[0].Title != title || gotA.Hits[1].Title != title {
		t.Fatal("synthetic exact hits or truncation incorrect")
	}
	if gotA.VaultID != f.firstVaultID || gotA.ConfigPath != f.firstConfig {
		t.Fatal("A exact scope mismatch")
	}

	localGenesisExactQueryProjectionForTest = func() []personal.VaultFileBaselineItem {
		return []personal.VaultFileBaselineItem{{ID: "b-item-1", Title: title}}
	}
	gotB, err := b.QueryExactTitle(LocalGenesisExactQuery{Title: title, Limit: 2})
	if err != nil {
		t.Fatal("synthetic B exact query failed")
	}
	if len(gotB.Hits) != 1 || gotB.Truncated || gotB.Hits[0].ID != "b-item-1" {
		t.Fatal("B exact hit or truncation incorrect")
	}
	if gotB.VaultID == gotA.VaultID || gotB.ConfigPath == gotA.ConfigPath ||
		gotB.Hits[0].ID == gotA.Hits[0].ID {
		t.Fatal("same-name per-vault identities merged")
	}

	oversized := make([]personal.VaultFileBaselineItem, LocalGenesisExactQueryScanItemsMax+1)
	for i := range oversized {
		oversized[i] = personal.VaultFileBaselineItem{ID: "oversized", Title: title}
	}
	localGenesisExactQueryProjectionForTest = func() []personal.VaultFileBaselineItem { return oversized }
	if _, err := a.QueryExactTitle(LocalGenesisExactQuery{Title: title, Limit: 1}); !errors.Is(err, ErrLocalGenesisExactQueryBound) {
		t.Fatal("oversized projection did not return the bound error")
	}

	localGenesisExactQueryProjectionForTest = func() []personal.VaultFileBaselineItem {
		return []personal.VaultFileBaselineItem{{ID: "b-item-2", Title: title}}
	}
	gotB2, err := b.QueryExactTitle(LocalGenesisExactQuery{Title: title, Limit: 1})
	if err != nil || len(gotB2.Hits) != 1 || gotB2.Hits[0].ID != "b-item-2" {
		t.Fatal("A bound error affected B")
	}
}

func TestLocalGenesisExactQueryStaleAKeepsB(t *testing.T) {
	f := newLocalGenesisTwoVaultFixture(t)
	a, _ := f.open(t, f.firstConfig, f.firstVaultID)
	t.Cleanup(func() { _ = a.Close() })
	b, _ := f.open(t, f.secondConfig, f.secondVaultID)
	t.Cleanup(func() { _ = b.Close() })

	companionPath, err := CompanionPath(f.firstConfig)
	if err != nil {
		t.Fatal("A companion path unavailable")
	}
	original, err := os.ReadFile(companionPath)
	if err != nil {
		t.Fatal("A companion read failed")
	}
	t.Cleanup(func() { _ = os.WriteFile(companionPath, original, 0600) })
	replaceLocalGenesisFileStable(t, companionPath, []byte("{}"))

	if _, err := a.QueryExactTitle(LocalGenesisExactQuery{Title: "stale-title", Limit: 1}); err == nil {
		t.Fatal("stale A query succeeded")
	}
	gotB, err := b.QueryExactTitle(LocalGenesisExactQuery{Title: "stale-title", Limit: 1})
	if err != nil {
		t.Fatal("stale A affected B")
	}
	if gotB.VaultID != f.secondVaultID || gotB.ConfigPath != f.secondConfig ||
		len(gotB.Hits) != 0 || gotB.Truncated {
		t.Fatal("B exact result not preserved")
	}
}

func TestLocalGenesisExactQueryValidation(t *testing.T) {
	var nilSession *LocalGenesisSession
	if _, err := nilSession.QueryExactTitle(LocalGenesisExactQuery{Title: "x", Limit: 1}); !errors.Is(err, ErrLocalReview) {
		t.Fatal("nil session did not return local review")
	}

	f := newLocalGenesisTwoVaultFixture(t)
	a, _ := f.open(t, f.firstConfig, f.firstVaultID)
	t.Cleanup(func() { _ = a.Close() })

	cases := []LocalGenesisExactQuery{
		{Title: "", Limit: 1},
		{Title: "x", Limit: 0},
		{Title: "x", Limit: LocalGenesisExactQueryHitsMax + 1},
		{Title: strings.Repeat("x", LocalGenesisExactQueryTitleBytesMax+1), Limit: 1},
	}
	for _, query := range cases {
		if _, err := a.QueryExactTitle(query); !errors.Is(err, ErrLocalGenesisExactQueryBound) {
			t.Fatal("invalid exact query did not return the bound error")
		}
	}

	got, err := a.QueryExactTitle(LocalGenesisExactQuery{Title: "valid-title", Limit: 1})
	if err != nil || len(got.Hits) != 0 || got.Truncated {
		t.Fatal("valid query after validation errors failed")
	}
}
