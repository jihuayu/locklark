//go:build darwin || linux

package vaultfileclient

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/vault"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
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

	// Use the projection seam to exercise the scanner's boundary.
	atCap := make([]personal.VaultFileBaselineItem, vault.MaxItems)
	atCap[len(atCap)-1] = gotA.Hits[0]
	localGenesisExactQueryProjectionForTest = func() []personal.VaultFileBaselineItem { return atCap }
	query := LocalGenesisExactQuery{Title: title, Limit: 1}
	got, err := a.QueryExactTitle(query)
	if err != nil || len(got.Hits) != 1 || got.Truncated || got.Hits[0] != gotA.Hits[0] {
		t.Fatal("query at the scan cap must return the final matching item")
	}

	oversized := make([]personal.VaultFileBaselineItem, vault.MaxItems+1)
	oversized[0] = gotA.Hits[0]
	localGenesisExactQueryProjectionForTest = func() []personal.VaultFileBaselineItem { return oversized }
	got, err = a.QueryExactTitle(query)
	if !errors.Is(err, ErrLocalGenesisExactQueryBound) || len(got.Hits) != 0 || got.Truncated || got.activation != nil {
		t.Fatal("query above the scan cap must fail without returning a partial result")
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

func installLocalGenesisActivationProjection(t *testing.T, items *[]personal.VaultFileBaselineItem) {
	t.Helper()
	old := localGenesisExactQueryProjectionForTest
	localGenesisExactQueryProjectionForTest = func() []personal.VaultFileBaselineItem {
		return append([]personal.VaultFileBaselineItem(nil), (*items)...)
	}
	t.Cleanup(func() { localGenesisExactQueryProjectionForTest = old })
}

func mustLocalGenesisActivationQuery(t *testing.T, session *LocalGenesisSession, title string) LocalGenesisExactQueryResult {
	t.Helper()
	result, err := session.QueryExactTitle(LocalGenesisExactQuery{Title: title, Limit: 1})
	if err != nil || len(result.Hits) != 1 {
		t.Fatal("QUERY_HIT_MISSING")
	}
	return result
}

func TestLocalGenesisExactQueryActivationReceiver(t *testing.T) {
	f := newLocalGenesisTwoVaultFixture(t)
	a, _ := f.open(t, f.firstConfig, f.firstVaultID)
	defer a.Close()
	b, _ := f.open(t, f.secondConfig, f.secondVaultID)
	defer b.Close()

	hit := personal.VaultFileBaselineItem{ID: f.firstVaultID, Title: t.Name()}
	items := []personal.VaultFileBaselineItem{hit}
	installLocalGenesisActivationProjection(t, &items)
	result := mustLocalGenesisActivationQuery(t, a, hit.Title)
	sibling := mustLocalGenesisActivationQuery(t, b, hit.Title)
	if err := a.ValidateExactQueryHit(result, hit.ID, hit.Title); err != nil {
		t.Fatal("ORIGINAL_RECEIVER_REJECTED")
	}
	copied := *a
	if err := copied.ValidateExactQueryHit(result, hit.ID, hit.Title); !errors.Is(err, ErrLocalReview) {
		t.Fatal("COPIED_RECEIVER_ACCEPTED")
	}
	if err := b.ValidateExactQueryHit(result, hit.ID, hit.Title); !errors.Is(err, ErrLocalReview) {
		t.Fatal("SIBLING_RECEIVER_ACCEPTED")
	}
	if err := a.Close(); err != nil {
		t.Fatal("ORIGINAL_CLOSE_FAILED")
	}
	if err := a.ValidateExactQueryHit(result, hit.ID, hit.Title); err == nil {
		t.Fatal("CLOSED_RECEIVER_ACCEPTED")
	}
	reopened, _ := f.open(t, f.firstConfig, f.firstVaultID)
	defer reopened.Close()
	fresh := mustLocalGenesisActivationQuery(t, reopened, hit.Title)
	if fresh.binding() != result.binding() || fresh.Hits[0] != result.Hits[0] {
		t.Fatal("REOPENED_EQUIVALENCE_MISSING")
	}
	if err := reopened.ValidateExactQueryHit(result, hit.ID, hit.Title); !errors.Is(err, ErrLocalReview) {
		t.Fatal("REOPENED_RECEIVER_ACCEPTED_OLD_HIT")
	}
	if err := reopened.ValidateExactQueryHit(fresh, hit.ID, hit.Title); err != nil {
		t.Fatal("REOPENED_RECEIVER_REJECTED_FRESH_HIT")
	}
	if err := b.ValidateExactQueryHit(sibling, hit.ID, hit.Title); err != nil {
		t.Fatal("SIBLING_HIT_LOST")
	}
}

func TestLocalGenesisExactQueryActivationImmutableResult(t *testing.T) {
	f := newLocalGenesisTwoVaultFixture(t)
	a, _ := f.open(t, f.firstConfig, f.firstVaultID)
	defer a.Close()

	hit := personal.VaultFileBaselineItem{ID: f.firstVaultID, Title: t.Name()}
	other := personal.VaultFileBaselineItem{ID: f.secondVaultID, Title: hit.Title}
	items := []personal.VaultFileBaselineItem{hit, other}
	installLocalGenesisActivationProjection(t, &items)
	result := mustLocalGenesisActivationQuery(t, a, hit.Title)
	if !result.Truncated || result.Hits[0] != hit {
		t.Fatal("LIMITED_QUERY_SETUP_FAILED")
	}

	for _, mutate := range []func(*LocalGenesisExactQueryResult){
		func(r *LocalGenesisExactQueryResult) { r.ConfigPath = f.secondConfig },
		func(r *LocalGenesisExactQueryResult) { r.WorkspaceRoot = f.secondConfig },
		func(r *LocalGenesisExactQueryResult) { r.VaultID = f.secondVaultID },
		func(r *LocalGenesisExactQueryResult) { r.JournalPath = f.secondConfig },
		func(r *LocalGenesisExactQueryResult) { r.ManifestSHA256 = t.Name() },
		func(r *LocalGenesisExactQueryResult) { r.JournalRevision = t.Name() },
		func(r *LocalGenesisExactQueryResult) { r.Truncated = false },
	} {
		changed := result
		mutate(&changed)
		if err := a.ValidateExactQueryHit(changed, hit.ID, hit.Title); !errors.Is(err, ErrLocalReview) {
			t.Fatal("ALTERED_RESULT_ACCEPTED")
		}
	}
	result.Hits[0] = other
	if err := a.ValidateExactQueryHit(result, other.ID, other.Title); !errors.Is(err, ErrLocalReview) {
		t.Fatal("UNRETURNED_ITEM_ACCEPTED")
	}
	forged := result
	forged.activation = nil
	if err := a.ValidateExactQueryHit(forged, hit.ID, hit.Title); !errors.Is(err, ErrLocalReview) {
		t.Fatal("UNBOUND_RESULT_ACCEPTED")
	}
	if err := a.ValidateExactQueryHit(result, hit.ID, hit.Title); err != nil {
		t.Fatal("ORIGINAL_MEMBERSHIP_LOST")
	}

	items = []personal.VaultFileBaselineItem{other}
	if err := a.ValidateExactQueryHit(result, hit.ID, hit.Title); !errors.Is(err, ErrLocalReview) {
		t.Fatal("MISSING_ID_ACCEPTED")
	}
	changedHit := hit
	changedHit.Title += t.Name()
	items = []personal.VaultFileBaselineItem{changedHit}
	if err := a.ValidateExactQueryHit(result, hit.ID, hit.Title); !errors.Is(err, ErrLocalReview) {
		t.Fatal("CHANGED_TITLE_ACCEPTED")
	}
	items = []personal.VaultFileBaselineItem{hit}
	if err := a.ValidateExactQueryHit(result, hit.ID, hit.Title); err != nil {
		t.Fatal("CURRENT_HIT_REJECTED")
	}
}

func TestLocalGenesisExactQueryActivationStaleBinding(t *testing.T) {
	f := newLocalGenesisTwoVaultFixture(t)
	a, _ := f.open(t, f.firstConfig, f.firstVaultID)
	defer a.Close()
	b, _ := f.open(t, f.secondConfig, f.secondVaultID)
	defer b.Close()

	hit := personal.VaultFileBaselineItem{ID: f.firstVaultID, Title: t.Name()}
	items := []personal.VaultFileBaselineItem{hit}
	installLocalGenesisActivationProjection(t, &items)
	result := mustLocalGenesisActivationQuery(t, a, hit.Title)
	sibling := mustLocalGenesisActivationQuery(t, b, hit.Title)
	manifest, err := os.ReadFile(f.firstConfig)
	if err != nil {
		t.Fatal("MANIFEST_SETUP_FAILED")
	}
	replaceLocalGenesisFileStable(t, f.firstConfig, nil)
	if err := a.ValidateExactQueryHit(result, hit.ID, hit.Title); err == nil {
		t.Fatal("CHANGED_LOCATOR_ACCEPTED")
	}
	replaceLocalGenesisFileStable(t, f.firstConfig, manifest)
	restored, _ := f.open(t, f.firstConfig, f.firstVaultID)
	defer restored.Close()
	before := mustLocalGenesisActivationQuery(t, restored, hit.Title)

	journal, err := vaultfilejournal.OpenExisting(before.JournalPath)
	if err != nil {
		t.Fatal("JOURNAL_OPEN_FAILED")
	}
	state, readErr := journal.LoadGenesisBaseline()
	closeErr := journal.Close()
	if readErr != nil || closeErr != nil || len(state.RemoteRevision) == 0 {
		t.Fatal("JOURNAL_BASELINE_SETUP_FAILED")
	}
	defer clear(state.BaseBytes)
	defer clear(state.WorkingBytes)
	state.RemoteRevision += state.RemoteRevision[:1]
	nextPath := before.JournalPath + ".next"
	next, err := vaultfilejournal.Open(nextPath)
	if err != nil {
		t.Fatal("NEXT_JOURNAL_OPEN_FAILED")
	}
	writeErr := next.InitializeState(state)
	closeErr = next.Close()
	if writeErr != nil || closeErr != nil || os.Rename(nextPath, before.JournalPath) != nil {
		t.Fatal("JOURNAL_REVISION_SETUP_FAILED")
	}
	if err := restored.ValidateExactQueryHit(before, hit.ID, hit.Title); err == nil {
		t.Fatal("CHANGED_REVISION_ACCEPTED")
	}
	updated, _ := f.open(t, f.firstConfig, f.firstVaultID)
	defer updated.Close()
	after := mustLocalGenesisActivationQuery(t, updated, hit.Title)
	if after.JournalRevision == before.JournalRevision || after.ManifestSHA256 != before.ManifestSHA256 {
		t.Fatal("JOURNAL_REVISION_CHANGE_UNVERIFIED")
	}
	if err := updated.ValidateExactQueryHit(after, hit.ID, hit.Title); err != nil {
		t.Fatal("UPDATED_REVISION_REJECTED")
	}
	if err := b.ValidateExactQueryHit(sibling, hit.ID, hit.Title); err != nil {
		t.Fatal("SIBLING_HIT_LOST")
	}
}

func TestLocalGenesisExactQueryActivationLocks(t *testing.T) {
	f := newLocalGenesisTwoVaultFixture(t)
	a, _ := f.open(t, f.firstConfig, f.firstVaultID)
	defer a.Close()
	b, _ := f.open(t, f.secondConfig, f.secondVaultID)
	defer b.Close()

	hit := personal.VaultFileBaselineItem{ID: f.firstVaultID, Title: t.Name()}
	items := []personal.VaultFileBaselineItem{hit}
	installLocalGenesisActivationProjection(t, &items)
	result := mustLocalGenesisActivationQuery(t, a, hit.Title)
	sibling := mustLocalGenesisActivationQuery(t, b, hit.Title)

	old := localGenesisSummaryReadyForTest
	t.Cleanup(func() { localGenesisSummaryReadyForTest = old })
	var lockErr error
	locked := false
	localGenesisSummaryReadyForTest = func() {
		lockErr = a.Close()
		locked = true
	}
	err := a.ValidateExactQueryHit(result, hit.ID, hit.Title)
	localGenesisSummaryReadyForTest = old
	if !locked || lockErr != nil || err == nil {
		t.Fatal("LATE_CHILD_LOCK_NOT_ENFORCED")
	}
	if err := b.ValidateExactQueryHit(sibling, hit.ID, hit.Title); err != nil {
		t.Fatal("SIBLING_HIT_LOST")
	}
	f.session.Lock()
	if err := b.ValidateExactQueryHit(sibling, hit.ID, hit.Title); err == nil {
		t.Fatal("PARENT_LOCK_NOT_ENFORCED")
	}
}
