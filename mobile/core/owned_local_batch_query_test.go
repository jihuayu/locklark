package mobilecore

import (
	"bytes"
	"errors"
	"testing"

	"github.com/jihuayu/locklark/internal/vaultfileclient"
)

func mobileOwnedReopenVault(t *testing.T, fx *mobileOwnedLocalFixture) *Vault {
	t.Helper()
	v, err := Open(fx.accountPath)
	if err != nil {
		t.Fatal("MOBILE_OWNED_BATCH_REOPEN_OPEN_FAILED")
	}
	if err := v.Unlock(bytes.Clone(fx.password), bytes.Clone(fx.key)); err != nil {
		v.Close()
		t.Fatal("MOBILE_OWNED_BATCH_REOPEN_UNLOCK_FAILED")
	}
	t.Cleanup(v.Close)
	return v
}

func mobileOwnedAddTarget(t *testing.T, targets *OwnedLocalExactTargets, config string, manifest vaultfileclient.Manifest) {
	t.Helper()
	if err := targets.Add(config, manifest.VaultID, manifest.Journal); err != nil {
		t.Fatal("MOBILE_OWNED_BATCH_TARGET_ADD_FAILED")
	}
}

func mobileOwnedBatchSearch(t *testing.T, v *Vault, workspaceRoot, title string, limit int, targets *OwnedLocalExactTargets, password, key []byte) (*OwnedLocalExactBatchResult, error) {
	t.Helper()
	pw, sk := bytes.Clone(password), bytes.Clone(key)
	result, err := v.SearchOwnedLocalExactBatch(workspaceRoot, title, limit, targets, pw, sk)
	mobileOwnedAssertCleared(t, pw)
	mobileOwnedAssertCleared(t, sk)
	return result, err
}

func mobileOwnedBatchEntry(t *testing.T, result *OwnedLocalExactBatchResult, index int) *OwnedLocalExactBatchEntry {
	t.Helper()
	if result == nil {
		t.Fatal("MOBILE_OWNED_BATCH_RESULT_MISSING")
	}
	entry, err := result.At(index)
	if err != nil || entry == nil {
		t.Fatal("MOBILE_OWNED_BATCH_ENTRY_MISSING")
	}
	return entry
}

func mobileOwnedAssertBatchBounds(t *testing.T, result *OwnedLocalExactBatchResult) {
	t.Helper()
	if result == nil || result.Count() < 0 {
		t.Fatal("MOBILE_OWNED_BATCH_RESULT_INVALID")
	}
	if _, err := result.At(-1); !errors.Is(err, errInvalid) {
		t.Fatal("MOBILE_OWNED_BATCH_RESULT_NEGATIVE_INDEX_ACCEPTED")
	}
	if _, err := result.At(result.Count()); !errors.Is(err, errInvalid) {
		t.Fatal("MOBILE_OWNED_BATCH_RESULT_OVERRUN_ACCEPTED")
	}
}

func mobileOwnedAssertBatchEntryBounds(t *testing.T, entry *OwnedLocalExactBatchEntry) {
	t.Helper()
	if entry == nil || entry.Count() < 0 {
		t.Fatal("MOBILE_OWNED_BATCH_ENTRY_INVALID")
	}
	if _, err := entry.At(-1); !errors.Is(err, errInvalid) {
		t.Fatal("MOBILE_OWNED_BATCH_ENTRY_NEGATIVE_INDEX_ACCEPTED")
	}
	if _, err := entry.At(entry.Count()); !errors.Is(err, errInvalid) {
		t.Fatal("MOBILE_OWNED_BATCH_ENTRY_OVERRUN_ACCEPTED")
	}
}

func mobileOwnedAssertBatchHit(t *testing.T, result *OwnedLocalExactBatchResult, index int, item vaultfileclient.LocalGenesisFirstItem, manifest vaultfileclient.Manifest, revision string) {
	t.Helper()
	entry := mobileOwnedBatchEntry(t, result, index)
	if entry.VaultID != manifest.VaultID || entry.Status != OwnedLocalExactStatusOK ||
		entry.BackendRevision != revision || entry.BackendRevision == "" ||
		entry.Truncated || entry.Count() != 1 {
		t.Fatal("MOBILE_OWNED_BATCH_HIT_BINDING_FAILED")
	}
	mobileOwnedAssertBatchEntryBounds(t, entry)
	hit, err := entry.At(0)
	if err != nil || hit == nil || hit.ID != item.ID || hit.Title != item.Title {
		t.Fatal("MOBILE_OWNED_BATCH_HIT_VALUE_FAILED")
	}
}

func mobileOwnedAssertBatchZero(t *testing.T, result *OwnedLocalExactBatchResult, index int, manifest vaultfileclient.Manifest, revision string) {
	t.Helper()
	entry := mobileOwnedBatchEntry(t, result, index)
	if entry.VaultID != manifest.VaultID || entry.Status != OwnedLocalExactStatusOK ||
		entry.BackendRevision != revision || entry.BackendRevision == "" ||
		entry.Truncated || entry.Count() != 0 {
		t.Fatal("MOBILE_OWNED_BATCH_ZERO_HIT_BINDING_FAILED")
	}
	mobileOwnedAssertBatchEntryBounds(t, entry)
}

func mobileOwnedAssertBatchFailure(t *testing.T, result *OwnedLocalExactBatchResult, index int, vaultID, wantStatus string) {
	t.Helper()
	entry := mobileOwnedBatchEntry(t, result, index)
	if entry.VaultID != vaultID || entry.Status == OwnedLocalExactStatusOK {
		t.Fatal("MOBILE_OWNED_BATCH_FAILURE_STATUS_FAILED")
	}
	if wantStatus != "" && entry.Status != wantStatus {
		t.Fatal("MOBILE_OWNED_BATCH_FAILURE_STATUS_MISMATCH")
	}
	if entry.Status != OwnedLocalExactStatusRefused && entry.Status != OwnedLocalExactStatusUnavailable {
		t.Fatal("MOBILE_OWNED_BATCH_FAILURE_STATUS_UNBOUNDED")
	}
	if entry.BackendRevision != "" || entry.Truncated || entry.Count() != 0 {
		t.Fatal("MOBILE_OWNED_BATCH_FAILURE_EXPOSED_CONTENT")
	}
	mobileOwnedAssertBatchEntryBounds(t, entry)
}

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

func TestMobileOwnedLocalExactBatchIndependentTwoVaults(t *testing.T) {
	fx := newMobileOwnedLocalFixture(t)
	v := mobileOwnedReopenVault(t, fx)
	root := fx.manifestA.BackendRoot
	if root == "" || root != fx.manifestB.BackendRoot {
		t.Fatal("MOBILE_OWNED_BATCH_WORKSPACE_NOT_SHARED")
	}
	backendA, backendRevisionA := mobileOwnedReadBackend(t, fx.manifestA)
	defer clear(backendA)
	backendB, backendRevisionB := mobileOwnedReadBackend(t, fx.manifestB)
	defer clear(backendB)
	if backendRevisionA != fx.revisionA || backendRevisionB != fx.revisionB ||
		backendRevisionA == "" || backendRevisionB == "" ||
		backendRevisionA == backendRevisionB {
		t.Fatal("MOBILE_OWNED_BATCH_PERSISTED_REVISIONS_MISMATCH")
	}
	if fx.itemA.Title != fx.itemB.Title || fx.itemA.ID == fx.itemB.ID {
		t.Fatal("MOBILE_OWNED_BATCH_ITEMS_NOT_DISTINCT")
	}
	beforeA := mobileOwnedScopeFingerprint(t, fx.configA, fx.manifestA)
	beforeB := mobileOwnedScopeFingerprint(t, fx.configB, fx.manifestB)
	beforeC := mobileOwnedScopeFingerprint(t, fx.configC, fx.manifestC)

	// Exact duplicate A must collapse to one read while preserving both
	// original indexes; B remains independently bound.
	targets := NewOwnedLocalExactTargets()
	if targets == nil || targets.Count() != 0 {
		t.Fatal("MOBILE_OWNED_BATCH_TARGETS_CONSTRUCTOR_FAILED")
	}
	mobileOwnedAddTarget(t, targets, fx.configA, fx.manifestA)
	mobileOwnedAddTarget(t, targets, fx.configA, fx.manifestA)
	mobileOwnedAddTarget(t, targets, fx.configB, fx.manifestB)
	if targets.Count() != 3 {
		t.Fatal("MOBILE_OWNED_BATCH_TARGETS_COUNT_FAILED")
	}
	result, err := mobileOwnedBatchSearch(t, v, root, mobileOwnedLocalTitle, 2, targets, fx.password, fx.key)
	if err != nil {
		t.Fatal("MOBILE_OWNED_BATCH_SUCCESS_FAILED")
	}
	if result.Count() != 3 {
		t.Fatal("MOBILE_OWNED_BATCH_RESULT_ORDER_LOST")
	}
	mobileOwnedAssertBatchHit(t, result, 0, fx.itemA, fx.manifestA, fx.revisionA)
	mobileOwnedAssertBatchHit(t, result, 1, fx.itemA, fx.manifestA, fx.revisionA)
	mobileOwnedAssertBatchHit(t, result, 2, fx.itemB, fx.manifestB, fx.revisionB)
	mobileOwnedAssertBatchBounds(t, result)
	entry0, _ := result.At(0)
	entry1, _ := result.At(1)
	hit0, _ := entry0.At(0)
	hit1, _ := entry1.At(0)
	if hit0.ID != hit1.ID || hit0.Title != hit1.Title {
		t.Fatal("MOBILE_OWNED_BATCH_DUPLICATE_DIVERGED")
	}
	var nilResult *OwnedLocalExactBatchResult
	if nilResult.Count() != 0 {
		t.Fatal("MOBILE_OWNED_BATCH_NIL_RESULT_COUNT")
	}
	if _, err := nilResult.At(0); !errors.Is(err, errInvalid) {
		t.Fatal("MOBILE_OWNED_BATCH_NIL_RESULT_INDEX_ACCEPTED")
	}
	var nilEntry *OwnedLocalExactBatchEntry
	if nilEntry.Count() != 0 {
		t.Fatal("MOBILE_OWNED_BATCH_NIL_ENTRY_COUNT")
	}
	if _, err := nilEntry.At(0); !errors.Is(err, errInvalid) {
		t.Fatal("MOBILE_OWNED_BATCH_NIL_ENTRY_INDEX_ACCEPTED")
	}

	// Zero hits is a successful target, not a failure status.
	zeroTargets := NewOwnedLocalExactTargets()
	mobileOwnedAddTarget(t, zeroTargets, fx.configA, fx.manifestA)
	mobileOwnedAddTarget(t, zeroTargets, fx.configB, fx.manifestB)
	zero, err := mobileOwnedBatchSearch(t, v, root, "no-such-owned-local-exact-title", 2, zeroTargets, fx.password, fx.key)
	if err != nil {
		t.Fatal("MOBILE_OWNED_BATCH_ZERO_QUERY_FAILED")
	}
	if zero.Count() != 2 {
		t.Fatal("MOBILE_OWNED_BATCH_ZERO_RESULT_COUNT")
	}
	mobileOwnedAssertBatchZero(t, zero, 0, fx.manifestA, fx.revisionA)
	mobileOwnedAssertBatchZero(t, zero, 1, fx.manifestB, fx.revisionB)

	// A mismatched claimed journal is refused without opening the target.
	mismatchTargets := NewOwnedLocalExactTargets()
	if err := mismatchTargets.Add(fx.configA, fx.manifestA.VaultID, fx.manifestB.Journal); err != nil {
		t.Fatal("MOBILE_OWNED_BATCH_MISMATCH_ADD_FAILED")
	}
	mismatch, err := mobileOwnedBatchSearch(t, v, root, mobileOwnedLocalTitle, 2, mismatchTargets, fx.password, fx.key)
	if err != nil {
		t.Fatal("MOBILE_OWNED_BATCH_MISMATCH_QUERY_FAILED")
	}
	if mismatch.Count() != 1 {
		t.Fatal("MOBILE_OWNED_BATCH_MISMATCH_RESULT_COUNT")
	}
	mobileOwnedAssertBatchFailure(t, mismatch, 0, fx.manifestA.VaultID, OwnedLocalExactStatusRefused)

	// A real foreign-account tuple stays denied while its valid sibling is
	// still delivered independently.
	foreignTargets := NewOwnedLocalExactTargets()
	mobileOwnedAddTarget(t, foreignTargets, fx.configA, fx.manifestA)
	mobileOwnedAddTarget(t, foreignTargets, fx.configC, fx.manifestC)
	foreign, err := mobileOwnedBatchSearch(t, v, root, mobileOwnedLocalTitle, 2, foreignTargets, fx.password, fx.key)
	if err != nil {
		t.Fatal("MOBILE_OWNED_BATCH_FOREIGN_QUERY_FAILED")
	}
	if foreign.Count() != 2 {
		t.Fatal("MOBILE_OWNED_BATCH_FOREIGN_RESULT_COUNT")
	}
	mobileOwnedAssertBatchHit(t, foreign, 0, fx.itemA, fx.manifestA, fx.revisionA)
	mobileOwnedAssertBatchFailure(t, foreign, 1, fx.manifestC.VaultID, OwnedLocalExactStatusRefused)

	// Differing locators that share a config path, journal path or vault ID
	// are conflicts; the independent B entry still succeeds.
	aliasTargets := NewOwnedLocalExactTargets()
	mobileOwnedAddTarget(t, aliasTargets, fx.configA, fx.manifestA)
	if err := aliasTargets.Add(fx.configA, fx.manifestA.VaultID, fx.manifestC.Journal); err != nil {
		t.Fatal("MOBILE_OWNED_BATCH_ALIAS_CONFIG_ADD_FAILED")
	}
	if err := aliasTargets.Add(fx.configC, fx.manifestC.VaultID, fx.manifestA.Journal); err != nil {
		t.Fatal("MOBILE_OWNED_BATCH_ALIAS_JOURNAL_ADD_FAILED")
	}
	mobileOwnedAddTarget(t, aliasTargets, fx.configB, fx.manifestB)
	aliases, err := mobileOwnedBatchSearch(t, v, root, mobileOwnedLocalTitle, 2, aliasTargets, fx.password, fx.key)
	if err != nil {
		t.Fatal("MOBILE_OWNED_BATCH_ALIAS_QUERY_FAILED")
	}
	if aliases.Count() != 4 {
		t.Fatal("MOBILE_OWNED_BATCH_ALIAS_RESULT_COUNT")
	}
	mobileOwnedAssertBatchFailure(t, aliases, 0, fx.manifestA.VaultID, OwnedLocalExactStatusRefused)
	mobileOwnedAssertBatchFailure(t, aliases, 1, fx.manifestA.VaultID, OwnedLocalExactStatusRefused)
	mobileOwnedAssertBatchFailure(t, aliases, 2, fx.manifestC.VaultID, OwnedLocalExactStatusRefused)
	mobileOwnedAssertBatchHit(t, aliases, 3, fx.itemB, fx.manifestB, fx.revisionB)

	if err := aliasTargets.Add("relative-config", "vault", "relative-journal"); !errors.Is(err, errInvalid) {
		t.Fatal("MOBILE_OWNED_BATCH_INVALID_TARGET_ACCEPTED")
	}

	if afterA := mobileOwnedScopeFingerprint(t, fx.configA, fx.manifestA); afterA != beforeA {
		t.Fatal("MOBILE_OWNED_BATCH_WROTE_A")
	}
	if afterB := mobileOwnedScopeFingerprint(t, fx.configB, fx.manifestB); afterB != beforeB {
		t.Fatal("MOBILE_OWNED_BATCH_WROTE_B")
	}
	if afterC := mobileOwnedScopeFingerprint(t, fx.configC, fx.manifestC); afterC != beforeC {
		t.Fatal("MOBILE_OWNED_BATCH_WROTE_C")
	}
	if !v.IsUnlocked() {
		t.Fatal("MOBILE_OWNED_BATCH_LOCKED_ACCOUNT")
	}
}

func TestMobileOwnedLocalExactBatchBackendDriftKeepsSibling(t *testing.T) {
	fx := newMobileOwnedLocalFixture(t)
	v := mobileOwnedReopenVault(t, fx)
	root := fx.manifestA.BackendRoot
	beforeA := mobileOwnedScopeFingerprint(t, fx.configA, fx.manifestA)
	beforeB := mobileOwnedScopeFingerprint(t, fx.configB, fx.manifestB)
	backendB, revisionBefore := mobileOwnedReadBackend(t, fx.manifestB)
	defer clear(backendB)
	updated := mobileOwnedRewriteBackend(t, fx.manifestB, backendB)
	backendAfter, revisionAfter := mobileOwnedReadBackend(t, fx.manifestB)
	defer clear(backendAfter)
	if updated == revisionBefore || revisionAfter != updated ||
		!bytes.Equal(backendB, backendAfter) {
		t.Fatal("MOBILE_OWNED_BATCH_DRIFT_NOT_REAL")
	}
	driftedB := mobileOwnedScopeFingerprint(t, fx.configB, fx.manifestB)
	if driftedB == beforeB {
		t.Fatal("MOBILE_OWNED_BATCH_DRIFT_NOT_OBSERVED")
	}

	targets := NewOwnedLocalExactTargets()
	mobileOwnedAddTarget(t, targets, fx.configA, fx.manifestA)
	mobileOwnedAddTarget(t, targets, fx.configB, fx.manifestB)
	result, err := mobileOwnedBatchSearch(t, v, root, mobileOwnedLocalTitle, 2, targets, fx.password, fx.key)
	if err != nil {
		t.Fatal("MOBILE_OWNED_BATCH_DRIFT_QUERY_FAILED")
	}
	if result.Count() != 2 {
		t.Fatal("MOBILE_OWNED_BATCH_DRIFT_RESULT_COUNT")
	}
	mobileOwnedAssertBatchHit(t, result, 0, fx.itemA, fx.manifestA, fx.revisionA)
	mobileOwnedAssertBatchFailure(t, result, 1, fx.manifestB.VaultID, "")
	driftedEntry := mobileOwnedBatchEntry(t, result, 1)
	if driftedEntry.Status != OwnedLocalExactStatusRefused &&
		driftedEntry.Status != OwnedLocalExactStatusUnavailable {
		t.Fatal("MOBILE_OWNED_BATCH_DRIFT_STATUS_UNBOUNDED")
	}
	if afterA := mobileOwnedScopeFingerprint(t, fx.configA, fx.manifestA); afterA != beforeA {
		t.Fatal("MOBILE_OWNED_BATCH_DRIFT_WROTE_A")
	}
	if afterB := mobileOwnedScopeFingerprint(t, fx.configB, fx.manifestB); afterB != driftedB {
		t.Fatal("MOBILE_OWNED_BATCH_DRIFT_WROTE_B")
	}
	if !v.IsUnlocked() {
		t.Fatal("MOBILE_OWNED_BATCH_DRIFT_LOCKED_ACCOUNT")
	}
}

func TestMobileOwnedLocalExactBatchRefusesExistingChild(t *testing.T) {
	fx := newMobileOwnedLocalFixture(t)
	v := mobileOwnedReopenVault(t, fx)
	root := fx.manifestA.BackendRoot
	beforeA := mobileOwnedScopeFingerprint(t, fx.configA, fx.manifestA)
	beforeB := mobileOwnedScopeFingerprint(t, fx.configB, fx.manifestB)
	s, _, err := v.active()
	if err != nil || s == nil {
		t.Fatal("MOBILE_OWNED_BATCH_EXISTING_ACTIVE_FAILED")
	}
	existing, _, err := vaultfileclient.OpenLocalGenesisSessionForJournal(
		s, fx.configA, root, fx.manifestA.VaultID, fx.manifestA.Journal,
		bytes.Clone(fx.password), bytes.Clone(fx.key))
	if err != nil || existing == nil {
		t.Fatal("MOBILE_OWNED_BATCH_EXISTING_OPEN_FAILED")
	}
	t.Cleanup(func() { _ = existing.Close() })

	targets := NewOwnedLocalExactTargets()
	mobileOwnedAddTarget(t, targets, fx.configA, fx.manifestA)
	mobileOwnedAddTarget(t, targets, fx.configB, fx.manifestB)
	result, err := mobileOwnedBatchSearch(t, v, root, mobileOwnedLocalTitle, 2, targets, fx.password, fx.key)
	if err != nil {
		t.Fatal("MOBILE_OWNED_BATCH_EXISTING_QUERY_FAILED")
	}
	if result.Count() != 2 {
		t.Fatal("MOBILE_OWNED_BATCH_EXISTING_RESULT_COUNT")
	}
	mobileOwnedAssertBatchFailure(t, result, 0, fx.manifestA.VaultID, OwnedLocalExactStatusRefused)
	mobileOwnedAssertBatchHit(t, result, 1, fx.itemB, fx.manifestB, fx.revisionB)

	// The pre-existing legitimate child must still read its own exact title.
	raw, err := existing.QueryExactTitle(vaultfileclient.LocalGenesisExactQuery{
		Title: mobileOwnedLocalTitle, Limit: 2,
	})
	if err != nil || raw.VaultID != fx.manifestA.VaultID || len(raw.Hits) != 1 ||
		raw.Hits[0].ID != fx.itemA.ID || raw.Hits[0].Title != mobileOwnedLocalTitle {
		t.Fatal("MOBILE_OWNED_BATCH_EXISTING_CHILD_REPLACED")
	}
	clearOwnedLocalRawHits(raw.Hits)
	if err := existing.Close(); err != nil {
		t.Fatal("MOBILE_OWNED_BATCH_EXISTING_CLOSE_FAILED")
	}

	// After the legitimate child closes, the aggregate may open A normally.
	afterTargets := NewOwnedLocalExactTargets()
	mobileOwnedAddTarget(t, afterTargets, fx.configA, fx.manifestA)
	afterResult, err := mobileOwnedBatchSearch(t, v, root, mobileOwnedLocalTitle, 2, afterTargets, fx.password, fx.key)
	if err != nil {
		t.Fatal("MOBILE_OWNED_BATCH_EXISTING_REOPEN_QUERY_FAILED")
	}
	if afterResult.Count() != 1 {
		t.Fatal("MOBILE_OWNED_BATCH_EXISTING_REOPEN_RESULT_COUNT")
	}
	mobileOwnedAssertBatchHit(t, afterResult, 0, fx.itemA, fx.manifestA, fx.revisionA)

	if afterA := mobileOwnedScopeFingerprint(t, fx.configA, fx.manifestA); afterA != beforeA {
		t.Fatal("MOBILE_OWNED_BATCH_EXISTING_WROTE_A")
	}
	if afterB := mobileOwnedScopeFingerprint(t, fx.configB, fx.manifestB); afterB != beforeB {
		t.Fatal("MOBILE_OWNED_BATCH_EXISTING_WROTE_B")
	}
	if !v.IsUnlocked() {
		t.Fatal("MOBILE_OWNED_BATCH_EXISTING_LOCKED_ACCOUNT")
	}
}

func TestMobileOwnedLocalExactBatchRequestLockWithholdsAggregate(t *testing.T) {
	fx := newMobileOwnedLocalFixture(t)
	v := mobileOwnedReopenVault(t, fx)
	root := fx.manifestA.BackendRoot
	view, err := v.CaptureOperation()
	if err != nil {
		t.Fatal("MOBILE_OWNED_BATCH_LOCK_CAPTURE_FAILED")
	}
	targets := NewOwnedLocalExactTargets()
	mobileOwnedAddTarget(t, targets, fx.configA, fx.manifestA)
	mobileOwnedAddTarget(t, targets, fx.configB, fx.manifestB)

	entered, release := make(chan struct{}), make(chan struct{})
	oldHook := ownedLocalBeforeGrantForTest
	ownedLocalBeforeGrantForTest = func() {
		close(entered)
		<-release
	}
	t.Cleanup(func() { ownedLocalBeforeGrantForTest = oldHook })

	type outcome struct {
		result *OwnedLocalExactBatchResult
		err    error
		leaked bool
	}
	done := make(chan outcome, 1)
	go func() {
		pw, sk := bytes.Clone(fx.password), bytes.Clone(fx.key)
		result, err := view.SearchOwnedLocalExactBatch(root, mobileOwnedLocalTitle, 2, targets, pw, sk)
		leaked := false
		for _, b := range append(append([]byte(nil), pw...), sk...) {
			if b != 0 {
				leaked = true
				break
			}
		}
		done <- outcome{result: result, err: err, leaked: leaked}
	}()
	<-entered
	v.RequestLock()
	close(release)
	finished := <-done
	ownedLocalBeforeGrantForTest = oldHook
	if finished.result != nil || finished.err == nil || !errors.Is(finished.err, errLocked) {
		t.Fatal("MOBILE_OWNED_BATCH_LOCK_REVEALED_AGGREGATE")
	}
	if finished.leaked {
		t.Fatal("MOBILE_OWNED_BATCH_LOCK_RETAINED_FACTORS")
	}
	if v.IsUnlocked() {
		t.Fatal("MOBILE_OWNED_BATCH_LOCK_WAS_LATE")
	}

	if err := v.Unlock(bytes.Clone(fx.password), bytes.Clone(fx.key)); err != nil {
		t.Fatal("MOBILE_OWNED_BATCH_LOCK_REUNLOCK_FAILED")
	}
	after, err := mobileOwnedBatchSearch(t, v, root, mobileOwnedLocalTitle, 2, targets, fx.password, fx.key)
	if err != nil {
		t.Fatal("MOBILE_OWNED_BATCH_LOCK_REOPEN_FAILED")
	}
	if after.Count() != 2 {
		t.Fatal("MOBILE_OWNED_BATCH_LOCK_REOPEN_RESULT_COUNT")
	}
	mobileOwnedAssertBatchHit(t, after, 0, fx.itemA, fx.manifestA, fx.revisionA)
	mobileOwnedAssertBatchHit(t, after, 1, fx.itemB, fx.manifestB, fx.revisionB)
}
