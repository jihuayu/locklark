//go:build darwin || linux

package vaultfileclient

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

// localQueryAssertRealExactHit requires one exact-title query over a reopened
// owned child to identify only the persisted item that the durable fixture
// independently verified, and to bind the result to that vault's real public
// locator and journal version.
func localQueryAssertRealExactHit(t *testing.T, wrapper *LocalGenesisSession, fx *localFirstWriteFixture, persisted localFirstSettledVault) LocalGenesisExactQueryResult {
	t.Helper()
	result, err := wrapper.QueryExactTitle(LocalGenesisExactQuery{Title: fx.item.Title, Limit: 2})
	if err != nil {
		t.Fatal("LOCAL_TWO_VAULT_QUERY_FAILED")
	}
	if result.ConfigPath != fx.config ||
		result.WorkspaceRoot != fx.manifest.BackendRoot ||
		result.VaultID != fx.manifest.VaultID ||
		result.JournalPath != fx.manifest.Journal ||
		result.ManifestSHA256 == "" || result.JournalRevision == "" {
		t.Fatal("LOCAL_TWO_VAULT_QUERY_PROVENANCE_FAILED")
	}
	if len(result.Hits) != 1 || result.Truncated ||
		result.Hits[0].ID != persisted.itemID ||
		result.Hits[0].ID != fx.item.ID ||
		result.Hits[0].Title != fx.item.Title {
		t.Fatal("LOCAL_TWO_VAULT_QUERY_HIT_FAILED")
	}
	return result
}

func localQueryAssertActivated(t *testing.T, wrapper *LocalGenesisSession, result LocalGenesisExactQueryResult) {
	t.Helper()
	if len(result.Hits) != 1 {
		t.Fatal("LOCAL_TWO_VAULT_ACTIVATION_HIT_FAILED")
	}
	if err := wrapper.ValidateExactQueryHit(result, result.Hits[0].ID, result.Hits[0].Title); err != nil {
		t.Fatal("LOCAL_TWO_VAULT_ACTIVATION_FAILED")
	}
}

func TestOwnedFirstWriteLocalTwoVaultsQueryAndActivation(t *testing.T) {
	f := newLocalGenesisTwoVaultFixture(t)
	fxA := newLocalFirstWriteFixtureFor(t, f, f.firstConfig, f.firstVaultID)
	fxB := newLocalFirstWriteFixtureFor(t, f, f.secondConfig, f.secondVaultID)

	if fxA.item.Title != fxB.item.Title || fxA.item.ID == fxB.item.ID {
		t.Fatal("LOCAL_TWO_VAULT_QUERY_IDENTITY_NOT_DISTINCT")
	}
	if fxA.manifest.PersonalFile != fxB.manifest.PersonalFile ||
		fxA.manifest.PersonalFile != f.f.proposal.PersonalFile {
		t.Fatal("LOCAL_TWO_VAULT_QUERY_ACCOUNT_NOT_SHARED")
	}
	if fxA.manifest.VaultID == fxB.manifest.VaultID ||
		fxA.manifest.Journal == fxB.manifest.Journal ||
		fxA.manifest.Name == fxB.manifest.Name ||
		fxA.config == fxB.config {
		t.Fatal("LOCAL_TWO_VAULT_QUERY_SCOPE_NOT_DISTINCT")
	}

	// Write each vault independently through the production first-item path.
	beforeA := localFirstObserveScope(t, fxA.manifest)
	defer beforeA.clear()
	beforeB := localFirstObserveScope(t, fxB.manifest)
	defer beforeB.clear()

	resultA, err := fxA.write(context.Background())
	if err != nil {
		t.Fatal("LOCAL_TWO_VAULT_QUERY_WRITE_A_FAILED")
	}
	localFirstAssertScopeUnchanged(t, beforeB, fxB.manifest, "LOCAL_TWO_VAULT_QUERY_B_CHANGED_BY_A")
	afterA := localFirstObserveScope(t, fxA.manifest)
	defer afterA.clear()
	evidenceA := localFirstAssertSettled(t, fxA, resultA, afterA)

	resultB, err := fxB.write(context.Background())
	if err != nil {
		t.Fatal("LOCAL_TWO_VAULT_QUERY_WRITE_B_FAILED")
	}
	localFirstAssertScopeUnchanged(t, afterA, fxA.manifest, "LOCAL_TWO_VAULT_QUERY_A_CHANGED_BY_B")
	afterB := localFirstObserveScope(t, fxB.manifest)
	defer afterB.clear()
	evidenceB := localFirstAssertSettled(t, fxB, resultB, afterB)

	if evidenceA.operationID == evidenceB.operationID || evidenceA.itemID == evidenceB.itemID ||
		resultA.OperationID == resultB.OperationID {
		t.Fatal("LOCAL_TWO_VAULT_QUERY_IDENTITIES_NOT_UNIQUE")
	}

	// Lock the write account session and unlock a fresh one from the persisted
	// account before opening either owned query child.
	fresh := localFirstUnlockFresh(t, f)
	wrapperA, summaryA, err := OpenLocalGenesisSessionForJournal(fresh, fxA.config,
		fxA.manifest.BackendRoot, fxA.manifest.VaultID, fxA.manifest.Journal,
		[]byte(f.f.password), f.f.key)
	if err != nil || wrapperA == nil {
		t.Fatal("LOCAL_TWO_VAULT_QUERY_A_OPEN_FAILED")
	}
	defer wrapperA.Close()
	localFirstAssertOrdinarySummary(t, wrapperA, summaryA, fxA)

	wrapperB, summaryB, err := OpenLocalGenesisSessionForJournal(fresh, fxB.config,
		fxB.manifest.BackendRoot, fxB.manifest.VaultID, fxB.manifest.Journal,
		[]byte(f.f.password), f.f.key)
	if err != nil || wrapperB == nil {
		t.Fatal("LOCAL_TWO_VAULT_QUERY_B_OPEN_FAILED")
	}
	defer wrapperB.Close()
	localFirstAssertOrdinarySummary(t, wrapperB, summaryB, fxB)

	queryA := localQueryAssertRealExactHit(t, wrapperA, fxA, evidenceA)
	queryB := localQueryAssertRealExactHit(t, wrapperB, fxB, evidenceB)
	if queryA.Hits[0].ID == queryB.Hits[0].ID ||
		queryA.VaultID == queryB.VaultID ||
		queryA.ConfigPath == queryB.ConfigPath ||
		queryA.JournalPath == queryB.JournalPath {
		t.Fatal("LOCAL_TWO_VAULT_QUERY_RESULTS_MERGED")
	}

	localQueryAssertActivated(t, wrapperA, queryA)
	localQueryAssertActivated(t, wrapperB, queryB)

	// The original proof belongs to its exact receiver and exact item identity.
	if err := wrapperB.ValidateExactQueryHit(queryA, queryA.Hits[0].ID, queryA.Hits[0].Title); !errors.Is(err, ErrLocalReview) {
		t.Fatal("LOCAL_TWO_VAULT_CROSS_VAULT_RESULT_ACCEPTED_BY_B")
	}
	if err := wrapperA.ValidateExactQueryHit(queryB, queryB.Hits[0].ID, queryB.Hits[0].Title); !errors.Is(err, ErrLocalReview) {
		t.Fatal("LOCAL_TWO_VAULT_CROSS_VAULT_RESULT_ACCEPTED_BY_A")
	}
	// A wrong but well-formed item identity with the exact correct title must
	// fail on a fresh real A result, independently of a wrong title.
	wrongIdentity := localQueryAssertRealExactHit(t, wrapperA, fxA, evidenceA)
	if err := wrapperA.ValidateExactQueryHit(wrongIdentity, fxB.item.ID, fxA.item.Title); !errors.Is(err, ErrLocalReview) {
		t.Fatal("LOCAL_TWO_VAULT_WRONG_ITEM_IDENTITY_ACCEPTED")
	}
	// The exact correct A identity with a separately non-matching title must
	// fail on its own fresh real A result.
	wrongTitle := localQueryAssertRealExactHit(t, wrapperA, fxA, evidenceA)
	if err := wrapperA.ValidateExactQueryHit(wrongTitle, fxA.item.ID, fxA.item.Title+"-changed"); !errors.Is(err, ErrLocalReview) {
		t.Fatal("LOCAL_TWO_VAULT_CHANGED_TITLE_ACCEPTED")
	}

	// A fresh wrapper over the same persisted vault is not the original proof
	// receiver, so the pre-reopen proof must be stale there.
	if err := wrapperB.Close(); err != nil {
		t.Fatal("LOCAL_TWO_VAULT_QUERY_B_CLOSE_FAILED")
	}
	reopenedB, reopenedSummaryB, err := OpenLocalGenesisSessionForJournal(fresh, fxB.config,
		fxB.manifest.BackendRoot, fxB.manifest.VaultID, fxB.manifest.Journal,
		[]byte(f.f.password), f.f.key)
	if err != nil || reopenedB == nil {
		t.Fatal("LOCAL_TWO_VAULT_QUERY_B_REOPEN_FAILED")
	}
	defer reopenedB.Close()
	localFirstAssertOrdinarySummary(t, reopenedB, reopenedSummaryB, fxB)
	if err := reopenedB.ValidateExactQueryHit(queryB, queryB.Hits[0].ID, queryB.Hits[0].Title); !errors.Is(err, ErrLocalReview) {
		t.Fatal("LOCAL_TWO_VAULT_STALE_PROOF_ACCEPTED")
	}
	queryB = localQueryAssertRealExactHit(t, reopenedB, fxB, evidenceB)
	localQueryAssertActivated(t, reopenedB, queryB)

	// Publish A's exact same backend ciphertext at a new opaque revision. This
	// is a real named-backend drift of A's original backend/name scope, not a
	// projected or synthetic result.
	backendBefore, revisionBefore := localFirstReadBackend(t, fxA.manifest)
	defer clear(backendBefore)
	updated := localFirstRewriteBackend(t, fxA.manifest, backendBefore)
	backendAfter, revisionAfter := localFirstReadBackend(t, fxA.manifest)
	defer clear(backendAfter)
	if updated == revisionBefore || revisionAfter != updated || !bytes.Equal(backendBefore, backendAfter) {
		t.Fatal("LOCAL_TWO_VAULT_DRIFT_NOT_REAL")
	}

	// Drift is terminal for A's original child. The old hit must not be
	// returned and A's original pre-drift proof must not activate.
	driftedA, err := wrapperA.QueryExactTitle(LocalGenesisExactQuery{Title: fxA.item.Title, Limit: 2})
	if err == nil || len(driftedA.Hits) != 0 {
		t.Fatal("LOCAL_TWO_VAULT_DRIFTED_QUERY_RETURNED_OLD_HIT")
	}
	if err := wrapperA.ValidateExactQueryHit(queryA, queryA.Hits[0].ID, queryA.Hits[0].Title); err == nil {
		t.Fatal("LOCAL_TWO_VAULT_DRIFTED_PROOF_ACCEPTED")
	}
	localFirstAssertScopeUnchanged(t, afterB, fxB.manifest, "LOCAL_TWO_VAULT_QUERY_B_CHANGED_BY_DRIFT")

	// The untouched B sibling still performs a real exact query bound to its
	// own durable item ID and activates both its original proof and a fresh
	// post-drift proof.
	queryBAfter := localQueryAssertRealExactHit(t, reopenedB, fxB, evidenceB)
	localQueryAssertActivated(t, reopenedB, queryBAfter)
	if err := reopenedB.ValidateExactQueryHit(queryB, queryB.Hits[0].ID, queryB.Hits[0].Title); err != nil {
		t.Fatal("LOCAL_TWO_VAULT_UNCHANGED_SIBLING_PROOF_LOST")
	}

	// An account lock is independent of the drift discriminator and must close
	// both the exact read and activation boundaries on the remaining child.
	fresh.Lock()
	locked, err := reopenedB.QueryExactTitle(LocalGenesisExactQuery{Title: fxB.item.Title, Limit: 2})
	if err == nil || len(locked.Hits) != 0 {
		t.Fatal("LOCAL_TWO_VAULT_QUERY_ACCOUNT_LOCK_IGNORED")
	}
	if err := reopenedB.ValidateExactQueryHit(queryBAfter, queryBAfter.Hits[0].ID, queryBAfter.Hits[0].Title); err == nil {
		t.Fatal("LOCAL_TWO_VAULT_ACTIVATION_ACCOUNT_LOCK_IGNORED")
	}
}
