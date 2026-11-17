//go:build darwin || linux

package desktop

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/vaultfileclient"
)

func newInitialOutcomeBatch(t *testing.T, f *localVaultSessionFixture) (*localVaultFileInitialBatch,
	[]vaultfileclient.LocalGenesisBatchResult) {
	t.Helper()
	profileDir, backendRoot := localVaultFilePaths(f.settingsPath, f.personalPath)
	refs, err := listLocalVaultFileRefs(profileDir, backendRoot, f.personalPath)
	if err != nil || len(refs) != 2 {
		t.Fatal("INITIAL_OUTCOME_REFS_FAILED")
	}
	candidates := make([]vaultfileclient.LocalGenesisBatchCandidate, 0, len(refs))
	candidateRefs := make([]int, 0, len(refs))
	for index := range refs {
		ref := refs[index]
		candidates = append(candidates, vaultfileclient.LocalGenesisBatchCandidate{
			ConfigPath: ref.path, WorkspaceRoot: backendRoot,
			VaultID: ref.vaultID, JournalPath: ref.journalPath,
		})
		candidateRefs = append(candidateRefs, index)
	}
	key, err := personal.ParseSecret(f.secret)
	if err != nil {
		t.Fatal("INITIAL_OUTCOME_PARSE_FAILED")
	}
	session, results, err := vaultfileclient.OpenLocalGenesisSessionsForAccount(
		context.Background(), f.personalPath, []byte(f.password), key, time.Minute, candidates)
	clear(key)
	if err != nil || session == nil || len(results) != 2 ||
		results[0].Wrapper == nil || results[1].Wrapper == nil {
		t.Fatal("INITIAL_OUTCOME_AUTH_FAILED")
	}
	rows, err := session.List("active")
	if err != nil {
		session.Lock()
		t.Fatal("INITIAL_OUTCOME_ROWS_FAILED")
	}
	batch := newLocalVaultFileInitialBatch(session, results, refs, candidateRefs,
		f.personalPath, f.settingsPath, profileDir, backendRoot, 0)
	batch.setRows(rows)
	t.Cleanup(func() {
		for index := range results {
			if results[index].Wrapper != nil {
				_ = results[index].Wrapper.Close()
			}
		}
		session.Lock()
	})
	return batch, results
}

func TestInitialAccountUnlockOutcomeMetadata(t *testing.T) {
	f := newLocalVaultSessionFixture(t)
	f.createVault(t)
	f.createVault(t)
	if _, err := f.parent.AddLogin("typed-outcome", "typed-user", "typed-value"); err != nil {
		t.Fatal("INITIAL_OUTCOME_ROW_SETUP_FAILED")
	}
	batch, results := newInitialOutcomeBatch(t, f)
	outcome := newInitialAccountUnlockOutcome(batch, results)
	metadata := outcome.finiteMetadata()
	if outcome.batch != batch || !metadata.valid || metadata.uniqueChildren != 2 {
		t.Fatal("INITIAL_OUTCOME_UNIQUE_COUNT_FAILED")
	}
	if got := batch.drainSummary(); got.state != localVaultFileInitialDrainNotReady {
		t.Fatal("INITIAL_OUTCOME_PREMATURE")
	}

	duplicate := newInitialAccountUnlockOutcome(batch,
		[]vaultfileclient.LocalGenesisBatchResult{results[0], results[0]})
	if duplicate.batch != batch || !duplicate.metadata.valid ||
		duplicate.metadata.uniqueChildren != 1 {
		t.Fatal("INITIAL_OUTCOME_DUPLICATE_COUNT_FAILED")
	}

	localErr := errors.New("local target failure")
	zero := newInitialAccountUnlockOutcome(batch,
		[]vaultfileclient.LocalGenesisBatchResult{{Err: localErr}})
	if zero.batch != batch || !zero.metadata.valid || zero.metadata.uniqueChildren != 0 {
		t.Fatal("INITIAL_OUTCOME_ZERO_FAILED")
	}

	invalid := newInitialAccountUnlockOutcome(batch,
		[]vaultfileclient.LocalGenesisBatchResult{{}})
	if invalid.batch != batch || invalid.metadata.valid || invalid.metadata.uniqueChildren != 0 {
		t.Fatal("INITIAL_OUTCOME_INVALID_SHAPE_FAILED")
	}
	wrapperErr := newInitialAccountUnlockOutcome(batch,
		[]vaultfileclient.LocalGenesisBatchResult{{Wrapper: results[0].Wrapper, Err: localErr}})
	if wrapperErr.batch != batch || wrapperErr.metadata.valid ||
		wrapperErr.metadata.uniqueChildren != 1 {
		t.Fatal("INITIAL_OUTCOME_WRAPPER_ERROR_FAILED")
	}
	nilOwner := newInitialAccountUnlockOutcome(nil, results)
	if nilOwner.batch != nil || nilOwner.metadata.valid {
		t.Fatal("INITIAL_OUTCOME_NIL_OWNER_FAILED")
	}
	overflowResults := make([]vaultfileclient.LocalGenesisBatchResult, initialAccountUnlockChildLimit+1)
	for index := range overflowResults {
		overflowResults[index].Wrapper = new(vaultfileclient.LocalGenesisSession)
	}
	overflow := newInitialAccountUnlockOutcome(batch, overflowResults)
	if overflow.batch != batch || overflow.metadata.valid ||
		overflow.metadata.uniqueChildren != initialAccountUnlockChildLimit {
		t.Fatal("INITIAL_OUTCOME_OVERFLOW_FAILED")
	}

	batch.drain()
	summary := batch.drainSummary()
	if summary.state != localVaultFileInitialDrainComplete || summary.closedWrappers != 2 ||
		!summary.parentLocked || !summary.refsCleared || !summary.rowsCleared {
		t.Fatal("INITIAL_OUTCOME_OWNER_DRAIN_FAILED")
	}
	if outcome.batch != batch || !outcome.metadata.valid || outcome.metadata.uniqueChildren != 2 {
		t.Fatal("INITIAL_OUTCOME_OWNER_METADATA_CHANGED")
	}
}
