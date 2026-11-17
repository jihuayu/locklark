//go:build darwin || linux

package desktop

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/vaultfileclient"
)

func newDrainSummaryBatch(t *testing.T, f *localVaultSessionFixture, refs []localVaultFileRef,
	candidateIndex int, duplicate bool) (*localVaultFileInitialBatch, []localVaultFileRef, []personal.Row) {
	t.Helper()
	profileDir, backendRoot := localVaultFilePaths(f.settingsPath, f.personalPath)
	ref := refs[candidateIndex]
	candidate := vaultfileclient.LocalGenesisBatchCandidate{
		ConfigPath: ref.path, WorkspaceRoot: backendRoot,
		VaultID: ref.vaultID, JournalPath: ref.journalPath,
	}
	key, err := personal.ParseSecret(f.secret)
	if err != nil {
		t.Fatal("DRAIN_SUMMARY_PARSE_FAILED")
	}
	session, results, err := vaultfileclient.OpenLocalGenesisSessionsForAccount(
		context.Background(), f.personalPath, []byte(f.password), key, time.Minute,
		[]vaultfileclient.LocalGenesisBatchCandidate{candidate})
	clear(key)
	if err != nil || session == nil || len(results) != 1 || results[0].Wrapper == nil {
		t.Fatal("DRAIN_SUMMARY_AUTH_FAILED")
	}
	if duplicate {
		results = []vaultfileclient.LocalGenesisBatchResult{results[0], results[0]}
	}
	rows, err := session.List("active")
	if err != nil {
		session.Lock()
		t.Fatal("DRAIN_SUMMARY_ROWS_FAILED")
	}
	refsAlias := refs
	rowsAlias := rows
	candidateRefs := make([]int, len(results))
	for index := range candidateRefs {
		candidateRefs[index] = candidateIndex
	}
	batch := newLocalVaultFileInitialBatch(session, results, refsAlias, candidateRefs,
		f.personalPath, f.settingsPath, profileDir, backendRoot, 0)
	batch.setRows(rowsAlias)
	t.Cleanup(func() {
		for index := range results {
			if results[index].Wrapper != nil {
				_ = results[index].Wrapper.Close()
			}
		}
		session.Lock()
	})
	return batch, refsAlias, rowsAlias
}

func TestLocalVaultFileInitialDrainSummary(t *testing.T) {
	f := newLocalVaultSessionFixture(t)
	f.createVault(t)
	f.createVault(t)
	if _, err := f.parent.AddLogin("drain-summary", "drain-user", "drain-value"); err != nil {
		t.Fatal("DRAIN_SUMMARY_ROW_SETUP_FAILED")
	}
	profileDir, backendRoot := localVaultFilePaths(f.settingsPath, f.personalPath)
	refs, err := listLocalVaultFileRefs(profileDir, backendRoot, f.personalPath)
	if err != nil || len(refs) != 2 {
		t.Fatal("DRAIN_SUMMARY_REFS_FAILED")
	}

	batch, refsAlias, rowsAlias := newDrainSummaryBatch(t, f, refs, 0, true)
	if got := batch.drainSummary(); got.state != localVaultFileInitialDrainNotReady {
		t.Fatal("DRAIN_SUMMARY_PREMATURE")
	}
	if len(rowsAlias) == 0 {
		t.Fatal("DRAIN_SUMMARY_ROWS_EMPTY")
	}
	other, _, _ := newDrainSummaryBatch(t, f, refs, 1, false)

	batch.drain()
	summary := batch.drainSummary()
	if summary.state != localVaultFileInitialDrainComplete ||
		summary.closedWrappers != 1 || !summary.parentLocked ||
		!summary.refsCleared || !summary.rowsCleared {
		t.Fatal("DRAIN_SUMMARY_NOT_COMPLETE")
	}
	for index := range refsAlias {
		if refsAlias[index] != (localVaultFileRef{}) {
			t.Fatal("DRAIN_SUMMARY_REFS_NOT_CLEARED")
		}
	}
	for index := range rowsAlias {
		if !reflect.DeepEqual(rowsAlias[index], personal.Row{}) {
			t.Fatal("DRAIN_SUMMARY_ROWS_NOT_CLEARED")
		}
	}
	batch.drain()
	if got := batch.drainSummary(); got != summary {
		t.Fatal("DRAIN_SUMMARY_REPEAT_UNSTABLE")
	}

	other.drain()
	otherSummary := other.drainSummary()
	if otherSummary.state != localVaultFileInitialDrainComplete ||
		otherSummary.closedWrappers != 1 || !otherSummary.parentLocked ||
		!otherSummary.refsCleared || !otherSummary.rowsCleared {
		t.Fatal("DRAIN_SUMMARY_SECOND_NOT_COMPLETE")
	}
	if got := batch.drainSummary(); got != summary {
		t.Fatal("DRAIN_SUMMARY_FOREIGN_OVERWRITE")
	}
}

func TestLocalVaultFileInitialDrainSummaryNotOwned(t *testing.T) {
	var nilBatch *localVaultFileInitialBatch
	if got := nilBatch.drainSummary(); got.state != localVaultFileInitialDrainInvalid {
		t.Fatal("DRAIN_SUMMARY_NIL_NOT_INVALID")
	}

	original := localVaultFileInitialBatchDrainForTest
	t.Cleanup(func() { localVaultFileInitialBatchDrainForTest = original })
	observerParentLocked := false
	localVaultFileInitialBatchDrainForTest = func(_ int, parentLocked bool) {
		observerParentLocked = parentLocked
	}
	notOwned := &localVaultFileInitialBatch{done: make(chan struct{})}
	notOwned.drain()
	summary := notOwned.drainSummary()
	if summary.state != localVaultFileInitialDrainInvalid ||
		summary.parentLocked || summary.closedWrappers != 0 ||
		!summary.refsCleared || !summary.rowsCleared {
		t.Fatal("DRAIN_SUMMARY_UNOWNED_INVALID")
	}
	if !observerParentLocked {
		t.Fatal("DRAIN_SUMMARY_OBSERVER_CONTRACT_CHANGED")
	}

	adopted := &localVaultFileInitialBatch{done: make(chan struct{})}
	if !adopted.takeForAdoption() {
		t.Fatal("DRAIN_SUMMARY_ADOPT_FAILED")
	}
	adopted.drain()
	if got := adopted.drainSummary(); got.state != localVaultFileInitialDrainNotReady {
		t.Fatal("DRAIN_SUMMARY_ADOPTED_DRAINED")
	}
	select {
	case <-adopted.done:
		t.Fatal("DRAIN_SUMMARY_ADOPTED_DONE_CLOSED")
	default:
	}

	overflow := localVaultFileInitialDrainResult(localVaultFileInitialDrainLimit+1, true, true, true)
	if overflow.state != localVaultFileInitialDrainInvalid ||
		overflow.closedWrappers != localVaultFileInitialDrainLimit {
		t.Fatal("DRAIN_SUMMARY_OVERFLOW_INVALID")
	}
	unlockedParent := localVaultFileInitialDrainResult(1, false, true, true)
	if unlockedParent.state != localVaultFileInitialDrainInvalid || unlockedParent.parentLocked {
		t.Fatal("DRAIN_SUMMARY_UNLOCKED_PARENT_INVALID")
	}
}
