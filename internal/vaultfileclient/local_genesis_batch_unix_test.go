//go:build darwin || linux

package vaultfileclient

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
)

func localGenesisBatchCandidate(t *testing.T, f *localGenesisTwoVaultFixture, configPath, vaultID string) LocalGenesisBatchCandidate {
	t.Helper()
	manifest, exists, err := ReadManifest(configPath)
	if err != nil || !exists || manifest.VaultID != vaultID {
		t.Fatal("LOCAL_BATCH_CANDIDATE_MANIFEST_FAILED")
	}
	return LocalGenesisBatchCandidate{
		ConfigPath: configPath, WorkspaceRoot: f.f.proposal.BackendRoot,
		VaultID: vaultID, JournalPath: manifest.Journal,
	}
}

func openLocalGenesisBatchForTest(t *testing.T, f *localGenesisTwoVaultFixture, ctx context.Context, candidates []LocalGenesisBatchCandidate) (*personal.Session, []LocalGenesisBatchResult, error) {
	t.Helper()
	return OpenLocalGenesisSessionsForAccount(ctx, f.f.proposal.PersonalFile,
		[]byte(f.f.password), f.f.key, time.Minute, candidates)
}

func TestOpenLocalGenesisSessionsForAccount(t *testing.T) {
	f := newLocalGenesisTwoVaultFixture(t)
	firstManifest, exists, err := ReadManifest(f.firstConfig)
	if err != nil || !exists {
		t.Fatal("LOCAL_BATCH_FIRST_MANIFEST_FAILED")
	}
	secondManifest, exists, err := ReadManifest(f.secondConfig)
	if err != nil || !exists {
		t.Fatal("LOCAL_BATCH_SECOND_MANIFEST_FAILED")
	}
	candidateA := localGenesisBatchCandidate(t, f, f.firstConfig, f.firstVaultID)
	candidateB := localGenesisBatchCandidate(t, f, f.secondConfig, f.secondVaultID)

	t.Run("candidate-cap-before-auth", func(t *testing.T) {
		candidates := make([]LocalGenesisBatchCandidate, MaxLocalGenesisBatchCandidates+1)
		parent, results, err := openLocalGenesisBatchForTest(t, f, context.Background(), candidates)
		if !errors.Is(err, ErrLocalReview) || parent != nil || results != nil {
			t.Fatal("LOCAL_BATCH_INPUT_CAP_NOT_PREAUTH")
		}
	})

	t.Run("opens-distinct-ab-and-invalid-middle", func(t *testing.T) {
		parent, results, err := openLocalGenesisBatchForTest(t, f, context.Background(),
			[]LocalGenesisBatchCandidate{candidateA, {}, candidateB, candidateA})
		if err != nil || parent == nil || len(results) != 4 {
			t.Fatal("LOCAL_BATCH_AB_DELIVERY_FAILED")
		}
		defer parent.Lock()
		for index := range results {
			if results[index].Index != index {
				t.Fatal("LOCAL_BATCH_AB_INDEX_UNSTABLE")
			}
		}
		if results[1].Err == nil || results[1].Wrapper != nil {
			t.Fatal("LOCAL_BATCH_INVALID_MIDDLE_NOT_LOCAL")
		}
		if results[0].Err != nil || results[3].Err != nil ||
			results[0].Wrapper == nil || results[0].Wrapper != results[3].Wrapper ||
			results[0].Baseline.VaultID != firstManifest.VaultID ||
			results[3].Baseline.VaultID != firstManifest.VaultID {
			t.Fatal("LOCAL_BATCH_DUPLICATE_IDENTITY_NOT_SHARED")
		}
		if results[2].Err != nil || results[2].Wrapper == nil ||
			results[2].Wrapper == results[0].Wrapper ||
			results[2].Baseline.VaultID != secondManifest.VaultID {
			t.Fatal("LOCAL_BATCH_DISTINCT_B_MISSING")
		}
		if parent == f.session {
			t.Fatal("LOCAL_BATCH_REUSED_EXISTING_PARENT")
		}
		if _, err := results[0].Wrapper.Summary(); err != nil {
			t.Fatal("LOCAL_BATCH_A_SUMMARY_FAILED")
		}
		if _, err := results[2].Wrapper.Summary(); err != nil {
			t.Fatal("LOCAL_BATCH_B_SUMMARY_FAILED")
		}
		_ = results[0].Wrapper.Close()
		_ = results[2].Wrapper.Close()
	})

	t.Run("posterior-locator-replacement-is-target-local", func(t *testing.T) {
		original, err := os.ReadFile(f.firstConfig)
		if err != nil {
			t.Fatal("LOCAL_BATCH_POSTERIOR_MANIFEST_READ_FAILED")
		}
		wrote := false
		localGenesisBatchAfterAuthForTest = func() {
			if wrote {
				return
			}
			wrote = true
			_ = os.WriteFile(f.firstConfig, []byte("{"), 0600)
		}
		t.Cleanup(func() {
			localGenesisBatchAfterAuthForTest = nil
			_ = os.WriteFile(f.firstConfig, original, 0600)
		})
		parent, results, err := openLocalGenesisBatchForTest(t, f, context.Background(),
			[]LocalGenesisBatchCandidate{candidateA, candidateB})
		_ = os.WriteFile(f.firstConfig, original, 0600)
		localGenesisBatchAfterAuthForTest = nil
		if err != nil || parent == nil || len(results) != 2 {
			t.Fatal("LOCAL_BATCH_POSTERIOR_DELIVERY_FAILED")
		}
		defer parent.Lock()
		if results[0].Err == nil || results[0].Wrapper != nil {
			t.Fatal("LOCAL_BATCH_POSTERIOR_A_NOT_LOCAL")
		}
		if results[1].Err != nil || results[1].Wrapper == nil ||
			results[1].Baseline.VaultID != secondManifest.VaultID {
			t.Fatal("LOCAL_BATCH_POSTERIOR_KILLED_B")
		}
		if _, err := results[1].Wrapper.Summary(); err != nil {
			t.Fatal("LOCAL_BATCH_POSTERIOR_B_SUMMARY_FAILED")
		}
		_ = results[1].Wrapper.Close()
	})

	t.Run("all-local-failure-retains-parent", func(t *testing.T) {
		conflict := candidateA
		conflict.JournalPath = candidateA.JournalPath + ".conflict"
		oversize := LocalGenesisBatchCandidate{
			ConfigPath:    strings.Repeat("a", maxLocalGenesisBatchPath+1),
			WorkspaceRoot: f.f.proposal.BackendRoot, VaultID: f.firstVaultID,
			JournalPath: firstManifest.Journal,
		}
		parent, results, err := openLocalGenesisBatchForTest(t, f, context.Background(),
			[]LocalGenesisBatchCandidate{candidateA, conflict, oversize})
		if err != nil || parent == nil || len(results) != 3 {
			t.Fatal("LOCAL_BATCH_ALL_LOCAL_PARENT_MISSING")
		}
		defer parent.Lock()
		for index := range results {
			if results[index].Err == nil || results[index].Wrapper != nil {
				t.Fatal("LOCAL_BATCH_ALL_LOCAL_NOT_LOCAL")
			}
		}
		if !parent.Unlocked() {
			t.Fatal("LOCAL_BATCH_ALL_LOCAL_PARENT_LOCKED")
		}
	})

	t.Run("cancellation-closes-delivery", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		observed := false
		closedWrappers, summaryBuffers := 0, 0
		summariesCleared := false
		localGenesisBatchBeforeDeliveryForTest = func() { cancel() }
		localGenesisBatchCleanupForTest = func(closed, summaries int, cleared bool) {
			observed = true
			closedWrappers, summaryBuffers, summariesCleared = closed, summaries, cleared
		}
		t.Cleanup(func() {
			localGenesisBatchBeforeDeliveryForTest = nil
			localGenesisBatchCleanupForTest = nil
		})
		parent, results, err := openLocalGenesisBatchForTest(t, f, ctx,
			[]LocalGenesisBatchCandidate{candidateA, candidateB})
		localGenesisBatchBeforeDeliveryForTest = nil
		localGenesisBatchCleanupForTest = nil
		if !errors.Is(err, context.Canceled) || parent != nil || results != nil {
			t.Fatal("LOCAL_BATCH_CANCEL_DELIVERED")
		}
		if !observed || closedWrappers != 2 || summaryBuffers != 2 || !summariesCleared {
			t.Fatal("LOCAL_BATCH_CANCEL_CLEANUP_INCOMPLETE")
		}
	})

	t.Run("existing-single-api-still-works", func(t *testing.T) {
		wrapper, summary, err := OpenLocalGenesisSessionForJournal(f.session, f.firstConfig,
			f.f.proposal.BackendRoot, f.firstVaultID, firstManifest.Journal,
			[]byte(f.f.password), f.f.key)
		if err != nil || wrapper == nil || summary.VaultID != firstManifest.VaultID {
			t.Fatal("LOCAL_BATCH_SINGLE_API_FAILED")
		}
		defer wrapper.Close()
		if _, err := wrapper.Summary(); err != nil {
			t.Fatal("LOCAL_BATCH_SINGLE_API_SUMMARY_FAILED")
		}
		if !f.session.Unlocked() {
			t.Fatal("LOCAL_BATCH_SINGLE_API_PARENT_LOCKED")
		}
	})
}
