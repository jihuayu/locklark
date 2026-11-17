//go:build darwin || linux

package vaultfileclient

import (
	"errors"
	"testing"
)

func localGenesisJournalForTest(t *testing.T, configPath string) string {
	t.Helper()
	manifest, exists, err := ReadManifest(configPath)
	if err != nil || !exists || manifest.Journal == "" {
		t.Fatal("LOCAL_GENESIS_JOURNAL_FIXTURE_MISSING")
	}
	return manifest.Journal
}

func TestLocalGenesisSessionForJournalAcceptsExactJournal(t *testing.T) {
	f := newLocalGenesisTwoVaultFixture(t)
	journal := localGenesisJournalForTest(t, f.firstConfig)
	session, summary, err := OpenLocalGenesisSessionForJournal(f.session, f.firstConfig, f.f.proposal.BackendRoot, f.firstVaultID, journal, f.f.password, f.f.key)
	if err != nil || session == nil {
		t.Fatal("LOCAL_GENESIS_JOURNAL_PIN_OPEN_FAILED")
	}
	defer session.Close()
	assertLocalGenesisSummary(t, summary, f.firstVaultID)
}

func TestLocalGenesisSessionForJournalRejectsMismatchAndMissingBeforeRegistration(t *testing.T) {
	f := newLocalGenesisTwoVaultFixture(t)
	aJournal := localGenesisJournalForTest(t, f.firstConfig)
	bJournal := localGenesisJournalForTest(t, f.secondConfig)
	if aJournal == bJournal {
		t.Fatal("LOCAL_GENESIS_JOURNAL_FIXTURE_NOT_INDEPENDENT")
	}
	b, bSummary := f.open(t, f.secondConfig, f.secondVaultID)
	defer b.Close()
	assertLocalGenesisSummary(t, bSummary, f.secondVaultID)

	if session, _, err := OpenLocalGenesisSessionForJournal(f.session, f.firstConfig, f.f.proposal.BackendRoot, f.firstVaultID, bJournal, f.f.password, f.f.key); !errors.Is(err, ErrLocalReview) || session != nil {
		t.Fatal("LOCAL_GENESIS_JOURNAL_MISMATCH_NOT_REJECTED")
	}
	if session, _, err := OpenLocalGenesisSessionForJournal(f.session, f.firstConfig, f.f.proposal.BackendRoot, f.firstVaultID, "", f.f.password, f.f.key); !errors.Is(err, ErrLocalReview) || session != nil {
		t.Fatal("LOCAL_GENESIS_JOURNAL_MISSING_NOT_REJECTED")
	}
	if !f.session.Unlocked() {
		t.Fatal("LOCAL_GENESIS_JOURNAL_PARENT_LOCKED")
	}
	bAgain, err := b.Summary()
	if err != nil || bAgain.VaultID != f.secondVaultID {
		t.Fatal("LOCAL_GENESIS_JOURNAL_SIBLING_LOST")
	}
	freshB, freshSummary, err := OpenLocalGenesisSessionForJournal(f.session, f.secondConfig, f.f.proposal.BackendRoot, f.secondVaultID, bJournal, f.f.password, f.f.key)
	if err != nil || freshB == nil {
		t.Fatal("LOCAL_GENESIS_JOURNAL_ACCOUNT_OWNERSHIP_CHANGED")
	}
	defer freshB.Close()
	assertLocalGenesisSummary(t, freshSummary, f.secondVaultID)
}
