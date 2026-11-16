//go:build darwin || linux

package desktop

import (
	"path/filepath"
	"testing"

	"github.com/jihuayu/locklark/internal/vaultfileclient"
)

func TestDesktopLocalVaultSessionJournalHintRequiredForStart(t *testing.T) {
	f := newLocalVaultSessionFixture(t)
	q := &localVaultSessionQueue{}
	q.install(f.app)
	aPath, aManifest := f.createVault(t)
	_, bManifest := f.createVault(t)
	aScope := f.scope(aPath, aManifest)
	if aScope.journalPath == "" || aScope.journalPath != aManifest.Journal {
		t.Fatal("LOCAL_JOURNAL_HINT_NOT_CAPTURED")
	}

	missing := aScope
	missing.journalPath = ""
	if op := f.app.beginLocalVaultFileSession(missing, []byte(f.password), f.key); op != nil {
		t.Fatal("LOCAL_JOURNAL_MISSING_STARTED")
	}
	if len(q.launches) != 0 {
		t.Fatal("LOCAL_JOURNAL_MISSING_LAUNCHED")
	}

	wrong := aScope
	wrong.journalPath = bManifest.Journal
	if wrong.journalPath == aManifest.Journal {
		t.Fatal("LOCAL_JOURNAL_FIXTURE_NOT_INDEPENDENT")
	}
	op := f.app.beginLocalVaultFileSession(wrong, []byte(f.password), f.key)
	if op == nil {
		t.Fatal("LOCAL_JOURNAL_WRONG_NOT_RESERVED")
	}
	q.runLaunch(t)
	result := localVaultSessionStagedResult(t, op)
	if result.outcome != localVaultFileSessionOutcomeFailed || result.candidate != nil {
		t.Fatal("LOCAL_JOURNAL_WRONG_FACTORY_STARTED")
	}
	q.runDispatch(t)
	slot := f.app.localVaultFiles.sessionSlots[wrong]
	if slot == nil || slot.session != nil || slot.operation != nil {
		t.Fatal("LOCAL_JOURNAL_WRONG_ADOPTED")
	}
	if op.finiteOutcome() != localVaultFileSessionOutcomeFailed {
		t.Fatal("LOCAL_JOURNAL_WRONG_NOT_FINISHED")
	}
	if !f.parent.Unlocked() {
		t.Fatal("LOCAL_JOURNAL_WRONG_LOCKED_PARENT")
	}
}

func TestDesktopCreateJournalHintCapturedAndCompleteWrongHintRefused(t *testing.T) {
	f := newDesktopCreateResumeFixture(t)
	q := &localVaultSessionQueue{}
	kit, scope := prepareDesktopCreateCompletion(t, f, q)
	manifest, exists, err := vaultfileclient.ReadManifest(scope.configPath)
	if err != nil || !exists || scope.journalPath == "" || scope.journalPath != manifest.Journal {
		t.Fatal("DESKTOP_CREATE_JOURNAL_HINT_NOT_CAPTURED")
	}

	// The frozen scheduling hint is deliberately wrong. The bound template is
	// the real manifest, so the Complete caller check must refuse before the
	// protocol constructor can run.
	f.app.localCreate.scope.journalPath = filepath.Join(f.root, "wrong-scheduling-hint.journal")
	f.app.localCreate.password, f.app.localCreate.secret, f.app.localCreate.kit = f.password, f.secret, kit
	f.app.localCreateComplete()
	childOp := f.app.localCreate.child
	if childOp == nil {
		t.Fatal("DESKTOP_CREATE_WRONG_HINT_NOT_RESERVED")
	}
	q.runLaunch(t)
	q.runDispatch(t)
	if childOp.finiteOutcome() != localVaultFileSessionOutcomeCancelled {
		t.Fatal("DESKTOP_CREATE_WRONG_HINT_NOT_REFUSED")
	}
	if childOp.slot == nil || childOp.slot.session != nil || childOp.slot.operation != nil {
		t.Fatal("DESKTOP_CREATE_WRONG_HINT_ADOPTED")
	}
	if f.app.localCreate.status != "创建未完成；请核查本地状态" {
		t.Fatal("DESKTOP_CREATE_WRONG_HINT_STATUS_CHANGED")
	}
}
