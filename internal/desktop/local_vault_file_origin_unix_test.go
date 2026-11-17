//go:build darwin || linux

package desktop

import (
	"os"
	"slices"
	"testing"

	"github.com/jihuayu/locklark/internal/vaultfileclient"
)

func desktopLocalVaultTupleAliasConfig(t *testing.T, target, source string) (string, vaultfileclient.Manifest) {
	t.Helper()
	rawManifest, err := os.ReadFile(source)
	if err != nil {
		t.Fatal("LOCAL_ORIGIN_ALIAS_MANIFEST_READ_FAILED")
	}
	sourceCompanion, err := vaultfileclient.CompanionPath(source)
	if err != nil {
		t.Fatal("LOCAL_ORIGIN_ALIAS_COMPANION_PATH_FAILED")
	}
	rawCompanion, err := os.ReadFile(sourceCompanion)
	if err != nil {
		t.Fatal("LOCAL_ORIGIN_ALIAS_COMPANION_READ_FAILED")
	}
	targetCompanion, err := vaultfileclient.CompanionPath(target)
	if err != nil {
		t.Fatal("LOCAL_ORIGIN_ALIAS_TARGET_COMPANION_PATH_FAILED")
	}
	if err := os.WriteFile(target, rawManifest, 0600); err != nil {
		t.Fatal("LOCAL_ORIGIN_ALIAS_MANIFEST_WRITE_FAILED")
	}
	if err := os.WriteFile(targetCompanion, rawCompanion, 0600); err != nil {
		t.Fatal("LOCAL_ORIGIN_ALIAS_COMPANION_WRITE_FAILED")
	}
	manifest, exists, err := vaultfileclient.ReadManifest(target)
	if err != nil || !exists {
		t.Fatal("LOCAL_ORIGIN_ALIAS_MANIFEST_MISSING")
	}
	return target, manifest
}

func TestDesktopLocalVaultTupleDriftWithPendingRefreshWithholdsOldProjection(t *testing.T) {
	f := newLocalVaultSessionFixture(t)
	q := &localVaultSessionQueue{}
	q.install(f.app)
	aPath, aManifest := f.createVault(t)
	bPath, _ := f.createVault(t)
	aScope := f.scope(aPath, aManifest)
	f.openVault(t, q, aScope)
	aSlot := f.app.localVaultFiles.sessionSlots[aScope]
	if aSlot == nil || aSlot.session == nil {
		t.Fatal("LOCAL_ORIGIN_PENDING_SETUP_FAILED")
	}
	aSession := aSlot.session
	aRef := localVaultNavigationRef(aPath, aManifest)
	f.app.localVaultFiles.refs = []localVaultFileRef{aRef}
	f.app.selectLocalVaultFile(aRef)

	old := f.app.beginLocalVaultFileRefresh(aScope)
	if old == nil {
		t.Fatal("LOCAL_ORIGIN_PENDING_REFRESH_BEGIN_FAILED")
	}
	q.runLaunch(t)
	if len(q.dispatches) != 1 {
		t.Fatal("LOCAL_ORIGIN_PENDING_REFRESH_NOT_STAGED")
	}
	oldDispatch := q.dispatches[0]
	q.dispatches = nil

	aliasPath, aliasManifest := desktopLocalVaultTupleAliasConfig(t, aPath, bPath)
	bAliasScope := f.scope(aliasPath, aliasManifest)
	f.openVault(t, q, bAliasScope)
	bSlot := f.app.localVaultFiles.sessionSlots[bAliasScope]
	if bSlot == nil || bSlot.session == nil {
		t.Fatal("LOCAL_ORIGIN_PENDING_B_ADOPT_FAILED")
	}
	bSession := bSlot.session
	if aliasManifest.VaultID == aManifest.VaultID || aliasManifest.Journal == aManifest.Journal {
		t.Fatal("LOCAL_ORIGIN_PENDING_TUPLE_NOT_DISTINCT")
	}

	f.app.refreshLocalVaultFiles()
	q.runLaunch(t)
	q.runDispatch(t)
	if f.app.localVaultFiles.projectionOrigin != nil {
		t.Fatal("LOCAL_ORIGIN_PENDING_ORIGIN_NOT_INVALIDATED")
	}
	if f.app.localVaultFiles.items != nil {
		t.Fatal("LOCAL_ORIGIN_PENDING_ITEMS_NOT_CLEARED")
	}
	if caption := f.app.localVaultFileRefreshCaption(); caption != "" {
		t.Fatal("LOCAL_ORIGIN_PENDING_CAPTION_NOT_WITHHELD")
	}
	if aSlot.session != aSession || bSlot.session != bSession {
		t.Fatal("LOCAL_ORIGIN_PENDING_METADATA_CHANGE_CLOSED_WRAPPER")
	}
	if old.finiteOutcome() != localVaultFileRefreshOutcomeCancelled {
		t.Fatal("LOCAL_ORIGIN_PENDING_OLD_READ_NOT_CANCELLED")
	}

	field := prepareLocalVaultBusyField(t, f.parent)
	entered := make(chan struct{})
	releaseCh := make(chan struct{})
	consumeDone := make(chan error, 1)
	go func() {
		consumeDone <- f.parent.Consume(field, func(_ []byte) error {
			close(entered)
			<-releaseCh
			return nil
		})
	}()
	<-entered
	f.app.clickLocalVaultFileRefreshAction()
	if len(q.launches) != 0 {
		close(releaseCh)
		t.Fatal("LOCAL_ORIGIN_PENDING_B_REFRESH_QUEUED")
	}
	if f.app.localVaultFiles.status != localVaultFileStatusUnavailable {
		close(releaseCh)
		t.Fatal("LOCAL_ORIGIN_PENDING_B_REFRESH_NOT_UNAVAILABLE")
	}
	close(releaseCh)
	if err := <-consumeDone; err != nil {
		t.Fatal("LOCAL_ORIGIN_PENDING_CONSUME_FAILED")
	}

	oldDispatch()
	if f.app.localVaultFiles.projectionOrigin != nil ||
		f.app.localVaultFiles.items != nil ||
		f.app.localVaultFiles.viewVerification == localVaultFileViewFresh ||
		f.app.localVaultFiles.viewVerification == localVaultFileViewFailed ||
		f.app.localVaultFileRefreshCaption() != "" {
		t.Fatal("LOCAL_ORIGIN_PENDING_OLD_CALLBACK_WROTE_PROJECTION")
	}
	if aSlot.session != aSession || bSlot.session != bSession {
		t.Fatal("LOCAL_ORIGIN_PENDING_OLD_CALLBACK_CHANGED_WRAPPER")
	}
	if summary, err := bSession.Summary(); err != nil || summary.VaultID != aliasManifest.VaultID {
		t.Fatal("LOCAL_ORIGIN_PENDING_B_LOST")
	}

	bRef := localVaultNavigationRef(aliasPath, aliasManifest)
	f.app.selectLocalVaultFile(bRef)
	origin := f.app.localVaultFiles.projectionOrigin
	if origin == nil || origin.scope.vaultID != aliasManifest.VaultID ||
		f.app.localVaultFileRefreshCaption() != localVaultFileCachedCaption {
		t.Fatal("LOCAL_ORIGIN_PENDING_B_CACHE_NOT_BOUND")
	}
	if aSlot.session != aSession || bSlot.session != bSession {
		t.Fatal("LOCAL_ORIGIN_PENDING_SELECT_CHANGED_WRAPPER")
	}
	if summary, err := bSession.Summary(); err != nil || summary.VaultID != aliasManifest.VaultID {
		t.Fatal("LOCAL_ORIGIN_PENDING_B_CACHE_LOST")
	}
}

func TestDesktopLocalVaultTupleDriftWithoutPendingWithholdsOldProjection(t *testing.T) {
	f := newLocalVaultSessionFixture(t)
	q := &localVaultSessionQueue{}
	q.install(f.app)
	aPath, aManifest := f.createVault(t)
	bPath, _ := f.createVault(t)
	aScope := f.scope(aPath, aManifest)
	f.openVault(t, q, aScope)
	aSlot := f.app.localVaultFiles.sessionSlots[aScope]
	if aSlot == nil || aSlot.session == nil {
		t.Fatal("LOCAL_ORIGIN_DIRECT_SETUP_FAILED")
	}
	aSession := aSlot.session
	aRef := localVaultNavigationRef(aPath, aManifest)
	f.app.localVaultFiles.refs = []localVaultFileRef{aRef}
	f.app.selectLocalVaultFile(aRef)
	if f.app.localVaultFiles.projectionOrigin == nil {
		t.Fatal("LOCAL_ORIGIN_DIRECT_PRECONDITION_MISSING")
	}
	aliasPath, aliasManifest := desktopLocalVaultTupleAliasConfig(t, aPath, bPath)
	bAliasScope := f.scope(aliasPath, aliasManifest)
	f.openVault(t, q, bAliasScope)
	bSlot := f.app.localVaultFiles.sessionSlots[bAliasScope]
	if bSlot == nil || bSlot.session == nil {
		t.Fatal("LOCAL_ORIGIN_DIRECT_B_ADOPT_FAILED")
	}
	bSession := bSlot.session

	f.app.refreshLocalVaultFiles()
	q.runLaunch(t)
	q.runDispatch(t)
	if f.app.localVaultFiles.projectionOrigin != nil ||
		f.app.localVaultFiles.items != nil ||
		f.app.localVaultFileRefreshCaption() != "" {
		t.Fatal("LOCAL_ORIGIN_DIRECT_OLD_PROJECTION_RENDERED")
	}
	if aSlot.session != aSession || bSlot.session != bSession {
		t.Fatal("LOCAL_ORIGIN_DIRECT_METADATA_CHANGE_CLOSED_WRAPPER")
	}
	if summary, err := bSession.Summary(); err != nil || summary.VaultID != aliasManifest.VaultID {
		t.Fatal("LOCAL_ORIGIN_DIRECT_B_LOST")
	}
	bRef := localVaultNavigationRef(aliasPath, aliasManifest)
	f.app.selectLocalVaultFile(bRef)
	origin := f.app.localVaultFiles.projectionOrigin
	if origin == nil || origin.scope.vaultID != aliasManifest.VaultID ||
		f.app.localVaultFileRefreshCaption() != localVaultFileCachedCaption {
		t.Fatal("LOCAL_ORIGIN_DIRECT_B_CACHE_NOT_BOUND")
	}
}

func TestDesktopLocalVaultCreationFirstListPreservesProjectionOrigin(t *testing.T) {
	f := newLocalVaultSessionFixture(t)
	q := &localVaultSessionQueue{}
	q.install(f.app)
	aPath, aManifest := f.createVault(t)
	aScope := f.scope(aPath, aManifest)
	op := f.app.beginLocalVaultFileSession(aScope, []byte(f.password), f.key)
	if op == nil {
		t.Fatal("LOCAL_ORIGIN_FIRST_LIST_ADOPT_FAILED")
	}
	q.runLaunch(t)
	q.runDispatch(t)
	if !f.app.presentAdoptedLocalVaultFileSession(op) {
		t.Fatal("LOCAL_ORIGIN_FIRST_LIST_PRESENT_FAILED")
	}
	state := &f.app.localVaultFiles
	origin := state.projectionOrigin
	if origin == nil || origin.scope != aScope || state.selected != aPath ||
		state.status != localVaultFileStatusReady || len(state.refs) != 0 {
		t.Fatal("LOCAL_ORIGIN_FIRST_LIST_PRECONDITION_FAILED")
	}
	viewSequence := state.viewSequence
	items := slices.Clone(state.items)
	aSlot := state.sessionSlots[aScope]
	if aSlot == nil || aSlot.session == nil {
		t.Fatal("LOCAL_ORIGIN_FIRST_LIST_CHILD_MISSING")
	}
	aSession := aSlot.session

	q.runLaunch(t)
	q.runDispatch(t)
	if state.projectionOrigin != origin || state.viewSequence != viewSequence ||
		!slices.Equal(state.items, items) || state.status != localVaultFileStatusReady ||
		state.selected != aPath || len(state.refs) != 1 {
		t.Fatal("LOCAL_ORIGIN_FIRST_LIST_DID_NOT_PRESERVE")
	}
	if aSlot.session != aSession {
		t.Fatal("LOCAL_ORIGIN_FIRST_LIST_CHANGED_CHILD")
	}

	const renamed = "renamed-local-vault-label"
	renamedRef := state.refs[0]
	renamedRef.name = renamed
	f.app.applyLocalVaultFileRefs([]localVaultFileRef{renamedRef}, f.backendRoot, nil)
	if state.projectionOrigin != origin || state.viewSequence != viewSequence ||
		!slices.Equal(state.items, items) || state.status != localVaultFileStatusReady ||
		state.selected != aPath || len(state.refs) != 1 ||
		state.refs[0].name != renamed {
		t.Fatal("LOCAL_ORIGIN_NAME_ONLY_UPDATE_CHANGED_PROJECTION")
	}
	if aSlot.session != aSession {
		t.Fatal("LOCAL_ORIGIN_NAME_ONLY_UPDATE_CHANGED_CHILD")
	}
	if summary, err := aSession.Summary(); err != nil || summary.VaultID != aManifest.VaultID {
		t.Fatal("LOCAL_ORIGIN_NAME_ONLY_UPDATE_LOST_CHILD")
	}
}

func TestDesktopLocalVaultUnopenedPresentationFirstListPreservesNotice(t *testing.T) {
	f := newLocalVaultSessionFixture(t)
	q := &localVaultSessionQueue{}
	q.install(f.app)
	aPath, aManifest := f.createVault(t)
	scope := f.scope(aPath, aManifest)
	f.app.presentUnopenedLocalVaultFile(scope)
	state := &f.app.localVaultFiles
	const createdUnopened = "已创建，尚未打开；请核查本地状态"
	if state.selected != aPath || state.status != createdUnopened ||
		state.unopenedNotice == nil || state.projectionOrigin != nil ||
		state.items != nil {
		t.Fatal("LOCAL_UNOPENED_PRESENTATION_PRECONDITION_FAILED")
	}
	if slot := state.sessionSlots[scope]; slot != nil {
		t.Fatal("LOCAL_UNOPENED_PRESENTATION_CREATED_SLOT")
	}
	viewSequence := state.viewSequence
	if len(q.launches) != 1 {
		t.Fatal("LOCAL_UNOPENED_PRESENTATION_LIST_NOT_QUEUED")
	}
	q.runLaunch(t)
	q.runDispatch(t)
	if state.selected != aPath || state.status != createdUnopened ||
		state.unopenedNotice != nil || state.projectionOrigin != nil ||
		state.items != nil || state.viewSequence != viewSequence ||
		len(state.refs) != 1 || state.refs[0].path != aPath ||
		state.refs[0].vaultID != aManifest.VaultID ||
		state.refs[0].journalPath != aManifest.Journal ||
		state.refsBackendRoot != f.backendRoot {
		t.Fatal("LOCAL_UNOPENED_PRESENTATION_FIRST_LIST_NOT_PRESERVED")
	}
	if slot := state.sessionSlots[scope]; slot != nil {
		t.Fatal("LOCAL_UNOPENED_PRESENTATION_FIRST_LIST_CREATED_SLOT")
	}
}

func TestDesktopLocalVaultUnopenedNoticeRejectsMismatchedFirstList(t *testing.T) {
	for _, tc := range []struct {
		name        string
		preexisting bool
	}{
		{name: "wrong-id"},
		{name: "wrong-journal"},
		{name: "wrong-root"},
		{name: "missing-target"},
		{name: "list-failure"},
		{name: "stale-parent", preexisting: true},
		{name: "stale-generation", preexisting: true},
		{name: "stale-view-sequence", preexisting: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newLocalVaultSessionFixture(t)
			q := &localVaultSessionQueue{}
			q.install(f.app)
			aPath, aManifest := f.createVault(t)
			scope := f.scope(aPath, aManifest)
			f.app.presentUnopenedLocalVaultFile(scope)
			q.launches = nil
			state := &f.app.localVaultFiles
			const createdUnopened = "已创建，尚未打开；请核查本地状态"
			if state.status != createdUnopened || state.unopenedNotice == nil {
				t.Fatal("LOCAL_UNOPENED_NOTICE_NEGATIVE_SETUP_FAILED")
			}
			ref := localVaultNavigationRef(aPath, aManifest)
			refs := []localVaultFileRef{ref}
			backendRoot := f.backendRoot
			var listErr error
			switch tc.name {
			case "wrong-id":
				if ref.vaultID == "ffffffffffffffffffffffffffffffff" {
					ref.vaultID = "00000000000000000000000000000000"
				} else {
					ref.vaultID = "ffffffffffffffffffffffffffffffff"
				}
				refs = []localVaultFileRef{ref}
			case "wrong-journal":
				ref.journalPath = aManifest.Journal + ".other"
				refs = []localVaultFileRef{ref}
			case "wrong-root":
				backendRoot = f.backendRoot + "-other"
			case "missing-target":
				refs = nil
			case "list-failure":
				refs = nil
				listErr = vaultfileclient.ErrLocalReview
			case "stale-parent":
				state.unopenedNotice.parent = nil
			case "stale-generation":
				state.unopenedNotice.generation++
			case "stale-view-sequence":
				state.viewSequence++
			}
			if tc.preexisting {
				state.refs = []localVaultFileRef{localVaultNavigationRef(aPath, aManifest)}
				state.refsBackendRoot = f.backendRoot
			}
			f.app.applyLocalVaultFileRefs(refs, backendRoot, listErr)
			if state.unopenedNotice != nil || state.projectionOrigin != nil ||
				state.items != nil {
				t.Fatal("LOCAL_UNOPENED_NOTICE_NEGATIVE_RETAINED_PROJECTION")
			}
			if state.status == createdUnopened {
				t.Fatal("LOCAL_UNOPENED_NOTICE_NEGATIVE_PRESERVED_STATUS")
			}
			if slot := state.sessionSlots[scope]; slot != nil {
				t.Fatal("LOCAL_UNOPENED_NOTICE_NEGATIVE_CREATED_SLOT")
			}
		})
	}
}

func TestDesktopLocalVaultUnopenedNoticeRejectsPreexistingMatchingRefs(t *testing.T) {
	f := newLocalVaultSessionFixture(t)
	q := &localVaultSessionQueue{}
	q.install(f.app)
	aPath, aManifest := f.createVault(t)
	_, bManifest := f.createVault(t)
	aScope := f.scope(aPath, aManifest)
	bRef := localVaultNavigationRef(aPath, bManifest)
	if bRef.vaultID == aManifest.VaultID || bRef.journalPath == aManifest.Journal {
		t.Fatal("LOCAL_UNOPENED_NOTICE_FALLBACK_TUPLE_NOT_DISTINCT")
	}
	state := &f.app.localVaultFiles
	state.refs = []localVaultFileRef{bRef}
	state.refsBackendRoot = f.backendRoot
	f.app.presentUnopenedLocalVaultFile(aScope)
	q.launches = nil
	const createdUnopened = "已创建，尚未打开；请核查本地状态"
	if state.status != createdUnopened || state.unopenedNotice == nil {
		t.Fatal("LOCAL_UNOPENED_NOTICE_FALLBACK_SETUP_FAILED")
	}
	f.app.applyLocalVaultFileRefs([]localVaultFileRef{bRef}, f.backendRoot, nil)
	if state.unopenedNotice != nil || state.status != localVaultFileStatusUnavailable ||
		state.projectionOrigin != nil || state.items != nil {
		t.Fatal("LOCAL_UNOPENED_NOTICE_FALLBACK_PRESERVED_STATUS")
	}
	if slot := state.sessionSlots[aScope]; slot != nil {
		t.Fatal("LOCAL_UNOPENED_NOTICE_FALLBACK_CREATED_SLOT")
	}
}
