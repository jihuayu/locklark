//go:build darwin || linux

package desktop

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/egoist/mygo/ui"
	"github.com/jihuayu/locklark/internal/vaultfileclient"
	oneui "github.com/oneo-me/onevra/source/components"
	"github.com/oneo-me/onevra/source/theme"
)

func localVaultNavigationRef(path string, manifest vaultfileclient.Manifest) localVaultFileRef {
	return localVaultFileRef{
		path:        path,
		vaultID:     manifest.VaultID,
		name:        manifest.Name,
		journalPath: manifest.Journal,
	}
}

func TestDesktopLocalVaultFileNavigationUsesAdoptedChildCache(t *testing.T) {
	f := newLocalVaultSessionFixture(t)
	q := &localVaultSessionQueue{}
	q.install(f.app)
	aPath, aManifest := f.createVault(t)
	bPath, bManifest := f.createVault(t)
	aScope, bScope := f.scope(aPath, aManifest), f.scope(bPath, bManifest)
	f.openVault(t, q, aScope)
	f.openVault(t, q, bScope)
	aSlot, bSlot := f.app.localVaultFiles.sessionSlots[aScope], f.app.localVaultFiles.sessionSlots[bScope]
	if aSlot == nil || bSlot == nil || aSlot.session == nil || bSlot.session == nil {
		t.Fatal("LOCAL_NAV_CACHE_CHILDREN_MISSING")
	}
	aSession, bSession := aSlot.session, bSlot.session
	aRef := localVaultNavigationRef(aPath, aManifest)
	bRef := localVaultNavigationRef(bPath, bManifest)
	f.app.localVaultFiles.refs = []localVaultFileRef{aRef, bRef}
	q.launches, q.dispatches = nil, nil

	f.app.selectLocalVaultFile(aRef)
	if f.app.localVaultFiles.selected != aPath || f.app.localVaultFiles.status != localVaultFileStatusReady {
		t.Fatal("LOCAL_NAV_A_CACHE_NOT_SELECTED")
	}
	if len(q.launches) != 0 || len(q.dispatches) != 0 {
		t.Fatal("LOCAL_NAV_A_CACHE_QUEUED_WORK")
	}
	if f.app.localVaultFiles.sessionSlots[aScope] != aSlot || aSlot.session != aSession ||
		f.app.localVaultFiles.sessionSlots[bScope] != bSlot || bSlot.session != bSession {
		t.Fatal("LOCAL_NAV_A_CACHE_REPLACED_CHILD")
	}
	if got := f.app.localVaultFileRefreshCaption(); got != localVaultFileCachedCaption {
		t.Fatal("LOCAL_NAV_A_CACHE_CAPTION_NOT_CACHED")
	}

	// Establish real fresh provenance through the reviewed refresh controller,
	// then prove navigation returns the same child to cached provenance.
	if f.app.beginLocalVaultFileRefresh(aScope) == nil {
		t.Fatal("LOCAL_NAV_REFRESH_NOT_STARTED")
	}
	q.runLaunch(t)
	q.runDispatch(t)
	if got := f.app.localVaultFileRefreshCaption(); got != localVaultFileFreshCaption {
		t.Fatal("LOCAL_NAV_REFRESH_NOT_FRESH")
	}
	q.launches, q.dispatches = nil, nil

	f.app.closeLocalVaultFileView()
	if f.app.localVaultFiles.selected != "" || len(f.app.localVaultFiles.items) != 0 {
		t.Fatal("LOCAL_NAV_CLOSE_RETAINED_VIEW")
	}
	if f.app.localVaultFiles.sessionSlots[aScope] != aSlot || aSlot.session != aSession ||
		f.app.localVaultFiles.sessionSlots[bScope] != bSlot || bSlot.session != bSession {
		t.Fatal("LOCAL_NAV_CLOSE_CHANGED_CHILD")
	}

	f.app.selectLocalVaultFile(bRef)
	if f.app.localVaultFiles.selected != bPath || f.app.localVaultFiles.status != localVaultFileStatusReady {
		t.Fatal("LOCAL_NAV_B_CACHE_NOT_SELECTED")
	}
	if got := f.app.localVaultFileRefreshCaption(); got != localVaultFileCachedCaption {
		t.Fatal("LOCAL_NAV_B_CACHE_CAPTION_NOT_CACHED")
	}
	f.app.selectLocalVaultFile(aRef)
	if f.app.localVaultFiles.selected != aPath || f.app.localVaultFiles.status != localVaultFileStatusReady {
		t.Fatal("LOCAL_NAV_BACK_CACHE_NOT_SELECTED")
	}
	if got := f.app.localVaultFileRefreshCaption(); got != localVaultFileCachedCaption {
		t.Fatal("LOCAL_NAV_BACK_FRESH_PROVENANCE_NOT_RESET")
	}
	if len(q.launches) != 0 || len(q.dispatches) != 0 {
		t.Fatal("LOCAL_NAV_BACK_QUEUED_WORK")
	}
	if f.app.localVaultFiles.sessionSlots[aScope] != aSlot || aSlot.session != aSession ||
		f.app.localVaultFiles.sessionSlots[bScope] != bSlot || bSlot.session != bSession {
		t.Fatal("LOCAL_NAV_BACK_REPLACED_CHILD")
	}
	if summary, err := aSession.Summary(); err != nil || summary.VaultID != aManifest.VaultID {
		t.Fatal("LOCAL_NAV_A_CHILD_NOT_ALIVE")
	}
	if summary, err := bSession.Summary(); err != nil || summary.VaultID != bManifest.VaultID {
		t.Fatal("LOCAL_NAV_B_CHILD_NOT_ALIVE")
	}
}

func TestDesktopLocalVaultFileNavigationFiniteWithoutCache(t *testing.T) {
	f := newLocalVaultSessionFixture(t)
	q := &localVaultSessionQueue{}
	q.install(f.app)
	aPath, aManifest := f.createVault(t)
	aRef := localVaultNavigationRef(aPath, aManifest)
	f.app.localVaultFiles.refs = []localVaultFileRef{aRef}

	f.app.selectLocalVaultFile(aRef)
	if f.app.localVaultFiles.selected != aPath ||
		f.app.localVaultFiles.status != "本地文件库尚未解锁" ||
		len(f.app.localVaultFiles.items) != 0 {
		t.Fatal("LOCAL_NAV_MISSING_CHILD_NOT_FINITE_LOCKED")
	}
	if len(q.launches) != 0 || len(q.dispatches) != 0 {
		t.Fatal("LOCAL_NAV_MISSING_CHILD_AUTO_OPENED")
	}
	if slot := f.app.localVaultFiles.sessionSlots[f.scope(aPath, aManifest)]; slot != nil && slot.session != nil {
		t.Fatal("LOCAL_NAV_MISSING_CHILD_ADOPTED")
	}

	missing := aRef
	missing.vaultID = ""
	f.app.selectLocalVaultFile(missing)
	if f.app.localVaultFiles.selected != aPath || f.app.localVaultFiles.status != localVaultFileStatusReview {
		t.Fatal("LOCAL_NAV_MISSING_HINT_NOT_REVIEW")
	}
	if len(q.launches) != 0 || len(q.dispatches) != 0 {
		t.Fatal("LOCAL_NAV_MISSING_HINT_QUEUED_WORK")
	}

	// Busy withholds delivery and must preserve an already adopted sibling.
	bPath, bManifest := f.createVault(t)
	bScope := f.scope(bPath, bManifest)
	f.openVault(t, q, bScope)
	bSlot := f.app.localVaultFiles.sessionSlots[bScope]
	if bSlot == nil || bSlot.session == nil {
		t.Fatal("LOCAL_NAV_BUSY_SIBLING_SETUP_FAILED")
	}
	bSession := bSlot.session
	q.launches, q.dispatches = nil, nil
	release := holdDesktopParentDBBusy(t, f)
	f.app.selectLocalVaultFile(aRef)
	if f.app.localVaultFiles.status != localVaultFileStatusUnavailable {
		release()
		t.Fatal("LOCAL_NAV_BUSY_NOT_FINITE_UNAVAILABLE")
	}
	if f.app.localVaultFiles.sessionSlots[bScope] != bSlot || bSlot.session != bSession {
		release()
		t.Fatal("LOCAL_NAV_BUSY_REPLACED_SIBLING")
	}
	release()
	if summary, err := bSession.Summary(); err != nil || summary.VaultID != bManifest.VaultID {
		t.Fatal("LOCAL_NAV_BUSY_LOST_SIBLING")
	}
	if len(q.launches) != 0 || len(q.dispatches) != 0 {
		t.Fatal("LOCAL_NAV_BUSY_QUEUED_WORK")
	}
}

func TestDesktopLocalVaultFileLabelSnapshotSharedBindings(t *testing.T) {
	f := newLocalVaultSessionFixture(t)
	aRef := localVaultFileRef{
		path:        filepath.Join(f.profileDir, "shared-a.json"),
		vaultID:     "01234567000000000000000000000000",
		name:        "本地库🙂",
		journalPath: filepath.Join(f.profileDir, "shared-a.journal"),
	}
	bRef := localVaultFileRef{
		path:        filepath.Join(f.profileDir, "shared-b.json"),
		vaultID:     "01234567111111111111111111111111",
		name:        "第二库",
		journalPath: filepath.Join(f.profileDir, "shared-b.journal"),
	}
	f.app.localVaultFiles.refs = []localVaultFileRef{aRef}
	f.app.localVaultFiles.selected = aRef.path

	wantA := localVaultFileDisplayLabels([]localVaultFileRef{aRef})[0].label
	if got := f.app.localVaultFileLabel(); got != wantA {
		t.Fatal("LOCAL_NAV_LABEL_TITLE_NOT_HELPER_STRING")
	}
	if strings.HasPrefix(wantA, "独立文件库：") || strings.Contains(wantA, f.profileDir) {
		t.Fatal("LOCAL_NAV_LABEL_TITLE_LEGACY_PREFIX_OR_PATH")
	}
	if got := f.app.localVaultFileDisplayLabelSnapshot(); len(got) != 1 ||
		got[0].ref != aRef || got[0].label != wantA {
		t.Fatal("LOCAL_NAV_LABEL_SNAPSHOT_NOT_HELPER_STRING")
	}

	render := func() *ui.Tester {
		return ui.NewTester(func(c *ui.Context) {
			c.SetTheme(theme.Onevra(c))
			oneui.Sidebar(c).Children(func() { f.app.onevraLocalVaultFileSidebar(c) })
		}, 480, 500)
	}
	if err := render().Click(wantA); err != nil || f.app.localVaultFiles.selected != aRef.path {
		t.Fatal("LOCAL_NAV_LABEL_SIDEBAR_NOT_EXACT_HELPER_STRING")
	}
	if !f.app.openLocalVaultFileUnlock(aRef) || f.app.localVaultUnlock.target.label != wantA {
		t.Fatal("LOCAL_NAV_LABEL_UNLOCK_TARGET_NOT_SHARED_SNAPSHOT")
	}
	f.app.cancelLocalVaultFileUnlock()

	f.app.localVaultFiles.refs = []localVaultFileRef{aRef, bRef}
	wantAWithB := localVaultFileDisplayLabels([]localVaultFileRef{aRef, bRef})[0].label
	if wantAWithB == wantA {
		t.Fatal("LOCAL_NAV_LABEL_B_ADDITION_DID_NOT_EXTEND_PREFIX")
	}
	snapshot := f.app.localVaultFileDisplayLabelSnapshot()
	if len(snapshot) != 2 || snapshot[0].ref != aRef || snapshot[1].ref != bRef ||
		snapshot[0].label != wantAWithB {
		t.Fatal("LOCAL_NAV_LABEL_SNAPSHOT_NOT_REFRESHED")
	}
	if got := f.app.localVaultFileLabel(); got != wantAWithB {
		t.Fatal("LOCAL_NAV_LABEL_TITLE_NOT_REFRESHED")
	}
	if err := render().Click(wantAWithB); err != nil || f.app.localVaultFiles.selected != aRef.path {
		t.Fatal("LOCAL_NAV_LABEL_SIDEBAR_NOT_REFRESHED")
	}
	if !f.app.openLocalVaultFileUnlock(aRef) || f.app.localVaultUnlock.target.label != wantAWithB {
		t.Fatal("LOCAL_NAV_LABEL_UNLOCK_TARGET_NOT_REFRESHED")
	}
	f.app.cancelLocalVaultFileUnlock()
	if !strings.Contains(wantAWithB, "本地库🙂") || strings.Contains(wantAWithB, f.profileDir) {
		t.Fatal("LOCAL_NAV_LABEL_TEXT_OR_PATH_CHANGED")
	}
}
