package desktop

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"

	"github.com/egoist/mygo/ui"
	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/teamfiles"
	"github.com/jihuayu/locklark/internal/vaultfileclient"
	oneui "github.com/oneo-me/onevra/source/components"
	"github.com/oneo-me/onevra/source/icons/lucide"
)

const (
	localVaultFileStatusReview      = "本地文件库待核查"
	localVaultFileStatusLocked      = "本地文件库尚未解锁"
	localVaultFileStatusUnavailable = "本地文件库暂不可用；请稍后核查"
	localVaultFileStatusReady       = "已验证本地初始版本 · 远端状态未核实"
)

// Local refs are navigation hints only. They never supply a policy checkpoint.
// journalPath is a captured scheduling hint from the strict manifest read; it is
// not a routing identity, grant or authority.
type localVaultFileRef struct {
	path, vaultID, name, journalPath string
}

type localVaultFileState struct {
	refs         []localVaultFileRef
	selected     string
	items        []personal.VaultFileBaselineItem
	status       string
	listSequence uint64
	// displayLabelRefs and displayLabels are a private display-only snapshot.
	// They are recomputed from the exact current refs whenever list metadata
	// differs, including when tests assign refs directly. The snapshot is never
	// an identity, route, grant or authority key.
	displayLabelRefs []localVaultFileRef
	displayLabels    []localVaultFileDisplayLabel

	// Projection provenance for the local vault-file view. This is controller
	// state only; the view layer renders the caption from it. viewSequence
	// invalidates pending delivery and fresh evidence on navigation, while an
	// adopted child and its bounded cache summary stay alive.
	viewSequence     uint64
	viewVerification localVaultFileViewVerification

	// Owned-session lifecycle state. It is reset on lock and never survives a
	// parent or App generation boundary. The wrapper itself is opaque here.
	sessionSlots map[localVaultFileSessionScope]*localVaultFileSessionSlot
	// sessionParent, sessionGeneration and sessionPath are bound together by
	// syncLocalVaultFileSessions from one nonblocking VaultFileCacheSnapshot.
	// sessionPath is only a routing hint for the exact parent and App
	// generation; it is never auth, proof, a factor, grant or token, and it is
	// empty for Busy/Revoked with no fallback to an older Active path.
	sessionParent     *personal.Session
	sessionGeneration uint64
	sessionPath       string
	// lockSequence is the private monotonic binding sequence for explicit lock
	// operations. It is never a path, authority, factor or routing identity.
	lockSequence uint64
	// sessionCandidateForTest observes the staged operation after the
	// production factory result has been handed off and before dispatch. The
	// worker captures it before launch; production leaves it nil.
	sessionCandidateForTest func(*localVaultFileSessionOperation)
	// sessionCandidateOpenPauseForTest and sessionCandidateClosePauseForTest
	// are parameterless private seams, nil in production. The open pause runs
	// at generic worker entry after the cancel check and before the real
	// factory; the close pause runs immediately before the real cleanup Close
	// of a candidate that never became an adopted slot. Both are captured
	// before launch so the worker never reads mutable App state, and neither
	// receives a factor, key, identity, VUK, handle or capability.
	sessionCandidateOpenPauseForTest  func()
	sessionCandidateClosePauseForTest func()
	// sessionPredecessorWaitForTest runs when a producer is about to wait for
	// its captured predecessors. sessionPostBarrierCancelPauseForTest runs in
	// the cancelled-after-barrier path just before the producer marks
	// processing finished. Both are parameterless, nil in production and
	// captured before launch; neither receives a factor, key, handle or
	// capability.
	sessionPredecessorWaitForTest        func()
	sessionPostBarrierCancelPauseForTest func()
	// refreshSummaryPauseForTest runs in the refresh worker immediately after
	// the real borrowed wrapper Summary returns and before the projection is
	// staged. It is parameterless, nil in production and captured before
	// launch; it never receives a factor, key, handle or capability.
	refreshSummaryPauseForTest func()
	// afterActiveSnapshotForTest, when non-nil, runs exactly once on the UI
	// path after an Active VaultFileCacheSnapshot has captured its routing path
	// and released the parent mutex, before the UI computes the next path. It
	// is nil in production and exists only for deterministic Busy-after-Active
	// regressions. The first caller claims it with an atomic compare-and-swap,
	// so no caller blocks on another caller's pause.
	afterActiveSnapshotForTest func()
	afterActiveSnapshotClaimed atomic.Bool
	// sessionAdoptedClosePauseForTest runs in the tracked-close worker
	// immediately before the real adopted wrapper Close. It is parameterless,
	// nil in production and captured on the UI path before launch; it never
	// receives a factor, key, kit, token, handle or capability.
	sessionAdoptedClosePauseForTest func()
}

func localVaultFilePaths(settingsPath, personalPath string) (profileDir, backendRoot string) {
	base := filepath.Join(filepath.Dir(settingsPath), "vaultfile-workspace")
	sum := sha256.Sum256([]byte(personalPath))
	return filepath.Join(base, "profiles", hex.EncodeToString(sum[:])), filepath.Join(base, "backend")
}

// localVaultFileRoutingPath performs the one nonblocking snapshot read used by
// this UI decision and returns the path only while Active. The returned value
// is bound to the exact current parent and App generation and is a routing
// hint only, never auth, proof, a factor, grant or token. Busy and Revoked
// return an empty path with no fallback to an older hint.
func (a *App) localVaultFileRoutingPath() (string, personal.VaultFileCacheState) {
	cache := a.syncLocalVaultFileSessions()
	state := &a.localVaultFiles
	if cache != personal.VaultFileCacheActive || state.sessionPath == "" ||
		state.sessionParent != a.session || state.sessionGeneration != a.generation {
		return "", cache
	}
	path := state.sessionPath
	a.runAfterActiveSnapshotForTest()
	return path, cache
}

// localVaultFileBoundRoutingPath returns the path already bound by the most
// recent sync for this exact parent and App generation. It never takes a new
// snapshot or calls a blocking parent method; callers use it only immediately
// after a successful snapshot helper.
func (a *App) localVaultFileBoundRoutingPath() (string, bool) {
	state := &a.localVaultFiles
	if state.sessionPath == "" || state.sessionParent != a.session ||
		state.sessionGeneration != a.generation {
		return "", false
	}
	return state.sessionPath, true
}

func (a *App) runAfterActiveSnapshotForTest() {
	pause := a.localVaultFiles.afterActiveSnapshotForTest
	if pause == nil || !a.localVaultFiles.afterActiveSnapshotClaimed.CompareAndSwap(false, true) {
		return
	}
	pause()
}

func listLocalVaultFileRefs(profileDir, backendRoot, personalPath string) ([]localVaultFileRef, error) {
	if _, err := os.Lstat(profileDir); os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
		return nil, vaultfileclient.ErrLocalReview
	}
	if teamfiles.ValidatePrivateParent(profileDir) != nil {
		return nil, vaultfileclient.ErrLocalReview
	}
	entries, err := os.ReadDir(profileDir)
	if err != nil || len(entries) > 128 {
		return nil, vaultfileclient.ErrLocalReview
	}
	refs := make([]localVaultFileRef, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(profileDir, entry.Name())
		ref := localVaultFileRef{path: path, name: "待核查文件"}
		manifest, exists, e := vaultfileclient.ReadManifest(path)
		if e == nil && exists && manifest.PersonalFile == personalPath && manifest.BackendRoot == backendRoot {
			ref.vaultID, ref.name, ref.journalPath = manifest.VaultID, manifest.Name, manifest.Journal
		}
		refs = append(refs, ref)
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].path < refs[j].path })
	return refs, nil
}

func (a *App) refreshLocalVaultFiles() {
	if a.session == nil {
		return
	}
	personalPath, cache := a.localVaultFileRoutingPath()
	if cache != personal.VaultFileCacheActive || personalPath == "" {
		// Withhold this list refresh without clobbering the current finite
		// status (including creation-complete presentation). No sibling or
		// projection state is touched.
		return
	}
	// Freeze the nonblocking routing path before the listing worker starts so
	// the UI never calls the blocking Session.VaultPath method.
	session, generation := a.session, a.generation
	a.localVaultFiles.listSequence++
	listSequence := a.localVaultFiles.listSequence
	profileDir, backendRoot := localVaultFilePaths(a.settingsPath, personalPath)
	a.launch(func() {
		refs, err := listLocalVaultFileRefs(profileDir, backendRoot, personalPath)
		a.dispatch(func() {
			if a.session != session || a.generation != generation || a.localVaultFiles.listSequence != listSequence {
				return
			}
			if err != nil {
				a.localVaultFiles.refs = nil
				a.localVaultFiles.status = "本地文件库目录待核查"
			} else {
				a.localVaultFiles.refs = refs
			}
			if a.win != nil {
				a.win.Invalidate()
			}
		})
	})
}

func (a *App) closeLocalVaultFileView() {
	// Navigation invalidates fresh view evidence and only this view's pending
	// refresh delivery. The adopted child and its cache summary remain alive.
	a.cancelLocalVaultFileRefreshView()
	state := &a.localVaultFiles
	state.selected, state.items, state.status = "", nil, ""
}

// localVaultFileNavigationScope resolves one navigation ref through the
// existing full-scope helper and requires the captured journal hint and a
// canonical path inside this workspace. It reads no manifest and touches no
// wrapper.
func (a *App) localVaultFileNavigationScope(ref localVaultFileRef) (localVaultFileSessionScope, bool) {
	scope, ok := a.localVaultFileSessionScopeFor(ref)
	if !ok || scope.configPath != ref.path || scope.vaultID == "" ||
		scope.backendRoot == "" || scope.journalPath == "" ||
		!filepath.IsAbs(ref.path) || filepath.Clean(ref.path) != ref.path {
		return localVaultFileSessionScope{}, false
	}
	personalPath, ok := a.localVaultFileBoundRoutingPath()
	if !ok {
		return localVaultFileSessionScope{}, false
	}
	profileDir, backendRoot := localVaultFilePaths(a.settingsPath, personalPath)
	if backendRoot != scope.backendRoot || filepath.Dir(ref.path) != profileDir {
		return localVaultFileSessionScope{}, false
	}
	return scope, true
}

// selectLocalVaultFile is pure navigation over the existing C1 scope/cache
// boundary. It never calls the legacy baseline opener, the wrapper's Summary or
// any factory/factor/unwrap path. Only the bounded cache projection of an
// already adopted child is delivered; a missing child gives finite controller
// feedback and waits for the future explicit unlock action.
func (a *App) selectLocalVaultFile(ref localVaultFileRef) {
	if a.session == nil || !a.session.Unlocked() {
		return
	}
	a.closeLocalVaultFileView()
	state := &a.localVaultFiles
	state.selected = ref.path
	switch a.syncLocalVaultFileSessions() {
	case personal.VaultFileCacheBusy:
		// Withhold delivery but preserve every adopted sibling wrapper and its
		// cache. A later explicit navigation can try again.
		state.status = localVaultFileStatusUnavailable
		return
	case personal.VaultFileCacheActive:
		// Continue below.
	default:
		// Revoked already ran the established C1 clear through sync.
		state.status = localVaultFileStatusReview
		return
	}
	scope, ok := a.localVaultFileNavigationScope(ref)
	if !ok {
		if a.syncLocalVaultFileSessions() == personal.VaultFileCacheBusy {
			state.status = localVaultFileStatusUnavailable
		} else {
			state.status = localVaultFileStatusReview
		}
		return
	}
	summary, ok := a.readLocalVaultFileSession(scope)
	if !ok {
		switch a.syncLocalVaultFileSessions() {
		case personal.VaultFileCacheBusy:
			state.status = localVaultFileStatusUnavailable
		case personal.VaultFileCacheActive:
			state.status = localVaultFileStatusLocked
		default:
			state.status = localVaultFileStatusReview
		}
		return
	}
	if summary.VaultID != scope.vaultID {
		clearLocalVaultFileSessionSummary(&summary)
		state.status = localVaultFileStatusReview
		return
	}
	state.items = summary.Items
	state.status = localVaultFileStatusReady
}

// localVaultFileDisplayLabelSnapshot returns one whole-list snapshot shared by
// the sidebar, the selected title and future unlock-dialog display metadata.
// The exact input refs are compared on every access so direct test assignment
// and any metadata or list change refresh the entire group.
func (a *App) localVaultFileDisplayLabelSnapshot() []localVaultFileDisplayLabel {
	state := &a.localVaultFiles
	if state.displayLabels != nil && localVaultFileRefsEqual(state.displayLabelRefs, state.refs) {
		return state.displayLabels
	}
	state.displayLabelRefs = append([]localVaultFileRef(nil), state.refs...)
	state.displayLabels = localVaultFileDisplayLabels(state.displayLabelRefs)
	return state.displayLabels
}

func localVaultFileRefsEqual(a, b []localVaultFileRef) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// localVaultFileDisplayLabelFor retrieves the shared snapshot label for one
// exact ref. The ref stays the route; the label is display metadata only.
func (a *App) localVaultFileDisplayLabelFor(ref localVaultFileRef) string {
	for _, entry := range a.localVaultFileDisplayLabelSnapshot() {
		if entry.ref == ref {
			return entry.label
		}
	}
	return ref.name
}

func (a *App) onevraLocalVaultFileSidebar(c *ui.Context) {
	oneui.SidebarSection(c, "独立文件库", func() {
		for _, entry := range a.localVaultFileDisplayLabelSnapshot() {
			ref, label := entry.ref, entry.label
			name, suffix := localVaultFileSidebarLabelParts(ref, label)
			item := oneui.SidebarItemWithContent(c, label, a.localVaultFiles.selected == ref.path,
				func(c *ui.Context, size float32) { oneui.Icon(c, lucide.Vault()).Size(size, size) },
				func(c *ui.Context) ui.Element { return oneui.Text(c, name).SingleLine() },
				func(c *ui.Context, size float32) {
					if suffix == "" {
						return
					}
					oneui.Text(c, suffix).FontSize(c.Theme().Rem(.72)).TextColor(c.Theme().TextMuted).SingleLine()
				})
			pathHash := sha256.Sum256([]byte(ref.path))
			item.Key("local-vault-file:" + hex.EncodeToString(pathHash[:]))
			if item.Clicked() {
				a.selectLocalVaultFile(ref)
			}
		}
		if oneui.Button(c, "刷新独立文件库", oneui.ButtonGhost).Clicked() {
			a.refreshLocalVaultFiles()
		}
		if oneui.Button(c, "新建独立文件库", oneui.ButtonGhost).Clicked() {
			a.openLocalVaultFileCreate("")
		}
	})
}

// localVaultFileSidebarLabelParts splits the reviewed helper output for layout
// only. The accessible button label remains the exact whole helper string; the
// suffix occupies the existing trailing slot so it stays visible when a long
// name truncates. No formatter, ID or fallback rule is reimplemented here.
func localVaultFileSidebarLabelParts(ref localVaultFileRef, label string) (name, suffix string) {
	displayName := localVaultFileDisplayName(ref.name)
	prefix := displayName + " · "
	if strings.HasPrefix(label, prefix) {
		return displayName, label[len(prefix):]
	}
	return label, ""
}

func (a *App) localVaultFileLabel() string {
	if a.localVaultFiles.selected == "" {
		return "独立文件库"
	}
	for _, entry := range a.localVaultFileDisplayLabelSnapshot() {
		if entry.ref.path == a.localVaultFiles.selected {
			// The reviewed helper string is the complete accessible title. No
			// legacy "独立文件库：" prefix is added for a known ref.
			return entry.label
		}
	}
	return "独立文件库"
}

func (a *App) onevraLocalVaultFileView(c *ui.Context) {
	t := c.Theme()
	ui.Column(c).Fill().Padding(t.Space(3)).Gap(t.Space(2)).Children(func() {
		oneui.Text(c, a.localVaultFiles.status).Bold()
		if caption := a.localVaultFileRefreshCaption(); caption != "" {
			oneui.Text(c, caption).TextColor(t.TextMuted)
		}
		if oneui.Button(c, "关闭本地基线视图", oneui.ButtonOutline).Clicked() {
			a.closeLocalVaultFileView()
		}
		if a.localVaultFiles.status == localVaultFileStatusReview && !a.localCreate.open {
			if oneui.Button(c, "核查或继续创建", oneui.ButtonOutline).Clicked() {
				a.openLocalVaultFileCreate(a.localVaultFiles.selected)
			}
		}
		for _, item := range a.localVaultFiles.items {
			oneui.Text(c, item.Title).SingleLine()
		}
	})
}
