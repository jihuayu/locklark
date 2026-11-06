package desktop

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/vault"
)

// Sidebar primary views. Category and tag filters are represented by the
// dedicated navCategory and navTag kinds plus the selected value.
const (
	navAllItems       = "all"
	navFavorites      = "favorites"
	navWatchtower     = "watchtower"
	navRecentlyDelete = "recently_deleted"
	navArchive        = "archive"
	navCategory       = "category"
	navTag            = "tag"
)

// TagCount is a sidebar tag row.
type TagCount struct {
	Tag   string
	Count int
}

// v2State owns the non-secret state of the three-pane desktop UI. Drafts and
// revealed values live here only while the session is unlocked; resetV2 is
// called from Lock before any secret-bearing buffer can be rendered again.
type v2State struct {
	loaded bool

	nav      string
	category vault.ItemCategory
	tag      string
	vaultID  string
	sortBy   string

	rows          []personal.ItemSummary
	all           []personal.ItemSummary
	vaults        []vault.VaultMeta
	tags          []TagCount
	categoryCount map[vault.ItemCategory]int
	vaultCount    map[string]int

	detail      *personal.ItemDetail
	detailPlain *personal.ItemDetail
	editing     bool
	draft       *ItemDraft

	historyOpen    bool
	showWatchtower bool
	watchtower     *WatchtowerReport
	watchtowerErr  string
	ignored        map[string]bool

	generator generatorState

	revealed       map[string]bool
	revealUntil    time.Time
	largeTypeOpen  bool
	largeTypeKey   string
	largeTypeLabel string
	largeTypeValue string

	selectedID       string
	selectedRevision string

	newVaultOpen bool
	newVaultName string
	newVaultDesc string
	newVaultIcon string

	moveTarget    string
	confirmPurge  bool
	confirmEmpty  bool
	attachmentMsg string
	editorError   string
	searchError   string
}

func newV2State() v2State {
	return v2State{
		nav:           navAllItems,
		vaultID:       "all",
		sortBy:        "title",
		categoryCount: map[vault.ItemCategory]int{},
		vaultCount:    map[string]int{},
		ignored:       map[string]bool{},
		revealed:      map[string]bool{},
		generator:     defaultGeneratorState(),
	}
}

// resetV2 drops every draft, revealed value and selection. Settings are
// deliberately not part of v2State and therefore survive a lock.
func (a *App) resetV2() {
	a.v2 = newV2State()
}

// classicLayoutRequested reports whether the classic single-list layout was
// requested via LOCKLARK_DESKTOP_LAYOUT=classic. The three-pane layout is the
// default; the classic layout remains available for users and for the native
// accessibility acceptance suites that drive its labels.
func classicLayoutRequested() bool {
	return os.Getenv("LOCKLARK_DESKTOP_LAYOUT") == "classic"
}

// EnableV2 enters the three-pane UI. It exists so tests and embedders that
// construct a Session without calling unlock still get deterministic state.
func (a *App) EnableV2() {
	if a.v2.nav == "" {
		a.v2 = newV2State()
	}
	a.v2Mode = true
	a.page = "vault"
	a.touchActivity()
}

func (a *App) enableV2() { a.EnableV2() }

// loadV2Metadata performs the first authenticated list after unlock.
func (a *App) loadV2Metadata() { a.reloadV2(false) }

// currentFilter derives the personal.ItemFilter for the active sidebar view,
// search query and sort order. It is safe to call before a session exists.
func (a *App) currentFilter() personal.ItemFilter {
	state := "active"
	switch a.v2.nav {
	case navArchive:
		state = "archived"
	case navRecentlyDelete:
		state = "trashed"
	case navAllItems, navFavorites, navWatchtower, navCategory, navTag:
		state = "active"
	}
	filter := personal.ItemFilter{
		VaultID: a.v2.vaultID,
		State:   state,
		Query:   a.query,
		SortBy:  a.v2.sortBy,
	}
	if a.v2.nav == navFavorites {
		favorite := true
		filter.Favorite = &favorite
	}
	if a.v2.nav == navCategory {
		filter.Category = a.v2.category
	}
	if a.v2.nav == navTag {
		filter.Tag = a.v2.tag
	}
	return filter
}

// legacyRow projects a v2 summary into the v1 row shape used by the legacy
// views and by existing tests.
func legacyRow(s personal.ItemSummary) personal.Row {
	return personal.Row{
		Kind:         s.Kind,
		ID:           s.ID,
		Title:        s.Title,
		Revision:     s.Revision,
		State:        s.State,
		RestoreState: s.RestoreState,
	}
}

func legacyRows(rows []personal.ItemSummary) []personal.Row {
	out := make([]personal.Row, 0, len(rows))
	for _, row := range rows {
		out = append(out, legacyRow(row))
	}
	return out
}

// navigate switches the sidebar view. Supported targets:
//
//	all, favorites, watchtower, recently_deleted, archive
//	category:<slug>, tag:<name>, vault:<id|all>
//	<category slug>            (e.g. "credit_card")
func (a *App) navigate(target string) {
	a.EnableV2()
	target = strings.TrimSpace(target)
	lower := strings.ToLower(target)
	switch lower {
	case "", "all", "all_items", "all items", "vault", "金库":
		a.v2.nav = navAllItems
		a.v2.category = ""
		a.v2.tag = ""
	case "favorites", "favourite", "收藏", "收藏夹":
		a.v2.nav = navFavorites
		a.v2.category = ""
		a.v2.tag = ""
	case "watchtower", "health", "安全体检":
		a.v2.nav = navWatchtower
		a.v2.category = ""
		a.v2.tag = ""
		a.v2.showWatchtower = true
	case "recently_deleted", "recently deleted", "trash", "trashed", "recentlydeleted", "回收站", "最近删除":
		a.v2.nav = navRecentlyDelete
		a.v2.category = ""
		a.v2.tag = ""
	case "archive", "archived", "归档":
		a.v2.nav = navArchive
		a.v2.category = ""
		a.v2.tag = ""
	default:
		switch {
		case strings.HasPrefix(lower, "category:"):
			a.setCategoryFilter(vault.ItemCategory(strings.TrimPrefix(lower, "category:")))
		case strings.HasPrefix(lower, "tag:"):
			a.setTagFilter(target[len("tag:"):])
		case strings.HasPrefix(lower, "vault:"):
			a.selectVault(target[len("vault:"):])
		case vault.ValidCategory(vault.ItemCategory(lower)):
			a.setCategoryFilter(vault.ItemCategory(lower))
		default:
			a.status = "未知的侧边栏视图：" + target
			return
		}
	}
	a.touchActivity()
	a.reloadV2(false)
}

// Navigate is an exported alias for embedders and external tests.
func (a *App) Navigate(target string) { a.navigate(target) }

func (a *App) setCategoryFilter(category vault.ItemCategory) {
	if category == "" {
		return
	}
	if !vault.ValidCategory(category) {
		a.status = "未知条目类别：" + string(category)
		return
	}
	a.v2.nav = navCategory
	a.v2.category = category
	a.v2.tag = ""
}

func (a *App) FilterByCategory(category vault.ItemCategory) {
	a.EnableV2()
	a.setCategoryFilter(category)
	a.touchActivity()
	a.reloadV2(false)
}

func (a *App) setTagFilter(tag string) {
	tag = strings.TrimSpace(tag)
	if tag == "" {
		return
	}
	a.v2.nav = navTag
	a.v2.tag = tag
	a.v2.category = ""
}

func (a *App) FilterByTag(tag string) {
	a.EnableV2()
	a.setTagFilter(tag)
	a.touchActivity()
	a.reloadV2(false)
}

func (a *App) showAllItems()        { a.navigate(navAllItems) }
func (a *App) showFavorites()       { a.navigate(navFavorites) }
func (a *App) showRecentlyDeleted() { a.navigate(navRecentlyDelete) }
func (a *App) showArchive()         { a.navigate(navArchive) }
func (a *App) ShowAllItems()        { a.showAllItems() }
func (a *App) ShowFavorites()       { a.showFavorites() }
func (a *App) ShowRecentlyDeleted() { a.showRecentlyDeleted() }
func (a *App) ShowArchive()         { a.showArchive() }

func (a *App) SetSort(sortBy string) {
	switch sortBy {
	case "title", "updated_at", "created_at":
	default:
		a.status = "未知排序方式：" + sortBy
		return
	}
	a.v2.sortBy = sortBy
	a.touchActivity()
	a.reloadV2(true)
}

func (a *App) SetSearchQuery(query string) {
	a.query = query
	a.v2.searchError = ""
	if a.query != "" && !personal.ValidSearchQuery(a.query) {
		a.v2.searchError = "搜索词须为有效文字，最多 256 字节，不能包含控制字符。"
		return
	}
	a.touchActivity()
	a.reloadV2(true)
}

func (a *App) searchV2() { a.SetSearchQuery(a.query) }

// refresh preserves the active search, category, tag, vault and sort order.
// It replaces the legacy title-only refresh path while keeping a.rows for the
// legacy views and existing tests.
func (a *App) refreshV2() {
	a.clearNotesEditor()
	a.clearDailyExposure()
	a.regenerate = nil
	a.reloadV2(false)
}

type v2Snapshot struct {
	rows   []personal.ItemSummary
	all    []personal.ItemSummary
	vaults []vault.VaultMeta
	err    error
}

// captureV2 collects every list needed by the three-pane layout in one
// authenticated read pass. filter is captured on the UI goroutine.
func (a *App) captureV2(s *personal.Session, filter personal.ItemFilter) v2Snapshot {
	if s == nil {
		return v2Snapshot{err: personal.ErrSessionLocked}
	}
	rows, err := s.ListByFilter(filter)
	if err != nil {
		return v2Snapshot{err: err}
	}
	all, err := s.ListByFilter(personal.ItemFilter{State: "all", VaultID: filter.VaultID, SortBy: "title"})
	if err != nil {
		return v2Snapshot{err: err}
	}
	vaults, err := s.ListVaults()
	if err != nil {
		return v2Snapshot{err: err}
	}
	return v2Snapshot{rows: rows, all: all, vaults: vaults}
}

func (a *App) applyV2Snapshot(snap v2Snapshot, keepSelection bool) {
	a.v2.rows = snap.rows
	a.v2.all = snap.all
	a.v2.vaults = snap.vaults
	a.v2.loaded = true
	a.rebuildSidebarCounts()
	a.rows = legacyRows(snap.rows)
	if !keepSelection || a.v2.selectedID == "" {
		a.selected = nil
		a.v2.detail = nil
		a.v2.detailPlain = nil
		a.v2.selectedID, a.v2.selectedRevision = "", ""
		a.v2.editing = false
		a.v2.draft = nil
	} else {
		found := false
		for i := range snap.rows {
			if snap.rows[i].ID == a.v2.selectedID {
				selected := legacyRow(snap.rows[i])
				a.selected = &selected
				a.v2.selectedRevision = snap.rows[i].Revision
				found = true
				break
			}
		}
		if !found {
			a.selected = nil
			a.v2.detail = nil
			a.v2.detailPlain = nil
			a.v2.selectedID, a.v2.selectedRevision = "", ""
			a.v2.editing = false
			a.v2.draft = nil
		}
	}
	a.status = fmt.Sprintf("%d 个条目", len(snap.rows))
}

func (a *App) rebuildSidebarCounts() {
	counts := map[vault.ItemCategory]int{}
	tags := map[string]int{}
	vaults := map[string]int{}
	for _, row := range a.v2.all {
		if row.State == "trashed" {
			continue
		}
		counts[row.Category]++
		vaults[row.VaultID]++
		for _, tag := range row.Tags {
			if tag != "" {
				tags[tag]++
			}
		}
	}
	a.v2.categoryCount = counts
	a.v2.vaultCount = vaults
	list := make([]TagCount, 0, len(tags))
	for tag, n := range tags {
		list = append(list, TagCount{Tag: tag, Count: n})
	}
	sort.Slice(list, func(i, j int) bool {
		return strings.ToLower(list[i].Tag) < strings.ToLower(list[j].Tag)
	})
	a.v2.tags = list
	if a.v2.vaultID != "all" && a.v2.vaultID != "" {
		// Keep the vault visible even when it has no matching active items.
		if _, ok := a.v2.vaultCount[a.v2.vaultID]; !ok {
			a.v2.vaultCount[a.v2.vaultID] = 0
		}
	}
}

// reloadV2 refreshes the list and sidebar metadata without resetting any
// search or filter state.
func (a *App) reloadV2(keepSelection bool) {
	s := a.session
	if s == nil {
		return
	}
	if a.busy {
		return
	}
	filter := a.currentFilter()
	a.run(func() outcome {
		snap := a.captureV2(s, filter)
		return outcome{err: snap.err, apply: func() { a.applyV2Snapshot(snap, keepSelection) }}
	})
}

// selectItem loads the masked detail for a list row.
func (a *App) selectItem(id, revision string) {
	a.EnableV2()
	s := a.session
	if s == nil {
		return
	}
	a.touchActivity()
	a.clearNotesEditor()
	a.clearDailyExposure()
	a.regenerate = nil
	a.v2.historyOpen = false
	a.v2.editing = false
	a.v2.draft = nil
	a.v2.confirmPurge = false
	a.run(func() outcome {
		detail, err := s.GetItemDetail(id, revision, false)
		return outcome{err: err, apply: func() {
			a.v2.detail = &detail
			a.v2.detailPlain = nil
			a.v2.selectedID, a.v2.selectedRevision = detail.ID, detail.Revision
			a.v2.revealed = map[string]bool{}
			selected := personal.Row{Kind: detail.Kind, ID: detail.ID, Title: detail.Title, Revision: detail.Revision, State: detail.State, RestoreState: detail.RestoreState}
			a.selected = &selected
			a.status = "已选择条目：" + detail.Title
		}}
	})
}

func (a *App) SelectItem(id, revision string) { a.selectItem(id, revision) }

func (a *App) selectSummary(row personal.ItemSummary) {
	a.selectItem(row.ID, row.Revision)
}

func (a *App) clearSelection() {
	a.v2.detail = nil
	a.v2.detailPlain = nil
	a.v2.selectedID, a.v2.selectedRevision = "", ""
	a.v2.editing = false
	a.v2.draft = nil
	a.v2.historyOpen = false
	a.selected = nil
}

func (a *App) selectVault(id string) {
	id = strings.TrimSpace(id)
	if id == "" {
		id = "all"
	}
	a.v2.vaultID = id
	if id == "all" {
		a.v2.nav = navAllItems
	}
}

func (a *App) SelectVault(id string) {
	a.EnableV2()
	a.selectVault(id)
	a.touchActivity()
	a.reloadV2(true)
}

// createVault creates a logical sub-vault inside the encrypted personal
// database (not a separate .ll file; see createVaultFile for that).
func (a *App) createVault(name, description, icon string) (vault.VaultMeta, error) {
	if a.session == nil {
		return vault.VaultMeta{}, personal.ErrSessionLocked
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return vault.VaultMeta{}, personal.ErrMutationRefused
	}
	s := a.session
	var created vault.VaultMeta
	var snap v2Snapshot
	ok := a.runNative(func(g *personal.MutationGate) nativeResult {
		meta, err := s.CreateVault(name, description, icon, g)
		if err != nil {
			return nativeResult{err: err}
		}
		created = meta
		snap = a.captureV2(s, a.currentFilter())
		return nativeResult{err: snap.err}
	}, func(r nativeResult) {
		a.applyV2Snapshot(snap, false)
		a.v2.vaultID = created.ID
		a.v2.newVaultOpen = false
		a.v2.newVaultName = ""
		a.v2.newVaultDesc = ""
		a.v2.newVaultIcon = ""
		a.status = "已创建金库：" + created.Name
	})
	if !ok {
		return vault.VaultMeta{}, personal.ErrMutationRefused
	}
	if a.status != "已创建金库："+created.Name {
		// runNative already recorded the concrete error.
		return vault.VaultMeta{}, personal.ErrMutationRefused
	}
	return created, nil
}

// CreateVault is the exported alias used by external callers.
func (a *App) CreateVault(name, description, icon string) (vault.VaultMeta, error) {
	a.EnableV2()
	return a.createVault(name, description, icon)
}

func (a *App) beginNewVault() {
	a.v2.newVaultOpen = true
	a.v2.newVaultName = ""
	a.v2.newVaultDesc = ""
	a.touchActivity()
}

// moveSelectedToVault moves or copies the selected item. copyItem preserves
// the source and selects the new copy.
func (a *App) moveSelectedToVault(targetVaultID string, copyItem bool) (string, string, error) {
	if a.v2.detail == nil {
		return "", "", personal.ErrMutationRefused
	}
	s, id, revision := a.session, a.v2.detail.ID, a.v2.detail.Revision
	if s == nil {
		return "", "", personal.ErrSessionLocked
	}
	var newID, newRevision string
	var snap v2Snapshot
	ok := a.runNative(func(g *personal.MutationGate) nativeResult {
		gotID, gotRevision, err := s.MoveItemVault(id, revision, targetVaultID, copyItem, g)
		if err != nil {
			return nativeResult{err: err}
		}
		newID, newRevision = gotID, gotRevision
		snap = a.captureV2(s, a.currentFilter())
		return nativeResult{err: snap.err}
	}, func(r nativeResult) {
		a.applyV2Snapshot(snap, false)
		a.v2.selectedID, a.v2.selectedRevision = newID, newRevision
		a.status = "条目已移动到金库"
		if copyItem {
			a.status = "条目已复制到金库"
		}
	})
	if !ok {
		return "", "", personal.ErrMutationRefused
	}
	return newID, newRevision, nil
}

func (a *App) MoveItemToVault(targetVaultID string, copyItem bool) (string, string, error) {
	a.EnableV2()
	return a.moveSelectedToVault(targetVaultID, copyItem)
}

func (a *App) duplicateSelected() (string, string, error) {
	if a.v2.detail == nil {
		return "", "", personal.ErrMutationRefused
	}
	return a.moveSelectedToVault(a.v2.detail.VaultID, true)
}

// setItemState performs archive/unarchive/trash/untrash and refreshes while
// preserving the current search and filter.
func (a *App) setItemState(action string) {
	if a.v2.detail == nil {
		return
	}
	s, id, revision := a.session, a.v2.detail.ID, a.v2.detail.Revision
	if s == nil {
		return
	}
	var snap v2Snapshot
	a.runNative(func(g *personal.MutationGate) nativeResult {
		if _, err := s.SetState(id, revision, action); err != nil {
			return nativeResult{err: err}
		}
		snap = a.captureV2(s, a.currentFilter())
		return nativeResult{err: snap.err}
	}, func(r nativeResult) {
		a.applyV2Snapshot(snap, false)
		a.status = "条目状态已更新"
	})
}

func (a *App) archiveSelected()   { a.setItemState("item.archive") }
func (a *App) unarchiveSelected() { a.setItemState("item.unarchive") }
func (a *App) trashSelected() {
	a.setItemState("item.trash")
}
func (a *App) restoreSelected() { a.setItemState("item.untrash") }

// purgeSelected permanently deletes a trashed item after confirmation.
func (a *App) purgeSelected() {
	if a.v2.detail == nil || !a.v2.confirmPurge {
		a.v2.confirmPurge = true
		a.v2.editorError = "再次确认：永久删除后无法恢复"
		return
	}
	s, id, revision := a.session, a.v2.detail.ID, a.v2.detail.Revision
	if s == nil {
		return
	}
	var snap v2Snapshot
	a.runNative(func(g *personal.MutationGate) nativeResult {
		if err := s.PurgeTrashed(id, revision, g); err != nil {
			return nativeResult{err: err}
		}
		snap = a.captureV2(s, a.currentFilter())
		return nativeResult{err: snap.err}
	}, func(r nativeResult) {
		a.v2.confirmPurge = false
		a.applyV2Snapshot(snap, false)
		a.status = "条目已永久删除"
	})
}

func (a *App) confirmPurgeSelected() { a.purgeSelected() }

// emptyTrash removes every trashed item. When olderThan is non-nil only items
// whose TrashedAt is at least that old are removed.
func (a *App) emptyTrash(olderThan *time.Duration) (int, error) {
	if a.session == nil {
		return 0, personal.ErrSessionLocked
	}
	s := a.session
	purged, err := 0, error(nil)
	var snap v2Snapshot
	ok := a.runNative(func(g *personal.MutationGate) nativeResult {
		purged, err = s.EmptyTrash(olderThan, g)
		if err != nil {
			return nativeResult{err: err}
		}
		snap = a.captureV2(s, a.currentFilter())
		return nativeResult{err: snap.err}
	}, func(r nativeResult) {
		a.applyV2Snapshot(snap, false)
		a.status = fmt.Sprintf("已永久删除 %d 个回收站条目", purged)
	})
	if !ok || err != nil {
		return 0, err
	}
	return purged, nil
}

// PurgeExpiredTrash removes trashed items older than the 30-day retention.
func (a *App) purgeExpiredTrash() (int, error) {
	thirtyDays := 30 * 24 * time.Hour
	return a.emptyTrash(&thirtyDays)
}

// EmptyTrash is the explicit "empty recently deleted" action.
func (a *App) EmptyTrash() (int, error) { return a.emptyTrash(nil) }

func idleLockLabel(d time.Duration) string {
	if d <= 0 {
		return "自动锁定已关闭"
	}
	return fmt.Sprintf("%d 分钟未操作自动锁定", int(d/time.Minute))
}
