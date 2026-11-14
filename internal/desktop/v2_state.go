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

	historyOpen     bool
	settingsOpen    bool
	settingsSection string
	watchtower      *WatchtowerReport
	ignored         map[string]bool

	generator generatorState

	revealed       map[string]bool
	narrowPassword narrowPasswordDisclosure
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

	// querySeq invalidates list snapshots whose filter was superseded while the
	// UI was busy. pendingReload defers such a refresh instead of dropping it;
	// the guard in applyV2Snapshot rejects the stale result.
	querySeq      uint64
	pendingReload bool
	pendingKeep   bool
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

// v2Query is the comparable identity of a list query: every filter input that
// can change the rows plus a monotonic sequence, so an A to B to A change is
// still detected and a slow read cannot repopulate stale rows.
type v2Query struct {
	vaultID  string
	state    string
	category vault.ItemCategory
	tag      string
	query    string
	sortBy   string
	favorite bool
	seq      uint64
}

func v2QueryFromFilter(filter personal.ItemFilter) v2Query {
	q := v2Query{
		vaultID:  filter.VaultID,
		state:    filter.State,
		category: filter.Category,
		tag:      filter.Tag,
		query:    filter.Query,
		sortBy:   filter.SortBy,
	}
	if filter.Favorite != nil {
		q.favorite = *filter.Favorite
	}
	return q
}

// touchV2Query records that the requested list changed.
func (a *App) touchV2Query() { a.v2.querySeq++ }

// currentV2Query captures the live query identity on the UI goroutine.
func (a *App) currentV2Query() v2Query {
	q := v2QueryFromFilter(a.currentFilter())
	q.seq = a.v2.querySeq
	return q
}

// v2QueryCurrent reports whether q still describes the requested list. A zero
// sequence means the caller did not capture one (legacy capture paths); those
// snapshots are still rejected when any filter value changed.
func (a *App) v2QueryCurrent(q v2Query) bool {
	cur := a.currentV2Query()
	if q.seq != 0 && cur.seq != q.seq {
		return false
	}
	q.seq, cur.seq = 0, 0
	return q == cur
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
//	all, favorites, recently_deleted, archive
//	category:<slug>, tag:<name>, vault:<id|all>
//	<category slug>            (e.g. "credit_card")
func (a *App) navigate(target string) {
	a.EnableV2()
	a.v2.settingsOpen = false
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
	a.touchV2Query()
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
	a.touchV2Query()
}

func (a *App) FilterByCategory(category vault.ItemCategory) {
	a.EnableV2()
	a.v2.settingsOpen = false
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
	a.touchV2Query()
}

func (a *App) FilterByTag(tag string) {
	a.EnableV2()
	a.v2.settingsOpen = false
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
	a.touchV2Query()
	a.touchActivity()
	a.reloadV2(true)
}

func (a *App) SetSearchQuery(query string) {
	a.query = query
	a.touchV2Query()
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
	query  v2Query
	err    error
}

// captureV2 collects every list needed by the three-pane layout in one
// authenticated read pass. filter is captured on the UI goroutine.
func (a *App) captureV2(s *personal.Session, filter personal.ItemFilter) v2Snapshot {
	query := v2QueryFromFilter(filter)
	if s == nil {
		return v2Snapshot{err: personal.ErrSessionLocked, query: query}
	}
	snapshot, err := s.ListDesktopSnapshot(filter)
	if err != nil {
		return v2Snapshot{err: err, query: query}
	}
	return v2Snapshot{rows: snapshot.Rows, all: snapshot.All, vaults: snapshot.Vaults, query: query}
}

func (a *App) applyV2Snapshot(snap v2Snapshot, keepSelection bool) bool {
	if !a.v2QueryCurrent(snap.query) {
		a.dropStaleV2Snapshot()
		return false
	}
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
	a.drainPendingV2Reload()
	return true
}

// dropStaleV2Snapshot discards a list captured for a query that is no longer
// requested, so a slow read cannot overwrite the newer search or filter.
func (a *App) dropStaleV2Snapshot() {
	a.v2.rows = nil
	a.rows = nil
	a.selected = nil
	a.v2.detail = nil
	a.v2.detailPlain = nil
	a.v2.selectedID, a.v2.selectedRevision = "", ""
	a.v2.historyOpen = false
	if !a.v2.editing {
		a.v2.draft = nil
	}
	a.status = "搜索条件已变更，请重新刷新"
	a.drainPendingV2Reload()
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
		// Keep the request instead of dropping it; the in-flight snapshot is
		// rejected by the query guard and replayed by drainPendingV2Reload.
		a.v2.pendingReload = true
		a.v2.pendingKeep = a.v2.pendingKeep || keepSelection
		return
	}
	a.v2.pendingReload, a.v2.pendingKeep = false, false
	filter, query := a.currentFilter(), a.currentV2Query()
	a.run(func() outcome {
		snap := a.captureV2(s, filter)
		snap.query = query
		return outcome{err: snap.err, apply: func() { _ = a.applyV2Snapshot(snap, keepSelection) }}
	})
}

// drainPendingV2Reload replays a reload requested while a read was in flight.
// It runs on the UI goroutine only, so pending state is never touched from a
// background worker.
func (a *App) drainPendingV2Reload() {
	if !a.v2.pendingReload || a.busy {
		return
	}
	keep := a.v2.pendingKeep
	a.v2.pendingReload, a.v2.pendingKeep = false, false
	a.reloadV2(keep)
}

// selectItem loads the masked detail for a list row.
func (a *App) selectItem(id, revision string) {
	a.EnableV2()
	if a.v2.nav == navWatchtower {
		a.v2.nav = navAllItems
	}
	a.v2.settingsOpen = false
	a.v2.generator.open = false
	a.v2.historyOpen = false
	a.v2.confirmPurge = false
	a.hideNarrowPassword()
	s := a.session
	if s == nil {
		if a.v2.detail != nil && a.v2.detail.ID == id {
			a.v2.selectedID, a.v2.selectedRevision = id, revision
		}
		return
	}
	a.touchActivity()
	a.clearNotesEditor()
	a.clearDailyExposure()
	a.regenerate = nil
	a.v2.editing = false
	a.v2.draft = nil
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
			a.revealPasswordByDefault()
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
	a.v2.confirmPurge = false
	a.selected = nil
}

func (a *App) selectVault(id string) {
	id = strings.TrimSpace(id)
	if id == "" {
		id = "all"
	}
	a.v2.vaultID = id
	if id == "all" || a.v2.nav == navWatchtower {
		a.v2.nav = navAllItems
	}
	a.touchV2Query()
}

func (a *App) SelectVault(id string) {
	a.EnableV2()
	a.v2.settingsOpen = false
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
	filter, query := a.currentFilter(), a.currentV2Query()
	ok := a.runNative(func(g *personal.MutationGate) nativeResult {
		meta, err := s.CreateVault(name, description, icon, g)
		if err != nil {
			return nativeResult{err: err}
		}
		created = meta
		snap = a.captureV2(s, filter)
		snap.query = query
		return nativeResult{err: snap.err}
	}, func(r nativeResult) {
		if !a.applyV2Snapshot(snap, false) {
			return
		}
		a.selectVault(created.ID)
		a.reloadV2(false)
		a.v2.newVaultOpen = false
		a.v2.newVaultName = ""
		a.v2.newVaultDesc = ""
		a.v2.newVaultIcon = ""
		a.status = "已创建金库：" + created.Name
	})
	if !ok {
		return vault.VaultMeta{}, personal.ErrMutationRefused
	}
	// The create is asynchronous; the concrete meta and any failure reach the UI
	// through the applied snapshot and a.status, never through this frame.
	return vault.VaultMeta{}, nil
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
	filter, query := a.currentFilter(), a.currentV2Query()
	ok := a.runNative(func(g *personal.MutationGate) nativeResult {
		gotID, gotRevision, err := s.MoveItemVault(id, revision, targetVaultID, copyItem, g)
		if err != nil {
			return nativeResult{err: err}
		}
		newID, newRevision = gotID, gotRevision
		snap = a.captureV2(s, filter)
		snap.query = query
		return nativeResult{err: snap.err}
	}, func(r nativeResult) {
		if !a.applyV2Snapshot(snap, false) {
			return
		}
		a.v2.selectedID, a.v2.selectedRevision = newID, newRevision
		a.status = "条目已移动到金库"
		if copyItem {
			a.status = "条目已复制到金库"
		}
	})
	if !ok {
		return "", "", personal.ErrMutationRefused
	}
	// The move is asynchronous; its new ids are selected by the apply closure.
	return "", "", nil
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
	filter, query := a.currentFilter(), a.currentV2Query()
	a.runNative(func(g *personal.MutationGate) nativeResult {
		if _, err := s.SetState(id, revision, action); err != nil {
			return nativeResult{err: err}
		}
		snap = a.captureV2(s, filter)
		snap.query = query
		return nativeResult{err: snap.err}
	}, func(r nativeResult) {
		if !a.applyV2Snapshot(snap, false) {
			return
		}
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
	filter, query := a.currentFilter(), a.currentV2Query()
	a.runNative(func(g *personal.MutationGate) nativeResult {
		if err := s.PurgeTrashed(id, revision, g); err != nil {
			return nativeResult{err: err}
		}
		snap = a.captureV2(s, filter)
		snap.query = query
		return nativeResult{err: snap.err}
	}, func(r nativeResult) {
		a.v2.confirmPurge = false
		if !a.applyV2Snapshot(snap, false) {
			return
		}
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
	var purged int
	var snap v2Snapshot
	filter, query := a.currentFilter(), a.currentV2Query()
	ok := a.runNative(func(g *personal.MutationGate) nativeResult {
		count, err := s.EmptyTrash(olderThan, g)
		if err != nil {
			return nativeResult{err: err}
		}
		purged = count
		snap = a.captureV2(s, filter)
		snap.query = query
		return nativeResult{err: snap.err}
	}, func(r nativeResult) {
		if !a.applyV2Snapshot(snap, false) {
			return
		}
		a.status = fmt.Sprintf("已永久删除 %d 个回收站条目", purged)
	})
	if !ok {
		return 0, personal.ErrMutationRefused
	}
	// The purge is asynchronous; its count and any failure are reported by the
	// apply closure and a.status, never through this frame.
	return 0, nil
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

func (a *App) openSettings() {
	a.v2.settingsOpen = true
	if a.v2.settingsSection == "" {
		a.v2.settingsSection = settingsSectionSecurity
	}
	a.touchActivity()
}

func (a *App) closeSettings() {
	a.v2.settingsOpen = false
	a.touchActivity()
}
