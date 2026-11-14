package desktop

import (
	"errors"
	"runtime"

	"github.com/egoist/mygo/ui"
	"github.com/jihuayu/locklark/internal/personal"
)

const (
	quickSearchPrompt        = "输入标题后按 Enter 或搜索；仅查询活动登录。"
	quickSearchWorking       = "查询正在处理；不会排队执行其他查询。"
	quickShortcutPending     = "全局快捷键注册请求已提交；系统可能仍需授权，可随时使用窗口的快捷搜索按钮。"
	quickShortcutUnavailable = "全局快捷键暂不可用；请使用窗口的快捷搜索按钮。"
)

// The panel owns only metadata. Its worker slot outlives panel dismissal so that
// closing, locking or reopening cannot start a second authenticated query.
type quickSearchPanel struct {
	open, loading, focus bool
	query, status        string
	rows                 []personal.Row
	generation, sequence uint64
	inFlight             *quickSearchRequest
}

type quickSearchRequest struct {
	session                                *personal.Session
	generation, panel, sequence, operation uint64
	query                                  string
}

// Called directly by the native shortcut/tray callback, preserving the native
// activation context for Show/Focus. A busy entry changes no operation state.
func (a *App) showQuickSearch() {
	if a.win != nil {
		a.win.Show()
		a.win.Focus()
	}
	a.openQuickSearch()
	if a.win != nil {
		a.win.Invalidate()
	}
}

func (a *App) registerQuickSearch(register func(string, func()) error) {
	if e := register("CmdOrCtrl+Shift+L", a.showQuickSearch); e != nil {
		a.quickShortcut = quickShortcutUnavailable
	} else {
		a.quickShortcut = quickShortcutPending
	}
}

func (a *App) openQuickSearch() {
	if a.busy || a.browser != nil || a.session == nil {
		return
	}
	if !a.session.Unlocked() {
		a.Lock()
		return
	}
	if a.quick.open {
		return
	}
	session, generation, operation := a.session, a.generation, a.operationSequence
	a.clearDailyExposure()
	if a.session != session || a.generation != generation || a.operationSequence != operation || a.busy || !session.Unlocked() {
		return
	}
	a.closeQuickSearch()
	a.quick.open, a.quick.focus = true, true
	a.quick.loading = a.quick.inFlight != nil
	a.quick.status = quickSearchPrompt
	if a.quick.loading {
		a.quick.status = quickSearchWorking
	}
}

// Closing revokes result delivery, not any search audit already in progress.
// It deliberately preserves the main editor and the independent worker slot.
func (a *App) closeQuickSearch() {
	q := &a.quick
	q.generation++
	q.sequence++
	q.open, q.loading, q.focus = false, false, false
	q.query, q.status, q.rows = "", "", nil
}

func (a *App) beginOperation() {
	a.operationSequence++
	a.closeQuickSearch()
}

func (a *App) quickQueryChanged() {
	q := &a.quick
	q.sequence++
	q.rows = nil
	q.status = quickSearchPrompt
	if q.inFlight != nil {
		q.status = quickSearchWorking
	}
}

func (a *App) searchQuick() {
	q := &a.quick
	if !q.open || a.busy || a.session == nil || q.inFlight != nil {
		return
	}
	if !a.session.Unlocked() {
		a.Lock()
		return
	}
	q.sequence++
	q.rows = nil
	if q.query != "" && !personal.ValidSearchQuery(q.query) {
		q.status = "标题查询须为有效文字，最多 256 字节，不能包含控制字符。"
		return
	}
	r := &quickSearchRequest{a.session, a.generation, q.generation, q.sequence, a.operationSequence, q.query}
	q.inFlight, q.loading, q.status = r, true, quickSearchWorking
	a.launch(func() {
		var rows []personal.Row
		var e error
		if r.query == "" {
			rows, e = r.session.List("active")
		} else {
			rows, e = r.session.Search(r.query, "active")
		}
		a.dispatch(func() { a.finishQuickSearch(r, rows, e) })
	})
}

func (a *App) finishQuickSearch(r *quickSearchRequest, rows []personal.Row, e error) {
	q := &a.quick
	if q.inFlight != r {
		return
	}
	q.inFlight = nil
	if !q.open {
		return
	}
	q.loading = false
	if a.session != r.session || a.generation != r.generation || q.generation != r.panel || q.sequence != r.sequence || a.operationSequence != r.operation || q.query != r.query {
		q.status = quickSearchPrompt
		return
	}
	if !r.session.Unlocked() {
		a.Lock()
		return
	}
	if e != nil {
		q.status = "快捷搜索未完成，请检查输入和金库状态后重试。"
		if errors.Is(e, personal.ErrSearchQuery) {
			q.status = "标题查询须为有效文字，最多 256 字节，不能包含控制字符。"
		}
		return
	}
	q.rows = loginProjection(rows)
	q.status = "选择登录后，再明确显示或复制所需字段。"
	if len(q.rows) == 0 {
		q.status = "没有匹配的活动登录。"
	}
}

func (a *App) chooseQuickResult(panel, sequence uint64, target personal.Row) {
	q := &a.quick
	if !q.open || q.loading || a.busy || a.session == nil || q.generation != panel || q.sequence != sequence {
		return
	}
	if !a.session.Unlocked() {
		a.Lock()
		return
	}
	found := false
	for _, row := range q.rows {
		if row.ID == target.ID && row.Revision == target.Revision {
			target, found = row, true
			break
		}
	}
	if !found {
		return
	}
	query, rows := q.query, append([]personal.Row(nil), q.rows...)
	session, generation, operation := a.session, a.generation, a.operationSequence
	a.closeQuickSearch()
	a.clearDailyExposure()
	if a.session != session || a.generation != generation || a.operationSequence != operation || a.busy || !session.Unlocked() {
		return
	}
	a.page, a.scope, a.query, a.rows = "vault", "active", query, loginProjection(rows)
	a.queryGeneration++
	a.clearNotesEditor()
	a.selected = &target
	a.title, a.website, a.username, a.value = "", "", "", ""
	a.regenerate = nil
	if a.v2Mode {
		// The V2 workspace renders from a.v2, so the legacy fields alone would
		// leave the previously selected item visible. selectItem loads only
		// metadata; concealed values stay behind the explicit reveal controls.
		a.selectItem(target.ID, target.Revision)
	}
}

func (a *App) quickSearchView(c *ui.Context) {
	t := c.Theme()
	q := &a.quick
	panel := ui.Column(c.Key(q.generation)).Grow(1).FillWidth().Border(1, t.Border).Radius(t.Radius).Background(t.Surface).Padding(t.Space(4)).Gap(12)
	panel.Children(func() {
		ui.Row(c).FillWidth().AlignItems(ui.Center).Gap(8).Children(func() {
			ui.Text(c, "快捷搜索活动登录").FontSize(22).Bold().TextColor(t.Text).Grow(1)
			ui.Text(c, "快捷键 "+quickSearchAcceleratorLabel()+" · Esc 关闭").FontSize(12).TextColor(t.TextMuted)
		})
		// SearchField consumes Escape to clear its text. This modal instead
		// gives Escape to the enclosing panel, even for a nonempty query.
		input := ui.TextInput(c.Key("quick-query"), &q.query).Label("快捷搜索标题").Placeholder("输入登录标题")
		if q.focus {
			input.Focus()
			q.focus = false
		}
		if input.Changed() {
			a.quickQueryChanged()
		}
		if input.Submitted() {
			a.searchQuick()
		}
		ui.Row(c).Gap(8).Children(func() {
			ui.PrimaryButton(c, "搜索活动登录").Disabled(q.loading).OnClick(a.searchQuick)
			ui.Button(c, "关闭快捷搜索").OnClick(a.closeQuickSearch)
		})
		ui.Text(c, q.status).FontSize(13).TextColor(t.TextMuted)
		ui.Scroll(c).Grow(1).FillWidth().Children(func() {
			ui.Column(c).FillWidth().Gap(8).Children(func() {
				for _, row := range q.rows {
					row := row
					generation, sequence := q.generation, q.sequence
					ui.Column(c.Key(row.ID)).Role(ui.RoleGroup).Label("快捷搜索结果").
						FillWidth().
						Border(1, t.Border).
						Radius(t.Radius).
						Background(t.Background).
						Padding(t.Space(2)).
						Gap(4).
						Children(func() {
							ui.Button(c, "选择登录："+browserTitle(row.Title)).Disabled(q.loading).OnClick(func() { a.chooseQuickResult(generation, sequence, row) })
							ui.Text(c, "ID："+row.ID).FontSize(12).TextColor(t.TextMuted)
						})
				}
			})
		})
	})
	if panel.OverlayShortcut(0, ui.KeyEscape) {
		a.closeQuickSearch()
	}
}

func quickSearchAcceleratorLabel() string {
	if runtime.GOOS == "darwin" {
		return "⌘⇧L"
	}
	return "Ctrl+Shift+L"
}
