package desktop

import (
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/vault"
	oneui "github.com/oneo-me/onevra/source/components"
)

// One action model, four entry points: the row context menu, the detail "⋯"
// menu, keyboard shortcuts and hover buttons all call these helpers. Every
// helper delegates to an existing audited session method; none reads or
// writes vault data directly.

func (a *App) summaryByID(id string) (personal.ItemSummary, bool) {
	for _, row := range a.v2.all {
		if row.ID == id {
			return row, true
		}
	}
	for _, row := range a.v2.rows {
		if row.ID == id {
			return row, true
		}
	}
	return personal.ItemSummary{}, false
}

// selectedSummary is the summary of the item shown in the detail pane.
func (a *App) selectedSummary() (personal.ItemSummary, bool) {
	if a.v2.detail == nil {
		return personal.ItemSummary{}, false
	}
	if row, ok := a.summaryByID(a.v2.detail.ID); ok {
		row.Revision = a.v2.detail.Revision
		row.State = a.v2.detail.State
		row.Favorite = a.v2.detail.Favorite
		return row, true
	}
	d := a.v2.detail
	return personal.ItemSummary{ID: d.ID, Revision: d.Revision, Kind: d.Kind, Category: d.Category, VaultID: d.VaultID, Title: d.Title, State: d.State, Favorite: d.Favorite}, true
}

// withItem runs fn against row once it is the selected detail. Actions that
// need the detail (copy, edit, duplicate) select a row first and run after
// the audited detail read has completed.
func (a *App) withItem(row personal.ItemSummary, fn func()) {
	if a.v2.detail != nil && a.v2.detail.ID == row.ID {
		fn()
		return
	}
	a.onevra.pending = &onevraPending{itemID: row.ID, run: fn}
	a.selectItem(row.ID, row.Revision)
}

// drainPendingAction runs a deferred row action when its detail is ready.
func (a *App) drainPendingAction() {
	p := a.onevra.pending
	if p == nil || a.busy {
		return
	}
	if a.v2.detail == nil || a.v2.detail.ID != p.itemID {
		if a.v2.selectedID != "" && a.v2.selectedID != p.itemID {
			a.onevra.pending = nil
		}
		return
	}
	a.onevra.pending = nil
	p.run()
}

// changeItemState applies a lifecycle action to any row (selected or not).
func (a *App) changeItemState(id, revision, action string, done func(newRevision string)) {
	s := a.session
	if s == nil || id == "" {
		return
	}
	var snap v2Snapshot
	var newRevision string
	filter, query := a.currentFilter(), a.currentV2Query()
	a.runNative(func(g *personal.MutationGate) nativeResult {
		rev, err := s.SetState(id, revision, action)
		if err != nil {
			return nativeResult{err: err}
		}
		newRevision = rev
		snap = a.captureV2(s, filter)
		snap.query = query
		return nativeResult{err: snap.err}
	}, func(r nativeResult) {
		if !a.applyV2Snapshot(snap, false) {
			return
		}
		a.status = "条目状态已更新"
		if done != nil {
			done(newRevision)
		}
	})
}

var inverseStateAction = map[string]string{
	"item.archive":   "item.unarchive",
	"item.unarchive": "item.archive",
	"item.trash":     "item.untrash",
	"item.untrash":   "item.trash",
}

var stateActionMessage = map[string]string{
	"item.archive":   "已归档",
	"item.unarchive": "已取消归档",
	"item.trash":     "已移入回收站",
	"item.untrash":   "已恢复到金库",
}

// moveItemState performs a reversible lifecycle change, keeps the list
// position by selecting the neighbouring row, and offers undo in a toast.
func (a *App) moveItemState(row personal.ItemSummary, action string) {
	index := -1
	for i := range a.v2.rows {
		if a.v2.rows[i].ID == row.ID {
			index = i
			break
		}
	}
	wasSelected := a.v2.selectedID == row.ID
	title := visible(row.Title)
	a.changeItemState(row.ID, row.Revision, action, func(newRevision string) {
		stillListed := false
		for _, r := range a.v2.rows {
			if r.ID == row.ID {
				stillListed = true
				break
			}
		}
		if wasSelected && !stillListed {
			a.clearSelection()
			if len(a.v2.rows) > 0 && index >= 0 {
				next := index
				if next >= len(a.v2.rows) {
					next = len(a.v2.rows) - 1
				}
				a.selectItem(a.v2.rows[next].ID, a.v2.rows[next].Revision)
			}
		} else if wasSelected {
			a.selectItem(row.ID, newRevision)
		}
		inverse := inverseStateAction[action]
		id := row.ID
		a.onevra.toast = &onevraToast{
			message: stateActionMessage[action] + "：" + title,
			action:  "撤销",
			undo: func() {
				a.changeItemState(id, newRevision, inverse, func(rev string) {
					a.selectItem(id, rev)
				})
			},
		}
	})
}

// setFavorite persists a star change for any row.
func (a *App) setFavorite(row personal.ItemSummary, favorite bool) {
	s := a.session
	if s == nil {
		return
	}
	filter := a.currentFilter()
	var snap v2Snapshot
	var newRevision string
	a.runNative(func(g *personal.MutationGate) nativeResult {
		rev, err := s.SetFavorite(row.ID, row.Revision, favorite, g)
		if err != nil {
			return nativeResult{err: err}
		}
		newRevision = rev
		snap = a.captureV2(s, filter)
		return nativeResult{err: snap.err}
	}, func(r nativeResult) {
		a.applyV2Snapshot(snap, false)
		if a.v2.detail != nil && a.v2.detail.ID == row.ID {
			a.v2.detail.Favorite = favorite
			a.v2.detail.Revision = newRevision
			a.v2.selectedRevision = newRevision
		}
		if favorite {
			a.status = "已加入收藏：" + visible(row.Title)
		} else {
			a.status = "已取消收藏：" + visible(row.Title)
		}
	})
}

func (a *App) toggleFavoriteRow(row personal.ItemSummary) { a.setFavorite(row, !row.Favorite) }

// markCopied records the inline "copied" feedback for a detail field.
func (a *App) markCopied(itemID, key string, timeout time.Duration) {
	now := time.Now()
	a.onevra.copiedItem, a.onevra.copiedKey, a.onevra.copiedAt = itemID, key, now
	if timeout > 0 {
		a.onevra.copiedUntil = now.Add(timeout)
	} else {
		a.onevra.copiedUntil = now.Add(2 * time.Second)
	}
}

// copiedRemaining reports the clipboard countdown for a field, if any.
func (a *App) copiedRemaining(itemID, key string, now time.Time) (time.Duration, float32, bool) {
	u := &a.onevra
	if u.copiedKey == "" || u.copiedItem != itemID || u.copiedKey != key || !now.Before(u.copiedUntil) {
		return 0, 0, false
	}
	total := u.copiedUntil.Sub(u.copiedAt)
	left := u.copiedUntil.Sub(now)
	frac := float32(1)
	if total > 0 {
		frac = float32(left) / float32(total)
	}
	return left, frac, true
}

func itemHasSecretLogin(row personal.ItemSummary) bool {
	switch row.Category {
	case vault.CategoryLogin, vault.CategoryPassword, vault.CategoryAPICredential, vault.CategoryDatabase, vault.CategoryServer:
		return true
	}
	return row.Kind == "login"
}

// onevraItemMenu builds the shared item action menu. Only actions available
// in the row's state are listed, never greyed-out placeholders.
func (a *App) onevraItemMenu(c *ui.Context, m *oneui.Menu, row personal.ItemSummary) {
	if row.State == "trashed" {
		if m.Item("恢复到金库").Chosen() {
			a.moveItemState(row, "item.untrash")
		}
		m.Separator()
		if m.Item("永久删除…").Chosen() {
			a.withItem(row, func() {
				a.v2.confirmPurge = true
			})
		}
		return
	}
	if row.Subtitle != "" && m.Item("复制用户名").Shortcut("Ctrl+Shift+U").Chosen() {
		a.withItem(row, func() { a.copyField("username") })
	}
	if itemHasSecretLogin(row) && m.Item("复制密码").Shortcut("Ctrl+Shift+C").Chosen() {
		a.withItem(row, func() { a.copyField("password") })
	}
	if row.HasOTP && m.Item("复制一次性验证码").Shortcut("Ctrl+Alt+C").Chosen() {
		a.withItem(row, func() { a.copyField("otp") })
	}
	if row.PrimaryURL != "" && m.Item("打开网站").Chosen() {
		c.OpenURL(row.PrimaryURL)
		a.status = "已在浏览器中打开：" + visible(row.PrimaryURL)
	}
	m.Separator()
	favLabel := "加入收藏"
	if row.Favorite {
		favLabel = "取消收藏"
	}
	if m.Item(favLabel).Shortcut("Ctrl+D").Chosen() {
		a.toggleFavoriteRow(row)
	}
	if m.Item("编辑").Shortcut("Ctrl+E").Chosen() {
		a.withItem(row, func() {
			if err := a.beginEdit(); err != nil {
				a.status = message(err)
			}
		})
	}
	if m.Item("创建副本").Chosen() {
		a.withItem(row, func() {
			if _, _, err := a.duplicateSelected(); err == nil {
				a.onevra.toast = &onevraToast{message: "已创建副本：" + visible(row.Title)}
			}
		})
	}
	if len(a.v2.vaults) > 1 {
		if m.Item("移动到其他保险库…").Chosen() {
			a.withItem(row, func() { a.openMoveVaultDialog(false) })
		}
		if m.Item("复制到其他保险库…").Chosen() {
			a.withItem(row, func() { a.openMoveVaultDialog(true) })
		}
	}
	m.Separator()
	if row.State == "archived" {
		if m.Item("取消归档").Chosen() {
			a.moveItemState(row, "item.unarchive")
		}
	} else if m.Item("归档").Chosen() {
		a.moveItemState(row, "item.archive")
	}
	if m.Item("移入回收站").Shortcut("Delete").Chosen() {
		a.moveItemState(row, "item.trash")
	}
}

// emitPendingToast shows a toast queued by an asynchronous mutation.
func (a *App) emitPendingToast(c *ui.Context) {
	t := a.onevra.toast
	if t == nil {
		return
	}
	a.onevra.toast = nil
	if t.undo != nil && t.action != "" {
		undo := t.undo
		c.ToastAction(t.message, t.action, func() { undo() })
		return
	}
	c.Toast(t.message)
}

// onevraShortcuts wires the keyboard entry points of the item action model.
// The innermost focused control handles keys first, so text boxes keep
// Delete, Ctrl+C and friends.
func (a *App) onevraShortcuts(root ui.Element) {
	row, hasRow := a.selectedSummary()
	switch {
	case root.Shortcut(ui.Ctrl, ui.KeyN):
		a.newItem(vault.CategoryLogin)
	case root.Shortcut(ui.Ctrl, ui.KeyL):
		a.Lock()
	case !hasRow || a.v2.editing:
	case root.Shortcut(ui.Ctrl, ui.KeyE):
		if row.State != "trashed" {
			if err := a.beginEdit(); err != nil {
				a.status = message(err)
			}
		}
	case root.Shortcut(ui.Ctrl, ui.KeyD):
		if row.State != "trashed" {
			a.toggleFavoriteRow(row)
		}
	case root.Shortcut(ui.Ctrl|ui.Shift, ui.KeyC):
		if row.State != "trashed" {
			a.copyField("password")
		}
	case root.Shortcut(ui.Ctrl|ui.Shift, ui.KeyU):
		if row.State != "trashed" {
			a.copyField("username")
		}
	case root.Shortcut(ui.Ctrl|ui.Alt, ui.KeyC):
		if row.State != "trashed" && row.HasOTP {
			a.copyField("otp")
		}
	case root.Shortcut(0, ui.KeyDelete):
		if row.State != "trashed" {
			a.moveItemState(row, "item.trash")
		}
	}
}
