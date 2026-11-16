package desktop

import (
	"github.com/egoist/mygo/ui"
	oneui "github.com/oneo-me/onevra/source/components"
)

func (a *App) onevraLocalVaultFileUnlockDialog(c *ui.Context) {
	state := &a.localVaultUnlock
	t := c.Theme()
	oneui.Dialog(c, &state.open, oneui.DialogOptions{
		Label:                "解锁独立文件库",
		DisableBackdropClose: true,
		DisableEscapeClose:   true,
	}, func(panel ui.Element) {
		panel.Width(460).Background(t.Surface).Border(1, t.Border).Radius(t.Radius).Padding(t.Space(4))
		panel.Children(func() {
			ui.Column(c).FillWidth().Gap(t.Space(2)).Children(func() {
				oneui.Text(c, "解锁独立文件库").Bold()
				targetLabel, targetOK := a.localVaultFileUnlockDialogTarget()
				status := state.status
				if !targetOK {
					status = localVaultFileUnlockStatusUnavailable
				}
				oneui.Text(c, status).Wrap()
				if targetOK {
					oneui.Text(c, targetLabel).TextColor(t.TextMuted).SingleLine().Ellipsis("…")
				}
				oneui.TextBox(c, &state.password, oneui.TextBoxOptions{}).
					Label("主密码").Password().Disabled(state.busy)
				oneui.TextBox(c, &state.secret, oneui.TextBoxOptions{}).
					Label("Secret Key").Password().Disabled(state.busy)
				ui.Row(c).FillWidth().Justify(ui.End).Gap(t.Space(1.5)).Children(func() {
					// Cancel remains usable while the exact worker is busy. It
					// routes only through the controller's exact cleanup.
					if oneui.Button(c, "取消", oneui.ButtonGhost).Clicked() {
						a.cancelLocalVaultFileUnlock()
					}
					submit := oneui.Button(c, "完整验证并解锁", oneui.ButtonPrimary)
					submit.Disabled(state.busy || !targetOK || state.password == "" || state.secret == "")
					if submit.Clicked() {
						a.submitLocalVaultFileUnlock()
					}
				})
			})
		})
	})
}
