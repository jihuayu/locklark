package desktop

import (
	"errors"
	"os"
	"time"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
	"github.com/jihuayu/locklark/internal/browserhost"
	"github.com/jihuayu/locklark/internal/personal"
)

func (a *App) browserView(c *ui.Context) {
	view := a.browser.Snapshot()
	if view.SaveStatus != "" {
		a.status = view.SaveStatus
	}
	if view.OTPStatus != "" {
		a.status = view.OTPStatus
	}
	ui.Text(c, "浏览器连接").FontSize(24).Bold()
	ui.Text(c, "固定扩展身份："+a.browserLabel).FontSize(12)
	ui.Text(c, "此窗口与浏览器共享已解锁的金库会话；请核对浏览器当前网站，再确认本次操作。")
	if view.Busy {
		ui.Text(c, "正在核对请求…")
		return
	}
	if view.Closed {
		ui.Text(c, "扩展已断开；请重新从浏览器连接。")
		return
	}
	if view.Pair {
		ui.Text(c, "连接后可在浏览器选择账号填充、保存登录或使用验证码。快捷模式允许本次连接中的明确浏览器操作，无需反复切回此窗口；锁库或连接到期后失效。")
		ui.PrimaryButton(c, "连接并启用快捷填充").Disabled(a.busy).OnClick(func() { s := a.session; a.run(func() outcome { return outcome{err: a.browser.ApproveQuickPair(s)} }) })
		ui.PrimaryButton(c, "确认连接此扩展").Disabled(a.busy).OnClick(func() { s := a.session; a.run(func() outcome { return outcome{err: a.browser.ApprovePair(s)} }) })
		ui.Button(c, "拒绝连接").Disabled(a.busy).OnClick(func() { a.run(func() outcome { return outcome{err: a.browser.Reject()} }) })
		return
	}
	if !view.Paired {
		ui.Text(c, "等待扩展发起新连接；重新解锁后必须重新配对。")
		return
	}
	ui.Text(c, "已连接 · 连接最多 15 分钟；5 分钟未明确操作自动锁定。")
	if view.QuickFill {
		ui.Text(c, "快捷填充已启用：在浏览器选择账号即可继续。自动登录设置由扩展管理。")
	}
	if view.Passkey == nil && view.PasskeyStatus != "" {
		ui.Text(c, view.PasskeyStatus).FontSize(13)
	}
	if view.Passkey != nil {
		a.browserPasskeyView(c, *view.Passkey, view.PasskeyStatus)
		return
	}
	if view.OTP != nil {
		a.browserOTPView(c, *view.OTP, view.OTPStatus)
		return
	}
	if view.Save != nil {
		a.browserSaveView(c, *view.Save, view.SaveStatus)
		return
	}
	if view.Signal != nil {
		a.browserSignalView(c, *view.Signal, view.SignalStatus)
		return
	}
	if view.SignalStatus != "" {
		ui.Text(c, view.SignalStatus).FontSize(13)
	}
	if view.Pending == nil {
		ui.Text(c, "在浏览器弹窗中选择当前网站的登录。此窗口不会自行请求或刷新候选。")
		return
	}
	pending := *view.Pending
	ui.Text(c, "确认本次登录填充").FontSize(22).Bold()
	ui.Text(c, "HTTPS 来源："+pending.Origin).FontSize(20).Bold()
	ui.Text(c, "条目："+browserTitle(pending.Title))
	ui.Text(c, "ID："+pending.ItemID).FontSize(12)
	ui.Text(c, "精确修订："+pending.Revision).FontSize(12)
	ui.Text(c, "仅交付用户名和密码；扩展可按自动登录设置提交。请求 30 秒后失效。")
	ui.PrimaryButton(c, "批准本次填充").Disabled(a.busy).OnClick(func() { a.run(func() outcome { return outcome{err: a.browser.ApproveFill(pending.ID)} }) })
	ui.Button(c, "拒绝本次填充").Disabled(a.busy).OnClick(func() { a.run(func() outcome { return outcome{err: a.browser.Reject()} }) })
}

func (a *App) browserSaveView(c *ui.Context, p browserhost.SaveView, status string) {
	if a.browserSaveID != p.ID {
		a.browserSaveID = p.ID
		a.browserSaveTitle = p.Title
	}
	heading, approve, reject := "新建登录", "批准保存登录", "拒绝保存登录"
	if p.Mode == "update" {
		heading, approve, reject = "更新登录", "批准更新登录", "拒绝更新登录"
	}
	ui.Text(c, heading).FontSize(22).Bold()
	ui.Text(c, "HTTPS 来源："+p.Origin).FontSize(20).Bold()
	if p.Mode == "new" {
		ui.TextInput(c, &a.browserSaveTitle).Label("新登录标题").Disabled(a.busy || p.Stage != "pending")
	} else {
		ui.Text(c, "条目："+browserTitle(p.Title))
		ui.Text(c, "ID："+p.ItemID).FontSize(12)
		ui.Text(c, "精确修订："+p.Revision).FontSize(12)
	}
	ui.Text(c, "保存的是点击时捕获的用户名与密码；不会验证网站账号是否正确。")
	if p.Mode == "update" {
		ui.Text(c, "仅替换用户名和密码；保留标题、网址、OTP、备注及来源记录。")
	}
	ui.Text(c, status)
	if p.Stage != "pending" {
		return
	}
	ui.PrimaryButton(c, approve).Disabled(a.busy).OnClick(func() {
		id, title := p.ID, a.browserSaveTitle
		a.browserSaveAction(id, func() error { return a.browser.ApproveSave(id, title) })
	})
	ui.Button(c, reject).Disabled(a.busy).OnClick(func() { a.browserSaveAction(p.ID, func() error { return a.browser.RejectSave(p.ID) }) })
}
func (a *App) browserSaveAction(id string, work func() error) {
	a.run(func() outcome {
		e := work()
		return outcome{apply: func() {
			v := a.browser.Snapshot()
			a.status = v.SaveStatus
			if v.SaveRequestID == id && e != nil && a.status == "" {
				a.status = message(e)
			}
		}}
	})
}

func (a *App) browserOTPView(c *ui.Context, p browserhost.OTPView, status string) {
	ui.Text(c, "确认本次验证码填充").FontSize(22).Bold()
	ui.Text(c, "HTTPS 来源："+visible(p.Origin)).FontSize(20).Bold()
	ui.Text(c, "条目："+browserTitle(p.Title))
	ui.Text(c, "ID："+p.ItemID).FontSize(12)
	ui.Text(c, "精确修订："+p.Revision).FontSize(12)
	ui.Text(c, "仅填入当前页面的唯一标准验证码框；不会自动提交，也不会自动生成下一期。").Bold()
	ui.Text(c, status)
	if p.Stage != "pending" {
		return
	}
	ui.PrimaryButton(c, "批准填充验证码").Disabled(a.busy).OnClick(func() { a.browserOTPAction(p.ID, func() error { return a.browser.ApproveOTP(p.ID) }) })
	ui.Button(c, "拒绝填充验证码").Disabled(a.busy).OnClick(func() { a.browserOTPAction(p.ID, func() error { return a.browser.RejectOTP(p.ID) }) })
}
func (a *App) browserOTPAction(id string, work func() error) {
	a.run(func() outcome {
		err := work()
		return outcome{apply: func() {
			view := a.browser.Snapshot()
			if view.OTPRequestID == id {
				a.status = view.OTPStatus
				if err != nil && a.status == "" {
					a.status = message(err)
				}
			}
		}}
	})
}

// browserSignalView renders the owner review for one WebAuthn signal hint. The
// page only ever receives the fixed acknowledgement; every change is shown
// here with the exact origin, RP, current account and new names, and only an
// explicit confirmation can reserve the mutation slot.
func (a *App) browserSignalView(c *ui.Context, p browserhost.SignalView, status string) {
	heading := "网站请求更新 Passkey 账号"
	switch p.Kind {
	case "unknown":
		heading = "网站报告未知的 Passkey 凭据"
	case "accepted":
		heading = "网站请求清理不再接受的 Passkey"
	case "user":
		heading = "网站请求更新 Passkey 账号名称"
	}
	ui.Text(c, heading).FontSize(22).Bold()
	ui.Text(c, "HTTPS 来源："+visible(p.Origin)).FontSize(20).Bold()
	ui.Text(c, "Passkey 域名："+visible(p.RPID))
	ui.Text(c, "仅处理下列已启用的登录 Passkey。网站不会获知本地是否存在凭据，也不会收到处理结果或数量。")
	removals := 0
	for _, change := range p.Changes {
		if change.Action == "remove" {
			removals++
			ui.Text(c, "移除 Passkey："+browserTitle(change.Title)+" · "+visible(change.Username))
			continue
		}
		ui.Text(c, "更新账号名称："+browserTitle(change.Title)+" · "+visible(change.Username))
		ui.Text(c, "  新用户名："+visible(change.Name)).FontSize(13)
		ui.Text(c, "  新显示名："+visible(change.DisplayName)).FontSize(13)
	}
	if removals > 0 {
		ui.Text(c, "注意：移除操作会在本地不可撤销地清除这些 Passkey；登录名、密码、验证码、备注与附件都会保留。网站信号本身不代表用户验证。").Bold()
	} else {
		ui.Text(c, "仅修改 Passkey 记录中的用户名和显示名；凭据 ID、用户句柄、私钥及所有登录字段保持不变。")
	}
	ui.Text(c, status)
	if p.Working {
		ui.Button(c, "取消尚未提交的更新").OnClick(func() { a.browserSignalCancel(p.ID) })
		return
	}
	ui.PrimaryButton(c, "确认应用这些更新").Disabled(a.busy || len(p.Changes) == 0).OnClick(func() {
		a.browserSignalAction(p.ID, func() error { return a.browser.ApprovePasskeySignal(p.ID) })
	})
	ui.Button(c, "取消（不做任何更改）").Disabled(a.busy).OnClick(func() {
		a.browserSignalAction(p.ID, func() error { return a.browser.RejectPasskeySignal(p.ID) })
	})
}

func (a *App) browserSignalAction(id string, work func() error) {
	a.run(func() outcome {
		err := work()
		return outcome{apply: func() {
			view := a.browser.Snapshot()
			if view.Signal == nil || view.Signal.ID == id {
				if view.SignalStatus != "" {
					a.status = view.SignalStatus
				} else if err != nil {
					a.status = message(err)
				}
			}
		}}
	})
}

// browserSignalCancel revokes a live signal gate directly on the native host.
// It deliberately bypasses a.run/a.busy: an approval may already be waiting on
// the database, and a cancel must still reach the host to cancel that gate.
// RejectPasskeySignal takes only the short Connection lock and performs no
// database work, so this click handler cannot block on the vault.
func (a *App) browserSignalCancel(id string) {
	a.status = "已请求取消；若已提交请核实金库"
	err := a.browser.RejectPasskeySignal(id)
	view := a.browser.Snapshot()
	if view.Busy || (view.Signal != nil && view.Signal.ID == id) {
		return
	}
	if view.SignalStatus != "" {
		a.status = view.SignalStatus
	} else if err != nil {
		a.status = message(err)
	}
}

func browserTitle(title string) string {
	if title == "" {
		return "（无标题）"
	}
	return visible(title)
}

// RunBrowser is a separate native process and session for this pipe. It exports
// no web bindings and accepts no command-line unlock factors or approval flags.
func RunBrowser(browser browserhost.Browser, args []string) error {
	if browserhost.ValidateLaunch(browser, args) != nil {
		return browserhost.ErrProtocol
	}
	if os.Getenv("LOCKLARK_BROWSER_STANDALONE") != "1" {
		err := browserhost.RelayStdio(browser, args, os.Stdin, os.Stdout)
		if err == nil {
			return nil
		}
		if !errors.Is(err, browserhost.ErrBrokerUnavailable) {
			return err
		}
	}
	if e := restoreBrowserAccessibility(browser); e != nil {
		return e
	}
	a := New()
	a.browserLabel = "chrome-extension://" + browserhost.ChromiumID + "/"
	if browser == browserhost.Firefox {
		a.browserLabel = browserhost.FirefoxID
	}
	writer := browserhost.NewNativeWriter(os.Stdout, 250*time.Millisecond, func() { os.Exit(74) })
	mygo.App.SetName("Locklark Browser")
	mygo.App.WhenReady(func() {
		a.win = mygo.NewWindow(mygo.WindowOptions{Title: "Locklark · 浏览器原生确认", Width: 1000, Height: 780, MinWidth: 900, MinHeight: 680, Content: ui.View(a.View)})
		a.dispatch = a.win.Update
		a.browser = browserhost.NewConnection(writer, func() { a.win.Invalidate() })
		a.win.OnClose(func(*mygo.CloseEvent) { a.Lock(); a.browser.Close(); mygo.App.Quit() })
		mygo.Power.OnSuspend(a.Lock)
		mygo.Power.OnLockScreen(a.Lock)
		mygo.App.OnQuit(a.Lock)
		go func() {
			for {
				request, e := browserhost.ReadRequest(os.Stdin)
				if e != nil {
					break
				}
				e = a.browser.Handle(request)
				request.Clear()
				if e != nil {
					break
				}
			}
			a.browser.Close()
			a.dispatch(func() { a.Lock(); mygo.App.Quit() })
		}()
	})
	return mygo.App.Run()
}

func (a *App) browserPasskeyView(c *ui.Context, p browserhost.PasskeyView, status string) {
	if a.browserPasskeyID != p.ID {
		a.browserPasskeyID = p.ID
		a.password = ""
		a.secret = ""
	}
	heading := "使用 Passkey 登录"
	if p.Create {
		heading = "保存 Passkey"
	}
	ui.Text(c, heading).FontSize(22).Bold()
	ui.Text(c, "网站："+visible(p.Origin)).FontSize(20).Bold()
	ui.Text(c, "Passkey 域名："+visible(p.RPID))
	if p.Create {
		ui.Text(c, "账号："+visible(p.Username))
	}
	ui.Text(c, status)
	if p.Working {
		return
	}
	ui.Text(c, "需要用户验证时，请在此重新输入主密码和 Secret Key。网站不会获得这些解锁因素。")
	ui.TextInput(c, &a.password).Label("验证主密码").Password().Disabled(a.busy)
	ui.TextInput(c, &a.secret).Label("验证 Secret Key").Password().Disabled(a.busy)
	approve := func(item string) {
		pw := []byte(a.password)
		var key []byte
		var err error
		if a.secret != "" {
			key, err = personal.ParseSecret(a.secret)
		}
		a.password = ""
		a.secret = ""
		if err != nil {
			clear(pw)
			a.status = "Secret Key 格式不正确"
			return
		}
		a.run(func() outcome {
			defer clear(pw)
			defer clear(key)
			return outcome{err: a.browser.ApprovePasskey(p.ID, item, pw, key)}
		})
	}
	if p.VerificationRequired {
		ui.Text(c, "此网站要求用户验证；必须填写两个解锁因素。").Bold()
	}
	factorsReady := a.password != "" && a.secret != "" || !p.VerificationRequired && a.password == "" && a.secret == ""
	if p.Create {
		ui.PrimaryButton(c, "创建新登录并保存 Passkey").Disabled(a.busy || !factorsReady).OnClick(func() { approve("") })
	}
	for _, choice := range p.Choices {
		choice := choice
		label := "登录：" + browserTitle(choice.Title) + " · " + visible(choice.Username)
		if p.Create {
			label = "保存到：" + browserTitle(choice.Title) + " · " + visible(choice.Username)
		}
		ui.Button(c, label).Disabled(a.busy || !factorsReady).OnClick(func() { approve(choice.ID) })
	}
	ui.Button(c, "取消 / 使用其他验证器").Disabled(a.busy).OnClick(func() {
		a.password = ""
		a.secret = ""
		a.run(func() outcome { return outcome{err: a.browser.RejectPasskey(p.ID)} })
	})
}
