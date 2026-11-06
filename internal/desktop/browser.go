package desktop

import (
	"os"
	"time"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
	"github.com/jihuayu/locklark/internal/browserhost"
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
	ui.Text(c, "此窗口持有独立金库会话；请核对浏览器当前网站，再确认本次操作。")
	if view.Busy {
		ui.Text(c, "正在核对请求…")
		return
	}
	if view.Closed {
		ui.Text(c, "扩展已断开；请重新从浏览器连接。")
		return
	}
	if view.Pair {
		ui.Text(c, "扩展请求连接此金库。确认后可读取当前网站的登录候选；每次填充仍须原生批准。")
		ui.PrimaryButton(c, "确认连接此扩展").Disabled(a.busy).OnClick(func() { s := a.session; a.run(func() outcome { return outcome{err: a.browser.ApprovePair(s)} }) })
		ui.Button(c, "拒绝连接").Disabled(a.busy).OnClick(func() { a.run(func() outcome { return outcome{err: a.browser.Reject()} }) })
		return
	}
	if !view.Paired {
		ui.Text(c, "等待扩展发起新连接；重新解锁后必须重新配对。")
		return
	}
	ui.Text(c, "已连接 · 连接最多 15 分钟；5 分钟未原生操作自动锁定。")
	if view.OTP != nil {
		a.browserOTPView(c, *view.OTP, view.OTPStatus)
		return
	}
	if view.Save != nil {
		a.browserSaveView(c, *view.Save, view.SaveStatus)
		return
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
	ui.Text(c, "仅交付用户名和密码；不会自动提交。请求 30 秒后失效。")
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
