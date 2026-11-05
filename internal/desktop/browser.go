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
	ui.Text(c, "浏览器连接").FontSize(24).Bold()
	ui.Text(c, "固定扩展身份："+a.browserLabel).FontSize(12)
	ui.Text(c, "此窗口持有独立金库会话；请核对浏览器当前网站，再逐次确认填充。")
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
	if view.Pending == nil {
		ui.Text(c, "在浏览器弹窗中选择当前网站的登录。此窗口不会自行请求或刷新候选。")
		return
	}
	pending := *view.Pending
	ui.Text(c, "确认本次登录填充").FontSize(22).Bold()
	ui.Text(c, "HTTPS 来源："+pending.Origin).FontSize(20).Bold()
	ui.Text(c, "条目："+visible(pending.Title))
	ui.Text(c, "ID："+pending.ItemID).FontSize(12)
	ui.Text(c, "精确修订："+pending.Revision).FontSize(12)
	ui.Text(c, "仅交付用户名和密码；不会自动提交。请求 30 秒后失效。")
	ui.PrimaryButton(c, "批准本次填充").Disabled(a.busy).OnClick(func() { a.run(func() outcome { return outcome{err: a.browser.ApproveFill(pending.ID)} }) })
	ui.Button(c, "拒绝本次填充").Disabled(a.busy).OnClick(func() { a.run(func() outcome { return outcome{err: a.browser.Reject()} }) })
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
	writer := browserhost.NewWriter(os.Stdout, 250*time.Millisecond)
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
				if e = a.browser.Handle(request); e != nil {
					break
				}
			}
			a.browser.Close()
			a.dispatch(func() { a.Lock(); mygo.App.Quit() })
		}()
	})
	return mygo.App.Run()
}
