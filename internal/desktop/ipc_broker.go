package desktop

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
	"github.com/jihuayu/locklark/internal/browserhost"
	"github.com/jihuayu/locklark/internal/nativeclipboard"
	"github.com/jihuayu/locklark/internal/personal"
	oneui "github.com/oneo-me/onevra/source/components"
	"github.com/oneo-me/onevra/source/icons/lucide"
	"github.com/oneo-me/onevra/source/shells/plain"
)

var errCLIRunRefused = errors.New("refused")

type cliRunPending struct {
	id       string
	peer     browserhost.Peer
	request  browserhost.BrokerCLIRequest
	decision chan bool
	once     sync.Once
	decided  bool
}

func (p *cliRunPending) choose(approved bool) {
	if !approved {
		p.once.Do(func() { p.decision <- false })
		return
	}
	p.once.Do(func() { p.decision <- true })
}

// browserBrokerCallbacks builds the desktop side of the IPC contract. It is a
// separate method so the clipboard factory and settings getter can be
// exercised without opening a listener.
func (a *App) browserBrokerCallbacks() browserhost.BrokerCallbacks {
	return browserhost.BrokerCallbacks{
		CurrentSession: func() (*personal.Session, uint64, bool) {
			a.brokerMu.Lock()
			defer a.brokerMu.Unlock()
			if a.brokerSession == nil || !a.brokerSession.Unlocked() {
				return nil, 0, false
			}
			return a.brokerSession, a.brokerEpoch, true
		},
		RequestLock: func() {
			a.dispatch(func() { a.Lock() })
		},
		RequestUnlockFocus: func() {
			a.dispatch(func() {
				if a.win != nil {
					a.winHidden = false
					a.win.Show()
					a.win.Focus()
				}
			})
		},
		NotifyChanged: func() {
			a.dispatch(func() {
				if a.win != nil {
					a.win.Invalidate()
				}
			})
		},
		HandleCLIRun: a.handleCLIRun,
		// The clipboard capability is announced only when this factory actually
		// exists. Each accepted connection gets its own two-phase manager over
		// the single App-owned native writer and global lease.
		NewClipboard: func() (*nativeclipboard.Manager, time.Duration) {
			return a.newBrowserClipboardManager(), a.clipboardClearDuration()
		},
		// The live getter is atomic only: the accept goroutine must never read
		// the UI settings struct. A negative mirror fails closed upstream.
		ClipboardClearDuration: a.clipboardClearDuration,
	}
}

// startBrowserBroker hosts the shared desktop↔extension IPC endpoint.
func (a *App) startBrowserBroker() {
	if a.broker != nil {
		return
	}
	endpoint, e := browserhost.DefaultBrokerEndpoint()
	if e != nil {
		return
	}
	b := browserhost.NewBroker(a.browserBrokerCallbacks())
	if e = b.Start(endpoint); e != nil {
		return
	}
	a.brokerMu.Lock()
	a.broker = b
	a.brokerEndpoint = endpoint
	a.brokerMu.Unlock()
}

func (a *App) stopBrowserBroker() {
	a.cancelPendingCLIRun()
	a.brokerMu.Lock()
	b := a.broker
	a.broker = nil
	a.brokerEndpoint = ""
	a.brokerSession = nil
	a.brokerMu.Unlock()
	if b != nil {
		_ = b.Close()
	}
}

func (a *App) cancelPendingCLIRun() {
	a.brokerMu.Lock()
	p := a.cliPending
	a.cliPending = nil
	if p != nil {
		p.decided = true
	}
	renderedID := a.approvalWinPending
	a.brokerMu.Unlock()
	if p != nil {
		p.choose(false)
		renderedID = p.id
	}
	a.hideApprovalWindowFor(renderedID)
}

func (a *App) notifyBrowserBrokerUnlocked() {
	a.brokerMu.Lock()
	a.brokerSession, a.brokerEpoch = a.session, a.generation
	b, s, generation := a.broker, a.brokerSession, a.brokerEpoch
	a.brokerMu.Unlock()
	if b != nil && s != nil {
		b.NotifyUnlocked(s, generation, true)
	}
}

func (a *App) notifyBrowserBrokerLocked() {
	a.brokerMu.Lock()
	a.brokerSession, a.brokerEpoch = nil, a.generation
	b := a.broker
	generation := a.generation
	a.brokerMu.Unlock()
	if b != nil {
		b.NotifyLocked(generation)
	}
}

// brokerCurrent reports whether the exact session and epoch captured at
// request entry are still the broker's current unlocked binding.
func (a *App) brokerCurrent(s *personal.Session, epoch uint64) bool {
	a.brokerMu.Lock()
	defer a.brokerMu.Unlock()
	return s != nil && s.Unlocked() && a.brokerSession == s && a.brokerEpoch == epoch
}

// handleCLIRun verifies the desktop vault, requests native approval, then
// extracts pinned targets in one authenticated view.
func (a *App) handleCLIRun(ctx context.Context, peer browserhost.Peer, req browserhost.BrokerCLIRequest) (browserhost.BrokerCLIResponse, error) {
	if ctx == nil {
		_ = a.recordCLIActivity("failed", peer, req)
		return browserhost.BrokerCLIResponse{}, errCLIRunRefused
	}
	// The absolute lifetime starts here and is never renewed. An earlier
	// caller deadline remains authoritative through WithTimeout.
	ctx, cancel := context.WithTimeout(ctx, browserhost.CLIRunApprovalMaxLifetime)
	defer cancel()
	a.brokerMu.Lock()
	s := a.brokerSession
	epoch := a.brokerEpoch
	path := ""
	if s != nil {
		path = s.VaultPath()
	}
	a.brokerMu.Unlock()
	if s == nil || !s.Unlocked() || path == "" || path != req.VaultPath {
		_ = a.recordCLIActivity("unavailable", peer, req)
		return browserhost.BrokerCLIResponse{}, browserhost.ErrBrokerUnavailable
	}
	approved := false
	if a.cliApprover != nil {
		ok, e := a.cliApprover(ctx, peer, req)
		if e != nil {
			_ = a.recordCLIActivity("failed", peer, req)
			return browserhost.BrokerCLIResponse{}, errCLIRunRefused
		}
		approved = ok
	} else {
		ok, e := a.requestCLIRunApproval(ctx, peer, req, s, epoch)
		if e != nil {
			_ = a.recordCLIActivity("failed", peer, req)
			return browserhost.BrokerCLIResponse{}, errCLIRunRefused
		}
		approved = ok
	}
	if !approved {
		_ = a.recordCLIActivity("refused", peer, req)
		return browserhost.BrokerCLIResponse{}, errCLIRunRefused
	}
	// Approval is not disclosure. A deadline that elapsed while the prompt was
	// open, or a lock/epoch change, must fail closed before extraction.
	if ctx.Err() != nil || !a.brokerCurrent(s, epoch) {
		_ = a.recordCLIActivity("failed", peer, req)
		return browserhost.BrokerCLIResponse{}, errCLIRunRefused
	}
	values, e := s.ExtractCLIBrokerTargets(req.Targets)
	if e != nil {
		_ = a.recordCLIActivity("failed", peer, req)
		return browserhost.BrokerCLIResponse{}, e
	}
	// Recheck immediately before the audited return so a lock or deadline
	// racing extraction cannot disclose values.
	if ctx.Err() != nil || !a.brokerCurrent(s, epoch) {
		clear(values)
		_ = a.recordCLIActivity("failed", peer, req)
		return browserhost.BrokerCLIResponse{}, errCLIRunRefused
	}
	if e := a.recordCLIActivity("approved", peer, req); e != nil {
		clear(values)
		return browserhost.BrokerCLIResponse{}, errCLIRunRefused
	}
	return browserhost.BrokerCLIResponse{V: 1, Values: values}, nil
}

func (a *App) requestCLIRunApproval(ctx context.Context, peer browserhost.Peer, req browserhost.BrokerCLIRequest, session *personal.Session, epoch uint64) (bool, error) {
	if ctx == nil {
		return false, errCLIRunRefused
	}
	// One absolute cap. A shorter caller deadline wins; no prompt activity
	// extends the deadline.
	ctx, cancel := context.WithTimeout(ctx, browserhost.CLIRunApprovalMaxLifetime)
	defer cancel()
	if ctx.Err() != nil {
		return false, errCLIRunRefused
	}
	p := &cliRunPending{peer: peer, request: req, decision: make(chan bool, 1)}
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		return false, errCLIRunRefused
	}
	p.id = hex.EncodeToString(b[:])
	a.brokerMu.Lock()
	if a.cliPending != nil || a.brokerSession != session || a.brokerEpoch != epoch || session == nil || !session.Unlocked() {
		a.brokerMu.Unlock()
		return false, errCLIRunRefused
	}
	a.cliPending = p
	a.brokerMu.Unlock()
	a.dispatch(func() {
		if a.onevra.shellActive && a.win != nil && (a.winHidden || !a.win.IsVisible()) {
			a.showApprovalWindow(p.id)
			return
		}
		if a.win != nil {
			a.winHidden = false
			a.win.Show()
			a.win.Focus()
			a.win.Invalidate()
		}
	})
	select {
	case approved := <-p.decision:
		a.brokerMu.Lock()
		if a.cliPending == p {
			a.cliPending = nil
		}
		a.brokerMu.Unlock()
		a.dispatch(func() {
			a.hideApprovalWindowFor(p.id)
			if a.win != nil {
				a.win.Invalidate()
			}
		})
		// A decision delivered at or after the deadline is stale. The exact
		// session/epoch binding must still be current as well.
		if ctx.Err() != nil || !a.brokerCurrent(session, epoch) {
			return false, errCLIRunRefused
		}
		return approved, nil
	case <-ctx.Done():
		a.brokerMu.Lock()
		if a.cliPending == p {
			a.cliPending = nil
		}
		a.brokerMu.Unlock()
		a.dispatch(func() {
			a.hideApprovalWindowFor(p.id)
			if a.win != nil {
				a.win.Invalidate()
			}
		})
		return false, errCLIRunRefused
	}
}

// cliRunDecisionHandlers binds the approve and refuse callbacks to the exact
// pending snapshot a view rendered. The views snapshot p under brokerMu and
// use these closures, so a callback queued from an older render still names
// the old id and approveCLIRun can ignore it once the pending request changes.
func (a *App) cliRunDecisionHandlers(p *cliRunPending) (approve, refuse func()) {
	return func() { a.approveCLIRun(p.id, true) }, func() { a.approveCLIRun(p.id, false) }
}

// approveCLIRun records and signals the decision for exactly the rendered
// pending id, once, under brokerMu. Any other id, including a stale view or a
// request already replaced by a newer one, is ignored without touching the
// current pending request or its window.
func (a *App) approveCLIRun(id string, approved bool) bool {
	a.brokerMu.Lock()
	p := a.cliPending
	if p == nil || id == "" || p.id != id || p.decided {
		a.brokerMu.Unlock()
		return false
	}
	p.decided = true
	p.choose(approved)
	a.brokerMu.Unlock()
	a.hideApprovalWindowFor(id)
	return true
}

// hideApprovalWindowFor hides the approval window only while it still renders
// id. A cleanup queued for an old request therefore cannot hide the window of
// a replacement request.
func (a *App) hideApprovalWindowFor(id string) bool {
	a.brokerMu.Lock()
	if id == "" || a.approvalWinPending != id {
		a.brokerMu.Unlock()
		return false
	}
	a.approvalWinPending = ""
	win := a.approvalWin
	a.brokerMu.Unlock()
	if win != nil && !win.IsDestroyed() {
		win.Hide()
	}
	return true
}

// rejectRenderedCLIRun is the window-close action. It refuses only the id the
// approval window currently renders, so a close callback cannot reject a
// different pending request.
func (a *App) rejectRenderedCLIRun() {
	a.brokerMu.Lock()
	id := a.approvalWinPending
	a.brokerMu.Unlock()
	if id == "" {
		a.hideApprovalWindow()
		return
	}
	if !a.approveCLIRun(id, false) {
		a.hideApprovalWindowFor(id)
	}
}

func (a *App) hideApprovalWindow() {
	a.brokerMu.Lock()
	a.approvalWinPending = ""
	win := a.approvalWin
	a.brokerMu.Unlock()
	if win != nil && !win.IsDestroyed() {
		win.Hide()
	}
}

func (a *App) showApprovalWindow(id string) {
	a.brokerMu.Lock()
	if a.cliPending == nil || a.cliPending.id != id {
		a.brokerMu.Unlock()
		return
	}
	a.approvalWinPending = id
	win := a.approvalWin
	a.brokerMu.Unlock()
	if win == nil || win.IsDestroyed() {
		shell := plain.NewShell(plain.ShellOptions{
			Title:     "Locklark · CLI 凭据请求审批",
			Width:     560,
			Height:    430,
			MinWidth:  500,
			MinHeight: 380,
			Hidden:    true,
			Theme:     a.onevraTheme,
			Content:   a.cliApprovalPopupView,
		})
		win = shell.Window()
		win.SetAlwaysOnTop(true)
		win.SetResizable(false)
		win.SetMinimizable(false)
		win.SetMaximizable(false)
		win.OnClose(func(e *mygo.CloseEvent) {
			e.PreventDefault()
			a.rejectRenderedCLIRun()
		})
		a.brokerMu.Lock()
		a.approvalWin = win
		a.brokerMu.Unlock()
	}
	// A decision or cleanup may have retired this id while the window was
	// being created. Never show a prompt whose exact binding was cleared.
	a.brokerMu.Lock()
	current := a.cliPending != nil && a.cliPending.id == id && a.approvalWinPending == id
	a.brokerMu.Unlock()
	if !current {
		return
	}
	win.Center()
	win.Show()
	win.Focus()
	win.Invalidate()
}

func (a *App) cliApprovalPopupView(c *ui.Context) {
	c.SetTheme(a.onevraTheme(c))
	t := c.Theme()
	a.brokerMu.Lock()
	p := a.cliPending
	a.brokerMu.Unlock()
	ui.Column(c.Key("cli-approval-popup")).Fill().Background(t.Background).Padding(t.Space(4)).Gap(t.Space(2.5)).Children(func() {
		if p == nil {
			oneui.Text(c, "暂无待处理的 CLI 凭据请求。").TextColor(t.TextMuted)
			return
		}
		ui.Row(c).FillWidth().AlignItems(ui.Center).Gap(t.Space(2)).Children(func() {
			iconBox := ui.Box(c).Size(t.Space(9), t.Space(9)).Shrink(0).Radius(t.Space(2.25)).
				Background(t.Accent.Alpha(.14)).AlignItems(ui.Center).Justify(ui.Center)
			iconBox.Children(func() {
				oneui.Icon(c, lucide.SquareTerminal()).Size(t.Space(4.5), t.Space(4.5)).TextColor(t.Accent)
			})
			ui.Column(c).Grow(1).MinWidth(0).Gap(t.Space(.25)).Children(func() {
				oneui.Text(c, "批准本地 CLI 凭据请求").FontSize(t.Rem(1.18)).Bold().TextColor(t.Text)
				oneui.Text(c, "调用进程：PID "+uintString(p.peer.PID)+" · "+p.peer.Process).FontSize(t.Rem(.78)).TextColor(t.TextMuted).SingleLine().Ellipsis("…")
			})
			oneui.Badge(c, "单次授权", oneui.BadgeOptions{Tone: oneui.BadgeWarning})
		})
		ui.Column(c).FillWidth().Border(1, t.Border).Radius(t.Radius).Background(t.Surface).
			Padding(t.Space(2.5)).Gap(t.Space(1)).Children(func() {
			vaultName := vaultDisplayBaseName(p.request.VaultPath)
			if vaultName == "" {
				vaultName = p.request.VaultPath
			}
			oneui.Text(c, "绑定金库："+vaultName+" · 请求用户："+p.peer.User).FontSize(t.Rem(.78)).TextColor(t.TextMuted).Wrap()
			oneui.Text(c, "请求字段槽位 ("+intString(len(p.request.Targets))+")：").FontSize(t.Rem(.78)).Bold().TextColor(t.Text)
			for _, target := range p.request.Targets {
				oneui.Text(c, "• "+target.Slot+" ← "+target.Field+" · "+shortDigest(target.ID)).FontSize(t.Rem(.76)).TextColor(t.Text)
			}
		})
		oneui.Text(c, "批准后，以上固定字段将一次性交给本机 CLI 进程；主密码与 Secret Key 永不交付。").
			FontSize(t.Rem(.76)).Bold().TextColor(t.Warning).Wrap()
		ui.Spacer(c)
		ui.Row(c).FillWidth().AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(t.Space(1.5)).Children(func() {
			oneui.Button(c, "打开主窗口", oneui.ButtonGhost).OnClick(func() {
				a.hideApprovalWindowFor(p.id)
				if a.win != nil {
					a.winHidden = false
					a.win.Show()
					a.win.Focus()
					a.win.Invalidate()
				}
			})
			ui.Row(c).Gap(t.Space(1.5)).Children(func() {
				approve, refuse := a.cliRunDecisionHandlers(p)
				oneui.Button(c, "拒绝本次请求", oneui.ButtonOutline).OnClick(refuse)
				oneui.Button(c, "仅批准本次 CLI 请求", oneui.ButtonPrimary).OnClick(approve)
			})
		})
	})
}

func (a *App) cliApprovalView(c *ui.Context) {
	a.brokerMu.Lock()
	p := a.cliPending
	a.brokerMu.Unlock()
	if p == nil {
		return
	}
	t := c.Theme()
	ui.Column(c).Width(640).Border(1, t.Border).Radius(t.Radius).Background(t.Surface).Padding(t.Space(4)).Gap(12).Children(func() {
		ui.Text(c, "批准本地 CLI 凭据请求").FontSize(24).Bold().TextColor(t.Text)
		ui.Column(c).FillWidth().Border(1, t.Border).Radius(t.Radius).Background(t.Background).Padding(t.Space(3)).Gap(4).Children(func() {
			ui.Text(c, "金库路径："+p.request.VaultPath).FontSize(12).TextColor(t.TextMuted)
			ui.Text(c, "本机用户："+p.peer.User).FontSize(12).TextColor(t.TextMuted)
			ui.Text(c, "调用进程：PID "+uintString(p.peer.PID)+" · "+p.peer.Process).FontSize(12).TextColor(t.TextMuted)
			ui.Text(c, "目标条目数："+intString(len(p.request.Targets))).FontSize(13).Bold().TextColor(t.Text)
		})
		if len(p.request.Targets) > 0 {
			ui.Column(c).FillWidth().Border(1, t.Border).Radius(t.Radius).Background(t.Background).Padding(t.Space(2)).Gap(4).Children(func() {
				for _, target := range p.request.Targets {
					ui.Text(c, target.Slot+" ← "+target.Field+" · "+target.ID).FontSize(12).TextColor(t.Text)
				}
			})
		}
		ui.Text(c, "批准后，以上固定字段将一次性交给本机 CLI 进程。每次请求都需要明确确认。").FontSize(13).Bold().TextColor(t.Warning)
		ui.Row(c).Gap(8).Children(func() {
			approve, refuse := a.cliRunDecisionHandlers(p)
			ui.PrimaryButton(c, "仅批准本次 CLI 请求").OnClick(approve)
			ui.Button(c, "拒绝本次请求").OnClick(refuse)
		})
	})
}

// small local helpers avoid importing fmt/strconv in this file's hot path.
func uintString(v uint32) string {
	if v == 0 {
		return "0"
	}
	var b [10]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}

func intString(v int) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
