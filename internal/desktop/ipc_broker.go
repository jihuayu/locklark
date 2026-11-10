package desktop

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/jihuayu/locklark/internal/browserhost"
	"github.com/jihuayu/locklark/internal/nativeclipboard"
	"github.com/jihuayu/locklark/internal/personal"
)

var errCLIRunRefused = errors.New("refused")

// browserPairPending is one explicit OS-peer browser pairing review. The
// decision is a fresh native gesture; no browser-supplied field can fill it in.
type browserPairPending struct {
	id       string
	request  browserhost.BrowserPairRequest
	decision chan browserhost.BrowserPairDecision
	once     sync.Once
}

func (p *browserPairPending) choose(decision browserhost.BrowserPairDecision) {
	p.once.Do(func() { p.decision <- decision })
}

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
		// Every brokered browser connection must pass this native review
		// before it can receive any capability. The declared Browser/Origin
		// are displayed, never trusted.
		ApproveBrowserPair: a.approveBrowserPair,
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
	a.cancelPendingBrowserPairs()
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
	a.brokerMu.Unlock()
	if p != nil {
		p.choose(false)
	}
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

// handleCLIRun verifies the desktop vault, requests native approval, then
// extracts pinned targets in one authenticated view.
func (a *App) handleCLIRun(ctx context.Context, peer browserhost.Peer, req browserhost.BrokerCLIRequest) (browserhost.BrokerCLIResponse, error) {
	a.brokerMu.Lock()
	s := a.brokerSession
	epoch := a.brokerEpoch
	path := ""
	if s != nil {
		path = s.VaultPath()
	}
	a.brokerMu.Unlock()
	if s == nil || !s.Unlocked() || path == "" || path != req.VaultPath {
		return browserhost.BrokerCLIResponse{}, browserhost.ErrBrokerUnavailable
	}
	approved := false
	if a.cliApprover != nil {
		ok, e := a.cliApprover(ctx, peer, req)
		if e != nil {
			return browserhost.BrokerCLIResponse{}, errCLIRunRefused
		}
		approved = ok
	} else {
		ok, e := a.requestCLIRunApproval(ctx, peer, req, s, epoch)
		if e != nil {
			return browserhost.BrokerCLIResponse{}, errCLIRunRefused
		}
		approved = ok
	}
	if !approved {
		return browserhost.BrokerCLIResponse{}, errCLIRunRefused
	}
	values, e := s.ExtractCLIBrokerTargets(req.Targets)
	if e != nil {
		return browserhost.BrokerCLIResponse{}, e
	}
	return browserhost.BrokerCLIResponse{V: 1, Values: values}, nil
}

func (a *App) requestCLIRunApproval(ctx context.Context, peer browserhost.Peer, req browserhost.BrokerCLIRequest, session *personal.Session, epoch uint64) (bool, error) {
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
		if a.win != nil {
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
			if a.win != nil {
				a.win.Invalidate()
			}
		})
		return approved, nil
	case <-ctx.Done():
		a.brokerMu.Lock()
		if a.cliPending == p {
			a.cliPending = nil
		}
		a.brokerMu.Unlock()
		return false, errCLIRunRefused
	}
}

// ApproveCLIRun is called from the native approval view exactly once.
func (a *App) approveCLIRun(approved bool) {
	a.brokerMu.Lock()
	p := a.cliPending
	a.brokerMu.Unlock()
	if p == nil || p.decided {
		return
	}
	p.decided = true
	p.choose(approved)
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
			ui.PrimaryButton(c, "仅批准本次 CLI 请求").OnClick(func() { a.approveCLIRun(true) })
			ui.Button(c, "拒绝本次请求").OnClick(func() { a.approveCLIRun(false) })
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

// approveBrowserPair is the only bridge from an OS-authenticated browser relay
// to a desktop session capability. It blocks the connection goroutine while
// the owner decides; the UI thread is never blocked.
func (a *App) approveBrowserPair(ctx context.Context, request browserhost.BrowserPairRequest) (browserhost.BrowserPairDecision, error) {
	if a.browserPairApprover != nil {
		return a.browserPairApprover(ctx, request)
	}
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		return browserhost.BrowserPairDecision{}, errCLIRunRefused
	}
	p := &browserPairPending{id: hex.EncodeToString(b[:]), request: request, decision: make(chan browserhost.BrowserPairDecision, 1)}
	a.brokerMu.Lock()
	if len(a.browserPairs) >= 8 {
		a.brokerMu.Unlock()
		return browserhost.BrowserPairDecision{}, errCLIRunRefused
	}
	a.browserPairs = append(a.browserPairs, p)
	a.brokerMu.Unlock()
	a.dispatch(func() {
		if a.win != nil {
			a.win.Show()
			a.win.Focus()
			a.win.Invalidate()
		}
	})
	select {
	case decision := <-p.decision:
		a.removeBrowserPair(p)
		return decision, nil
	case <-ctx.Done():
		a.removeBrowserPair(p)
		return browserhost.BrowserPairDecision{}, errCLIRunRefused
	}
}

func (a *App) removeBrowserPair(p *browserPairPending) {
	a.brokerMu.Lock()
	out := a.browserPairs[:0]
	for _, item := range a.browserPairs {
		if item != p {
			out = append(out, item)
		}
	}
	a.browserPairs = out
	a.brokerMu.Unlock()
	a.dispatch(func() {
		if a.win != nil {
			a.win.Invalidate()
		}
	})
}

func (a *App) cancelPendingBrowserPairs() {
	a.brokerMu.Lock()
	pending := a.browserPairs
	a.browserPairs = nil
	a.brokerMu.Unlock()
	for _, p := range pending {
		p.choose(browserhost.BrowserPairDecision{})
	}
}

func (a *App) pendingBrowserPair() *browserPairPending {
	a.brokerMu.Lock()
	defer a.brokerMu.Unlock()
	if len(a.browserPairs) == 0 {
		return nil
	}
	return a.browserPairs[0]
}

func (a *App) decideBrowserPair(id string, decision browserhost.BrowserPairDecision) {
	a.brokerMu.Lock()
	var chosen *browserPairPending
	out := a.browserPairs[:0]
	for _, item := range a.browserPairs {
		if item.id == id && chosen == nil {
			chosen = item
			continue
		}
		out = append(out, item)
	}
	a.browserPairs = out
	a.brokerMu.Unlock()
	if chosen != nil {
		chosen.choose(decision)
	}
}

func (a *App) browserPairView(c *ui.Context) {
	p := a.pendingBrowserPair()
	if p == nil {
		return
	}
	t := c.Theme()
	label := string(p.request.Browser)
	if label == "" || label == "auto" {
		label = "Chromium / Firefox"
	}
	ui.Column(c).Width(680).Border(1, t.Border).Radius(t.Radius).Background(t.Surface).Padding(t.Space(4)).Gap(12).Children(func() {
		ui.Text(c, "批准浏览器连接桌面金库").FontSize(24).Bold().TextColor(t.Text)
		ui.Text(c, "此请求来自本机同一用户的进程。请核对系统认证的调用进程与浏览器扩展身份；浏览器声明不能替代本次授权。").FontSize(13).TextColor(t.TextMuted)
		ui.Column(c).FillWidth().Border(1, t.Border).Radius(t.Radius).Background(t.Background).Padding(t.Space(3)).Gap(4).Children(func() {
			ui.Text(c, "本机用户："+p.request.Peer.User).FontSize(12).TextColor(t.TextMuted)
			ui.Text(c, "调用进程：PID "+uintString(p.request.Peer.PID)+" · "+p.request.Peer.Process).FontSize(12).TextColor(t.TextMuted)
			ui.Text(c, "声明的浏览器："+label).FontSize(13).TextColor(t.Text)
			ui.Text(c, "声明的扩展来源："+p.request.Origin).FontSize(12).TextColor(t.TextMuted)
		})
		ui.Text(c, "快捷填充只授权本连接内的明确浏览器操作；Passkey、跨源结账和敏感 V2 操作仍会在此窗口逐次确认。锁库、断连或到期后失效。").FontSize(13).TextColor(t.Text)
		ui.Row(c).Gap(8).Wrap().Children(func() {
			ui.PrimaryButton(c, "连接并启用快捷填充").OnClick(func() {
				a.decideBrowserPair(p.id, browserhost.BrowserPairDecision{Approved: true, QuickFill: true})
			})
			ui.PrimaryButton(c, "确认连接（每次敏感操作需批准）").OnClick(func() {
				a.decideBrowserPair(p.id, browserhost.BrowserPairDecision{Approved: true})
			})
			ui.Button(c, "拒绝连接").OnClick(func() {
				a.decideBrowserPair(p.id, browserhost.BrowserPairDecision{})
			})
		})
	})
}
