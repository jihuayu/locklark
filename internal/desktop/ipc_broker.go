package desktop

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"

	"github.com/egoist/mygo/ui"
	"github.com/jihuayu/locklark/internal/browserhost"
	"github.com/jihuayu/locklark/internal/personal"
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

// startBrowserBroker hosts the shared desktop↔extension IPC endpoint.
func (a *App) startBrowserBroker() {
	if a.broker != nil {
		return
	}
	endpoint, e := browserhost.DefaultBrokerEndpoint()
	if e != nil {
		return
	}
	callbacks := browserhost.BrokerCallbacks{
		CurrentSession: func() (*personal.Session, uint64, bool) {
			a.brokerMu.Lock()
			defer a.brokerMu.Unlock()
			if a.session == nil || !a.session.Unlocked() {
				return nil, 0, false
			}
			return a.session, a.generation, true
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
	}
	b := browserhost.NewBroker(callbacks)
	if e = b.Start(endpoint); e != nil {
		return
	}
	a.brokerMu.Lock()
	a.broker = b
	a.brokerEndpoint = endpoint
	a.brokerMu.Unlock()
}

func (a *App) stopBrowserBroker() {
	a.brokerMu.Lock()
	b := a.broker
	a.broker = nil
	a.brokerEndpoint = ""
	a.brokerMu.Unlock()
	if b != nil {
		_ = b.Close()
	}
}

func (a *App) notifyBrowserBrokerUnlocked() {
	a.brokerMu.Lock()
	b, s := a.broker, a.session
	generation := a.generation
	a.brokerMu.Unlock()
	if b != nil && s != nil {
		b.NotifyUnlocked(s, generation, true)
	}
}

func (a *App) notifyBrowserBrokerLocked() {
	a.brokerMu.Lock()
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
	s := a.session
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
		ok, e := a.requestCLIRunApproval(ctx, peer, req)
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

func (a *App) requestCLIRunApproval(ctx context.Context, peer browserhost.Peer, req browserhost.BrokerCLIRequest) (bool, error) {
	p := &cliRunPending{peer: peer, request: req, decision: make(chan bool, 1)}
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		return false, errCLIRunRefused
	}
	p.id = hex.EncodeToString(b[:])
	a.brokerMu.Lock()
	if a.cliPending != nil {
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
	ui.Column(c).Width(640).Gap(12).Children(func() {
		ui.Text(c, "批准本地 CLI 凭据请求").FontSize(26).Bold()
		ui.Text(c, "Vault: "+p.request.VaultPath).FontSize(12)
		ui.Text(c, "Peer: "+p.peer.User).FontSize(12)
		ui.Text(c, "PID: "+uintString(p.peer.PID)+" · "+p.peer.Process).FontSize(12)
		ui.Text(c, "目标条目数："+intString(len(p.request.Targets)))
		for _, t := range p.request.Targets {
			ui.Text(c, t.Slot+" ← "+t.Field+" · "+t.ID).FontSize(12)
		}
		ui.Text(c, "批准后，以下固定字段将一次性交给本机 CLI 进程。每次请求都需要明确确认。").Bold()
		ui.PrimaryButton(c, "仅批准本次 CLI 请求").OnClick(func() { a.approveCLIRun(true) })
		ui.Button(c, "拒绝本次请求").OnClick(func() { a.approveCLIRun(false) })
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
