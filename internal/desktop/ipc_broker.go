package desktop

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strconv"
	"sync"
	"time"
	"unicode/utf8"

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

type cliApprovalPopup struct {
	id      string
	win     *mygo.Window
	retired bool
}

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

// cliRunPending is one native CLI-run review. The scope and targets are
// private copies taken when the review is reserved, so the displayed approval
// matches exactly what was validated on the wire. The view only reads a
// rendered summary, so the owner never holds or re-encodes the live scope.
type cliRunPending struct {
	id   string
	peer browserhost.Peer
	// request is the immutable 150-era view model retained for the owned
	// approval window. It is a private copy and never read back into the
	// broker's validated request.
	request browserhost.BrokerCLIRequest
	summary cliRunApprovalSummary
	// session and epoch are the exact broker generation this request was
	// published under. A decision is only valid while both are still current.
	session  *personal.Session
	epoch    uint64
	decision chan bool
	once     sync.Once
	decided  bool
	// popup is the exact window created for this pending id. Guarded by
	// App.brokerMu.
	popup *cliApprovalPopup
}

func (p *cliRunPending) choose(approved bool) {
	if !approved {
		p.once.Do(func() { p.decision <- false })
		return
	}
	p.once.Do(func() { p.decision <- true })
}

// brokerCurrent reports whether s at epoch is still the unlocked broker session.
func (a *App) brokerCurrent(s *personal.Session, epoch uint64) bool {
	a.brokerMu.Lock()
	defer a.brokerMu.Unlock()
	return s != nil && s.Unlocked() && a.brokerSession == s && a.brokerEpoch == epoch
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
	if p != nil {
		p.decided = true
	}
	popup := a.approvalPopup
	win := a.approvalWin
	if p != nil && p.popup != nil {
		popup = p.popup
	}
	a.brokerMu.Unlock()
	if p != nil {
		p.choose(false)
	}
	if popup != nil {
		a.retireCLIApprovalPopup(popup)
	} else if win != nil && !win.IsDestroyed() {
		win.Destroy()
	}
}

func (a *App) notifyBrowserBrokerUnlocked() {
	a.brokerMu.Lock()
	a.brokerSession, a.brokerEpoch = a.session, a.generation
	b, s, generation := a.broker, a.brokerSession, a.brokerEpoch
	a.brokerMu.Unlock()
	if b != nil && s != nil {
		b.NotifyUnlocked(s, generation)
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

// handleCLIRun is the desktop authorization and response step of one brokered
// CLI-run. It authorizes exactly the unlocked broker session and epoch that are
// current when it is entered and that own the requested vault path, requests
// the explicit native approval of the immutable request, rechecks that same
// session and epoch, then prepares the canonical RunBundle request into the
// audited {"v":1,"values_b64":...,"receipt":...} reply through
// Session.PrepareBrokeredRun. It never reads a credential through the legacy
// ExtractCLIBrokerTargets path, never substitutes any request field, and never
// starts a child process here. Profile, scope, and target validation already
// ran in the broker before this callback.
//
// Only the genuine entry state — no unlocked broker session or no vault path —
// is browserhost.ErrBrokerUnavailable, and only as that exact sentinel, which
// the broker alone may classify as "unavailable". A refusal, a cancellation, a
// different vault, a stale session or epoch, an invalid canonical request, and
// every other failure are the fixed errCLIRunRefused, so no later failure can
// fall back as eligible.
func (a *App) handleCLIRun(ctx context.Context, peer browserhost.Peer, req browserhost.BrokerCLIRequest) (browserhost.BrokerCLIResponse, error) {
	if ctx == nil {
		_ = a.recordCLIActivity("failed", peer, req)
		return browserhost.BrokerCLIResponse{}, errCLIRunRefused
	}
	// The absolute lifetime starts here and is never renewed. A shorter caller
	// deadline remains authoritative through WithTimeout.
	ctx, cancel := context.WithTimeout(ctx, browserhost.CLIRunApprovalMaxLifetime)
	defer cancel()
	// Everything below works on local copies: scope is the immutable copy the
	// canonical request, the native review, and the preparation are built from,
	// and callbackTargets is a fresh copy of the requested targets, so no later
	// step depends on the caller's containers still being intact.
	scope := req.Scope.Clone()
	callbackTargets := append(make([]personal.CLIBrokerTarget, 0, len(req.Targets)), req.Targets...)
	// Ownership of the prepared bytes: only a fully validated success sets
	// transferred, which hands that exact map to the broker callback — the
	// broker encodes it and zeroes every buffer afterwards. Every other return
	// leaves transferred false, so the deferred cleanup zeroes all prepared
	// bytes, then clears the request containers.
	//
	// req is taken by value, so the caller's struct and its own slice and map
	// headers are unreachable here; only the shared backing arrays are. Targets
	// are blanked through the caller's slice and the local copies. Scope.Clear
	// blanks the scalar strings and drops the Args, Helper and Passthru
	// containers; Go strings and map buckets are immutable memory that cannot be
	// wiped, so only the reference-visible entries go.
	var prepared map[string][]byte
	transferred := false
	defer func() {
		if !transferred && prepared != nil {
			clearDesktopCLIPrepared(prepared)
		}
		clearDesktopCLITargets(req.Targets)
		scope.Clear()
		clearDesktopCLITargets(callbackTargets)
	}()
	// Entry state: the exact broker session, its epoch, its vault path, and
	// whether it is unlocked, all read under one brokerMu section, so
	// approval and preparation are bound to one generation. Only this
	// snapshot admits the unavailable sentinel. Once a session is captured,
	// every later check is brokerCurrent: a lock start, a session lock, or an
	// epoch change after this point is the fixed refusal, never unavailable.
	a.brokerMu.Lock()
	s, epoch := a.brokerSession, a.brokerEpoch
	path, unlocked := "", false
	if s != nil {
		path, unlocked = s.VaultPath(), s.Unlocked()
	}
	a.brokerMu.Unlock()
	if s == nil || path == "" || !unlocked {
		_ = a.recordCLIActivity("unavailable", peer, req)
		return browserhost.BrokerCLIResponse{}, browserhost.ErrBrokerUnavailable
	}
	if path != req.VaultPath || browserhost.ValidateCLIRunScope(scope) != nil {
		return browserhost.BrokerCLIResponse{}, errCLIRunRefused
	}
	// Native approval reviews only the rendered summary of scope and targets;
	// the test-only approver hook sees the request before approval.
	approved := false
	if a.cliApprover != nil {
		ok, e := a.cliApprover(ctx, peer, req)
		if e != nil {
			_ = a.recordCLIActivity("failed", peer, req)
			return browserhost.BrokerCLIResponse{}, errCLIRunRefused
		}
		approved = ok
	} else {
		ok, e := a.requestCLIRunApproval(ctx, peer, path, scope, callbackTargets, s, epoch)
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
	// Build the canonical request only from the approved scope. Its profile
	// resolves to the built-in spec; no wire field can override it.
	request, e := browserhost.CanonicalCLIRunRequest(scope, scope.TempRoot)
	if e != nil {
		return browserhost.BrokerCLIResponse{}, errCLIRunRefused
	}
	// targets are the canonical conversion of the validated wire targets; the
	// scratch copies of a failed preparation are cleared with them.
	targets := browserhost.CanonicalCLIRunTargets(callbackTargets)
	defer func() {
		clearDesktopCLIRunBundleRequest(&request)
		clearDesktopCLIBundleTargets(targets)
	}()
	receipt, values, e := s.PrepareBrokeredRun(ctx, targets, request, scope.TempRoot)
	if e != nil {
		return browserhost.BrokerCLIResponse{}, errCLIRunRefused
	}
	prepared = values
	if !validDesktopCLIPrepared(targets, prepared) || !validDesktopCLIReceipt(receipt) {
		return browserhost.BrokerCLIResponse{}, errCLIRunRefused
	}
	// Preparation commits the intent in the session, so the exact session and
	// epoch must still be current afterwards. Otherwise the deferred cleanup
	// clears every prepared buffer and only the fixed refusal is returned.
	if !a.brokerCurrent(s, epoch) {
		return browserhost.BrokerCLIResponse{}, errCLIRunRefused
	}
	// The audited success record is part of the disclosure boundary: a record
	// failure keeps ownership local so the deferred cleanup zeroes every buffer.
	if e := a.recordCLIActivity("approved", peer, req); e != nil {
		return browserhost.BrokerCLIResponse{}, errCLIRunRefused
	}
	// The exact bytes and the audited receipt are complete, so ownership of
	// the prepared map moves to the broker: the local cleanup must not touch it.
	transferred = true
	return browserhost.BrokerCLIResponse{V: 1, PreparedValues: prepared, Receipt: receipt}, nil
}

func (a *App) requestCLIRunApproval(ctx context.Context, peer browserhost.Peer, vaultPath string, scope browserhost.CLIRunScope, targets []personal.CLIBrokerTarget, session *personal.Session, epoch uint64) (bool, error) {
	if ctx == nil || session == nil {
		return false, errCLIRunRefused
	}
	// One absolute cap. A shorter caller deadline wins; no prompt activity
	// extends the deadline.
	ctx, cancel := context.WithTimeout(ctx, browserhost.CLIRunApprovalMaxLifetime)
	defer cancel()
	if ctx.Err() != nil {
		return false, errCLIRunRefused
	}
	summary := cliRunApprovalSummaryFor(peer, vaultPath, scope, targets)
	// The window shows the same immutable request shape the 150 view always
	// used, but it is a private copy: clearing the local containers below
	// cannot change what is displayed.
	request := browserhost.BrokerCLIRequest{
		V:         1,
		VaultPath: vaultPath,
		Scope:     scope.Clone(),
		Targets:   append([]personal.CLIBrokerTarget(nil), targets...),
	}
	scope.Clear()
	targets = nil
	p := &cliRunPending{
		peer:     peer,
		request:  request,
		summary:  summary,
		session:  session,
		epoch:    epoch,
		decision: make(chan bool, 1),
	}
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		return false, errCLIRunRefused
	}
	p.id = hex.EncodeToString(b[:])
	a.brokerMu.Lock()
	if a.cliPending != nil || a.brokerSession != session || a.brokerEpoch != epoch || !session.Unlocked() {
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
		// Retire the summary as before, but never publish a positive result
		// unless the exact binding is still current at that point.
		current := a.finishCLIRunApproval(p)
		if !current {
			return false, errCLIRunRefused
		}
		return approved, nil
	case <-ctx.Done():
		a.finishCLIRunApproval(p)
		return false, errCLIRunRefused
	}
}

// finishCLIRunApproval retires a decided or cancelled review, drops its
// rendered summary, and retires the window owned by exactly this pending id.
// It revalidates the epoch binding under the same lock, so a stale decision can
// never retire a newer review, and reports whether p was decided and its exact
// session, broker epoch and unlocked state still match.
func (a *App) finishCLIRunApproval(p *cliRunPending) bool {
	if p == nil {
		return false
	}
	a.brokerMu.Lock()
	current := p.decided && p.session != nil && p.session.Unlocked() && a.brokerSession == p.session && a.brokerEpoch == p.epoch
	if a.cliPending == p {
		a.cliPending = nil
	}
	p.summary = cliRunApprovalSummary{}
	popup := p.popup
	p.popup = nil
	var win *mygo.Window
	if a.approvalWinPending == p.id {
		if popup == nil && a.approvalPopup != nil && a.approvalPopup.id == p.id {
			popup = a.approvalPopup
		}
		win = a.approvalWin
		a.approvalWinPending = ""
		a.approvalWin = nil
		if popup != nil && a.approvalPopup == popup {
			a.approvalPopup = nil
		}
	}
	a.brokerMu.Unlock()
	if popup != nil {
		a.retireCLIApprovalPopup(popup)
	} else if win != nil && !win.IsDestroyed() {
		win.Destroy()
	}
	a.dispatch(func() {
		if a.win != nil {
			a.win.Invalidate()
		}
	})
	return current
}

// defaultCLIRunHandlerFactory is the production factory cliApprovalView uses.
var defaultCLIRunHandlerFactory cliRunHandlerFactory = (*App).cliRunApproveRefuseHandlers

// cliRunHandlerFactory builds the approve and refuse handlers for exactly one
// rendered review. cliApprovalView binds the review it snapshotted under
// brokerMu when it renders; tests use the same factory to capture the closures
// the view wired for that review.
type cliRunHandlerFactory func(a *App, pending, snapshot *cliRunPending) (approve, refuse func())

// cliRunApproveRefuseHandlers returns the native approve and refuse handlers
// for snapshot, the review the view rendered and displayed, when the view was
// built for current, the review it saw as pending. Each handler decides exactly
// snapshot; nothing happens if snapshot is no longer the current pending
// review. A stale view of a retired review therefore cannot approve or refuse
// a newer request. The decision is recorded and signalled exactly once, under
// brokerMu, so the lock path and a double click cannot race it.
func (a *App) cliRunApproveRefuseHandlers(current, snapshot *cliRunPending) (approve, refuse func()) {
	return func() { a.approveCLIRun(snapshot, true) }, func() { a.approveCLIRun(snapshot, false) }
}

// cliRunHandlers builds the approve and refuse closures for the rendered
// snapshot through the active factory: the production pair outside tests, and
// the capturing factory a test installs with t.Cleanup restoring it. The
// receiver is the owner of the in-progress view.
func (a *App) cliRunHandlers(current, snapshot *cliRunPending) (approve, refuse func()) {
	return defaultCLIRunHandlerFactory(a, current, snapshot)
}

// cliRunDecisionHandlers binds the approve and refuse callbacks to the exact
// pending snapshot a popup rendered. The decision uses pointer identity, so a
// queued callback from an older render cannot decide a replacement request.
func (a *App) cliRunDecisionHandlers(p *cliRunPending) (approve, refuse func()) {
	return func() { a.approveCLIRun(p, true) }, func() { a.approveCLIRun(p, false) }
}

// decideCLIRunLocked records exactly one decision for p while brokerMu is
// held. A positive decision is published only for the exact non-nil session,
// current broker epoch, and still-unlocked session bound at request entry;
// every other positive attempt is signalled as a refusal. It returns the popup
// and window owned by p so the caller can retire them after unlocking, and
// reports whether p was the current undecided pending.
func (a *App) decideCLIRunLocked(p *cliRunPending, approved bool) (*cliApprovalPopup, *mygo.Window, bool) {
	if p == nil || a.cliPending != p || p.decided {
		return nil, nil, false
	}
	p.decided = true
	positive := approved && p.session != nil && p.session.Unlocked() &&
		a.brokerSession == p.session && a.brokerEpoch == p.epoch
	p.choose(positive)
	id := p.id
	popup := p.popup
	if popup == nil && a.approvalPopup != nil && a.approvalPopup.id == id {
		popup = a.approvalPopup
	}
	win := a.approvalWin
	if a.approvalWinPending == id {
		a.approvalWinPending = ""
		a.approvalWin = nil
	}
	if popup != nil && a.approvalPopup == popup {
		a.approvalPopup = nil
	}
	return popup, win, true
}

// retireDecidedCLIRun retires the exact popup and window captured for an
// accepted decision. Retirement takes brokerMu itself, so it must run only
// after decideCLIRunLocked has released the lock.
func (a *App) retireDecidedCLIRun(popup *cliApprovalPopup, win *mygo.Window) {
	if popup != nil {
		a.retireCLIApprovalPopup(popup)
	} else if win != nil && !win.IsDestroyed() {
		win.Destroy()
	}
}

// approveCLIRun records and signals the decision for the exact pending pointer
// once, under brokerMu. A positive decision also requires the exact non-nil
// session and current broker epoch to be current and unlocked; every refusal
// or stale binding is signalled as a refusal. The owned popup, if any, is
// retired on every accepted decision; a stale pointer touches nothing and
// reports false.
func (a *App) approveCLIRun(p *cliRunPending, approved bool) bool {
	a.brokerMu.Lock()
	popup, win, ok := a.decideCLIRunLocked(p, approved)
	a.brokerMu.Unlock()
	if !ok {
		return false
	}
	a.retireDecidedCLIRun(popup, win)
	return true
}

// approveCLIRunID is the typed wrapper for the 150-owned popup close action,
// which is bound to a rendered id rather than the pending pointer. It resolves
// the id to the current pending under brokerMu and then applies the same
// pointer/session/epoch checks as approveCLIRun; an empty, unknown, or stale
// id reports false and decides nothing.
func (a *App) approveCLIRunID(id string, approved bool) bool {
	a.brokerMu.Lock()
	p := a.cliPending
	if p == nil || id == "" || p.id != id {
		a.brokerMu.Unlock()
		return false
	}
	popup, win, ok := a.decideCLIRunLocked(p, approved)
	a.brokerMu.Unlock()
	if !ok {
		return false
	}
	a.retireDecidedCLIRun(popup, win)
	return true
}

// cliRunCloseHandler captures one immutable popup. A delayed close event from
// an old window can therefore reject only its own pending id and retire only
// its own window, never whatever happens to be rendered now.
func (a *App) cliRunCloseHandler(popup *cliApprovalPopup) func(*mygo.CloseEvent) {
	return func(e *mygo.CloseEvent) {
		if e != nil {
			e.PreventDefault()
		}
		a.closeCLIApprovalPopup(popup)
	}
}

func (a *App) closeCLIApprovalPopup(popup *cliApprovalPopup) {
	if popup == nil {
		return
	}
	// approveCLIRun rejects the captured id only while it is still current.
	// A stale p1 popup leaves p2's decision and window untouched.
	a.approveCLIRunID(popup.id, false)
	a.retireCLIApprovalPopup(popup)
}

// retireCLIApprovalPopup destroys exactly popup's window without firing a
// close event, so retiring p1 cannot recurse into the live p2 popup.
func (a *App) retireCLIApprovalPopup(popup *cliApprovalPopup) {
	if popup == nil {
		return
	}
	a.brokerMu.Lock()
	if popup.retired {
		a.brokerMu.Unlock()
		return
	}
	popup.retired = true
	win := popup.win
	popup.win = nil
	if a.approvalPopup == popup {
		a.approvalPopup = nil
		a.approvalWin = nil
		if a.approvalWinPending == popup.id {
			a.approvalWinPending = ""
		}
	}
	if a.cliPending != nil && a.cliPending.popup == popup {
		a.cliPending.popup = nil
	}
	a.brokerMu.Unlock()
	if win != nil && !win.IsDestroyed() {
		win.Destroy()
	}
}

// retireCLIRunPendingWindow retires the popup captured by one pending request,
// even if a replacement request has since become current. It is safe to call
// more than once and from a queued cleanup.
func (a *App) retireCLIRunPendingWindow(p *cliRunPending) {
	if p == nil {
		return
	}
	a.brokerMu.Lock()
	popup := p.popup
	p.popup = nil
	var win *mygo.Window
	if a.approvalWinPending == p.id {
		if popup == nil && a.approvalPopup != nil && a.approvalPopup.id == p.id {
			popup = a.approvalPopup
		}
		win = a.approvalWin
		a.approvalWinPending = ""
		a.approvalWin = nil
		if popup != nil && a.approvalPopup == popup {
			a.approvalPopup = nil
		}
	}
	a.brokerMu.Unlock()
	if popup != nil {
		a.retireCLIApprovalPopup(popup)
		return
	}
	if win != nil && !win.IsDestroyed() {
		win.Destroy()
		return
	}
	// Test/legacy state may have rendered an owner without a popup object.
	a.hideApprovalWindowFor(p.id)
}

// hideApprovalWindowFor retires the popup only while it still renders id. A
// cleanup queued for an old request therefore cannot hide the window of a
// replacement request.
func (a *App) hideApprovalWindowFor(id string) bool {
	a.brokerMu.Lock()
	if id == "" || a.approvalWinPending != id {
		a.brokerMu.Unlock()
		return false
	}
	popup := a.approvalPopup
	if popup == nil && a.cliPending != nil && a.cliPending.id == id {
		popup = a.cliPending.popup
	}
	win := a.approvalWin
	a.approvalWinPending = ""
	a.approvalWin = nil
	if popup != nil && a.approvalPopup == popup {
		a.approvalPopup = nil
	}
	if a.cliPending != nil && a.cliPending.popup == popup {
		a.cliPending.popup = nil
	}
	a.brokerMu.Unlock()
	if popup != nil {
		a.retireCLIApprovalPopup(popup)
	} else if win != nil && !win.IsDestroyed() {
		win.Destroy()
	}
	return true
}

// hideApprovalWindow retires the current popup without deciding its pending.
// It is used for teardown paths such as lock/quit, not for a rendered action.
func (a *App) hideApprovalWindow() {
	a.brokerMu.Lock()
	popup := a.approvalPopup
	if popup == nil && a.cliPending != nil {
		popup = a.cliPending.popup
	}
	win := a.approvalWin
	a.approvalWinPending = ""
	a.approvalWin = nil
	a.approvalPopup = nil
	if a.cliPending != nil {
		a.cliPending.popup = nil
	}
	a.brokerMu.Unlock()
	if popup != nil {
		a.retireCLIApprovalPopup(popup)
	} else if win != nil && !win.IsDestroyed() {
		win.Destroy()
	}
}

func (a *App) showCLIApprovalPopup(popup *cliApprovalPopup) {
	if popup == nil {
		return
	}
	a.brokerMu.Lock()
	if popup.retired || popup.win == nil {
		a.brokerMu.Unlock()
		return
	}
	win := popup.win
	a.brokerMu.Unlock()
	if win.IsDestroyed() {
		return
	}
	win.Center()
	win.Show()
	win.Focus()
	win.Invalidate()
}

func (a *App) showApprovalWindow(id string) {
	a.brokerMu.Lock()
	p := a.cliPending
	if p == nil || p.id != id {
		a.brokerMu.Unlock()
		return
	}
	if p.popup != nil && !p.popup.retired && p.popup.win != nil && !p.popup.win.IsDestroyed() {
		popup := p.popup
		a.approvalPopup = popup
		a.approvalWin = popup.win
		a.approvalWinPending = id
		a.brokerMu.Unlock()
		a.showCLIApprovalPopup(popup)
		return
	}
	oldPopup, oldWin, stalePopup := a.approvalPopup, a.approvalWin, p.popup
	a.approvalPopup = nil
	a.approvalWin = nil
	a.approvalWinPending = ""
	a.brokerMu.Unlock()
	if oldPopup != nil {
		a.retireCLIApprovalPopup(oldPopup)
	}
	if stalePopup != nil && stalePopup != oldPopup {
		a.retireCLIApprovalPopup(stalePopup)
	}
	if oldPopup == nil && stalePopup == nil && oldWin != nil && !oldWin.IsDestroyed() {
		oldWin.Destroy()
	}

	// Every pending request gets its own popup, its own immutable close
	// handler, and its own content closure. The content captures popup and
	// revalidates exact ownership before rendering; it never substitutes the
	// then-current global pending into an older window.
	popup := &cliApprovalPopup{id: id}
	shell := plain.NewShell(plain.ShellOptions{
		Title:     "Locklark · CLI 凭据请求审批",
		Width:     560,
		Height:    430,
		MinWidth:  500,
		MinHeight: 380,
		Hidden:    true,
		Theme:     a.onevraTheme,
		Content:   a.cliApprovalPopupContent(popup),
	})
	win := shell.Window()
	popup.win = win
	win.SetAlwaysOnTop(true)
	win.SetResizable(false)
	win.SetMinimizable(false)
	win.SetMaximizable(false)
	win.OnClose(a.cliRunCloseHandler(popup))

	a.brokerMu.Lock()
	if a.cliPending == nil || a.cliPending.id != id {
		a.brokerMu.Unlock()
		a.retireCLIApprovalPopup(popup)
		return
	}
	if a.cliPending.popup != nil && !a.cliPending.popup.retired && a.cliPending.popup != popup {
		existing := a.cliPending.popup
		a.brokerMu.Unlock()
		a.retireCLIApprovalPopup(popup)
		a.showCLIApprovalPopup(existing)
		return
	}
	previous := a.approvalPopup
	p.popup = popup
	a.approvalPopup = popup
	a.approvalWin = win
	a.approvalWinPending = id
	a.brokerMu.Unlock()
	if previous != nil && previous != popup {
		a.retireCLIApprovalPopup(previous)
	}
	a.showCLIApprovalPopup(popup)
}

// cliApprovalPopupContent binds a window's content to the immutable popup
// created for one pending id. Every render revalidates that this popup is
// still the exact current owner; otherwise it renders the neutral empty state
// and never builds controls or details from a replacement pending.
func (a *App) cliApprovalPopupContent(popup *cliApprovalPopup) func(*ui.Context) {
	return func(c *ui.Context) {
		a.renderCLIApprovalPopupExact(c, popup)
	}
}

// cliApprovalPopupView renders only the exact live current popup. It is a
// convenience entry point for the view tests; production windows use the
// captured content closure above.
func (a *App) cliApprovalPopupView(c *ui.Context) {
	a.brokerMu.Lock()
	popup := a.approvalPopup
	a.brokerMu.Unlock()
	a.renderCLIApprovalPopupExact(c, popup)
}

func (a *App) renderCLIApprovalPopupExact(c *ui.Context, popup *cliApprovalPopup) {
	a.brokerMu.Lock()
	var p *cliRunPending
	if popup != nil && !popup.retired &&
		a.approvalPopup == popup && a.approvalWinPending == popup.id &&
		a.cliPending != nil && a.cliPending.id == popup.id && a.cliPending.popup == popup {
		p = a.cliPending
	}
	a.brokerMu.Unlock()
	a.renderCLIApprovalPopup(c, p)
}

func (a *App) renderCLIApprovalPopup(c *ui.Context, p *cliRunPending) {
	c.SetTheme(a.onevraTheme(c))
	t := c.Theme()
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
	// Snapshot the pending review pointer and its immutable summary under the
	// same mutex that finishCLIRunApproval uses to retire the review and
	// replace the summary, so the render loop below never races the slice
	// headers. Rendering happens after the lock is released, and the buttons
	// stay bound to this exact snapshot: the decision compares it by pointer
	// against the current pending review, so a stale view can never decide a
	// newer request.
	a.brokerMu.Lock()
	pending := a.cliPending
	var snapshot *cliRunPending
	var summary *cliRunApprovalSummary
	if pending != nil {
		snapshot = pending
		rendered := pending.summary
		summary = &rendered
	}
	a.brokerMu.Unlock()
	if snapshot == nil || summary == nil {
		return
	}
	t := c.Theme()
	ui.Column(c).Width(640).Border(1, t.Border).Radius(t.Radius).Background(t.Surface).Padding(t.Space(4)).Gap(12).Children(func() {
		ui.Text(c, cliRunApprovalTitle).FontSize(24).Bold().TextColor(t.Text)
		ui.Column(c).FillWidth().Border(1, t.Border).Radius(t.Radius).Background(t.Background).Padding(t.Space(3)).Gap(4).Children(func() {
			for _, line := range summary.Peer {
				ui.Text(c, line).FontSize(12).TextColor(t.TextMuted)
			}
		})
		for _, section := range summary.Sections {
			ui.Column(c).FillWidth().Border(1, t.Border).Radius(t.Radius).Background(t.Background).Padding(t.Space(2)).Gap(4).Children(func() {
				ui.Text(c, section.Heading).FontSize(13).Bold().TextColor(t.Text)
				for _, line := range section.Lines {
					ui.Text(c, line).FontSize(12).TextColor(t.Text).Selectable()
				}
			})
		}
		for _, warning := range summary.Warnings {
			ui.Text(c, warning).FontSize(13).Bold().TextColor(t.Warning)
		}
		ui.Row(c).Gap(8).Wrap().Children(func() {
			approve, refuse := (*App)(a).cliRunHandlers(pending, snapshot)
			ui.PrimaryButton(c, cliRunApproveLabel).OnClick(approve)
			ui.Button(c, cliRunRefuseLabel).OnClick(refuse)
		})
	})
}

const (
	cliRunApprovalTitle  = "批准本地 CLI 凭据请求"
	cliRunApproveLabel   = "仅批准本次 CLI 请求"
	cliRunRefuseLabel    = "拒绝本次请求"
	cliRunUnpinnedLabel  = "未固定（仍会校验为普通可执行文件）"
	cliRunEmptyLabel     = "（无）"
	cliRunTokenEnvPrefix = "动态令牌环境变量名（不显示值）："
)

// cliRunApprovalSection is one titled block of the native CLI-run approval.
type cliRunApprovalSection struct {
	Heading string
	Lines   []string
}

// cliRunApprovalSummary is the complete authorization scope the owner reviews
// before approving one CLI-run. It is derived only from the validated scope,
// the immutable targets, and the OS-authenticated peer.
type cliRunApprovalSummary struct {
	Peer     []string
	Sections []cliRunApprovalSection
	Warnings []string
}

// cliRunApprovalSummaryFor builds the secret-free text of the native approval.
// Every value shown is either an OS-authenticated peer field, a validated and
// bounded scope field, or a target slot/ID/revision/field. Passthrough
// environment values are never read: only their sorted names are listed. The
// nonce is protocol metadata for the replay slice and is not displayed: it
// authenticates nothing to the owner, who reviews the TTY identity instead.
//
// Every user-supplied display value goes through cliRunQuote, so a CR, LF,
// escape, or other control character can neither add nor hide a review line:
// each label stays exactly one line of untrusted, visibly quoted text.
func cliRunApprovalSummaryFor(peer browserhost.Peer, vaultPath string, scope browserhost.CLIRunScope, targets []personal.CLIBrokerTarget) cliRunApprovalSummary {
	out := cliRunApprovalSummary{
		Peer: []string{
			"金库路径：" + cliRunQuote(vaultPath),
			"本机用户：" + cliRunQuote(peer.User),
			"调用进程：PID " + uintString(peer.PID) + " · " + cliRunQuote(peer.Process),
		},
	}
	pin := "未固定 · " + cliRunUnpinnedLabel
	if scope.ProgramPinned() {
		pin = "已固定 SHA-256 " + cliRunQuote(scope.ProgramSH)
	}
	// The nonce is deliberately absent: it is protocol metadata, and the owner
	// authorizes by the TTY identity, not by an opaque random string.
	out.Sections = append(out.Sections, cliRunApprovalSection{
		Heading: "授权范围",
		Lines: []string{
			"配置档：" + cliRunQuote(scope.Profile),
			"终端标识：" + cliRunQuote(scope.TTY),
			"执行程序：" + cliRunQuote(scope.Program),
			"程序固定：" + pin,
			"工作目录：" + cliRunQuote(scope.CWD),
			"超时限制：" + intString(scope.Timeout) + " 秒", // bounded int, no user text
			"临时运行目录：" + cliRunQuote(scope.TempRoot),
		},
	})
	arguments := scope.Args
	args := make([]string, 0, len(arguments))
	if len(arguments) == 0 {
		args = append(args, cliRunEmptyLabel)
	}
	for i, arg := range arguments {
		args = append(args, "["+intString(i)+"] "+cliRunQuote(arg))
	}
	out.Sections = append(out.Sections, cliRunApprovalSection{Heading: "命令参数（共 " + intString(len(arguments)) + " 项）", Lines: args})
	targetLines := make([]string, 0, len(targets))
	if len(targets) == 0 {
		targetLines = append(targetLines, cliRunEmptyLabel)
	}
	for _, target := range targets {
		targetLines = append(targetLines,
			cliRunQuote(target.Slot)+" ← "+cliRunQuote(target.Field),
			"    条目 "+cliRunQuote(target.ID)+" · 修订 "+cliRunQuote(target.Revision))
	}
	out.Sections = append(out.Sections, cliRunApprovalSection{Heading: "金库目标（不可变修订）", Lines: targetLines})
	helper := make([]string, 0, len(scope.Helper))
	if len(scope.Helper) == 0 {
		helper = append(helper, cliRunEmptyLabel)
	}
	for _, dir := range scope.Helper {
		helper = append(helper, cliRunQuote(dir))
	}
	out.Sections = append(out.Sections, cliRunApprovalSection{Heading: "辅助 PATH 目录", Lines: helper})
	names := make([]string, 0, len(scope.Passthru)) // names only; values are never read
	if len(scope.Passthru) == 0 {
		names = append(names, cliRunEmptyLabel)
	}
	for _, name := range scope.PassthroughNames() {
		names = append(names, cliRunQuote(name))
	}
	out.Sections = append(out.Sections, cliRunApprovalSection{Heading: "透传环境变量名（不显示值）", Lines: names})
	if scope.TokenEnv != "" {
		out.Sections = append(out.Sections, cliRunApprovalSection{Heading: cliRunTokenEnvPrefix, Lines: []string{cliRunQuote(scope.TokenEnv)}})
	}
	out.Warnings = []string{
		"批准后，以上固定字段将一次性交给本机 CLI 进程。每次请求都需要明确确认。",
		"这不是沙箱：程序及其后代可以读取、复制或外发已披露的值，且无法收回。",
	}
	return out
}

// cliRunQuote renders one user-supplied display value as a single, quoted line.
// Valid UTF-8 is quoted with strconv.Quote and values with invalid UTF-8 with a
// Go string literal, so CR, LF, escapes, quotes, and every other control
// character appear only as visible escape sequences: a value can never start,
// hide, or forge a review line. Both forms match strconv.Quote's rules exactly.
func cliRunQuote(value string) string {
	if utf8.ValidString(value) {
		return strconv.Quote(value)
	}
	return quotedStringLiteral(value)
}

// quotedStringLiteral quotes s with strconv.Quote's rules for every valid
// sequence, except that each invalid UTF-8 byte becomes one \xNN byte escape
// instead of the lossy U+FFFD rewrite and the octal escapes. Non-ASCII runes are
// kept only when they are graphic and not spaces, as in strconv.Quote: every
// other rune (C1 controls such as U+0085, U+2028/U+2029, invalid runes, and
// formatting characters such as the bidi overrides U+202E/U+202B, which are
// category Cf) is escaped as \uNNNN or \UNNNNNNNN, so no rune can reorder,
// hide, or split the displayed line.
func quotedStringLiteral(s string) string {
	const hex = "0123456789abcdef"
	b := make([]byte, 0, len(s)+2)
	b = append(b, '"')
	appendUnicodeEscape := func(r rune) {
		if r < 0x10000 {
			b = append(b, '\\', 'u', hex[r>>12&0xf], hex[r>>8&0xf], hex[r>>4&0xf], hex[r&0xf])
			return
		}
		b = append(b, '\\', 'U', hex[r>>28&0xf], hex[r>>24&0xf], hex[r>>20&0xf], hex[r>>16&0xf],
			hex[r>>12&0xf], hex[r>>8&0xf], hex[r>>4&0xf], hex[r&0xf])
	}
	for len(s) > 0 {
		if c := s[0]; c >= utf8.RuneSelf {
			r, width := utf8.DecodeRuneInString(s)
			if r == utf8.RuneError && width == 1 {
				b = append(b, '\\', 'x', hex[c>>4], hex[c&0xf])
				s = s[1:]
				continue
			}
			s = s[width:]
			// This is strconv.Quote's per-rune rule for canonical ordering of
			// e.g. combining marks.
			if !strconv.IsPrint(r) {
				appendUnicodeEscape(r)
				continue
			}
			if r < utf8.RuneSelf {
				if c := byte(r); c == '\\' || c == '"' {
					b = append(b, '\\', c)
				} else {
					b = append(b, c)
				}
				continue
			}
			b = utf8.AppendRune(b, r)
			continue
		}
		c := s[0]
		s = s[1:]
		switch c {
		case '\a':
			b = append(b, '\\', 'a')
		case '\b':
			b = append(b, '\\', 'b')
		case '\f':
			b = append(b, '\\', 'f')
		case '\n':
			b = append(b, '\\', 'n')
		case '\r':
			b = append(b, '\\', 'r')
		case '\t':
			b = append(b, '\\', 't')
		case '\v':
			b = append(b, '\\', 'v')
		case '\\':
			b = append(b, '\\', '\\')
		case '"':
			b = append(b, '\\', '"')
		default:
			if c < 0x20 || c == 0x7f {
				b = append(b, '\\', 'x', hex[c>>4], hex[c&0xf])
			} else {
				b = append(b, c)
			}
		}
	}
	return string(append(b, '"'))
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

// validDesktopCLIReceipt is an independent check of the preparation receipt
// the audited reply must carry: the explicit preparation status, a canonical
// 32-hex session ID, and two canonical 64-hex digests. The broker checks the
// same shape again before encoding, so a malformed receipt is refused here and
// never reaches the wire with any value.
func validDesktopCLIReceipt(receipt personal.RunBundlePreparationReceipt) bool {
	return receipt.Status == personal.RunBundlePreparationStatus &&
		desktopLowerHex(receipt.Session, 32) && desktopLowerHex(receipt.Intent, 64) && desktopLowerHex(receipt.TargetDigest, 64)
}

func desktopLowerHex(value string, n int) bool {
	if len(value) != n {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c >= '0' && c <= '9' || c >= 'a' && c <= 'f' {
			continue
		}
		return false
	}
	return true
}

// validDesktopCLIPrepared reports whether values carries exactly one non-nil
// buffer for each canonical target slot and nothing else, so a missing, extra,
// or nil buffer is a refusal rather than a partial disclosure.
func validDesktopCLIPrepared(targets []personal.BundleTarget, values map[string][]byte) bool {
	if len(targets) == 0 || len(values) != len(targets) {
		return false
	}
	seen := make(map[string]bool, len(targets))
	for _, target := range targets {
		value, ok := values[target.Slot]
		if !ok || value == nil || seen[target.Slot] {
			return false
		}
		seen[target.Slot] = true
	}
	return true
}

// clearDesktopCLILegacyValues blanks and drops every entry of a legacy
// map[string]string payload. Only tests read that map, to know the fixture's
// expected plaintext, and they clear it afterwards so no extra copy lingers.
func clearDesktopCLILegacyValues(values map[string]string) {
	for slot := range values {
		values[slot] = ""
		delete(values, slot)
	}
}

// clearDesktopCLIPrepared zeroes every prepared byte buffer in place and drops
// the map. Byte slices are the one secret carrier Go can actually overwrite, so
// every error path and the broker's own copy after encoding use this.
func clearDesktopCLIPrepared(values map[string][]byte) {
	for slot, value := range values {
		clear(value)
		delete(values, slot)
	}
}

// clearDesktopCLITargets blanks the wire target elements (slot, ID, revision,
// field) of a request copy. None of these is a credential; they are cleared so
// a finished or refused request leaves no field to inspect.
func clearDesktopCLITargets(targets []personal.CLIBrokerTarget) {
	for i := range targets {
		targets[i] = personal.CLIBrokerTarget{}
	}
}

// clearDesktopCLIBundleTargets blanks the canonical RunBundle target copies.
func clearDesktopCLIBundleTargets(targets []personal.BundleTarget) {
	for i := range targets {
		targets[i] = personal.BundleTarget{}
	}
}

// clearDesktopCLIRunBundleRequest empties every mutable container of the
// canonical request copy: its arguments, helper paths, and passthrough map,
// and the resolved profile spec's slots, files, dirs, environment map,
// passthrough names, and nested deny-argument slices. Element slots and map
// entry pointers are zeroed; the string bytes they referenced are immutable
// and are not wiped by Go, so no secure erasure is claimed here. The request
// carries only the approved execution scope, never a credential.
func clearDesktopCLIRunBundleRequest(request *personal.RunBundleRequest) {
	if request == nil {
		return
	}
	clear(request.Args)
	clear(request.HelperPath)
	for name := range request.Passthrough {
		delete(request.Passthrough, name)
	}
	clear(request.Spec.Slots)
	clear(request.Spec.Files)
	clear(request.Spec.Dirs)
	clear(request.Spec.PassthroughEnv)
	for name := range request.Spec.Env {
		delete(request.Spec.Env, name)
	}
	for i := range request.Spec.DenyArgs {
		clear(request.Spec.DenyArgs[i])
		request.Spec.DenyArgs[i] = nil
	}
	clear(request.Spec.DenyArgs)
	*request = personal.RunBundleRequest{}
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
		ui.Text(c, "启用快捷填充：你显式授权本连接在 15 分钟内执行 V2 列表/详情（含身份信息与非隐藏字段）、字段复制/显示、附件读取、条目新建/编辑/状态/恢复、暂存保存、附件写入，以及验证码填充和保存登录，不再逐次弹窗。Passkey 删除和附件删除始终逐次确认，即使启用快捷填充也不例外；Passkey 登录/创建/信号和跨源或资料字段填充同样仍会逐次确认。").FontSize(13).TextColor(t.Text)
		ui.Text(c, "逐次确认：V2 列表仍可直接显示标题和公开元数据用于选择；条目详情（含身份信息与非隐藏字段）、字段复制/显示、附件读取、条目/附件写入、验证码填充和保存登录都会逐个回到此窗口批准。Passkey 删除和附件删除始终逐次确认，即使启用快捷填充也不例外；Passkey 其他操作和资料填充同样逐次确认。锁库、断连或到期后两种模式都失效。").FontSize(13).TextColor(t.TextMuted)
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
