package desktop

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/jihuayu/locklark/internal/browserhost"
	"github.com/jihuayu/locklark/internal/cliprofile"
	"github.com/jihuayu/locklark/internal/nativeclipboard"
	"github.com/jihuayu/locklark/internal/personal"
)

var errCLIRunRefused = errors.New("refused")

const (
	cliV2ApproveLabel = "仅批准本次 CLI 请求"
	cliV2LeaseLabel   = "批准此终端相同命令 5 分钟"
	cliV2RefuseLabel  = "拒绝本次请求"
)

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

// cliRunV2Pending owns exactly one undecided cli-run v2 approval. It retains a
// deep clone of the whole trusted scope (never only the target selectors), the
// exact broker session and epoch it was published under, and one buffered
// decision. decided is guarded by App.brokerMu; decision is delivered at most
// once through once.
type cliRunV2Pending struct {
	id       string
	scope    browserhost.CLIRunV2Scope
	session  *personal.Session
	decision chan bool
	once     sync.Once
	decided  bool

	// proofOK reports whether a real kernel terminal attestation and the
	// ordinary program image hash both succeeded before publication. Only then
	// may the explicit five-minute lease button exist. terminal and attested
	// are public evidence; no credential is retained here.
	proofOK       bool
	terminal      cliLeaseTerminal
	attested      browserhost.CLITerminalIdentity
	programSHA256 string
	leaseKey      cliLeaseKey

	// leaseIntent is captured under brokerMu in the same critical section as
	// the one-shot decision. It is read only after the decision is received, so
	// a later click can never promote an earlier approval to a lease.
	leaseIntent bool
}

func (p *cliRunV2Pending) choose(approved bool) {
	p.once.Do(func() { p.decision <- approved })
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
		// Only the one-shot v2 approval path is wired. Installing it is what
		// disables the legacy per-field v1 cli-run server path; the product no
		// longer exports a v1 handler at all.
		PrepareCLIRunV2: a.PrepareCLIRunV2,
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

// cancelPendingCLIRun refuses any owned v1 or v2 approval. It only ever clears
// the pending values it actually observed, so a callback that is already past
// approval can never publish a grant for a session that is gone.
func (a *App) cancelPendingCLIRun() {
	a.brokerMu.Lock()
	v1 := a.cliPending
	a.cliPending = nil
	v2 := a.cliV2Pending
	a.cliV2Pending = nil
	a.brokerMu.Unlock()
	// A lock or broker stop revokes every terminal lease before any pending
	// approval can be decided: the cache is never carried across a session.
	if a.cliLeases != nil {
		a.cliLeases.purge()
	}
	if v1 != nil {
		v1.choose(false)
	}
	if v2 != nil {
		v2.choose(false)
	}
}

func (a *App) notifyBrowserBrokerUnlocked() {
	a.brokerMu.Lock()
	oldSession, oldEpoch := a.brokerSession, a.brokerEpoch
	a.brokerSession, a.brokerEpoch = a.session, a.generation
	b, s, generation := a.broker, a.brokerSession, a.brokerEpoch
	changed := oldSession != a.brokerSession || oldEpoch != a.brokerEpoch
	a.brokerMu.Unlock()
	if changed && a.cliLeases != nil {
		a.cliLeases.purge()
	}
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
	if a.cliLeases != nil {
		a.cliLeases.purge()
	}
	if b != nil {
		b.NotifyLocked(generation)
	}
}

// handleCLIRun verifies the desktop vault, requests native approval, then
// extracts pinned targets in one authenticated view.
//
// It is deliberately not wired into the broker any more: the legacy per-field
// v1 cli-run protocol is disabled in the product by installing
// PrepareCLIRunV2, and this v1-only hook survives solely so the v1 approval
// tests can still exercise the historical path. It never touches v2 state.
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
	if p == nil || p.decided {
		a.brokerMu.Unlock()
		return
	}
	p.decided = true
	a.brokerMu.Unlock()
	p.choose(approved)
}

// PrepareCLIRunV2 is the only native cli-run v2 approval callback. It receives
// the fully reconstructed trusted scope, captures the kernel terminal and
// program proof once, and then either reuses one exact unexpired terminal lease
// with a brand-new session intent or publishes one cloned pending approval.
//
// It never reads the legacy cliApprover hook, never extracts per-field values
// and never returns a value map: the opaque result carries only the owning
// session, its one-use grant and the final proof callbacks.
func (a *App) PrepareCLIRunV2(ctx context.Context, scope browserhost.CLIRunV2Scope) (*browserhost.NativeCLIRunV2, error) {
	if ctx == nil || ctx.Err() != nil || !validCLIRunV2Scope(scope) {
		return nil, errCLIRunRefused
	}
	// Own every caller slice and map before anything can be published or
	// prepared, so the pending approval and the fresh intent can never change
	// under a later caller mutation.
	owned := cloneCLIRunV2Scope(scope)

	// Attestation and the ordinary program image hash are the only sources of a
	// lease identity. A refusal here is not a one-shot refusal: it only means no
	// lease identity exists, so the fresh native approval stays usable. This is
	// exactly the non-Linux / no-TTY behaviour.
	evidence, proofOK := captureCLILeaseEvidence(owned.Peer, owned.Request.Program)
	leases := a.cliLeases

	a.brokerMu.Lock()
	session, epoch := a.brokerSession, a.brokerEpoch
	a.brokerMu.Unlock()
	if session == nil || !session.Unlocked() || epoch != owned.Epoch || session.VaultPath() != owned.VaultPath {
		return nil, errCLIRunRefused
	}
	var leaseKey cliLeaseKey
	if proofOK {
		leaseKey, proofOK = cliLeaseKeyFor(owned, session, evidence.terminal, evidence.programSHA256)
	}

	// An exact, unexpired lease skips the dialog, but it never skips the fresh
	// prepare: every reuse commits a new item.run.bundle intent with the whole
	// request and every exact target.
	if proofOK && leases != nil {
		if deadline, ok := leases.match(leaseKey); ok {
			return a.prepareCLILeaseGrant(ctx, owned, session, epoch, evidence, leaseKey, deadline, leases)
		}
	}

	pending := &cliRunV2Pending{
		scope: owned, decision: make(chan bool, 1),
		proofOK: proofOK, terminal: evidence.terminal, attested: evidence.exact,
		programSHA256: evidence.programSHA256, leaseKey: leaseKey,
	}
	var id [16]byte
	if _, e := rand.Read(id[:]); e != nil {
		return nil, errCLIRunRefused
	}
	pending.id = hex.EncodeToString(id[:])

	a.brokerMu.Lock()
	session = a.brokerSession
	epoch = a.brokerEpoch
	if session == nil || !session.Unlocked() || epoch != pending.scope.Epoch || session.VaultPath() != pending.scope.VaultPath ||
		a.cliPending != nil || a.cliV2Pending != nil {
		a.brokerMu.Unlock()
		return nil, errCLIRunRefused
	}
	pending.session = session
	a.cliV2Pending = pending
	a.brokerMu.Unlock()
	a.dispatch(func() {
		if a.win != nil {
			a.win.Show()
			a.win.Focus()
			a.win.Invalidate()
		}
	})

	var approved bool
	select {
	case approved = <-pending.decision:
	case <-ctx.Done():
		a.releaseCLIRunV2(pending)
		return nil, errCLIRunRefused
	}

	// Re-pin the exact live session, vault path and epoch after the decision and
	// immediately before the session-owned intent may be prepared. A lock,
	// disconnect-driven cancellation or stale epoch refuses without any intent.
	a.brokerMu.Lock()
	ownedPending := a.cliV2Pending == pending
	if ownedPending {
		a.cliV2Pending = nil
	}
	// Read the captured lease intent under the same mutex that decided it; the
	// channel receive above provides the happens-before edge.
	leaseIntent := pending.leaseIntent
	current, currentEpoch := a.brokerSession, a.brokerEpoch
	a.brokerMu.Unlock()
	if !ownedPending || !approved {
		return nil, errCLIRunRefused
	}
	a.dispatch(func() {
		if a.win != nil {
			a.win.Invalidate()
		}
	})
	if current == nil || current != pending.session || !current.Unlocked() ||
		currentEpoch != pending.scope.Epoch || current.VaultPath() != pending.scope.VaultPath || ctx.Err() != nil {
		return nil, errCLIRunRefused
	}
	// A lease intent without real proof is impossible from the UI (the button
	// only exists with proof), but refuse defensively rather than fabricating a
	// weaker identity.
	if leaseIntent && (!pending.proofOK || leases == nil) {
		return nil, errCLIRunRefused
	}
	var deadline time.Time
	if leaseIntent {
		deadline = leases.nowTime().Add(cliLeaseTTL)
	}
	approval := &cliLeaseApproval{
		peer: pending.scope.Peer, lease: leaseIntent, dialog: true, exact: pending.attested,
		hasProof: pending.proofOK, program: pending.scope.Request.Program,
		programSHA256: pending.programSHA256, deadline: deadline, key: pending.leaseKey,
		cache: leases,
	}
	// Re-read the kernel proof after the owner decision and before disclosure.
	if err := approval.revalidate(); err != nil {
		return nil, errCLIRunRefused
	}
	if ctx.Err() != nil {
		return nil, errCLIRunRefused
	}
	// Re-pin once more after the proof read, immediately before the intent.
	a.brokerMu.Lock()
	again, againEpoch := a.brokerSession, a.brokerEpoch
	a.brokerMu.Unlock()
	if again != current || againEpoch != currentEpoch || !again.Unlocked() ||
		again.VaultPath() != pending.scope.VaultPath || ctx.Err() != nil {
		return nil, errCLIRunRefused
	}
	grant, e := current.PrepareRunBundleGrant(ctx, pending.scope.Targets, pending.scope.Request, pending.scope.Root)
	if e != nil || grant == nil {
		if grant != nil {
			grant.Discard()
		}
		return nil, errCLIRunRefused
	}
	if ctx.Err() != nil {
		grant.Discard()
		return nil, errCLIRunRefused
	}
	// Only a successfully prepared grant may create the lease. A replicate
	// approval never extends an existing absolute deadline.
	if leaseIntent {
		if err := leases.add(pending.leaseKey, deadline); err != nil {
			grant.Discard()
			return nil, errCLIRunRefused
		}
	}
	if err := approval.stillValid(); err != nil {
		grant.Discard()
		return nil, errCLIRunRefused
	}
	return &browserhost.NativeCLIRunV2{
		Session: current, Grant: grant,
		Revalidate: approval.revalidate, StillValid: approval.stillValid,
	}, nil
}

// prepareCLILeaseGrant prepares one fresh session intent for a matched terminal
// lease. It never shows a dialog, never reuses a prepared grant and never
// extends the lease deadline. Lock, ctx, epoch, revision, program and terminal
// changes all refuse instead of falling back to a weaker local check.
func (a *App) prepareCLILeaseGrant(ctx context.Context, scope browserhost.CLIRunV2Scope, session *personal.Session, epoch uint64, evidence cliLeaseEvidence, key cliLeaseKey, deadline time.Time, leases *cliLeaseCache) (*browserhost.NativeCLIRunV2, error) {
	approval := &cliLeaseApproval{
		peer: scope.Peer, lease: true, dialog: false, exact: evidence.exact, hasProof: true,
		program: scope.Request.Program, programSHA256: evidence.programSHA256,
		deadline: deadline, key: key, cache: leases,
	}
	// A new CLI process is expected here, so PeerStart may differ; the stable
	// terminal identity and the program image may not.
	if err := approval.revalidate(); err != nil {
		return nil, errCLIRunRefused
	}
	if ctx.Err() != nil {
		return nil, errCLIRunRefused
	}
	a.brokerMu.Lock()
	again, againEpoch := a.brokerSession, a.brokerEpoch
	a.brokerMu.Unlock()
	if again != session || againEpoch != epoch || !again.Unlocked() ||
		again.VaultPath() != scope.VaultPath || ctx.Err() != nil {
		return nil, errCLIRunRefused
	}
	grant, e := session.PrepareRunBundleGrant(ctx, scope.Targets, scope.Request, scope.Root)
	if e != nil || grant == nil {
		if grant != nil {
			grant.Discard()
		}
		return nil, errCLIRunRefused
	}
	if ctx.Err() != nil {
		grant.Discard()
		return nil, errCLIRunRefused
	}
	// Revocation and the absolute deadline are checked once more at the moment
	// the grant exists. The broker repeats the cheap check before its first
	// disclosure byte.
	if err := approval.stillValid(); err != nil {
		grant.Discard()
		return nil, errCLIRunRefused
	}
	return &browserhost.NativeCLIRunV2{
		Session: session, Grant: grant,
		Revalidate: approval.revalidate, StillValid: approval.stillValid,
	}, nil
}

// decideCLIRunV2 is the one-shot decision entry point used by the primary
// button. It never implies a lease.
func (a *App) decideCLIRunV2(id string, approved bool) {
	a.decideCLIRunV2Choice(id, approved, false)
}

// approveCLIRunV2Lease is the separate explicit five-minute decision entry
// point. The lease intent is captured in the same atomic decision as the
// approval; it is never a mutable flag a later click can set.
func (a *App) approveCLIRunV2Lease(id string) {
	a.decideCLIRunV2Choice(id, true, true)
}

// decideCLIRunV2Choice publishes exactly one immutable owner decision for the
// pending request whose id is still current. A late click for a replaced request
// is ignored, and no second click can promote or alter the first decision.
func (a *App) decideCLIRunV2Choice(id string, approved, lease bool) {
	a.brokerMu.Lock()
	p := a.cliV2Pending
	if p == nil || p.id != id || p.decided {
		a.brokerMu.Unlock()
		return
	}
	p.decided = true
	p.leaseIntent = approved && lease
	a.brokerMu.Unlock()
	p.choose(approved)
}

// releaseCLIRunV2 clears only the pending approval it owns. A newer pending is
// never touched.
func (a *App) releaseCLIRunV2(p *cliRunV2Pending) {
	a.brokerMu.Lock()
	owned := a.cliV2Pending == p
	if owned {
		a.cliV2Pending = nil
	}
	a.brokerMu.Unlock()
	if owned {
		a.dispatch(func() {
			if a.win != nil {
				a.win.Invalidate()
			}
		})
	}
}

// validCLIRunV2Scope is defence in depth over the broker's own wire validation.
// The trusted request must validate against the trusted policy, carry the same
// pinned spec id, and name absolute vault/root paths.
func validCLIRunV2Scope(scope browserhost.CLIRunV2Scope) bool {
	if scope.ProfileID == "" || scope.SpecID == "" || !cliV2CanonicalHex(scope.SpecDigest, 32) || !cliV2CanonicalHex(scope.ScopeDigest, 32) {
		return false
	}
	if !filepath.IsAbs(scope.VaultPath) || !filepath.IsAbs(scope.Root) {
		return false
	}
	if scope.Request.Validate(scope.Targets) != nil {
		return false
	}
	return scope.Request.Spec.ID == scope.SpecID && scope.Spec.ID == scope.SpecID
}

func cliV2CanonicalHex(value string, n int) bool {
	if len(value) != n*2 {
		return false
	}
	raw, e := hex.DecodeString(value)
	if e != nil || len(raw) != n {
		return false
	}
	defer clear(raw)
	return hex.EncodeToString(raw) == value
}

// cloneCLIRunV2Scope deep-copies every slice and map of the trusted scope,
// including the policy spec, so the pending approval owns its own memory.
func cloneCLIRunV2Scope(in browserhost.CLIRunV2Scope) browserhost.CLIRunV2Scope {
	out := in
	out.Request.Args = append([]string(nil), in.Request.Args...)
	out.Request.HelperPath = append([]string(nil), in.Request.HelperPath...)
	if in.Request.Passthrough != nil {
		out.Request.Passthrough = make(map[string]string, len(in.Request.Passthrough))
		for name, value := range in.Request.Passthrough {
			out.Request.Passthrough[name] = value
		}
	}
	out.Request.Spec = cliprofile.CloneSpec(in.Request.Spec)
	out.Spec = cliprofile.CloneSpec(in.Spec)
	out.Targets = append([]personal.BundleTarget(nil), in.Targets...)
	return out
}

// cliV2SummaryLines renders the complete cloned scope for the native approval
// view: peer identity, vault, root, profile name, pinned spec id and digest,
// the exact program, every argument, working directory and timeout, helper path
// entries, passthrough names and values, and every target slot with its item id,
// full revision and field. Every caller-controlled string is escaped; the scope
// holds no credential bytes, so nothing secret is rendered.
func cliV2SummaryLines(scope browserhost.CLIRunV2Scope) []string {
	lines := []string{
		"Vault: " + visible(scope.VaultPath),
		"Root: " + visible(scope.Root),
		"Profile: " + visible(scope.ProfileID) + " · Spec: " + visible(scope.SpecID),
		"SpecDigest: " + visible(scope.SpecDigest),
		"Epoch: " + uint64String(scope.Epoch),
		"Peer: " + visible(scope.Peer.User) + " · PID " + uintString(scope.Peer.PID),
		"Process: " + visible(scope.Peer.Process),
		"Program: " + visible(scope.Request.Program),
		"CWD: " + visible(scope.Request.Directory),
		"Timeout: " + intString(scope.Request.TimeoutSeconds) + "s",
		"TokenEnv: " + visible(scope.Request.TokenEnvName),
		"Args (" + intString(len(scope.Request.Args)) + "):",
	}
	for i, arg := range scope.Request.Args {
		lines = append(lines, "  ["+intString(i+1)+"] "+visible(arg))
	}
	lines = append(lines, "HelperPath ("+intString(len(scope.Request.HelperPath))+"):")
	for i, entry := range scope.Request.HelperPath {
		lines = append(lines, "  ["+intString(i+1)+"] "+visible(entry))
	}
	names := make([]string, 0, len(scope.Request.Passthrough))
	for name := range scope.Request.Passthrough {
		names = append(names, name)
	}
	sort.Strings(names)
	lines = append(lines, "Passthrough ("+intString(len(names))+"):")
	for _, name := range names {
		lines = append(lines, "  "+visible(name)+"="+visible(scope.Request.Passthrough[name]))
	}
	lines = append(lines, "Targets ("+intString(len(scope.Targets))+"):")
	for _, target := range scope.Targets {
		lines = append(lines, "  "+visible(target.Slot)+" ← "+visible(target.Field)+" · "+visible(target.ID)+" · "+visible(target.Revision))
	}
	return lines
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

// cliV2ApprovalView shows the full cloned v2 scope inside a bounded scroll area
// with the approve/refuse decision pinned below it, so the decision buttons stay
// visible however long the argument, helper-path, passthrough or target list is.
func (a *App) cliV2ApprovalView(c *ui.Context) {
	a.brokerMu.Lock()
	p := a.cliV2Pending
	a.brokerMu.Unlock()
	if p == nil {
		return
	}
	scope := p.scope
	lines := cliV2SummaryLines(scope)
	ui.Column(c).Fill().Gap(12).Children(func() {
		ui.Text(c, "批准本地 CLI 凭据请求").FontSize(26).Bold()
		ui.Text(c, "以下为本次请求的完整授权范围；每项内容都来自已认证的本机连接。").FontSize(12)
		ui.Scroll(c).Grow(1).FillHeight().Children(func() {
			ui.Column(c).Gap(4).Children(func() {
				for _, line := range lines {
					ui.Text(c, line).FontSize(12)
				}
			})
		})
		if p.proofOK {
			// Only public, kernel-derived metadata is rendered. The executable
			// path is escaped; the session numbers are plain public numbers.
			ui.Text(c, "终端/SID: TTY "+uint64String(p.terminal.TTYDevice)+" · SID "+uintString(p.terminal.SessionID)).FontSize(12)
			ui.Text(c, "CLI 可执行文件: "+visible(p.terminal.ExecutablePath)+" · SHA256 "+p.terminal.ExecutableSHA256).FontSize(12)
			ui.Text(c, "终端租约有效期: "+cliLeaseTTLLabel()+"，到期不会续期。").FontSize(12)
			ui.Text(c, "仅批准本次仍会新建一次性授权。终端租约只允许同一终端的相同命令在有效期内再次新建授权；每次都会提交新的一次性意图。").Bold()
		} else {
			ui.Text(c, "终端证明不可用：只能批准本次请求，绝不创建可复用租约。").Bold()
		}
		ui.Row(c).Gap(8).Children(func() {
			ui.PrimaryButton(c, cliV2ApproveLabel).OnClick(func() { a.decideCLIRunV2(p.id, true) })
			if p.proofOK {
				ui.Button(c, cliV2LeaseLabel).OnClick(func() { a.approveCLIRunV2Lease(p.id) })
			}
			ui.Button(c, cliV2RefuseLabel).OnClick(func() { a.decideCLIRunV2(p.id, false) })
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

func uint64String(v uint64) string {
	if v == 0 {
		return "0"
	}
	var b [20]byte
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
