package desktop

import (
	"path/filepath"

	"github.com/jihuayu/locklark/internal/personal"
)

// The explicit full-factor local-vault unlock dialog is controller state only
// in this checkpoint. It renders no UI. Opening it freezes one exact target and
// performs no unwrap, authentication or factor work; only an explicit submit
// starts the one pinned child producer.
const (
	localVaultFileUnlockStatusPrompt            = "请输入主密码与 Secret Key 进行完整验证"
	localVaultFileUnlockStatusBusy              = "正在完整验证本地文件库"
	localVaultFileUnlockStatusFailed            = "完整验证失败；请重新输入"
	localVaultFileUnlockStatusAlreadyOpen       = "本地文件库已打开"
	localVaultFileUnlockStatusUnavailable       = "无法打开本地文件库；请核查当前目标"
	localVaultFileUnlockStatusStale             = "完整验证已失效；请重新打开"
	localVaultFileUnlockStatusOpened            = "已完整验证本地文件库"
	localVaultFileUnlockStatusOpenedUnavailable = "已打开；本地视图暂不可用，请稍后核查"
)

// localVaultFileUnlockTarget is the frozen public target of one dialog. The
// scope supplies exact routing/scheduling identity, while label is display
// metadata only and is never consulted for identity, grant or authority.
type localVaultFileUnlockTarget struct {
	scope      localVaultFileSessionScope
	parent     *personal.Session
	generation uint64
	label      string
}

type localVaultFileUnlockState struct {
	open, busy bool
	status     string
	target     localVaultFileUnlockTarget
	// password and secret are the only dialog-owned factors and exist only
	// while the user is typing. Submit clears both strings immediately after
	// copying short-lived bytes for the one worker.
	password string
	secret   string
	// op is the exact reserved child operation owned by this dialog attempt.
	// It never stores a factor, decoded key, kit or identity.
	op       *localVaultFileSessionOperation
	sequence uint64
}

// localVaultFileUnlockTargetFor validates the frozen full target against the
// current parent and workspace without reading the manifest, unwrapping a
// child, authenticating factors or touching a wrapper. The navigation ref and
// its label are hints only; the exact scope is the controller identity.
func (a *App) localVaultFileUnlockTargetFor(ref localVaultFileRef, parent *personal.Session) (localVaultFileUnlockTarget, bool) {
	if parent == nil || a.session != parent || !parent.Unlocked() {
		return localVaultFileUnlockTarget{}, false
	}
	if ref.path == "" || ref.vaultID == "" || ref.journalPath == "" {
		return localVaultFileUnlockTarget{}, false
	}
	if !filepath.IsAbs(ref.path) || filepath.Clean(ref.path) != ref.path {
		return localVaultFileUnlockTarget{}, false
	}
	scope, ok := a.localVaultFileSessionScopeFor(ref)
	if !ok || scope.configPath == "" || scope.vaultID == "" ||
		scope.backendRoot == "" || scope.journalPath == "" {
		return localVaultFileUnlockTarget{}, false
	}
	profileDir, backendRoot := localVaultFilePaths(a.settingsPath, parent.VaultPath())
	if backendRoot != scope.backendRoot || filepath.Dir(ref.path) != profileDir {
		return localVaultFileUnlockTarget{}, false
	}
	return localVaultFileUnlockTarget{
		scope:      scope,
		parent:     parent,
		generation: a.generation,
		// Display metadata only: reuse the same whole-list snapshot the sidebar
		// and title consume. It never participates in identity or authority.
		label: a.localVaultFileDisplayLabelFor(ref),
	}, true
}

// openLocalVaultFileUnlock freezes an exact target and dialog sequence. It does
// not queue a factory, parse a factor or touch an already adopted child. It
// refuses unknown hints, targets outside the current workspace, inactive
// parents and an exact target that is already open.
func (a *App) openLocalVaultFileUnlock(ref localVaultFileRef) bool {
	a.cancelLocalVaultFileUnlock()
	state := &a.localVaultUnlock
	target, ok := a.localVaultFileUnlockTargetFor(ref, a.session)
	if !ok {
		state.open, state.busy, state.op = false, false, nil
		state.status = localVaultFileUnlockStatusUnavailable
		return false
	}
	state.sequence++
	state.password, state.secret = "", ""
	// An already adopted exact target is never closed or reopened merely to
	// show the unlock dialog. Leave its child and sibling wrappers intact.
	if slot := a.localVaultFiles.sessionSlots[target.scope]; slot != nil && slot.session != nil {
		state.open, state.busy, state.op = false, false, nil
		state.target = localVaultFileUnlockTarget{}
		state.status = localVaultFileUnlockStatusAlreadyOpen
		return false
	}
	state.open = true
	state.busy = false
	state.status = localVaultFileUnlockStatusPrompt
	state.target = target
	return true
}

// submitLocalVaultFileUnlock consumes only the dialog's explicit password and
// textual Secret Key. It never reads a.password, a.secret, the keychain, a
// cached global proof or a previous input. Both UI strings are cleared before
// validation, the bytes are handed to one worker, and only the exact C1
// operation is reserved on the UI path before that worker launches.
func (a *App) submitLocalVaultFileUnlock() {
	state := &a.localVaultUnlock
	if !state.open || state.busy || state.op != nil {
		return
	}
	password, secret := []byte(state.password), []byte(state.secret)
	state.password, state.secret = "", ""
	defer clear(password)
	defer clear(secret)
	if len(password) == 0 || len(secret) == 0 {
		state.status = localVaultFileUnlockStatusPrompt
		return
	}
	target := state.target
	if target.parent == nil || a.session != target.parent ||
		a.generation != target.generation || !target.parent.Unlocked() ||
		target.scope.configPath == "" || target.scope.vaultID == "" ||
		target.scope.backendRoot == "" || target.scope.journalPath == "" {
		a.dismissLocalVaultFileUnlock(state, localVaultFileUnlockStatusStale)
		return
	}
	profileDir, backendRoot := localVaultFilePaths(a.settingsPath, target.parent.VaultPath())
	if backendRoot != target.scope.backendRoot || filepath.Dir(target.scope.configPath) != profileDir {
		a.dismissLocalVaultFileUnlock(state, localVaultFileUnlockStatusStale)
		return
	}
	// A child may have been adopted while the dialog was open. Refuse rather
	// than replacing or closing that valid child with a factor attempt.
	if slot := a.localVaultFiles.sessionSlots[target.scope]; slot != nil && slot.session != nil {
		state.open, state.busy, state.op = false, false, nil
		state.target = localVaultFileUnlockTarget{}
		state.status = localVaultFileUnlockStatusAlreadyOpen
		return
	}
	op := a.reserveLocalVaultFileSessionOperation(target.scope)
	if op == nil {
		state.open, state.busy, state.op = false, false, nil
		state.target = localVaultFileUnlockTarget{}
		state.status = localVaultFileUnlockStatusUnavailable
		return
	}
	// The observer is installed before the worker launches. It captures no
	// factor or key material and is consumed exactly once on the UI path after
	// the operation records a finite outcome and releases its exact binding.
	sequence := state.sequence
	op.setCompletionObserver(func(outcome localVaultFileSessionOutcome) {
		a.finishLocalVaultFileUnlock(sequence, target, op, outcome)
	})
	state.busy = true
	state.op = op
	state.status = localVaultFileUnlockStatusBusy
	a.launchLocalVaultFileSessionUnlockOperation(op, password, secret)
}

// cancelLocalVaultFileUnlock clears every dialog-owned input and cancels only
// the exact captured child operation. Existing real pending-handoff cleanup and
// settlement run independently of any held dispatch. An already adopted child
// and unrelated siblings are never closed here, and no cancellation ACK is
// treated as proof that every physical Close has finished.
func (a *App) cancelLocalVaultFileUnlock() {
	state := &a.localVaultUnlock
	op := state.op
	state.sequence++
	state.open, state.busy, state.op = false, false, nil
	state.password, state.secret = "", ""
	state.status = ""
	state.target = localVaultFileUnlockTarget{}
	if op != nil {
		a.cancelLocalVaultFileSessionOperationExact(op)
	}
}

// dismissLocalVaultFileUnlock retires only the exact old dialog state. A newer
// open attempt has already advanced sequence, so its state is preserved.
func (a *App) dismissLocalVaultFileUnlock(state *localVaultFileUnlockState, status string) {
	state.sequence++
	state.open, state.busy, state.op = false, false, nil
	state.password, state.secret = "", ""
	state.target = localVaultFileUnlockTarget{}
	state.status = status
}

// finishLocalVaultFileUnlock is the one UI completion observer body. It runs
// only after the operation has a finite outcome and has released its exact slot
// binding, not merely after settlement. A stale parent, App generation,
// workspace, operation or dialog sequence can neither clear a newer dialog nor
// adopt a foreign child.
func (a *App) finishLocalVaultFileUnlock(sequence uint64, target localVaultFileUnlockTarget, op *localVaultFileSessionOperation, outcome localVaultFileSessionOutcome) {
	state := &a.localVaultUnlock
	if state.sequence != sequence || state.op != op ||
		state.target.scope != target.scope || state.target.parent != target.parent ||
		state.target.generation != target.generation {
		return
	}
	state.busy = false
	state.op = nil
	if a.session != target.parent || a.generation != target.generation || !target.parent.Unlocked() {
		a.dismissLocalVaultFileUnlock(state, localVaultFileUnlockStatusStale)
		return
	}
	profileDir, backendRoot := localVaultFilePaths(a.settingsPath, target.parent.VaultPath())
	if backendRoot != target.scope.backendRoot || filepath.Dir(target.scope.configPath) != profileDir {
		a.dismissLocalVaultFileUnlock(state, localVaultFileUnlockStatusStale)
		return
	}
	switch outcome {
	case localVaultFileSessionOutcomeOpened:
		// Success closes the dialog and retains the real adopted child. The
		// projection is delivered only through the existing C1 cache getter
		// and exact-operation presentation, and only while the exact target is
		// still the current selected view. The legacy global opener is never
		// used.
		presented := false
		if a.localVaultFiles.selected == target.scope.configPath {
			presented = a.presentAdoptedLocalVaultFileSession(op)
		}
		state.sequence++
		state.open, state.busy, state.op = false, false, nil
		state.password, state.secret = "", ""
		state.target = localVaultFileUnlockTarget{}
		if presented {
			state.status = localVaultFileUnlockStatusOpened
		} else {
			state.status = localVaultFileUnlockStatusOpenedUnavailable
		}
	case localVaultFileSessionOutcomeCancelled:
		a.dismissLocalVaultFileUnlock(state, localVaultFileUnlockStatusStale)
	default:
		// Wrong or malformed factors are a finite failure. The dialog stays
		// open in manual-retry state with empty fields and no busy flag.
		state.open = true
		state.status = localVaultFileUnlockStatusFailed
		state.password, state.secret = "", ""
	}
}
