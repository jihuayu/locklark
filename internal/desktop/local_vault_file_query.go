package desktop

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/vaultfileclient"
	oneui "github.com/oneo-me/onevra/source/components"
)

const (
	localVaultFileQueryPrompt           = "输入完整标题，精确查询当前已打开的独立文件库。"
	localVaultFileQueryWorking          = "正在精确查询当前已打开的独立文件库…"
	localVaultFileQueryEmpty            = "没有匹配的本地文件库条目。"
	localVaultFileQueryFailed           = "精确查询未完成；请核查独立的本地文件库状态。"
	localVaultFileQueryActivationFailed = "激活未完成；请重新查询本地文件库。"
	localVaultFileQueryActivated        = "已激活本地文件库条目。"
	localVaultFileQueryStale            = "精确查询结果已失效；请重新查询本地文件库。"
	localVaultFileQueryPartialSuffix    = " · 部分独立的本地文件库暂不可用"
	localVaultFileQueryHitsLimit        = 2
	// localVaultFileQueryRevalidationMinStart is the named minimum start
	// interval for one active query generation's background rechecks.
	localVaultFileQueryRevalidationMinStart = 5 * time.Second
)

// localVaultFileActiveItem is display-only controller state. It records which
// item the normal exact-query activation path selected after the exact wrapper
// accepted the immutable query proof. It is never proof, identity or authority.
type localVaultFileActiveItem struct {
	scope      localVaultFileSessionScope
	parent     *personal.Session
	generation uint64
	id, title  string
}

// localVaultFileQueryHit is one immutable hit from a real per-wrapper
// QueryExactTitle result. The activation path passes result.proof and this
// exact ID/title back to result.wrapper.ValidateExactQueryHit.
type localVaultFileQueryHit struct {
	result          *localVaultFileQueryResult
	queryOperation  *localVaultFileQueryOperation
	queryGeneration uint64
	id              string
	title           string
}

// localVaultFileQueryResult binds one real exact-query proof to the frozen
// slot, wrapper, account, parent path, generation and sequence that produced
// it. The proof is never reconstructed from display data.
type localVaultFileQueryResult struct {
	scope           localVaultFileSessionScope
	parent          *personal.Session
	parentPath      string
	generation      uint64
	slot            *localVaultFileSessionSlot
	slotSequence    uint64
	wrapper         *vaultfileclient.LocalGenesisSession
	queryOperation  *localVaultFileQueryOperation
	queryGeneration uint64
	proof           vaultfileclient.LocalGenesisExactQueryResult
	hits            []*localVaultFileQueryHit
}

// localVaultFileQuerySource is the worker's immutable input snapshot for one
// current live ready slot. Only the launched worker writes proof/failed/detach;
// UI state is never published before dispatch.
type localVaultFileQuerySource struct {
	scope        localVaultFileSessionScope
	slot         *localVaultFileSessionSlot
	slotSequence uint64
	wrapper      *vaultfileclient.LocalGenesisSession
	proof        vaultfileclient.LocalGenesisExactQueryResult
	failed       bool
	detach       bool
}

// localVaultFileQueryOperation is one exact-title query over the bound
// account's current live ready owned slots. Its staged result is handed to the
// UI at most once; replacement/cancellation makes a late stage a no-op.
type localVaultFileQueryOperation struct {
	parent          *personal.Session
	parentPath      string
	generation      uint64
	queryGeneration uint64
	title           string
	sources         []localVaultFileQuerySource
	// nextSweep is the UI-only minimum start time for this query generation's
	// next background recheck. A fresh operation starts at zero, so its first
	// sweep is immediately eligible; old operations never gate a replacement.
	nextSweep time.Time

	mu       sync.Mutex
	terminal bool
	ready    bool
	staged   []localVaultFileQuerySource
}

func (op *localVaultFileQueryOperation) stage(results []localVaultFileQuerySource) bool {
	if op == nil {
		return false
	}
	op.mu.Lock()
	defer op.mu.Unlock()
	if op.terminal || op.ready {
		return false
	}
	op.staged = results
	op.ready = true
	return true
}

func (op *localVaultFileQueryOperation) take() ([]localVaultFileQuerySource, bool) {
	if op == nil {
		return nil, false
	}
	op.mu.Lock()
	defer op.mu.Unlock()
	if !op.ready || op.terminal {
		return nil, false
	}
	results := op.staged
	op.staged = nil
	op.ready = false
	op.terminal = true
	return results, true
}

// cancel makes the operation terminal. It returns any staged result so the UI
// path can clear the immutable proof copies without touching any wrapper.
func (op *localVaultFileQueryOperation) cancel() ([]localVaultFileQuerySource, bool) {
	if op == nil {
		return nil, false
	}
	op.mu.Lock()
	defer op.mu.Unlock()
	if op.terminal {
		return nil, false
	}
	op.terminal = true
	if !op.ready {
		return nil, false
	}
	results := op.staged
	op.staged = nil
	op.ready = false
	return results, true
}

func (op *localVaultFileQueryOperation) terminalState() bool {
	if op == nil {
		return true
	}
	op.mu.Lock()
	defer op.mu.Unlock()
	return op.terminal
}

// localVaultFileQueryActivation freezes the exact hit and lifecycle that were
// current when the user asked to activate it. ValidateExactQueryHit runs on the
// captured wrapper before this operation may select any destination.
type localVaultFileQueryActivation struct {
	queryGeneration uint64
	queryOperation  *localVaultFileQueryOperation
	hit             *localVaultFileQueryHit
	result          *localVaultFileQueryResult
	id, title       string
}

// localVaultFileQueryPendingActivation is one already-authorized UI click held
// behind its exact current sweep. It never carries proof, a wrapper or a
// capability; it only freezes the same immutable hit and generation so the
// normal activation path can recheck Active routing after the sweep settles.
type localVaultFileQueryPendingActivation struct {
	sweep           *localVaultFileQuerySweep
	queryGeneration uint64
	queryOperation  *localVaultFileQueryOperation
	hit             *localVaultFileQueryHit
	result          *localVaultFileQueryResult
}

// localVaultFileQuerySweep is one lifecycle-bound per-query background
// revalidation. It borrows the exact wrappers of the current results only for
// the duration of the worker and never owns, closes, replaces or reactivates a
// wrapper. At most one sweep may be in flight for the current query.
type localVaultFileQuerySweep struct {
	queryOperation  *localVaultFileQueryOperation
	queryGeneration uint64
	parent          *personal.Session
	generation      uint64
	parentPath      string
	results         []*localVaultFileQueryResult

	mu       sync.Mutex
	terminal bool
}

func (sweep *localVaultFileQuerySweep) stop() {
	if sweep == nil {
		return
	}
	sweep.mu.Lock()
	sweep.terminal = true
	sweep.mu.Unlock()
}

func (sweep *localVaultFileQuerySweep) stopped() bool {
	if sweep == nil {
		return true
	}
	sweep.mu.Lock()
	defer sweep.mu.Unlock()
	return sweep.terminal
}

type localVaultFileQueryState struct {
	title      string
	status     string
	sequence   uint64
	operation  *localVaultFileQueryOperation
	current    *localVaultFileQueryOperation
	results    []*localVaultFileQueryResult
	activation *localVaultFileQueryActivation
	// pendingActivation is the single exact click serialized behind its own
	// current sweep. It is cleared on query/cancel/lock/replacement boundaries.
	pendingActivation *localVaultFileQueryPendingActivation
	sweep             *localVaultFileQuerySweep
}

func clearLocalVaultFileExactResult(result *vaultfileclient.LocalGenesisExactQueryResult) {
	if result == nil {
		return
	}
	for index := range result.Hits {
		result.Hits[index] = personal.VaultFileBaselineItem{}
	}
	*result = vaultfileclient.LocalGenesisExactQueryResult{}
}

func clearLocalVaultFileQuerySources(sources []localVaultFileQuerySource) {
	for index := range sources {
		clearLocalVaultFileExactResult(&sources[index].proof)
	}
}

// localVaultFileQueryChanged is the text-edit boundary. It replaces any
// in-flight query and drops the old result set without touching a wrapper.
func (a *App) localVaultFileQueryChanged() {
	state := &a.localVaultFiles
	a.cancelLocalVaultFileQueryExact(state.query.operation)
	a.cancelLocalVaultFileQuerySweep(state.query.sweep)
	state.query.sequence++
	state.query.operation = nil
	state.query.current = nil
	state.query.results = nil
	state.query.activation = nil
	state.query.pendingActivation = nil
	state.query.status = localVaultFileQueryPrompt
}

// cancelLocalVaultFileQuery is the navigation, close-view, lock and
// parent/generation boundary. It cancels only delivery; wrappers remain owned by
// their slots.
func (a *App) cancelLocalVaultFileQuery() {
	state := &a.localVaultFiles
	a.cancelLocalVaultFileQueryExact(state.query.operation)
	a.cancelLocalVaultFileQuerySweep(state.query.sweep)
	state.query.sequence++
	state.query.operation = nil
	state.query.current = nil
	state.query.results = nil
	state.query.activation = nil
	state.query.pendingActivation = nil
	state.query.status = ""
	state.query.title = ""
}

func (a *App) cancelLocalVaultFileQueryExact(op *localVaultFileQueryOperation) {
	if op == nil {
		return
	}
	if results, pending := op.cancel(); pending {
		clearLocalVaultFileQuerySources(results)
	}
}

func (a *App) cancelLocalVaultFileQuerySweep(sweep *localVaultFileQuerySweep) {
	if sweep == nil {
		return
	}
	sweep.stop()
	if a.localVaultFiles.query.sweep == sweep {
		a.localVaultFiles.query.sweep = nil
	}
	a.cancelLocalVaultFileQueryPendingActivationForSweep(sweep)
}

func (a *App) cancelLocalVaultFileQueryPendingActivationForSweep(sweep *localVaultFileQuerySweep) {
	state := &a.localVaultFiles
	if state.query.pendingActivation != nil &&
		state.query.pendingActivation.sweep == sweep {
		state.query.pendingActivation = nil
	}
}

// settleLocalVaultFileQueryPendingActivation ends the one click held behind a
// sweep that could not observe Active routing at its completion boundary. Busy
// is a terminal checkpoint for this exact pending click, not a new state: clear
// only that click and publish the same finite activation/requery feedback the
// normal refusal path uses. A replacement query, cancel, lock or parent/App
// generation change never receives this status. The authorized results and
// live sibling proofs are left untouched, so a later explicit click after the
// parent cache returns Active runs the normal authenticated activation once.
func (a *App) settleLocalVaultFileQueryPendingActivation(sweep *localVaultFileQuerySweep, cache personal.VaultFileCacheState) {
	state := &a.localVaultFiles
	pending := state.query.pendingActivation
	if pending == nil || pending.sweep != sweep {
		return
	}
	state.query.pendingActivation = nil
	if cache != personal.VaultFileCacheBusy {
		return
	}
	if state.query.operation != nil || state.query.current != sweep.queryOperation ||
		state.query.sequence != sweep.queryGeneration ||
		pending.queryOperation != sweep.queryOperation ||
		pending.queryGeneration != sweep.queryGeneration ||
		a.session != sweep.parent || a.generation != sweep.generation {
		return
	}
	state.query.status = localVaultFileQueryActivationFailed
}

// searchLocalVaultFileExactTitle is the normal local-vault query action. It
// validates only the tight selector bound, captures the current live ready
// slots on the UI path, and launches the real per-wrapper query work.
func (a *App) searchLocalVaultFileExactTitle() {
	state := &a.localVaultFiles
	if a.session == nil || !a.session.Unlocked() {
		return
	}
	title := state.query.title
	if title == "" || len([]byte(title)) > vaultfileclient.LocalGenesisExactQueryTitleBytesMax {
		a.cancelLocalVaultFileQueryExact(state.query.operation)
		a.cancelLocalVaultFileQuerySweep(state.query.sweep)
		state.query.sequence++
		state.query.operation = nil
		state.query.current = nil
		state.query.results = nil
		state.query.activation = nil
		state.query.pendingActivation = nil
		state.query.status = fmt.Sprintf("请输入非空且不超过 %d 字节的完整标题。", vaultfileclient.LocalGenesisExactQueryTitleBytesMax)
		return
	}
	op := a.beginLocalVaultFileExactQuery(title)
	if op == nil {
		if state.query.status == "" {
			state.query.status = localVaultFileQueryFailed
		}
		return
	}
	a.launchLocalVaultFileQuery(op)
}

func (a *App) beginLocalVaultFileExactQuery(title string) *localVaultFileQueryOperation {
	parentPath, cache := a.localVaultFileRoutingPath()
	if cache != personal.VaultFileCacheActive || parentPath == "" || a.session == nil {
		return nil
	}
	state := &a.localVaultFiles
	sources := a.localVaultFileQuerySources(parentPath)
	a.cancelLocalVaultFileQueryExact(state.query.operation)
	a.cancelLocalVaultFileQuerySweep(state.query.sweep)
	state.query.sequence++
	state.query.operation = nil
	state.query.current = nil
	state.query.results = nil
	state.query.activation = nil
	state.query.pendingActivation = nil
	state.query.status = localVaultFileQueryWorking
	if len(sources) == 0 {
		state.query.status = "当前没有已打开且可查询的独立文件库。"
		return nil
	}
	op := &localVaultFileQueryOperation{
		parent: a.session, parentPath: parentPath, generation: a.generation,
		queryGeneration: state.query.sequence, title: title, sources: sources,
	}
	state.query.operation = op
	return op
}

// localVaultFileQuerySources captures only current live ready owned slots of
// the bound account. Unknown, retiring, non-active or mismatched scopes are not
// queried at all.
func (a *App) localVaultFileQuerySources(parentPath string) []localVaultFileQuerySource {
	state := &a.localVaultFiles
	sources := make([]localVaultFileQuerySource, 0, len(state.sessionSlots))
	for scope, slot := range state.sessionSlots {
		if !a.localVaultFileQuerySlotCurrent(parentPath, scope, slot) {
			continue
		}
		sources = append(sources, localVaultFileQuerySource{
			scope: scope, slot: slot, slotSequence: slot.sequence, wrapper: slot.session,
		})
	}
	sort.Slice(sources, func(i, j int) bool {
		if sources[i].scope.configPath != sources[j].scope.configPath {
			return sources[i].scope.configPath < sources[j].scope.configPath
		}
		return sources[i].scope.journalPath < sources[j].scope.journalPath
	})
	return sources
}

func (a *App) localVaultFileQuerySlotCurrent(parentPath string, scope localVaultFileSessionScope, slot *localVaultFileSessionSlot) bool {
	if slot == nil || slot.session == nil {
		return false
	}
	return a.localVaultFileQueryBindingCurrent(parentPath, a.session, a.generation,
		scope, slot, slot.sequence, slot.session)
}

// localVaultFileQueryBindingCurrent is the one lifecycle gate for a query
// result. It requires the exact parent/App generation, active routing path,
// current map slot pointer/sequence/wrapper, nonretiring live summary and the
// exact current ref tuple.
func (a *App) localVaultFileQueryBindingCurrent(parentPath string, parent *personal.Session,
	generation uint64, scope localVaultFileSessionScope, slot *localVaultFileSessionSlot,
	slotSequence uint64, wrapper *vaultfileclient.LocalGenesisSession) bool {
	if a.session == nil || parent == nil || slot == nil || wrapper == nil ||
		a.session != parent || a.generation != generation ||
		scope.configPath == "" || scope.vaultID == "" ||
		scope.backendRoot == "" || scope.journalPath == "" {
		return false
	}
	state := &a.localVaultFiles
	current := state.sessionSlots[scope]
	if current != slot || slot.scope != scope || slot.parent != parent ||
		slot.appGeneration != generation || slot.sequence != slotSequence ||
		slot.session != wrapper || slot.retiring ||
		slot.summary.VaultID == "" || slot.summary.VaultID != scope.vaultID {
		return false
	}
	_, currentRoot := localVaultFilePaths(a.settingsPath, parentPath)
	if currentRoot != scope.backendRoot || state.refsBackendRoot != scope.backendRoot {
		return false
	}
	ref, ok := localVaultFileRefByPath(state.refs, scope.configPath)
	return ok && ref.vaultID == scope.vaultID && ref.journalPath == scope.journalPath
}

func (a *App) localVaultFileQueryResultCurrent(result *localVaultFileQueryResult) bool {
	if result == nil || result.parent == nil || result.slot == nil || result.wrapper == nil {
		return false
	}
	parentPath, cache := a.localVaultFileRoutingPath()
	if cache != personal.VaultFileCacheActive || parentPath == "" ||
		parentPath != result.parentPath {
		return false
	}
	return a.localVaultFileQueryResultLifecycleCurrent(parentPath, result)
}

// localVaultFileQueryResultLifecycleCurrent checks the exact session/slot/ref
// binding using a routing path already verified by the caller. It does not take
// a new cache snapshot, so a transient Busy observation cannot be mistaken for
// a replacement or stale wrapper.
func (a *App) localVaultFileQueryResultLifecycleCurrent(parentPath string, result *localVaultFileQueryResult) bool {
	if result == nil || result.parent == nil || result.slot == nil || result.wrapper == nil {
		return false
	}
	return a.localVaultFileQueryBindingCurrent(parentPath, result.parent, result.generation,
		result.scope, result.slot, result.slotSequence, result.wrapper)
}

// localVaultFileQueryResultAuthorized requires exact membership in the one
// completed query result set that is still current. A result retained by a
// caller after query edit, replacement or cancellation is never authorized.
func (a *App) localVaultFileQueryResultAuthorized(result *localVaultFileQueryResult) bool {
	state := &a.localVaultFiles
	if result == nil || state.query.operation != nil || state.query.current == nil ||
		result.queryOperation != state.query.current ||
		result.queryGeneration != state.query.sequence {
		return false
	}
	for _, current := range state.query.results {
		if current == result {
			return true
		}
	}
	return false
}

// localVaultFileQueryHitAuthorized additionally requires the exact displayed
// hit entry and its immutable originating query identity.
func (a *App) localVaultFileQueryHitAuthorized(hit *localVaultFileQueryHit) bool {
	if hit == nil || hit.result == nil ||
		hit.queryOperation != hit.result.queryOperation ||
		hit.queryGeneration != hit.result.queryGeneration ||
		!a.localVaultFileQueryResultAuthorized(hit.result) {
		return false
	}
	for _, current := range hit.result.hits {
		if current == hit {
			return true
		}
	}
	return false
}

// launchLocalVaultFileQuery captures the dispatch boundary on the UI path. The
// worker performs only real QueryExactTitle reads and stages immutable proof
// copies; it never reads or mutates App UI state.
func (a *App) launchLocalVaultFileQuery(op *localVaultFileQueryOperation) {
	if op == nil {
		return
	}
	dispatch := a.dispatch
	a.launch(func() {
		results := make([]localVaultFileQuerySource, len(op.sources))
		for index := range op.sources {
			if op.terminalState() {
				clearLocalVaultFileQuerySources(results)
				return
			}
			source := op.sources[index]
			proof, err := source.wrapper.QueryExactTitle(vaultfileclient.LocalGenesisExactQuery{
				Title: op.title, Limit: localVaultFileQueryHitsLimit,
			})
			if err != nil {
				source.failed = true
				source.detach = !errors.Is(err, vaultfileclient.ErrLocalGenesisExactQueryBound)
				clearLocalVaultFileExactResult(&proof)
				results[index] = source
				continue
			}
			if proof.ConfigPath != source.scope.configPath ||
				proof.WorkspaceRoot != source.scope.backendRoot ||
				proof.VaultID != source.scope.vaultID ||
				proof.JournalPath != source.scope.journalPath ||
				proof.ManifestSHA256 == "" || proof.JournalRevision == "" {
				source.failed = true
				source.detach = true
				clearLocalVaultFileExactResult(&proof)
				results[index] = source
				continue
			}
			source.proof = proof
			results[index] = source
		}
		if !op.stage(results) {
			clearLocalVaultFileQuerySources(results)
			return
		}
		if dispatch != nil {
			dispatch(func() { a.takeAndCompleteLocalVaultFileQuery(op) })
		}
	})
}

func (a *App) takeAndCompleteLocalVaultFileQuery(op *localVaultFileQueryOperation) bool {
	results, ok := op.take()
	if !ok {
		return false
	}
	a.completeLocalVaultFileQuery(op, results)
	return true
}

// completeLocalVaultFileQuery accepts only sources whose exact lifecycle is
// still current. A failed source is detached only when its exact wrapper is
// still the current one and the failure was not a pure bound rejection; valid
// siblings are always preserved.
func (a *App) completeLocalVaultFileQuery(op *localVaultFileQueryOperation, sources []localVaultFileQuerySource) {
	state := &a.localVaultFiles
	if op == nil || state.query.operation != op {
		clearLocalVaultFileQuerySources(sources)
		return
	}
	state.query.operation = nil
	state.query.current = nil
	if cache := a.syncLocalVaultFileSessions(); cache != personal.VaultFileCacheActive ||
		a.session != op.parent || a.generation != op.generation {
		clearLocalVaultFileQuerySources(sources)
		state.query.results = nil
		state.query.status = localVaultFileQueryFailed
		return
	}
	parentPath, cache := a.localVaultFileRoutingPath()
	if cache != personal.VaultFileCacheActive || parentPath == "" || parentPath != op.parentPath {
		clearLocalVaultFileQuerySources(sources)
		state.query.results = nil
		state.query.status = localVaultFileQueryFailed
		return
	}

	results := make([]*localVaultFileQueryResult, 0, len(sources))
	partial := false
	for index := range sources {
		source := sources[index]
		if !a.localVaultFileQueryBindingCurrent(parentPath, op.parent, op.generation,
			source.scope, source.slot, source.slotSequence, source.wrapper) {
			partial = true
			clearLocalVaultFileExactResult(&source.proof)
			continue
		}
		if source.failed {
			partial = true
			if source.detach {
				a.detachLocalVaultFileSessionWrapper(source.slot)
			}
			clearLocalVaultFileExactResult(&source.proof)
			continue
		}
		result := &localVaultFileQueryResult{
			scope: source.scope, parent: op.parent, parentPath: op.parentPath,
			generation: op.generation, slot: source.slot,
			slotSequence: source.slotSequence, wrapper: source.wrapper,
			queryOperation: op, queryGeneration: op.queryGeneration,
			proof: source.proof,
		}
		for _, item := range source.proof.Hits {
			if item.ID == "" || item.Title != op.title {
				continue
			}
			result.hits = append(result.hits, &localVaultFileQueryHit{
				result: result, queryOperation: op, queryGeneration: op.queryGeneration,
				id: item.ID, title: item.Title,
			})
		}
		if len(result.hits) == 0 {
			clearLocalVaultFileExactResult(&result.proof)
			continue
		}
		results = append(results, result)
	}
	state.query.current = op
	state.query.results = results
	count := 0
	for _, result := range results {
		count += len(result.hits)
	}
	switch {
	case count == 0 && partial:
		state.query.status = localVaultFileQueryFailed
	case count == 0:
		state.query.status = localVaultFileQueryEmpty
	case partial:
		state.query.status = fmt.Sprintf("精确查询找到 %d 条%s", count, localVaultFileQueryPartialSuffix)
	default:
		state.query.status = fmt.Sprintf("精确查询找到 %d 条。", count)
	}
	if a.win != nil {
		a.win.Invalidate()
	}
}

// scheduleLocalVaultFileQueryRevalidation is the shared View/ticker entry. It
// uses the observation time supplied by the caller when available.
func (a *App) scheduleLocalVaultFileQueryRevalidation() *localVaultFileQuerySweep {
	return a.scheduleLocalVaultFileQueryRevalidationAt(time.Now())
}

// scheduleLocalVaultFileQueryRevalidationAt starts at most one background sweep
// for the current completed query. It reuses the app's existing launch/dispatch
// boundary and returns nil when a sweep is already in flight, the generation's
// minimum start interval has not elapsed, or no current result remains.
func (a *App) scheduleLocalVaultFileQueryRevalidationAt(now time.Time) *localVaultFileQuerySweep {
	state := &a.localVaultFiles
	if state.query.operation != nil || state.query.current == nil ||
		state.query.sweep != nil || state.query.activation != nil ||
		state.query.pendingActivation != nil ||
		a.session == nil || !a.session.Unlocked() || a.dispatch == nil {
		return nil
	}
	parentPath, cache := a.localVaultFileRoutingPath()
	if cache != personal.VaultFileCacheActive || parentPath == "" {
		return nil
	}
	current := state.query.current
	if current == nil || state.query.operation != nil {
		return nil
	}
	if !current.nextSweep.IsZero() && now.Before(current.nextSweep) {
		return nil
	}
	results := make([]*localVaultFileQueryResult, 0, len(state.query.results))
	for _, result := range state.query.results {
		if !a.localVaultFileQueryResultAuthorized(result) ||
			!a.localVaultFileQueryResultCurrent(result) {
			continue
		}
		results = append(results, result)
	}
	if len(results) == 0 || state.query.current != current || state.query.operation != nil ||
		state.query.activation != nil || state.query.pendingActivation != nil {
		return nil
	}
	// Reserve and advance this generation only when a sweep actually starts.
	current.nextSweep = now.Add(localVaultFileQueryRevalidationMinStart)
	sweep := &localVaultFileQuerySweep{
		queryOperation: current, queryGeneration: state.query.sequence,
		parent: a.session, generation: a.generation, parentPath: parentPath,
		results: results,
	}
	state.query.sweep = sweep
	a.launchLocalVaultFileQueryRevalidation(sweep)
	return sweep
}

// launchLocalVaultFileQueryRevalidation uses only the normal non-consuming
// Summary revalidation of the exact borrowed wrapper. The worker never owns a
// wrapper and stages no projection; it reports only which exact result pointers
// failed the current backend/locator read.
func (a *App) launchLocalVaultFileQueryRevalidation(sweep *localVaultFileQuerySweep) {
	if sweep == nil || len(sweep.results) == 0 {
		return
	}
	dispatch := a.dispatch
	a.launch(func() {
		stale := make([]*localVaultFileQueryResult, 0, len(sweep.results))
		for _, result := range sweep.results {
			if sweep.stopped() {
				return
			}
			summary, err := result.wrapper.Summary()
			fresh := err == nil && summary.VaultID == result.scope.vaultID
			clearLocalVaultFileSessionSummary(&summary)
			if !fresh {
				stale = append(stale, result)
			}
		}
		if sweep.stopped() {
			return
		}
		if dispatch != nil {
			dispatch(func() { a.finishLocalVaultFileQueryRevalidation(sweep, stale) })
		}
	})
}

// finishLocalVaultFileQueryRevalidation applies only the exact results of the
// sweep's originating query generation. A late older sweep is a no-op for a
// replacement query. A failed current scope is detached and removed; current
// siblings and their original proofs are untouched.
func (a *App) finishLocalVaultFileQueryRevalidation(sweep *localVaultFileQuerySweep, stale []*localVaultFileQueryResult) {
	state := &a.localVaultFiles
	if sweep == nil || state.query.sweep != sweep {
		a.cancelLocalVaultFileQueryPendingActivationForSweep(sweep)
		return
	}
	if state.query.operation != nil || state.query.current != sweep.queryOperation ||
		state.query.sequence != sweep.queryGeneration || a.session != sweep.parent ||
		a.generation != sweep.generation {
		state.query.sweep = nil
		a.cancelLocalVaultFileQueryPendingActivationForSweep(sweep)
		return
	}
	if cache := a.syncLocalVaultFileSessions(); cache != personal.VaultFileCacheActive ||
		a.session != sweep.parent || a.generation != sweep.generation {
		if state.query.sweep == sweep {
			state.query.sweep = nil
		}
		a.settleLocalVaultFileQueryPendingActivation(sweep, cache)
		return
	}
	parentPath, cache := a.localVaultFileRoutingPath()
	if cache != personal.VaultFileCacheActive || parentPath == "" ||
		parentPath != sweep.parentPath ||
		state.query.sweep != sweep || state.query.operation != nil ||
		state.query.current != sweep.queryOperation ||
		state.query.sequence != sweep.queryGeneration {
		if state.query.sweep == sweep {
			state.query.sweep = nil
		}
		a.settleLocalVaultFileQueryPendingActivation(sweep, cache)
		return
	}

	// Detach the one queued click from the sweep before applying results. It is
	// resumed only after the sweep's exact stale drops and the fresh Active
	// routing check, and only for its original immutable hit.
	pending := state.query.pendingActivation
	if pending != nil && pending.sweep == sweep {
		state.query.pendingActivation = nil
	} else {
		pending = nil
	}
	staleSet := make(map[*localVaultFileQueryResult]struct{}, len(stale))
	for _, result := range stale {
		staleSet[result] = struct{}{}
	}
	changed := false
	for _, result := range sweep.results {
		if !a.localVaultFileQueryResultAuthorized(result) {
			continue
		}
		_, failed := staleSet[result]
		current := a.localVaultFileQueryResultLifecycleCurrent(parentPath, result)
		if !failed && current {
			continue
		}
		if failed && current {
			a.detachLocalVaultFileSessionWrapper(result.slot)
		}
		a.dropLocalVaultFileQueryResult(result)
		changed = true
	}
	state.query.sweep = nil
	if changed {
		if state.query.operation != nil || state.query.current != sweep.queryOperation ||
			state.query.sequence != sweep.queryGeneration || a.session != sweep.parent ||
			a.generation != sweep.generation {
			return
		}
		count := 0
		for _, result := range state.query.results {
			if !a.localVaultFileQueryResultAuthorized(result) ||
				!a.localVaultFileQueryResultLifecycleCurrent(parentPath, result) {
				continue
			}
			count += len(result.hits)
		}
		if count == 0 {
			state.query.status = localVaultFileQueryStale
		} else {
			state.query.status = fmt.Sprintf("精确查询找到 %d 条%s", count, localVaultFileQueryPartialSuffix)
		}
		if a.win != nil {
			a.win.Invalidate()
		}
	}
	if pending != nil {
		a.resumeLocalVaultFileQueryPendingActivation(pending)
	}
}

// resumeLocalVaultFileQueryPendingActivation consumes the single click that was
// waiting for its own sweep. It never retries: it starts the existing
// authenticated activation at most once, and only while the original query,
// parent, App generation, hit, result and locked routing path are still current.
func (a *App) resumeLocalVaultFileQueryPendingActivation(pending *localVaultFileQueryPendingActivation) {
	if pending == nil {
		return
	}
	state := &a.localVaultFiles
	if pending.sweep == nil || state.query.sweep != nil ||
		state.query.operation != nil || state.query.current != pending.queryOperation ||
		state.query.sequence != pending.queryGeneration ||
		pending.result == nil || a.session != pending.result.parent ||
		a.generation != pending.result.generation ||
		!a.localVaultFileQueryHitAuthorized(pending.hit) {
		state.query.status = localVaultFileQueryActivationFailed
		return
	}
	a.startLocalVaultFileQueryActivation(pending.hit)
}

// localVaultFileQueryHits returns only hits whose exact wrapper/slot/account/
// lock generation is still current. Stale A is never shown while valid B stays
// visible.
func (a *App) localVaultFileQueryHits() []*localVaultFileQueryHit {
	state := &a.localVaultFiles
	if state.query.operation != nil || state.query.current == nil {
		return nil
	}
	var hits []*localVaultFileQueryHit
	for _, result := range state.query.results {
		if !a.localVaultFileQueryResultCurrent(result) ||
			!a.localVaultFileQueryResultAuthorized(result) {
			continue
		}
		hits = append(hits, result.hits...)
	}
	return hits
}

// activateLocalVaultFileQueryHit is the normal activation action. It freezes
// the exact hit and launches the captured wrapper's ValidateExactQueryHit
// before any destination selection. The dispatch path selects only after that
// validation returned nil and the full lifecycle is still current.
//
// A click that arrives while the hit's own current query sweep is in flight is
// serialized behind that sweep instead of being rejected by a transient Busy
// parent snapshot. The wait does not authenticate, serve stale data or widen the
// result set; after the sweep settles, the same immutable hit must pass the
// normal Active check before the existing validation starts.
func (a *App) activateLocalVaultFileQueryHit(hit *localVaultFileQueryHit) {
	state := &a.localVaultFiles
	if hit == nil || hit.result == nil || hit.id == "" || hit.title == "" {
		return
	}
	if state.query.operation != nil {
		state.query.status = localVaultFileQueryWorking
		return
	}
	if !a.localVaultFileQueryHitAuthorized(hit) {
		state.query.status = localVaultFileQueryFailed
		return
	}
	if state.query.activation != nil {
		state.query.status = localVaultFileQueryWorking
		return
	}
	if state.query.sweep != nil {
		if !a.localVaultFileQueryPendingActivationCurrent(hit, state.query.sweep) {
			state.query.status = localVaultFileQueryActivationFailed
			return
		}
		// A newer click on an authorized row supersedes only the older queued
		// click. It keeps its own exact immutable hit; it is never remapped to
		// another query or sibling.
		state.query.pendingActivation = &localVaultFileQueryPendingActivation{
			sweep:           state.query.sweep,
			queryGeneration: state.query.sequence,
			queryOperation:  state.query.current,
			hit:             hit,
			result:          hit.result,
		}
		state.query.status = localVaultFileQueryWorking
		return
	}
	state.query.pendingActivation = nil
	if !a.startLocalVaultFileQueryActivation(hit) {
		return
	}
}

// localVaultFileQueryPendingActivationCurrent checks the cache-independent
// lifecycle that lets one click wait for its own sweep. It deliberately does not
// take a new parent cache snapshot: the exact pending hit must belong to the
// sweep's query generation and still be bound to the same parent, App
// generation, slot, wrapper, ref tuple and workspace. The fresh Active routing
// check happens only after the sweep has settled.
func (a *App) localVaultFileQueryPendingActivationCurrent(hit *localVaultFileQueryHit, sweep *localVaultFileQuerySweep) bool {
	state := &a.localVaultFiles
	if hit == nil || hit.result == nil || sweep == nil ||
		state.query.sweep != sweep ||
		state.query.operation != nil || state.query.current != sweep.queryOperation ||
		state.query.sequence != sweep.queryGeneration ||
		sweep.queryOperation == nil || sweep.queryGeneration != state.query.sequence ||
		a.session == nil || a.session != sweep.parent || a.generation != sweep.generation ||
		hit.result.parent != sweep.parent || hit.result.generation != sweep.generation ||
		hit.result.parentPath != sweep.parentPath ||
		hit.result.queryOperation != sweep.queryOperation ||
		hit.result.queryGeneration != sweep.queryGeneration ||
		!a.localVaultFileQueryHitAuthorized(hit) ||
		!a.localVaultFileQueryResultLifecycleCurrent(sweep.parentPath, hit.result) {
		return false
	}
	for _, result := range sweep.results {
		if result == hit.result {
			return true
		}
	}
	return false
}

// startLocalVaultFileQueryActivation is the single authenticated activation
// entry. It is called only after the current sweep has settled (or when no
// sweep is in flight), so its normal Active snapshot is never replaced by a
// wait or a stale route. Failure leaves the prior query scope unchanged apart
// from the finite activation-failed status.
func (a *App) startLocalVaultFileQueryActivation(hit *localVaultFileQueryHit) bool {
	state := &a.localVaultFiles
	if hit == nil || hit.result == nil || hit.id == "" || hit.title == "" ||
		state.query.activation != nil || state.query.pendingActivation != nil ||
		state.query.sweep != nil || state.query.operation != nil ||
		!a.localVaultFileQueryHitAuthorized(hit) ||
		!a.localVaultFileQueryResultCurrent(hit.result) {
		state.query.status = localVaultFileQueryActivationFailed
		return false
	}
	op := &localVaultFileQueryActivation{
		queryGeneration: state.query.sequence,
		queryOperation:  state.query.current,
		hit:             hit,
		result:          hit.result, id: hit.id, title: hit.title,
	}
	state.query.activation = op
	wrapper, proof := hit.result.wrapper, hit.result.proof
	dispatch := a.dispatch
	a.launch(func() {
		err := wrapper.ValidateExactQueryHit(proof, op.id, op.title)
		if dispatch != nil {
			dispatch(func() { a.finishLocalVaultFileQueryActivation(op, err) })
		}
	})
	return true
}

func (a *App) finishLocalVaultFileQueryActivation(op *localVaultFileQueryActivation, err error) {
	if op == nil {
		return
	}
	state := &a.localVaultFiles
	if state.query.activation != op {
		return
	}
	state.query.activation = nil
	if err != nil {
		// Drop only an exact result that is still part of this activation's
		// immutable query generation. A stale click from a replaced query must
		// not consume anything from the replacement query.
		if state.query.sequence == op.queryGeneration &&
			state.query.current == op.queryOperation {
			a.dropLocalVaultFileQueryResult(op.result)
		}
		state.query.status = localVaultFileQueryActivationFailed
		return
	}
	if state.query.sequence != op.queryGeneration ||
		state.query.current != op.queryOperation ||
		state.query.operation != nil ||
		!a.localVaultFileQueryHitAuthorized(op.hit) ||
		!a.localVaultFileQueryResultCurrent(op.result) {
		state.query.status = localVaultFileQueryActivationFailed
		return
	}
	ref, ok := localVaultFileRefByPath(state.refs, op.result.scope.configPath)
	if !ok || ref.vaultID != op.result.scope.vaultID ||
		ref.journalPath != op.result.scope.journalPath {
		state.query.status = localVaultFileQueryActivationFailed
		return
	}
	a.selectLocalVaultFile(ref)
	scope, _, live := a.localVaultFileCurrentLiveScopeGate()
	if !live || scope != op.result.scope {
		a.localVaultFiles.status = localVaultFileQueryActivationFailed
		return
	}
	a.localVaultFiles.activeItem = localVaultFileActiveItem{
		scope: op.result.scope, parent: op.result.parent,
		generation: op.result.generation, id: op.id, title: op.title,
	}
	a.localVaultFiles.status = localVaultFileQueryActivated
	if a.win != nil {
		a.win.Invalidate()
	}
}

func (a *App) dropLocalVaultFileQueryResult(result *localVaultFileQueryResult) {
	if result == nil {
		return
	}
	state := &a.localVaultFiles
	for index, existing := range state.query.results {
		if existing != result {
			continue
		}
		copy(state.query.results[index:], state.query.results[index+1:])
		state.query.results[len(state.query.results)-1] = nil
		state.query.results = state.query.results[:len(state.query.results)-1]
		if state.query.activation != nil && state.query.activation.result == result {
			state.query.activation = nil
		}
		if state.query.pendingActivation != nil && state.query.pendingActivation.result == result {
			state.query.pendingActivation = nil
		}
		if state.activeItem.scope == result.scope && state.activeItem.parent == result.parent &&
			state.activeItem.generation == result.generation {
			state.activeItem = localVaultFileActiveItem{}
		}
		clearLocalVaultFileExactResult(&result.proof)
		result.hits = nil
		return
	}
}

func (a *App) localVaultFileActiveItemCurrent() (localVaultFileActiveItem, bool) {
	item := a.localVaultFiles.activeItem
	if item.id == "" || item.parent == nil || a.session == nil ||
		item.parent != a.session || item.generation != a.generation {
		return localVaultFileActiveItem{}, false
	}
	scope, slot, ok := a.localVaultFileCurrentLiveScopeGate()
	if !ok || slot == nil || item.scope != scope {
		return localVaultFileActiveItem{}, false
	}
	return item, true
}

func (a *App) onevraLocalVaultFileQuery(c *ui.Context) {
	a.scheduleLocalVaultFileQueryRevalidation()
	t := c.Theme()
	state := &a.localVaultFiles
	input := ui.TextInput(c.Key("local-vault-query"), &state.query.title).
		Label("精确查询独立文件库标题").Placeholder("输入完整标题").FillWidth()
	if input.Changed() {
		a.localVaultFileQueryChanged()
	}
	if input.Submitted() {
		a.searchLocalVaultFileExactTitle()
	}
	if oneui.Button(c, "精确查询独立文件库", oneui.ButtonOutline).Clicked() {
		a.searchLocalVaultFileExactTitle()
	}
	if state.query.status != "" {
		oneui.Text(c, state.query.status).TextColor(t.TextMuted)
	}
	for _, hit := range a.localVaultFileQueryHits() {
		hit := hit
		ref, ok := localVaultFileRefByPath(state.refs, hit.result.scope.configPath)
		if !ok {
			continue
		}
		label := a.localVaultFileDisplayLabelFor(ref)
		sum := sha256.Sum256([]byte(hit.result.scope.configPath + "\x00" + hit.id))
		ui.Column(c).Key("local-vault-query-hit:" + hex.EncodeToString(sum[:])).
			FillWidth().Gap(t.Space(1)).Children(func() {
			if oneui.Button(c, "激活到 "+label+"："+hit.title, oneui.ButtonOutline).Clicked() {
				a.activateLocalVaultFileQueryHit(hit)
			}
			oneui.Text(c, "ID："+hit.id).
				FontSize(t.Rem(.72)).TextColor(t.TextMuted).SingleLine()
		})
	}
}
