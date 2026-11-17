package desktop

import (
	"sync"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/vaultfileclient"
)

const (
	localVaultFileInitialFanoutIncompleteSuffix = " · 部分独立文件库暂不可用"
	localVaultFileInitialAdoptionFailedStatus   = "解锁未完成；请核查本地状态"
)

// localVaultFileInitialBatchDrainForTest observes only finite cleanup metadata
// after the real wrapper Close calls and parent Lock have returned. It is nil in
// production and never receives a factor, key, wrapper, token, parent, path,
// identity or authority-bearing result.
const localVaultFileInitialDrainLimit = 64

type localVaultFileInitialDrainState uint8

const (
	localVaultFileInitialDrainNotReady localVaultFileInitialDrainState = iota
	localVaultFileInitialDrainComplete
	localVaultFileInitialDrainInvalid
)

type localVaultFileInitialDrainSummary struct {
	state          localVaultFileInitialDrainState
	closedWrappers int
	parentLocked   bool
	refsCleared    bool
	rowsCleared    bool
}

func localVaultFileInitialDrainResult(closed int, parentLocked, refsCleared, rowsCleared bool) localVaultFileInitialDrainSummary {
	summary := localVaultFileInitialDrainSummary{
		closedWrappers: closed,
		parentLocked:   parentLocked,
		refsCleared:    refsCleared,
		rowsCleared:    rowsCleared,
	}
	if closed < 0 || closed > localVaultFileInitialDrainLimit {
		summary.closedWrappers = localVaultFileInitialDrainLimit
		summary.state = localVaultFileInitialDrainInvalid
		return summary
	}
	if !parentLocked || !refsCleared || !rowsCleared {
		summary.state = localVaultFileInitialDrainInvalid
		return summary
	}
	summary.state = localVaultFileInitialDrainComplete
	return summary
}

func clearLocalVaultFileInitialRefs(refs []localVaultFileRef) {
	for index := range refs {
		refs[index] = localVaultFileRef{}
	}
}

func localVaultFileInitialRefsCleared(refs []localVaultFileRef) bool {
	for _, ref := range refs {
		if ref != (localVaultFileRef{}) {
			return false
		}
	}
	return true
}

func localVaultFileInitialRowsCleared(rows []personal.Row) bool {
	for _, row := range rows {
		if row.Kind != "" || row.RestoreState != "" || row.Category != "" ||
			row.Subtitle != "" || row.State != "" || row.ID != "" ||
			row.Title != "" || row.Revision != "" || row.WatchtowerFlags != nil ||
			row.StrengthScore != nil || row.StrengthCategory != "" ||
			row.ReuseCount != 0 || row.BreachCount != 0 {
			return false
		}
	}
	return true
}

var localVaultFileInitialBatchDrainForTest func(closedWrappers int, parentLocked bool)

// localVaultFileInitialBatch is the private ownership envelope for the one
// initial explicit-account unlock batch. It may be adopted exactly once on the
// UI generation gate, or drained exactly once when stale, cancelled or failed.
// It is never published to App state before adoption.
type localVaultFileInitialBatch struct {
	mu sync.Mutex

	parent        *personal.Session
	results       []vaultfileclient.LocalGenesisBatchResult
	refs          []localVaultFileRef
	candidateRefs []int
	rows          []personal.Row

	accountPath, settingsPath, profileDir, backendRoot string
	generation                                         uint64
	fanoutIncomplete                                   bool

	adopted, dropRequested, draining bool
	done                             chan struct{}
	summary                          localVaultFileInitialDrainSummary
	notice                           chan localVaultFileInitialDrainSummary
	noticeOpen                       bool
}

func clearLocalVaultFileInitialRows(rows []personal.Row) {
	for index := range rows {
		rows[index] = personal.Row{}
	}
}

func newLocalVaultFileInitialBatch(parent *personal.Session, results []vaultfileclient.LocalGenesisBatchResult,
	refs []localVaultFileRef, candidateRefs []int, accountPath, settingsPath, profileDir, backendRoot string,
	generation uint64) *localVaultFileInitialBatch {
	return &localVaultFileInitialBatch{
		parent: parent, results: results, refs: refs, candidateRefs: candidateRefs,
		accountPath: accountPath, settingsPath: settingsPath,
		profileDir: profileDir, backendRoot: backendRoot,
		generation: generation, done: make(chan struct{}),
	}
}

func (b *localVaultFileInitialBatch) view() (*personal.Session, []vaultfileclient.LocalGenesisBatchResult,
	[]localVaultFileRef, []int, []personal.Row, bool) {
	if b == nil {
		return nil, nil, nil, nil, nil, false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.adopted || b.dropRequested || b.draining {
		return nil, nil, nil, nil, nil, false
	}
	return b.parent, b.results, b.refs, b.candidateRefs, b.rows, true
}

func (b *localVaultFileInitialBatch) setRows(rows []personal.Row) {
	if b == nil {
		return
	}
	b.mu.Lock()
	if !b.adopted && !b.dropRequested && !b.draining {
		b.rows = rows
	}
	b.mu.Unlock()
}

func (b *localVaultFileInitialBatch) takeForAdoption() bool {
	if b == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.adopted || b.dropRequested || b.draining {
		return false
	}
	b.retireDrainNoticeLocked()
	b.adopted = true
	b.parent = nil
	b.results = nil
	b.refs = nil
	b.candidateRefs = nil
	b.rows = nil
	return true
}

func (b *localVaultFileInitialBatch) drop(launch func(func())) {
	if b == nil {
		return
	}
	b.mu.Lock()
	if b.adopted || b.dropRequested {
		b.mu.Unlock()
		return
	}
	b.dropRequested = true
	clearLocalVaultFileInitialRows(b.rows)
	b.rows = nil
	b.mu.Unlock()
	if launch == nil {
		b.drain()
		return
	}
	launch(func() { b.drain() })
}

// drain closes only the exact wrappers/parent owned by this unpublished batch.
// Wrapper Close is synchronous and waits for the real child close barrier;
// parent Lock follows. It never touches an older or newer independent parent.
func (b *localVaultFileInitialBatch) drainNotice() (<-chan localVaultFileInitialDrainSummary, bool) {
	if b == nil {
		return nil, false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.adopted || b.notice != nil {
		return nil, false
	}
	if b.summary.state == localVaultFileInitialDrainComplete ||
		b.summary.state == localVaultFileInitialDrainInvalid {
		notice := make(chan localVaultFileInitialDrainSummary, 1)
		notice <- b.summary
		close(notice)
		b.notice = notice
		return notice, true
	}
	notice := make(chan localVaultFileInitialDrainSummary, 1)
	b.notice = notice
	b.noticeOpen = true
	return notice, true
}

func (b *localVaultFileInitialBatch) publishDrainNoticeLocked() {
	if b.notice == nil || !b.noticeOpen {
		return
	}
	select {
	case b.notice <- b.summary:
	default:
	}
	close(b.notice)
	b.noticeOpen = false
}

func (b *localVaultFileInitialBatch) retireDrainNoticeLocked() {
	if b.notice == nil || !b.noticeOpen {
		return
	}
	close(b.notice)
	b.noticeOpen = false
}

func (b *localVaultFileInitialBatch) drainSummary() localVaultFileInitialDrainSummary {
	if b == nil {
		return localVaultFileInitialDrainSummary{state: localVaultFileInitialDrainInvalid}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.summary
}

func (b *localVaultFileInitialBatch) drain() {
	if b == nil {
		return
	}
	b.mu.Lock()
	if b.adopted {
		b.mu.Unlock()
		return
	}
	if b.draining {
		done := b.done
		b.mu.Unlock()
		<-done
		return
	}
	b.draining = true
	parent := b.parent
	results := b.results
	refs := b.refs
	rows := b.rows
	clearLocalVaultFileInitialRows(rows)
	rowsCleared := localVaultFileInitialRowsCleared(rows)
	clearLocalVaultFileInitialRefs(refs)
	refsCleared := localVaultFileInitialRefsCleared(refs)
	b.refs = nil
	b.candidateRefs = nil
	b.rows = nil
	b.mu.Unlock()

	closedWrappers := 0
	seen := make(map[*vaultfileclient.LocalGenesisSession]struct{})
	for index := range results {
		wrapper := results[index].Wrapper
		if wrapper == nil {
			continue
		}
		if _, ok := seen[wrapper]; ok {
			continue
		}
		seen[wrapper] = struct{}{}
		_ = wrapper.Close()
		closedWrappers++
	}
	for index := range results {
		clearLocalVaultFileSessionSummary(&results[index].Baseline)
		results[index] = vaultfileclient.LocalGenesisBatchResult{}
	}
	parentLocked := false
	observerParentLocked := true
	if parent != nil {
		parent.Lock()
		parentLocked = !parent.Unlocked()
		observerParentLocked = parentLocked
	}

	b.mu.Lock()
	b.parent = nil
	b.results = nil
	b.refs = nil
	b.candidateRefs = nil
	b.rows = nil
	b.summary = localVaultFileInitialDrainResult(closedWrappers, parentLocked, refsCleared, rowsCleared)
	b.publishDrainNoticeLocked()
	close(b.done)
	b.mu.Unlock()

	if localVaultFileInitialBatchDrainForTest != nil {
		localVaultFileInitialBatchDrainForTest(closedWrappers, observerParentLocked)
	}
}

func (a *App) adoptLocalVaultFileInitialBatch(batch *localVaultFileInitialBatch) (*personal.Session, []personal.Row, bool) {
	fail := func() (*personal.Session, []personal.Row, bool) {
		if batch != nil {
			batch.drop(a.launch)
		}
		a.status = localVaultFileInitialAdoptionFailedStatus
		return nil, nil, false
	}
	parent, results, refs, candidateRefs, rows, ok := batch.view()
	if !ok || a.generation != batch.generation || a.session != nil ||
		a.path != batch.accountPath || a.settingsPath != batch.settingsPath ||
		len(a.localVaultFiles.sessionSlots) != 0 || a.localVaultFiles.sessionParent != nil {
		return fail()
	}
	profileDir, backendRoot := localVaultFilePaths(a.settingsPath, batch.accountPath)
	if profileDir != batch.profileDir || backendRoot != batch.backendRoot ||
		parent == nil || len(candidateRefs) != len(results) {
		return fail()
	}
	cache, cachePath := parent.VaultFileCacheSnapshot()
	if cache != personal.VaultFileCacheActive || cachePath != batch.accountPath {
		return fail()
	}

	slots := make(map[localVaultFileSessionScope]*localVaultFileSessionSlot, len(results))
	seenWrappers := make(map[*vaultfileclient.LocalGenesisSession]localVaultFileSessionScope)
	for index, result := range results {
		if result.Err != nil {
			continue
		}
		if result.Index != index || result.Wrapper == nil || index >= len(candidateRefs) {
			return fail()
		}
		refIndex := candidateRefs[index]
		if refIndex < 0 || refIndex >= len(refs) {
			return fail()
		}
		ref := refs[refIndex]
		if ref.vaultID == "" || ref.journalPath == "" || result.Baseline.VaultID != ref.vaultID {
			return fail()
		}
		scope := localVaultFileSessionScope{
			configPath: ref.path, vaultID: ref.vaultID,
			backendRoot: batch.backendRoot, journalPath: ref.journalPath,
		}
		if existing, ok := seenWrappers[result.Wrapper]; ok && existing != scope {
			return fail()
		}
		if _, exists := slots[scope]; exists {
			return fail()
		}
		seenWrappers[result.Wrapper] = scope
		slots[scope] = &localVaultFileSessionSlot{
			scope: scope, parent: parent, appGeneration: batch.generation,
			session: result.Wrapper, summary: result.Baseline,
		}
	}
	if !batch.takeForAdoption() {
		return fail()
	}
	// The result baseline slices now belong to the installed slots. Zero only
	// the private result structs, never the adopted item storage.
	for index := range results {
		results[index].Baseline = vaultfileclient.LocalGenesisBaseline{}
	}

	a.closeLocalVaultFileView()
	state := &a.localVaultFiles
	state.refs = refs
	state.refsBackendRoot = batch.backendRoot
	state.sessionSlots = slots
	state.sessionParent = parent
	state.sessionGeneration = batch.generation
	state.sessionPath = batch.accountPath
	state.viewVerification = localVaultFileViewUnverified
	state.status = ""
	return parent, rows, true
}
