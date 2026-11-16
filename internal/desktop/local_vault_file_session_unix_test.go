//go:build darwin || linux

package desktop

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/vaultfileclient"
	bolt "go.etcd.io/bbolt"
)

type localVaultSessionFixture struct {
	root                           string
	settingsPath                   string
	personalPath, password, secret string
	key                            []byte
	profileDir, backendRoot        string
	app                            *App
	parent                         *personal.Session
}

func newLocalVaultSessionFixture(t *testing.T) *localVaultSessionFixture {
	t.Helper()
	root := desktopPrivateTestRoot(t)
	settingsDir := filepath.Join(root, "settings")
	if err := os.Mkdir(settingsDir, 0700); err != nil {
		t.Fatal("LOCAL_SESSION_SETTINGS_DIRECTORY_FAILED")
	}
	settingsPath := filepath.Join(settingsDir, "settings.json")
	personalPath := filepath.Join(root, "personal.ll")
	password := "local-session-factor"
	key := []byte("1234567890abcdef")
	if personal.Create(personalPath, password, key) != nil {
		t.Fatal("LOCAL_SESSION_PROFILE_CREATE_FAILED")
	}
	session, err := personal.UnlockSession(personalPath, []byte(password), key, time.Minute)
	if err != nil {
		t.Fatal("LOCAL_SESSION_PROFILE_UNLOCK_FAILED")
	}
	a := New()
	a.path, a.session = personalPath, session
	a.settingsPath = settingsPath
	profileDir, backendRoot, err := ensureLocalVaultFileWorkspace(settingsPath, personalPath)
	if err != nil {
		t.Fatal("LOCAL_SESSION_WORKSPACE_FAILED")
	}
	t.Cleanup(session.Lock)
	return &localVaultSessionFixture{
		root: root, settingsPath: settingsPath, personalPath: personalPath,
		password: password, secret: personal.FormatSecret(key), key: key,
		profileDir: profileDir, backendRoot: backendRoot, app: a, parent: session,
	}
}

type localVaultSessionQueue struct {
	launches   []func()
	dispatches []func()
}

func (q *localVaultSessionQueue) install(a *App) {
	a.launch = func(fn func()) { q.launches = append(q.launches, fn) }
	a.dispatch = func(fn func()) { q.dispatches = append(q.dispatches, fn) }
}

func (q *localVaultSessionQueue) runLaunch(t *testing.T) {
	t.Helper()
	if len(q.launches) == 0 {
		t.Fatal("LOCAL_SESSION_LAUNCH_MISSING")
	}
	fn := q.launches[0]
	q.launches = q.launches[1:]
	fn()
}

func (q *localVaultSessionQueue) runDispatch(t *testing.T) {
	t.Helper()
	if len(q.dispatches) == 0 {
		t.Fatal("LOCAL_SESSION_DISPATCH_MISSING")
	}
	fn := q.dispatches[0]
	q.dispatches = q.dispatches[1:]
	fn()
}

func (q *localVaultSessionQueue) drain(t *testing.T) {
	t.Helper()
	for len(q.dispatches) != 0 || len(q.launches) != 0 {
		for len(q.dispatches) != 0 {
			q.runDispatch(t)
		}
		for len(q.launches) != 0 {
			q.runLaunch(t)
		}
	}
}

func (q *localVaultSessionQueue) drainLaunches(t *testing.T) {
	t.Helper()
	for len(q.launches) != 0 {
		q.runLaunch(t)
	}
}

func localVaultSessionStagedResult(t *testing.T, op *localVaultFileSessionOperation) localVaultFileSessionResult {
	t.Helper()
	op.handoffMu.Lock()
	defer op.handoffMu.Unlock()
	if !op.handoffReady {
		t.Fatal("LOCAL_SESSION_RESULT_NOT_STAGED")
	}
	return op.handoffResult
}

func localVaultSessionStagedCandidate(t *testing.T, op *localVaultFileSessionOperation) *vaultfileclient.LocalGenesisSession {
	t.Helper()
	result := localVaultSessionStagedResult(t, op)
	if result.outcome != localVaultFileSessionOutcomeOpened || result.candidate == nil {
		t.Fatal("LOCAL_SESSION_CANDIDATE_NOT_STAGED")
	}
	return result.candidate
}

func assertLocalVaultSessionCompleted(t *testing.T, op *localVaultFileSessionOperation, want localVaultFileSessionOutcome) {
	t.Helper()
	op.handoffMu.Lock()
	ready, terminal, outcome := op.handoffReady, op.handoffTerminal, op.outcome
	op.handoffMu.Unlock()
	if ready || !terminal || outcome != want {
		t.Fatal("LOCAL_SESSION_OPERATION_NOT_COMPLETED")
	}
}

func holdDesktopParentDBBusy(t *testing.T, f *localVaultSessionFixture) func() {
	t.Helper()
	holder, err := bolt.Open(f.parent.VaultPath(), 0600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		t.Fatal("LOCAL_SESSION_BUSY_DB_HOLDER_FAILED")
	}
	blocker, err := holder.Begin(true)
	if err != nil {
		_ = holder.Close()
		t.Fatal("LOCAL_SESSION_BUSY_WRITE_TRANSACTION_FAILED")
	}
	done := make(chan error, 1)
	go func() {
		_, err := f.parent.List("active")
		done <- err
	}()
	released := false
	operationFinished := false
	release := func() {
		if released {
			return
		}
		released = true
		_ = blocker.Rollback()
		_ = holder.Close()
		if operationFinished {
			return
		}
		select {
		case err := <-done:
			if err != nil {
				t.Fatal("LOCAL_SESSION_BUSY_PARENT_OPERATION_FAILED")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("LOCAL_SESSION_BUSY_PARENT_OPERATION_STUCK")
		}
	}
	t.Cleanup(release)
	deadline := time.Now().Add(5 * time.Second)
	for f.parent.VaultFileCacheState() != personal.VaultFileCacheBusy {
		if time.Now().After(deadline) {
			t.Fatal("LOCAL_SESSION_BUSY_TIMEOUT")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case err := <-done:
		_ = err
		operationFinished = true
		t.Fatal("LOCAL_SESSION_BUSY_OPERATION_NOT_BLOCKED")
	default:
	}
	return release
}

func (f *localVaultSessionFixture) createVault(t *testing.T) (string, vaultfileclient.Manifest) {
	t.Helper()
	configPath, proposal, err := newLocalVaultFileProposal(f.profileDir, f.backendRoot, f.personalPath)
	if err != nil {
		t.Fatal("LOCAL_SESSION_PROPOSAL_FAILED")
	}
	ctx := context.Background()
	creation, err := vaultfileclient.OpenCreation(configPath, &proposal, []byte(f.password), []byte(f.secret))
	if err != nil {
		t.Fatal("LOCAL_SESSION_CREATION_OPEN_FAILED")
	}
	backupRequired, err := creation.Prepare(ctx)
	creation.Close()
	if err != nil || !backupRequired {
		t.Fatal("LOCAL_SESSION_CREATION_PREPARE_FAILED")
	}
	manifest, exists, err := vaultfileclient.ReadManifest(configPath)
	if err != nil || !exists {
		t.Fatal("LOCAL_SESSION_MANIFEST_MISSING")
	}
	backup, err := personal.PrepareBackup(manifest.PersonalFile, manifest.Archive, f.password, f.key)
	if err != nil {
		t.Fatal("LOCAL_SESSION_BACKUP_PREPARE_FAILED")
	}
	kit := backup.Material()
	if kit == "" {
		backup.Close()
		t.Fatal("LOCAL_SESSION_BACKUP_MATERIAL_MISSING")
	}
	if err := backup.Publish(); err != nil {
		backup.Close()
		t.Fatal("LOCAL_SESSION_BACKUP_PUBLISH_FAILED")
	}
	backup.Close()
	creation, err = vaultfileclient.OpenCreation(configPath, nil, []byte(f.password), []byte(f.secret))
	if err != nil {
		t.Fatal("LOCAL_SESSION_COMPLETION_OPEN_FAILED")
	}
	backupRequired, err = creation.Prepare(ctx)
	if err != nil || backupRequired {
		creation.Close()
		t.Fatal("LOCAL_SESSION_COMPLETION_PREPARE_FAILED")
	}
	if err := creation.Complete(ctx, []byte(f.password), []byte(f.secret), []byte(kit)); err != nil {
		creation.Close()
		t.Fatal("LOCAL_SESSION_COMPLETE_FAILED")
	}
	if err := creation.Verify(ctx, []byte(f.password), []byte(f.secret), []byte(kit)); err != nil {
		creation.Close()
		t.Fatal("LOCAL_SESSION_VERIFY_FAILED")
	}
	creation.Close()
	manifest, exists, err = vaultfileclient.ReadManifest(configPath)
	if err != nil || !exists || manifest.VaultID == "" {
		t.Fatal("LOCAL_SESSION_MANIFEST_BINDING_MISSING")
	}
	return configPath, manifest
}

func (f *localVaultSessionFixture) scope(configPath string, manifest vaultfileclient.Manifest) localVaultFileSessionScope {
	return localVaultFileSessionScope{configPath: configPath, vaultID: manifest.VaultID, backendRoot: f.backendRoot}
}

func (f *localVaultSessionFixture) openVault(t *testing.T, q *localVaultSessionQueue, scope localVaultFileSessionScope) *localVaultFileSessionOperation {
	t.Helper()
	op := f.app.beginLocalVaultFileSession(scope, []byte(f.password), f.key)
	if op == nil {
		t.Fatal("LOCAL_SESSION_BEGIN_FAILED")
	}
	q.runLaunch(t)
	q.runDispatch(t)
	if f.app.localVaultFiles.sessionSlots[scope] == nil || f.app.localVaultFiles.sessionSlots[scope].session == nil {
		t.Fatal("LOCAL_SESSION_ADOPT_FAILED")
	}
	return op
}

func TestDesktopLocalVaultSessionPerVaultCloseIsolation(t *testing.T) {
	f := newLocalVaultSessionFixture(t)
	q := &localVaultSessionQueue{}
	q.install(f.app)
	aPath, aManifest := f.createVault(t)
	bPath, bManifest := f.createVault(t)
	if aManifest.VaultID == bManifest.VaultID || aManifest.Name == bManifest.Name {
		t.Fatal("LOCAL_SESSION_VAULTS_NOT_INDEPENDENT")
	}
	aCompanion, aExists, aErr := vaultfileclient.ReadCompanion(aPath, aManifest)
	bCompanion, bExists, bErr := vaultfileclient.ReadCompanion(bPath, bManifest)
	if aErr != nil || bErr != nil || !aExists || !bExists ||
		aCompanion.GenesisSHA256 == bCompanion.GenesisSHA256 {
		t.Fatal("LOCAL_SESSION_GENESIS_NOT_INDEPENDENT")
	}
	aScope, bScope := f.scope(aPath, aManifest), f.scope(bPath, bManifest)
	f.openVault(t, q, aScope)
	f.openVault(t, q, bScope)
	aSession := f.app.localVaultFiles.sessionSlots[aScope].session
	bSession := f.app.localVaultFiles.sessionSlots[bScope].session
	if aSession == nil || bSession == nil || aSession == bSession {
		t.Fatal("LOCAL_SESSION_WRAPPERS_NOT_DISTINCT")
	}
	f.app.closeLocalVaultFileSession(aScope)
	if f.app.localVaultFiles.sessionSlots[aScope] != nil {
		t.Fatal("LOCAL_SESSION_CLOSE_RETAINED_SLOT")
	}
	q.drain(t)
	if _, err := aSession.Summary(); err == nil {
		t.Fatal("LOCAL_SESSION_CLOSED_CHILD_STILL_READS")
	}
	summary, err := bSession.Summary()
	if err != nil || summary.VaultID != bManifest.VaultID {
		t.Fatal("LOCAL_SESSION_SIBLING_CHILD_LOST")
	}
	if !f.parent.Unlocked() {
		t.Fatal("LOCAL_SESSION_PARENT_LOCKED_WITH_CHILD")
	}
	if _, ok := f.app.readLocalVaultFileSession(aScope); ok {
		t.Fatal("LOCAL_SESSION_CLOSED_SLOT_READABLE")
	}
	if read, ok := f.app.readLocalVaultFileSession(bScope); !ok || read.VaultID != bManifest.VaultID {
		t.Fatal("LOCAL_SESSION_SIBLING_SLOT_UNREADABLE")
	}
}

func TestDesktopLocalVaultSessionLateCandidateDropsWithoutReplacingNewSlot(t *testing.T) {
	f := newLocalVaultSessionFixture(t)
	q := &localVaultSessionQueue{}
	q.install(f.app)
	configPath, manifest := f.createVault(t)
	scope := f.scope(configPath, manifest)
	oldOp := f.app.beginLocalVaultFileSession(scope, []byte(f.password), f.key)
	if oldOp == nil {
		t.Fatal("LOCAL_SESSION_OLD_BEGIN_FAILED")
	}
	q.runLaunch(t)
	oldCandidate := localVaultSessionStagedCandidate(t, oldOp)
	if len(q.dispatches) != 1 {
		t.Fatal("LOCAL_SESSION_OLD_CANDIDATE_NOT_PENDING")
	}
	f.app.closeLocalVaultFileSession(scope)
	assertLocalVaultSessionCompleted(t, oldOp, localVaultFileSessionOutcomeCancelled)
	newOp := f.app.beginLocalVaultFileSession(scope, []byte(f.password), f.key)
	if newOp == nil || newOp == oldOp {
		t.Fatal("LOCAL_SESSION_NEW_BEGIN_FAILED")
	}
	q.drainLaunches(t)
	newCandidate := localVaultSessionStagedCandidate(t, newOp)
	if len(q.dispatches) != 2 {
		t.Fatal("LOCAL_SESSION_NEW_CANDIDATE_NOT_PENDING")
	}
	oldAdopt, newAdopt := q.dispatches[0], q.dispatches[1]
	q.dispatches = nil
	newAdopt()
	if got := f.app.localVaultFiles.sessionSlots[scope]; got == nil || got.session != newCandidate || got.operation != nil {
		t.Fatal("LOCAL_SESSION_NEW_CANDIDATE_NOT_ADOPTED")
	}
	assertLocalVaultSessionCompleted(t, newOp, localVaultFileSessionOutcomeOpened)
	oldAdopt()
	if got := f.app.localVaultFiles.sessionSlots[scope]; got == nil || got.session != newCandidate {
		t.Fatal("LOCAL_SESSION_STALE_CANDIDATE_REMOVED_NEW_SLOT")
	}
	q.drain(t)
	if _, err := oldCandidate.Summary(); err == nil {
		t.Fatal("LOCAL_SESSION_STALE_CANDIDATE_NOT_CLOSED")
	}
	summary, err := newCandidate.Summary()
	if err != nil || summary.VaultID != manifest.VaultID {
		t.Fatal("LOCAL_SESSION_NEW_CANDIDATE_LOST")
	}
}

func TestDesktopLocalVaultSessionParentChangeRejectsCapturedCandidate(t *testing.T) {
	f := newLocalVaultSessionFixture(t)
	q := &localVaultSessionQueue{}
	q.install(f.app)
	aPath, aManifest := f.createVault(t)
	bPath, bManifest := f.createVault(t)
	aScope, bScope := f.scope(aPath, aManifest), f.scope(bPath, bManifest)
	f.openVault(t, q, aScope)
	f.openVault(t, q, bScope)
	aSession := f.app.localVaultFiles.sessionSlots[aScope].session
	bSession := f.app.localVaultFiles.sessionSlots[bScope].session

	otherPath := filepath.Join(f.root, "other-personal.ll")
	otherPassword := "other-session-factor"
	otherKey := []byte("abcdef1234567890")
	if personal.Create(otherPath, otherPassword, otherKey) != nil {
		t.Fatal("LOCAL_SESSION_OTHER_PARENT_CREATE_FAILED")
	}
	other, err := personal.UnlockSession(otherPath, []byte(otherPassword), otherKey, time.Minute)
	if err != nil {
		t.Fatal("LOCAL_SESSION_OTHER_PARENT_UNLOCK_FAILED")
	}
	t.Cleanup(other.Lock)

	op := f.app.beginLocalVaultFileSession(aScope, []byte(f.password), f.key)
	if op == nil {
		t.Fatal("LOCAL_SESSION_SWITCH_BEGIN_FAILED")
	}
	f.app.session, f.app.generation = other, f.app.generation+1
	q.drainLaunches(t)
	candidate := localVaultSessionStagedCandidate(t, op)
	q.drain(t)
	if len(f.app.localVaultFiles.sessionSlots) != 0 {
		t.Fatal("LOCAL_SESSION_PARENT_CHANGE_RETAINED_SLOTS")
	}
	if op.finiteOutcome() != localVaultFileSessionOutcomeFailed {
		t.Fatal("LOCAL_SESSION_PARENT_CHANGE_OPERATION_NOT_FINISHED")
	}
	for _, session := range []*vaultfileclient.LocalGenesisSession{aSession, bSession, candidate} {
		if _, err := session.Summary(); err == nil {
			t.Fatal("LOCAL_SESSION_PARENT_CHANGE_RETAINED_CHILD")
		}
	}
	if !f.parent.Unlocked() || !other.Unlocked() {
		t.Fatal("LOCAL_SESSION_PARENT_CHANGE_LOCKED_PARENT")
	}
}

func TestDesktopLocalVaultSessionGlobalLockClearsAdoptedAndPending(t *testing.T) {
	f := newLocalVaultSessionFixture(t)
	q := &localVaultSessionQueue{}
	q.install(f.app)
	aPath, aManifest := f.createVault(t)
	bPath, bManifest := f.createVault(t)
	aScope, bScope := f.scope(aPath, aManifest), f.scope(bPath, bManifest)
	f.openVault(t, q, aScope)
	f.openVault(t, q, bScope)
	aSession := f.app.localVaultFiles.sessionSlots[aScope].session
	bSession := f.app.localVaultFiles.sessionSlots[bScope].session
	op := f.app.beginLocalVaultFileSession(aScope, []byte(f.password), f.key)
	if op == nil {
		t.Fatal("LOCAL_SESSION_LOCK_PENDING_BEGIN_FAILED")
	}
	q.drainLaunches(t)
	candidate := localVaultSessionStagedCandidate(t, op)
	if len(q.dispatches) != 1 {
		t.Fatal("LOCAL_SESSION_GLOBAL_LOCK_CANDIDATE_NOT_PENDING")
	}
	f.app.Lock()
	if len(f.app.localVaultFiles.sessionSlots) != 0 || f.app.localVaultFiles.sessionParent != nil ||
		f.app.localVaultFiles.selected != "" || f.app.localVaultFiles.items != nil {
		t.Fatal("LOCAL_SESSION_GLOBAL_LOCK_RETAINED_STATE")
	}
	assertLocalVaultSessionCompleted(t, op, localVaultFileSessionOutcomeCancelled)
	q.drain(t)
	for _, session := range []*vaultfileclient.LocalGenesisSession{aSession, bSession, candidate} {
		if _, err := session.Summary(); err == nil {
			t.Fatal("LOCAL_SESSION_GLOBAL_LOCK_RETAINED_CHILD")
		}
	}
	if f.parent.Unlocked() {
		t.Fatal("LOCAL_SESSION_GLOBAL_LOCK_LEFT_PARENT_UNLOCKED")
	}
}

func TestDesktopLocalVaultSessionConcurrentLateDrop(t *testing.T) {
	f := newLocalVaultSessionFixture(t)
	a := f.app
	dispatch := make(chan func(), 8)
	staged := make(chan *localVaultFileSessionOperation, 2)
	var launches atomic.Int64
	a.dispatch = func(fn func()) { dispatch <- fn }
	a.launch = func(fn func()) {
		launches.Add(1)
		go fn()
	}
	a.localVaultFiles.sessionCandidateForTest = func(op *localVaultFileSessionOperation) {
		staged <- op
	}
	configPath, manifest := f.createVault(t)
	scope := f.scope(configPath, manifest)
	oldOp := a.beginLocalVaultFileSession(scope, []byte(f.password), f.key)
	if oldOp == nil {
		t.Fatal("LOCAL_SESSION_CONCURRENT_OLD_BEGIN_FAILED")
	}
	select {
	case op := <-staged:
		if op != oldOp {
			t.Fatal("LOCAL_SESSION_CONCURRENT_OLD_STAGE_MISMATCH")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("LOCAL_SESSION_CONCURRENT_OLD_OPEN_TIMEOUT")
	}
	oldCandidate := localVaultSessionStagedCandidate(t, oldOp)
	var oldAdopt func()
	select {
	case oldAdopt = <-dispatch:
	case <-time.After(5 * time.Second):
		t.Fatal("LOCAL_SESSION_CONCURRENT_OLD_ADOPT_TIMEOUT")
	}
	a.closeLocalVaultFileSession(scope)
	assertLocalVaultSessionCompleted(t, oldOp, localVaultFileSessionOutcomeCancelled)
	newOp := a.beginLocalVaultFileSession(scope, []byte(f.password), f.key)
	if newOp == nil || newOp == oldOp {
		t.Fatal("LOCAL_SESSION_CONCURRENT_NEW_BEGIN_FAILED")
	}
	select {
	case op := <-staged:
		if op != newOp {
			t.Fatal("LOCAL_SESSION_CONCURRENT_NEW_STAGE_MISMATCH")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("LOCAL_SESSION_CONCURRENT_NEW_OPEN_TIMEOUT")
	}
	newCandidate := localVaultSessionStagedCandidate(t, newOp)
	var newAdopt func()
	select {
	case newAdopt = <-dispatch:
	case <-time.After(5 * time.Second):
		t.Fatal("LOCAL_SESSION_CONCURRENT_NEW_ADOPT_TIMEOUT")
	}
	newAdopt()
	if got := a.localVaultFiles.sessionSlots[scope]; got == nil || got.session != newCandidate || got.operation != nil {
		t.Fatal("LOCAL_SESSION_CONCURRENT_NEW_CANDIDATE_NOT_ADOPTED")
	}
	assertLocalVaultSessionCompleted(t, newOp, localVaultFileSessionOutcomeOpened)
	before := launches.Load()
	oldAdopt()
	if launches.Load() != before {
		t.Fatal("LOCAL_SESSION_CONCURRENT_STALE_CALLBACK_CHANGED_CLEANUP")
	}
	// Joining the same exact close is idempotent and never locks the parent.
	_ = oldCandidate.Close()
	if _, err := oldCandidate.Summary(); err == nil {
		t.Fatal("LOCAL_SESSION_CONCURRENT_STALE_CANDIDATE_NOT_CLOSED")
	}
	summary, err := newCandidate.Summary()
	if err != nil || summary.VaultID != manifest.VaultID {
		t.Fatal("LOCAL_SESSION_CONCURRENT_NEW_CANDIDATE_LOST")
	}
}

func TestDesktopLocalVaultSessionParentLockStopsCachedMetadata(t *testing.T) {
	f := newLocalVaultSessionFixture(t)
	q := &localVaultSessionQueue{}
	q.install(f.app)
	aPath, aManifest := f.createVault(t)
	bPath, bManifest := f.createVault(t)
	aScope, bScope := f.scope(aPath, aManifest), f.scope(bPath, bManifest)
	f.openVault(t, q, aScope)
	f.openVault(t, q, bScope)
	generation := f.app.generation
	aSlot := f.app.localVaultFiles.sessionSlots[aScope]
	bSlot := f.app.localVaultFiles.sessionSlots[bScope]
	if aSlot == nil || bSlot == nil || aSlot.session == nil || bSlot.session == nil {
		t.Fatal("LOCAL_SESSION_PARENT_LOCK_SETUP_FAILED")
	}
	aSession, bSession := aSlot.session, bSlot.session
	pending := f.app.beginLocalVaultFileSession(bScope, []byte(f.password), f.key)
	if pending == nil || pending.slot != bSlot {
		t.Fatal("LOCAL_SESSION_PARENT_LOCK_PENDING_MISSING")
	}

	f.parent.Lock()
	if f.parent.Unlocked() {
		t.Fatal("LOCAL_SESSION_PARENT_LOCK_NOT_REAL")
	}
	if f.app.session != f.parent || f.app.generation != generation {
		t.Fatal("LOCAL_SESSION_PARENT_LOCK_BOUNDARY_CHANGED")
	}
	if _, ok := f.app.readLocalVaultFileSession(aScope); ok {
		t.Fatal("LOCAL_SESSION_PARENT_LOCK_CACHE_DELIVERED")
	}
	if len(f.app.localVaultFiles.sessionSlots) != 0 ||
		f.app.localVaultFiles.sessionParent != nil ||
		f.app.localVaultFiles.sessionGeneration != 0 {
		t.Fatal("LOCAL_SESSION_PARENT_LOCK_REGISTRY_RETAINED")
	}
	if pending.finiteOutcome() != localVaultFileSessionOutcomeCancelled ||
		pending.slot.operation != nil || pending.slot.session != nil {
		t.Fatal("LOCAL_SESSION_PARENT_LOCK_PENDING_RETAINED")
	}
	if aSlot.session != nil || aSlot.summary.VaultID != "" || len(aSlot.summary.Items) != 0 {
		t.Fatal("LOCAL_SESSION_PARENT_LOCK_SUMMARY_RETAINED")
	}
	if _, ok := f.app.readLocalVaultFileSession(bScope); ok {
		t.Fatal("LOCAL_SESSION_PARENT_LOCK_SIBLING_CACHE_DELIVERED")
	}
	if f.app.localVaultFiles.sessionParent != nil {
		t.Fatal("LOCAL_SESSION_PARENT_LOCK_REBOUND")
	}
	if _, err := aSession.Summary(); err == nil {
		t.Fatal("LOCAL_SESSION_PARENT_LOCK_CHILD_READABLE")
	}
	if _, err := bSession.Summary(); err == nil {
		t.Fatal("LOCAL_SESSION_PARENT_LOCK_SIBLING_READABLE")
	}
	q.drain(t)
	if _, ok := f.app.readLocalVaultFileSession(aScope); ok ||
		len(f.app.localVaultFiles.sessionSlots) != 0 ||
		f.app.localVaultFiles.sessionParent != nil {
		t.Fatal("LOCAL_SESSION_PARENT_LOCK_CACHE_REVIVED")
	}
}

func TestDesktopLocalVaultSessionBusyPreservesCacheAndSibling(t *testing.T) {
	f := newLocalVaultSessionFixture(t)
	q := &localVaultSessionQueue{}
	q.install(f.app)
	aPath, aManifest := f.createVault(t)
	bPath, bManifest := f.createVault(t)
	aScope, bScope := f.scope(aPath, aManifest), f.scope(bPath, bManifest)
	f.openVault(t, q, aScope)
	f.openVault(t, q, bScope)
	bSlot := f.app.localVaultFiles.sessionSlots[bScope]
	if bSlot == nil || bSlot.session == nil || bSlot.summary.VaultID != bManifest.VaultID {
		t.Fatal("LOCAL_SESSION_BUSY_SETUP_FAILED")
	}
	bSession := bSlot.session
	parent, generation := f.app.session, f.app.generation
	release := holdDesktopParentDBBusy(t, f)
	if f.app.session != parent || f.app.generation != generation ||
		f.app.localVaultFiles.sessionParent != parent {
		t.Fatal("LOCAL_SESSION_BUSY_PARENT_BOUNDARY_CHANGED")
	}

	if _, ok := f.app.readLocalVaultFileSession(bScope); ok {
		t.Fatal("LOCAL_SESSION_BUSY_CACHE_DELIVERED")
	}
	if _, ok := f.app.readLocalVaultFileSession(aScope); ok {
		t.Fatal("LOCAL_SESSION_BUSY_SIBLING_CACHE_DELIVERED")
	}
	if len(f.app.localVaultFiles.sessionSlots) != 2 ||
		f.app.localVaultFiles.sessionSlots[bScope] != bSlot ||
		bSlot.session != bSession || bSlot.summary.VaultID != bManifest.VaultID {
		t.Fatal("LOCAL_SESSION_BUSY_RETREATED_REGISTRY")
	}
	if op := f.app.beginLocalVaultFileSession(aScope, []byte(f.password), f.key); op != nil {
		t.Fatal("LOCAL_SESSION_BUSY_BEGIN_AUTHORIZED")
	}
	if len(f.app.localVaultFiles.sessionSlots) != 2 ||
		f.app.localVaultFiles.sessionSlots[bScope] != bSlot || bSlot.session != bSession {
		t.Fatal("LOCAL_SESSION_BUSY_BEGIN_RETREATED_REGISTRY")
	}

	release()
	if read, ok := f.app.readLocalVaultFileSession(bScope); !ok || read.VaultID != bManifest.VaultID {
		t.Fatal("LOCAL_SESSION_BUSY_CACHE_NOT_RESTORED")
	}
	summary, err := bSession.Summary()
	if err != nil || summary.VaultID != bManifest.VaultID {
		t.Fatal("LOCAL_SESSION_BUSY_SIBLING_LOST")
	}
}

func TestDesktopLocalVaultSessionHeldDispatchCancelClosesPendingCandidate(t *testing.T) {
	f := newLocalVaultSessionFixture(t)
	q := &localVaultSessionQueue{}
	q.install(f.app)
	aPath, aManifest := f.createVault(t)
	bPath, bManifest := f.createVault(t)
	aScope, bScope := f.scope(aPath, aManifest), f.scope(bPath, bManifest)
	f.openVault(t, q, bScope)
	bSlot := f.app.localVaultFiles.sessionSlots[bScope]
	if bSlot == nil || bSlot.session == nil {
		t.Fatal("LOCAL_SESSION_HELD_DISPATCH_SETUP_FAILED")
	}
	bSession := bSlot.session
	op := f.app.beginLocalVaultFileSession(aScope, []byte(f.password), f.key)
	if op == nil {
		t.Fatal("LOCAL_SESSION_HELD_DISPATCH_BEGIN_FAILED")
	}
	q.runLaunch(t)
	candidate := localVaultSessionStagedCandidate(t, op)
	if len(q.dispatches) != 1 {
		t.Fatal("LOCAL_SESSION_HELD_DISPATCH_NOT_STAGED")
	}

	f.app.closeLocalVaultFileSession(aScope)
	assertLocalVaultSessionCompleted(t, op, localVaultFileSessionOutcomeCancelled)
	q.drainLaunches(t)
	if _, err := candidate.Summary(); err == nil {
		t.Fatal("LOCAL_SESSION_HELD_DISPATCH_CANDIDATE_READABLE")
	}
	summary, err := bSession.Summary()
	if err != nil || summary.VaultID != bManifest.VaultID {
		t.Fatal("LOCAL_SESSION_HELD_DISPATCH_SIBLING_LOST")
	}
	if !f.parent.Unlocked() {
		t.Fatal("LOCAL_SESSION_HELD_DISPATCH_PARENT_LOCKED")
	}
	if len(f.app.localVaultFiles.sessionSlots) != 1 ||
		f.app.localVaultFiles.sessionSlots[bScope] != bSlot || bSlot.session != bSession {
		t.Fatal("LOCAL_SESSION_HELD_DISPATCH_REGISTRY_CHANGED")
	}
	if len(q.dispatches) != 1 {
		t.Fatal("LOCAL_SESSION_HELD_DISPATCH_EXECUTED")
	}
}

func TestDesktopLocalVaultSessionFactoryErrorFinishesCurrentOperation(t *testing.T) {
	f := newLocalVaultSessionFixture(t)
	q := &localVaultSessionQueue{}
	q.install(f.app)
	aPath, aManifest := f.createVault(t)
	bPath, bManifest := f.createVault(t)
	aScope, bScope := f.scope(aPath, aManifest), f.scope(bPath, bManifest)
	f.openVault(t, q, bScope)
	bSlot := f.app.localVaultFiles.sessionSlots[bScope]
	if bSlot == nil || bSlot.session == nil {
		t.Fatal("LOCAL_SESSION_FACTORY_ERROR_SETUP_FAILED")
	}
	bSession := bSlot.session
	op := f.app.beginLocalVaultFileSession(aScope, []byte("wrong-local-factor"), []byte("fedcba0987654321"))
	if op == nil {
		t.Fatal("LOCAL_SESSION_FACTORY_ERROR_BEGIN_FAILED")
	}
	q.runLaunch(t)
	result := localVaultSessionStagedResult(t, op)
	if result.outcome != localVaultFileSessionOutcomeFailed || result.candidate != nil {
		t.Fatal("LOCAL_SESSION_FACTORY_ERROR_NOT_STAGED")
	}
	q.runDispatch(t)
	assertLocalVaultSessionCompleted(t, op, localVaultFileSessionOutcomeFailed)
	slot := f.app.localVaultFiles.sessionSlots[aScope]
	if slot == nil || slot.operation != nil || slot.session != nil {
		t.Fatal("LOCAL_SESSION_FACTORY_ERROR_OPERATION_RETAINED")
	}
	summary, err := bSession.Summary()
	if err != nil || summary.VaultID != bManifest.VaultID {
		t.Fatal("LOCAL_SESSION_FACTORY_ERROR_SIBLING_LOST")
	}
}

func TestDesktopLocalVaultSessionWorkspaceChangeFinishesCurrentOperation(t *testing.T) {
	f := newLocalVaultSessionFixture(t)
	q := &localVaultSessionQueue{}
	q.install(f.app)
	aPath, aManifest := f.createVault(t)
	bPath, bManifest := f.createVault(t)
	aScope, bScope := f.scope(aPath, aManifest), f.scope(bPath, bManifest)
	f.openVault(t, q, bScope)
	bSlot := f.app.localVaultFiles.sessionSlots[bScope]
	if bSlot == nil || bSlot.session == nil {
		t.Fatal("LOCAL_SESSION_WORKSPACE_SETUP_FAILED")
	}
	bSession := bSlot.session
	op := f.app.beginLocalVaultFileSession(aScope, []byte(f.password), f.key)
	if op == nil {
		t.Fatal("LOCAL_SESSION_WORKSPACE_BEGIN_FAILED")
	}
	q.runLaunch(t)
	candidate := localVaultSessionStagedCandidate(t, op)
	f.app.settingsPath = filepath.Join(f.root, "changed-settings", "settings.json")
	q.runDispatch(t)
	assertLocalVaultSessionCompleted(t, op, localVaultFileSessionOutcomeFailed)
	q.drainLaunches(t)
	if _, err := candidate.Summary(); err == nil {
		t.Fatal("LOCAL_SESSION_WORKSPACE_CANDIDATE_READABLE")
	}
	slot := f.app.localVaultFiles.sessionSlots[aScope]
	if slot == nil || slot.operation != nil || slot.session != nil {
		t.Fatal("LOCAL_SESSION_WORKSPACE_OPERATION_RETAINED")
	}
	summary, err := bSession.Summary()
	if err != nil || summary.VaultID != bManifest.VaultID {
		t.Fatal("LOCAL_SESSION_WORKSPACE_SIBLING_LOST")
	}
}

func TestDesktopLocalVaultSessionLateFailureDoesNotClearLaterOperation(t *testing.T) {
	f := newLocalVaultSessionFixture(t)
	q := &localVaultSessionQueue{}
	q.install(f.app)
	aPath, aManifest := f.createVault(t)
	bPath, bManifest := f.createVault(t)
	aScope, bScope := f.scope(aPath, aManifest), f.scope(bPath, bManifest)
	f.openVault(t, q, bScope)
	bSlot := f.app.localVaultFiles.sessionSlots[bScope]
	if bSlot == nil || bSlot.session == nil {
		t.Fatal("LOCAL_SESSION_LATE_FAILURE_SETUP_FAILED")
	}
	bSession := bSlot.session
	oldOp := f.app.beginLocalVaultFileSession(aScope, []byte("wrong-local-factor"), []byte("fedcba0987654321"))
	if oldOp == nil {
		t.Fatal("LOCAL_SESSION_LATE_FAILURE_OLD_BEGIN_FAILED")
	}
	q.runLaunch(t)
	oldDispatch := q.dispatches[0]
	q.dispatches = nil
	f.app.closeLocalVaultFileSession(aScope)
	assertLocalVaultSessionCompleted(t, oldOp, localVaultFileSessionOutcomeCancelled)
	newOp := f.app.beginLocalVaultFileSession(aScope, []byte(f.password), f.key)
	if newOp == nil || newOp == oldOp {
		t.Fatal("LOCAL_SESSION_LATE_FAILURE_NEW_BEGIN_FAILED")
	}
	q.runLaunch(t)
	newCandidate := localVaultSessionStagedCandidate(t, newOp)
	newDispatch := q.dispatches[0]
	q.dispatches = nil
	newDispatch()
	assertLocalVaultSessionCompleted(t, newOp, localVaultFileSessionOutcomeOpened)
	slot := f.app.localVaultFiles.sessionSlots[aScope]
	if slot == nil || slot.session != newCandidate || slot.operation != nil {
		t.Fatal("LOCAL_SESSION_LATE_FAILURE_NEW_OPERATION_NOT_ADOPTED")
	}
	oldDispatch()
	if got := f.app.localVaultFiles.sessionSlots[aScope]; got != slot || slot.session != newCandidate {
		t.Fatal("LOCAL_SESSION_LATE_FAILURE_CLEARED_NEW_OPERATION")
	}
	assertLocalVaultSessionCompleted(t, newOp, localVaultFileSessionOutcomeOpened)
	summary, err := bSession.Summary()
	if err != nil || summary.VaultID != bManifest.VaultID {
		t.Fatal("LOCAL_SESSION_LATE_FAILURE_SIBLING_LOST")
	}
}

func TestDesktopLocalVaultSessionBusyAdoptFinishesOperation(t *testing.T) {
	f := newLocalVaultSessionFixture(t)
	q := &localVaultSessionQueue{}
	q.install(f.app)
	aPath, aManifest := f.createVault(t)
	bPath, bManifest := f.createVault(t)
	aScope, bScope := f.scope(aPath, aManifest), f.scope(bPath, bManifest)
	f.openVault(t, q, bScope)
	bSlot := f.app.localVaultFiles.sessionSlots[bScope]
	if bSlot == nil || bSlot.session == nil {
		t.Fatal("LOCAL_SESSION_BUSY_ADOPT_SETUP_FAILED")
	}
	bSession := bSlot.session
	op := f.app.beginLocalVaultFileSession(aScope, []byte(f.password), f.key)
	if op == nil {
		t.Fatal("LOCAL_SESSION_BUSY_ADOPT_BEGIN_FAILED")
	}
	q.runLaunch(t)
	candidate := localVaultSessionStagedCandidate(t, op)
	if len(q.dispatches) != 1 {
		t.Fatal("LOCAL_SESSION_BUSY_ADOPT_NOT_STAGED")
	}
	release := holdDesktopParentDBBusy(t, f)
	q.runDispatch(t)
	assertLocalVaultSessionCompleted(t, op, localVaultFileSessionOutcomeFailed)
	slot := f.app.localVaultFiles.sessionSlots[aScope]
	if slot == nil || slot.operation != nil || slot.session != nil {
		t.Fatal("LOCAL_SESSION_BUSY_ADOPT_OPERATION_RETAINED")
	}
	if f.app.localVaultFiles.sessionSlots[bScope] != bSlot || bSlot.session != bSession {
		t.Fatal("LOCAL_SESSION_BUSY_ADOPT_SIBLING_RETREATED")
	}
	q.drainLaunches(t)
	if _, err := candidate.Summary(); err == nil {
		t.Fatal("LOCAL_SESSION_BUSY_ADOPT_CANDIDATE_READABLE")
	}
	release()
	if read, ok := f.app.readLocalVaultFileSession(bScope); !ok || read.VaultID != bManifest.VaultID {
		t.Fatal("LOCAL_SESSION_BUSY_ADOPT_CACHE_NOT_RESTORED")
	}
	summary, err := bSession.Summary()
	if err != nil || summary.VaultID != bManifest.VaultID {
		t.Fatal("LOCAL_SESSION_BUSY_ADOPT_SIBLING_LOST")
	}
}
