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
	var candidates []*vaultfileclient.LocalGenesisSession
	f.app.localVaultFiles.sessionCandidateForTest = func(_ *localVaultFileSessionOperation, candidate *vaultfileclient.LocalGenesisSession) {
		candidates = append(candidates, candidate)
	}
	configPath, manifest := f.createVault(t)
	scope := f.scope(configPath, manifest)
	oldOp := f.app.beginLocalVaultFileSession(scope, []byte(f.password), f.key)
	if oldOp == nil {
		t.Fatal("LOCAL_SESSION_OLD_BEGIN_FAILED")
	}
	q.runLaunch(t)
	if len(candidates) != 1 || len(q.dispatches) != 1 {
		t.Fatal("LOCAL_SESSION_OLD_CANDIDATE_NOT_PENDING")
	}
	f.app.closeLocalVaultFileSession(scope)
	if !oldOp.canceled {
		t.Fatal("LOCAL_SESSION_OLD_OPERATION_NOT_CANCELED")
	}
	newOp := f.app.beginLocalVaultFileSession(scope, []byte(f.password), f.key)
	if newOp == nil || newOp == oldOp {
		t.Fatal("LOCAL_SESSION_NEW_BEGIN_FAILED")
	}
	q.runLaunch(t)
	if len(candidates) != 2 || len(q.dispatches) != 2 {
		t.Fatal("LOCAL_SESSION_NEW_CANDIDATE_NOT_PENDING")
	}
	oldAdopt, newAdopt := q.dispatches[0], q.dispatches[1]
	q.dispatches = nil
	newAdopt()
	if got := f.app.localVaultFiles.sessionSlots[scope]; got == nil || got.session != candidates[1] {
		t.Fatal("LOCAL_SESSION_NEW_CANDIDATE_NOT_ADOPTED")
	}
	oldAdopt()
	if got := f.app.localVaultFiles.sessionSlots[scope]; got == nil || got.session != candidates[1] {
		t.Fatal("LOCAL_SESSION_STALE_CANDIDATE_REMOVED_NEW_SLOT")
	}
	q.drain(t)
	if _, err := candidates[0].Summary(); err == nil {
		t.Fatal("LOCAL_SESSION_STALE_CANDIDATE_NOT_CLOSED")
	}
	summary, err := candidates[1].Summary()
	if err != nil || summary.VaultID != manifest.VaultID {
		t.Fatal("LOCAL_SESSION_NEW_CANDIDATE_LOST")
	}
}

func TestDesktopLocalVaultSessionParentChangeRejectsCapturedCandidate(t *testing.T) {
	f := newLocalVaultSessionFixture(t)
	q := &localVaultSessionQueue{}
	q.install(f.app)
	var candidates []*vaultfileclient.LocalGenesisSession
	f.app.localVaultFiles.sessionCandidateForTest = func(_ *localVaultFileSessionOperation, candidate *vaultfileclient.LocalGenesisSession) {
		candidates = append(candidates, candidate)
	}
	aPath, aManifest := f.createVault(t)
	bPath, bManifest := f.createVault(t)
	aScope, bScope := f.scope(aPath, aManifest), f.scope(bPath, bManifest)
	f.openVault(t, q, aScope)
	f.openVault(t, q, bScope)
	aSession := f.app.localVaultFiles.sessionSlots[aScope].session
	bSession := f.app.localVaultFiles.sessionSlots[bScope].session
	candidates = nil

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
	for len(q.launches) != 0 {
		q.runLaunch(t)
	}
	if len(candidates) != 1 {
		t.Fatal("LOCAL_SESSION_CAPTURED_PARENT_NOT_USED")
	}
	q.drain(t)
	if len(f.app.localVaultFiles.sessionSlots) != 0 {
		t.Fatal("LOCAL_SESSION_PARENT_CHANGE_RETAINED_SLOTS")
	}
	for _, session := range []*vaultfileclient.LocalGenesisSession{aSession, bSession, candidates[0]} {
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
	var candidates []*vaultfileclient.LocalGenesisSession
	f.app.localVaultFiles.sessionCandidateForTest = func(_ *localVaultFileSessionOperation, candidate *vaultfileclient.LocalGenesisSession) {
		candidates = append(candidates, candidate)
	}
	aPath, aManifest := f.createVault(t)
	bPath, bManifest := f.createVault(t)
	aScope, bScope := f.scope(aPath, aManifest), f.scope(bPath, bManifest)
	f.openVault(t, q, aScope)
	f.openVault(t, q, bScope)
	aSession := f.app.localVaultFiles.sessionSlots[aScope].session
	bSession := f.app.localVaultFiles.sessionSlots[bScope].session
	candidates = nil
	if op := f.app.beginLocalVaultFileSession(aScope, []byte(f.password), f.key); op == nil {
		t.Fatal("LOCAL_SESSION_LOCK_PENDING_BEGIN_FAILED")
	}
	for len(q.launches) != 0 {
		q.runLaunch(t)
	}
	if len(candidates) != 1 || len(q.dispatches) != 1 {
		t.Fatal("LOCAL_SESSION_GLOBAL_LOCK_CANDIDATE_NOT_PENDING")
	}
	f.app.Lock()
	if len(f.app.localVaultFiles.sessionSlots) != 0 || f.app.localVaultFiles.sessionParent != nil ||
		f.app.localVaultFiles.selected != "" || f.app.localVaultFiles.items != nil {
		t.Fatal("LOCAL_SESSION_GLOBAL_LOCK_RETAINED_STATE")
	}
	q.drain(t)
	for _, session := range []*vaultfileclient.LocalGenesisSession{aSession, bSession, candidates[0]} {
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
	opened := make(chan *vaultfileclient.LocalGenesisSession, 2)
	var launches atomic.Int64
	a.dispatch = func(fn func()) { dispatch <- fn }
	a.launch = func(fn func()) {
		launches.Add(1)
		go fn()
	}
	a.localVaultFiles.sessionCandidateForTest = func(_ *localVaultFileSessionOperation, candidate *vaultfileclient.LocalGenesisSession) {
		opened <- candidate
	}
	configPath, manifest := f.createVault(t)
	scope := f.scope(configPath, manifest)
	oldOp := a.beginLocalVaultFileSession(scope, []byte(f.password), f.key)
	if oldOp == nil {
		t.Fatal("LOCAL_SESSION_CONCURRENT_OLD_BEGIN_FAILED")
	}
	var oldCandidate *vaultfileclient.LocalGenesisSession
	select {
	case oldCandidate = <-opened:
	case <-time.After(5 * time.Second):
		t.Fatal("LOCAL_SESSION_CONCURRENT_OLD_OPEN_TIMEOUT")
	}
	var oldAdopt func()
	select {
	case oldAdopt = <-dispatch:
	case <-time.After(5 * time.Second):
		t.Fatal("LOCAL_SESSION_CONCURRENT_OLD_ADOPT_TIMEOUT")
	}
	a.closeLocalVaultFileSession(scope)
	newOp := a.beginLocalVaultFileSession(scope, []byte(f.password), f.key)
	if newOp == nil || newOp == oldOp {
		t.Fatal("LOCAL_SESSION_CONCURRENT_NEW_BEGIN_FAILED")
	}
	var newCandidate *vaultfileclient.LocalGenesisSession
	select {
	case newCandidate = <-opened:
	case <-time.After(5 * time.Second):
		t.Fatal("LOCAL_SESSION_CONCURRENT_NEW_OPEN_TIMEOUT")
	}
	var newAdopt func()
	select {
	case newAdopt = <-dispatch:
	case <-time.After(5 * time.Second):
		t.Fatal("LOCAL_SESSION_CONCURRENT_NEW_ADOPT_TIMEOUT")
	}
	newAdopt()
	if got := a.localVaultFiles.sessionSlots[scope]; got == nil || got.session != newCandidate {
		t.Fatal("LOCAL_SESSION_CONCURRENT_NEW_CANDIDATE_NOT_ADOPTED")
	}
	before := launches.Load()
	oldAdopt()
	if launches.Load() != before+1 {
		t.Fatal("LOCAL_SESSION_CONCURRENT_STALE_CLOSE_NOT_LAUNCHED")
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
