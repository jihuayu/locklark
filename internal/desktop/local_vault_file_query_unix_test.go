//go:build darwin || linux

package desktop

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/vaultfileclient"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
)

const (
	desktopLocalVaultQueryTitle = "Shared exact local title"
	desktopLocalVaultQueryIDA   = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	desktopLocalVaultQueryIDB   = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

type desktopLocalVaultQueryFixture struct {
	f         *localVaultSessionFixture
	app       *App
	queue     *localVaultSessionQueue
	aPath     string
	bPath     string
	aManifest vaultfileclient.Manifest
	bManifest vaultfileclient.Manifest
}

func newDesktopLocalVaultQueryFixture(t *testing.T) *desktopLocalVaultQueryFixture {
	t.Helper()
	f := newLocalVaultSessionFixture(t)
	aPath, aManifest := f.createVault(t)
	bPath, bManifest := f.createVault(t)
	if aManifest.PersonalFile != bManifest.PersonalFile ||
		aManifest.VaultID == bManifest.VaultID ||
		aManifest.Journal == bManifest.Journal ||
		aManifest.Name == bManifest.Name || aPath == bPath {
		t.Fatal("DESKTOP_LOCAL_QUERY_VAULT_SCOPE_NOT_DISTINCT")
	}

	ctx := context.Background()
	if _, err := vaultfileclient.WriteLocalGenesisFirstItem(ctx, f.parent, aPath,
		aManifest.BackendRoot, aManifest.VaultID, aManifest.Journal,
		[]byte(f.password), f.key, vaultfileclient.LocalGenesisFirstItem{
			ID: desktopLocalVaultQueryIDA, Title: desktopLocalVaultQueryTitle,
			Username: "local-query-a", Password: "local-query-secret-a",
		}); err != nil {
		t.Fatalf("DESKTOP_LOCAL_QUERY_WRITE_A_FAILED: %v", err)
	}
	if _, err := vaultfileclient.WriteLocalGenesisFirstItem(ctx, f.parent, bPath,
		bManifest.BackendRoot, bManifest.VaultID, bManifest.Journal,
		[]byte(f.password), f.key, vaultfileclient.LocalGenesisFirstItem{
			ID: desktopLocalVaultQueryIDB, Title: desktopLocalVaultQueryTitle,
			Username: "local-query-b", Password: "local-query-secret-b",
		}); err != nil {
		t.Fatalf("DESKTOP_LOCAL_QUERY_WRITE_B_FAILED: %v", err)
	}

	// Genuinely reopen both persisted vaults through the normal desktop unlock
	// and owned fan-out adoption path, not the write session's wrappers.
	f.parent.Lock()
	app, queue := newInitialFanoutTestApp(t, f, f.settingsPath)
	app.unlock()
	queue.runLaunch(t)
	queue.runDispatch(t)
	queue.drain(t)
	if app.session == nil || !app.session.Unlocked() {
		t.Fatal("DESKTOP_LOCAL_QUERY_REOPEN_SESSION_FAILED")
	}
	if len(app.localVaultFiles.refs) != 2 || len(app.localVaultFiles.sessionSlots) != 2 {
		t.Fatal("DESKTOP_LOCAL_QUERY_REOPEN_VAULTS_FAILED")
	}
	return &desktopLocalVaultQueryFixture{
		f: f, app: app, queue: queue,
		aPath: aPath, bPath: bPath, aManifest: aManifest, bManifest: bManifest,
	}
}

func (fx *desktopLocalVaultQueryFixture) query(t *testing.T) []*localVaultFileQueryHit {
	t.Helper()
	fx.queue.drain(t)
	fx.app.localVaultFiles.query.title = desktopLocalVaultQueryTitle
	fx.app.searchLocalVaultFileExactTitle()
	fx.queue.runLaunch(t)
	fx.queue.runDispatch(t)
	return fx.app.localVaultFileQueryHits()
}

func (fx *desktopLocalVaultQueryFixture) activate(t *testing.T, hit *localVaultFileQueryHit) {
	t.Helper()
	fx.queue.drain(t)
	fx.app.activateLocalVaultFileQueryHit(hit)
	if len(fx.queue.launches) == 0 {
		return
	}
	fx.queue.runLaunch(t)
	fx.queue.runDispatch(t)
	fx.queue.drain(t)
}

func (fx *desktopLocalVaultQueryFixture) hitsByID(t *testing.T, hits []*localVaultFileQueryHit) map[string]*localVaultFileQueryHit {
	t.Helper()
	byID := make(map[string]*localVaultFileQueryHit, len(hits))
	for _, hit := range hits {
		if hit == nil || hit.result == nil {
			t.Fatal("DESKTOP_LOCAL_QUERY_NIL_HIT")
		}
		if _, exists := byID[hit.id]; exists {
			t.Fatal("DESKTOP_LOCAL_QUERY_DUPLICATE_HIT")
		}
		byID[hit.id] = hit
	}
	return byID
}

func desktopLocalVaultQueryDriftA(t *testing.T, manifest vaultfileclient.Manifest) {
	t.Helper()
	backend, err := vaultfilebackend.OpenExistingDir(manifest.BackendRoot)
	if err != nil {
		t.Fatal("DESKTOP_LOCAL_QUERY_DRIFT_BACKEND_OPEN_FAILED")
	}
	before, err := backend.Read(context.Background(), manifest.Name)
	if err != nil {
		_ = backend.Close()
		t.Fatal("DESKTOP_LOCAL_QUERY_DRIFT_READ_FAILED")
	}
	defer clear(before.Bytes)
	if err := backend.ReplaceIfVersion(context.Background(), manifest.Name,
		before.Revision, before.Bytes); err != nil {
		_ = backend.Close()
		t.Fatal("DESKTOP_LOCAL_QUERY_DRIFT_REPLACE_FAILED")
	}
	after, err := backend.Read(context.Background(), manifest.Name)
	closeErr := backend.Close()
	if err != nil || closeErr != nil {
		t.Fatal("DESKTOP_LOCAL_QUERY_DRIFT_VERIFY_FAILED")
	}
	defer clear(after.Bytes)
	if after.Revision == before.Revision {
		t.Fatal("DESKTOP_LOCAL_QUERY_DRIFT_NOT_REAL")
	}
}

func TestDesktopLocalVaultExactQueryActivation(t *testing.T) {
	fx := newDesktopLocalVaultQueryFixture(t)

	// Start a real query; the shared View/ticker scheduler is driven explicitly
	// below so its interval mechanics are deterministic.
	hits := fx.query(t)
	if len(hits) != 2 {
		t.Fatalf("DESKTOP_LOCAL_QUERY_ROW_COUNT_FAILED: %d", len(hits))
	}
	byID := fx.hitsByID(t, hits)
	hitA, hitB := byID[desktopLocalVaultQueryIDA], byID[desktopLocalVaultQueryIDB]
	if hitA == nil || hitB == nil {
		t.Fatal("DESKTOP_LOCAL_QUERY_IDS_NOT_INDEPENDENT")
	}
	if hitA.title != desktopLocalVaultQueryTitle || hitB.title != desktopLocalVaultQueryTitle ||
		hitA.result.scope == hitB.result.scope ||
		hitA.result.scope.configPath == hitB.result.scope.configPath ||
		hitA.result.scope.vaultID == hitB.result.scope.vaultID ||
		hitA.result.scope.journalPath == hitB.result.scope.journalPath ||
		hitA.result.wrapper == hitB.result.wrapper {
		t.Fatal("DESKTOP_LOCAL_QUERY_ROWS_NOT_INDEPENDENTLY_SCOPED")
	}
	// Deterministic throttle window: initial launch is immediate, one sweep is
	// in flight, rapid ticks inside the interval add nothing, and the eligible
	// tick starts exactly one more.
	queryNow := time.Unix(1_800_000_000, 0)
	if len(fx.queue.launches) != 0 {
		t.Fatal("DESKTOP_LOCAL_QUERY_SWEEP_AUTO_STARTED")
	}
	if fx.app.scheduleLocalVaultFileQueryRevalidationAt(queryNow) == nil {
		t.Fatal("DESKTOP_LOCAL_QUERY_INITIAL_SWEEP_NOT_STARTED")
	}
	if len(fx.queue.launches) != 1 {
		t.Fatal("DESKTOP_LOCAL_QUERY_INITIAL_SWEEP_NOT_QUEUED")
	}
	if fx.app.scheduleLocalVaultFileQueryRevalidationAt(queryNow) != nil ||
		len(fx.queue.launches) != 1 {
		t.Fatal("DESKTOP_LOCAL_QUERY_PARALLEL_SWEEP_STARTED")
	}
	// Drive the production sweep without drift; both original results remain.
	fx.queue.runLaunch(t)
	fx.queue.runDispatch(t)
	fx.queue.drain(t)
	if len(fx.app.localVaultFileQueryHits()) != 2 {
		t.Fatal("DESKTOP_LOCAL_QUERY_CLEAN_SWEEP_DROPPED_RESULT")
	}
	if fx.app.scheduleLocalVaultFileQueryRevalidationAt(queryNow.Add(time.Second)) != nil ||
		len(fx.queue.launches) != 0 {
		t.Fatal("DESKTOP_LOCAL_QUERY_RAPID_TICK_STARTED_SWEEP")
	}
	if fx.app.scheduleLocalVaultFileQueryRevalidationAt(queryNow.Add(localVaultFileQueryRevalidationMinStart)) == nil ||
		len(fx.queue.launches) != 1 {
		t.Fatal("DESKTOP_LOCAL_QUERY_ELIGIBLE_TICK_NOT_STARTED")
	}
	if fx.app.scheduleLocalVaultFileQueryRevalidationAt(queryNow.Add(localVaultFileQueryRevalidationMinStart)) != nil ||
		len(fx.queue.launches) != 1 {
		t.Fatal("DESKTOP_LOCAL_QUERY_ELIGIBLE_TICK_STARTED_PARALLEL_SWEEP")
	}
	fx.queue.runLaunch(t)
	fx.queue.runDispatch(t)
	fx.queue.drain(t)

	// Finding 1: a retained row from a finished query must not activate after
	// the query input changed and before another query was launched.
	oldA := hitA
	fx.app.localVaultFiles.query.title = desktopLocalVaultQueryTitle + " changed"
	fx.app.localVaultFileQueryChanged()
	if len(fx.app.localVaultFiles.query.results) != 0 ||
		fx.app.localVaultFiles.query.current != nil ||
		fx.app.localVaultFiles.query.sweep != nil {
		t.Fatal("DESKTOP_LOCAL_QUERY_EDIT_RETAINED_RESULT")
	}
	selectedBefore := fx.app.localVaultFiles.selected
	activeBefore := fx.app.localVaultFiles.activeItem
	fx.app.activateLocalVaultFileQueryHit(oldA)
	if len(fx.queue.launches) != 0 || len(fx.queue.dispatches) != 0 {
		t.Fatal("DESKTOP_LOCAL_QUERY_EDIT_OLD_CLICK_QUEUED")
	}
	if fx.app.localVaultFiles.query.activation != nil ||
		fx.app.localVaultFiles.selected != selectedBefore ||
		fx.app.localVaultFiles.activeItem != activeBefore {
		t.Fatal("DESKTOP_LOCAL_QUERY_EDIT_OLD_CLICK_ACTIVATED")
	}
	if len(oldA.result.proof.Hits) != 1 {
		t.Fatal("DESKTOP_LOCAL_QUERY_EDIT_OLD_CLICK_CONSUMED_PROOF")
	}

	// Same-generation exact activations still work, and a cross-wrapper proof
	// remains rejected both by the real client wrapper and by the desktop
	// membership gate.
	hits = fx.query(t)
	byID = fx.hitsByID(t, hits)
	hitA, hitB = byID[desktopLocalVaultQueryIDA], byID[desktopLocalVaultQueryIDB]
	if hitA == nil || hitB == nil {
		t.Fatal("DESKTOP_LOCAL_QUERY_SECOND_QUERY_MISSING")
	}
	// A new generation is immediately eligible even though the old generation's
	// minimum-start hold has not expired.
	if fx.app.scheduleLocalVaultFileQueryRevalidationAt(queryNow.Add(time.Second)) == nil ||
		len(fx.queue.launches) != 1 {
		t.Fatal("DESKTOP_LOCAL_QUERY_NEW_GENERATION_INHERITED_HOLD")
	}
	if err := hitB.result.wrapper.ValidateExactQueryHit(hitA.result.proof,
		hitA.id, hitA.title); !errors.Is(err, vaultfileclient.ErrLocalReview) {
		t.Fatal("DESKTOP_LOCAL_QUERY_CROSS_PROOF_ACCEPTED")
	}
	cross := &localVaultFileQueryHit{result: hitB.result, id: hitA.id, title: hitA.title}
	selectedBefore = fx.app.localVaultFiles.selected
	fx.activate(t, cross)
	if fx.app.localVaultFiles.selected != selectedBefore {
		t.Fatal("DESKTOP_LOCAL_QUERY_CROSS_PROOF_SELECTED")
	}
	if active, ok := fx.app.localVaultFileActiveItemCurrent(); ok {
		t.Fatal("DESKTOP_LOCAL_QUERY_CROSS_PROOF_ACTIVATED: " + active.id)
	}

	fx.activate(t, hitA)
	active, ok := fx.app.localVaultFileActiveItemCurrent()
	if fx.app.localVaultFiles.selected != fx.aPath || !ok ||
		active.id != desktopLocalVaultQueryIDA {
		t.Fatal("DESKTOP_LOCAL_QUERY_ACTIVATE_A_FAILED")
	}

	hits = fx.query(t)
	byID = fx.hitsByID(t, hits)
	hitB = byID[desktopLocalVaultQueryIDB]
	if hitB == nil {
		t.Fatal("DESKTOP_LOCAL_QUERY_B_MISSING_AFTER_A")
	}
	fx.activate(t, hitB)
	active, ok = fx.app.localVaultFileActiveItemCurrent()
	if fx.app.localVaultFiles.selected != fx.bPath || !ok ||
		active.id != desktopLocalVaultQueryIDB {
		t.Fatal("DESKTOP_LOCAL_QUERY_ACTIVATE_B_FAILED")
	}

	// Finding 2: after the query is applied, advance A's named backend without
	// issuing another user query. The scheduled production sweep must clear only
	// stale A while preserving B and B's unused original immutable proof.
	fx.app.closeLocalVaultFileView()
	fx.queue.drain(t)
	fx.app.localVaultFiles.query.title = desktopLocalVaultQueryTitle
	fx.app.searchLocalVaultFileExactTitle()
	fx.queue.runLaunch(t)
	fx.queue.runDispatch(t)
	if fx.app.scheduleLocalVaultFileQueryRevalidationAt(
		queryNow.Add(2*localVaultFileQueryRevalidationMinStart)) == nil ||
		len(fx.queue.launches) != 1 {
		t.Fatal("DESKTOP_LOCAL_QUERY_BACKGROUND_SWEEP_NOT_QUEUED")
	}
	hits = fx.app.localVaultFileQueryHits()
	byID = fx.hitsByID(t, hits)
	originalA, originalB := byID[desktopLocalVaultQueryIDA], byID[desktopLocalVaultQueryIDB]
	if originalA == nil || originalB == nil {
		t.Fatal("DESKTOP_LOCAL_QUERY_BACKGROUND_SOURCE_MISSING")
	}
	if !fx.app.localVaultFileQueryHitAuthorized(originalB) ||
		!fx.app.localVaultFileQueryResultAuthorized(originalB.result) ||
		!fx.app.localVaultFileQueryResultCurrent(originalB.result) ||
		originalB.result.queryGeneration != fx.app.localVaultFiles.query.sequence ||
		originalB.result.queryOperation != fx.app.localVaultFiles.query.current {
		t.Fatal("DESKTOP_LOCAL_QUERY_BACKGROUND_B_NOT_CURRENT_BEFORE_DRIFT")
	}
	if fx.app.localVaultFiles.selected == fx.bPath {
		t.Fatal("DESKTOP_LOCAL_QUERY_BACKGROUND_B_PRESELECTED")
	}
	if _, ok := fx.app.localVaultFileActiveItemCurrent(); ok {
		t.Fatal("DESKTOP_LOCAL_QUERY_BACKGROUND_ACTIVE_ITEM_BEFORE_ACTIVATION")
	}
	desktopLocalVaultQueryDriftA(t, fx.aManifest)
	fx.queue.runLaunch(t)
	fx.queue.runDispatch(t)
	// The close of the failed exact A wrapper may still be queued; the display
	// contract is already published by the completed sweep.
	after := fx.app.localVaultFileQueryHits()
	if len(after) != 1 || after[0].id != desktopLocalVaultQueryIDB ||
		after[0] != originalB {
		t.Fatal("DESKTOP_LOCAL_QUERY_BACKGROUND_STALE_A_VISIBLE")
	}
	if !fx.app.localVaultFileQueryHitAuthorized(originalB) ||
		!fx.app.localVaultFileQueryResultAuthorized(originalB.result) ||
		!fx.app.localVaultFileQueryResultCurrent(originalB.result) {
		t.Fatal("DESKTOP_LOCAL_QUERY_BACKGROUND_B_MEMBERSHIP_LOST")
	}
	if len(originalA.result.proof.Hits) != 0 {
		t.Fatal("DESKTOP_LOCAL_QUERY_BACKGROUND_STALE_A_PROOF_RETAINED")
	}
	if len(originalB.result.proof.Hits) != 1 {
		t.Fatal("DESKTOP_LOCAL_QUERY_BACKGROUND_B_PROOF_LOST")
	}
	fx.activate(t, originalA)
	if fx.app.localVaultFiles.selected != "" {
		t.Fatal("DESKTOP_LOCAL_QUERY_BACKGROUND_STALE_A_SELECTED")
	}
	if _, ok := fx.app.localVaultFileActiveItemCurrent(); ok {
		t.Fatal("DESKTOP_LOCAL_QUERY_BACKGROUND_STALE_A_ACTIVATED")
	}
	fx.activate(t, originalB)
	active, ok = fx.app.localVaultFileActiveItemCurrent()
	if fx.app.localVaultFiles.selected != fx.bPath || !ok ||
		active.id != desktopLocalVaultQueryIDB || active.title != desktopLocalVaultQueryTitle {
		t.Fatal("DESKTOP_LOCAL_QUERY_BACKGROUND_B_ACTIVATION_FAILED")
	}
}

// desktopLocalVaultQueryHoldOwnSweep starts one real current-query sweep,
// runs its worker, leaves its production dispatch pending so the sweep is
// still current, and then holds the actual parent cache busy. beforeLaunch runs
// after scheduling and before Summary so a test can advance only its chosen
// backend. The returned release is idempotent and registered for cleanup.
func desktopLocalVaultQueryHoldOwnSweep(t *testing.T, fx *desktopLocalVaultQueryFixture,
	now time.Time, beforeLaunch func()) func() {
	t.Helper()
	fx.queue.drain(t)
	sweep := fx.app.scheduleLocalVaultFileQueryRevalidationAt(now)
	if sweep == nil || len(fx.queue.launches) != 1 {
		t.Fatal("DESKTOP_LOCAL_QUERY_OWN_SWEEP_NOT_STARTED")
	}
	if beforeLaunch != nil {
		beforeLaunch()
	}
	fx.queue.runLaunch(t)
	if len(fx.queue.dispatches) != 1 ||
		fx.app.localVaultFiles.query.sweep != sweep {
		t.Fatal("DESKTOP_LOCAL_QUERY_OWN_SWEEP_DID_NOT_STAY_CURRENT")
	}
	return holdDesktopParentDBBusy(t, &localVaultSessionFixture{parent: fx.app.session})
}

func TestDesktopLocalVaultExactQueryActivationSurvivesOwnSweep(t *testing.T) {
	fx := newDesktopLocalVaultQueryFixture(t)
	hits := fx.query(t)
	byID := fx.hitsByID(t, hits)
	hitB := byID[desktopLocalVaultQueryIDB]
	if hitB == nil {
		t.Fatal("DESKTOP_LOCAL_QUERY_OWN_SWEEP_B_MISSING")
	}
	queryNow := time.Unix(1_800_000_000, 0)
	release := desktopLocalVaultQueryHoldOwnSweep(t, fx, queryNow, nil)

	// The exact B row is enabled and current, while the owned sweep is still
	// current and the real parent cache is transiently Busy. The click must be
	// held as one exact operation, not authenticated and not reported failed.
	fx.app.activateLocalVaultFileQueryHit(hitB)
	pending := fx.app.localVaultFiles.query.pendingActivation
	if pending == nil || pending.hit != hitB || pending.result != hitB.result ||
		fx.app.localVaultFiles.query.activation != nil ||
		len(fx.queue.launches) != 0 {
		release()
		t.Fatal("DESKTOP_LOCAL_QUERY_OWN_SWEEP_CLICK_NOT_HELD")
	}
	if fx.app.scheduleLocalVaultFileQueryRevalidationAt(
		queryNow.Add(localVaultFileQueryRevalidationMinStart)) != nil ||
		len(fx.queue.launches) != 0 {
		release()
		t.Fatal("DESKTOP_LOCAL_QUERY_OWN_SWEEP_STARTED_SECOND_SWEEP")
	}

	release()
	fx.queue.runDispatch(t)
	if len(fx.queue.launches) != 1 ||
		fx.app.localVaultFiles.query.pendingActivation != nil ||
		fx.app.localVaultFiles.query.activation == nil {
		t.Fatal("DESKTOP_LOCAL_QUERY_OWN_SWEEP_CLICK_NOT_RESUMED")
	}
	if fx.app.scheduleLocalVaultFileQueryRevalidationAt(
		queryNow.Add(2*localVaultFileQueryRevalidationMinStart)) != nil ||
		len(fx.queue.launches) != 1 {
		t.Fatal("DESKTOP_LOCAL_QUERY_ACTIVATION_STARTED_PARALLEL_SWEEP")
	}
	fx.queue.runLaunch(t)
	if fx.app.scheduleLocalVaultFileQueryRevalidationAt(
		queryNow.Add(3*localVaultFileQueryRevalidationMinStart)) != nil ||
		len(fx.queue.launches) != 0 {
		t.Fatal("DESKTOP_LOCAL_QUERY_ACTIVATION_IN_FLIGHT_STARTED_SWEEP")
	}
	fx.queue.runDispatch(t)
	fx.queue.drain(t)
	active, ok := fx.app.localVaultFileActiveItemCurrent()
	if fx.app.localVaultFiles.selected != fx.bPath || !ok ||
		active.id != desktopLocalVaultQueryIDB ||
		active.title != desktopLocalVaultQueryTitle {
		t.Fatal("DESKTOP_LOCAL_QUERY_OWN_SWEEP_B_ACTIVATION_FAILED")
	}
}

func TestDesktopLocalVaultExactQueryActivationRefusesStaleOwnSweepClick(t *testing.T) {
	t.Run("background-stale-hit", func(t *testing.T) {
		fx := newDesktopLocalVaultQueryFixture(t)
		hits := fx.query(t)
		hitB := fx.hitsByID(t, hits)[desktopLocalVaultQueryIDB]
		if hitB == nil {
			t.Fatal("DESKTOP_LOCAL_QUERY_STALE_CLICK_B_MISSING")
		}
		release := desktopLocalVaultQueryHoldOwnSweep(t, fx,
			time.Unix(1_800_000_000, 0), func() {
				desktopLocalVaultQueryDriftA(t, fx.bManifest)
			})
		fx.app.activateLocalVaultFileQueryHit(hitB)
		if fx.app.localVaultFiles.query.pendingActivation == nil {
			release()
			t.Fatal("DESKTOP_LOCAL_QUERY_STALE_CLICK_NOT_HELD")
		}
		release()
		fx.queue.drain(t)
		if fx.app.localVaultFiles.query.pendingActivation != nil ||
			fx.app.localVaultFiles.query.activation != nil ||
			fx.app.localVaultFiles.selected != "" {
			t.Fatal("DESKTOP_LOCAL_QUERY_STALE_CLICK_ACTIVATED")
		}
		if _, ok := fx.app.localVaultFileActiveItemCurrent(); ok {
			t.Fatal("DESKTOP_LOCAL_QUERY_STALE_CLICK_PUBLISHED_ACTIVE")
		}
		after := fx.app.localVaultFileQueryHits()
		if len(after) != 1 || after[0].id != desktopLocalVaultQueryIDA {
			t.Fatal("DESKTOP_LOCAL_QUERY_STALE_CLICK_WIDENED_RESULTS")
		}
	})

	t.Run("busy-at-sweep-dispatch", func(t *testing.T) {
		fx := newDesktopLocalVaultQueryFixture(t)
		hits := fx.query(t)
		byID := fx.hitsByID(t, hits)
		hitA, hitB := byID[desktopLocalVaultQueryIDA], byID[desktopLocalVaultQueryIDB]
		if hitA == nil || hitB == nil {
			t.Fatal("DESKTOP_LOCAL_QUERY_BUSY_DISPATCH_ROWS_MISSING")
		}
		release := desktopLocalVaultQueryHoldOwnSweep(t, fx,
			time.Unix(1_800_000_000, 0), nil)
		fx.app.activateLocalVaultFileQueryHit(hitB)
		if fx.app.localVaultFiles.query.pendingActivation == nil {
			release()
			t.Fatal("DESKTOP_LOCAL_QUERY_BUSY_DISPATCH_CLICK_NOT_HELD")
		}
		// Dispatch the owned sweep's completion while the real parent cache is
		// still Busy. The held click must terminate once, not remain Working.
		fx.queue.runDispatch(t)
		state := &fx.app.localVaultFiles
		if state.query.pendingActivation != nil ||
			state.query.activation != nil ||
			state.query.sweep != nil ||
			len(fx.queue.launches) != 0 {
			release()
			t.Fatal("DESKTOP_LOCAL_QUERY_BUSY_DISPATCH_DELIVERED_WORK")
		}
		if state.query.status != localVaultFileQueryActivationFailed {
			release()
			t.Fatalf("DESKTOP_LOCAL_QUERY_BUSY_DISPATCH_STICKY_STATUS: %q", state.query.status)
		}
		if len(state.query.results) != 2 ||
			!fx.app.localVaultFileQueryHitAuthorized(hitA) ||
			!fx.app.localVaultFileQueryHitAuthorized(hitB) ||
			len(hitA.result.proof.Hits) != 1 ||
			len(hitB.result.proof.Hits) != 1 {
			release()
			t.Fatal("DESKTOP_LOCAL_QUERY_BUSY_DISPATCH_LOST_SIBLING")
		}
		if state.selected != "" {
			release()
			t.Fatal("DESKTOP_LOCAL_QUERY_BUSY_DISPATCH_SELECTED")
		}
		if _, ok := fx.app.localVaultFileActiveItemCurrent(); ok {
			release()
			t.Fatal("DESKTOP_LOCAL_QUERY_BUSY_DISPATCH_PUBLISHED_ACTIVE")
		}
		if len(fx.queue.launches) != 0 || len(fx.queue.dispatches) != 0 {
			release()
			t.Fatal("DESKTOP_LOCAL_QUERY_BUSY_DISPATCH_AUTO_RETRIED")
		}
		release()
		if len(fx.queue.launches) != 0 || len(fx.queue.dispatches) != 0 {
			t.Fatal("DESKTOP_LOCAL_QUERY_BUSY_RELEASE_AUTO_RETRIED")
		}
		if after := fx.app.localVaultFileQueryHits(); len(after) != 2 {
			t.Fatal("DESKTOP_LOCAL_QUERY_BUSY_RELEASE_ROWS_NOT_RESTORED")
		}
		// Only an explicit new user click after the cache clears authenticates.
		fx.app.activateLocalVaultFileQueryHit(hitB)
		if fx.app.localVaultFiles.query.activation == nil ||
			len(fx.queue.launches) != 1 {
			t.Fatal("DESKTOP_LOCAL_QUERY_BUSY_RETRY_NOT_AUTHENTICATED")
		}
		fx.queue.runLaunch(t)
		fx.queue.runDispatch(t)
		fx.queue.drain(t)
		active, ok := fx.app.localVaultFileActiveItemCurrent()
		if fx.app.localVaultFiles.selected != fx.bPath || !ok ||
			active.id != desktopLocalVaultQueryIDB ||
			active.title != desktopLocalVaultQueryTitle {
			t.Fatal("DESKTOP_LOCAL_QUERY_BUSY_RETRY_B_ACTIVATION_FAILED")
		}
	})

	t.Run("lock-target", func(t *testing.T) {
		fx := newDesktopLocalVaultQueryFixture(t)
		hits := fx.query(t)
		hitB := fx.hitsByID(t, hits)[desktopLocalVaultQueryIDB]
		if hitB == nil {
			t.Fatal("DESKTOP_LOCAL_QUERY_LOCK_CLICK_B_MISSING")
		}
		release := desktopLocalVaultQueryHoldOwnSweep(t, fx,
			time.Unix(1_800_000_000, 0), nil)
		fx.app.activateLocalVaultFileQueryHit(hitB)
		if fx.app.localVaultFiles.query.pendingActivation == nil {
			release()
			t.Fatal("DESKTOP_LOCAL_QUERY_LOCK_CLICK_NOT_HELD")
		}
		if fx.app.beginLocalVaultFileLock(hitB.result.scope) == nil {
			release()
			t.Fatal("DESKTOP_LOCAL_QUERY_LOCK_CLICK_LOCK_NOT_STARTED")
		}
		release()
		fx.queue.drain(t)
		if fx.app.localVaultFiles.query.pendingActivation != nil ||
			fx.app.localVaultFiles.query.activation != nil ||
			fx.app.localVaultFiles.selected != "" {
			t.Fatal("DESKTOP_LOCAL_QUERY_LOCK_CLICK_ACTIVATED")
		}
		if _, ok := fx.app.localVaultFileActiveItemCurrent(); ok {
			t.Fatal("DESKTOP_LOCAL_QUERY_LOCK_CLICK_PUBLISHED_ACTIVE")
		}
	})

	t.Run("query-cancel", func(t *testing.T) {
		fx := newDesktopLocalVaultQueryFixture(t)
		hits := fx.query(t)
		hitB := fx.hitsByID(t, hits)[desktopLocalVaultQueryIDB]
		if hitB == nil {
			t.Fatal("DESKTOP_LOCAL_QUERY_CANCEL_CLICK_B_MISSING")
		}
		release := desktopLocalVaultQueryHoldOwnSweep(t, fx,
			time.Unix(1_800_000_000, 0), nil)
		fx.app.activateLocalVaultFileQueryHit(hitB)
		if fx.app.localVaultFiles.query.pendingActivation == nil {
			release()
			t.Fatal("DESKTOP_LOCAL_QUERY_CANCEL_CLICK_NOT_HELD")
		}
		fx.app.localVaultFileQueryChanged()
		if fx.app.localVaultFiles.query.pendingActivation != nil ||
			fx.app.localVaultFiles.query.sweep != nil {
			release()
			t.Fatal("DESKTOP_LOCAL_QUERY_CANCEL_KEPT_PENDING")
		}
		release()
		fx.queue.runDispatch(t)
		fx.queue.drain(t)
		if fx.app.localVaultFiles.query.activation != nil ||
			fx.app.localVaultFiles.selected != "" {
			t.Fatal("DESKTOP_LOCAL_QUERY_CANCEL_CLICK_ACTIVATED")
		}
		if _, ok := fx.app.localVaultFileActiveItemCurrent(); ok {
			t.Fatal("DESKTOP_LOCAL_QUERY_CANCEL_CLICK_PUBLISHED_ACTIVE")
		}
	})

	t.Run("query-replace", func(t *testing.T) {
		fx := newDesktopLocalVaultQueryFixture(t)
		hits := fx.query(t)
		hitB := fx.hitsByID(t, hits)[desktopLocalVaultQueryIDB]
		if hitB == nil {
			t.Fatal("DESKTOP_LOCAL_QUERY_REPLACE_CLICK_B_MISSING")
		}
		release := desktopLocalVaultQueryHoldOwnSweep(t, fx,
			time.Unix(1_800_000_000, 0), nil)
		fx.app.activateLocalVaultFileQueryHit(hitB)
		if fx.app.localVaultFiles.query.pendingActivation == nil {
			release()
			t.Fatal("DESKTOP_LOCAL_QUERY_REPLACE_CLICK_NOT_HELD")
		}
		release()
		fx.app.localVaultFiles.query.title = desktopLocalVaultQueryTitle
		fx.app.searchLocalVaultFileExactTitle()
		if fx.app.localVaultFiles.query.pendingActivation != nil ||
			fx.app.localVaultFiles.query.operation == nil {
			t.Fatal("DESKTOP_LOCAL_QUERY_REPLACE_KEPT_PENDING")
		}
		fx.queue.runDispatch(t)
		fx.queue.runLaunch(t)
		fx.queue.runDispatch(t)
		fx.queue.drain(t)
		if fx.app.localVaultFiles.selected != "" {
			t.Fatal("DESKTOP_LOCAL_QUERY_REPLACE_CLICK_ACTIVATED")
		}
		if _, ok := fx.app.localVaultFileActiveItemCurrent(); ok {
			t.Fatal("DESKTOP_LOCAL_QUERY_REPLACE_CLICK_PUBLISHED_ACTIVE")
		}
		if fx.app.activateLocalVaultFileQueryHit(hitB); len(fx.queue.launches) != 0 {
			t.Fatal("DESKTOP_LOCAL_QUERY_REPLACE_OLD_HIT_QUEUED")
		}
		after := fx.app.localVaultFileQueryHits()
		if len(after) != 2 {
			t.Fatal("DESKTOP_LOCAL_QUERY_REPLACE_NEW_RESULTS_MISSING")
		}
	})

	t.Run("account-lock", func(t *testing.T) {
		fx := newDesktopLocalVaultQueryFixture(t)
		hits := fx.query(t)
		hitB := fx.hitsByID(t, hits)[desktopLocalVaultQueryIDB]
		if hitB == nil {
			t.Fatal("DESKTOP_LOCAL_QUERY_ACCOUNT_CLICK_B_MISSING")
		}
		release := desktopLocalVaultQueryHoldOwnSweep(t, fx,
			time.Unix(1_800_000_000, 0), nil)
		fx.app.activateLocalVaultFileQueryHit(hitB)
		if fx.app.localVaultFiles.query.pendingActivation == nil {
			release()
			t.Fatal("DESKTOP_LOCAL_QUERY_ACCOUNT_CLICK_NOT_HELD")
		}
		// Release the artificial cache barrier before the real account lock so
		// its own held operation can settle; the sweep dispatch is still pending.
		release()
		fx.app.Lock()
		if fx.app.localVaultFiles.query.pendingActivation != nil ||
			fx.app.localVaultFiles.query.sweep != nil {
			t.Fatal("DESKTOP_LOCAL_QUERY_ACCOUNT_KEPT_PENDING")
		}
		fx.queue.drain(t)
		if fx.app.session != nil ||
			fx.app.localVaultFiles.query.activation != nil ||
			fx.app.localVaultFiles.selected != "" {
			t.Fatal("DESKTOP_LOCAL_QUERY_ACCOUNT_CLICK_ACTIVATED")
		}
		if _, ok := fx.app.localVaultFileActiveItemCurrent(); ok {
			t.Fatal("DESKTOP_LOCAL_QUERY_ACCOUNT_CLICK_PUBLISHED_ACTIVE")
		}
	})
}
