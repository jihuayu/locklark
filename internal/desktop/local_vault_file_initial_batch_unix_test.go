//go:build darwin || linux

package desktop

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/vaultfileclient"
)

func newInitialFanoutTestApp(t *testing.T, f *localVaultSessionFixture, settingsPath string) (*App, *localVaultSessionQueue) {
	t.Helper()
	t.Setenv("LOCKLARK_BROWSER_SOCKET", desktopBrokerSocket(t))
	a := New()
	a.settingsPath = settingsPath
	a.path = f.personalPath
	a.password = f.password
	a.secret = f.secret
	a.session = nil
	a.deviceSecrets = nil
	a.busy = false
	q := &localVaultSessionQueue{}
	q.install(a)
	t.Cleanup(func() {
		a.Lock()
		drainInitialFanoutQueue(q)
		a.stopBrowserBroker()
	})
	return a, q
}

func drainInitialFanoutQueue(q *localVaultSessionQueue) {
	for len(q.dispatches) > 0 || len(q.launches) > 0 {
		if len(q.dispatches) > 0 {
			fn := q.dispatches[0]
			q.dispatches = q.dispatches[1:]
			fn()
			continue
		}
		fn := q.launches[0]
		q.launches = q.launches[1:]
		fn()
	}
}

func newInitialFanoutSettingsPath(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "settings")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal("LOCAL_INITIAL_FANOUT_SETTINGS_DIR_FAILED")
	}
	return filepath.Join(dir, "settings.json")
}

type failingInitialFanoutSystemStore struct{}

func (failingInitialFanoutSystemStore) Store(string, []byte) error { return errors.New("unavailable") }
func (failingInitialFanoutSystemStore) Load(string) ([]byte, error) {
	return nil, errors.New("unavailable")
}
func (failingInitialFanoutSystemStore) Delete(string) error { return nil }

func TestDesktopInitialOwnedFanoutUnlock(t *testing.T) {
	f := newLocalVaultSessionFixture(t)
	aPath, aManifest := f.createVault(t)
	bPath, bManifest := f.createVault(t)
	if _, err := f.parent.AddLogin("Initial fanout login", "fanout-user", "fanout-value"); err != nil {
		t.Fatal("LOCAL_INITIAL_FANOUT_PRIMARY_FIXTURE_FAILED")
	}

	t.Run("explicit-unlock-adopts-ab-without-navigation-auth", func(t *testing.T) {
		a, q := newInitialFanoutTestApp(t, f, f.settingsPath)
		a.unlock()
		if len(q.launches) != 1 {
			t.Fatal("LOCAL_INITIAL_FANOUT_WORKER_NOT_LAUNCHED")
		}
		q.runLaunch(t)
		if a.session != nil || len(a.localVaultFiles.sessionSlots) != 0 {
			t.Fatal("LOCAL_INITIAL_FANOUT_PUBLISHED_BEFORE_DISPATCH")
		}
		q.runDispatch(t)
		if a.session == nil || a.session == f.parent {
			t.Fatal("LOCAL_INITIAL_FANOUT_PARENT_NOT_ADOPTED")
		}
		if len(a.rows) != 1 || a.rows[0].Kind != "login" || a.rows[0].Title != "Initial fanout login" {
			t.Fatal("LOCAL_INITIAL_FANOUT_PROJECTION_LOST")
		}
		if len(a.localVaultFiles.refs) != 2 || len(a.localVaultFiles.sessionSlots) != 2 {
			t.Fatal("LOCAL_INITIAL_FANOUT_AB_NOT_ADOPTED")
		}
		if a.localVaultFiles.viewVerification == localVaultFileViewFresh {
			t.Fatal("LOCAL_INITIAL_FANOUT_CLAIMED_FRESH")
		}
		// loadV2Metadata legitimately queues the existing primary metadata read.
		// Settle that finite work before measuring navigation's own work.
		q.drain(t)
		if len(q.launches) != 0 || len(q.dispatches) != 0 {
			t.Fatal("LOCAL_INITIAL_FANOUT_POST_APPLY_WORK_UNSETTLED")
		}

		var refA, refB localVaultFileRef
		for _, ref := range a.localVaultFiles.refs {
			switch ref.vaultID {
			case aManifest.VaultID:
				refA = ref
			case bManifest.VaultID:
				refB = ref
			}
		}
		if refA.path != aPath || refB.path != bPath || refA.journalPath == "" || refB.journalPath == "" {
			t.Fatal("LOCAL_INITIAL_FANOUT_REFS_MISSING")
		}
		a.selectLocalVaultFile(refA)
		if a.localVaultFiles.selected != refA.path ||
			a.localVaultFiles.status != localVaultFileStatusReady ||
			a.localVaultFiles.viewVerification != localVaultFileViewCached {
			t.Fatal("LOCAL_INITIAL_FANOUT_NAVIGATION_CACHE_FAILED")
		}
		if len(q.launches) != 0 || len(q.dispatches) != 0 {
			t.Fatal("LOCAL_INITIAL_FANOUT_NAVIGATION_AUTH_LAUNCHED")
		}
		if a.localVaultUnlock.open || a.localCreate.open {
			t.Fatal("LOCAL_INITIAL_FANOUT_NAVIGATION_PROMPT_OPENED")
		}

		var aScope, bScope localVaultFileSessionScope
		var aWrapper, bWrapper *vaultfileclient.LocalGenesisSession
		var bSlot *localVaultFileSessionSlot
		for scope, slot := range a.localVaultFiles.sessionSlots {
			switch scope.configPath {
			case refA.path:
				aScope, aWrapper = scope, slot.session
			case refB.path:
				bScope, bSlot, bWrapper = scope, slot, slot.session
			}
		}
		if aScope.configPath == "" || bScope.configPath == "" || aWrapper == nil || bWrapper == nil || bSlot == nil {
			t.Fatal("LOCAL_INITIAL_FANOUT_SLOT_SCOPE_MISSING")
		}
		lock := a.beginLocalVaultFileLock(aScope)
		if lock == nil {
			t.Fatal("LOCAL_INITIAL_FANOUT_LOCK_BEGIN_FAILED")
		}
		q.drain(t)
		if !lock.isDone() {
			t.Fatal("LOCAL_INITIAL_FANOUT_LOCK_NOT_DONE")
		}
		if outcome, ok := lock.finiteOutcome(); !ok || outcome != localVaultFileLockOutcomeSucceeded {
			t.Fatal("LOCAL_INITIAL_FANOUT_LOCK_NOT_SUCCEEDED")
		}
		if _, err := aWrapper.Summary(); err == nil {
			t.Fatal("LOCAL_INITIAL_FANOUT_A_STILL_READABLE")
		}
		if _, err := bWrapper.Summary(); err != nil {
			t.Fatal("LOCAL_INITIAL_FANOUT_B_CLOSED_BY_A_LOCK")
		}
		if a.localVaultFiles.sessionSlots[bScope] != bSlot || a.session == nil || !a.session.Unlocked() {
			t.Fatal("LOCAL_INITIAL_FANOUT_SIBLING_OR_PARENT_LOST")
		}
		a.Lock()
		q.drain(t)
	})

	t.Run("late-lock-drops-batch-and-preserves-independent-b", func(t *testing.T) {
		a, q := newInitialFanoutTestApp(t, f, f.settingsPath)
		independent, _, err := vaultfileclient.OpenLocalGenesisSessionForJournal(
			f.parent, bPath, f.backendRoot, bManifest.VaultID, bManifest.Journal,
			[]byte(f.password), f.key)
		if err != nil || independent == nil {
			t.Fatal("LOCAL_INITIAL_FANOUT_INDEPENDENT_B_FAILED")
		}
		defer independent.Close()

		observed := make(chan struct{})
		var closedWrappers int
		var parentLocked, drained bool
		localVaultFileInitialBatchDrainForTest = func(closed int, locked bool) {
			closedWrappers, parentLocked, drained = closed, locked, true
			close(observed)
		}
		t.Cleanup(func() { localVaultFileInitialBatchDrainForTest = nil })

		a.unlock()
		q.runLaunch(t)
		if a.session != nil || len(a.localVaultFiles.sessionSlots) != 0 {
			t.Fatal("LOCAL_INITIAL_FANOUT_LATE_PUBLISHED_BEFORE_DISPATCH")
		}
		a.Lock()
		q.runDispatch(t)
		if len(q.launches) == 0 {
			t.Fatal("LOCAL_INITIAL_FANOUT_LATE_DRAIN_NOT_QUEUED")
		}
		if a.session != nil || len(a.localVaultFiles.sessionSlots) != 0 {
			t.Fatal("LOCAL_INITIAL_FANOUT_LATE_REVIVED")
		}
		q.runLaunch(t)
		select {
		case <-observed:
		case <-time.After(5 * time.Second):
			t.Fatal("LOCAL_INITIAL_FANOUT_LATE_DRAIN_TIMEOUT")
		}
		if !drained || closedWrappers != 2 || !parentLocked {
			t.Fatal("LOCAL_INITIAL_FANOUT_LATE_DRAIN_INCOMPLETE")
		}
		if _, err := independent.Summary(); err != nil {
			t.Fatal("LOCAL_INITIAL_FANOUT_LATE_KILLED_INDEPENDENT_B")
		}
	})

	t.Run("empty-all-local-and-overflow-retain-parent", func(t *testing.T) {
		cases := []struct {
			name           string
			prepare        func(t *testing.T, profileDir string)
			wantRefs       int
			wantIncomplete bool
		}{
			{"empty", func(*testing.T, string) {}, 0, false},
			{"all-local", func(t *testing.T, profileDir string) {
				if err := os.MkdirAll(profileDir, 0700); err != nil {
					t.Fatal("LOCAL_INITIAL_FANOUT_ALL_LOCAL_DIR_FAILED")
				}
				if err := os.WriteFile(filepath.Join(profileDir, "bad.json"), []byte("{}"), 0600); err != nil {
					t.Fatal("LOCAL_INITIAL_FANOUT_ALL_LOCAL_FILE_FAILED")
				}
			}, 1, true},
			{"overflow", func(t *testing.T, profileDir string) {
				if err := os.MkdirAll(profileDir, 0700); err != nil {
					t.Fatal("LOCAL_INITIAL_FANOUT_OVERFLOW_DIR_FAILED")
				}
				for index := 0; index < 129; index++ {
					if err := os.WriteFile(filepath.Join(profileDir, fmt.Sprintf("entry-%03d", index)), nil, 0600); err != nil {
						t.Fatal("LOCAL_INITIAL_FANOUT_OVERFLOW_FILE_FAILED")
					}
				}
			}, 0, true},
		}
		for _, testCase := range cases {
			t.Run(testCase.name, func(t *testing.T) {
				settingsPath := newInitialFanoutSettingsPath(t)
				profileDir, _ := localVaultFilePaths(settingsPath, f.personalPath)
				testCase.prepare(t, profileDir)
				a, q := newInitialFanoutTestApp(t, f, settingsPath)
				a.unlock()
				q.runLaunch(t)
				q.runDispatch(t)
				if a.session == nil || !a.session.Unlocked() {
					t.Fatal("LOCAL_INITIAL_FANOUT_LOCAL_CASE_PARENT_MISSING")
				}
				if len(a.localVaultFiles.refs) != testCase.wantRefs || len(a.localVaultFiles.sessionSlots) != 0 {
					t.Fatal("LOCAL_INITIAL_FANOUT_LOCAL_CASE_FAKE_SLOT")
				}
				if a.status == "" {
					t.Fatal("LOCAL_INITIAL_FANOUT_LOCAL_CASE_NO_FEEDBACK")
				}
				if testCase.wantIncomplete &&
					!strings.Contains(a.status, localVaultFileInitialFanoutIncompleteSuffix) {
					t.Fatal("LOCAL_INITIAL_FANOUT_LOCAL_CASE_INCOMPLETE_NOT_FINITE")
				}
				a.Lock()
				q.drain(t)
			})
		}
	})

	t.Run("system-unlock-does-not-fanout", func(t *testing.T) {
		a, q := newInitialFanoutTestApp(t, f, f.settingsPath)
		a.systemStore = failingInitialFanoutSystemStore{}
		a.systemUnlock()
		q.runLaunch(t)
		q.runDispatch(t)
		if a.session != nil || len(a.localVaultFiles.refs) != 0 ||
			len(a.localVaultFiles.sessionSlots) != 0 {
			t.Fatal("LOCAL_INITIAL_FANOUT_SYSTEM_PATH_FANNED_OUT")
		}
	})
}

func TestLocalVaultFileInitialRowBackingClear(t *testing.T) {
	score := 9
	raw := []personal.Row{
		{Kind: "login", ID: "row-id", Title: "row-title", WatchtowerFlags: []string{"flag-one"}, StrengthScore: &score},
		{Kind: "ssh", ID: "ssh-id", Title: "ssh-title"},
	}
	delivered := loginProjection(raw)
	if len(delivered) != 1 || delivered[0].Kind != "login" ||
		delivered[0].ID != "row-id" || delivered[0].Title != "row-title" {
		t.Fatal("LOCAL_INITIAL_FANOUT_PROJECTION_FILTER_FAILED")
	}
	if len(delivered[0].WatchtowerFlags) != 1 || delivered[0].WatchtowerFlags[0] != "flag-one" ||
		delivered[0].StrengthScore == nil || *delivered[0].StrengthScore != score {
		t.Fatal("LOCAL_INITIAL_FANOUT_PROJECTION_NESTED_LOST")
	}
	clearLocalVaultFileInitialRows(raw)
	for index := range raw {
		if !reflect.DeepEqual(raw[index], personal.Row{}) {
			t.Fatal("LOCAL_INITIAL_FANOUT_RAW_ROW_NOT_CLEARED")
		}
	}
	if delivered[0].Title != "row-title" || len(delivered[0].WatchtowerFlags) != 1 ||
		delivered[0].WatchtowerFlags[0] != "flag-one" ||
		delivered[0].StrengthScore == nil || *delivered[0].StrengthScore != score {
		t.Fatal("LOCAL_INITIAL_FANOUT_DELIVERED_MUTATED")
	}

	dropRows := []personal.Row{{Kind: "login", ID: "drop-id", Title: "drop-title"}}
	dropBatch := &localVaultFileInitialBatch{rows: dropRows, done: make(chan struct{})}
	dropBatch.drop(nil)
	for index := range dropRows {
		if !reflect.DeepEqual(dropRows[index], personal.Row{}) {
			t.Fatal("LOCAL_INITIAL_FANOUT_DROP_ROW_NOT_CLEARED")
		}
	}

	drainRows := []personal.Row{{Kind: "login", ID: "drain-id", Title: "drain-title"}}
	drainBatch := &localVaultFileInitialBatch{rows: drainRows, done: make(chan struct{})}
	drainBatch.drain()
	for index := range drainRows {
		if !reflect.DeepEqual(drainRows[index], personal.Row{}) {
			t.Fatal("LOCAL_INITIAL_FANOUT_DRAIN_ROW_NOT_CLEARED")
		}
	}
}
