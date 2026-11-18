//go:build darwin

package desktop

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/egoist/mygo"
	"github.com/jihuayu/locklark/internal/vaultfileclient"
	"github.com/oneo-me/onevra/source/shells/plain"
)

// This checkpoint starts from the product's locked native view and uses only
// the rendered controls to perform one explicit full-factor account unlock.
// The controls receive MyGo automation input, the same surface events the
// macOS backend delivers, and the ordinary widget handlers do the unlock.
// It never calls App.unlock, installs an already-unlocked session, or reaches
// into the local-vault adoption handlers to simulate the result.
//
// The account and its workspace are fresh fixtures under the test's private
// temporary root. The two independent child vaults carry different IDs behind
// the same item title. The visible window is isolated and addressed by exact
// ID and title; the test never drives another window or the host's credential
// store.
//
// A negative full-factor submission (wrong master password, valid Secret Key)
// must settle without a parent, refs or child slots. The same process and
// window then submit the positive factors and must publish exactly two
// independently pinned children. The documented visible-window child harness
// does not expose a launcher-owned hold between candidate staging and
// adoption; that held-cancel path is exercised by the existing external
// native-initial-tagged-held-cancel scenario with its tagged native fence and
// launcher-owned descriptors. This visible-window checkpoint therefore uses
// the negative authenticated-factor path available to the ordinary child
// harness.

const (
	nativeInitialFanoutAcceptanceTitle = "Locklark native initial fanout acceptance"
	nativeInitialFanoutWrongPassword   = "wrong-initial-fanout-factor"

	// The parent only selects and supervises this exact child test. The child
	// owns the one visible native app that performs the failed submission and
	// the successful same-window retry.
	nativeInitialFanoutChildEnv      = "LOCKLARK_NATIVE_INITIAL_FANOUT_CHILD"
	nativeInitialFanoutChildTest     = "TestDesktopInitialOwnedFanoutNativeWindowChild"
	nativeInitialFanoutChildTimeout  = 5 * time.Minute
	nativeInitialFanoutChildTestTime = "4m"
	nativeInitialFanoutSuccessMarker = "NATIVE_INITIAL_FANOUT_NATIVE_OK negative=1 positive=1 children=2 rows=2 ids=2"
)

// nativeInitialFanoutDeviceStore serializes the existing in-memory fake. The
// native lock view may read the badge while the unlock worker stores the
// synthetic Secret Key, so the test store must never touch the host Keychain
// and must not race on its own map.
type nativeInitialFanoutDeviceStore struct {
	mu    sync.Mutex
	inner *fakeDeviceSecretStore
}

func newNativeInitialFanoutDeviceStore() *nativeInitialFanoutDeviceStore {
	return &nativeInitialFanoutDeviceStore{inner: newFakeDeviceSecretStore()}
}

func (s *nativeInitialFanoutDeviceStore) Set(key string, value []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.inner.Set(key, value)
}

func (s *nativeInitialFanoutDeviceStore) Get(key string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.inner.Get(key)
}

func (s *nativeInitialFanoutDeviceStore) Delete(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.inner.Delete(key)
}

type nativeInitialFanoutFixture struct {
	f         *localVaultSessionFixture
	app       *App
	aPath     string
	bPath     string
	aManifest vaultfileclient.Manifest
	bManifest vaultfileclient.Manifest
}

func newNativeInitialFanoutFixture(t *testing.T) *nativeInitialFanoutFixture {
	t.Helper()
	f := newLocalVaultSessionFixture(t)
	aPath, aManifest := f.createVault(t)
	bPath, bManifest := f.createVault(t)
	if aManifest.PersonalFile != bManifest.PersonalFile ||
		aManifest.VaultID == bManifest.VaultID ||
		aManifest.Journal == bManifest.Journal ||
		aManifest.Name == bManifest.Name || aPath == bPath {
		t.Fatal("NATIVE_INITIAL_FANOUT_VAULT_SCOPE_NOT_DISTINCT")
	}

	ctx := context.Background()
	if _, err := vaultfileclient.WriteLocalGenesisFirstItem(ctx, f.parent, aPath,
		aManifest.BackendRoot, aManifest.VaultID, aManifest.Journal,
		[]byte(f.password), f.key, vaultfileclient.LocalGenesisFirstItem{
			ID: desktopLocalVaultQueryIDA, Title: desktopLocalVaultQueryTitle,
			Username: "native-initial-a", Password: "native-initial-secret-a",
		}); err != nil {
		t.Fatal("NATIVE_INITIAL_FANOUT_WRITE_A_FAILED")
	}
	if _, err := vaultfileclient.WriteLocalGenesisFirstItem(ctx, f.parent, bPath,
		bManifest.BackendRoot, bManifest.VaultID, bManifest.Journal,
		[]byte(f.password), f.key, vaultfileclient.LocalGenesisFirstItem{
			ID: desktopLocalVaultQueryIDB, Title: desktopLocalVaultQueryTitle,
			Username: "native-initial-b", Password: "native-initial-secret-b",
		}); err != nil {
		t.Fatal("NATIVE_INITIAL_FANOUT_WRITE_B_FAILED")
	}

	// The fixture's creating parent is a separate custody owner. Lock it before
	// the child app exists so no already-open session can leak into the native
	// unlock path under test.
	f.parent.Lock()
	if f.parent.Unlocked() {
		t.Fatal("NATIVE_INITIAL_FANOUT_FIXTURE_PARENT_UNLOCKED")
	}

	app, _ := newInitialFanoutTestApp(t, f, f.settingsPath)
	mygo.RunOnMain(func() {
		app.session = nil
		app.password = ""
		app.secret = ""
		app.confirmation = ""
		app.showSecretFallback = false
		// A fresh in-memory store keeps the full-factor success path local: the
		// app may remember the synthetic Secret Key, but never through the host
		// Keychain or any pre-existing device binding.
		app.deviceSecrets = newNativeInitialFanoutDeviceStore()
		app.busy = false
		app.onevra.shellActive = true
	})
	return &nativeInitialFanoutFixture{
		f: f, app: app,
		aPath: aPath, bPath: bPath,
		aManifest: aManifest, bManifest: bManifest,
	}
}

func nativeInitialFanoutOpenWindow(t *testing.T, app *App) (int, string) {
	t.Helper()
	foreground := os.Getenv("LOCKLARK_NATIVE_FOREGROUND") == "1"
	var shell *plain.Shell
	var windowID int
	var windowTitle string
	mygo.RunOnMain(func() {
		shell = plain.NewShell(plain.ShellOptions{
			Title:         nativeInitialFanoutAcceptanceTitle,
			Width:         1240,
			Height:        820,
			MinWidth:      980,
			MinHeight:     680,
			Hidden:        true,
			Theme:         app.onevraTheme,
			HeaderLeading: app.onevraHeaderLeading,
			HeaderActions: app.onevraHeaderActions,
			Content:       app.View,
		})
		app.win = shell.Window()
		app.dispatch = app.win.Update
		app.launch = func(fn func()) { go fn() }
		windowID = app.win.ID()
		windowTitle = app.win.Title()
		if !foreground {
			// Keep the real window off-screen while it remains the key window,
			// so the rendered controls receive native key and text events.
			app.win.SetPosition(-30000, -30000)
		}
		app.win.Show()
		app.win.Focus()
		app.win.Invalidate()
	})
	if shell == nil {
		t.Fatal("NATIVE_INITIAL_FANOUT_SHELL_MISSING")
	}
	t.Cleanup(func() {
		mygo.RunOnMain(func() {
			app.cancelLocalVaultFileQuery()
			if app.win != nil {
				app.win.Hide()
				app.win.Destroy()
				app.win = nil
			}
		})
	})
	return windowID, windowTitle
}

func nativeInitialFanoutFindField(nodes []nativeQueryAcceptanceNode, label string) (nativeQueryAcceptanceNode, int) {
	var found nativeQueryAcceptanceNode
	count := 0
	for _, node := range nodes {
		if (node.Role == "textField" || node.Role == "comboBox") && node.Label == label {
			found = node
			count++
		}
	}
	return found, count
}

func nativeInitialFanoutRequireLockedForm(t *testing.T, app *App, client *nativeQueryAcceptanceAutomation, window int) {
	t.Helper()
	nativeQueryAcceptanceWaitNode(t, app, client, window, 15*time.Second,
		"NATIVE_INITIAL_FANOUT_LOCKED_FORM_MISSING", func(tree nativeQueryAcceptanceTree) (nativeQueryAcceptanceNode, bool) {
			emergency, emergencyCount := nativeQueryAcceptanceFindLabel(tree.Nodes, "使用应急资料…")
			unlock, unlockCount := nativeQueryAcceptanceFindLabel(tree.Nodes, "解锁")
			return emergency, emergencyCount == 1 && unlockCount == 1 && unlock.ID != ""
		})
}

func nativeInitialFanoutClickField(t *testing.T, app *App, client *nativeQueryAcceptanceAutomation,
	window int, title, label string) {
	t.Helper()
	nativeQueryAcceptanceWaitNode(t, app, client, window, 10*time.Second,
		"NATIVE_INITIAL_FANOUT_FIELD_MISSING", func(tree nativeQueryAcceptanceTree) (nativeQueryAcceptanceNode, bool) {
			field, count := nativeInitialFanoutFindField(tree.Nodes, label)
			return field, count == 1 && field.Bounds.Width > 0 && field.Bounds.Height > 0
		})
	client.requireWindow(t, window, title)
	tree, err := client.tree(window)
	if err != nil {
		t.Fatal("NATIVE_INITIAL_FANOUT_FIELD_TREE_FAILED")
	}
	field, count := nativeInitialFanoutFindField(tree.Nodes, label)
	if count != 1 || field.Bounds.Width <= 0 || field.Bounds.Height <= 0 {
		t.Fatal("NATIVE_INITIAL_FANOUT_FIELD_CHANGED")
	}
	client.requireWindow(t, window, title)
	x, y := nativeQueryAcceptanceCenter(field.Bounds)
	if err := client.input(window, nativeQueryAcceptanceEvent{Type: "click", X: x, Y: y}); err != nil {
		t.Fatal("NATIVE_INITIAL_FANOUT_FIELD_INPUT_FAILED")
	}
	nativeQueryAcceptanceWait(t, app, 5*time.Second, "NATIVE_INITIAL_FANOUT_FIELD_NOT_FOCUSED", func() bool {
		tree, err := client.tree(window)
		if err != nil {
			return false
		}
		fresh, count := nativeInitialFanoutFindField(tree.Nodes, label)
		return count == 1 && tree.Focus == fresh.ID
	})
}

func nativeInitialFanoutTypeField(t *testing.T, client *nativeQueryAcceptanceAutomation,
	window int, title, label, text string) {
	t.Helper()
	client.requireWindow(t, window, title)
	tree, err := client.tree(window)
	if err != nil {
		t.Fatal("NATIVE_INITIAL_FANOUT_FIELD_TREE_FAILED")
	}
	field, count := nativeInitialFanoutFindField(tree.Nodes, label)
	if count != 1 || tree.Focus != field.ID {
		t.Fatal("NATIVE_INITIAL_FANOUT_FIELD_NOT_FOCUSED")
	}
	client.requireWindow(t, window, title)
	if err := client.input(window,
		nativeQueryAcceptanceEvent{Type: "key", Key: "CmdOrCtrl+A"},
		nativeQueryAcceptanceEvent{Type: "key", Key: "Backspace"},
		nativeQueryAcceptanceEvent{Type: "text", Text: text}); err != nil {
		t.Fatal("NATIVE_INITIAL_FANOUT_FIELD_INPUT_FAILED")
	}
}

func nativeInitialFanoutFillField(t *testing.T, app *App, client *nativeQueryAcceptanceAutomation,
	window int, title, label, text string) {
	t.Helper()
	nativeInitialFanoutClickField(t, app, client, window, title, label)
	nativeInitialFanoutTypeField(t, client, window, title, label, text)
}

func nativeInitialFanoutSequence(app *App) uint64 {
	var sequence uint64
	mygo.RunOnMain(func() { sequence = app.operationSequence })
	return sequence
}

func nativeInitialFanoutWaitStarted(t *testing.T, app *App, after uint64, timeout time.Duration, marker string) {
	t.Helper()
	nativeQueryAcceptanceWait(t, app, timeout, marker, func() bool {
		started := false
		mygo.RunOnMain(func() { started = app.operationSequence > after })
		return started
	})
}

func nativeInitialFanoutWaitSettled(t *testing.T, app *App, after uint64, timeout time.Duration,
	marker string, adopted bool) {
	t.Helper()
	nativeQueryAcceptanceWait(t, app, timeout, marker, func() bool {
		settled := false
		mygo.RunOnMain(func() {
			state := &app.localVaultFiles
			if app.operationSequence <= after || app.busy || app.accountUnlock != nil {
				return
			}
			if adopted {
				settled = app.session != nil && app.session.Unlocked() &&
					len(state.refs) == 2 && len(state.sessionSlots) == 2
				return
			}
			settled = app.session == nil &&
				len(state.refs) == 0 && len(state.sessionSlots) == 0
		})
		return settled
	})
}

func nativeInitialFanoutRequireNoAdoption(t *testing.T, fx *nativeInitialFanoutFixture) {
	t.Helper()
	var marker string
	mygo.RunOnMain(func() {
		state := &fx.app.localVaultFiles
		switch {
		case fx.app.session != nil:
			marker = "NATIVE_INITIAL_FANOUT_NEGATIVE_ADOPTED_SESSION"
		case len(state.refs) != 0 || len(state.sessionSlots) != 0 || state.sessionParent != nil:
			marker = "NATIVE_INITIAL_FANOUT_NEGATIVE_RETAINED_CHILD"
		case fx.app.busy || fx.app.accountUnlock != nil:
			marker = "NATIVE_INITIAL_FANOUT_NEGATIVE_NOT_SETTLED"
		case fx.app.password != "" || fx.app.secret != "":
			marker = "NATIVE_INITIAL_FANOUT_NEGATIVE_FACTORS_RETAINED"
		case !fx.app.showSecretFallback:
			marker = "NATIVE_INITIAL_FANOUT_NEGATIVE_FALLBACK_LOST"
		}
	})
	if marker != "" {
		t.Fatal(marker)
	}
	if fx.f.parent.Unlocked() {
		t.Fatal("NATIVE_INITIAL_FANOUT_NEGATIVE_REVIVED_FIXTURE_PARENT")
	}
}

func nativeInitialFanoutRequireAdopted(t *testing.T, fx *nativeInitialFanoutFixture) (string, string) {
	t.Helper()
	var marker string
	var refA, refB localVaultFileRef
	var scopeA, scopeB localVaultFileSessionScope
	var wrapperA, wrapperB *vaultfileclient.LocalGenesisSession
	var labelA, labelB string
	mygo.RunOnMain(func() {
		app := fx.app
		state := &app.localVaultFiles
		switch {
		case app.session == nil || !app.session.Unlocked():
			marker = "NATIVE_INITIAL_FANOUT_PARENT_NOT_UNLOCKED"
			return
		case app.session == fx.f.parent:
			marker = "NATIVE_INITIAL_FANOUT_REUSED_FIXTURE_PARENT"
			return
		case state.sessionParent != app.session:
			marker = "NATIVE_INITIAL_FANOUT_PARENT_NOT_PINNED"
			return
		case len(state.refs) != 2 || len(state.sessionSlots) != 2:
			marker = "NATIVE_INITIAL_FANOUT_CHILD_COUNT"
			return
		}
		for _, ref := range state.refs {
			switch ref.vaultID {
			case fx.aManifest.VaultID:
				refA = ref
			case fx.bManifest.VaultID:
				refB = ref
			}
		}
		if refA.path != fx.aPath || refB.path != fx.bPath ||
			refA.journalPath == "" || refB.journalPath == "" ||
			refA.journalPath == refB.journalPath {
			marker = "NATIVE_INITIAL_FANOUT_REFS_NOT_INDEPENDENT"
			return
		}
		labelA = app.localVaultFileDisplayLabelFor(refA)
		labelB = app.localVaultFileDisplayLabelFor(refB)
		if labelA == "" || labelB == "" || labelA == labelB {
			marker = "NATIVE_INITIAL_FANOUT_DISPLAY_LABELS_NOT_INDEPENDENT"
			return
		}
		for scope, slot := range state.sessionSlots {
			if slot == nil || slot.session == nil || slot.operation != nil {
				marker = "NATIVE_INITIAL_FANOUT_SLOT_NOT_READABLE"
				return
			}
			switch scope.configPath {
			case fx.aPath:
				scopeA, wrapperA = scope, slot.session
			case fx.bPath:
				scopeB, wrapperB = scope, slot.session
			}
		}
		if scopeA.configPath == "" || scopeB.configPath == "" ||
			scopeA == scopeB || wrapperA == nil || wrapperB == nil || wrapperA == wrapperB {
			marker = "NATIVE_INITIAL_FANOUT_SLOTS_NOT_INDEPENDENT"
		}
	})
	if marker != "" {
		t.Fatal(marker)
	}
	if fx.f.parent.Unlocked() {
		t.Fatal("NATIVE_INITIAL_FANOUT_OLD_PARENT_REVIVED")
	}
	summaryA, errA := wrapperA.Summary()
	summaryB, errB := wrapperB.Summary()
	if errA != nil || errB != nil {
		t.Fatal("NATIVE_INITIAL_FANOUT_CHILD_SUMMARY_FAILED")
	}
	if summaryA.VaultID != fx.aManifest.VaultID || summaryB.VaultID != fx.bManifest.VaultID ||
		len(summaryA.Items) != 1 || len(summaryB.Items) != 1 ||
		summaryA.Items[0].Title != desktopLocalVaultQueryTitle ||
		summaryB.Items[0].Title != desktopLocalVaultQueryTitle {
		t.Fatal("NATIVE_INITIAL_FANOUT_CHILD_BASELINE_MISMATCH")
	}
	nativeInitialFanoutRequireExactChildID(t, wrapperA, fx.aPath, fx.aManifest,
		desktopLocalVaultQueryIDA, desktopLocalVaultQueryIDB)
	nativeInitialFanoutRequireExactChildID(t, wrapperB, fx.bPath, fx.bManifest,
		desktopLocalVaultQueryIDB, desktopLocalVaultQueryIDA)
	return labelA, labelB
}

func nativeInitialFanoutRequireExactChildID(t *testing.T, wrapper *vaultfileclient.LocalGenesisSession,
	configPath string, manifest vaultfileclient.Manifest, expectedID, oppositeID string) {
	t.Helper()
	result, err := wrapper.QueryExactTitle(vaultfileclient.LocalGenesisExactQuery{
		Title: desktopLocalVaultQueryTitle, Limit: 2,
	})
	if err != nil {
		t.Fatal("NATIVE_INITIAL_FANOUT_CHILD_QUERY_FAILED")
	}
	if result.ConfigPath != configPath || result.WorkspaceRoot != manifest.BackendRoot ||
		result.VaultID != manifest.VaultID || result.JournalPath != manifest.Journal ||
		result.ManifestSHA256 == "" || result.JournalRevision == "" {
		t.Fatal("NATIVE_INITIAL_FANOUT_CHILD_QUERY_SCOPE_MISMATCH")
	}
	if len(result.Hits) != 1 || result.Truncated ||
		result.Hits[0].ID != expectedID || result.Hits[0].Title != desktopLocalVaultQueryTitle {
		t.Fatal("NATIVE_INITIAL_FANOUT_CHILD_ITEMS_NOT_INDEPENDENT")
	}
	if err := wrapper.ValidateExactQueryHit(result, expectedID, desktopLocalVaultQueryTitle); err != nil {
		t.Fatal("NATIVE_INITIAL_FANOUT_CHILD_CORRECT_ID_NOT_VALIDATED")
	}
	if err := wrapper.ValidateExactQueryHit(result, oppositeID, desktopLocalVaultQueryTitle); !errors.Is(err, vaultfileclient.ErrLocalReview) {
		t.Fatal("NATIVE_INITIAL_FANOUT_CHILD_OPPOSITE_ID_NOT_REJECTED")
	}
}

// nativeInitialFanoutRunChild runs the one exact child test in a fresh Go test
// process with a dedicated automation socket under a private temporary
// directory. The child's output is captured only to detect the fixed success
// marker; neither raw child output nor fixture values reach this process's
// stdout or a fatal message.
func nativeInitialFanoutRunChild(t *testing.T) {
	t.Helper()
	dir, err := os.MkdirTemp("", "ll-a3-")
	if err != nil {
		t.Fatal("NATIVE_INITIAL_FANOUT_CHILD_SOCKET_DIR_FAILED")
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Errorf("NATIVE_INITIAL_FANOUT_CHILD_SOCKET_DIR_CLEANUP_FAILED")
		}
	})
	if err := os.Chmod(dir, 0o700); err != nil {
		_ = os.RemoveAll(dir)
		t.Fatal("NATIVE_INITIAL_FANOUT_CHILD_SOCKET_DIR_MODE_FAILED")
	}
	socketPath := filepath.Join(dir, "a.sock")
	stdoutPath := filepath.Join(dir, "stdout")
	stderrPath := filepath.Join(dir, "stderr")
	stdout, err := os.OpenFile(stdoutPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal("NATIVE_INITIAL_FANOUT_CHILD_STDOUT_CREATE_FAILED")
	}
	stderr, err := os.OpenFile(stderrPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		_ = stdout.Close()
		t.Fatal("NATIVE_INITIAL_FANOUT_CHILD_STDERR_CREATE_FAILED")
	}
	executable, err := os.Executable()
	if err != nil {
		_ = stdout.Close()
		_ = stderr.Close()
		t.Fatal("NATIVE_INITIAL_FANOUT_CHILD_EXECUTABLE_FAILED")
	}
	ctx, cancel := context.WithTimeout(context.Background(), nativeInitialFanoutChildTimeout)
	defer cancel()
	command := exec.CommandContext(ctx, executable,
		"-test.run=^"+nativeInitialFanoutChildTest+"$",
		"-test.count=1",
		"-test.timeout="+nativeInitialFanoutChildTestTime)
	command.Env = nativeInitialFanoutChildEnvironment(os.Environ(), dir, socketPath)
	command.Stdout = stdout
	command.Stderr = stderr
	command.WaitDelay = 5 * time.Second
	runErr := command.Run()
	_ = stdout.Close()
	_ = stderr.Close()
	if ctx.Err() == context.DeadlineExceeded {
		t.Fatal("NATIVE_INITIAL_FANOUT_CHILD_TIMEOUT")
	}
	if runErr != nil {
		code := -1
		var exit *exec.ExitError
		if errors.As(runErr, &exit) {
			code = exit.ExitCode()
		}
		t.Fatalf("NATIVE_INITIAL_FANOUT_CHILD_FAILED exit=%d", code)
	}
	output, err := os.ReadFile(stdoutPath)
	if err != nil {
		t.Fatal("NATIVE_INITIAL_FANOUT_CHILD_MARKER_UNREADABLE")
	}
	if !nativeInitialFanoutChildSucceeded(string(output)) {
		t.Fatal("NATIVE_INITIAL_FANOUT_CHILD_MARKER_MISSING")
	}
	t.Log("NATIVE_INITIAL_FANOUT_ISOLATION_OK exit=0 marker=1")
}

func nativeInitialFanoutChildEnvironment(base []string, dir, socketPath string) []string {
	env := make([]string, 0, len(base)+4)
	for _, entry := range base {
		key, _, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		switch key {
		case "MYGO_AUTOMATION", "TMPDIR", "LOCKLARK_NATIVE_SMOKE",
			nativeInitialFanoutChildEnv,
			"LOCKLARK_NATIVE_FENCE_CONTROL_FD", "LOCKLARK_NATIVE_FENCE_EVENT_FD":
			continue
		default:
			env = append(env, entry)
		}
	}
	// The child's MyGo user-data and fixture temporary directories live under
	// this parent-owned directory, so removing it also cleans a child that
	// failed or timed out before its own TestMain cleanup could run.
	return append(env,
		"MYGO_AUTOMATION="+socketPath,
		"TMPDIR="+dir,
		"LOCKLARK_NATIVE_SMOKE=1",
		nativeInitialFanoutChildEnv+"=1")
}

func nativeInitialFanoutChildSucceeded(output string) bool {
	count := 0
	for _, line := range strings.Split(output, "\n") {
		if strings.TrimSuffix(line, "\r") == nativeInitialFanoutSuccessMarker {
			count++
		}
	}
	return count == 1
}

// TestDesktopInitialOwnedFanoutNativeWindow is only the opt-in supervisor.
// It never creates a fixture, App, shell or platform window in this process:
// the child gets a fresh Go test process, a fresh visible native app and its
// own private automation socket. That keeps this root's state out of the
// shared process so the existing real native query test can run afterward
// unchanged.
func TestDesktopInitialOwnedFanoutNativeWindow(t *testing.T) {
	if os.Getenv("LOCKLARK_NATIVE_SMOKE") != "1" {
		t.Skip("requires LOCKLARK_NATIVE_SMOKE=1 in a macOS desktop session")
	}
	if os.Getenv(nativeInitialFanoutChildEnv) != "" {
		t.Skip("native initial fanout isolation child execution")
	}
	if os.Getenv("MYGO_AUTOMATION") == "" {
		t.Fatal("NATIVE_INITIAL_FANOUT_AUTOMATION_NOT_CONFIGURED")
	}
	if os.Getenv("LOCKLARK_NATIVE_FENCE_CONTROL_FD") != "" ||
		os.Getenv("LOCKLARK_NATIVE_FENCE_EVENT_FD") != "" {
		// The tagged external launcher owns this process and expects its own
		// release protocol; do not contend with that run.
		t.Skip("tagged native fence transport owns this run")
	}
	nativeInitialFanoutRunChild(t)
}

// TestDesktopInitialOwnedFanoutNativeWindowChild is the exact isolated child.
// It is inert unless the parent selected it with the private child variable.
func TestDesktopInitialOwnedFanoutNativeWindowChild(t *testing.T) {
	if os.Getenv(nativeInitialFanoutChildEnv) != "1" {
		t.Skip("native initial fanout isolation child only")
	}
	if os.Getenv("LOCKLARK_NATIVE_SMOKE") != "1" {
		t.Skip("requires LOCKLARK_NATIVE_SMOKE=1 in a macOS desktop session")
	}
	if os.Getenv("MYGO_AUTOMATION") == "" {
		t.Fatal("NATIVE_INITIAL_FANOUT_AUTOMATION_NOT_CONFIGURED")
	}
	if os.Getenv("LOCKLARK_NATIVE_FENCE_CONTROL_FD") != "" ||
		os.Getenv("LOCKLARK_NATIVE_FENCE_EVENT_FD") != "" {
		t.Skip("tagged native fence transport owns this run")
	}
	if classicLayoutRequested() {
		t.Fatal("NATIVE_INITIAL_FANOUT_ONEVRA_LAYOUT_REQUIRED")
	}

	fx := newNativeInitialFanoutFixture(t)
	app := fx.app
	var initiallyLocked bool
	mygo.RunOnMain(func() {
		_, tempStore := app.deviceSecrets.(*nativeInitialFanoutDeviceStore)
		initiallyLocked = app.session == nil && !app.busy && tempStore &&
			!app.showSecretFallback &&
			app.path == fx.f.personalPath && app.password == "" && app.secret == ""
	})
	if !initiallyLocked {
		t.Fatal("NATIVE_INITIAL_FANOUT_NOT_LOCKED")
	}

	windowID, windowTitle := nativeInitialFanoutOpenWindow(t, app)
	client := nativeQueryAcceptanceOpenAutomation(t)
	nativeQueryAcceptanceWait(t, app, 10*time.Second,
		"NATIVE_INITIAL_FANOUT_TARGET_WINDOW_NOT_ISOLATED", func() bool {
			_, ok, err := client.isolatedWindow(windowID, windowTitle)
			return err == nil && ok
		})
	client.requireWindow(t, windowID, windowTitle)
	nativeInitialFanoutRequireLockedForm(t, app, client, windowID)

	// First submit a negative full factor. The Secret Key is valid, so the
	// failure is the wrong master password rather than an input shortcut.
	nativeQueryAcceptanceClickLabel(t, app, client, windowID, windowTitle, "使用应急资料…")
	nativeQueryAcceptanceWaitNode(t, app, client, windowID, 5*time.Second,
		"NATIVE_INITIAL_FANOUT_SECRET_FIELD_MISSING", func(tree nativeQueryAcceptanceTree) (nativeQueryAcceptanceNode, bool) {
			field, count := nativeInitialFanoutFindField(tree.Nodes, "Secret Key")
			return field, count == 1 && field.Bounds.Width > 0 && field.Bounds.Height > 0
		})
	nativeInitialFanoutFillField(t, app, client, windowID, windowTitle, "主密码", nativeInitialFanoutWrongPassword)
	nativeInitialFanoutFillField(t, app, client, windowID, windowTitle, "Secret Key", fx.f.secret)
	negativeSequence := nativeInitialFanoutSequence(app)
	nativeQueryAcceptanceClickLabel(t, app, client, windowID, windowTitle, "解锁")
	nativeInitialFanoutWaitStarted(t, app, negativeSequence, 5*time.Second,
		"NATIVE_INITIAL_FANOUT_NEGATIVE_DID_NOT_START")
	nativeInitialFanoutWaitSettled(t, app, negativeSequence, 30*time.Second,
		"NATIVE_INITIAL_FANOUT_NEGATIVE_DID_NOT_SETTLE", false)
	nativeInitialFanoutRequireNoAdoption(t, fx)
	client.requireWindow(t, windowID, windowTitle)

	// The same process and native window now submit the positive factors.
	nativeInitialFanoutFillField(t, app, client, windowID, windowTitle, "主密码", fx.f.password)
	nativeInitialFanoutFillField(t, app, client, windowID, windowTitle, "Secret Key", fx.f.secret)
	positiveSequence := nativeInitialFanoutSequence(app)
	nativeQueryAcceptanceClickLabel(t, app, client, windowID, windowTitle, "解锁")
	nativeInitialFanoutWaitStarted(t, app, positiveSequence, 5*time.Second,
		"NATIVE_INITIAL_FANOUT_POSITIVE_DID_NOT_START")
	nativeInitialFanoutWaitSettled(t, app, positiveSequence, 45*time.Second,
		"NATIVE_INITIAL_FANOUT_POSITIVE_DID_NOT_SETTLE", true)
	labelA, labelB := nativeInitialFanoutRequireAdopted(t, fx)
	if labelA == "" || labelB == "" {
		t.Fatal("NATIVE_INITIAL_FANOUT_LABELS_MISSING")
	}

	nativeQueryAcceptanceWait(t, app, 10*time.Second,
		"NATIVE_INITIAL_FANOUT_NORMAL_VIEW_UNAVAILABLE", func() bool {
			return nativeQueryAcceptanceV2View(app)
		})
	keyA, keyB := nativeQueryAcceptanceLocalVaultKey(fx.aPath), nativeQueryAcceptanceLocalVaultKey(fx.bPath)
	nativeQueryAcceptanceWaitNode(t, app, client, windowID, 15*time.Second,
		"NATIVE_INITIAL_FANOUT_SIDEBAR_MISSING", func(tree nativeQueryAcceptanceTree) (nativeQueryAcceptanceNode, bool) {
			node, countA := nativeQueryAcceptanceFindKey(tree.Nodes, keyA)
			_, countB := nativeQueryAcceptanceFindKey(tree.Nodes, keyB)
			return node, countA == 1 && countB == 1 && node.Bounds.Width > 0 && node.Bounds.Height > 0
		})
	nativeQueryAcceptanceClickKey(t, app, client, windowID, windowTitle, keyA)
	nativeQueryAcceptanceWait(t, app, 10*time.Second,
		"NATIVE_INITIAL_FANOUT_NAVIGATION_FAILED", func() bool {
			selected := false
			mygo.RunOnMain(func() { selected = app.localVaultFiles.selected == fx.aPath })
			return selected
		})

	nativeQueryAcceptanceRunQuery(t, app, client, windowID, windowTitle,
		fx.aPath, fx.bPath, fx.aManifest.VaultID, fx.bManifest.VaultID)
	if _, err := os.Stdout.WriteString(nativeInitialFanoutSuccessMarker + "\n"); err != nil {
		t.Fatal("NATIVE_INITIAL_FANOUT_CHILD_MARKER_WRITE_FAILED")
	}
}
