package desktop

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/plugins/updater"
)

const (
	updaterStartupHelperEnv = "PASSME_DESKTOP_UPDATER_STARTUP_HELPER"
	updaterRegisteredMarker = "updater-startup-registered"
	updaterHelperTimeout    = 5 * time.Second
)

var errUpdaterStartupBoundary = errors.New("updater startup boundary reached")

// runUpdaterStartupHelperMain is the child half of
// TestUpdaterStartupRegistersNativeMenu. TestMain calls it on the process's
// main goroutine, which MyGo locks to the native UI thread, before m.Run:
// updater.MenuItem resolves the app locale through MyGo's main-thread API and
// would wait forever if a testing goroutine called it without App.Run.
func runUpdaterStartupHelperMain() (code int, handled bool) {
	mode := os.Getenv(updaterStartupHelperEnv)
	if mode == "" {
		return 0, false
	}
	switch mode {
	case "unregistered":
		// This is the control: MenuItem must fail closed while no updater
		// plugin is active. Leave the panic unrecovered so the parent also
		// sees the real Go panic exit status and stderr.
		updater.MenuItem()
		fmt.Fprintln(os.Stderr, "updater startup helper: unregistered MenuItem unexpectedly succeeded")
		return 1, true
	case "run", "settings":
	default:
		fmt.Fprintln(os.Stderr, "updater startup helper: unknown mode")
		return 1, true
	}

	dir, e := os.MkdirTemp("", "passme-updater-startup-")
	if e != nil {
		fmt.Fprintln(os.Stderr, "updater startup helper: cannot create owned data directory")
		return 1, true
	}
	defer os.RemoveAll(dir)
	// Keep the real HOME/CODEX_HOME and other user directories untouched.
	// This helper process owns only its MyGo user-data directory.
	mygo.App.SetPath(mygo.PathUserData, dir)

	desktopStartupBoundary = func() error { return errUpdaterStartupBoundary }
	var err error
	if mode == "run" {
		err = Run()
	} else {
		err = RunWithSettingsPath(filepath.Join(dir, "settings.json"))
	}
	if !errors.Is(err, errUpdaterStartupBoundary) {
		fmt.Fprintln(os.Stderr, "updater startup helper: entry point did not reach the startup boundary")
		return 1, true
	}
	item := updater.MenuItem()
	if item == nil || strings.TrimSpace(item.Label) == "" {
		fmt.Fprintln(os.Stderr, "updater startup helper: MenuItem did not produce a labeled item")
		return 1, true
	}
	fmt.Fprintln(os.Stdout, updaterRegisteredMarker)
	return 0, true
}

// TestUpdaterStartupHelper guards the TestMain dispatch. It must never run in
// helper mode: doing so would call MyGo's main-thread API from a testing
// goroutine, which waits for an event loop that this regression never starts.
func TestUpdaterStartupHelper(t *testing.T) {
	if os.Getenv(updaterStartupHelperEnv) != "" {
		t.Fatal("updater startup helper ran outside the TestMain main-goroutine dispatch")
	}
}

// TestUpdaterStartupRegistersNativeMenu proves both desktop entry points
// register MyGo's native updater before any App or GUI state. The unregistered
// control demonstrates the panic the tray's updater.MenuItem call hits when the
// registration is missing; the registered children prove the real plugin setup
// makes MenuItem succeed. No child enters App.Run or opens a window.
func TestUpdaterStartupRegistersNativeMenu(t *testing.T) {
	t.Run("unregistered-menu-item-panics-exit-2", func(t *testing.T) {
		out, code := runUpdaterStartupHelper(t, "unregistered")
		if code != 2 {
			t.Fatalf("unregistered helper exit code = %d, want Go panic exit 2; output:\n%s", code, out)
		}
		if !strings.Contains(out, "updater: the plugin is not used") {
			t.Fatalf("unregistered helper did not report the real updater refusal; output:\n%s", out)
		}
	})

	for _, mode := range []string{"run", "settings"} {
		t.Run(mode+"-registers-before-startup", func(t *testing.T) {
			out, code := runUpdaterStartupHelper(t, mode)
			if code != 0 {
				t.Fatalf("%s helper exit code = %d, want 0; output:\n%s", mode, code, out)
			}
			if !strings.Contains(out, updaterRegisteredMarker) {
				t.Fatalf("%s helper did not reach a working updater.MenuItem; output:\n%s", mode, out)
			}
		})
	}
}

func runUpdaterStartupHelper(t *testing.T, mode string) (string, int) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("locate test binary: %v", err)
	}
	env := make([]string, 0, len(os.Environ())+1)
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		switch key {
		case updaterStartupHelperEnv, "PASSME_NATIVE_SMOKE", "PASSME_NATIVE_FOREGROUND", "PASSME_SCREENSHOTS":
			continue
		}
		env = append(env, entry)
	}
	env = append(env, updaterStartupHelperEnv+"="+mode)
	ctx, cancel := context.WithTimeout(context.Background(), updaterHelperTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestUpdaterStartupHelper$")
	cmd.Env = env
	cmd.WaitDelay = time.Second
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		t.Fatalf("%s helper exceeded %s and was killed", mode, updaterHelperTimeout)
	}
	if err == nil {
		return string(out), 0
	}
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		t.Fatalf("run updater startup helper: %v", err)
	}
	return string(out), exit.ExitCode()
}
