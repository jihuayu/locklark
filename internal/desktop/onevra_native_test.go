package desktop

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/egoist/mygo"
	"github.com/oneo-me/onevra/source/shells/plain"
	"github.com/oneo-me/onevra/source/theme"
)

func TestMain(m *testing.M) {
	if os.Getenv("LOCKLARK_NATIVE_SMOKE") != "1" {
		os.Exit(m.Run())
	}
	dir, err := os.MkdirTemp("", "locklark-desktop-native-smoke-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	mygo.App.SetName("Locklark native smoke")
	mygo.App.SetPath(mygo.PathUserData, dir)
	if os.Getenv("LOCKLARK_NATIVE_FOREGROUND") != "1" {
		mygo.App.SetActivationPolicy(mygo.ActivationPolicyAccessory)
	}
	mygo.App.OnWindowAllClosed(func() {})
	result := make(chan int, 1)
	mygo.App.WhenReady(func() {
		go func() {
			result <- m.Run()
			mygo.App.Quit()
		}()
	})
	if err = mygo.App.Run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		_ = os.RemoveAll(dir)
		os.Exit(1)
	}
	code := <-result
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func TestOnevraNativeWindowSnapshot(t *testing.T) {
	if os.Getenv("LOCKLARK_NATIVE_SMOKE") != "1" {
		t.Skip("requires LOCKLARK_NATIVE_SMOKE=1 in a Windows desktop session")
	}
	a := newOnevraTestApp()
	var shell *plain.Shell
	mygo.RunOnMain(func() {
		shell = plain.NewShell(plain.ShellOptions{
			Title:         "Locklark · Onevra desktop",
			Width:         1240,
			Height:        820,
			MinWidth:      980,
			MinHeight:     680,
			Hidden:        os.Getenv("LOCKLARK_NATIVE_FOREGROUND") != "1",
			Theme:         theme.Onevra,
			HeaderLeading: a.onevraHeaderLeading,
			HeaderActions: a.onevraHeaderActions,
			Content:       a.onevraVaultView,
		})
		a.win = shell.Window()
	})
	if shell == nil {
		t.Fatal("Onevra shell was not created")
	}
	foreground := os.Getenv("LOCKLARK_NATIVE_FOREGROUND") == "1"
	mygo.RunOnMain(func() {
		if !foreground {
			// Windows does not paint a fully hidden window. Keep the capture
			// off-screen and inactive so native frames can render without taking
			// focus or covering the user's desktop.
			shell.Window().SetPosition(-30000, -30000)
			shell.Window().ShowInactive()
		}
	})
	defer mygo.RunOnMain(func() {
		shell.Window().Hide()
		shell.Window().Destroy()
	})

	for range 5 {
		mygo.RunOnMain(shell.Window().Invalidate)
		time.Sleep(100 * time.Millisecond)
	}
	var data []byte
	var err error
	mygo.RunOnMain(func() {
		shell.Window().Invalidate()
		data, err = shell.Window().CapturePage()
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(data) < 8 || string(data[:8]) != "\x89PNG\r\n\x1a\n" {
		t.Fatalf("native capture is not a PNG: %d bytes", len(data))
	}
	dir := os.Getenv("LOCKLARK_SCREENSHOTS")
	if dir == "" {
		dir = t.TempDir()
	}
	if err = os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "onevra-stage1-windows-native.png")
	if err = os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("native Onevra snapshot: %s", path)
}
