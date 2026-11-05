//go:build (windows || darwin) && (amd64 || arm64)

package nativeclipboard

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"testing"
	"time"
)

func TestNativeClipboardSmoke(t *testing.T) {
	if os.Getenv("LOCKLARK_TEST_NATIVE_CLIPBOARD") != "1" {
		t.Skip("native clipboard smoke requires explicit opt-in")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if mode := os.Getenv("LOCKLARK_CLIPBOARD_CHILD"); mode != "" {
		smokeChild(t, mode)
		return
	}
	value := []byte("Synthetic clipboard 雪🙂𝄞")
	first, err := Write(value)
	if err != nil || first == nil {
		t.Fatal("native Unicode acquisition failed")
	}
	if !readSmokeOwned(first, value) {
		t.Fatal("native Unicode content mismatch")
	}
	if ClearOwned(first) != Cleared {
		t.Fatal("native owned cleanup failed")
	}
	first, err = Write(value)
	if err != nil {
		t.Fatal("native reacquisition failed")
	}
	second, err := Write(value)
	if err != nil {
		t.Fatal("same-value native acquisition failed")
	}
	if ClearOwned(first) != Superseded || !readSmokeOwned(second, value) {
		t.Fatal("old lease erased same-value acquisition")
	}
	if ClearOwned(second) != Cleared {
		t.Fatal("new lease cleanup failed")
	}
	first, err = Write(value)
	if err != nil {
		t.Fatal("foreign-owner precondition failed")
	}
	finish := startSmokeChild(t, "owner")
	before := smokeOwnership()
	if ClearOwned(first) != Superseded || smokeOwnership() != before {
		t.Fatal("foreign same-value owner was changed")
	}
	finish()
	smokePlatformCases(t, value)
}

func startSmokeChild(t *testing.T, mode string) func() {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestNativeClipboardSmoke$", "-test.count=1")
	command.Env = append(os.Environ(), "LOCKLARK_CLIPBOARD_CHILD="+mode)
	in, err := command.StdinPipe()
	if err != nil {
		cancel()
		t.Fatal("child input pipe failed")
	}
	out, err := command.StdoutPipe()
	if err != nil {
		cancel()
		t.Fatal("child output pipe failed")
	}
	if err = command.Start(); err != nil {
		cancel()
		t.Fatal("native child failed to start")
	}
	scanner := bufio.NewScanner(out)
	if err := smokeWait(func() error {
		if !scanner.Scan() || scanner.Text() != "ready" {
			return ErrUnavailable
		}
		return nil
	}); err != nil {
		cancel()
		_ = command.Wait()
		t.Fatal("native child precondition failed")
	}
	return func() {
		_, _ = in.Write([]byte("finish\n"))
		_ = in.Close()
		// Drain fixed testing output so no pipe can keep the child alive.
		err := smokeWait(func() error {
			for scanner.Scan() {
			}
			return command.Wait()
		})
		cancel()
		if err != nil {
			t.Fatal("native child cleanup failed")
		}
	}
}

func smokeChild(t *testing.T, mode string) {
	var finish func()
	if mode == "busy" {
		finish = smokeHoldClipboard(t)
	} else {
		lease, err := Write([]byte("Synthetic clipboard 雪🙂𝄞"))
		if err != nil {
			t.Fatal("child native acquisition failed")
		}
		finish = func() {
			if ClearOwned(lease) != Cleared {
				t.Fatal("child cleanup failed")
			}
		}
	}
	fmt.Println("ready")
	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() || scanner.Text() != "finish" {
		t.Fatal("child control failed")
	}
	finish()
}
