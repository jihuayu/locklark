package teambootstrapcli

import (
	"bytes"
	"context"
	"github.com/jihuayu/locklark/internal/teamclient"
	"github.com/jihuayu/locklark/internal/teamconsent"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestBootstrapNoControllingTerminalRefusesBeforeMutation(t *testing.T) {
	const marker = "LOCKLARK_TEST_BOOTSTRAP_NO_TTY"
	if os.Getenv(marker) == "1" {
		if detachChildConsole() != nil {
			t.Fatal("no controlling console precondition failed")
		}
		at := 0
		for i, arg := range os.Args {
			if arg == "--" {
				at = i + 1
				break
			}
		}
		if at == 0 {
			t.Fatal("child argument setup")
		}
		var out bytes.Buffer
		rt := normalRuntime()
		rt.store = func() teamclient.SystemStore { t.Fatal("OS called without controlling terminal consent"); return nil }
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := run(ctx, os.Args[at:], &out, false, rt); err == nil || ExitCode(err) != 1 || out.Len() != 0 {
			t.Fatal("missing control terminal did not refuse")
		}
		return
	}
	service, d, _ := protectedService(t)
	root := t.TempDir()
	profile, anchor, pins := filepath.Join(root, "owner.profile"), filepath.Join(root, "owner.anchor"), filepath.Join(root, "pins.json")
	fp, _ := teamconsent.Fingerprint(d.Signing)
	args := []string{"-test.run=^TestBootstrapNoControllingTerminalRefusesBeforeMutation$", "--", "create", "--profile", profile, "--anchor", anchor, "--service", service, "--expect-sequencer-fingerprint", fp, "--pins-out", pins}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], args...)
	cmd.Env = append(os.Environ(), marker+"=1")
	cmd.WaitDelay = time.Second
	configureDetached(cmd)
	if cmd.Run() != nil {
		t.Fatal("no controlling terminal child failed")
	}
	for _, path := range []string{profile, profile + ".identity-lease", anchor, pins} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("missing terminal mutated identity")
		}
	}
}
