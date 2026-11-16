package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/teamfiles"
	"github.com/jihuayu/locklark/internal/vaultfileclient"
	"golang.org/x/term"
)

// This provisional manifest is deliberately distinct from the v1 resume
// config: it has no policy checkpoint and cannot authorize a backend read or
// write. The path itself is the stable create entry on every invocation.
type vaultFileCreateManifest = vaultfileclient.Manifest

const vaultFileCreateKind = vaultfileclient.CreateKind

func runVaultFileCreate(args []string, out io.Writer) (retErr error) {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		_, err := io.WriteString(out, vaultFileUsage)
		return err
	}
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		return errVaultFileUnsupported
	}
	flags := flag.NewFlagSet("vault-file create", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	config := flags.String("config", "", "private durable create manifest")
	personalFile := flags.String("personal-file", "", "existing personal vault")
	backendRoot := flags.String("backend-root", "", "future local backend root")
	name := flags.String("name", "", "future backend object name")
	journal := flags.String("journal", "", "future local intent journal")
	archive := flags.String("archive", "", "future published recovery archive")
	if flags.Parse(args) != nil || flags.NArg() != 0 || !teamfiles.ValidPath(*config) {
		return errVaultFileConfig
	}
	input := vaultFileCreateManifest{Version: 1, Kind: vaultFileCreateKind,
		PersonalFile: *personalFile, BackendRoot: *backendRoot, Name: *name,
		Journal: *journal, Archive: *archive}
	initial := input.PersonalFile != "" || input.BackendRoot != "" || input.Name != "" || input.Journal != "" || input.Archive != ""
	if initial {
		if !validVaultFileCreateManifestPhase(*config, input, false, false) {
			return errVaultFileConfig
		}
	}
	manifest, exists, err := readVaultFileCreateManifest(*config)
	if err != nil {
		return errVaultFileLocalReview
	}
	if exists {
		if initial && (manifest.PersonalFile != input.PersonalFile || manifest.BackendRoot != input.BackendRoot ||
			manifest.Name != input.Name || manifest.Journal != input.Journal || manifest.Archive != input.Archive) {
			return errVaultFileLocalReview
		}
	} else {
		if !initial {
			return errVaultFileLocalReview
		}
		manifest, err = vaultfileclient.ReserveManifest(*config, input)
		if err != nil {
			return err
		}
	}
	// No backend is opened and no sealed file or key leaves this phase.
	controlInput, controlOutput, err := openRunCLIConsole()
	if err != nil {
		return errVaultFileCancelled
	}
	defer controlInput.Close()
	if controlOutput != controlInput {
		defer controlOutput.Close()
	}
	fd := int(controlInput.Fd())
	state, err := term.MakeRaw(fd)
	if err != nil {
		return errVaultFileCancelled
	}
	var once sync.Once
	var resetErr error
	restore := func() { once.Do(func() { resetErr = term.Restore(fd, state) }) }
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(signals)
	done := make(chan struct{})
	defer func() {
		close(done)
		restore()
		if retErr == nil && resetErr != nil {
			retErr = errVaultFileLocalUnknown
		}
	}()
	go func() {
		select {
		case <-signals:
			restore()
			os.Exit(130)
		case <-done:
		}
	}()
	c := console{reader: consoleByteReader{controlInput}, writer: controlOutput}
	password, err := c.field("主密码")
	if err != nil {
		return errVaultFileCancelled
	}
	defer clear(password)
	secretInput, err := c.field("Secret Key")
	if err != nil {
		return errVaultFileCancelled
	}
	key, err := personal.ParseSecret(string(secretInput))
	clear(secretInput)
	if err != nil {
		return errVaultFileVerification
	}
	defer clear(key)
	session, err := personal.UnlockSession(manifest.PersonalFile, password, key, time.Minute)
	if err != nil {
		return errVaultFileVerification
	}
	defer session.Lock()
	projection, err := session.PrepareVaultFileOwnership(manifest.VaultID)
	if err != nil || projection.VaultID != manifest.VaultID {
		return errVaultFileVerification
	}
	status := `{"status":"BACKUP_REQUIRED"}`
	if _, err := os.Lstat(manifest.Archive); os.IsNotExist(err) {
		companionPath, pathErr := vaultFileCreateCompanionPath(*config)
		if pathErr != nil {
			return pathErr
		}
		if _, journalErr := os.Lstat(manifest.Journal); !os.IsNotExist(journalErr) {
			return errVaultFileLocalReview
		}
		if _, companionErr := os.Lstat(companionPath); !os.IsNotExist(companionErr) {
			return errVaultFileLocalReview
		}
	} else if err != nil {
		return errVaultFileLocalReview
	} else {
		kit, err := c.field("备份恢复码")
		if err != nil {
			return errVaultFileCancelled
		}
		defer clear(kit)
		if err := completeVaultFileCreate(*config, manifest, session, password, key, kit); err != nil {
			return err
		}
		status = `{"status":"LOCAL_BASELINE","remote_freshness":"UNVERIFIED"}`
	}
	session.Lock()
	restore()
	if resetErr != nil {
		return errVaultFileLocalUnknown
	}
	if _, err := fmt.Fprintln(out, status); err != nil {
		return errVaultFileLocalUnknown
	}
	return nil
}

func readVaultFileCreateManifest(path string) (vaultFileCreateManifest, bool, error) {
	return vaultfileclient.ReadManifest(path)
}

func validVaultFileCreateManifestPhase(path string, manifest vaultFileCreateManifest, requireID, journalMustBeNew bool) bool {
	return vaultfileclient.ValidManifestPhase(path, manifest, requireID, journalMustBeNew)
}
