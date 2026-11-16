package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/teamfiles"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	"golang.org/x/term"
)

// This provisional manifest is deliberately distinct from the v1 resume
// config: it has no policy checkpoint and cannot authorize a backend read or
// write. The path itself is the stable create entry on every invocation.
type vaultFileCreateManifest struct {
	Version      int    `json:"version"`
	Kind         string `json:"kind"`
	VaultID      string `json:"vault_id"`
	PersonalFile string `json:"personal_file"`
	BackendRoot  string `json:"backend_root"`
	Name         string `json:"name"`
	Journal      string `json:"journal"`
	Archive      string `json:"archive"`
}

const vaultFileCreateKind = "vault_file_create"

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
		if !validVaultFileCreateManifest(*config, input, false) {
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
		var selector [16]byte
		if _, err := rand.Read(selector[:]); err != nil {
			return errVaultFileLocalUnknown
		}
		input.VaultID = hex.EncodeToString(selector[:])
		encoded, err := json.Marshal(input)
		if err != nil {
			return errVaultFileLocalUnknown
		}
		defer clear(encoded)
		if err := teamfiles.WriteNew(*config, encoded); err != nil {
			// Another invocation may have won O_EXCL. Only the exact same
			// independently validated manifest can be used on this path.
			manifest, exists, err = readVaultFileCreateManifest(*config)
			if err != nil || !exists || manifest.PersonalFile != input.PersonalFile ||
				manifest.BackendRoot != input.BackendRoot || manifest.Name != input.Name ||
				manifest.Journal != input.Journal || manifest.Archive != input.Archive {
				return errVaultFileLocalUnknown
			}
		} else {
			manifest = input
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
	session.Lock()
	restore()
	if resetErr != nil {
		return errVaultFileLocalUnknown
	}
	if _, err := fmt.Fprintln(out, `{"status":"BACKUP_REQUIRED"}`); err != nil {
		return errVaultFileLocalUnknown
	}
	return nil
}

func readVaultFileCreateManifest(path string) (vaultFileCreateManifest, bool, error) {
	var manifest vaultFileCreateManifest
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return manifest, false, nil
	} else if err != nil {
		return manifest, false, err
	}
	raw, err := teamfiles.Read(path, 64<<10, true)
	if err != nil {
		return manifest, true, err
	}
	defer clear(raw)
	if teamfiles.JSON(raw, &manifest) != nil || !validVaultFileCreateManifest(path, manifest, true) {
		return vaultFileCreateManifest{}, true, errVaultFileLocalReview
	}
	return manifest, true, nil
}

func validVaultFileCreateManifest(path string, manifest vaultFileCreateManifest, requireID bool) bool {
	if manifest.Version != 1 || manifest.Kind != vaultFileCreateKind ||
		!teamfiles.ValidPath(path) || !teamfiles.ValidPath(manifest.PersonalFile) ||
		!teamfiles.ValidPath(manifest.BackendRoot) || !teamfiles.ValidPath(manifest.Journal) ||
		!teamfiles.ValidPath(manifest.Archive) || !vaultfilebackend.ValidName(manifest.Name) ||
		!privateVaultFileCreateParent(filepath.Dir(path)) || !privateVaultFileCreateParent(filepath.Dir(manifest.Journal)) ||
		!teamfiles.Distinct(path, manifest.PersonalFile, manifest.BackendRoot, manifest.Journal, manifest.Archive) {
		return false
	}
	if requireID {
		id, err := hex.DecodeString(manifest.VaultID)
		if err != nil || len(id) != 16 || hex.EncodeToString(id) != manifest.VaultID {
			return false
		}
	} else if manifest.VaultID != "" {
		return false
	}
	info, err := os.Lstat(manifest.PersonalFile)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return false
	}
	if separateVaultFileStatusState(manifest.BackendRoot, path, manifest.PersonalFile, manifest.Journal, manifest.Archive) != nil {
		return false
	}
	if teamfiles.CheckNew(manifest.Journal) != nil {
		return false
	}
	return true
}

func privateVaultFileCreateParent(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.IsDir() && info.Mode().Perm()&0077 == 0
}
