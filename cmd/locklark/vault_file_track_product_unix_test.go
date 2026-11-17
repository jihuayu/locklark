//go:build darwin || linux

package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
	"golang.org/x/sys/unix"
)

func newTrackProductCase(t *testing.T, material resumeProductMaterial) importProductCase {
	t.Helper()
	c := newRemoteProductCase(t, material)
	input := filepath.Join(c.root, "input.locklark")
	if os.WriteFile(input, material.p, 0600) != nil {
		t.Fatal("TRACK_INPUT_CREATE_FAILED")
	}
	return importProductCase{resumeProductCase: c, inputPath: input}
}

// Only static outcome enums escape the owned process's captured output.
func runTrackProduct(product, config string, restrictiveMask bool) string {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	args := []string{"vault-file", "track-existing", "--config", config}
	cmd := exec.CommandContext(ctx, product, args...)
	if restrictiveMask {
		// The umask belongs only to this child shell, which execs the actual
		// product. The test driver and operator environment are unchanged.
		cmd = exec.CommandContext(ctx, "/bin/sh", append([]string{"-c", `umask 0777; exec "$@"`, "owned-track", product}, args...)...)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		return "PRODUCT_TIMED_OUT"
	}
	if err == nil && stdout.String() == "{\"status\":\"TRACKED\"}\n" && stderr.Len() == 0 {
		return "TRACKED"
	}
	if err != nil && stdout.Len() == 0 {
		for _, enum := range []string{"TARGET_EXISTS", "CONFIG_REJECTED", "JOURNAL_REJECTED", "BACKEND_REJECTED", "VERIFY_REJECTED", "LOCAL_UNKNOWN", "CANCELLED", "UNSUPPORTED"} {
			if stderr.String() == "locklark: "+enum+"\n" {
				return enum
			}
		}
	}
	return "PRODUCT_CONTRACT_FAILED"
}

func checkTrackedProductJournal(t *testing.T, c importProductCase, material resumeProductMaterial) {
	t.Helper()
	j, err := vaultfilejournal.OpenExisting(c.cfg.Journal)
	if err != nil {
		t.Fatal("TRACK_JOURNAL_OWNER_REOPEN_FAILED")
	}
	s, err := j.LoadState()
	if err != nil || s.Generation != 0 || s.RemoteRevision != c.initial.Revision ||
		!bytes.Equal(s.BaseBytes, material.r) || !bytes.Equal(s.WorkingBytes, material.r) {
		t.Fatal("TRACK_BASELINE_MISMATCH")
	}
	if _, err := j.Load(); err != vaultfilejournal.ErrEmpty {
		t.Fatal("TRACK_UNEXPECTED_LEGACY")
	}
	if _, err := j.LoadPrepared(); err != vaultfilejournal.ErrEmpty || j.Close() != nil {
		t.Fatal("TRACK_UNEXPECTED_PREPARED")
	}
	info, err := os.Lstat(c.cfg.Journal)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("TRACK_MODE_NOT_OWNER_READ_WRITE")
	}
}

func TestVaultFileTrackProductMinimum(t *testing.T) {
	product := vaultFileProductBinary(t)
	material := newResumeProductMaterial(t)
	c := newTrackProductCase(t, material)
	if _, err := os.Lstat(c.cfg.Journal); !os.IsNotExist(err) {
		t.Fatal("TRACK_FIXTURE_ALREADY_HAS_JOURNAL")
	}
	before := resumeDisk(t, c.cfg.BackendRoot)
	if runTrackProduct(product, c.configPath, false) != "TRACKED" {
		t.Fatal("TRACK_PRODUCT_MINIMUM_FAILED")
	}
	if !maps.Equal(before, resumeDisk(t, c.cfg.BackendRoot)) {
		t.Fatal("TRACK_CHANGED_BACKEND")
	}
	checkTrackedProductJournal(t, c, material)
	invokeImportProduct(t, product, c, "PREPARED")
	invokeResumeProduct(t, product, c.configPath, "RESUMED")
	verifyResumeProductResult(t, c.resumeProductCase, material, "")
}

func TestVaultFileTrackProductMatrix(t *testing.T) {
	product := vaultFileProductBinary(t)
	material := newResumeProductMaterial(t)
	t.Run("TWO_REAL_PROCESSES_ONE_TARGET", func(t *testing.T) {
		c := newTrackProductCase(t, material)
		ready, results := make(chan struct{}), make(chan string, 2)
		for range 2 {
			go func() { <-ready; results <- runTrackProduct(product, c.configPath, false) }()
		}
		close(ready)
		counts := map[string]int{}
		for range 2 {
			counts[<-results]++
		}
		if counts["TRACKED"] != 1 || counts["TARGET_EXISTS"] != 1 {
			t.Fatal("TRACK_EXCLUSIVE_RACE_FAILED")
		}
		checkTrackedProductJournal(t, c, material)
	})
	t.Run("CHILD_UMASK_OWNER_REOPEN", func(t *testing.T) {
		c := newTrackProductCase(t, material)
		if runTrackProduct(product, c.configPath, true) != "TRACKED" {
			t.Fatal("TRACK_RESTRICTIVE_UMASK_FAILED")
		}
		checkTrackedProductJournal(t, c, material)
		invokeImportProduct(t, product, c, "PREPARED")
		invokeResumeProduct(t, product, c.configPath, "RESUMED")
		verifyResumeProductResult(t, c.resumeProductCase, material, "")
	})
	t.Run("ANCESTOR_ALIAS_OWNER_REOPEN", func(t *testing.T) {
		c := newTrackProductCase(t, material)
		parent := filepath.Join(c.root, "state")
		if os.Mkdir(parent, 0700) != nil {
			t.Fatal("TRACK_ALIAS_PARENT_FIXTURE_FAILED")
		}
		alias := resumeScopeAlias(t, c.resumeProductCase, c.root)
		c.cfg.Journal = filepath.Join(alias, "state", "journal.db")
		writeResumeScopeConfig(t, c.resumeProductCase)
		if runTrackProduct(product, c.configPath, false) != "TRACKED" {
			t.Fatal("TRACK_CANONICAL_PARENT_FAILED")
		}
		checkTrackedProductJournal(t, c, material)
		invokeImportProduct(t, product, c, "PREPARED")
		invokeResumeProduct(t, product, c.configPath, "RESUMED")
		verifyResumeProductResult(t, c.resumeProductCase, material, "")
	})
	cases := []string{"EXISTING_EMPTY", "EXISTING_CORRUPT", "EXISTING_BASELINE", "EXISTING_EDIT", "EXISTING_PREPARED", "EXISTING_SYMLINK", "EXISTING_DIRECTORY", "EXISTING_FIFO",
		"WRONG_PIN", "FOREIGN_REMOTE", "MALFORMED_REMOTE", "MISSING_REMOTE", "MISSING_BACKEND", "MISSING_LOCK", "MISSING_PARENT", "SHARED_PARENT", "SHARED_CONFIG", "JOURNAL_NAMESPACE", "CONFIG_NAMESPACE"}
	if resumeScopeCaseAliases(t) {
		cases = append(cases, "CASE_NAMESPACE_ALIAS", "CASE_EXISTING_TARGET")
	}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			c := newTrackProductCase(t, material)
			want := "TARGET_EXISTS"
			switch name {
			case "EXISTING_EMPTY", "EXISTING_CORRUPT", "CASE_EXISTING_TARGET":
				data := []byte{}
				if name != "EXISTING_EMPTY" {
					data = []byte("owned corrupt existing target")
				}
				if os.WriteFile(c.cfg.Journal, data, 0600) != nil {
					t.Fatal("TRACK_EXISTING_FIXTURE_FAILED")
				}
				if name == "CASE_EXISTING_TARGET" {
					c.cfg.Journal = filepath.Join(c.root, "JOURNAL.DB")
					writeResumeScopeConfig(t, c.resumeProductCase)
				}
			case "EXISTING_BASELINE", "EXISTING_EDIT", "EXISTING_PREPARED":
				j, err := vaultfilejournal.Open(c.cfg.Journal)
				if err != nil || j.InitializeEmptyState(vaultfilejournal.State{BaseBytes: material.r, WorkingBytes: material.r, RemoteRevision: c.initial.Revision}) != nil {
					t.Fatal("TRACK_EXISTING_STATE_FIXTURE_FAILED")
				}
				if name != "EXISTING_BASELINE" && j.UpdateWorking(0, material.p) != nil {
					t.Fatal("TRACK_EXISTING_EDIT_FIXTURE_FAILED")
				}
				if name == "EXISTING_PREPARED" && j.Prepare(1, vaultfilejournal.Proposal{Generation: 1, OperationID: "prepared-operation", ExpectedRevision: c.initial.Revision, Bytes: material.p}) != nil {
					t.Fatal("TRACK_EXISTING_PREPARED_FIXTURE_FAILED")
				}
				if j.Close() != nil {
					t.Fatal("TRACK_EXISTING_CLOSE_FAILED")
				}
			case "EXISTING_SYMLINK":
				if os.Symlink(c.inputPath, c.cfg.Journal) != nil {
					t.Fatal("TRACK_SYMLINK_FIXTURE_FAILED")
				}
			case "EXISTING_DIRECTORY":
				if os.Mkdir(c.cfg.Journal, 0700) != nil {
					t.Fatal("TRACK_DIRECTORY_FIXTURE_FAILED")
				}
			case "EXISTING_FIFO":
				if unix.Mkfifo(c.cfg.Journal, 0600) != nil {
					t.Fatal("TRACK_FIFO_FIXTURE_FAILED")
				}
			case "WRONG_PIN":
				want = "VERIFY_REJECTED"
				cp := *c.cfg.Checkpoint
				cp.OwnerRootPublicKey = hex.EncodeToString(bytes.Repeat([]byte{0x11}, 32))
				c.cfg.Checkpoint = &cp
				writeResumeScopeConfig(t, c.resumeProductCase)
			case "FOREIGN_REMOTE", "MALFORMED_REMOTE":
				want = "VERIFY_REJECTED"
				data := []byte("owned malformed remote")
				if name == "FOREIGN_REMOTE" {
					data = newResumeProductMaterial(t).r
				}
				b, err := vaultfilebackend.OpenExistingDir(c.cfg.BackendRoot)
				if err != nil || b.ReplaceIfVersion(context.Background(), c.cfg.Name, c.initial.Revision, data) != nil || b.Close() != nil {
					t.Fatal("TRACK_INVALID_REMOTE_FIXTURE_FAILED")
				}
			case "MISSING_REMOTE":
				want, c.cfg.Name = "BACKEND_REJECTED", "missing.locklark"
				writeResumeScopeConfig(t, c.resumeProductCase)
			case "MISSING_BACKEND":
				want = "BACKEND_REJECTED"
				if os.RemoveAll(c.cfg.BackendRoot) != nil {
					t.Fatal("TRACK_MISSING_BACKEND_FIXTURE_FAILED")
				}
			case "MISSING_LOCK":
				want = "BACKEND_REJECTED"
				if os.Remove(filepath.Join(c.cfg.BackendRoot, "vaultfile-backend", "v1", ".locklark-vaultfile.lock")) != nil {
					t.Fatal("TRACK_MISSING_LOCK_FIXTURE_FAILED")
				}
			case "MISSING_PARENT":
				want, c.cfg.Journal = "CONFIG_REJECTED", filepath.Join(c.root, "missing", "journal.db")
				writeResumeScopeConfig(t, c.resumeProductCase)
			case "SHARED_PARENT":
				want = "JOURNAL_REJECTED"
				parent := filepath.Join(c.root, "shared")
				if os.Mkdir(parent, 0700) != nil || os.Chmod(parent, 0755) != nil {
					t.Fatal("TRACK_SHARED_PARENT_FIXTURE_FAILED")
				}
				c.cfg.Journal = filepath.Join(parent, "journal.db")
				writeResumeScopeConfig(t, c.resumeProductCase)
			case "SHARED_CONFIG":
				want = "CONFIG_REJECTED"
				if os.Chmod(c.configPath, 0644) != nil {
					t.Fatal("TRACK_SHARED_CONFIG_FIXTURE_FAILED")
				}
			case "JOURNAL_NAMESPACE", "CASE_NAMESPACE_ALIAS":
				want = "CONFIG_REJECTED"
				ns := "vaultfile-backend"
				if name == "CASE_NAMESPACE_ALIAS" {
					ns = "VAULTFILE-BACKEND"
				}
				c.cfg.Journal = filepath.Join(c.cfg.BackendRoot, ns, "v1", "tmp", "op-00112233445566778899aabbccddeeff")
				writeResumeScopeConfig(t, c.resumeProductCase)
			case "CONFIG_NAMESPACE":
				want = "CONFIG_REJECTED"
				moveResumeScopeConfig(t, &c.resumeProductCase, filepath.Join(c.cfg.BackendRoot, "vaultfile-backend", "v1", "tmp", "op-00112233445566778899aabbccddeeff"))
			}
			before := resumeDisk(t, c.root)
			if runTrackProduct(product, c.configPath, false) != want {
				t.Fatal("TRACK_REFUSAL_CONTRACT_FAILED")
			}
			if !maps.Equal(before, resumeDisk(t, c.root)) {
				t.Fatal("TRACK_REFUSAL_CHANGED_DISK")
			}
		})
	}
}
