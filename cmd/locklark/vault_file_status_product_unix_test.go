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

	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
	bolt "go.etcd.io/bbolt"
)

func statusProductOutput(state string) string {
	return "{\"status\":\"" + state + "\",\"remote_freshness\":\"UNVERIFIED\"}\n"
}

// Only the four bounded local states and fixed refusal enums escape the owned
// child's captured output. No journal, config or backend content is logged.
func runStatusProduct(product, config string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, product, "vault-file", "status", "--config", config)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		return "PRODUCT_TIMED_OUT"
	}
	if err == nil && stderr.Len() == 0 {
		for _, state := range []string{"CLEAN", "DIRTY", "PREPARED", "REVIEW"} {
			if stdout.String() == statusProductOutput(state) {
				return state
			}
		}
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

func addStatusBackendDeadHolder(t *testing.T, c importProductCase) {
	t.Helper()
	base := filepath.Join(c.cfg.BackendRoot, "vaultfile-backend", "v1")
	id := "00112233445566778899aabbccddeeff"
	if os.WriteFile(filepath.Join(base, "tmp", "op-"+id), []byte("staged"), 0600) != nil ||
		os.WriteFile(filepath.Join(base, ".locklark-vaultfile.lock"), []byte("holder "+id+"\n"), 0600) != nil {
		t.Fatal("STATUS_NO_BACKEND_READ_FIXTURE_FAILED")
	}
}

// The minimum follows the real product path only: one independently built CLI
// creates the journal, status observes that exact journal, the same CLI imports
// a prepared operation, and status observes the pending local record. Status is
// interleaved with a staged backend holder to prove it did not clean or read it.
func TestVaultFileStatusProductMinimum(t *testing.T) {
	product := vaultFileProductBinary(t)
	material := newResumeProductMaterial(t)
	c := newTrackProductCase(t, material)
	if runTrackProduct(product, c.configPath, false) != "TRACKED" {
		t.Fatal("STATUS_MINIMUM_TRACK_FAILED")
	}
	addStatusBackendDeadHolder(t, c)
	before := resumeDisk(t, c.root)
	if got := runStatusProduct(product, c.configPath); got != "CLEAN" {
		t.Fatal("STATUS_MINIMUM_CLEAN_REPORT_FAILED")
	}
	if !maps.Equal(before, resumeDisk(t, c.root)) {
		t.Fatal("STATUS_MINIMUM_CLEAN_CHANGED_DISK")
	}
	invokeImportProduct(t, product, c, "PREPARED")
	before = resumeDisk(t, c.root)
	if got := runStatusProduct(product, c.configPath); got != "PREPARED" {
		t.Fatal("STATUS_MINIMUM_PREPARED_REPORT_FAILED")
	}
	if !maps.Equal(before, resumeDisk(t, c.root)) {
		t.Fatal("STATUS_MINIMUM_PREPARED_CHANGED_DISK")
	}
}

func TestVaultFileStatusProductMatrix(t *testing.T) {
	product := vaultFileProductBinary(t)
	material := newResumeProductMaterial(t)
	cases := []string{
		"CLEAN", "DIRTY", "PREPARED", "LEGACY_PENDING",
		"CORRUPT_STATE", "CORRUPT_LEGACY", "CORRUPT_PREPARED",
		"MISSING_JOURNAL", "EMPTY_JOURNAL", "NO_STATE",
		"SHARED_JOURNAL", "UNSAFE_PARENT", "JOURNAL_SYMLINK",
		"MISSING_JOURNAL_PARENT", "SHARED_CONFIG", "MISSING_CONFIG", "RELATIVE_CONFIG",
		"CONFIG_WRONG_PIN_SHAPE", "CONFIG_NAMESPACE", "JOURNAL_NAMESPACE",
		"MISSING_BACKEND", "MISSING_BACKEND_NAMESPACE", "MISSING_BACKEND_LOCK_LOCAL_ONLY",
	}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			var c resumeProductCase
			if name == "DIRTY" {
				c = newResumeProductCase(t, material, false)
			} else if name == "PREPARED" {
				c = newResumeProductCase(t, material, true)
			} else {
				c = newBaselineProductCase(t, material)
			}
			want := "CLEAN"
			switch name {
			case "DIRTY":
				want = "DIRTY"
			case "PREPARED":
				want = "PREPARED"
			case "LEGACY_PENDING":
				want = "REVIEW"
				journal, err := vaultfilejournal.OpenExisting(c.cfg.Journal)
				if err != nil {
					t.Fatal("STATUS_LEGACY_FIXTURE_OPEN_FAILED")
				}
				err = journal.Save(vaultfilejournal.Proposal{Generation: 1, OperationID: "legacy-operation", ExpectedRevision: c.initial.Revision, Bytes: material.p})
				if err != nil || journal.Close() != nil {
					t.Fatal("STATUS_LEGACY_FIXTURE_FAILED")
				}
			case "CORRUPT_STATE", "CORRUPT_LEGACY", "CORRUPT_PREPARED", "NO_STATE":
				want = "JOURNAL_REJECTED"
				if name == "NO_STATE" {
					if os.Remove(c.cfg.Journal) != nil {
						t.Fatal("STATUS_NO_STATE_FIXTURE_REMOVE_FAILED")
					}
				}
				db, err := bolt.Open(c.cfg.Journal, 0600, nil)
				if err != nil {
					t.Fatal("STATUS_CORRUPT_FIXTURE_OPEN_FAILED")
				}
				if err := db.Update(func(tx *bolt.Tx) error {
					bucket, err := tx.CreateBucketIfNotExists([]byte("journal"))
					if err != nil {
						return err
					}
					switch name {
					case "CORRUPT_STATE":
						return bucket.Put([]byte("state"), []byte("corrupt"))
					case "CORRUPT_LEGACY":
						return bucket.Put([]byte("proposal"), []byte("corrupt"))
					case "CORRUPT_PREPARED":
						return bucket.Put([]byte("prepared"), []byte("corrupt"))
					default:
						return nil
					}
				}); err != nil || db.Close() != nil {
					t.Fatal("STATUS_CORRUPT_FIXTURE_FAILED")
				}
			case "MISSING_JOURNAL":
				want = "JOURNAL_REJECTED"
				if os.Remove(c.cfg.Journal) != nil {
					t.Fatal("STATUS_MISSING_JOURNAL_FIXTURE_FAILED")
				}
			case "EMPTY_JOURNAL":
				want = "JOURNAL_REJECTED"
				if os.Truncate(c.cfg.Journal, 0) != nil {
					t.Fatal("STATUS_EMPTY_JOURNAL_FIXTURE_FAILED")
				}
			case "SHARED_JOURNAL":
				want = "JOURNAL_REJECTED"
				if os.Chmod(c.cfg.Journal, 0644) != nil {
					t.Fatal("STATUS_SHARED_JOURNAL_FIXTURE_FAILED")
				}
			case "UNSAFE_PARENT":
				want = "JOURNAL_REJECTED"
				if os.Chmod(filepath.Dir(c.cfg.Journal), 0755) != nil {
					t.Fatal("STATUS_UNSAFE_PARENT_FIXTURE_FAILED")
				}
			case "JOURNAL_SYMLINK":
				want = "JOURNAL_REJECTED"
				target := filepath.Join(c.root, "journal-target")
				if os.Rename(c.cfg.Journal, target) != nil || os.Symlink(target, c.cfg.Journal) != nil {
					t.Fatal("STATUS_JOURNAL_SYMLINK_FIXTURE_FAILED")
				}
			case "MISSING_JOURNAL_PARENT":
				want = "CONFIG_REJECTED"
				c.cfg.Journal = filepath.Join(c.root, "missing", "journal.db")
				writeResumeScopeConfig(t, c)
			case "SHARED_CONFIG":
				want = "CONFIG_REJECTED"
				if os.Chmod(c.configPath, 0644) != nil {
					t.Fatal("STATUS_SHARED_CONFIG_FIXTURE_FAILED")
				}
			case "MISSING_CONFIG":
				want = "CONFIG_REJECTED"
				c.configPath = filepath.Join(c.root, "missing-operator.json")
			case "RELATIVE_CONFIG":
				want = "CONFIG_REJECTED"
				c.configPath = "operator.json"
			case "CONFIG_WRONG_PIN_SHAPE":
				want = "CONFIG_REJECTED"
				cp := *c.cfg.Checkpoint
				cp.OwnerRootPublicKey = hex.EncodeToString(bytes.Repeat([]byte{0x11}, 31))
				c.cfg.Checkpoint = &cp
				writeResumeScopeConfig(t, c)
			case "CONFIG_NAMESPACE":
				want = "CONFIG_REJECTED"
				moveResumeScopeConfig(t, &c, filepath.Join(c.cfg.BackendRoot, "vaultfile-backend", "v1", "tmp", "op-00112233445566778899aabbccddeeff"))
			case "JOURNAL_NAMESPACE":
				want = "CONFIG_REJECTED"
				moveResumeScopeJournal(t, &c, filepath.Join(c.cfg.BackendRoot, "vaultfile-backend", "v1", "tmp", "op-00112233445566778899aabbccddeeff"))
				writeResumeScopeConfig(t, c)
			case "MISSING_BACKEND":
				if os.RemoveAll(c.cfg.BackendRoot) != nil {
					t.Fatal("STATUS_MISSING_BACKEND_FIXTURE_FAILED")
				}
			case "MISSING_BACKEND_NAMESPACE":
				if os.RemoveAll(filepath.Join(c.cfg.BackendRoot, "vaultfile-backend")) != nil {
					t.Fatal("STATUS_MISSING_BACKEND_NAMESPACE_FIXTURE_FAILED")
				}
			case "MISSING_BACKEND_LOCK_LOCAL_ONLY":
				// Status is local-only: a missing backend lock is not a local
				// journal defect and no backend store is opened to observe it.
				want = "CLEAN"
				if os.Remove(filepath.Join(c.cfg.BackendRoot, "vaultfile-backend", "v1", ".locklark-vaultfile.lock")) != nil {
					t.Fatal("STATUS_MISSING_BACKEND_LOCK_FIXTURE_FAILED")
				}
			}
			before := resumeDisk(t, c.root)
			if got := runStatusProduct(product, c.configPath); got != want {
				t.Fatal("STATUS_PRODUCT_REFUSAL_OR_STATE_MISMATCH")
			}
			if !maps.Equal(before, resumeDisk(t, c.root)) {
				t.Fatal("STATUS_PRODUCT_CHANGED_DISK")
			}
		})
	}
}

// A backend root with a self-referential symlink makes even EvalSymlinks fail.
// All four valid local journal states must still be reported by the real CLI,
// with no backend repair and no change to the configured journal.
func TestVaultFileStatusProductBackendIndependent(t *testing.T) {
	product := vaultFileProductBinary(t)
	material := newResumeProductMaterial(t)
	for _, name := range []string{"CLEAN", "DIRTY", "PREPARED", "REVIEW"} {
		t.Run(name, func(t *testing.T) {
			var c resumeProductCase
			switch name {
			case "DIRTY":
				c = newResumeProductCase(t, material, false)
			case "PREPARED":
				c = newResumeProductCase(t, material, true)
			default:
				c = newBaselineProductCase(t, material)
			}
			if name == "REVIEW" {
				journal, err := vaultfilejournal.OpenExisting(c.cfg.Journal)
				if err != nil {
					t.Fatal("STATUS_OFFLINE_REVIEW_OPEN_FAILED")
				}
				err = journal.Save(vaultfilejournal.Proposal{Generation: 1, OperationID: "legacy-operation", ExpectedRevision: c.initial.Revision, Bytes: material.p})
				if err != nil || journal.Close() != nil {
					t.Fatal("STATUS_OFFLINE_REVIEW_FIXTURE_FAILED")
				}
			}
			if os.RemoveAll(c.cfg.BackendRoot) != nil || os.Symlink(c.cfg.BackendRoot, c.cfg.BackendRoot) != nil {
				t.Fatal("STATUS_OFFLINE_BACKEND_FIXTURE_FAILED")
			}
			before := resumeDisk(t, c.root)
			if got := runStatusProduct(product, c.configPath); got != name {
				t.Fatal("STATUS_OFFLINE_BACKEND_LOCAL_STATE_FAILED")
			}
			if !maps.Equal(before, resumeDisk(t, c.root)) {
				t.Fatal("STATUS_OFFLINE_BACKEND_CHANGED_DISK")
			}
		})
	}
}
