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
	bolt "go.etcd.io/bbolt"
	"golang.org/x/sys/unix"
)

type importProductCase struct {
	resumeProductCase
	inputPath string
}

func newImportProductCase(t *testing.T, material resumeProductMaterial) importProductCase {
	t.Helper()
	c := newBaselineProductCase(t, material)
	input := filepath.Join(c.root, "input.locklark")
	if os.WriteFile(input, material.p, 0600) != nil {
		t.Fatal("IMPORT_INPUT_CREATE_FAILED")
	}
	return importProductCase{resumeProductCase: c, inputPath: input}
}

func invokeImportProduct(t *testing.T, product string, c importProductCase, want string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, product, "vault-file", "import-prepared", "--config", c.configPath, "--input", c.inputPath)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		t.Fatal("IMPORT_PRODUCT_TIMED_OUT")
	}
	if want == "PREPARED" {
		if err != nil || stdout.String() != "{\"status\":\"PREPARED\"}\n" || stderr.Len() != 0 {
			t.Fatal("IMPORT_PRODUCT_SUCCESS_CONTRACT_FAILED")
		}
	} else if err == nil || stdout.Len() != 0 || stderr.String() != "locklark: "+want+"\n" {
		t.Fatal("IMPORT_PRODUCT_REFUSAL_CONTRACT_FAILED")
	}
}

func checkImportedProductJournal(t *testing.T, c importProductCase, material resumeProductMaterial) {
	t.Helper()
	j, err := vaultfilejournal.OpenExisting(c.cfg.Journal)
	if err != nil {
		t.Fatal("IMPORT_RESULT_JOURNAL_OPEN_FAILED")
	}
	defer j.Close()
	s, err := j.LoadState()
	if err != nil || s.Generation != 1 || s.RemoteRevision != c.initial.Revision ||
		!bytes.Equal(s.BaseBytes, material.r) || !bytes.Equal(s.WorkingBytes, material.p) {
		t.Fatal("IMPORT_RESULT_STATE_MISMATCH")
	}
	if _, err := j.Load(); err != vaultfilejournal.ErrEmpty {
		t.Fatal("IMPORT_CREATED_LEGACY_RECORD")
	}
	pp, err := j.LoadPrepared()
	if err != nil || pp.WorkingGeneration != 1 || pp.Proposal.Generation != 1 ||
		pp.Proposal.OperationID != "prepared-operation" || pp.Proposal.ExpectedRevision != c.initial.Revision ||
		!bytes.Equal(pp.Proposal.Bytes, material.p) {
		t.Fatal("IMPORT_RESULT_PREPARED_MISMATCH")
	}
}

// Reading a real persisted bbolt transaction counter proves that an exact
// prepared retry did another DB.Update. No counter or file bytes are printed.
func importedProductTransaction(t *testing.T, path string) int {
	t.Helper()
	db, err := bolt.Open(path, 0600, &bolt.Options{ReadOnly: true, Timeout: time.Second})
	if err != nil {
		t.Fatal("IMPORT_TRANSACTION_INSPECTION_OPEN_FAILED")
	}
	defer db.Close()
	var id int
	if db.View(func(tx *bolt.Tx) error { id = tx.ID(); return nil }) != nil {
		t.Fatal("IMPORT_TRANSACTION_INSPECTION_FAILED")
	}
	return id
}

func TestVaultFileImportProductMinimum(t *testing.T) {
	product := vaultFileProductBinary(t)
	material := newResumeProductMaterial(t)
	c := newImportProductCase(t, material)
	// A backend read would clean this dead holder and staged file. Import
	// must leave both intact; only the later explicit resume may recover them.
	base := filepath.Join(c.cfg.BackendRoot, "vaultfile-backend", "v1")
	id := "00112233445566778899aabbccddeeff"
	if os.WriteFile(filepath.Join(base, "tmp", "op-"+id), []byte("staged"), 0600) != nil ||
		os.WriteFile(filepath.Join(base, ".locklark-vaultfile.lock"), []byte("holder "+id+"\n"), 0600) != nil {
		t.Fatal("IMPORT_NO_BACKEND_READ_FIXTURE_FAILED")
	}
	before := resumeDisk(t, c.cfg.BackendRoot)
	invokeImportProduct(t, product, c, "PREPARED")
	if !maps.Equal(before, resumeDisk(t, c.cfg.BackendRoot)) {
		t.Fatal("IMPORT_READ_OR_CHANGED_BACKEND")
	}
	checkImportedProductJournal(t, c, material)
	input, err := os.ReadFile(c.inputPath)
	if err != nil || !bytes.Equal(input, material.p) {
		t.Fatal("IMPORT_CHANGED_INPUT")
	}
	// This is a second real product process, consuming the record that the
	// first product process made, not one prepared by the fixture creator.
	invokeResumeProduct(t, product, c.configPath, "RESUMED")
	verifyResumeProductResult(t, c.resumeProductCase, material, "")
}

func TestVaultFileImportProductMatrix(t *testing.T) {
	product := vaultFileProductBinary(t)
	material := newResumeProductMaterial(t)
	t.Run("EXACT_PREPARED_RETRY_SYNCS", func(t *testing.T) {
		c := newImportProductCase(t, material)
		invokeImportProduct(t, product, c, "PREPARED")
		before := importedProductTransaction(t, c.cfg.Journal)
		backend := resumeDisk(t, c.cfg.BackendRoot)
		invokeImportProduct(t, product, c, "PREPARED")
		if importedProductTransaction(t, c.cfg.Journal) <= before || !maps.Equal(backend, resumeDisk(t, c.cfg.BackendRoot)) {
			t.Fatal("EXACT_RETRY_DID_NOT_USE_REAL_DB_UPDATE")
		}
		checkImportedProductJournal(t, c, material)
	})
	t.Run("PARTIAL_STATE_RESTART", func(t *testing.T) {
		c := newImportProductCase(t, material)
		j, err := vaultfilejournal.OpenExisting(c.cfg.Journal)
		if err != nil || j.UpdateWorking(0, material.p) != nil || j.Close() != nil {
			t.Fatal("PARTIAL_STATE_FIXTURE_FAILED")
		}
		invokeImportProduct(t, product, c, "PREPARED")
		checkImportedProductJournal(t, c, material)
		invokeResumeProduct(t, product, c.configPath, "RESUMED")
		verifyResumeProductResult(t, c.resumeProductCase, material, "")
	})
	t.Run("UNKNOWN_REMOTE_PRESERVES_NEW_EDIT", func(t *testing.T) {
		c := newImportProductCase(t, material)
		invokeImportProduct(t, product, c, "PREPARED")
		backend, err := vaultfilebackend.OpenExistingDir(c.cfg.BackendRoot)
		if err != nil || backend.ReplaceIfVersion(context.Background(), c.cfg.Name, c.initial.Revision, material.s) != nil || backend.Close() != nil {
			t.Fatal("IMPORT_UNKNOWN_REMOTE_FIXTURE_FAILED")
		}
		j, err := vaultfilejournal.OpenExisting(c.cfg.Journal)
		if err != nil || j.UpdateWorking(1, material.w) != nil || j.Close() != nil {
			t.Fatal("IMPORT_NEW_EDIT_FIXTURE_FAILED")
		}
		before := resumeDisk(t, c.root)
		invokeResumeProduct(t, product, c.configPath, "UNKNOWN_REVIEW")
		if !maps.Equal(before, resumeDisk(t, c.root)) {
			t.Fatal("IMPORT_UNKNOWN_LOST_PERSISTED_STATE")
		}
	})
	for _, name := range []string{
		"OTHER_WORKING", "LEGACY_PENDING", "LEGACY_CORRUPT", "PREPARED_OTHER_OPERATION", "PREPARED_OTHER_GENERATION",
		"PREPARED_NEWER_WORKING", "INPUT_NOT_SUCCESSOR", "INPUT_FOREIGN_PIN", "CONFIG_WRONG_PIN", "MISSING_INPUT",
		"SHARED_INPUT", "OVERSIZE_INPUT", "FIFO_INPUT", "INPUT_IS_CONFIG", "INPUT_IS_JOURNAL", "INPUT_NAMESPACE",
		"INPUT_NAMESPACE_ANCESTOR_ALIAS", "CONFIG_NAMESPACE", "JOURNAL_NAMESPACE", "MISSING_JOURNAL", "EMPTY_JOURNAL",
	} {
		t.Run(name, func(t *testing.T) {
			c := newImportProductCase(t, material)
			want := "LOCAL_REVIEW"
			switch name {
			case "OTHER_WORKING", "LEGACY_PENDING", "LEGACY_CORRUPT", "PREPARED_OTHER_OPERATION", "PREPARED_OTHER_GENERATION", "PREPARED_NEWER_WORKING":
				j, err := vaultfilejournal.OpenExisting(c.cfg.Journal)
				if err != nil {
					t.Fatal("IMPORT_REJECTION_JOURNAL_OPEN_FAILED")
				}
				if name == "OTHER_WORKING" {
					err = j.UpdateWorking(0, material.s)
				} else if name == "LEGACY_PENDING" || name == "LEGACY_CORRUPT" {
					err = j.Save(vaultfilejournal.Proposal{Generation: 1, OperationID: "legacy-operation", ExpectedRevision: c.initial.Revision, Bytes: material.p})
				} else {
					err = j.UpdateWorking(0, material.p)
					p := vaultfilejournal.Proposal{Generation: 1, OperationID: "prepared-operation", ExpectedRevision: c.initial.Revision, Bytes: material.p}
					if name == "PREPARED_OTHER_OPERATION" {
						p.OperationID = "other-operation"
					} else if name == "PREPARED_OTHER_GENERATION" {
						p.Generation = 2
					}
					if err == nil {
						err = j.Prepare(1, p)
					}
					if err == nil && name == "PREPARED_NEWER_WORKING" {
						err = j.UpdateWorking(1, material.p)
					}
				}
				closed := j.Close()
				if err != nil || closed != nil {
					t.Fatal("IMPORT_PENDING_FIXTURE_FAILED")
				}
				if name == "LEGACY_CORRUPT" {
					db, err := bolt.Open(c.cfg.Journal, 0600, nil)
					if err != nil {
						t.Fatal("IMPORT_CORRUPT_FIXTURE_OPEN_FAILED")
					}
					if db.Update(func(tx *bolt.Tx) error {
						return tx.Bucket([]byte("journal")).Put([]byte("proposal"), []byte("corrupt"))
					}) != nil || db.Close() != nil {
						t.Fatal("IMPORT_CORRUPT_FIXTURE_FAILED")
					}
				}
			case "INPUT_NOT_SUCCESSOR", "INPUT_FOREIGN_PIN":
				want = "VERIFY_REJECTED"
				input := material.w
				if name == "INPUT_FOREIGN_PIN" {
					input = newResumeProductMaterial(t).p
				}
				if os.WriteFile(c.inputPath, input, 0600) != nil {
					t.Fatal("IMPORT_INVALID_INPUT_FIXTURE_FAILED")
				}
			case "CONFIG_WRONG_PIN":
				want = "VERIFY_REJECTED"
				cp := *c.cfg.Checkpoint
				cp.OwnerRootPublicKey = hex.EncodeToString(bytes.Repeat([]byte{0x11}, 32))
				c.cfg.Checkpoint = &cp
				writeResumeScopeConfig(t, c.resumeProductCase)
			case "MISSING_INPUT":
				want = "INPUT_REJECTED"
				c.inputPath = filepath.Join(c.root, "missing-input")
			case "SHARED_INPUT":
				want = "INPUT_REJECTED"
				if os.Chmod(c.inputPath, 0644) != nil {
					t.Fatal("IMPORT_SHARED_INPUT_FIXTURE_FAILED")
				}
			case "OVERSIZE_INPUT":
				want = "INPUT_REJECTED"
				if os.Truncate(c.inputPath, vaultfilebackend.MaxValueSize+1) != nil {
					t.Fatal("IMPORT_OVERSIZE_FIXTURE_FAILED")
				}
			case "FIFO_INPUT":
				want = "INPUT_REJECTED"
				if os.Remove(c.inputPath) != nil || unix.Mkfifo(c.inputPath, 0600) != nil {
					t.Fatal("IMPORT_FIFO_FIXTURE_FAILED")
				}
			case "INPUT_IS_CONFIG":
				want = "CONFIG_REJECTED"
				c.inputPath = c.configPath
			case "INPUT_IS_JOURNAL":
				want = "CONFIG_REJECTED"
				c.inputPath = c.cfg.Journal
			case "INPUT_NAMESPACE", "INPUT_NAMESPACE_ANCESTOR_ALIAS", "CONFIG_NAMESPACE", "JOURNAL_NAMESPACE":
				want = "CONFIG_REJECTED"
				v1 := filepath.Join(c.cfg.BackendRoot, "vaultfile-backend", "v1")
				target := filepath.Join(v1, "tmp", "op-00112233445566778899aabbccddeeff")
				if name == "CONFIG_NAMESPACE" {
					moveResumeScopeConfig(t, &c.resumeProductCase, target)
				} else if name == "JOURNAL_NAMESPACE" {
					moveResumeScopeJournal(t, &c.resumeProductCase, target)
					writeResumeScopeConfig(t, c.resumeProductCase)
				} else {
					if os.Rename(c.inputPath, target) != nil {
						t.Fatal("IMPORT_SCOPE_INPUT_MOVE_FAILED")
					}
					c.inputPath = target
					if name == "INPUT_NAMESPACE_ANCESTOR_ALIAS" {
						alias := resumeScopeAlias(t, c.resumeProductCase, v1)
						c.inputPath = filepath.Join(alias, "tmp", filepath.Base(target))
					}
				}
			case "MISSING_JOURNAL", "EMPTY_JOURNAL":
				want = "JOURNAL_REJECTED"
				var err error
				if name == "MISSING_JOURNAL" {
					err = os.Remove(c.cfg.Journal)
				} else {
					err = os.Truncate(c.cfg.Journal, 0)
				}
				if err != nil {
					t.Fatal("IMPORT_MISSING_JOURNAL_FIXTURE_FAILED")
				}
			}
			before := resumeDisk(t, c.root)
			invokeImportProduct(t, product, c, want)
			if !maps.Equal(before, resumeDisk(t, c.root)) {
				t.Fatal("IMPORT_REFUSAL_CHANGED_DISK")
			}
		})
	}
}
