//go:build darwin || linux

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/jihuayu/locklark/internal/vault"
	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
	bolt "go.etcd.io/bbolt"
)

// These tests require the actual root product executable built independently
// with go build ./cmd/locklark. They never substitute run(), a test helper child
// or a verifier callback for that executable.
func vaultFileProductBinary(t *testing.T) string {
	t.Helper()
	path := os.Getenv("LOCKLARK_TEST_VAULTFILE_PRODUCT")
	if path == "" {
		t.Skip("owned product binary is not configured")
	}
	if !filepath.IsAbs(path) {
		t.Fatal("PRODUCT_BINARY_NOT_ABSOLUTE")
	}
	return path
}

type resumeProductMaterial struct {
	config vaultFileCheckpointConfig
	r, p   []byte
	s, w   []byte
}

// The fixture creator generates an independent operator root and checkpoint
// before creating a backend. No backend readback, journal record or test-only
// production verifier supplies trust. Only public checkpoint metadata is kept;
// every private key is confined to this test-side creator.
func newResumeProductMaterial(t *testing.T) resumeProductMaterial {
	t.Helper()
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("OPERATOR_ROOT_CREATE_FAILED")
	}
	defer clear(rootPrivate)
	devicePublic, devicePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("DEVICE_SIGNER_CREATE_FAILED")
	}
	defer clear(devicePrivate)
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal("DEVICE_RECIPIENT_CREATE_FAILED")
	}
	policy := &vaultfile.Policy{
		Format: vaultfile.Format, Version: vaultfile.Version, VaultID: "owned-resume-vault", PolicySeq: 0,
		OwnerRoot: vaultfile.OwnerRoot{KeyID: "independent-operator-root", Alg: vaultfile.PolicySigAlgEd25519,
			PublicKey: rootPublic, Owners: []vaultfile.Principal{{PrincipalID: "operator", Label: "Operator"}}},
		Writers: []vaultfile.Member{{PrincipalID: "operator", Label: "Operator"}},
		Admins:  []vaultfile.Member{{PrincipalID: "operator", Label: "Operator"}},
		Owners:  []vaultfile.Member{{PrincipalID: "operator", Label: "Operator"}},
		Devices: []vaultfile.Device{{DeviceID: "operator-device", PrincipalID: "operator", Label: "Owned device",
			ContentSigningKey: vaultfile.PublicKey{Alg: vaultfile.SigAlgEd25519, PublicKey: devicePublic},
			AgeEncryptionKey:  identity.Recipient().String()}},
	}
	document, err := vaultfile.EncodePolicyDocument(policy)
	if err != nil {
		t.Fatal("OPERATOR_POLICY_CREATE_FAILED")
	}
	pin := vaultfile.PolicyCheckpoint{VaultID: policy.VaultID, OwnerRootKeyID: policy.OwnerRoot.KeyID,
		OwnerRootPublicKey: rootPublic, PolicySeq: policy.PolicySeq, PolicyDigest: vaultfile.PolicyDigest(policy)}
	proof := vaultfile.SignedPolicy{Policy: *policy, Document: document, SignerID: policy.OwnerRoot.KeyID,
		Alg: vaultfile.PolicySigAlgEd25519,
		Sig: ed25519.Sign(rootPrivate, append([]byte(vaultfile.DomainPolicyDocumentSignature+"\x00"), document...))}
	vuk := make([]byte, vaultfile.CEKSize)
	if _, err := rand.Read(vuk); err != nil {
		t.Fatal("EPOCH_KEY_CREATE_FAILED")
	}
	defer clear(vuk)
	seal := func(seq uint64, parent []byte, operation, title string) []byte {
		db, err := vault.NewItemDatabase([]byte(`{"owned":"resume-product"}`), []vault.Item{{
			ID: "owned-resume-item", Kind: "login", Title: title, Username: "owned-user", Password: "owned-fixture-value",
		}})
		if err != nil {
			t.Fatal("ITEM_DATABASE_CREATE_FAILED")
		}
		draft := &vaultfile.File{Format: vaultfile.Format, Version: vaultfile.Version,
			Header: vaultfile.Header{VaultID: policy.VaultID, KeyEpoch: 1, ContentSeq: seq, PrevDigest: parent,
				OpID: operation, PolicySeq: policy.PolicySeq, PolicyDigest: pin.PolicyDigest, AuthorDeviceID: "operator-device"},
			SignedPolicyProofs: []vaultfile.SignedPolicy{proof}}
		sealed, err := vaultfile.SealAuthenticatedFile(draft, db, &pin, vuk, devicePrivate)
		if err != nil {
			t.Fatal("AUTHENTICATED_FILE_CREATE_FAILED")
		}
		file, err := vaultfile.ParseFile(sealed)
		if err != nil || vaultfile.VerifyPolicyCheckpoint(file, &pin) != nil {
			t.Fatal("CREATOR_SIGNATURE_CHECK_FAILED")
		}
		return sealed
	}
	digest := func(sealed []byte) []byte {
		file, err := vaultfile.ParseFile(sealed)
		if err != nil {
			t.Fatal("CREATOR_PARSE_FAILED")
		}
		value, err := vaultfile.FileDigest(file)
		if err != nil {
			t.Fatal("CREATOR_DIGEST_FAILED")
		}
		raw, err := hex.DecodeString(value)
		if err != nil {
			t.Fatal("CREATOR_DIGEST_DECODE_FAILED")
		}
		return raw
	}
	r := seal(0, nil, "initial-operation", "Initial")
	p := seal(1, digest(r), "prepared-operation", "Prepared")
	s := seal(1, digest(r), "third-party-operation", "Third party")
	w := seal(2, digest(p), "new-local-operation", "Later local edit")
	zero := uint64(0)
	return resumeProductMaterial{config: vaultFileCheckpointConfig{
		VaultID: pin.VaultID, OwnerRootKeyID: pin.OwnerRootKeyID, OwnerRootPublicKey: hex.EncodeToString(rootPublic),
		PolicySeq: &zero, PolicyDigest: hex.EncodeToString(pin.PolicyDigest),
	}, r: r, p: p, s: s, w: w}
}

type resumeProductCase struct {
	root, configPath string
	cfg              vaultFileResumeConfig
	initial          vaultfilebackend.ReadResult
}

func newResumeProductCase(t *testing.T, material resumeProductMaterial, prepare bool) resumeProductCase {
	t.Helper()
	root := t.TempDir()
	cfg := vaultFileResumeConfig{Version: 1, BackendRoot: filepath.Join(root, "backend"), Name: "owned.locklark",
		Journal: filepath.Join(root, "journal.db"), Checkpoint: &material.config}
	configPath := filepath.Join(root, "operator.json")
	raw, err := json.Marshal(cfg)
	if err != nil || os.WriteFile(configPath, raw, 0600) != nil {
		t.Fatal("OPERATOR_CONFIGURATION_CREATE_FAILED")
	}
	backend, err := vaultfilebackend.OpenDir(cfg.BackendRoot)
	if err != nil {
		t.Fatal("FIXTURE_BACKEND_CREATE_FAILED")
	}
	if backend.CreateIfAbsent(context.Background(), cfg.Name, material.r) != nil {
		t.Fatal("FIXTURE_BASE_PUBLISH_FAILED")
	}
	read, err := backend.Read(context.Background(), cfg.Name)
	if err != nil || backend.Close() != nil {
		t.Fatal("FIXTURE_BASE_READ_FAILED")
	}
	journal, err := vaultfilejournal.Open(cfg.Journal)
	if err != nil {
		t.Fatal("FIXTURE_JOURNAL_CREATE_FAILED")
	}
	state := vaultfilejournal.State{BaseBytes: material.r, WorkingBytes: material.r, RemoteRevision: read.Revision}
	if journal.InitializeEmptyState(state) != nil {
		journal.Close()
		t.Fatal("FIXTURE_JOURNAL_STATE_FAILED")
	}
	if journal.UpdateWorking(0, material.p) != nil {
		journal.Close()
		t.Fatal("FIXTURE_WORKING_EDIT_FAILED")
	}
	if prepare && journal.Prepare(1, vaultfilejournal.Proposal{Generation: 1, OperationID: "prepared-operation", ExpectedRevision: read.Revision, Bytes: material.p}) != nil {
		journal.Close()
		t.Fatal("FIXTURE_PREPARE_FAILED")
	}
	if journal.Close() != nil {
		t.Fatal("FIXTURE_JOURNAL_CLOSE_FAILED")
	}
	return resumeProductCase{root: root, configPath: configPath, cfg: cfg, initial: read}
}

func invokeResumeProduct(t *testing.T, product, config, want string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, product, "vault-file", "resume-prepared", "--config", config)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		t.Fatal("PRODUCT_PROCESS_TIMED_OUT")
	}
	if want == "RESUMED" {
		if err != nil || stdout.String() != "{\"status\":\"RESUMED\"}\n" || stderr.Len() != 0 {
			t.Fatal("PRODUCT_SUCCESS_CONTRACT_FAILED")
		}
	} else if err == nil || stdout.Len() != 0 || stderr.String() != "locklark: "+want+"\n" {
		t.Fatal("PRODUCT_FIXED_REFUSAL_CONTRACT_FAILED")
	}
}

type resumeDiskEntry struct {
	mode   fs.FileMode
	digest [sha256.Size]byte
	link   string
}

func resumeDisk(t *testing.T, root string) map[string]resumeDiskEntry {
	t.Helper()
	result := map[string]resumeDiskEntry{}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		value := resumeDiskEntry{mode: info.Mode()}
		if info.Mode().IsRegular() {
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			value.digest = sha256.Sum256(raw)
		} else if info.Mode()&os.ModeSymlink != 0 {
			value.link, err = os.Readlink(path)
			if err != nil {
				return err
			}
		}
		key, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		result[key] = value
		return nil
	})
	if err != nil {
		t.Fatal("OWNED_DISK_INSPECTION_FAILED")
	}
	return result
}

func verifyResumeProductResult(t *testing.T, c resumeProductCase, material resumeProductMaterial, expectedRevision vaultfilebackend.Revision) {
	t.Helper()
	backend, err := vaultfilebackend.OpenExistingDir(c.cfg.BackendRoot)
	if err != nil {
		t.Fatal("RESULT_BACKEND_OPEN_FAILED")
	}
	read, err := backend.Read(context.Background(), c.cfg.Name)
	if err != nil || backend.Close() != nil || !bytes.Equal(read.Bytes, material.p) {
		t.Fatal("PRODUCT_DID_NOT_PUBLISH_EXACT_PROPOSAL")
	}
	if expectedRevision != "" && read.Revision != expectedRevision {
		t.Fatal("ALREADY_APPLIED_PROPOSAL_WAS_REWRITTEN")
	}
	journal, err := vaultfilejournal.OpenExisting(c.cfg.Journal)
	if err != nil {
		t.Fatal("RESULT_JOURNAL_OPEN_FAILED")
	}
	defer journal.Close()
	state, err := journal.LoadState()
	if err != nil || !bytes.Equal(state.BaseBytes, material.p) || state.RemoteRevision != read.Revision || !bytes.Equal(state.WorkingBytes, material.p) {
		t.Fatal("PRODUCT_ACK_STATE_INCORRECT")
	}
	if _, err := journal.LoadPrepared(); !errors.Is(err, vaultfilejournal.ErrEmpty) {
		t.Fatal("PRODUCT_ACK_LEFT_PREPARED_RECORD")
	}
}

func TestVaultFileResumeProductMinimum(t *testing.T) {
	product := vaultFileProductBinary(t)
	material := newResumeProductMaterial(t)
	c := newResumeProductCase(t, material, true)
	// Every setup handle is closed: the product must open the persisted files
	// in an independent process, perform the original CAS and persist its Ack.
	invokeResumeProduct(t, product, c.configPath, "RESUMED")
	verifyResumeProductResult(t, c, material, "")
}

func TestVaultFileResumeProductMatrix(t *testing.T) {
	product := vaultFileProductBinary(t)
	material := newResumeProductMaterial(t)
	t.Run("ALREADY_APPLIED_ACK_ONLY", func(t *testing.T) {
		c := newResumeProductCase(t, material, true)
		backend, err := vaultfilebackend.OpenExistingDir(c.cfg.BackendRoot)
		if err != nil || backend.ReplaceIfVersion(context.Background(), c.cfg.Name, c.initial.Revision, material.p) != nil {
			t.Fatal("ALREADY_APPLIED_FIXTURE_FAILED")
		}
		applied, err := backend.Read(context.Background(), c.cfg.Name)
		if err != nil || backend.Close() != nil {
			t.Fatal("ALREADY_APPLIED_READ_FAILED")
		}
		invokeResumeProduct(t, product, c.configPath, "RESUMED")
		verifyResumeProductResult(t, c, material, applied.Revision)
		before := resumeDisk(t, c.root)
		invokeResumeProduct(t, product, c.configPath, "JOURNAL_REJECTED")
		if !maps.Equal(before, resumeDisk(t, c.root)) {
			t.Fatal("RESOLVED_OPERATION_REPLAY_CHANGED_DISK")
		}
	})
	t.Run("THIRD_SUCCESSOR_PRESERVES_NEW_EDIT", func(t *testing.T) {
		c := newResumeProductCase(t, material, true)
		backend, err := vaultfilebackend.OpenExistingDir(c.cfg.BackendRoot)
		if err != nil || backend.ReplaceIfVersion(context.Background(), c.cfg.Name, c.initial.Revision, material.s) != nil || backend.Close() != nil {
			t.Fatal("THIRD_SUCCESSOR_FIXTURE_FAILED")
		}
		journal, err := vaultfilejournal.OpenExisting(c.cfg.Journal)
		if err != nil || journal.UpdateWorking(1, material.w) != nil || journal.Close() != nil {
			t.Fatal("NEW_EDIT_FIXTURE_FAILED")
		}
		before := resumeDisk(t, c.root)
		invokeResumeProduct(t, product, c.configPath, "UNKNOWN_REVIEW")
		if !maps.Equal(before, resumeDisk(t, c.root)) {
			t.Fatal("UNKNOWN_REVIEW_CHANGED_PERSISTED_RECORDS")
		}
	})
	t.Run("UNTRUSTED_READBACK", func(t *testing.T) {
		c := newResumeProductCase(t, material, true)
		foreign := newResumeProductMaterial(t)
		backend, err := vaultfilebackend.OpenExistingDir(c.cfg.BackendRoot)
		if err != nil || backend.ReplaceIfVersion(context.Background(), c.cfg.Name, c.initial.Revision, foreign.p) != nil || backend.Close() != nil {
			t.Fatal("UNTRUSTED_READBACK_FIXTURE_FAILED")
		}
		before := resumeDisk(t, c.root)
		invokeResumeProduct(t, product, c.configPath, "VERIFY_REJECTED")
		if !maps.Equal(before, resumeDisk(t, c.root)) {
			t.Fatal("READBACK_AUTHORIZED_ITS_OWN_ROOT")
		}
	})
	for _, name := range []string{"MISSING_CONFIG", "MISSING_SEQUENCE", "WRONG_ROOT_PIN", "WRONG_VAULT", "MISSING_REMOTE_NAME", "SHARED_CONFIG", "MISSING_JOURNAL", "EMPTY_JOURNAL", "NO_STATE", "NO_PREPARED", "MISSING_BACKEND_ROOT", "MISSING_BACKEND_LOCK"} {
		t.Run(name, func(t *testing.T) {
			c := newResumeProductCase(t, material, name != "NO_PREPARED")
			config := c.configPath
			want := "CONFIG_REJECTED"
			switch name {
			case "MISSING_CONFIG":
				config = filepath.Join(c.root, "missing-operator.json")
			case "MISSING_SEQUENCE", "WRONG_ROOT_PIN", "WRONG_VAULT":
				raw, err := os.ReadFile(config)
				if err != nil {
					t.Fatal("CONFIG_FIXTURE_READ_FAILED")
				}
				var document map[string]any
				if json.Unmarshal(raw, &document) != nil {
					t.Fatal("CONFIG_FIXTURE_PARSE_FAILED")
				}
				checkpoint := document["checkpoint"].(map[string]any)
				if name == "MISSING_SEQUENCE" {
					delete(checkpoint, "policy_seq")
				} else if name == "WRONG_ROOT_PIN" {
					checkpoint["owner_root_public_key"] = hex.EncodeToString(bytes.Repeat([]byte{0x11}, 32))
					want = "VERIFY_REJECTED"
				} else {
					checkpoint["vault_id"] = "other-operator-vault"
					want = "VERIFY_REJECTED"
				}
				raw, err = json.Marshal(document)
				if err != nil || os.WriteFile(config, raw, 0600) != nil {
					t.Fatal("CONFIG_FIXTURE_REWRITE_FAILED")
				}
				if name != "MISSING_SEQUENCE" {
					// Reading the backend would resolve this stale holder and
					// remove its staged file. A wrong pin must fail beforehand.
					base := filepath.Join(c.cfg.BackendRoot, "vaultfile-backend", "v1")
					id := "00112233445566778899aabbccddeeff"
					if os.WriteFile(filepath.Join(base, "tmp", "op-"+id), []byte("staged"), 0600) != nil ||
						os.WriteFile(filepath.Join(base, ".locklark-vaultfile.lock"), []byte("holder "+id+"\n"), 0600) != nil {
						t.Fatal("NO_READ_FIXTURE_FAILED")
					}
				}
			case "SHARED_CONFIG":
				if os.Chmod(config, 0644) != nil {
					t.Fatal("SHARED_CONFIG_FIXTURE_FAILED")
				}
			case "MISSING_REMOTE_NAME":
				want = "BACKEND_REJECTED"
				cfg := c.cfg
				cfg.Name = "missing-remote.locklark"
				raw, err := json.Marshal(cfg)
				if err != nil || os.WriteFile(config, raw, 0600) != nil {
					t.Fatal("REMOTE_NAME_FIXTURE_FAILED")
				}
			case "MISSING_JOURNAL":
				want = "JOURNAL_REJECTED"
				if os.Remove(c.cfg.Journal) != nil {
					t.Fatal("MISSING_JOURNAL_FIXTURE_FAILED")
				}
			case "EMPTY_JOURNAL":
				want = "JOURNAL_REJECTED"
				if os.Truncate(c.cfg.Journal, 0) != nil {
					t.Fatal("EMPTY_JOURNAL_FIXTURE_FAILED")
				}
			case "NO_STATE":
				want = "JOURNAL_REJECTED"
				if os.Remove(c.cfg.Journal) != nil {
					t.Fatal("NO_STATE_FIXTURE_REMOVE_FAILED")
				}
				db, err := bolt.Open(c.cfg.Journal, 0600, &bolt.Options{NoFreelistSync: true})
				if err != nil {
					t.Fatal("NO_STATE_FIXTURE_OPEN_FAILED")
				}
				if db.Update(func(tx *bolt.Tx) error { _, err := tx.CreateBucketIfNotExists([]byte("uninitialized")); return err }) != nil || db.Close() != nil {
					t.Fatal("NO_STATE_FIXTURE_CLOSE_FAILED")
				}
			case "NO_PREPARED":
				want = "JOURNAL_REJECTED"
			case "MISSING_BACKEND_ROOT":
				want = "BACKEND_REJECTED"
				if os.RemoveAll(c.cfg.BackendRoot) != nil {
					t.Fatal("MISSING_BACKEND_FIXTURE_FAILED")
				}
			case "MISSING_BACKEND_LOCK":
				want = "BACKEND_REJECTED"
				if os.Remove(filepath.Join(c.cfg.BackendRoot, "vaultfile-backend", "v1", ".locklark-vaultfile.lock")) != nil {
					t.Fatal("MISSING_LOCK_FIXTURE_FAILED")
				}
			}
			before := resumeDisk(t, c.root)
			invokeResumeProduct(t, product, config, want)
			if !maps.Equal(before, resumeDisk(t, c.root)) {
				t.Fatal("REFUSAL_CREATED_OR_REPAIRED_RESOURCES")
			}
		})
	}
}
