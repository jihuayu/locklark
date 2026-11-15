//go:build darwin || linux

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
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
)

const ownedOpenTitle = "Owned shared baseline"
const ownedOpenSecret = "owned-hidden-password"

type openBaselineProductCase struct {
	root, configPath string
	cfg              vaultFileResumeConfig
	sealed           []byte
}

// The reader device comes only from the real full-factor personal CLI. The
// author and owner root are independent fixture keys; the test never reads or
// exports the personal device's age identity or signing seed.
func newOpenBaselineProductCase(t *testing.T, personalPath string, reader map[string]string) openBaselineProductCase {
	t.Helper()
	readerPub, err := hex.DecodeString(reader["content_signing_public_key"])
	if err != nil || len(readerPub) != ed25519.PublicKeySize {
		t.Fatal("OPEN_READER_PUBLIC_INVALID")
	}
	if _, err := age.ParseX25519Recipient(reader["age_recipient"]); err != nil {
		t.Fatal("OPEN_READER_RECIPIENT_INVALID")
	}
	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("OPEN_ROOT_CREATE_FAILED")
	}
	defer clear(rootPriv)
	authorPub, authorPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("OPEN_AUTHOR_CREATE_FAILED")
	}
	defer clear(authorPriv)
	authorAge, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal("OPEN_AUTHOR_RECIPIENT_FAILED")
	}
	policy := &vaultfile.Policy{
		Format: vaultfile.Format, Version: vaultfile.Version, VaultID: "owned-open-vault", PolicySeq: 0,
		OwnerRoot: vaultfile.OwnerRoot{KeyID: "owned-independent-root", Alg: vaultfile.PolicySigAlgEd25519,
			PublicKey: rootPub, Owners: []vaultfile.Principal{{PrincipalID: "owner", Label: "Owner"}}},
		Readers: []vaultfile.Member{{PrincipalID: "reader", Label: "Reader"}},
		Writers: []vaultfile.Member{{PrincipalID: "owner", Label: "Owner"}},
		Admins:  []vaultfile.Member{{PrincipalID: "owner", Label: "Owner"}},
		Owners:  []vaultfile.Member{{PrincipalID: "owner", Label: "Owner"}},
		Devices: []vaultfile.Device{
			{DeviceID: "author-device", PrincipalID: "owner", Label: "Author",
				ContentSigningKey: vaultfile.PublicKey{Alg: vaultfile.SigAlgEd25519, PublicKey: authorPub},
				AgeEncryptionKey:  authorAge.Recipient().String()},
			{DeviceID: "reader-device", PrincipalID: "reader", Label: "Reader",
				ContentSigningKey: vaultfile.PublicKey{Alg: vaultfile.SigAlgEd25519, PublicKey: readerPub},
				AgeEncryptionKey:  reader["age_recipient"]},
		},
	}
	document, err := vaultfile.EncodePolicyDocument(policy)
	if err != nil {
		t.Fatal("OPEN_POLICY_DOCUMENT_FAILED")
	}
	pin := vaultfile.PolicyCheckpoint{
		VaultID: policy.VaultID, OwnerRootKeyID: policy.OwnerRoot.KeyID,
		OwnerRootPublicKey: rootPub, PolicySeq: policy.PolicySeq, PolicyDigest: vaultfile.PolicyDigest(policy),
	}
	proof := vaultfile.SignedPolicy{Policy: *policy, Document: document, SignerID: policy.OwnerRoot.KeyID,
		Alg: vaultfile.PolicySigAlgEd25519,
		Sig: ed25519.Sign(rootPriv, append([]byte(vaultfile.DomainPolicyDocumentSignature+"\x00"), document...))}
	vuk := make([]byte, vaultfile.CEKSize)
	if _, err := rand.Read(vuk); err != nil {
		t.Fatal("OPEN_EPOCH_KEY_FAILED")
	}
	defer clear(vuk)
	db, err := vault.NewItemDatabase([]byte(`{"owned":"open-baseline"}`), []vault.Item{{
		ID: "owned-open-item", Kind: "login", Title: ownedOpenTitle, Username: "owned-user", Password: ownedOpenSecret,
	}})
	if err != nil {
		t.Fatal("OPEN_ITEM_DATABASE_FAILED")
	}
	draft := &vaultfile.File{Format: vaultfile.Format, Version: vaultfile.Version,
		Header: vaultfile.Header{VaultID: policy.VaultID, KeyEpoch: 1, ContentSeq: 0,
			OpID: "owned-genesis", PolicySeq: policy.PolicySeq, PolicyDigest: pin.PolicyDigest, AuthorDeviceID: "author-device"},
		SignedPolicyProofs: []vaultfile.SignedPolicy{proof}}
	sealed, err := vaultfile.SealAuthenticatedFile(draft, db, &pin, vuk, authorPriv)
	if err != nil {
		t.Fatal("OPEN_SEALED_FILE_FAILED")
	}
	root := newProductPrivateRoot(t, t.TempDir())
	cfg := vaultFileResumeConfig{Version: 1, BackendRoot: filepath.Join(root, "backend"), Name: "owned.locklark",
		Journal: filepath.Join(root, "journal.db"), PersonalFile: personalPath,
		Checkpoint: &vaultFileCheckpointConfig{VaultID: pin.VaultID, OwnerRootKeyID: pin.OwnerRootKeyID,
			OwnerRootPublicKey: hex.EncodeToString(rootPub), PolicySeq: new(uint64), PolicyDigest: hex.EncodeToString(pin.PolicyDigest)}}
	configPath := filepath.Join(root, "operator.json")
	writeOpenBaselineConfig(t, configPath, cfg)
	backend, err := vaultfilebackend.OpenDir(cfg.BackendRoot)
	if err != nil {
		t.Fatal("OPEN_BACKEND_FIXTURE_FAILED")
	}
	putErr := backend.CreateIfAbsent(context.Background(), cfg.Name, sealed)
	closeErr := backend.Close()
	if putErr != nil || closeErr != nil {
		t.Fatal("OPEN_BASELINE_FIXTURE_PUBLISH_FAILED")
	}
	return openBaselineProductCase{root: root, configPath: configPath, cfg: cfg, sealed: sealed}
}

func writeOpenBaselineConfig(t *testing.T, path string, cfg vaultFileResumeConfig) {
	t.Helper()
	raw, err := json.Marshal(cfg)
	if err != nil || os.WriteFile(path, raw, 0600) != nil {
		t.Fatal("OPEN_CONFIG_FIXTURE_FAILED")
	}
}

type openBaselinePTYResult struct {
	Status string `json:"status"`
	Echoed bool   `json:"echoed"`
	Items  []struct {
		Title    string `json:"title"`
		Category string `json:"category"`
	} `json:"items"`
}

func runOpenBaselineProduct(t *testing.T, product, config string, password []byte, secret string, missing bool, expectedRefusal string) openBaselinePTYResult {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal("OPEN_PTY_RUNTIME_UNAVAILABLE")
	}
	request, err := json.Marshal(struct {
		Product         string `json:"product"`
		Config          string `json:"config"`
		Password        string `json:"password"`
		Secret          string `json:"secret"`
		MissingSecret   bool   `json:"missing_secret"`
		ExpectedRefusal string `json:"expected_refusal"`
	}{product, config, string(password), secret, missing, expectedRefusal})
	if err != nil {
		t.Fatal("OPEN_PTY_REQUEST_FAILED")
	}
	defer clear(request)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, python, "-I", "-B", filepath.Join("testdata", "vault_file_open_pty.py"))
	cmd.Stdin = bytes.NewReader(request)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil || ctx.Err() != nil || stderr.Len() != 0 {
		t.Fatal("OPEN_PTY_EXECUTION_FAILED")
	}
	var result openBaselinePTYResult
	decoder := json.NewDecoder(&stdout)
	decoder.DisallowUnknownFields()
	if decoder.Decode(&result) != nil || decoder.Decode(new(any)) != io.EOF {
		t.Fatal("OPEN_PTY_VERDICT_INVALID")
	}
	return result
}

func TestVaultFileOpenBaselineProductMinimum(t *testing.T) {
	product := vaultFileProductBinary(t)
	personalPath, password, secret := publicDeviceProductFixture(t)
	defer clear(password)
	enrollment := runVaultFileDevicePublicProduct(t, product, personalPath, password, secret, false)
	if enrollment.Status != "PUBLIC" || enrollment.Echoed || len(enrollment.Public) != 2 {
		t.Fatal("OPEN_MINIMUM_ENROLLMENT_FAILED")
	}
	c := newOpenBaselineProductCase(t, personalPath, enrollment.Public)
	if runTrackProduct(product, c.configPath, false) != "TRACKED" {
		t.Fatal("OPEN_MINIMUM_TRACK_FAILED")
	}
	before, err := os.ReadFile(c.cfg.Journal)
	if err != nil {
		t.Fatal("OPEN_MINIMUM_JOURNAL_READ_FAILED")
	}
	// The baseline must remain openable without any backend bytes or store.
	if os.RemoveAll(c.cfg.BackendRoot) != nil {
		t.Fatal("OPEN_MINIMUM_BACKEND_REMOVE_FAILED")
	}
	result := runOpenBaselineProduct(t, product, c.configPath, password, secret, false, "")
	if result.Status != "LOCAL_BASELINE" || result.Echoed || len(result.Items) != 1 ||
		result.Items[0].Title != ownedOpenTitle || result.Items[0].Category != "login" {
		t.Fatal("OPEN_MINIMUM_PRODUCT_RESULT_FAILED")
	}
	rawResult, err := json.Marshal(result)
	if err != nil || bytes.Contains(rawResult, []byte(ownedOpenSecret)) || bytes.Contains(rawResult, []byte("owned-open-item")) {
		t.Fatal("OPEN_MINIMUM_SECRET_OR_ID_DISCLOSED")
	}
	after, err := os.ReadFile(c.cfg.Journal)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("OPEN_MINIMUM_JOURNAL_CHANGED")
	}
}

func TestVaultFileOpenBaselineProductRefusals(t *testing.T) {
	product := vaultFileProductBinary(t)
	personalPath, password, secret := publicDeviceProductFixture(t)
	defer clear(password)
	enrollment := runVaultFileDevicePublicProduct(t, product, personalPath, password, secret, false)
	if enrollment.Status != "PUBLIC" || len(enrollment.Public) != 2 {
		t.Fatal("OPEN_REFUSAL_ENROLLMENT_FAILED")
	}
	c := newOpenBaselineProductCase(t, personalPath, enrollment.Public)
	if runTrackProduct(product, c.configPath, false) != "TRACKED" {
		t.Fatal("OPEN_REFUSAL_TRACK_FAILED")
	}
	refuse := func(t *testing.T, config string, pw []byte, key string, missing bool, want string) {
		t.Helper()
		result := runOpenBaselineProduct(t, product, config, pw, key, missing, want)
		if result.Status != want || result.Echoed || result.Items != nil {
			t.Fatal("OPEN_REFUSAL_OUTPUT_FAILED")
		}
	}
	t.Run("bad-checkpoint", func(t *testing.T) {
		cfg := c.cfg
		pin := *cfg.Checkpoint
		if pin.PolicyDigest[0] == '0' {
			pin.PolicyDigest = "1" + pin.PolicyDigest[1:]
		} else {
			pin.PolicyDigest = "0" + pin.PolicyDigest[1:]
		}
		cfg.Checkpoint = &pin
		path := filepath.Join(c.root, "bad-pin.json")
		writeOpenBaselineConfig(t, path, cfg)
		refuse(t, path, password, secret, false, "VERIFY_REJECTED")
	})
	t.Run("wrong-device", func(t *testing.T) {
		foreignAge, err := age.GenerateX25519Identity()
		if err != nil {
			t.Fatal("OPEN_FOREIGN_RECIPIENT_FAILED")
		}
		foreignPub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal("OPEN_FOREIGN_SIGNER_FAILED")
		}
		foreign := newOpenBaselineProductCase(t, personalPath, map[string]string{
			"age_recipient": foreignAge.Recipient().String(), "content_signing_public_key": hex.EncodeToString(foreignPub),
		})
		if runTrackProduct(product, foreign.configPath, false) != "TRACKED" {
			t.Fatal("OPEN_FOREIGN_TRACK_FAILED")
		}
		refuse(t, foreign.configPath, password, secret, false, "VERIFY_REJECTED")
	})
	t.Run("malformed-duplicate-device", func(t *testing.T) {
		var document map[string]any
		if json.Unmarshal(c.sealed, &document) != nil {
			t.Fatal("OPEN_DUPLICATE_FIXTURE_DECODE_FAILED")
		}
		proofs := document["signed_policy_proofs"].([]any)
		policy := proofs[len(proofs)-1].(map[string]any)["policy"].(map[string]any)
		devices := policy["devices"].([]any)
		duplicate := make(map[string]any)
		for key, value := range devices[len(devices)-1].(map[string]any) {
			duplicate[key] = value
		}
		duplicate["device_id"] = "reader-duplicate"
		policy["devices"] = append(devices, duplicate)
		malformed, err := json.Marshal(document)
		if err != nil {
			t.Fatal("OPEN_DUPLICATE_FIXTURE_ENCODE_FAILED")
		}
		cfg := c.cfg
		cfg.Journal = filepath.Join(c.root, "ambiguous.db")
		path := filepath.Join(c.root, "ambiguous.json")
		writeOpenBaselineConfig(t, path, cfg)
		if err := vaultfilejournal.CreateNewState(cfg.Journal, vaultfilejournal.State{
			BaseBytes: malformed, WorkingBytes: malformed, RemoteRevision: vaultfilebackend.Revision("owned-revision"),
		}); err != nil {
			t.Fatal("OPEN_DUPLICATE_JOURNAL_CREATE_FAILED")
		}
		refuse(t, path, password, secret, false, "VERIFY_REJECTED")
	})
	t.Run("wrong-factor", func(t *testing.T) {
		refuse(t, c.configPath, []byte("wrong-owned-password"), secret, false, "VERIFY_REJECTED")
	})
	t.Run("missing-factor", func(t *testing.T) {
		refuse(t, c.configPath, password, secret, true, "CANCELLED")
	})
}

func TestVaultFileOpenBaselineConfigPathRefusals(t *testing.T) {
	product := vaultFileProductBinary(t)
	personalPath, password, _ := publicDeviceProductFixture(t)
	defer clear(password)
	assertConfigRefused := func(t *testing.T, document map[string]any) {
		t.Helper()
		configPath := filepath.Join(t.TempDir(), "operator.json")
		if os.WriteFile(configPath, encodeResumeConfigTest(t, document), 0600) != nil {
			t.Fatal("OPEN_SCOPE_CONFIG_CREATE_FAILED")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, product, "vault-file", "open-baseline", "--config", configPath)
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		if err := cmd.Run(); err == nil || ctx.Err() != nil || stdout.Len() != 0 || stderr.String() != "locklark: CONFIG_REJECTED\n" {
			t.Fatal("OPEN_SCOPE_CONFIG_NOT_REFUSED_BEFORE_PROMPT")
		}
	}
	t.Run("missing-personal-file", func(t *testing.T) {
		assertConfigRefused(t, resumeConfigDocument(t))
	})
	t.Run("journal-alias", func(t *testing.T) {
		document := resumeConfigDocument(t)
		document["personal_file"] = document["journal"]
		assertConfigRefused(t, document)
	})
	t.Run("personal-symlink", func(t *testing.T) {
		link := filepath.Join(t.TempDir(), "personal-link.ll")
		if os.Symlink(personalPath, link) != nil {
			t.Fatal("OPEN_SCOPE_SYMLINK_CREATE_FAILED")
		}
		document := resumeConfigDocument(t)
		document["personal_file"] = link
		assertConfigRefused(t, document)
	})
}
