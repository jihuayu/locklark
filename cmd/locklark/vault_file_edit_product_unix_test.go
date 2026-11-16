//go:build darwin || linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
)

const ownedEditedTitle = "Owned renamed baseline"

type titleEditProductCase struct {
	product, personalPath, secret, itemID, oldTitle string
	password                                        []byte
	baseline                                        openBaselineProductCase
}

func newTitleEditProductCase(t *testing.T, writer bool) titleEditProductCase {
	t.Helper()
	product := vaultFileProductBinary(t)
	personalPath, password, secret := publicDeviceProductFixture(t)
	t.Cleanup(func() { clear(password) })
	enrollment := runVaultFileDevicePublicProduct(t, product, personalPath, password, secret, false)
	if enrollment.Status != "PUBLIC" || enrollment.Echoed || len(enrollment.Public) != 2 {
		t.Fatal("EDIT_ENROLLMENT_FAILED")
	}
	baseline := newOpenBaselineProductCaseWithWriter(t, personalPath, enrollment.Public, writer)
	if runTrackProduct(product, baseline.configPath, false) != "TRACKED" {
		t.Fatal("EDIT_TRACK_FAILED")
	}
	opened := runOpenBaselineProductMode(t, product, baseline.configPath, password, secret, false, "", true)
	if opened.Status != "LOCAL_BASELINE" || opened.Echoed || len(opened.Items) != 1 ||
		opened.Items[0].ID != ownedOpenItemID || opened.Items[0].Title != ownedOpenTitle {
		t.Fatal("EDIT_PUBLIC_REFERENCE_FAILED")
	}
	// The request below uses the ID actually returned by the product, with
	// independent fixture metadata only checking that it names the right item.
	return titleEditProductCase{product: product, personalPath: personalPath, password: password, secret: secret,
		itemID: opened.Items[0].ID, oldTitle: opened.Items[0].Title, baseline: baseline}
}

func writeTitleEditRequest(t *testing.T, c titleEditProductCase, name, oldTitle, newTitle string) string {
	t.Helper()
	path := filepath.Join(c.baseline.root, name+".json")
	raw, err := json.Marshal(map[string]string{
		"item_id": c.itemID, "expected_old_title": oldTitle, "new_title": newTitle,
	})
	if err != nil || os.WriteFile(path, raw, 0600) != nil {
		t.Fatal("EDIT_PRIVATE_INPUT_CREATE_FAILED")
	}
	return path
}

type titleEditPTYVerdict struct {
	Status string `json:"status"`
	Echoed bool   `json:"echoed"`
}

func runTitleEditProduct(t *testing.T, c titleEditProductCase, config, input string, password []byte, missing bool, want string) titleEditPTYVerdict {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal("EDIT_PTY_RUNTIME_UNAVAILABLE")
	}
	request, err := json.Marshal(struct {
		Product         string `json:"product"`
		Config          string `json:"config"`
		Input           string `json:"input"`
		Password        string `json:"password"`
		Secret          string `json:"secret"`
		MissingSecret   bool   `json:"missing_secret"`
		ExpectedRefusal string `json:"expected_refusal"`
	}{Product: c.product, Config: config, Input: input, Password: string(password), Secret: c.secret,
		MissingSecret: missing, ExpectedRefusal: want})
	if err != nil {
		t.Fatal("EDIT_PTY_REQUEST_FAILED")
	}
	defer clear(request)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, python, "-I", "-B", filepath.Join("testdata", "vault_file_edit_pty.py"))
	cmd.Stdin = bytes.NewReader(request)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil || ctx.Err() != nil || stderr.Len() != 0 {
		t.Fatal("EDIT_PTY_EXECUTION_FAILED")
	}
	var result titleEditPTYVerdict
	decoder := json.NewDecoder(&stdout)
	decoder.DisallowUnknownFields()
	if decoder.Decode(&result) != nil || decoder.Decode(new(any)) != io.EOF {
		t.Fatal("EDIT_PTY_VERDICT_INVALID")
	}
	return result
}

func requireEditVerdict(t *testing.T, got titleEditPTYVerdict, want string) {
	t.Helper()
	if got.Status != want || got.Echoed {
		t.Fatal("EDIT_PRODUCT_VERDICT_FAILED")
	}
}

func TestVaultFileTitleEditProductMinimum(t *testing.T) {
	c := newTitleEditProductCase(t, true)
	input := writeTitleEditRequest(t, c, "rename", c.oldTitle, ownedEditedTitle)
	parked := filepath.Join(c.baseline.root, "parked-backend")
	if os.Rename(c.baseline.cfg.BackendRoot, parked) != nil {
		t.Fatal("EDIT_BACKEND_PARK_FAILED")
	}
	// Prepare has no backend store/data dependency. The exact backend tree is
	// restored unchanged only before the existing resume command performs CAS.
	requireEditVerdict(t, runTitleEditProduct(t, c, c.baseline.configPath, input, c.password, false, ""), "PREPARED")
	if runStatusProduct(c.product, c.baseline.configPath) != "PREPARED" {
		t.Fatal("EDIT_OFFLINE_PREPARED_STATE_MISSING")
	}
	if os.Rename(parked, c.baseline.cfg.BackendRoot) != nil {
		t.Fatal("EDIT_BACKEND_RESTORE_FAILED")
	}
	invokeResumeProduct(t, c.product, c.baseline.configPath, "RESUMED")
	if runStatusProduct(c.product, c.baseline.configPath) != "CLEAN" {
		t.Fatal("EDIT_RESUME_NOT_CLEAN")
	}
	opened := runOpenBaselineProduct(t, c.product, c.baseline.configPath, c.password, c.secret, false, "")
	if opened.Status != "LOCAL_BASELINE" || opened.Echoed || len(opened.Items) != 1 ||
		opened.Items[0].Title != ownedEditedTitle || opened.Items[0].Category != "login" || opened.Items[0].ID != "" {
		t.Fatal("EDIT_RESUMED_TITLE_NOT_OPENED")
	}
}

func TestVaultFileTitleEditProductRefusals(t *testing.T) {
	t.Run("reader-cannot-write", func(t *testing.T) {
		c := newTitleEditProductCase(t, false)
		input := writeTitleEditRequest(t, c, "reader-edit", c.oldTitle, ownedEditedTitle)
		before, err := os.ReadFile(c.baseline.cfg.Journal)
		if err != nil {
			t.Fatal("EDIT_READER_JOURNAL_READ_FAILED")
		}
		requireEditVerdict(t, runTitleEditProduct(t, c, c.baseline.configPath, input, c.password, false, "VERIFY_REJECTED"), "VERIFY_REJECTED")
		after, err := os.ReadFile(c.baseline.cfg.Journal)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("EDIT_READER_MUTATED_JOURNAL")
		}
	})
	t.Run("bad-pin-and-factors", func(t *testing.T) {
		c := newTitleEditProductCase(t, true)
		input := writeTitleEditRequest(t, c, "factor-edit", c.oldTitle, ownedEditedTitle)
		cfg := c.baseline.cfg
		pin := *cfg.Checkpoint
		if pin.PolicyDigest[0] == '0' {
			pin.PolicyDigest = "1" + pin.PolicyDigest[1:]
		} else {
			pin.PolicyDigest = "0" + pin.PolicyDigest[1:]
		}
		cfg.Checkpoint = &pin
		badConfig := filepath.Join(c.baseline.root, "edit-bad-pin.json")
		writeOpenBaselineConfig(t, badConfig, cfg)
		requireEditVerdict(t, runTitleEditProduct(t, c, badConfig, input, c.password, false, "VERIFY_REJECTED"), "VERIFY_REJECTED")
		requireEditVerdict(t, runTitleEditProduct(t, c, c.baseline.configPath, input, []byte("wrong-owned-factor"), false, "VERIFY_REJECTED"), "VERIFY_REJECTED")
		requireEditVerdict(t, runTitleEditProduct(t, c, c.baseline.configPath, input, c.password, true, "CANCELLED"), "CANCELLED")
		if runStatusProduct(c.product, c.baseline.configPath) != "CLEAN" {
			t.Fatal("EDIT_REFUSALS_MUTATED_STATE")
		}
	})
	t.Run("expected-title-conflict", func(t *testing.T) {
		c := newTitleEditProductCase(t, true)
		input := writeTitleEditRequest(t, c, "stale-title", "not-the-current-title", ownedEditedTitle)
		requireEditVerdict(t, runTitleEditProduct(t, c, c.baseline.configPath, input, c.password, false, "LOCAL_REVIEW"), "LOCAL_REVIEW")
		if runStatusProduct(c.product, c.baseline.configPath) != "CLEAN" {
			t.Fatal("EDIT_TITLE_CONFLICT_MUTATED_STATE")
		}
	})
}

func TestVaultFileTitleEditProductReplayAndStaleRemote(t *testing.T) {
	c := newTitleEditProductCase(t, true)
	input := writeTitleEditRequest(t, c, "first-edit", c.oldTitle, ownedEditedTitle)
	requireEditVerdict(t, runTitleEditProduct(t, c, c.baseline.configPath, input, c.password, false, ""), "PREPARED")
	j, err := vaultfilejournal.OpenExisting(c.baseline.cfg.Journal)
	if err != nil {
		t.Fatal("EDIT_REPLAY_JOURNAL_OPEN_FAILED")
	}
	beforeState, stateErr := j.LoadState()
	beforePrepared, prepErr := j.LoadPrepared()
	if j.Close() != nil || stateErr != nil || prepErr != nil {
		t.Fatal("EDIT_REPLAY_SNAPSHOT_FAILED")
	}
	requireEditVerdict(t, runTitleEditProduct(t, c, c.baseline.configPath, input, c.password, false, ""), "PREPARED")
	other := writeTitleEditRequest(t, c, "second-edit", c.oldTitle, "Different second edit")
	requireEditVerdict(t, runTitleEditProduct(t, c, c.baseline.configPath, other, c.password, false, "LOCAL_REVIEW"), "LOCAL_REVIEW")
	j, err = vaultfilejournal.OpenExisting(c.baseline.cfg.Journal)
	if err != nil {
		t.Fatal("EDIT_REPLAY_JOURNAL_REOPEN_FAILED")
	}
	afterState, stateErr := j.LoadState()
	afterPrepared, prepErr := j.LoadPrepared()
	if j.Close() != nil || stateErr != nil || prepErr != nil ||
		afterState.Generation != beforeState.Generation || afterState.RemoteRevision != beforeState.RemoteRevision ||
		!bytes.Equal(afterState.BaseBytes, beforeState.BaseBytes) || !bytes.Equal(afterState.WorkingBytes, beforeState.WorkingBytes) ||
		afterPrepared.Proposal.OperationID != beforePrepared.Proposal.OperationID ||
		!bytes.Equal(afterPrepared.Proposal.Bytes, beforePrepared.Proposal.Bytes) {
		t.Fatal("EDIT_REPLAY_PROPOSAL_CHANGED")
	}
	backend, err := vaultfilebackend.OpenExistingDir(c.baseline.cfg.BackendRoot)
	if err != nil {
		t.Fatal("EDIT_STALE_BACKEND_OPEN_FAILED")
	}
	current, err := backend.Read(context.Background(), c.baseline.cfg.Name)
	if err != nil || backend.ReplaceIfVersion(context.Background(), c.baseline.cfg.Name, current.Revision, c.baseline.sealed) != nil {
		t.Fatal("EDIT_STALE_BACKEND_ADVANCE_FAILED")
	}
	stale, err := backend.Read(context.Background(), c.baseline.cfg.Name)
	if err != nil || backend.Close() != nil || stale.Revision == current.Revision {
		t.Fatal("EDIT_STALE_BACKEND_READ_FAILED")
	}
	invokeResumeProduct(t, c.product, c.baseline.configPath, "UNKNOWN_REVIEW")
	backend, err = vaultfilebackend.OpenExistingDir(c.baseline.cfg.BackendRoot)
	if err != nil {
		t.Fatal("EDIT_STALE_BACKEND_REOPEN_FAILED")
	}
	afterRemote, err := backend.Read(context.Background(), c.baseline.cfg.Name)
	if err != nil || backend.Close() != nil || afterRemote.Revision != stale.Revision ||
		!bytes.Equal(afterRemote.Bytes, stale.Bytes) {
		t.Fatal("EDIT_STALE_RESUME_WROTE_BACKEND")
	}
	if runStatusProduct(c.product, c.baseline.configPath) != "PREPARED" {
		t.Fatal("EDIT_STALE_RESUME_LOST_PREPARED")
	}
}

func TestVaultFileTitleEditProductUnsafePaths(t *testing.T) {
	c := newTitleEditProductCase(t, true)
	input := writeTitleEditRequest(t, c, "safe-edit", c.oldTitle, ownedEditedTitle)
	refuseBeforePrompt := func(t *testing.T, config, path, want string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, c.product, "vault-file", "edit-prepared", "--config", config, "--input", path)
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		if err := cmd.Run(); err == nil || ctx.Err() != nil || stdout.Len() != 0 ||
			stderr.String() != "locklark: "+want+"\n" {
			t.Fatal("EDIT_UNSAFE_PATH_NOT_REFUSED_BEFORE_PROMPT")
		}
	}
	t.Run("journal-as-input", func(t *testing.T) {
		refuseBeforePrompt(t, c.baseline.configPath, c.baseline.cfg.Journal, "CONFIG_REJECTED")
	})
	t.Run("symlinked-input", func(t *testing.T) {
		link := filepath.Join(c.baseline.root, "linked-input.json")
		if os.Symlink(input, link) != nil {
			t.Fatal("EDIT_INPUT_LINK_FIXTURE_FAILED")
		}
		refuseBeforePrompt(t, c.baseline.configPath, link, "INPUT_REJECTED")
	})
	t.Run("symlinked-personal-file", func(t *testing.T) {
		link := filepath.Join(c.baseline.root, "linked-personal.ll")
		if os.Symlink(c.personalPath, link) != nil {
			t.Fatal("EDIT_PERSONAL_LINK_FIXTURE_FAILED")
		}
		cfg := c.baseline.cfg
		cfg.PersonalFile = link
		config := filepath.Join(c.baseline.root, "linked-personal-config.json")
		writeOpenBaselineConfig(t, config, cfg)
		refuseBeforePrompt(t, config, input, "CONFIG_REJECTED")
	})
	t.Run("unknown-input-field", func(t *testing.T) {
		path := filepath.Join(c.baseline.root, "unknown-edit.json")
		raw, err := json.Marshal(map[string]string{
			"item_id": c.itemID, "expected_old_title": c.oldTitle, "new_title": ownedEditedTitle,
			"debug": "extra",
		})
		if err != nil || os.WriteFile(path, raw, 0600) != nil {
			t.Fatal("EDIT_UNKNOWN_FIELD_FIXTURE_FAILED")
		}
		refuseBeforePrompt(t, c.baseline.configPath, path, "INPUT_REJECTED")
	})
	t.Run("oversize-input", func(t *testing.T) {
		path := filepath.Join(c.baseline.root, "oversize-edit.json")
		if os.WriteFile(path, bytes.Repeat([]byte(" "), 4097), 0600) != nil {
			t.Fatal("EDIT_OVERSIZE_FIXTURE_FAILED")
		}
		refuseBeforePrompt(t, c.baseline.configPath, path, "INPUT_REJECTED")
	})
}
