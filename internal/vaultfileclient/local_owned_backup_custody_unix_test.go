//go:build darwin || linux

package vaultfileclient

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/pkg/vaultfile"
)

func localCustodyCheckpoint(checkpoint *vaultfile.PolicyCheckpoint) vaultfile.PolicyCheckpoint {
	return vaultfile.PolicyCheckpoint{
		VaultID:            checkpoint.VaultID,
		OwnerRootKeyID:     checkpoint.OwnerRootKeyID,
		OwnerRootPublicKey: bytes.Clone(checkpoint.OwnerRootPublicKey),
		PolicySeq:          checkpoint.PolicySeq,
		PolicyDigest:       bytes.Clone(checkpoint.PolicyDigest),
	}
}

func localCustodyOpenRefuses(t *testing.T, code string, artifact []byte,
	expected vaultfile.PolicyCheckpoint, factor *personal.VaultFileBackupRecoveryFactor) {
	t.Helper()
	opened, err := OpenLocalOwnedBackupCustody(context.Background(), artifact, expected, factor)
	if !errors.Is(err, ErrLocalOwnedBackupReview) ||
		opened.Source.VaultID != "" || opened.Source.Current != nil || opened.Source.Origin != nil ||
		opened.Ownership != (personal.VaultFileOwnershipPublic{}) {
		t.Fatal(code)
	}
}

func localCustodyAssertPristineSummary(t *testing.T, wrapper *LocalGenesisSession,
	summary LocalGenesisBaseline, vaultID string) {
	t.Helper()
	if summary.VaultID != vaultID || len(summary.Items) != 0 {
		t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_SIBLING_SUMMARY_FAILED")
	}
	again, err := wrapper.Summary()
	if err != nil || again.VaultID != vaultID || len(again.Items) != 0 {
		t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_SIBLING_REOPEN_FAILED")
	}
}

func localCustodyAssertSource(t *testing.T, opened LocalOwnedBackupCustodyOpen,
	checkpoint vaultfile.PolicyCheckpoint, current, origin []byte,
	journalRevision, backendRevision, originRevision string, contentSeq uint64,
	sourceIdentity [32]byte, code string) {
	t.Helper()
	if opened.Source.VaultID != checkpoint.VaultID ||
		!sameLocalOwnedBackupCustodyCheckpoint(opened.Source.Checkpoint, checkpoint) ||
		!bytes.Equal(opened.Source.Current, current) ||
		!bytes.Equal(opened.Source.Origin, origin) ||
		string(opened.Source.JournalRevision) != journalRevision ||
		string(opened.Source.BackendRevision) != backendRevision ||
		string(opened.Source.OriginRevision) != originRevision ||
		opened.Source.ContentSeq != contentSeq ||
		opened.Source.CheckpointDigest == ([32]byte{}) ||
		opened.Source.IdentityDigest == ([32]byte{}) ||
		opened.SourceIdentity != sourceIdentity || sourceIdentity == ([32]byte{}) ||
		opened.Ownership.VaultID != checkpoint.VaultID ||
		opened.Ownership.OwnerRootKeyID != checkpoint.OwnerRootKeyID ||
		opened.Ownership.OwnerRootPublicKey != fmt.Sprintf("%x", checkpoint.OwnerRootPublicKey) {
		t.Fatal(code)
	}
}

// localCustodySelfAssertedScope rewrites the public vault and checkpoint fields
// of an artifact without the owner-root signature. The real decrypt/verify
// entry must refuse the self-asserted scope.
func localCustodySelfAssertedScope(t *testing.T, artifact []byte, checkpoint vaultfile.PolicyCheckpoint) []byte {
	t.Helper()
	var envelope map[string]any
	if err := json.Unmarshal(artifact, &envelope); err != nil {
		t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_SCOPE_PARSE_FAILED")
	}
	header, ok := envelope["header"].(map[string]any)
	if !ok {
		t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_SCOPE_HEADER_FAILED")
	}
	header["vault_id"] = checkpoint.VaultID
	header["checkpoint"] = map[string]any{
		"VaultID":            checkpoint.VaultID,
		"OwnerRootKeyID":     checkpoint.OwnerRootKeyID,
		"OwnerRootPublicKey": base64.StdEncoding.EncodeToString(checkpoint.OwnerRootPublicKey),
		"PolicySeq":          checkpoint.PolicySeq,
		"PolicyDigest":       base64.StdEncoding.EncodeToString(checkpoint.PolicyDigest),
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_SCOPE_ENCODE_FAILED")
	}
	return raw
}

type localCustodyPrepareResult struct {
	custody LocalOwnedBackupCustody
	factor  *personal.VaultFileBackupRecoveryFactor
	err     error
}

func localCustodyOpenDirectSeal(t *testing.T, session *personal.Session,
	v *localIsolationVault, f *creationBoundaryFixture,
	expected vaultfile.PolicyCheckpoint) (personal.VaultFileChildToken,
	*personal.VaultFileReadDeliveryClaim, *personal.VaultFileBackupCustodySeal) {
	t.Helper()
	pin := localBackupPin(t, v.manifest, v.companion)
	target := personal.OwnedVaultFileFirstSuccessorTarget{
		BackendRoot: v.manifest.BackendRoot, BackendName: v.manifest.Name, Pin: pin,
	}
	token, items, err := session.OpenOwnedFirstSuccessorVaultFileChildForCustody(
		v.manifest.Journal, target, v.checkpoint, f.password, f.key,
		personal.VaultFileChildOptions{})
	clearLocalGenesisItems(items)
	clear(target.Pin.Root.OwnerRootPublicKey)
	if err != nil {
		t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_DIRECT_CHILD_FAILED")
	}
	claim, err := session.BeginVaultFileReadDeliveryClaim(token)
	if err != nil {
		_ = session.LockVaultFileChild(token)
		t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_DIRECT_CLAIM_FAILED")
	}
	seal, err := session.PrepareVaultFileBackupCustodyForChild(context.Background(),
		token, claim, expected, f.password, f.key)
	if err != nil || seal == nil {
		_ = session.LockVaultFileChild(token)
		t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_DIRECT_SEAL_FAILED")
	}
	return token, claim, seal
}

func TestLocalOwnedBackupCustodySealsOneVaultAndRefusesScope(t *testing.T) {
	passwordA := []byte("local-custody-factor-a")
	keyA := bytes.Repeat([]byte{0x3c}, 16)
	passwordB := []byte("local-custody-factor-b")
	keyB := bytes.Repeat([]byte{0x7d}, 16)
	defer clear(passwordA)
	defer clear(passwordB)
	defer clear(keyA)
	defer clear(keyB)

	fA := localIsolationCreation(t, "custody-a", passwordA, keyA)
	fB := localIsolationCreation(t, "custody-b", passwordB, keyB)
	vA := newLocalIsolationVault(t, fA, localFirstWriteTitle)
	vB := newLocalIsolationVault(t, fB, localFirstWriteTitle)
	vA.item.Password = localFirstWriteSecret + "-custody-a"
	vB.item.Password = localFirstWriteSecret + "-custody-b"

	resultA := vA.write(t)
	settledA := localIsolationReadSettled(t, vA, resultA)
	defer settledA.clear()
	beforeB := localFirstObserveScope(t, vB.manifest)
	defer beforeB.clear()
	expectedA := localCustodyCheckpoint(vA.checkpoint)
	defer clear(expectedA.OwnerRootPublicKey)
	defer clear(expectedA.PolicyDigest)
	expectedB := localCustodyCheckpoint(vB.checkpoint)
	defer clear(expectedB.OwnerRootPublicKey)
	defer clear(expectedB.PolicyDigest)

	custodyA, factorA, err := PrepareLocalOwnedBackupCustody(context.Background(),
		vA.session, vA.config, vA.manifest.BackendRoot, vA.manifest.VaultID,
		vA.manifest.Journal, expectedA, fA.password, fA.key)
	if err != nil || len(custodyA.Artifact) == 0 || factorA == nil {
		t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_A_PREPARE_FAILED")
	}
	defer custodyA.Clear()
	defer factorA.Clear()
	localFirstAssertScopeUnchanged(t, beforeB, vB.manifest,
		"LOCAL_OWNED_BACKUP_CUSTODY_B_CHANGED_BY_A_PREPARE")
	if !vA.session.Unlocked() || !vB.session.Unlocked() {
		t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_PARENT_LOCKED_BY_A_PREPARE")
	}
	if bytes.Contains(custodyA.Artifact, []byte(vB.manifest.VaultID)) {
		t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_A_CONTAINS_B")
	}

	custodyB, factorB, err := PrepareLocalOwnedBackupCustody(context.Background(),
		vB.session, vB.config, vB.manifest.BackendRoot, vB.manifest.VaultID,
		vB.manifest.Journal, expectedB, fB.password, fB.key)
	if err != nil || len(custodyB.Artifact) == 0 || factorB == nil {
		t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_B_PREPARE_FAILED")
	}
	defer custodyB.Clear()
	defer factorB.Clear()
	localFirstAssertScopeUnchanged(t, beforeB, vB.manifest,
		"LOCAL_OWNED_BACKUP_CUSTODY_B_CHANGED_BY_B_PREPARE")

	materialA := factorA.Material()
	defer clear(materialA)
	materialB := factorB.Material()
	defer clear(materialB)
	if len(materialA) == 0 || len(materialB) == 0 || bytes.Equal(materialA, materialB) {
		t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_FACTORS_NOT_INDEPENDENT")
	}
	if bytes.Contains(custodyA.Artifact, materialA) || bytes.Contains(custodyB.Artifact, materialB) {
		t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_FACTOR_LEAKED_TO_ARTIFACT")
	}
	factorA.Clear()
	factorB.Clear()
	if factorA.Material() != nil || factorB.Material() != nil {
		t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_FACTOR_NOT_CLEARED")
	}
	importedA, err := ImportLocalOwnedBackupRecoveryFactor(materialA)
	if err != nil || importedA == nil {
		t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_FACTOR_IMPORT_A_FAILED")
	}
	defer importedA.Clear()
	importedB, err := ImportLocalOwnedBackupRecoveryFactor(materialB)
	if err != nil || importedB == nil {
		t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_FACTOR_IMPORT_B_FAILED")
	}
	defer importedB.Clear()
	if _, err := ImportLocalOwnedBackupRecoveryFactor([]byte("not-a-recovery-factor")); !errors.Is(err, ErrLocalOwnedBackupReview) {
		t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_INVALID_FACTOR_ACCEPTED")
	}
	if _, err := ImportLocalOwnedBackupRecoveryFactor(bytes.Repeat([]byte{'A'}, 129)); !errors.Is(err, ErrLocalOwnedBackupUnsupported) {
		t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_OVERSIZE_FACTOR_ACCEPTED")
	}
	const redacted = "[vault-file backup recovery factor]"
	for _, verb := range []string{"%v", "%+v", "%#v", "%d", "%x", "%s", "%q"} {
		for _, value := range []any{importedA, *importedA} {
			if formatted := fmt.Sprintf(verb, value); formatted != redacted {
				t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_FACTOR_NOT_REDACTED")
			}
		}
		if formatted := fmt.Sprintf(verb, (*personal.VaultFileBackupRecoveryFactor)(nil)); formatted != "<nil>" {
			t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_FACTOR_NIL_NOT_FIXED")
		}
	}
	for _, value := range []any{importedA, *importedA} {
		if raw, err := json.Marshal(value); err != nil || bytes.Contains(raw, materialA) {
			t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_FACTOR_JSON_LEAKED")
		}
	}
	if raw, err := json.Marshal((*personal.VaultFileBackupRecoveryFactor)(nil)); err != nil || string(raw) != "null" {
		t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_FACTOR_NIL_JSON_FAILED")
	}
	reopened := importedA.Material()
	if !bytes.Equal(reopened, materialA) {
		clear(reopened)
		t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_FACTOR_REOPEN_MISMATCH")
	}
	clear(reopened)

	openedA, err := OpenLocalOwnedBackupCustody(context.Background(), custodyA.Artifact, expectedA, importedA)
	if err != nil {
		t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_A_OPEN_FAILED")
	}
	defer openedA.Clear()
	localCustodyAssertSource(t, openedA, expectedA,
		settledA.record.SuccessorBytes, settledA.record.GenesisBytes,
		string(settledA.record.SuccessorRevision), string(settledA.record.SuccessorRevision),
		string(settledA.record.GenesisRevision), 1,
		custodyA.SourceIdentity, "LOCAL_OWNED_BACKUP_CUSTODY_A_SOURCE_MISMATCH")
	ownersA, err := vA.session.VaultFileOwnerships()
	if err != nil || len(ownersA) != 1 || openedA.Ownership != ownersA[0] {
		t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_A_OWNER_MISMATCH")
	}
	if ownersA[0].VaultID == vB.manifest.VaultID {
		t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_A_OWNER_IS_B")
	}

	backendB, revisionB := localFirstReadBackend(t, vB.manifest)
	defer clear(backendB)
	openedB, err := OpenLocalOwnedBackupCustody(context.Background(), custodyB.Artifact, expectedB, importedB)
	if err != nil {
		t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_B_OPEN_FAILED")
	}
	defer openedB.Clear()
	localCustodyAssertSource(t, openedB, expectedB, backendB, nil,
		string(revisionB), string(revisionB), "", 0,
		custodyB.SourceIdentity, "LOCAL_OWNED_BACKUP_CUSTODY_B_SOURCE_MISMATCH")
	ownersB, err := vB.session.VaultFileOwnerships()
	if err != nil || len(ownersB) != 1 || openedB.Ownership != ownersB[0] {
		t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_B_OWNER_MISMATCH")
	}

	// A factor cannot open B, B cannot open A, and the exact expected
	// checkpoint is checked before decryption.
	localCustodyOpenRefuses(t, "LOCAL_OWNED_BACKUP_CUSTODY_A_WRONG_FACTOR",
		custodyA.Artifact, expectedA, importedB)
	localCustodyOpenRefuses(t, "LOCAL_OWNED_BACKUP_CUSTODY_B_WRONG_FACTOR",
		custodyB.Artifact, expectedB, importedA)
	localCustodyOpenRefuses(t, "LOCAL_OWNED_BACKUP_CUSTODY_A_WRONG_CHECKPOINT",
		custodyA.Artifact, expectedB, importedA)
	localCustodyOpenRefuses(t, "LOCAL_OWNED_BACKUP_CUSTODY_B_WRONG_CHECKPOINT",
		custodyB.Artifact, expectedA, importedB)

	tampered := bytes.Clone(custodyA.Artifact)
	tampered[len(tampered)/2] ^= 0x40
	localCustodyOpenRefuses(t, "LOCAL_OWNED_BACKUP_CUSTODY_TAMPER_ACCEPTED",
		tampered, expectedA, importedA)
	clear(tampered)

	selfAsserted := localCustodySelfAssertedScope(t, custodyA.Artifact, expectedB)
	localCustodyOpenRefuses(t, "LOCAL_OWNED_BACKUP_CUSTODY_SELF_ASSERTED_SCOPE_ACCEPTED",
		selfAsserted, expectedB, importedA)
	clear(selfAsserted)

	wrongAccount, wrongAccountFactor, err := PrepareLocalOwnedBackupCustody(context.Background(),
		vB.session, vA.config, vA.manifest.BackendRoot, vA.manifest.VaultID,
		vA.manifest.Journal, expectedA, fB.password, fB.key)
	if !errors.Is(err, ErrLocalOwnedBackupReview) || wrongAccount.Artifact != nil || wrongAccountFactor != nil {
		t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_WRONG_ACCOUNT_ACCEPTED")
	}
	wrongBinding, wrongBindingFactor, err := PrepareLocalOwnedBackupCustody(context.Background(),
		vA.session, vA.config, vA.manifest.BackendRoot, vA.manifest.VaultID,
		vA.manifest.Journal, expectedB, fA.password, fA.key)
	if !errors.Is(err, ErrLocalOwnedBackupReview) || wrongBinding.Artifact != nil || wrongBindingFactor != nil {
		t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_WRONG_BINDING_ACCEPTED")
	}
	localFirstAssertScopeUnchanged(t, beforeB, vB.manifest,
		"LOCAL_OWNED_BACKUP_CUSTODY_B_CHANGED_BY_REFUSALS")
	if !vA.session.Unlocked() || !vB.session.Unlocked() {
		t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_REFUSAL_LOCKED_PARENT")
	}

	wrapperB, summaryB, err := OpenLocalGenesisSessionForJournal(vB.session, vB.config,
		vB.manifest.BackendRoot, vB.manifest.VaultID, vB.manifest.Journal,
		fB.password, fB.key)
	if err != nil || wrapperB == nil {
		t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_SIBLING_OPEN_FAILED")
	}
	defer wrapperB.Close()
	localCustodyAssertPristineSummary(t, wrapperB, summaryB, vB.manifest.VaultID)

	t.Run("ordinary child authority cannot seal", func(t *testing.T) {
		pin := localBackupPin(t, vA.manifest, vA.companion)
		target := personal.OwnedVaultFileFirstSuccessorTarget{
			BackendRoot: vA.manifest.BackendRoot, BackendName: vA.manifest.Name, Pin: pin,
		}
		token, items, err := vA.session.OpenOwnedFirstSuccessorVaultFileChild(
			vA.manifest.Journal, target, vA.checkpoint, fA.password, fA.key,
			personal.VaultFileChildOptions{})
		clearLocalGenesisItems(items)
		clear(target.Pin.Root.OwnerRootPublicKey)
		if err != nil {
			t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_ORDINARY_CHILD_OPEN_FAILED")
		}
		defer vA.session.LockVaultFileChild(token)
		claim, err := vA.session.BeginVaultFileReadDeliveryClaim(token)
		if err != nil {
			t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_ORDINARY_CHILD_CLAIM_FAILED")
		}
		sealed, err := vA.session.PrepareVaultFileBackupCustodyForChild(context.Background(), token,
			claim, expectedA, fA.password, fA.key)
		if !errors.Is(err, personal.ErrVaultFileBackupCustody) || sealed != nil {
			t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_ORDINARY_CHILD_ACCEPTED")
		}
	})

	startPrepare := func(ctx context.Context) chan localCustodyPrepareResult {
		done := make(chan localCustodyPrepareResult, 1)
		go func() {
			custody, factor, err := PrepareLocalOwnedBackupCustody(ctx,
				vA.session, vA.config, vA.manifest.BackendRoot, vA.manifest.VaultID,
				vA.manifest.Journal, expectedA, fA.password, fA.key)
			done <- localCustodyPrepareResult{custody: custody, factor: factor, err: err}
		}()
		return done
	}
	installCloseBlock := func(state *localGenesisSessionState, started, release chan struct{}) {
		state.firstCloseForTest = func() {
			close(started)
			<-release
		}
	}

	t.Run("cancel cannot deliver", func(t *testing.T) {
		started := make(chan struct{})
		release := make(chan struct{})
		released := false
		localOwnedBackupBeforeCloseForTest = func(state *localGenesisSessionState) {
			installCloseBlock(state, started, release)
		}
		defer func() {
			localOwnedBackupBeforeCloseForTest = nil
			if !released {
				close(release)
			}
		}()
		ctx, cancel := context.WithCancel(context.Background())
		done := startPrepare(ctx)
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			cancel()
			t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_CANCEL_NOT_REACHED")
		}
		cancel()
		close(release)
		released = true
		result := <-done
		if !errors.Is(result.err, ErrLocalOwnedBackupCanceled) ||
			result.custody.Artifact != nil || result.factor != nil {
			t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_CANCEL_DELIVERED")
		}
		if !vA.session.Unlocked() {
			t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_CANCEL_LOCKED_A")
		}
		localFirstAssertScopeUnchanged(t, beforeB, vB.manifest,
			"LOCAL_OWNED_BACKUP_CUSTODY_B_CHANGED_BY_CANCEL")
	})

	t.Run("request lock cannot deliver", func(t *testing.T) {
		started := make(chan struct{})
		release := make(chan struct{})
		released := false
		localOwnedBackupBeforeCloseForTest = func(state *localGenesisSessionState) {
			installCloseBlock(state, started, release)
		}
		defer func() {
			localOwnedBackupBeforeCloseForTest = nil
			if !released {
				close(release)
			}
		}()
		done := startPrepare(context.Background())
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_LOCK_NOT_REACHED")
		}
		lockReturned := make(chan struct{})
		go func() {
			vA.session.RequestLock()
			close(lockReturned)
		}()
		select {
		case <-lockReturned:
		case <-time.After(2 * time.Second):
			t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_REQUEST_LOCK_BLOCKED")
		}
		close(release)
		released = true
		result := <-done
		if !errors.Is(result.err, ErrLocalOwnedBackupCanceled) ||
			result.custody.Artifact != nil || result.factor != nil {
			t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_LOCK_DELIVERED")
		}
		if vA.session.Unlocked() {
			t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_LOCK_DID_NOT_LOCK_A")
		}
		localCustodyAssertPristineSummary(t, wrapperB, summaryB, vB.manifest.VaultID)
		localFirstAssertScopeUnchanged(t, beforeB, vB.manifest,
			"LOCAL_OWNED_BACKUP_CUSTODY_B_CHANGED_BY_A_LOCK")
	})

	t.Run("corrupt backend revision cannot seal", func(t *testing.T) {
		if err := wrapperB.Close(); err != nil {
			t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_B_WRAPPER_CLOSE_FAILED")
		}
		current, _ := localFirstReadBackend(t, vB.manifest)
		defer clear(current)
		localOwnedBackupCustodyBeforeSealForTest = func(*localGenesisSessionState) {
			localFirstRewriteBackend(t, vB.manifest, current)
		}
		defer func() { localOwnedBackupCustodyBeforeSealForTest = nil }()
		custody, factor, err := PrepareLocalOwnedBackupCustody(context.Background(),
			vB.session, vB.config, vB.manifest.BackendRoot, vB.manifest.VaultID,
			vB.manifest.Journal, expectedB, fB.password, fB.key)
		if !errors.Is(err, ErrLocalOwnedBackupReview) || custody.Artifact != nil || factor != nil {
			t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_CORRUPT_REVISION_ACCEPTED")
		}
		if !vB.session.Unlocked() {
			t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_CORRUPT_REVISION_LOCKED_B")
		}
	})

	t.Run("seal release is atomic and copy safe", func(t *testing.T) {
		freshA, err := personal.UnlockSession(vA.manifest.PersonalFile, fA.password, fA.key, time.Minute)
		if err != nil {
			t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_DIRECT_UNLOCK_FAILED")
		}
		t.Cleanup(freshA.Lock)

		const sealRedacted = "[vault-file backup custody seal]"
		token, claim, seal := localCustodyOpenDirectSeal(t, freshA, vA, fA, expectedA)
		defer freshA.LockVaultFileChild(token)
		for _, verb := range []string{"%v", "%+v", "%#v", "%d", "%x", "%s", "%q"} {
			for _, value := range []any{seal, *seal} {
				if formatted := fmt.Sprintf(verb, value); formatted != sealRedacted {
					t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_SEAL_NOT_REDACTED")
				}
			}
			if formatted := fmt.Sprintf(verb, (*personal.VaultFileBackupCustodySeal)(nil)); formatted != "<nil>" {
				t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_SEAL_NIL_NOT_FIXED")
			}
		}
		for _, value := range []any{seal, *seal} {
			if raw, err := json.Marshal(value); err != nil || string(raw) != "{}" {
				t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_SEAL_JSON_LEAKED")
			}
		}
		if raw, err := json.Marshal((*personal.VaultFileBackupCustodySeal)(nil)); err != nil || string(raw) != "null" {
			t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_SEAL_NIL_JSON_FAILED")
		}

		// Take before the actual close must refuse and wipe without release.
		artifact, factor, ownership, sourceIdentity, err := seal.Take(context.Background(), freshA)
		if err == nil || artifact != nil || factor != nil ||
			ownership != (personal.VaultFileOwnershipPublic{}) || sourceIdentity != ([32]byte{}) {
			t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_PRECHECK_RELEASED")
		}
		if err := claim.Consume(context.Background(), freshA); !errors.Is(err, personal.ErrVaultFileScopedChild) {
			t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_ORDINARY_CONSUME_ACCEPTED")
		}
		if err := freshA.LockVaultFileChild(token); err != nil {
			t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_PRECHECK_CLOSE_FAILED")
		}

		// A closed token without a sealed claim must not release either.
		token2, claim2, seal2 := localCustodyOpenDirectSeal(t, freshA, vA, fA, expectedA)
		defer freshA.LockVaultFileChild(token2)
		if err := freshA.LockVaultFileChild(token2); err != nil {
			t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_FAILED_CLOSE_PRECLOSE_FAILED")
		}
		if err := claim2.CloseChild(freshA); !errors.Is(err, personal.ErrVaultFileScopedChild) {
			t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_FAILED_CLOSE_ACCEPTED")
		}
		artifact, factor, _, _, err = seal2.Take(context.Background(), freshA)
		if err == nil || artifact != nil || factor != nil {
			t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_FAILED_CLOSE_RELEASED")
		}

		// A foreign Session cannot release; the rightful Session still can.
		token3, claim3, seal3 := localCustodyOpenDirectSeal(t, freshA, vA, fA, expectedA)
		defer freshA.LockVaultFileChild(token3)
		if err := claim3.CloseChild(freshA); err != nil {
			t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_DIRECT_CLOSE_FAILED")
		}
		if artifact, factor, _, _, err := seal3.Take(context.Background(), vB.session); err == nil || artifact != nil || factor != nil {
			t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_FOREIGN_SESSION_RELEASED")
		}
		artifact, factor, _, _, err = seal3.Take(context.Background(), freshA)
		if err != nil || len(artifact) == 0 || factor == nil {
			t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_RIGHTFUL_AFTER_FOREIGN_FAILED")
		}
		clear(artifact)
		factor.Clear()

		// Fresh closed claim then context cancellation must refuse.
		token4, claim4, seal4 := localCustodyOpenDirectSeal(t, freshA, vA, fA, expectedA)
		defer freshA.LockVaultFileChild(token4)
		if err := claim4.CloseChild(freshA); err != nil {
			t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_CANCEL_CLOSE_FAILED")
		}
		cancelCtx, cancel := context.WithCancel(context.Background())
		cancel()
		if artifact, factor, _, _, err := seal4.Take(cancelCtx, freshA); err == nil || artifact != nil || factor != nil {
			t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_CANCEL_RELEASED")
		}

		// Two copies share one state; exactly one Take wins and a loser Clear
		// cannot corrupt the winner's detached artifact/factor.
		token5, claim5, seal5 := localCustodyOpenDirectSeal(t, freshA, vA, fA, expectedA)
		defer freshA.LockVaultFileChild(token5)
		if err := claim5.CloseChild(freshA); err != nil {
			t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_RACE_CLOSE_FAILED")
		}
		copySeal := *seal5
		type takeResult struct {
			artifact []byte
			factor   *personal.VaultFileBackupRecoveryFactor
			err      error
		}
		start := make(chan struct{})
		results := make(chan takeResult, 2)
		var wait sync.WaitGroup
		for _, candidate := range []*personal.VaultFileBackupCustodySeal{seal5, &copySeal} {
			wait.Add(1)
			go func(candidate *personal.VaultFileBackupCustodySeal) {
				defer wait.Done()
				<-start
				artifact, factor, _, _, err := candidate.Take(context.Background(), freshA)
				results <- takeResult{artifact: artifact, factor: factor, err: err}
			}(candidate)
		}
		close(start)
		wait.Wait()
		close(results)
		var winner takeResult
		wins := 0
		for result := range results {
			if result.err == nil {
				wins++
				winner = result
			}
		}
		if wins != 1 || len(winner.artifact) == 0 || winner.factor == nil {
			t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_RACE_NOT_SINGLE_USE")
		}
		seal5.Clear()
		copySeal.Clear()
		if len(winner.artifact) == 0 || winner.factor == nil {
			t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_RACE_WINNER_CLEARED")
		}
		winnerMaterial := winner.factor.Material()
		if len(winnerMaterial) == 0 {
			t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_RACE_WINNER_FACTOR_MISSING")
		}
		winnerFactor, err := ImportLocalOwnedBackupRecoveryFactor(winnerMaterial)
		clear(winnerMaterial)
		if err != nil {
			t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_RACE_WINNER_FACTOR_IMPORT_FAILED")
		}
		opened, err := OpenLocalOwnedBackupCustody(context.Background(), winner.artifact, expectedA, winnerFactor)
		winnerFactor.Clear()
		if err != nil {
			clear(winner.artifact)
			winner.factor.Clear()
			t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_RACE_WINNER_ARTIFACT_FAILED")
		}
		opened.Clear()
		clear(winner.artifact)
		winner.factor.Clear()

		// A fresh closed claim then RequestLock must refuse.
		token6, claim6, seal6 := localCustodyOpenDirectSeal(t, freshA, vA, fA, expectedA)
		defer freshA.LockVaultFileChild(token6)
		if err := claim6.CloseChild(freshA); err != nil {
			t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_LOCK_CLOSE_FAILED")
		}
		freshA.RequestLock()
		if artifact, factor, _, _, err := seal6.Take(context.Background(), freshA); err == nil || artifact != nil || factor != nil {
			t.Fatal("LOCAL_OWNED_BACKUP_CUSTODY_LOCK_RELEASED")
		}
	})
}
