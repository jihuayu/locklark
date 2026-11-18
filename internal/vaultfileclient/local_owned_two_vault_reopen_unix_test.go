//go:build darwin || linux

package vaultfileclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"testing"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/vault"
	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
)

// localFirstScopeBytes is the exact durable scope of one vault: its journal
// bytes, the named backend object bytes and that object's opaque revision.
// Nothing here is normalized or hashed, so an assertion is byte-for-byte.
type localFirstScopeBytes struct {
	journal  []byte
	backend  []byte
	revision vaultfilebackend.Revision
}

func localFirstObserveScope(t *testing.T, manifest Manifest) localFirstScopeBytes {
	t.Helper()
	journal, err := os.ReadFile(manifest.Journal)
	if err != nil {
		t.Fatal("LOCAL_TWO_VAULT_JOURNAL_READ_FAILED")
	}
	backend, revision := localFirstReadBackend(t, manifest)
	return localFirstScopeBytes{journal: journal, backend: backend, revision: revision}
}

func (s *localFirstScopeBytes) clear() {
	if s == nil {
		return
	}
	clear(s.journal)
	clear(s.backend)
	s.revision = ""
}

func (s localFirstScopeBytes) assertSame(t *testing.T, other localFirstScopeBytes, code string) {
	t.Helper()
	if s.revision != other.revision || !bytes.Equal(s.journal, other.journal) ||
		!bytes.Equal(s.backend, other.backend) {
		t.Fatal(code)
	}
}

func localFirstAssertScopeUnchanged(t *testing.T, want localFirstScopeBytes, manifest Manifest, code string) {
	t.Helper()
	got := localFirstObserveScope(t, manifest)
	defer got.clear()
	want.assertSame(t, got, code)
}

// localFirstSettledVault records the two exact identities that must stay
// distinct across the two independently owned vaults.
type localFirstSettledVault struct {
	operationID string
	itemID      string
}

// localFirstAssertSettled verifies one acknowledged write against its typed
// journal record, a fresh named-backend observation, the signed immediate
// transition, the active account/device writer and the decrypted persisted
// item identity. The returned evidence contains only the opaque operation and
// item identifiers needed for cross-vault uniqueness assertions.
func localFirstAssertSettled(t *testing.T, fx *localFirstWriteFixture, result LocalOwnedFirstWriteResult, observed localFirstScopeBytes) localFirstSettledVault {
	t.Helper()
	if result.VaultID != fx.manifest.VaultID || result.JournalPath != fx.manifest.Journal ||
		result.OperationID == "" || result.Revision == "" {
		t.Fatal("LOCAL_TWO_VAULT_RESULT_BINDING_FAILED")
	}

	record := localFirstReadRecord(t, fx)
	defer clear(record.GenesisBytes)
	defer clear(record.SuccessorBytes)
	if record.GenesisRevision != fx.bootstrapRevision ||
		string(record.SuccessorRevision) != result.Revision ||
		!bytes.Equal(record.GenesisBytes, fx.genesis) {
		t.Fatal("LOCAL_TWO_VAULT_RECORD_BINDING_FAILED")
	}
	if observed.revision != record.SuccessorRevision || !bytes.Equal(observed.backend, record.SuccessorBytes) {
		t.Fatal("LOCAL_TWO_VAULT_BACKEND_RECORD_DISAGREE")
	}
	if err := vaultfile.VerifyContentTransition(record.GenesisBytes, record.SuccessorBytes, fx.checkpoint); err != nil {
		t.Fatal("LOCAL_TWO_VAULT_TRANSITION_INVALID")
	}

	genesis, err := vaultfile.ParseFile(record.GenesisBytes)
	if err != nil {
		t.Fatal("LOCAL_TWO_VAULT_GENESIS_PARSE_FAILED")
	}
	successor, err := vaultfile.ParseFile(record.SuccessorBytes)
	if err != nil || len(successor.SignedPolicyProofs) == 0 ||
		successor.Header.VaultID != fx.manifest.VaultID ||
		successor.Header.OpID != result.OperationID ||
		successor.Header.OpID == genesis.Header.OpID ||
		successor.Header.ContentSeq != genesis.Header.ContentSeq+1 {
		t.Fatal("LOCAL_TWO_VAULT_SUCCESSOR_BINDING_FAILED")
	}

	signing, localAge, recipient := localClientAccountIdentity(t, fx.f.f.proposal.PersonalFile,
		[]byte(fx.f.f.password), fx.f.f.key)
	defer clear(signing)
	policy := &successor.SignedPolicyProofs[len(successor.SignedPolicyProofs)-1].Policy
	writer, ok := localOwnedWriterDevice(policy, recipient, signing.Public().(ed25519.PublicKey))
	if !ok || writer != successor.Header.AuthorDeviceID {
		t.Fatal("LOCAL_TWO_VAULT_ACCOUNT_WRITER_FAILED")
	}

	_, metadata, items, err := vault.OpenAuthenticatedItems(record.SuccessorBytes, fx.checkpoint, writer, localAge)
	defer clear(metadata)
	defer func() {
		for i := range items {
			items[i] = vault.Item{}
		}
	}()
	if err != nil || len(items) != 1 ||
		items[0].ID != fx.item.ID || items[0].Title != fx.item.Title ||
		items[0].Username != fx.item.Username || items[0].Password != fx.item.Password {
		t.Fatal("LOCAL_TWO_VAULT_PERSISTED_ITEM_FAILED")
	}
	return localFirstSettledVault{operationID: result.OperationID, itemID: items[0].ID}
}

func localFirstAssertOrdinarySummary(t *testing.T, wrapper *LocalGenesisSession, summary LocalGenesisBaseline, fx *localFirstWriteFixture) {
	t.Helper()
	if summary.VaultID != fx.manifest.VaultID || len(summary.Items) != 1 ||
		summary.Items[0].Title != fx.item.Title {
		t.Fatal("LOCAL_TWO_VAULT_SUMMARY_FAILED")
	}
	again, err := wrapper.Summary()
	if err != nil || again.VaultID != fx.manifest.VaultID || len(again.Items) != 1 ||
		again.Items[0].Title != fx.item.Title {
		t.Fatal("LOCAL_TWO_VAULT_SUMMARY_REOPEN_FAILED")
	}
}

// localFirstAssertReopenedItemID uses the normally exposed fresh account and
// owned-child capabilities with IncludeItemIDs. The committed
// LocalGenesisSession.Summary constructor reads VaultFileChildOptions{} and so
// has no ID projection; this read is the committed production path that can
// expose the exact persisted item identity.
func localFirstAssertReopenedItemID(t *testing.T, session *personal.Session, fx *localFirstWriteFixture) {
	t.Helper()
	target := personal.OwnedVaultFileFirstSuccessorTarget{
		BackendRoot: fx.manifest.BackendRoot, BackendName: fx.manifest.Name,
		Pin: cloneLocalGenesisGenesisPin(fx.pin),
	}
	defer clear(target.Pin.Root.OwnerRootPublicKey)
	token, items, err := session.OpenOwnedFirstSuccessorVaultFileChild(fx.manifest.Journal, target,
		fx.checkpoint, []byte(fx.f.f.password), fx.f.f.key,
		personal.VaultFileChildOptions{IncludeItemIDs: true})
	if err != nil {
		t.Fatal("LOCAL_TWO_VAULT_CHILD_OPEN_FAILED")
	}
	defer func() { _ = session.LockVaultFileChild(token) }()
	defer clearLocalGenesisItems(items)
	if len(items) != 1 || items[0].ID != fx.item.ID || items[0].Title != fx.item.Title {
		t.Fatal("LOCAL_TWO_VAULT_CHILD_ITEM_ID_FAILED")
	}
}

func TestOwnedFirstWriteLocalTwoVaultsDurableReopen(t *testing.T) {
	f := newLocalGenesisTwoVaultFixture(t)
	fxA := newLocalFirstWriteFixtureFor(t, f, f.firstConfig, f.firstVaultID)
	fxB := newLocalFirstWriteFixtureFor(t, f, f.secondConfig, f.secondVaultID)

	if fxA.item.Title != fxB.item.Title || fxA.item.ID == fxB.item.ID {
		t.Fatal("LOCAL_TWO_VAULT_ITEM_IDENTITY_NOT_DISTINCT")
	}
	if fxA.manifest.PersonalFile != fxB.manifest.PersonalFile ||
		fxA.manifest.PersonalFile != f.f.proposal.PersonalFile {
		t.Fatal("LOCAL_TWO_VAULT_ACCOUNT_NOT_SHARED")
	}
	if fxA.manifest.VaultID == fxB.manifest.VaultID ||
		fxA.manifest.Journal == fxB.manifest.Journal ||
		fxA.manifest.Name == fxB.manifest.Name ||
		fxA.config == fxB.config {
		t.Fatal("LOCAL_TWO_VAULT_SCOPE_NOT_DISTINCT")
	}
	companionA, err := CompanionPath(fxA.config)
	if err != nil {
		t.Fatal("LOCAL_TWO_VAULT_COMPANION_PATH_FAILED")
	}
	companionB, err := CompanionPath(fxB.config)
	if err != nil || companionA == companionB {
		t.Fatal("LOCAL_TWO_VAULT_COMPANION_SCOPE_NOT_DISTINCT")
	}

	beforeA := localFirstObserveScope(t, fxA.manifest)
	defer beforeA.clear()
	beforeB := localFirstObserveScope(t, fxB.manifest)
	defer beforeB.clear()

	// The first write must publish only vault A.
	resultA, err := fxA.write(context.Background())
	if err != nil {
		t.Fatalf("WriteLocalGenesisFirstItem(A): %v", err)
	}
	localFirstAssertScopeUnchanged(t, beforeB, fxB.manifest, "LOCAL_TWO_VAULT_B_CHANGED_BY_A")
	afterA := localFirstObserveScope(t, fxA.manifest)
	defer afterA.clear()
	evidenceA := localFirstAssertSettled(t, fxA, resultA, afterA)

	// A cross-target journal must be refused before publication and must leave
	// both exact scopes untouched.
	if _, err := WriteLocalGenesisFirstItem(context.Background(), f.session, fxA.config,
		fxA.manifest.BackendRoot, fxA.manifest.VaultID, fxB.manifest.Journal,
		[]byte(f.f.password), f.f.key, fxB.item); !errors.Is(err, ErrLocalOwnedFirstWriteConflict) {
		t.Fatal("LOCAL_TWO_VAULT_CROSS_TARGET_WRITE_ACCEPTED")
	}
	if wrapper, _, err := OpenLocalGenesisSessionForJournal(f.session, fxA.config,
		fxA.manifest.BackendRoot, fxA.manifest.VaultID, fxB.manifest.Journal,
		[]byte(f.f.password), f.f.key); wrapper != nil || !errors.Is(err, ErrLocalReview) {
		t.Fatal("LOCAL_TWO_VAULT_CROSS_TARGET_OPEN_ACCEPTED")
	}
	afterACross := localFirstObserveScope(t, fxA.manifest)
	defer afterACross.clear()
	afterA.assertSame(t, afterACross, "LOCAL_TWO_VAULT_A_CHANGED_BY_CROSS_TARGET")
	localFirstAssertScopeUnchanged(t, beforeB, fxB.manifest, "LOCAL_TWO_VAULT_B_CHANGED_BY_CROSS_TARGET")

	// The second write must publish only vault B and leave A's acknowledged
	// journal/backend bytes and opaque revision exactly unchanged.
	resultB, err := fxB.write(context.Background())
	if err != nil {
		t.Fatalf("WriteLocalGenesisFirstItem(B): %v", err)
	}
	localFirstAssertScopeUnchanged(t, afterA, fxA.manifest, "LOCAL_TWO_VAULT_A_CHANGED_BY_B")
	afterB := localFirstObserveScope(t, fxB.manifest)
	defer afterB.clear()
	evidenceB := localFirstAssertSettled(t, fxB, resultB, afterB)

	if evidenceA.operationID == evidenceB.operationID || evidenceA.itemID == evidenceB.itemID ||
		resultA.OperationID == resultB.OperationID {
		t.Fatal("LOCAL_TWO_VAULT_IDENTITIES_NOT_UNIQUE")
	}

	// One independent close boundary and one independent account lock boundary
	// through the normally exposed child and account capabilities.
	childA, _, err := OpenLocalGenesisSessionForJournal(f.session, fxA.config,
		fxA.manifest.BackendRoot, fxA.manifest.VaultID, fxA.manifest.Journal,
		[]byte(f.f.password), f.f.key)
	if err != nil || childA == nil {
		t.Fatal("LOCAL_TWO_VAULT_CHILD_A_OPEN_FAILED")
	}
	childB, _, err := OpenLocalGenesisSessionForJournal(f.session, fxB.config,
		fxB.manifest.BackendRoot, fxB.manifest.VaultID, fxB.manifest.Journal,
		[]byte(f.f.password), f.f.key)
	if err != nil || childB == nil {
		t.Fatal("LOCAL_TWO_VAULT_CHILD_B_OPEN_FAILED")
	}
	if err := childA.Close(); err != nil {
		t.Fatal("LOCAL_TWO_VAULT_CHILD_A_CLOSE_FAILED")
	}
	if _, err := childB.Summary(); err != nil {
		t.Fatal("LOCAL_TWO_VAULT_CHILD_B_HURT_BY_A_CLOSE")
	}
	f.session.Lock()
	if _, err := childB.Summary(); err == nil {
		t.Fatal("LOCAL_TWO_VAULT_CHILD_B_READ_AFTER_ACCOUNT_LOCK")
	}
	if err := childB.Close(); err != nil {
		t.Fatal("LOCAL_TWO_VAULT_CHILD_B_CLOSE_FAILED")
	}

	// A locked original account session must never be a positive reopen path.
	if wrapper, _, err := OpenLocalGenesisSessionForJournal(f.session, fxA.config,
		fxA.manifest.BackendRoot, fxA.manifest.VaultID, fxA.manifest.Journal,
		[]byte(f.f.password), f.f.key); wrapper != nil || !errors.Is(err, ErrLocalReview) {
		t.Fatal("LOCAL_TWO_VAULT_OLD_SESSION_REOPEN_ACCEPTED")
	}

	// Unlock a fresh account session from the persisted account and reconstruct
	// both locators through the committed read-only production API.
	fresh := localFirstUnlockFresh(t, f)
	wrapperA, summaryA, err := OpenLocalGenesisSessionForJournal(fresh, fxA.config,
		fxA.manifest.BackendRoot, fxA.manifest.VaultID, fxA.manifest.Journal,
		[]byte(f.f.password), f.f.key)
	if err != nil || wrapperA == nil {
		t.Fatal("LOCAL_TWO_VAULT_FRESH_A_OPEN_FAILED")
	}
	defer wrapperA.Close()
	localFirstAssertOrdinarySummary(t, wrapperA, summaryA, fxA)
	localFirstAssertReopenedItemID(t, fresh, fxA)

	wrapperB, summaryB, err := OpenLocalGenesisSessionForJournal(fresh, fxB.config,
		fxB.manifest.BackendRoot, fxB.manifest.VaultID, fxB.manifest.Journal,
		[]byte(f.f.password), f.f.key)
	if err != nil || wrapperB == nil {
		t.Fatal("LOCAL_TWO_VAULT_FRESH_B_OPEN_FAILED")
	}
	defer wrapperB.Close()
	localFirstAssertOrdinarySummary(t, wrapperB, summaryB, fxB)
	localFirstAssertReopenedItemID(t, fresh, fxB)
}
