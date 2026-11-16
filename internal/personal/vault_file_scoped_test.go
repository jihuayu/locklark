//go:build darwin || linux

package personal

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/jihuayu/locklark/internal/vault"
	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
	bolt "go.etcd.io/bbolt"
)

type scopedChildVault struct {
	journal    string
	checkpoint *vaultfile.PolicyCheckpoint
	sealed     []byte
	itemID     string
}

type scopedChildFixture struct {
	session  *Session
	password []byte
	key      []byte
	a        scopedChildVault
	b        scopedChildVault
}

func newScopedChildFixture(t *testing.T) *scopedChildFixture {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "personal.ll")
	password := []byte("scoped-child-full-factor")
	key := bytes.Repeat([]byte{0x5c}, 16)
	if err := Create(path, string(password), key); err != nil {
		t.Fatal("SCOPED_CHILD_CREATE_FAILED")
	}
	session, err := UnlockSession(path, password, key, time.Minute)
	if err != nil {
		t.Fatal("SCOPED_CHILD_UNLOCK_FAILED")
	}
	t.Cleanup(session.Lock)

	var accountIdentity identity
	if err := json.Unmarshal(session.material, &accountIdentity); err != nil ||
		len(accountIdentity.Signing) != ed25519.SeedSize || accountIdentity.Device == "" {
		t.Fatal("SCOPED_CHILD_IDENTITY_READ_FAILED")
	}
	defer func() {
		accountIdentity.clear()
		accountIdentity.Device = ""
	}()
	localAge, err := age.ParseX25519Identity(accountIdentity.Device)
	if err != nil {
		t.Fatal("SCOPED_CHILD_AGE_PARSE_FAILED")
	}
	signer := ed25519.NewKeyFromSeed(accountIdentity.Signing)
	defer clear(signer)

	fx := &scopedChildFixture{session: session, password: password, key: key}
	fx.a = newScopedChildVault(t, dir, "a", signer, localAge.Recipient().String(), "login-a")
	fx.b = newScopedChildVault(t, dir, "b", signer, localAge.Recipient().String(), "login-b")
	return fx
}

func newScopedChildVault(t *testing.T, dir, name string, signer ed25519.PrivateKey, recipient, itemID string) scopedChildVault {
	t.Helper()
	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("SCOPED_CHILD_ROOT_KEY_FAILED")
	}
	vaultID, err := randomID()
	if err != nil {
		t.Fatal("SCOPED_CHILD_VAULT_ID_FAILED")
	}
	opID, err := randomID()
	if err != nil {
		t.Fatal("SCOPED_CHILD_OP_ID_FAILED")
	}
	vuk := make([]byte, vaultfile.CEKSize)
	if _, err := rand.Read(vuk); err != nil {
		t.Fatal("SCOPED_CHILD_VUK_FAILED")
	}
	defer clear(vuk)

	policy := &vaultfile.Policy{
		Format:           vaultfile.Format,
		Version:          vaultfile.Version,
		VaultID:          vaultID,
		PolicySeq:        0,
		PrevPolicyDigest: nil,
		OwnerRoot: vaultfile.OwnerRoot{
			KeyID:     "owner-root-" + name,
			Alg:       vaultfile.PolicySigAlgEd25519,
			PublicKey: bytes.Clone(rootPub),
			Owners:    []vaultfile.Principal{{PrincipalID: "owner", Label: "Owner"}},
		},
		Writers: []vaultfile.Member{{PrincipalID: "owner", Label: "Owner"}},
		Owners:  []vaultfile.Member{{PrincipalID: "owner", Label: "Owner"}},
		Devices: []vaultfile.Device{{
			DeviceID:          vaultFileGenesisAuthorDeviceID,
			PrincipalID:       "owner",
			Label:             "Personal device",
			ContentSigningKey: vaultfile.PublicKey{Alg: vaultfile.SigAlgEd25519, PublicKey: signer.Public().(ed25519.PublicKey)},
			AgeEncryptionKey:  recipient,
		}},
	}
	if err := vaultfile.ValidatePolicy(policy); err != nil {
		t.Fatal("SCOPED_CHILD_POLICY_INVALID")
	}
	document, err := vaultfile.EncodePolicyDocument(policy)
	if err != nil {
		t.Fatal("SCOPED_CHILD_POLICY_ENCODE_FAILED")
	}
	msg := make([]byte, 0, len(vaultfile.DomainPolicyDocumentSignature)+1+len(document))
	msg = append(msg, vaultfile.DomainPolicyDocumentSignature...)
	msg = append(msg, 0)
	msg = append(msg, document...)
	proof := vaultfile.SignedPolicy{
		Policy:   *clonePolicyForScopedChild(policy),
		Document: document,
		SignerID: policy.OwnerRoot.KeyID,
		Alg:      vaultfile.PolicySigAlgEd25519,
		Sig:      ed25519.Sign(rootPriv, msg),
	}
	policyDigest := vaultfile.PolicyDigest(policy)
	checkpoint := &vaultfile.PolicyCheckpoint{
		VaultID:            vaultID,
		OwnerRootKeyID:     policy.OwnerRoot.KeyID,
		OwnerRootPublicKey: bytes.Clone(rootPub),
		PolicySeq:          0,
		PolicyDigest:       bytes.Clone(policyDigest),
	}
	draft := &vaultfile.File{
		Format:  vaultfile.Format,
		Version: vaultfile.Version,
		Header: vaultfile.Header{
			VaultID:        vaultID,
			KeyEpoch:       1,
			ContentSeq:     0,
			OpID:           opID,
			PolicySeq:      0,
			PolicyDigest:   bytes.Clone(policyDigest),
			AuthorDeviceID: vaultFileGenesisAuthorDeviceID,
		},
		SignedPolicyProofs: []vaultfile.SignedPolicy{proof},
	}
	items := []vault.Item{{
		ID: itemID, Kind: "login", Title: "Shared scoped title",
		Username: "shared-user", Password: "shared-password",
		OTP: "otpauth://totp/example?secret=AAAA",
	}}
	sealed, err := vault.SealAuthenticatedItems(draft, []byte{}, items, checkpoint, vuk, signer)
	if err != nil {
		t.Fatal("SCOPED_CHILD_SEAL_FAILED")
	}
	journalDir := filepath.Join(dir, "journal-"+name)
	if err := os.Mkdir(journalDir, 0700); err != nil {
		t.Fatal("SCOPED_CHILD_JOURNAL_DIR_FAILED")
	}
	journalPath := filepath.Join(journalDir, "state.journal")
	state := vaultfilejournal.State{
		BaseBytes:      bytes.Clone(sealed),
		WorkingBytes:   bytes.Clone(sealed),
		RemoteRevision: vaultfilebackend.Revision("\"rev-" + name + "\""),
		Generation:     0,
	}
	if err := vaultfilejournal.CreateNewState(journalPath, state); err != nil {
		t.Fatal("SCOPED_CHILD_JOURNAL_CREATE_FAILED")
	}
	return scopedChildVault{journal: journalPath, checkpoint: checkpoint, sealed: sealed, itemID: itemID}
}

// clonePolicyForScopedChild is a test-only deep copy for the signed proof.
func clonePolicyForScopedChild(p *vaultfile.Policy) *vaultfile.Policy {
	q := *p
	q.PrevPolicyDigest = bytes.Clone(p.PrevPolicyDigest)
	q.OwnerRoot.PublicKey = bytes.Clone(p.OwnerRoot.PublicKey)
	q.OwnerRoot.Owners = append([]vaultfile.Principal(nil), p.OwnerRoot.Owners...)
	q.Readers = append([]vaultfile.Member(nil), p.Readers...)
	q.Writers = append([]vaultfile.Member(nil), p.Writers...)
	q.Admins = append([]vaultfile.Member(nil), p.Admins...)
	q.Owners = append([]vaultfile.Member(nil), p.Owners...)
	q.AdminDelegations = append([]vaultfile.AdminDelegation(nil), p.AdminDelegations...)
	q.Devices = append([]vaultfile.Device(nil), p.Devices...)
	for i := range q.Devices {
		q.Devices[i].ContentSigningKey.PublicKey = bytes.Clone(p.Devices[i].ContentSigningKey.PublicKey)
		if p.Devices[i].PolicySigningKey != nil {
			k := *p.Devices[i].PolicySigningKey
			k.PublicKey = bytes.Clone(k.PublicKey)
			q.Devices[i].PolicySigningKey = &k
		}
	}
	return &q
}

func (fx *scopedChildFixture) child(path string) *vaultFileChild {
	fx.session.vaultFileMu.Lock()
	defer fx.session.vaultFileMu.Unlock()
	return fx.session.vaultFileChildren[path]
}

func (fx *scopedChildFixture) registryLen() int {
	fx.session.vaultFileMu.Lock()
	defer fx.session.vaultFileMu.Unlock()
	return len(fx.session.vaultFileChildren)
}

func assertScopedChildHandleClosed(t *testing.T, handle *vaultfile.ScopedUnlock) {
	t.Helper()
	if handle == nil {
		t.Fatal("SCOPED_CHILD_HANDLE_MISSING")
	}
	if _, _, err := handle.OpenDatabase(nil); err == nil {
		t.Fatal("SCOPED_CHILD_HANDLE_STILL_OPEN")
	} else if e, ok := vaultfile.AsError(err); !ok || e.Code != vaultfile.CodeUnlockUnavailable {
		t.Fatalf("SCOPED_CHILD_HANDLE_CLOSE_CODE=%q", func() string {
			if e, ok := vaultfile.AsError(err); ok {
				return e.Code
			}
			return ""
		}())
	}
}

func openScopedChildPair(t *testing.T, fx *scopedChildFixture) (VaultFileChildToken, VaultFileChildToken, *vaultfile.ScopedUnlock, *vaultfile.ScopedUnlock) {
	t.Helper()
	tokenA, _, err := fx.session.OpenVaultFileChild(fx.a.journal, fx.a.checkpoint, fx.password, fx.key, VaultFileChildOptions{})
	if err != nil {
		t.Fatalf("open A: %v", err)
	}
	tokenB, _, err := fx.session.OpenVaultFileChild(fx.b.journal, fx.b.checkpoint, fx.password, fx.key, VaultFileChildOptions{})
	if err != nil {
		t.Fatalf("open B: %v", err)
	}
	childA := fx.child(fx.a.journal)
	childB := fx.child(fx.b.journal)
	if childA == nil || childB == nil {
		t.Fatal("children not registered")
	}
	return tokenA, tokenB, childA.handle, childB.handle
}

func replaceScopedChildSlot(t *testing.T, path string, raw []byte) {
	t.Helper()
	db, err := bolt.Open(path, 0600, nil)
	if err != nil {
		t.Fatalf("open account db: %v", err)
	}
	updateErr := db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucket).Put(slotKey, raw)
	})
	closeErr := db.Close()
	if updateErr != nil || closeErr != nil {
		t.Fatalf("replace account slot: %v / %v", updateErr, closeErr)
	}
}

func deleteScopedChildSlot(t *testing.T, path string) {
	t.Helper()
	db, err := bolt.Open(path, 0600, nil)
	if err != nil {
		t.Fatalf("open account db: %v", err)
	}
	updateErr := db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucket).Delete(slotKey)
	})
	closeErr := db.Close()
	if updateErr != nil || closeErr != nil {
		t.Fatalf("delete account slot: %v / %v", updateErr, closeErr)
	}
}

func makeScopedChildDBUnreadable(t *testing.T, path string) {
	t.Helper()
	moved := path + ".moved"
	if err := os.Rename(path, moved); err != nil {
		t.Fatalf("move account db: %v", err)
	}
	t.Cleanup(func() { _ = os.Rename(moved, path) })
}

func expireScopedParentIdle(t *testing.T, s *Session) {
	t.Helper()
	s.mu.Lock()
	s.last = time.Now()
	s.mu.Unlock()
	if err := s.SetIdleTimeout(5 * time.Second); err != nil {
		t.Fatalf("SetIdleTimeout: %v", err)
	}
	s.mu.Lock()
	s.last = time.Now().Add(-6 * time.Second)
	s.mu.Unlock()
}

func installScopedParentCloseFault(t *testing.T, failOn int32) *atomic.Int32 {
	t.Helper()
	var calls atomic.Int32
	vaultFileParentCheckCloseFault = func() error {
		if calls.Add(1) == failOn {
			return errors.New("injected parent-check close failure")
		}
		return nil
	}
	t.Cleanup(func() { vaultFileParentCheckCloseFault = nil })
	return &calls
}

func TestVaultFileChildReadRechecksParentAuthority(t *testing.T) {
	checkDrained := func(t *testing.T, fx *scopedChildFixture, handleA, handleB *vaultfile.ScopedUnlock) {
		t.Helper()
		if fx.registryLen() != 0 || fx.session.Unlocked() {
			t.Fatal("parent failure did not drain all children")
		}
		assertScopedChildHandleClosed(t, handleA)
		assertScopedChildHandleClosed(t, handleB)
	}

	t.Run("slot-change", func(t *testing.T) {
		fx := newScopedChildFixture(t)
		tokenA, _, handleA, handleB := openScopedChildPair(t, fx)
		replaceScopedChildSlot(t, fx.session.path, []byte("not-a-slot"))
		items, err := fx.session.ReadVaultFileChild(tokenA, VaultFileChildOptions{})
		if !errors.Is(err, ErrSessionLocked) || items != nil {
			t.Fatalf("A read after slot change = %v / %v", items, err)
		}
		checkDrained(t, fx, handleA, handleB)
	})

	t.Run("missing-slot", func(t *testing.T) {
		fx := newScopedChildFixture(t)
		tokenA, _, handleA, handleB := openScopedChildPair(t, fx)
		deleteScopedChildSlot(t, fx.session.path)
		items, err := fx.session.ReadVaultFileChild(tokenA, VaultFileChildOptions{})
		if !errors.Is(err, ErrSessionLocked) || items != nil {
			t.Fatalf("A read after missing slot = %v / %v", items, err)
		}
		checkDrained(t, fx, handleA, handleB)
	})

	t.Run("unreadable-db", func(t *testing.T) {
		fx := newScopedChildFixture(t)
		tokenA, _, handleA, handleB := openScopedChildPair(t, fx)
		makeScopedChildDBUnreadable(t, fx.session.path)
		items, err := fx.session.ReadVaultFileChild(tokenA, VaultFileChildOptions{})
		if !errors.Is(err, ErrSessionLocked) || items != nil {
			t.Fatalf("A read with unreadable account = %v / %v", items, err)
		}
		checkDrained(t, fx, handleA, handleB)
	})

	t.Run("lowered-idle", func(t *testing.T) {
		fx := newScopedChildFixture(t)
		tokenA, _, handleA, handleB := openScopedChildPair(t, fx)
		expireScopedParentIdle(t, fx.session)
		items, err := fx.session.ReadVaultFileChild(tokenA, VaultFileChildOptions{})
		if !errors.Is(err, ErrSessionLocked) || items != nil {
			t.Fatalf("A read after lowered idle = %v / %v", items, err)
		}
		checkDrained(t, fx, handleA, handleB)
	})
}

func TestVaultFileChildLateReadRechecksParentAuthority(t *testing.T) {
	run := func(t *testing.T, mutate func(*scopedChildFixture)) {
		t.Helper()
		fx := newScopedChildFixture(t)
		tokenA, _, handleA, handleB := openScopedChildPair(t, fx)
		entered := make(chan struct{})
		release := make(chan struct{})
		vaultFileChildReadHook = func() {
			close(entered)
			<-release
		}
		t.Cleanup(func() { vaultFileChildReadHook = nil })

		type readResult struct {
			count int
			err   error
		}
		result := make(chan readResult, 1)
		go func() {
			items, err := fx.session.ReadVaultFileChild(tokenA, VaultFileChildOptions{IncludeItemIDs: true})
			result <- readResult{count: len(items), err: err}
		}()
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("read did not reach the post-decrypt seam")
		}
		mutate(fx)
		close(release)
		select {
		case got := <-result:
			if got.err == nil || got.count != 0 || !errors.Is(got.err, ErrSessionLocked) {
				t.Fatalf("late read = count=%d err=%v", got.count, got.err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("late read did not return")
		}
		if fx.registryLen() != 0 || fx.session.Unlocked() {
			t.Fatal("late parent failure did not drain all children")
		}
		assertScopedChildHandleClosed(t, handleA)
		assertScopedChildHandleClosed(t, handleB)
	}

	t.Run("slot-after-decrypt", func(t *testing.T) {
		run(t, func(fx *scopedChildFixture) {
			replaceScopedChildSlot(t, fx.session.path, []byte("not-a-slot"))
		})
	})
	t.Run("idle-after-decrypt", func(t *testing.T) {
		run(t, func(fx *scopedChildFixture) {
			expireScopedParentIdle(t, fx.session)
		})
	})
}

func TestVaultFileChildOpenRechecksSlotBeforeRegister(t *testing.T) {
	fx := newScopedChildFixture(t)
	if _, _, err := fx.session.OpenVaultFileChild(fx.b.journal, fx.b.checkpoint, fx.password, fx.key, VaultFileChildOptions{}); err != nil {
		t.Fatalf("open B: %v", err)
	}
	childB := fx.child(fx.b.journal)
	vaultFileChildBeforeRegister = func() {
		replaceScopedChildSlot(t, fx.session.path, []byte("not-a-slot"))
	}
	t.Cleanup(func() { vaultFileChildBeforeRegister = nil })

	token, items, err := fx.session.OpenVaultFileChild(fx.a.journal, fx.a.checkpoint, fx.password, fx.key, VaultFileChildOptions{})
	if !errors.Is(err, ErrSessionLocked) || token != (VaultFileChildToken{}) || items != nil {
		t.Fatalf("A open after slot replacement = token=%v items=%v err=%v", token != (VaultFileChildToken{}), items, err)
	}
	if fx.child(fx.a.journal) != nil || fx.registryLen() != 0 || fx.session.Unlocked() {
		t.Fatal("slot replacement left a registered candidate")
	}
	assertScopedChildHandleClosed(t, childB.handle)
}

func TestVaultFileChildParentCheckCloseErrorDrains(t *testing.T) {
	t.Run("read-final-close", func(t *testing.T) {
		fx := newScopedChildFixture(t)
		tokenA, _, handleA, handleB := openScopedChildPair(t, fx)
		installScopedParentCloseFault(t, 2)
		items, err := fx.session.ReadVaultFileChild(tokenA, VaultFileChildOptions{IncludeItemIDs: true})
		if !errors.Is(err, ErrSessionLocked) || items != nil {
			t.Fatalf("read with final close fault = %v / %v", items, err)
		}
		if fx.registryLen() != 0 || fx.session.Unlocked() {
			t.Fatal("close fault left registered children")
		}
		assertScopedChildHandleClosed(t, handleA)
		assertScopedChildHandleClosed(t, handleB)
	})

	t.Run("open-register-close", func(t *testing.T) {
		fx := newScopedChildFixture(t)
		if _, _, err := fx.session.OpenVaultFileChild(fx.b.journal, fx.b.checkpoint, fx.password, fx.key, VaultFileChildOptions{}); err != nil {
			t.Fatalf("open B: %v", err)
		}
		childB := fx.child(fx.b.journal)
		installScopedParentCloseFault(t, 1)
		token, items, err := fx.session.OpenVaultFileChild(fx.a.journal, fx.a.checkpoint, fx.password, fx.key, VaultFileChildOptions{})
		if !errors.Is(err, ErrSessionLocked) || token != (VaultFileChildToken{}) || items != nil {
			t.Fatalf("open with final close fault = token=%v items=%v err=%v", token != (VaultFileChildToken{}), items, err)
		}
		if fx.child(fx.a.journal) != nil || fx.registryLen() != 0 || fx.session.Unlocked() {
			t.Fatal("close fault left a registered candidate")
		}
		assertScopedChildHandleClosed(t, childB.handle)
	})
}

func TestVaultFileChildLifecycleAndTokenGeneration(t *testing.T) {
	fx := newScopedChildFixture(t)
	open := func(v scopedChildVault) (VaultFileChildToken, []VaultFileBaselineItem) {
		t.Helper()
		token, items, err := fx.session.OpenVaultFileChild(v.journal, v.checkpoint, fx.password, fx.key, VaultFileChildOptions{IncludeItemIDs: true})
		if err != nil {
			t.Fatalf("OpenVaultFileChild: %v", err)
		}
		return token, items
	}

	tokenA, itemsA := open(fx.a)
	tokenB, itemsB := open(fx.b)
	if len(itemsA) != 1 || len(itemsB) != 1 ||
		itemsA[0].Title != "Shared scoped title" || itemsB[0].Title != "Shared scoped title" ||
		itemsA[0].ID != fx.a.itemID || itemsB[0].ID != fx.b.itemID ||
		itemsA[0].Category != vault.CategoryLogin || itemsB[0].Category != vault.CategoryLogin {
		t.Fatal("SCOPED_CHILD_INITIAL_SUMMARY_MISMATCH")
	}

	// Locking A rejects a later A read and leaves B and the account active.
	if err := fx.session.LockVaultFileChild(tokenA); err != nil {
		t.Fatalf("LockVaultFileChild(A): %v", err)
	}
	if _, err := fx.session.ReadVaultFileChild(tokenA, VaultFileChildOptions{}); !errors.Is(err, ErrVaultFileScopedChild) {
		t.Fatalf("A late read = %v", err)
	}
	if items, err := fx.session.ReadVaultFileChild(tokenB, VaultFileChildOptions{IncludeItemIDs: true}); err != nil ||
		len(items) != 1 || items[0].ID != fx.b.itemID {
		t.Fatalf("B read after A lock = %v", err)
	}
	if !fx.session.Unlocked() {
		t.Fatal("A child lock locked the parent account")
	}

	// Wrong factors reject only this attempt; B is unchanged.
	wrongPassword := bytes.Clone(fx.password)
	wrongPassword[0] ^= 1
	if _, _, err := fx.session.OpenVaultFileChild(fx.a.journal, fx.a.checkpoint, wrongPassword, fx.key, VaultFileChildOptions{}); !errors.Is(err, ErrVaultFileScopedFactors) {
		t.Fatalf("wrong factors = %v", err)
	}
	if _, err := fx.session.ReadVaultFileChild(tokenB, VaultFileChildOptions{}); err != nil {
		t.Fatal("wrong factors invalidated B")
	}

	// Correct factors establish a new A without replacing the parent Session,
	// and do not extend fullUnlock.
	parent := fx.session
	wantFullUnlock := fx.session.fullUnlock
	tokenA2, itemsA2 := open(fx.a)
	if tokenA2 == tokenA || len(itemsA2) != 1 || itemsA2[0].ID != fx.a.itemID {
		t.Fatal("new A generation or summary mismatch")
	}
	if fx.session != parent || fx.session.path != parent.path || !bytes.Equal(fx.session.material, parent.material) {
		t.Fatal("child unlock replaced the parent Session")
	}
	if !fx.session.fullUnlock.Equal(wantFullUnlock) {
		t.Fatal("child unlock extended global fullUnlock")
	}

	// A stale old-token close is a no-op for the new generation.
	if err := fx.session.LockVaultFileChild(tokenA); err != nil {
		t.Fatalf("stale close: %v", err)
	}
	if _, err := fx.session.ReadVaultFileChild(tokenA2, VaultFileChildOptions{}); err != nil {
		t.Fatal("stale old close removed the new A")
	}

	// Re-opening A replaces and closes the previous candidate rather than
	// merely dropping its pointer; the old token cannot touch the new child.
	old := fx.child(fx.a.journal)
	tokenA3, itemsA3 := open(fx.a)
	if tokenA3 == tokenA2 || len(itemsA3) != 1 {
		t.Fatal("A replacement did not create a new generation")
	}
	assertScopedChildHandleClosed(t, old.handle)
	if _, err := fx.session.ReadVaultFileChild(tokenA2, VaultFileChildOptions{}); !errors.Is(err, ErrVaultFileScopedChild) {
		t.Fatalf("superseded A read = %v", err)
	}
	if err := fx.session.LockVaultFileChild(tokenA2); err != nil {
		t.Fatalf("superseded close: %v", err)
	}
	if _, err := fx.session.ReadVaultFileChild(tokenA3, VaultFileChildOptions{}); err != nil {
		t.Fatal("superseded close removed the current A")
	}
}

type scopedClosePause struct {
	entered chan struct{}
	release chan struct{}
	claimed atomic.Bool
}

func installScopedClosePause(t *testing.T) *scopedClosePause {
	t.Helper()
	p := &scopedClosePause{entered: make(chan struct{}), release: make(chan struct{})}
	vaultFileChildBeforeHandleClose = func() {
		// Claim only the first closer. A later sibling must return without
		// joining this wait, so a bug that fails to make the parent wait for
		// A cannot be masked by B blocking on the same Once.
		if !p.claimed.CompareAndSwap(false, true) {
			return
		}
		close(p.entered)
		<-p.release
	}
	t.Cleanup(func() { vaultFileChildBeforeHandleClose = nil })
	return p
}

func waitScopedCloseSeam(t *testing.T, p *scopedClosePause) {
	t.Helper()
	select {
	case <-p.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("first child close did not reach the before-handle-close seam")
	}
}

func assertScopedRequestLockImmediate(t *testing.T, s *Session) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		s.RequestLock()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("RequestLock waited for a retiring child")
	}
}

func assertScopedStillBlocked(t *testing.T, done <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-done:
		t.Fatalf("%s returned before the retiring child close completed", what)
	case <-time.After(150 * time.Millisecond):
	}
}

func TestVaultFileChildParentLockWaitsForRetiringClose(t *testing.T) {
	t.Run("lock-child-and-duplicate-close", func(t *testing.T) {
		fx := newScopedChildFixture(t)
		tokenA, _, err := fx.session.OpenVaultFileChild(fx.a.journal, fx.a.checkpoint, fx.password, fx.key, VaultFileChildOptions{})
		if err != nil {
			t.Fatalf("open A: %v", err)
		}
		if _, _, err := fx.session.OpenVaultFileChild(fx.b.journal, fx.b.checkpoint, fx.password, fx.key, VaultFileChildOptions{}); err != nil {
			t.Fatalf("open B: %v", err)
		}
		childA := fx.child(fx.a.journal)
		childB := fx.child(fx.b.journal)
		pause := installScopedClosePause(t)

		// A is the only started close, so it claims the seam first.
		lockA := make(chan error, 1)
		go func() { lockA <- fx.session.LockVaultFileChild(tokenA) }()
		waitScopedCloseSeam(t, pause)

		// A later close must wait on A's real handle.Close, not return on the
		// closed flag.
		duplicate := make(chan struct{})
		duplicateStarted := make(chan struct{})
		go func() {
			close(duplicateStarted)
			childA.close()
			close(duplicate)
		}()
		<-duplicateStarted
		assertScopedStillBlocked(t, duplicate, "duplicate child close")

		// RequestLock must not wait on the blocked child close.
		assertScopedRequestLockImmediate(t, fx.session)

		parentDone := make(chan struct{})
		go func() {
			fx.session.Lock()
			close(parentDone)
		}()
		assertScopedStillBlocked(t, parentDone, "Session.Lock")

		close(pause.release)
		select {
		case err := <-lockA:
			if err != nil {
				t.Fatalf("LockVaultFileChild(A): %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("LockVaultFileChild(A) did not return after release")
		}
		select {
		case <-duplicate:
		case <-time.After(5 * time.Second):
			t.Fatal("duplicate close did not return after release")
		}
		select {
		case <-parentDone:
		case <-time.After(5 * time.Second):
			t.Fatal("Session.Lock did not return after release")
		}
		assertScopedChildHandleClosed(t, childA.handle)
		assertScopedChildHandleClosed(t, childB.handle)
	})

	t.Run("supersession", func(t *testing.T) {
		fx := newScopedChildFixture(t)
		if _, _, err := fx.session.OpenVaultFileChild(fx.a.journal, fx.a.checkpoint, fx.password, fx.key, VaultFileChildOptions{}); err != nil {
			t.Fatalf("open A: %v", err)
		}
		if _, _, err := fx.session.OpenVaultFileChild(fx.b.journal, fx.b.checkpoint, fx.password, fx.key, VaultFileChildOptions{}); err != nil {
			t.Fatalf("open B: %v", err)
		}
		oldChild := fx.child(fx.a.journal)
		childB := fx.child(fx.b.journal)
		pause := installScopedClosePause(t)

		reopen := make(chan error, 1)
		go func() {
			_, _, err := fx.session.OpenVaultFileChild(fx.a.journal, fx.a.checkpoint, fx.password, fx.key, VaultFileChildOptions{})
			reopen <- err
		}()
		waitScopedCloseSeam(t, pause)
		newChild := fx.child(fx.a.journal)
		if newChild == nil || newChild == oldChild {
			t.Fatal("replacement did not publish a new active child")
		}
		assertScopedRequestLockImmediate(t, fx.session)

		parentDone := make(chan struct{})
		go func() {
			fx.session.Lock()
			close(parentDone)
		}()
		assertScopedStillBlocked(t, parentDone, "Session.Lock after supersession")

		close(pause.release)
		select {
		case err := <-reopen:
			if err != nil {
				t.Fatalf("replacement open: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("replacement open did not return after release")
		}
		select {
		case <-parentDone:
		case <-time.After(5 * time.Second):
			t.Fatal("Session.Lock did not return after supersession release")
		}
		assertScopedChildHandleClosed(t, oldChild.handle)
		assertScopedChildHandleClosed(t, newChild.handle)
		assertScopedChildHandleClosed(t, childB.handle)
	})

	t.Run("invalidate", func(t *testing.T) {
		fx := newScopedChildFixture(t)
		tokenA, _, err := fx.session.OpenVaultFileChild(fx.a.journal, fx.a.checkpoint, fx.password, fx.key, VaultFileChildOptions{})
		if err != nil {
			t.Fatalf("open A: %v", err)
		}
		if _, _, err := fx.session.OpenVaultFileChild(fx.b.journal, fx.b.checkpoint, fx.password, fx.key, VaultFileChildOptions{}); err != nil {
			t.Fatalf("open B: %v", err)
		}
		childA := fx.child(fx.a.journal)
		childB := fx.child(fx.b.journal)
		childA.mu.Lock()
		childA.fullFactorDeadline = time.Now().Add(-time.Second)
		childA.mu.Unlock()
		pause := installScopedClosePause(t)

		readA := make(chan error, 1)
		go func() {
			_, err := fx.session.ReadVaultFileChild(tokenA, VaultFileChildOptions{})
			readA <- err
		}()
		waitScopedCloseSeam(t, pause)
		assertScopedRequestLockImmediate(t, fx.session)

		parentDone := make(chan struct{})
		go func() {
			fx.session.Lock()
			close(parentDone)
		}()
		assertScopedStillBlocked(t, parentDone, "Session.Lock after invalidation")

		close(pause.release)
		select {
		case err := <-readA:
			if !errors.Is(err, ErrVaultFileScopedChild) {
				t.Fatalf("expired A read = %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("expired A read did not return after release")
		}
		select {
		case <-parentDone:
		case <-time.After(5 * time.Second):
			t.Fatal("Session.Lock did not return after invalidation release")
		}
		assertScopedChildHandleClosed(t, childA.handle)
		assertScopedChildHandleClosed(t, childB.handle)
	})

	t.Run("parent-drain", func(t *testing.T) {
		fx := newScopedChildFixture(t)
		if _, _, err := fx.session.OpenVaultFileChild(fx.a.journal, fx.a.checkpoint, fx.password, fx.key, VaultFileChildOptions{}); err != nil {
			t.Fatalf("open A: %v", err)
		}
		if _, _, err := fx.session.OpenVaultFileChild(fx.b.journal, fx.b.checkpoint, fx.password, fx.key, VaultFileChildOptions{}); err != nil {
			t.Fatalf("open B: %v", err)
		}
		childA := fx.child(fx.a.journal)
		childB := fx.child(fx.b.journal)
		pause := installScopedClosePause(t)

		parentDone := make(chan struct{})
		go func() {
			fx.session.Lock()
			close(parentDone)
		}()
		waitScopedCloseSeam(t, pause)
		assertScopedRequestLockImmediate(t, fx.session)
		assertScopedStillBlocked(t, parentDone, "Session.Lock during parent drain")

		close(pause.release)
		select {
		case <-parentDone:
		case <-time.After(5 * time.Second):
			t.Fatal("Session.Lock did not return after parent-drain release")
		}
		assertScopedChildHandleClosed(t, childA.handle)
		assertScopedChildHandleClosed(t, childB.handle)
	})
}

func TestVaultFileChildWrongCheckpointRejected(t *testing.T) {
	fx := newScopedChildFixture(t)
	tokenB, _, err := fx.session.OpenVaultFileChild(fx.b.journal, fx.b.checkpoint, fx.password, fx.key, VaultFileChildOptions{})
	if err != nil {
		t.Fatalf("open B: %v", err)
	}
	if _, _, err := fx.session.OpenVaultFileChild(fx.a.journal, fx.b.checkpoint, fx.password, fx.key, VaultFileChildOptions{}); !errors.Is(err, ErrVaultFileBaselineVerification) {
		t.Fatalf("foreign checkpoint = %v", err)
	}
	if _, err := fx.session.ReadVaultFileChild(tokenB, VaultFileChildOptions{}); err != nil {
		t.Fatal("foreign checkpoint invalidated B")
	}
}

func TestVaultFileChildRequestLockArbitratesInFlightRead(t *testing.T) {
	fx := newScopedChildFixture(t)
	tokenA, _, err := fx.session.OpenVaultFileChild(fx.a.journal, fx.a.checkpoint, fx.password, fx.key, VaultFileChildOptions{})
	if err != nil {
		t.Fatalf("open A: %v", err)
	}
	tokenB, _, err := fx.session.OpenVaultFileChild(fx.b.journal, fx.b.checkpoint, fx.password, fx.key, VaultFileChildOptions{})
	if err != nil {
		t.Fatalf("open B: %v", err)
	}
	childA := fx.child(fx.a.journal)
	childB := fx.child(fx.b.journal)
	if childA == nil || childB == nil {
		t.Fatal("children not registered")
	}

	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	vaultFileChildReadHook = func() {
		once.Do(func() { close(entered) })
		<-release
	}
	defer func() { vaultFileChildReadHook = nil }()

	type readResult struct {
		count int
		err   error
	}
	result := make(chan readResult, 1)
	go func() {
		items, err := fx.session.ReadVaultFileChild(tokenA, VaultFileChildOptions{IncludeItemIDs: true})
		result <- readResult{count: len(items), err: err}
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("in-flight read did not reach the seam")
	}

	requested := make(chan struct{})
	go func() {
		fx.session.RequestLock()
		close(requested)
	}()
	select {
	case <-requested:
	case <-time.After(time.Second):
		t.Fatal("RequestLock waited for an in-flight child read")
	}
	if _, err := fx.session.ReadVaultFileChild(tokenB, VaultFileChildOptions{}); !errors.Is(err, ErrSessionLocked) {
		t.Fatalf("post-RequestLock B read = %v", err)
	}

	close(release)
	got := <-result
	if got.err == nil || got.count != 0 {
		t.Fatalf("revoked in-flight read returned count=%d err=%v", got.count, got.err)
	}

	fx.session.Lock()
	if fx.registryLen() != 0 {
		t.Fatal("Lock left scoped children registered")
	}
	assertScopedChildHandleClosed(t, childA.handle)
	assertScopedChildHandleClosed(t, childB.handle)
}

func TestVaultFileChildLockIsolatesInFlightRead(t *testing.T) {
	fx := newScopedChildFixture(t)
	tokenA, _, err := fx.session.OpenVaultFileChild(fx.a.journal, fx.a.checkpoint, fx.password, fx.key, VaultFileChildOptions{})
	if err != nil {
		t.Fatalf("open A: %v", err)
	}
	tokenB, _, err := fx.session.OpenVaultFileChild(fx.b.journal, fx.b.checkpoint, fx.password, fx.key, VaultFileChildOptions{})
	if err != nil {
		t.Fatalf("open B: %v", err)
	}
	childA := fx.child(fx.a.journal)

	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	vaultFileChildReadHook = func() {
		once.Do(func() { close(entered) })
		<-release
	}
	defer func() { vaultFileChildReadHook = nil }()

	type readResult struct {
		count int
		err   error
	}
	result := make(chan readResult, 1)
	go func() {
		items, err := fx.session.ReadVaultFileChild(tokenA, VaultFileChildOptions{})
		result <- readResult{count: len(items), err: err}
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("in-flight read did not reach the seam")
	}

	locked := make(chan error, 1)
	go func() { locked <- fx.session.LockVaultFileChild(tokenA) }()
	select {
	case err := <-locked:
		if err != nil {
			t.Fatalf("LockVaultFileChild: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("LockVaultFileChild waited for an in-flight child read")
	}
	close(release)
	got := <-result
	if got.err == nil || got.count != 0 {
		t.Fatalf("A-locked in-flight read returned count=%d err=%v", got.count, got.err)
	}
	if items, err := fx.session.ReadVaultFileChild(tokenB, VaultFileChildOptions{IncludeItemIDs: true}); err != nil ||
		len(items) != 1 || items[0].ID != fx.b.itemID {
		t.Fatalf("B read after A child lock = %v", err)
	}
	if !fx.session.Unlocked() {
		t.Fatal("A child lock locked the parent account")
	}
	assertScopedChildHandleClosed(t, childA.handle)
}

func TestVaultFileChildParentIdleAndInvalidSlotDrain(t *testing.T) {
	t.Run("idle", func(t *testing.T) {
		fx := newScopedChildFixture(t)
		if _, _, err := fx.session.OpenVaultFileChild(fx.a.journal, fx.a.checkpoint, fx.password, fx.key, VaultFileChildOptions{}); err != nil {
			t.Fatalf("open A: %v", err)
		}
		if _, _, err := fx.session.OpenVaultFileChild(fx.b.journal, fx.b.checkpoint, fx.password, fx.key, VaultFileChildOptions{}); err != nil {
			t.Fatalf("open B: %v", err)
		}
		childA := fx.child(fx.a.journal)
		childB := fx.child(fx.b.journal)
		fx.session.mu.Lock()
		fx.session.last = time.Now().Add(-2 * time.Minute)
		fx.session.idle = time.Minute
		fx.session.mu.Unlock()
		if _, err := fx.session.List("active"); !errors.Is(err, ErrSessionLocked) {
			t.Fatalf("idle session List = %v", err)
		}
		if fx.registryLen() != 0 || fx.session.Unlocked() {
			t.Fatal("idle finalization did not drain children")
		}
		assertScopedChildHandleClosed(t, childA.handle)
		assertScopedChildHandleClosed(t, childB.handle)
	})

	t.Run("invalid-slot", func(t *testing.T) {
		fx := newScopedChildFixture(t)
		if _, _, err := fx.session.OpenVaultFileChild(fx.a.journal, fx.a.checkpoint, fx.password, fx.key, VaultFileChildOptions{}); err != nil {
			t.Fatalf("open A: %v", err)
		}
		if _, _, err := fx.session.OpenVaultFileChild(fx.b.journal, fx.b.checkpoint, fx.password, fx.key, VaultFileChildOptions{}); err != nil {
			t.Fatalf("open B: %v", err)
		}
		childA := fx.child(fx.a.journal)
		childB := fx.child(fx.b.journal)
		db, err := bolt.Open(fx.session.path, 0600, nil)
		if err != nil {
			t.Fatalf("open account db: %v", err)
		}
		err = db.Update(func(tx *bolt.Tx) error {
			return tx.Bucket(bucket).Put(slotKey, []byte("not-a-slot"))
		})
		if closeErr := db.Close(); err != nil || closeErr != nil {
			t.Fatalf("replace slot: %v / %v", err, closeErr)
		}
		if _, _, err := fx.session.OpenVaultFileChild(fx.a.journal, fx.a.checkpoint, fx.password, fx.key, VaultFileChildOptions{}); !errors.Is(err, ErrSessionLocked) {
			t.Fatalf("invalid slot = %v", err)
		}
		if fx.registryLen() != 0 || fx.session.Unlocked() {
			t.Fatal("invalid slot did not follow the parent lock boundary")
		}
		assertScopedChildHandleClosed(t, childA.handle)
		assertScopedChildHandleClosed(t, childB.handle)
	})
}

func TestVaultFileChildExpiryAndJournalDriftArePerChild(t *testing.T) {
	t.Run("expiry", func(t *testing.T) {
		fx := newScopedChildFixture(t)
		tokenA, _, err := fx.session.OpenVaultFileChild(fx.a.journal, fx.a.checkpoint, fx.password, fx.key, VaultFileChildOptions{})
		if err != nil {
			t.Fatalf("open A: %v", err)
		}
		tokenB, _, err := fx.session.OpenVaultFileChild(fx.b.journal, fx.b.checkpoint, fx.password, fx.key, VaultFileChildOptions{})
		if err != nil {
			t.Fatalf("open B: %v", err)
		}
		childA := fx.child(fx.a.journal)
		childA.mu.Lock()
		childA.fullFactorDeadline = time.Now().Add(-time.Second)
		childA.mu.Unlock()
		if _, err := fx.session.ReadVaultFileChild(tokenA, VaultFileChildOptions{}); !errors.Is(err, ErrVaultFileScopedChild) {
			t.Fatalf("expired A read = %v", err)
		}
		if _, err := fx.session.ReadVaultFileChild(tokenB, VaultFileChildOptions{}); err != nil {
			t.Fatal("A expiry invalidated B")
		}
		assertScopedChildHandleClosed(t, childA.handle)
	})

	t.Run("journal-drift", func(t *testing.T) {
		fx := newScopedChildFixture(t)
		tokenA, _, err := fx.session.OpenVaultFileChild(fx.a.journal, fx.a.checkpoint, fx.password, fx.key, VaultFileChildOptions{})
		if err != nil {
			t.Fatalf("open A: %v", err)
		}
		tokenB, _, err := fx.session.OpenVaultFileChild(fx.b.journal, fx.b.checkpoint, fx.password, fx.key, VaultFileChildOptions{})
		if err != nil {
			t.Fatalf("open B: %v", err)
		}
		childA := fx.child(fx.a.journal)
		j, err := vaultfilejournal.OpenExisting(fx.a.journal)
		if err != nil {
			t.Fatalf("reopen A journal: %v", err)
		}
		state, err := j.LoadState()
		if err != nil {
			t.Fatalf("load A state: %v", err)
		}
		err = j.UpdateWorking(0, state.BaseBytes)
		clear(state.BaseBytes)
		clear(state.WorkingBytes)
		if closeErr := j.Close(); err != nil || closeErr != nil {
			t.Fatalf("drift A journal: %v / %v", err, closeErr)
		}
		if _, err := fx.session.ReadVaultFileChild(tokenA, VaultFileChildOptions{}); !errors.Is(err, ErrVaultFileBaselineJournal) {
			t.Fatalf("drifted A read = %v", err)
		}
		if _, err := fx.session.ReadVaultFileChild(tokenB, VaultFileChildOptions{}); err != nil {
			t.Fatal("A journal drift invalidated B")
		}
		assertScopedChildHandleClosed(t, childA.handle)
	})
}

func TestVaultFileChildExplicitFactorsOnQuickOrOldParent(t *testing.T) {
	fx := newScopedChildFixture(t)
	fx.session.mu.Lock()
	fx.session.fullUnlock = time.Time{}
	fx.session.mu.Unlock()
	if _, _, err := fx.session.OpenVaultFileChild(fx.a.journal, fx.a.checkpoint, fx.password, fx.key, VaultFileChildOptions{}); err != nil {
		t.Fatalf("explicit factors on quick-unlock parent: %v", err)
	}
	fx.session.mu.Lock()
	quickStillZero := fx.session.fullUnlock.IsZero()
	fx.session.fullUnlock = time.Now().Add(-passkeyTransferFullFactorWindow)
	fx.session.mu.Unlock()
	if !quickStillZero {
		t.Fatal("explicit child unlock wrote global fullUnlock")
	}
	if _, _, err := fx.session.OpenVaultFileChild(fx.b.journal, fx.b.checkpoint, fx.password, fx.key, VaultFileChildOptions{}); err != nil {
		t.Fatalf("explicit factors on old parent: %v", err)
	}
}
