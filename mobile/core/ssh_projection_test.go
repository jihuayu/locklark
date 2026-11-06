package mobilecore

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
	"golang.org/x/crypto/ssh"
)

func TestLegacyMobileLoginProjectionExcludesSSHKeys(t *testing.T) {
	rows := rowsResult([]personal.Row{{Kind: "login", ID: "login"}, {Kind: "ssh-key", ID: "ssh"}, {Kind: "document", ID: "document"}})
	if rows.Count() != 2 {
		t.Fatal("SSH key leaked into legacy mobile login controls")
	}
	for i := 0; i < rows.Count(); i++ {
		r, e := rows.At(i)
		if e != nil || r.ID == "ssh" {
			t.Fatal("SSH projection was not excluded")
		}
	}
}

type mixedMobileSSHVault struct {
	vault      *Vault
	path       string
	accountKey []byte
	login      *Receipt
	key        personal.SSHKeyRow
	seed, pem  []byte
	public     ssh.PublicKey
}

func mixedMobileSSHFixture(t *testing.T) *mixedMobileSSHVault {
	t.Helper()
	v, path, accountKey := mobileFixture(t)
	login, err := v.CreateLogin("Mixed boundary login", "https://example.test", []byte("fixture-user"), []byte("fixture-password"))
	if err != nil {
		t.Fatal("mixed login creation failed")
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal("mixed key fixture failed")
	}
	t.Cleanup(func() { clear(seed) })
	private := ed25519.NewKeyFromSeed(seed)
	defer clear(private)
	public, err := ssh.NewPublicKey(private.Public())
	if err != nil {
		t.Fatal("mixed public fixture failed")
	}
	block, err := ssh.MarshalPrivateKey(private, "")
	if err != nil {
		t.Fatal("mixed import fixture failed")
	}
	defer clear(block.Bytes)
	encoded := pem.EncodeToMemory(block)
	t.Cleanup(func() { clear(encoded) })
	session, err := personal.UnlockSession(path, []byte("mobile-fixture"), bytes.Clone(accountKey), time.Minute)
	if err != nil {
		t.Fatal("mixed personal unlock failed")
	}
	defer session.Lock()
	gate := personal.NewMutationGate(time.Now().Add(30 * time.Second))
	defer gate.Cancel()
	defer session.ReleaseMutation(gate)
	if session.RegisterMutation(gate) != nil {
		t.Fatal("mixed import gate failed")
	}
	imported := bytes.Clone(encoded)
	row, err := session.ImportSSHKey("Mixed boundary SSH key", imported, gate)
	if err != nil || !bytes.Equal(imported, make([]byte, len(imported))) {
		t.Fatal("mixed key import failed or retained its input")
	}
	rows, err := session.List("all")
	if err != nil || len(rows) != 2 {
		t.Fatal("mixed vault fixture did not persist both item kinds")
	}
	kinds := map[string]string{}
	for _, item := range rows {
		kinds[item.ID] = item.Kind
	}
	if kinds[login.ID] != "login" || kinds[row.ID] != "ssh-key" {
		t.Fatal("mixed vault fixture item kinds differ")
	}
	return &mixedMobileSSHVault{v, path, accountKey, login, row, seed, encoded, public}
}

// A refusal may fail closed and lock the underlying session. Establish a fresh
// authenticated login view before every negative request so later cases never
// pass merely because an earlier refusal left the vault locked.
func (f *mixedMobileSSHVault) activeLogin(t *testing.T) {
	t.Helper()
	if !f.vault.IsUnlocked() {
		f.vault.Lock()
		if f.vault.Unlock([]byte("mobile-fixture"), bytes.Clone(f.accountKey)) != nil {
			t.Fatal("mixed login reauthentication failed")
		}
	}
	rows, err := f.vault.List("active")
	if err != nil || rows.Count() != 1 || !f.vault.IsUnlocked() {
		t.Fatal("mixed login was not active before target request")
	}
	row, err := rows.At(0)
	if err != nil || row.ID != f.login.ID || row.Revision != f.login.Revision {
		t.Fatal("mixed login target changed unexpectedly")
	}
}

func requireNoSSHDisclosure(t *testing.T, value *SecretValue, err error) {
	t.Helper()
	if value != nil {
		// An unexpected handle is a failure even if its subsequent Take refuses;
		// actually exercise Take so a late read cannot hide behind metadata.
		raw, _ := value.Take()
		clear(raw)
		value.Clear()
		t.Fatal("SSH target returned a mobile disclosure handle")
	}
	if err == nil {
		t.Fatal("SSH target did not refuse mobile disclosure")
	}
}

func (f *mixedMobileSSHVault) verifyStoredSSHKey(t *testing.T) {
	t.Helper()
	f.vault.Lock()
	raw, err := os.ReadFile(f.path)
	if err != nil {
		t.Fatal("mixed encrypted store read failed")
	}
	base64Seed := make([]byte, base64.StdEncoding.EncodedLen(len(f.seed)))
	base64.StdEncoding.Encode(base64Seed, f.seed)
	defer clear(base64Seed)
	hexSeed := make([]byte, hex.EncodedLen(len(f.seed)))
	hex.Encode(hexSeed, f.seed)
	defer clear(hexSeed)
	if bytes.Contains(raw, f.seed) || bytes.Contains(raw, base64Seed) || bytes.Contains(raw, hexSeed) || bytes.Contains(raw, f.pem) {
		clear(raw)
		t.Fatal("mixed encrypted store contains unprotected key material")
	}
	clear(raw)
	session, err := personal.UnlockSession(f.path, []byte("mobile-fixture"), bytes.Clone(f.accountKey), time.Minute)
	if err != nil {
		t.Fatal("mixed stored key reopen failed")
	}
	defer session.Lock()
	rows, err := session.ListSSHKeys()
	if err != nil || len(rows) != 1 || rows[0] != f.key {
		t.Fatal("mobile login operation changed the stored SSH identity or revision")
	}
	message := []byte("mixed vault key preservation challenge")
	request := personal.SSHSignRequest{RequestID: strings.Repeat("1", 32), ConnectionID: strings.Repeat("2", 32),
		Peer: "unit-test explicit personal approval", PublicKey: f.public.Marshal(), Data: bytes.Clone(message)}
	defer clear(request.Data)
	intent, err := session.PrepareSSHSign(personal.SSHKeyTarget{ID: f.key.ID, Revision: f.key.Revision}, request, time.Now().Add(personal.SSHSignLifetime))
	if err != nil {
		t.Fatal("preserved SSH key preparation failed")
	}
	defer session.DiscardSSHSign(intent)
	output, err := session.ApproveSSHSign(intent)
	if err != nil {
		t.Fatal("preserved SSH key explicit approval failed")
	}
	defer session.DiscardSSHSignature(output)
	wire, err := session.ConsumeSSHSignature(output)
	defer clear(wire)
	var signature ssh.Signature
	if err != nil || ssh.Unmarshal(wire, &signature) != nil || signature.Format != ssh.KeyAlgoED25519 || f.public.Verify(message, &signature) != nil {
		t.Fatal("mobile operations did not preserve the imported SSH key")
	}
}

func TestMobileMixedVaultHidesSSHAndRefusesLoginAPIs(t *testing.T) {
	f := mixedMobileSSHFixture(t)
	for _, state := range []string{"active", "all"} {
		f.activeLogin(t)
		rows, err := f.vault.Search("Mixed boundary", state)
		if err != nil || rows.Count() != 1 {
			t.Fatal("mixed title search exposed SSH metadata or lost the login")
		}
		row, err := rows.At(0)
		if err != nil || row.ID != f.login.ID {
			t.Fatal("mixed title search returned the SSH target")
		}
		rows, err = f.vault.Search("Mixed boundary SSH key", state)
		if err != nil || rows.Count() != 0 {
			t.Fatal("SSH-only title search exposed a mobile row")
		}
		rows, err = f.vault.List(state)
		if err != nil || rows.Count() != 1 {
			t.Fatal("mixed list exposed SSH metadata or lost the login")
		}
		row, err = rows.At(0)
		if err != nil || row.ID != f.login.ID || row.Revision != f.login.Revision {
			t.Fatal("mixed list returned the SSH target or a different login revision")
		}
	}
	for _, field := range []string{"username", "password", "notes"} {
		f.activeLogin(t)
		value, err := f.vault.RevealField(f.key.ID, f.key.Revision, field)
		requireNoSSHDisclosure(t, value, err)
		f.activeLogin(t)
	}
	f.activeLogin(t)
	value, err := f.vault.RevealOTP(f.key.ID, f.key.Revision)
	requireNoSSHDisclosure(t, value, err)
	f.activeLogin(t)
	for _, field := range []string{"title", "url", "username", "password", "notes", "otp"} {
		f.activeLogin(t)
		value := []byte("valid fixture update")
		if field == "url" {
			value = []byte("https://changed.example.test")
		}
		if field == "otp" {
			value = []byte("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP")
		}
		receipt, err := f.vault.EditField(f.key.ID, f.key.Revision, field, value)
		if err == nil || receipt != nil || !bytes.Equal(value, make([]byte, len(value))) {
			t.Fatal("SSH target accepted a mobile field edit or retained its input")
		}
		f.activeLogin(t)
	}
	f.activeLogin(t)
	receipt, err := f.vault.RegeneratePassword(f.key.ID, f.key.Revision, 24)
	if err == nil || receipt != nil {
		t.Fatal("SSH target accepted mobile password regeneration")
	}
	f.activeLogin(t)
	f.verifyStoredSSHKey(t)
}

func TestMobileLoginEditsPreserveActualEncryptedSSHKey(t *testing.T) {
	f := mixedMobileSSHFixture(t)
	for _, field := range []string{"title", "url", "username", "password", "notes", "otp"} {
		f.activeLogin(t)
		value := []byte("updated login fixture")
		if field == "url" {
			value = []byte("https://changed.example.test")
		}
		if field == "otp" {
			value = []byte("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP")
		}
		next, err := f.vault.EditField(f.login.ID, f.login.Revision, field, value)
		if err != nil || next == nil || next.ID != f.login.ID || next.Revision == f.login.Revision || !bytes.Equal(value, make([]byte, len(value))) {
			t.Fatal("mixed login edit did not persist exactly or retained its input")
		}
		f.login = next
	}
	next, err := f.vault.RegeneratePassword(f.login.ID, f.login.Revision, 24)
	if err != nil || next == nil || next.ID != f.login.ID || next.Length != 24 || next.Revision == f.login.Revision {
		t.Fatal("mixed login password regeneration failed")
	}
	f.login = next
	f.activeLogin(t)
	secret, err := f.vault.RevealField(f.login.ID, f.login.Revision, "password")
	if err != nil || secret == nil {
		t.Fatal("mixed login disclosure failed")
	}
	password, err := secret.Take()
	defer clear(password)
	if err != nil || len(password) != 24 {
		t.Fatal("mixed login regenerated value was not usable")
	}
	f.verifyStoredSSHKey(t)
}
