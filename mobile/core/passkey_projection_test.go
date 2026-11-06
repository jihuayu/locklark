package mobilecore

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/jihuayu/locklark/internal/account"
	"github.com/jihuayu/locklark/internal/passkey"
	"github.com/jihuayu/locklark/internal/personal"
	vaultpkg "github.com/jihuayu/locklark/internal/vault"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/crypto/ssh"
)

const mobilePasskeyChallenge = "Y2hhbGxlbmdlLTAxMjM0NTY3ODk"

type mixedMobilePasskeyVault struct {
	vault      *Vault
	path       string
	accountKey []byte
	login      *Receipt
	standalone *Receipt
	contexts   [2]personal.BrowserContext
	rpIDs      [2]string
	created    [2]passkey.Response
	public     [2]*ecdsa.PublicKey
	private    [2][]byte
	records    [2][]byte
	sshKey     personal.SSHKeyRow
	seed, pem  []byte
	sshPublic  ssh.PublicKey
}

func mobilePasskeyGate(t *testing.T, s *personal.Session) *personal.MutationGate {
	t.Helper()
	g := personal.NewMutationGate(time.Now().Add(time.Minute))
	if err := s.RegisterMutation(g); err != nil {
		t.Fatal("mixed passkey mutation gate failed")
	}
	return g
}

func passkeyFixturePublicKey(t *testing.T, response passkey.Response) *ecdsa.PublicKey {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(response.Response.PublicKey)
	if err != nil {
		t.Fatal("mixed passkey public key decoding failed")
	}
	parsed, err := x509.ParsePKIXPublicKey(raw)
	key, ok := parsed.(*ecdsa.PublicKey)
	if err != nil || !ok || key.Curve != elliptic.P256() {
		t.Fatal("mixed passkey public key is not an ES256 key")
	}
	return key
}

// encryptedPasskeyRecords authenticates the personal store exactly as the
// production read path does and returns the decrypted credential blobs. The
// projection tests need the actual private keys to prove that mobile metadata
// operations never write them unprotected to the sealed database.
func encryptedPasskeyRecords(t *testing.T, path, password string, accountKey []byte) map[string][]byte {
	t.Helper()
	items := encryptedPersonalItems(t, path, password, accountKey)
	records := map[string][]byte{}
	for _, item := range items {
		if item.Kind == "login" && len(item.Passkey) != 0 {
			records[item.ID] = bytes.Clone(item.Passkey)
		}
		clear(item.Passkey)
		clear(item.SSHSeed)
		clear(item.Attachment)
		clear(item.ImportSource)
	}
	return records
}

func encryptedPersonalItems(t *testing.T, path, password string, accountKey []byte) []vaultpkg.Item {
	t.Helper()
	db, err := bolt.Open(path, 0600, &bolt.Options{ReadOnly: true, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal("mixed passkey store open failed")
	}
	var slotRaw, snapshotRaw []byte
	err = db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("locklark.personal/v1"))
		if b == nil {
			return fmt.Errorf("missing personal bucket")
		}
		slotRaw = bytes.Clone(b.Get([]byte("device-slot")))
		snapshotRaw = bytes.Clone(b.Get([]byte("snapshot")))
		return nil
	})
	db.Close()
	if err != nil {
		t.Fatal("mixed passkey store read failed")
	}
	defer clear(slotRaw)
	defer clear(snapshotRaw)
	var slot account.Slot
	if json.Unmarshal(slotRaw, &slot) != nil {
		t.Fatal("mixed passkey device slot decoding failed")
	}
	opened, err := account.Unwrap(password, accountKey, slot)
	if err != nil {
		t.Fatal("mixed passkey device unwrap failed")
	}
	defer clear(opened)
	var identity struct {
		Device                          string
		Signing, Audit, AuditEncryption []byte
	}
	if json.Unmarshal(opened, &identity) != nil || len(identity.Signing) != ed25519.SeedSize {
		t.Fatal("mixed passkey identity decoding failed")
	}
	defer clear(identity.Signing)
	defer clear(identity.Audit)
	defer clear(identity.AuditEncryption)
	device, err := age.ParseX25519Identity(identity.Device)
	if err != nil {
		t.Fatal("mixed passkey age identity failed")
	}
	signer := ed25519.NewKeyFromSeed(identity.Signing)
	defer clear(signer)
	var snapshot vaultpkg.Snapshot
	if json.Unmarshal(snapshotRaw, &snapshot) != nil {
		t.Fatal("mixed passkey snapshot decoding failed")
	}
	_, items, err := vaultpkg.OpenItems(snapshot, device, signer.Public().(ed25519.PublicKey), snapshot.Epoch)
	if err != nil {
		t.Fatal("mixed passkey snapshot authentication failed")
	}
	return items
}

func mixedMobilePasskeyFixture(t *testing.T) *mixedMobilePasskeyVault {
	t.Helper()
	v, path, accountKey := mobileFixture(t)
	login, err := v.CreateLogin("Mixed passkey login", "https://example.test/login", []byte("fixture-user"), []byte("fixture-password"))
	if err != nil {
		t.Fatal("mixed passkey login creation failed")
	}
	contexts := [2]personal.BrowserContext{
		{RequestID: strings.Repeat("3", 32), Origin: "https://example.test", TabID: 1, DocumentID: "doc-1"},
		{RequestID: strings.Repeat("4", 32), Origin: "https://rp2.example.test", TabID: 2, DocumentID: "doc-2"},
	}
	options := [2][]byte{
		[]byte(`{"challenge":"` + mobilePasskeyChallenge + `","rp":{"id":"example.test","name":"Example"},"user":{"id":"dXNlcjE","name":"passkey-user-canary","displayName":"Passkey Display Canary"},"pubKeyCredParams":[{"type":"public-key","alg":-7}],"extensions":{"credProps":true}}`),
		[]byte(`{"challenge":"` + mobilePasskeyChallenge + `","rp":{"id":"rp2.example.test","name":"Second Example"},"user":{"id":"dXNlcjI","name":"standalone-passkey-canary","displayName":"Standalone Display Canary"},"pubKeyCredParams":[{"type":"public-key","alg":-7}]}`),
	}
	session, err := personal.UnlockSession(path, []byte("mobile-fixture"), bytes.Clone(accountKey), time.Minute)
	if err != nil {
		t.Fatal("mixed passkey personal unlock failed")
	}
	defer session.Lock()
	var created [2]passkey.Response
	created[0], err = session.PerformPasskey(personal.PasskeyTarget{Context: contexts[0], Create: true, ID: login.ID, Revision: login.Revision, Options: options[0]}, false, mobilePasskeyGate(t, session))
	if err != nil {
		t.Fatal("mixed attached passkey creation failed")
	}
	created[1], err = session.PerformPasskey(personal.PasskeyTarget{Context: contexts[1], Create: true, Options: options[1]}, false, mobilePasskeyGate(t, session))
	if err != nil {
		t.Fatal("mixed standalone passkey creation failed")
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal("mixed passkey SSH seed fixture failed")
	}
	t.Cleanup(func() { clear(seed) })
	private := ed25519.NewKeyFromSeed(seed)
	defer clear(private)
	public, err := ssh.NewPublicKey(private.Public())
	if err != nil {
		t.Fatal("mixed passkey SSH public fixture failed")
	}
	block, err := ssh.MarshalPrivateKey(private, "")
	if err != nil {
		t.Fatal("mixed passkey SSH import fixture failed")
	}
	defer clear(block.Bytes)
	encoded := pem.EncodeToMemory(block)
	t.Cleanup(func() { clear(encoded) })
	imported := bytes.Clone(encoded)
	sshKey, err := session.ImportSSHKey("Mixed passkey SSH key", imported, mobilePasskeyGate(t, session))
	if err != nil || !bytes.Equal(imported, make([]byte, len(imported))) {
		t.Fatal("mixed passkey SSH import failed or retained its input")
	}
	rows, err := session.List("all")
	if err != nil || len(rows) != 3 {
		t.Fatal("mixed passkey vault fixture did not persist all three item shapes")
	}
	var loginRow, standaloneRow personal.Row
	for _, row := range rows {
		switch {
		case row.ID == login.ID:
			loginRow = row
		case row.Kind == "login" && row.Title == "rp2.example.test · standalone-passkey-canary":
			standaloneRow = row
		}
	}
	if loginRow.ID == "" || standaloneRow.ID == "" {
		t.Fatal("mixed passkey vault fixture item identities differ")
	}
	f := &mixedMobilePasskeyVault{
		vault: v, path: path, accountKey: accountKey,
		login:      &Receipt{ID: loginRow.ID, Revision: loginRow.Revision},
		standalone: &Receipt{ID: standaloneRow.ID, Revision: standaloneRow.Revision},
		contexts:   contexts, rpIDs: [2]string{"example.test", "rp2.example.test"},
		created: created, sshKey: sshKey, seed: seed, pem: encoded, sshPublic: public,
	}
	f.public[0] = passkeyFixturePublicKey(t, created[0])
	f.public[1] = passkeyFixturePublicKey(t, created[1])
	records := encryptedPasskeyRecords(t, path, "mobile-fixture", accountKey)
	for i, id := range []string{f.login.ID, f.standalone.ID} {
		raw := records[id]
		if len(raw) == 0 {
			t.Fatal("mixed passkey credential missing from sealed snapshot")
		}
		record, err := passkey.Load(raw)
		if err != nil || record.ID != created[i].ID {
			t.Fatal("mixed passkey credential does not match its creation response")
		}
		f.private[i] = bytes.Clone(record.PrivateKey)
		f.records[i] = bytes.Clone(raw)
		record.Clear()
		clear(records[id])
	}
	t.Cleanup(func() {
		for i := range f.private {
			clear(f.private[i])
			clear(f.records[i])
		}
	})
	return f
}

func requireNoPasskeyDisclosure(t *testing.T, value *SecretValue, err error) {
	t.Helper()
	if value != nil {
		raw, _ := value.Take()
		clear(raw)
		value.Clear()
		t.Fatal("passkey target returned a mobile disclosure handle")
	}
	if err == nil {
		t.Fatal("passkey target did not refuse mobile disclosure")
	}
}

func (f *mixedMobilePasskeyVault) active(t *testing.T) {
	t.Helper()
	if !f.vault.IsUnlocked() {
		f.vault.Lock()
		if f.vault.Unlock([]byte("mobile-fixture"), bytes.Clone(f.accountKey)) != nil {
			t.Fatal("mixed passkey reauthentication failed")
		}
	}
	rows, err := f.vault.List("active")
	if err != nil || rows.Count() != 2 || !f.vault.IsUnlocked() {
		t.Fatal("mixed passkey login was not active before target request")
	}
	found := map[string]string{}
	for i := 0; i < rows.Count(); i++ {
		row, err := rows.At(i)
		if err != nil {
			t.Fatal("mixed passkey active row failed")
		}
		found[row.ID] = row.Revision
	}
	if f.login == nil || found[f.login.ID] != f.login.Revision || f.standalone == nil || found[f.standalone.ID] != f.standalone.Revision {
		t.Fatal("mixed passkey target revision changed unexpectedly")
	}
}

func (f *mixedMobilePasskeyVault) verifyPasskey(t *testing.T, session *personal.Session, index int) {
	t.Helper()
	receipt := f.login
	if index == 1 {
		receipt = f.standalone
	}
	target := personal.PasskeyTarget{Context: f.contexts[index], Options: []byte(`{"rpId":"` + f.rpIDs[index] + `","challenge":"` + mobilePasskeyChallenge + `","allowCredentials":[{"type":"public-key","id":"` + f.created[index].ID + `"}]}`)}
	choices, err := session.ReviewPasskey(target)
	if err != nil || len(choices) != 1 || choices[0].ID != receipt.ID || choices[0].Revision != receipt.Revision {
		t.Fatal("preserved passkey was not discoverable at the post-mobile-edit revision", err)
	}
	target.ID, target.Revision = choices[0].ID, choices[0].Revision
	signed, err := session.PerformPasskey(target, false, mobilePasskeyGate(t, session))
	if err != nil || signed.ID != f.created[index].ID {
		t.Fatal("preserved passkey could not sign after mobile edits", err)
	}
	authData, err := base64.RawURLEncoding.DecodeString(signed.Response.AuthenticatorData)
	if err != nil {
		t.Fatal("preserved passkey authenticator data decoding failed")
	}
	clientData, err := base64.RawURLEncoding.DecodeString(signed.Response.ClientDataJSON)
	if err != nil {
		t.Fatal("preserved passkey client data decoding failed")
	}
	signature, err := base64.RawURLEncoding.DecodeString(signed.Response.Signature)
	if err != nil {
		t.Fatal("preserved passkey signature decoding failed")
	}
	var client struct {
		Type, Challenge, Origin string
	}
	if json.Unmarshal(clientData, &client) != nil || client.Type != "webauthn.get" || client.Challenge != mobilePasskeyChallenge || client.Origin != f.contexts[index].Origin {
		t.Fatal("preserved passkey assertion was bound to different browser data")
	}
	rpHash := sha256.Sum256([]byte(f.rpIDs[index]))
	if len(authData) < sha256.Size || !bytes.Equal(authData[:sha256.Size], rpHash[:]) {
		t.Fatal("preserved passkey assertion was bound to a different relying party")
	}
	clientHash := sha256.Sum256(clientData)
	message := append(bytes.Clone(authData), clientHash[:]...)
	digest := sha256.Sum256(message)
	if !ecdsa.VerifyASN1(f.public[index], digest[:], signature) {
		t.Fatal("preserved passkey ES256 assertion did not verify")
	}
}

func (f *mixedMobilePasskeyVault) verifyStored(t *testing.T) {
	t.Helper()
	f.vault.Lock()
	raw, err := os.ReadFile(f.path)
	if err != nil {
		t.Fatal("mixed passkey encrypted store read failed")
	}
	needles := [][]byte{}
	for i := range f.private {
		base64Key := make([]byte, base64.StdEncoding.EncodedLen(len(f.private[i])))
		base64.StdEncoding.Encode(base64Key, f.private[i])
		hexKey := make([]byte, hex.EncodedLen(len(f.private[i])))
		hex.Encode(hexKey, f.private[i])
		needles = append(needles, f.private[i], base64Key, hexKey, f.records[i])
	}
	base64Seed := make([]byte, base64.StdEncoding.EncodedLen(len(f.seed)))
	base64.StdEncoding.Encode(base64Seed, f.seed)
	hexSeed := make([]byte, hex.EncodedLen(len(f.seed)))
	hex.Encode(hexSeed, f.seed)
	needles = append(needles, f.seed, base64Seed, hexSeed, f.pem)
	for _, needle := range needles {
		if len(needle) != 0 && bytes.Contains(raw, needle) {
			clear(raw)
			t.Fatal("mixed encrypted store contains unprotected passkey or SSH key material")
		}
	}
	clear(raw)
	session, err := personal.UnlockSession(f.path, []byte("mobile-fixture"), bytes.Clone(f.accountKey), time.Minute)
	if err != nil {
		t.Fatal("mixed passkey stored reopen failed")
	}
	defer session.Lock()
	rows, err := session.List("all")
	if err != nil || len(rows) != 3 {
		t.Fatal("mixed passkey mobile edits changed the item set")
	}
	revisions := map[string]string{}
	for _, row := range rows {
		revisions[row.ID] = row.Revision
	}
	if revisions[f.login.ID] != f.login.Revision || revisions[f.standalone.ID] != f.standalone.Revision {
		t.Fatal("mixed passkey mobile edits did not persist the latest revisions")
	}
	keys, err := session.ListSSHKeys()
	if err != nil || len(keys) != 1 || keys[0] != f.sshKey {
		t.Fatal("mixed passkey mobile edits changed the stored SSH identity or revision")
	}
	message := []byte("mixed passkey vault SSH preservation challenge")
	request := personal.SSHSignRequest{RequestID: strings.Repeat("1", 32), ConnectionID: strings.Repeat("2", 32),
		Peer: "unit-test explicit personal approval", PublicKey: f.sshPublic.Marshal(), Data: bytes.Clone(message)}
	defer clear(request.Data)
	intent, err := session.PrepareSSHSign(personal.SSHKeyTarget{ID: f.sshKey.ID, Revision: f.sshKey.Revision}, request, time.Now().Add(personal.SSHSignLifetime))
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
	if err != nil || ssh.Unmarshal(wire, &signature) != nil || signature.Format != ssh.KeyAlgoED25519 || f.sshPublic.Verify(message, &signature) != nil {
		t.Fatal("mobile passkey operations did not preserve the imported SSH key")
	}
	f.verifyPasskey(t, session, 0)
	f.verifyPasskey(t, session, 1)
}

func TestMobilePasskeyMetadataAndFieldBoundariesRefusePasskeyDisclosure(t *testing.T) {
	f := mixedMobilePasskeyFixture(t)
	for _, state := range []string{"active", "all"} {
		f.active(t)
		rows, err := f.vault.List(state)
		if err != nil || rows.Count() != 2 {
			t.Fatal("mixed passkey list exposed an SSH row or lost a login")
		}
		seen := map[string]bool{}
		for i := 0; i < rows.Count(); i++ {
			row, err := rows.At(i)
			if err != nil {
				t.Fatal("mixed passkey list row failed")
			}
			seen[row.ID] = true
			encoded, err := json.Marshal(row)
			if err != nil {
				t.Fatal("mixed passkey row serialization failed")
			}
			// The standalone login title intentionally derives from the browser
			// account name, so only credential-only canaries must be absent here.
			for _, canary := range []string{"passkey-user-canary", "Passkey Display Canary", "dXNlcjE", "dXNlcjI", f.created[0].ID, f.created[1].ID} {
				if bytes.Contains(encoded, []byte(canary)) {
					t.Fatal("mixed passkey metadata row leaked credential material")
				}
			}
		}
		if !seen[f.login.ID] || !seen[f.standalone.ID] || seen[f.sshKey.ID] {
			t.Fatal("mixed passkey metadata identities differ")
		}
		encoded, err := json.Marshal(rows)
		if err != nil {
			t.Fatal("mixed passkey rows serialization failed")
		}
		for _, canary := range []string{"passkey-user-canary", "Passkey Display Canary", "dXNlcjE", "dXNlcjI", f.created[0].ID, f.created[1].ID} {
			if bytes.Contains(encoded, []byte(canary)) {
				t.Fatal("mixed passkey rows leaked credential material")
			}
		}
	}
	for _, receipt := range []*Receipt{f.login, f.standalone} {
		encoded, err := json.Marshal(receipt)
		if err != nil {
			t.Fatal("mixed passkey receipt serialization failed")
		}
		for _, canary := range []string{"passkey-user-canary", "Passkey Display Canary", "standalone-passkey-canary", "dXNlcjE", "dXNlcjI", f.created[0].ID, f.created[1].ID} {
			if bytes.Contains(encoded, []byte(canary)) {
				t.Fatal("mixed passkey receipt leaked credential material")
			}
		}
	}
	for _, query := range []string{"passkey-user-canary", "dXNlcjE", f.created[0].ID} {
		f.active(t)
		rows, err := f.vault.Search(query, "all")
		if err != nil || rows.Count() != 0 {
			t.Fatal("mixed passkey search inspected credential-only fields")
		}
	}
	for _, field := range []string{"passkey", "private_key", "Locklark.Passkey", "credential"} {
		f.active(t)
		value, err := f.vault.RevealField(f.login.ID, f.login.Revision, field)
		requireNoPasskeyDisclosure(t, value, err)
		f.active(t)
		buf := []byte("forbidden passkey update")
		receipt, err := f.vault.EditField(f.login.ID, f.login.Revision, field, buf)
		if err == nil || receipt != nil || !bytes.Equal(buf, make([]byte, len(buf))) {
			t.Fatal("passkey field accepted a mobile edit or retained its input")
		}
	}
	f.active(t)
	secret, err := f.vault.RevealField(f.standalone.ID, f.standalone.Revision, "password")
	if err != nil || secret == nil {
		t.Fatal("standalone passkey login empty password disclosure failed")
	}
	password, err := secret.Take()
	defer clear(password)
	if err != nil || len(password) != 0 {
		t.Fatal("standalone passkey login disclosed unexpected password bytes")
	}
	for i := range f.records {
		if bytes.Contains(password, f.records[i]) || bytes.Contains(password, f.private[i]) {
			t.Fatal("standalone passkey login disclosed credential material as a password")
		}
	}
	f.verifyStored(t)
}

func TestMobileLoginEditsPreserveActualEncryptedPasskeysAndSSHKey(t *testing.T) {
	f := mixedMobilePasskeyFixture(t)
	for _, field := range []string{"title", "url", "username", "password", "notes", "otp"} {
		f.active(t)
		value := []byte("updated mixed passkey field")
		switch field {
		case "title":
			value = []byte("Updated mixed passkey login")
		case "url":
			value = []byte("https://example.test/changed")
		case "username":
			value = []byte("updated-fixture-user")
		case "password":
			value = []byte("updated-fixture-password")
		case "notes":
			value = []byte("updated mixed passkey notes")
		case "otp":
			value = []byte("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP")
		}
		next, err := f.vault.EditField(f.login.ID, f.login.Revision, field, value)
		if err != nil || next == nil || next.ID != f.login.ID || next.Revision == f.login.Revision || !bytes.Equal(value, make([]byte, len(value))) {
			t.Fatal("mixed passkey login edit did not persist exactly or retained its input")
		}
		f.login = next
	}
	f.active(t)
	next, err := f.vault.RegeneratePassword(f.login.ID, f.login.Revision, 24)
	if err != nil || next == nil || next.ID != f.login.ID || next.Length != 24 || next.Revision == f.login.Revision {
		t.Fatal("mixed passkey login password regeneration failed")
	}
	f.login = next
	f.active(t)
	secret, err := f.vault.RevealField(f.login.ID, f.login.Revision, "password")
	if err != nil || secret == nil {
		t.Fatal("mixed passkey login disclosure failed")
	}
	password, err := secret.Take()
	if err != nil || len(password) != 24 {
		clear(password)
		t.Fatal("mixed passkey login regenerated value was not usable")
	}
	clear(password)
	f.active(t)
	next, err = f.vault.EditField(f.standalone.ID, f.standalone.Revision, "notes", []byte("standalone mobile notes"))
	if err != nil || next == nil || next.ID != f.standalone.ID || next.Revision == f.standalone.Revision {
		t.Fatal("standalone passkey login notes edit failed")
	}
	f.standalone = next
	f.active(t)
	// Twenty alphanumeric characters fall below the 128-bit policy floor, so
	// use the smallest length that still satisfies the production generator.
	next, err = f.vault.RegeneratePassword(f.standalone.ID, f.standalone.Revision, 22)
	if err != nil || next == nil || next.ID != f.standalone.ID || next.Length != 22 || next.Revision == f.standalone.Revision {
		t.Fatal("standalone passkey login password regeneration failed")
	}
	f.standalone = next
	f.active(t)
	secret, err = f.vault.RevealField(f.standalone.ID, f.standalone.Revision, "password")
	if err != nil || secret == nil {
		t.Fatal("standalone passkey login regenerated disclosure failed")
	}
	password, err = secret.Take()
	if err != nil || len(password) != 22 {
		clear(password)
		t.Fatal("standalone passkey login regenerated value was not usable")
	}
	clear(password)
	f.verifyStored(t)
}
