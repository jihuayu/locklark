package personal

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/vault"
	"golang.org/x/crypto/ssh"
)

func TestSSHImportGenerationIdentityAndBackupRestore(t *testing.T) {
	s, key, generated := sshFixture(t)
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{61}, 32))
	defer clear(private)
	block, e := ssh.MarshalPrivateKey(private, "")
	if e != nil {
		t.Fatal("SSH import fixture")
	}
	input := pem.EncodeToMemory(block)
	inputRef := input
	g := NewMutationGate(time.Now().Add(time.Minute))
	if s.RegisterMutation(g) != nil {
		t.Fatal("SSH import gate")
	}
	imported, e := s.ImportSSHKey("Imported key", input, g)
	if e != nil {
		t.Fatal("SSH import", e)
	}
	if !bytes.Equal(inputRef, make([]byte, len(inputRef))) {
		t.Fatal("SSH import input not consumed")
	}
	if imported.ID == generated.ID || imported.PublicKey == generated.PublicKey {
		t.Fatal("SSH keys reused")
	}
	items := readStoredItems(t, s.path, "fixture", key)
	var identity identity
	if json.Unmarshal(s.material, &identity) != nil {
		t.Fatal("personal identity")
	}
	defer identity.clear()
	var created, known vault.Item
	for _, item := range items {
		if item.ID == generated.ID {
			created = item
		}
		if item.ID == imported.ID {
			known = item
		}
	}
	if len(created.SSHSeed) != 32 || bytes.Equal(created.SSHSeed, identity.Signing) || bytes.Equal(created.SSHSeed, identity.Audit) || bytes.Equal(created.SSHSeed, identity.AuditEncryption) {
		t.Fatal("SSH seed was not independent")
	}
	if !bytes.Equal(known.SSHSeed, private[:32]) {
		t.Fatal("SSH import changed seed")
	}
	archive := filepath.Join(t.TempDir(), "backup.llb")
	kit, e := Backup(s.path, archive, "fixture", key)
	if e != nil {
		t.Fatal("SSH backup", e)
	}
	fresh, e := NewSecret()
	if e != nil {
		t.Fatal("fresh factor")
	}
	defer clear(fresh)
	dest := filepath.Join(t.TempDir(), "restored.ll")
	if Restore(archive, dest, "fixture", key, kit, fresh) != nil {
		t.Fatal("SSH restore")
	}
	restored, e := UnlockSession(dest, []byte("fixture"), fresh, time.Minute)
	if e != nil {
		t.Fatal("SSH restored unlock")
	}
	defer restored.Lock()
	rows, e := restored.ListSSHKeys()
	if e != nil || len(rows) != 2 {
		t.Fatal("SSH restored metadata")
	}
	var row SSHKeyRow
	for _, r := range rows {
		if r.ID == imported.ID {
			row = r
		}
	}
	if row.PublicKey != imported.PublicKey || row.Fingerprint != imported.Fingerprint {
		t.Fatal("SSH backup changed public identity")
	}
	i := preparedSSH(t, restored, row)
	o, e := restored.ApproveSSHSign(i)
	if e != nil {
		t.Fatal("restored SSH approval")
	}
	wire, e := restored.ConsumeSSHSignature(o)
	defer clear(wire)
	if e != nil {
		t.Fatal("restored SSH signature")
	}
	var signature ssh.Signature
	if ssh.Unmarshal(wire, &signature) != nil {
		t.Fatal("restored signature format")
	}
	public, _ := ssh.NewPublicKey(private.Public())
	if public.Verify([]byte("exact SSH client message"), &signature) != nil {
		t.Fatal("restored key cannot sign")
	}
}

func TestSSHMetadataAndOtherCapabilitiesNeverExposeSeed(t *testing.T) {
	s, key, row := sshFixture(t)
	items := readStoredItems(t, s.path, "fixture", key)
	var seed []byte
	for _, it := range items {
		if it.ID == row.ID {
			seed = it.SSHSeed
		}
	}
	if len(seed) != 32 {
		t.Fatal("SSH seed fixture")
	}
	rows, e := s.List("all")
	if e != nil {
		t.Fatal("ordinary metadata")
	}
	keys, e := s.ListSSHKeys()
	if e != nil {
		t.Fatal("SSH metadata")
	}
	refs, e := References(s.path, "fixture", key)
	if e != nil {
		t.Fatal("SSH reference projection", e)
	}
	report, e := s.Health()
	if e != nil {
		t.Fatal("SSH health projection")
	}
	raw, e := json.Marshal([]any{rows, keys, refs, report})
	if e != nil {
		t.Fatal("metadata JSON")
	}
	if bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString(seed))) || bytes.Contains(raw, []byte("SSHSeed")) {
		t.Fatal("seed leaked into metadata")
	}
	for _, field := range []string{"SSHSeed", "ssh", "private-key", "seed"} {
		if ValidRevealTarget(row.ID, row.Revision, field) {
			t.Fatal("shared field scope expanded")
		}
	}
	if _, e = s.Search("Signing key", "all"); e != nil {
		t.Fatal("search of other item category")
	}
	if _, e = RevealLogin(s.path, "fixture", key, RevealTarget{row.ID, row.Revision, "password"}, &bytes.Buffer{}); e == nil {
		t.Fatal("SSH key treated as login password")
	}
	// A lifecycle mutation uses the existing exact-revision signed journal.
	rev, e := s.SetState(row.ID, row.Revision, "item.trash")
	if e != nil {
		t.Fatal("SSH trash", e)
	}
	if keys, e = s.ListSSHKeys(); e != nil || len(keys) != 0 {
		t.Fatal("trashed key exposed")
	}
	if _, e = s.SetState(row.ID, rev, "item.untrash"); e != nil {
		t.Fatal("SSH restore from trash")
	}
	if keys, e = s.ListSSHKeys(); e != nil || len(keys) != 1 {
		t.Fatal("SSH restored key missing")
	}
}

func TestSSHCreationCancellationAndInvalidImportClearInput(t *testing.T) {
	s, _, _ := sshFixture(t)
	g := NewMutationGate(time.Now().Add(time.Minute))
	if s.RegisterMutation(g) != nil {
		t.Fatal("SSH cancellation gate")
	}
	g.Cancel()
	if row, e := s.GenerateSSHKey("must not exist", g); e == nil || row != (SSHKeyRow{}) {
		t.Fatal("cancelled generation committed")
	}
	before, e := s.ListSSHKeys()
	if e != nil {
		t.Fatal("SSH list after cancel")
	}
	input := []byte(strings.Repeat("secret invalid key", 10))
	reference := input
	g = NewMutationGate(time.Now().Add(time.Minute))
	if s.RegisterMutation(g) != nil {
		t.Fatal("invalid import gate")
	}
	if row, e := s.ImportSSHKey("bad", input, g); !errors.Is(e, ErrSSHKey) || row != (SSHKeyRow{}) {
		t.Fatal("invalid SSH input accepted")
	}
	if !bytes.Equal(reference, make([]byte, len(reference))) {
		t.Fatal("failed import input not cleared")
	}
	after, e := s.ListSSHKeys()
	if e != nil || len(after) != len(before) {
		t.Fatal("failed generation/import changed keys")
	}
}
