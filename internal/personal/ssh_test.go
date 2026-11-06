package personal

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func sshFixture(t *testing.T) (*Session, []byte, SSHKeyRow) {
	t.Helper()
	path, key, _ := revealFixture(t)
	s, e := UnlockSession(path, []byte("fixture"), key, time.Minute)
	if e != nil {
		t.Fatal("SSH fixture unlock")
	}
	t.Cleanup(s.Lock)
	g := NewMutationGate(time.Now().Add(time.Minute))
	if s.RegisterMutation(g) != nil {
		t.Fatal("SSH fixture gate")
	}
	row, e := s.GenerateSSHKey("Signing key", g)
	if e != nil {
		t.Fatal("SSH key creation", e)
	}
	return s, key, row
}
func sshRequest(t *testing.T, row SSHKeyRow) SSHSignRequest {
	t.Helper()
	p, _, _, _, e := ssh.ParseAuthorizedKey([]byte(row.PublicKey))
	if e != nil {
		t.Fatal("SSH public key")
	}
	return SSHSignRequest{RequestID: strings.Repeat("1", 32), ConnectionID: strings.Repeat("2", 32), Peer: "uid=1000 pid=321", PublicKey: p.Marshal(), Data: []byte("exact SSH client message")}
}
func TestSSHSignIntentBeforeSignatureAndSingleUse(t *testing.T) {
	s, _, row := sshFixture(t)
	last := s.last
	rows, e := s.ListSSHKeys()
	if e != nil || len(rows) != 1 || rows[0] != row || s.last != last {
		t.Fatal("SSH identities/idle")
	}
	r := sshRequest(t, row)
	want := bytes.Clone(r.Data)
	intent, e := s.PrepareSSHSign(SSHKeyTarget{row.ID, row.Revision}, r, time.Now().Add(10*time.Second))
	if e != nil {
		t.Fatal("SSH prepare", e)
	}
	clear(r.Data)
	clear(r.PublicKey)
	events, e := s.Audit()
	if e != nil {
		t.Fatal("SSH audit before approval")
	}
	for _, ev := range events {
		if ev.Action == sshSignAction {
			t.Fatal("prepare recorded signing intent")
		}
	}
	last = s.last
	o, e := s.ApproveSSHSign(intent)
	if e != nil {
		t.Fatal("SSH approve", e)
	}
	if s.last != last {
		t.Fatal("SSH approval renewed idle lifetime")
	}
	events, e = s.Audit()
	if e != nil {
		t.Fatal("SSH signed audit")
	}
	found := 0
	for _, ev := range events {
		if ev.Action == sshSignAction {
			found++
			if ev.Result != "intent" || ev.BaseRevision != row.Revision || !digestOK(ev.Link) {
				t.Fatal("SSH intent binding")
			}
		}
	}
	if found != 1 {
		t.Fatal("SSH intent not committed before output")
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	success := 0
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			wire, e := s.ConsumeSSHSignature(o)
			defer clear(wire)
			if e != nil {
				return
			}
			var signature ssh.Signature
			if ssh.Unmarshal(wire, &signature) != nil {
				t.Error("SSH signature encoding")
				return
			}
			public, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(row.PublicKey))
			if public.Verify(want, &signature) != nil {
				t.Error("SSH signature wrong message")
			}
			mu.Lock()
			success++
			mu.Unlock()
		}()
	}
	wg.Wait()
	if success != 1 {
		t.Fatal("SSH output was not one-use")
	}
	rows, e = s.ListSSHKeys()
	if e != nil || rows[0].Revision != row.Revision {
		t.Fatal("signing changed key revision")
	}
}

func TestSSHUnencryptedImportRejectsEncryptedBeforeKDF(t *testing.T) {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{39}, 32))
	defer clear(private)
	block, e := ssh.MarshalPrivateKey(private, "")
	if e != nil {
		t.Fatal("SSH import fixture")
	}
	encoded := pem.EncodeToMemory(block)
	seed, e := parseSSHSeed(encoded)
	defer clear(seed)
	if e != nil || !bytes.Equal(seed, private[:32]) {
		t.Fatal("unencrypted Ed25519 import")
	}
	public, _ := ssh.NewPublicKey(private.Public())
	mutated := bytes.Clone(block.Bytes)
	defer clear(mutated)
	index := bytes.Index(mutated, public.Marshal())
	if index < 0 {
		t.Fatal("SSH public fixture")
	}
	mutated[index+len(public.Marshal())-1] ^= 1
	if _, e = parseSSHSeed(pem.EncodeToMemory(&pem.Block{Type: block.Type, Bytes: mutated})); !errors.Is(e, ErrSSHKey) {
		t.Fatal("OpenSSH outer public key mismatch accepted")
	}
	// Deliberately impossible KDF payload: the parser must reject the encrypted
	// profile without calling a password KDF, not wait for a passphrase prompt.
	bad := pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: append([]byte("openssh-key-v1\x00"), ssh.Marshal(struct {
		Cipher, KDF string
		Options     []byte
	}{"aes256-ctr", "bcrypt", bytes.Repeat([]byte{255}, 64)})...)})
	if _, e = parseSSHSeed(bad); !errors.Is(e, ErrSSHKey) {
		t.Fatal("encrypted OpenSSH key accepted")
	}
	for _, raw := range [][]byte{nil, []byte("private garbage"), bytes.Repeat([]byte{1}, MaxSSHImport+1), append(bytes.Clone(encoded), encoded...)} {
		if _, e = parseSSHSeed(raw); !errors.Is(e, ErrSSHKey) {
			t.Fatal("unsupported SSH key input accepted")
		}
	}
}

func TestSSHSigningTypesAreRedacted(t *testing.T) {
	r := SSHSignRequest{Data: []byte("sensitive sign canary")}
	for _, v := range []any{r, &r, SSHSignIntent{}, &SSHSignIntent{}, SSHSignatureOutput{}, &SSHSignatureOutput{}} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			got := fmt.Sprintf(format, v)
			if !strings.HasPrefix(got, "[SSH ") || strings.Contains(got, "canary") {
				t.Fatal("SSH request formatting exposed data")
			}
		}
		if _, e := json.Marshal(v); e == nil {
			t.Fatal("SSH request JSON exposed data")
		}
	}
}
