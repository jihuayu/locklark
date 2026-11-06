package teamclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"testing"

	"filippo.io/age"
	"github.com/jihuayu/locklark/internal/directory"
)

// The fake checks ownership/error boundaries only; it is not OS protection.
type memoryStore struct {
	mu                sync.Mutex
	records           map[string][]byte
	storeErr, loadErr error
	writes, deletes   int
}

func newMemoryStore() *memoryStore { return &memoryStore{records: make(map[string][]byte)} }
func (s *memoryStore) Store(id string, b []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.writes++
	s.records[id] = bytes.Clone(b)
	return s.storeErr
}
func (s *memoryStore) Load(id string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.loadErr != nil {
		return nil, s.loadErr
	}
	b, ok := s.records[id]
	if !ok {
		return nil, errors.New("test record unavailable")
	}
	return bytes.Clone(b), nil
}
func (s *memoryStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deletes++
	delete(s.records, id)
	return nil
}

func fixturePins(t *testing.T) (directory.Pins, ed25519.PrivateKey) {
	t.Helper()
	public := make([]string, 3)
	var owner ed25519.PrivateKey
	for n := range public {
		p, k, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			t.Fatal("fixture signing key")
		}
		public[n] = hex.EncodeToString(p)
		if n == 0 {
			owner = k
		} else {
			clear(k)
		}
	}
	t.Cleanup(func() { clear(owner) })
	return directory.Pins{Team: "11111111111111111111111111111111", Vault: "22222222222222222222222222222222", Owners: []string{public[0]}, Sequencer: public[1], Publisher: public[2]}, owner
}

func TestDeviceProtectedIdentityAnswersRealDualKeyChallenge(t *testing.T) {
	pins, owner := fixturePins(t)
	cfg, e := directory.NewConfigWithWriterACL(pins)
	if e != nil {
		t.Fatal("fixture config")
	}
	// Positive control proves that the existing age/Ed admission protocol works.
	ageIdentity, e := age.GenerateX25519Identity()
	if e != nil {
		t.Fatal("fixture age key")
	}
	public, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal("fixture device signer")
	}
	defer clear(private)
	expected := directory.Enrollment{Parent: cfg.Genesis(), Member: "33333333333333333333333333333333", Device: directory.Device{ID: "44444444444444444444444444444444", Encryption: ageIdentity.Recipient().String(), Signing: hex.EncodeToString(public)}}
	challenge, e := directory.IssueChallenge(cfg, owner, expected)
	if e != nil {
		t.Fatal("fixture challenge")
	}
	proof, e := directory.AnswerChallenge(cfg, expected, challenge, ageIdentity, private)
	if e != nil || directory.VerifyAdmission(cfg, expected, proof) != nil {
		t.Fatal("existing protocol positive control")
	}

	plan, e := PrepareDevice(pins)
	if e != nil {
		t.Fatal("team device preparation is missing")
	}
	defer plan.Close()
	descriptor := plan.Descriptor()
	if descriptor.State != DevicePreparing || descriptor.Version != 1 || descriptor.Role != "device" || descriptor.Scope != cfg.Genesis().Scope {
		t.Fatal("prepared device descriptor")
	}
	store := newMemoryStore()
	pending, e := plan.Protect(context.Background(), store)
	if e != nil || pending.State != DevicePending {
		t.Fatal("OS protection was not acknowledged as local-only pending")
	}
	op, e := NewDeviceOperation(pins, pending)
	if e != nil {
		t.Fatal("device operation")
	}
	defer op.Close()
	if op.Load(context.Background(), store) != nil {
		t.Fatal("protected identity load")
	}
	expected.Device = pending.Device
	challenge, e = directory.IssueChallenge(cfg, owner, expected)
	if e != nil {
		t.Fatal("new device challenge")
	}
	proof, e = op.AnswerChallenge(expected, challenge)
	if e != nil || directory.VerifyAdmission(cfg, expected, proof) != nil {
		t.Fatal("protected device did not prove both keys")
	}
	if _, e = op.AnswerChallenge(expected, challenge); e == nil {
		t.Fatal("device operation replayed")
	}
	raw, e := json.Marshal(pending)
	if e != nil || bytes.Contains(raw, []byte("AGE-SECRET-KEY")) {
		t.Fatal("public descriptor exposed private identity")
	}
	if store.writes != 1 || store.deletes != 0 {
		t.Fatal("unexpected OS record rewrite or delete")
	}
}
