package browserhost

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/passkey"
	"github.com/jihuayu/locklark/internal/personal"
)

// systemFactorStore is a component-contract fake for the trusted native OS
// adapter. It is not hardware: it only proves that the host asks the adapter
// exactly once per approval, never during rendering, and fails closed when the
// adapter denies, blocks, or returns an unusable capsule.
type systemFactorStore struct {
	mu       sync.Mutex
	values   map[string][]byte
	calls    int
	deny     bool
	override []byte
	entered  chan struct{}
	release  chan struct{}
	once     sync.Once
}

func newSystemFactorStore() *systemFactorStore {
	return &systemFactorStore{values: map[string][]byte{}}
}

func (s *systemFactorStore) Store(id string, b []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.deny {
		return errors.New("denied")
	}
	s.values[id] = bytes.Clone(b)
	return nil
}

func (s *systemFactorStore) Load(id string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.deny {
		return nil, errors.New("denied")
	}
	return bytes.Clone(s.values[id]), nil
}

func (s *systemFactorStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.values, id)
	return nil
}

func (s *systemFactorStore) LoadForPasskeyVerification(id string) ([]byte, error) {
	s.mu.Lock()
	s.calls++
	override := bytes.Clone(s.override)
	value := bytes.Clone(s.values[id])
	entered, release := s.entered, s.release
	s.mu.Unlock()
	if entered != nil {
		s.once.Do(func() { close(entered) })
	}
	if release != nil {
		<-release
	}
	// Denial can arrive while the prompt is open, so re-read it afterwards.
	s.mu.Lock()
	deny := s.deny
	s.mu.Unlock()
	if deny {
		return nil, errors.New("denied")
	}
	if override != nil {
		return override, nil
	}
	return value, nil
}

func (s *systemFactorStore) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func (s *systemFactorStore) setDeny(deny bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deny = deny
}

func (s *systemFactorStore) setOverride(raw []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.override = bytes.Clone(raw)
}

func (s *systemFactorStore) rawCapsule(t *testing.T) []byte {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.values) != 1 {
		t.Fatalf("expected exactly one enrollment, got %d", len(s.values))
	}
	for _, raw := range s.values {
		return bytes.Clone(raw)
	}
	return nil
}

func (s *systemFactorStore) block() (chan struct{}, chan struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entered, s.release = make(chan struct{}), make(chan struct{})
	return s.entered, s.release
}

const systemCreateOptions = `{"challenge":"Y2hhbGxlbmdlLTAxMjM0NTY3ODk","rp":{"id":"example.test","name":"Example"},"user":{"id":"dXNlcjE","name":"alice","displayName":"Alice"},"pubKeyCredParams":[{"type":"public-key","alg":-7}],"authenticatorSelection":{"userVerification":"required"}}`

type systemPasskeyHarness struct {
	c          *Connection
	s          *personal.Session
	out        *memoryPipe
	path       string
	key        []byte
	capability string
	store      *systemFactorStore
}

func newSystemPasskeyHarness(t *testing.T) *systemPasskeyHarness {
	t.Helper()
	path := filepath.Join(t.TempDir(), "system.ll")
	key := bytes.Repeat([]byte{9}, 16)
	if e := personal.Create(path, "fixture", key); e != nil {
		t.Fatal(e)
	}
	s, e := personal.UnlockSession(path, []byte("fixture"), key, time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(s.Lock)
	id, e := s.AddLogin("System login", "fixture-user", "fixture-password")
	if e != nil {
		t.Fatal(e)
	}
	rows, e := s.List("active")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Edit(personal.Edit{ID: id, Revision: rows[0].Revision, Field: "url", Value: "https://example.test/login"}); e != nil {
		t.Fatal(e)
	}
	out := &memoryPipe{}
	c := NewConnection(NewWriter(out, time.Second), nil)
	t.Cleanup(c.Close)
	if e = c.Handle(Request{V: 1, ID: reqID(1), Type: "hello"}); e != nil {
		t.Fatal(e)
	}
	if e = c.ApprovePair(s); e != nil {
		t.Fatal(e)
	}
	capability := out.responses(t)[0].Capability
	store := newSystemFactorStore()
	if e = s.EnableSystemUnlock(store); e != nil {
		t.Fatal(e)
	}
	return &systemPasskeyHarness{c: c, s: s, out: out, path: path, key: key, capability: capability, store: store}
}

func (h *systemPasskeyHarness) create(t *testing.T, n int) Request {
	t.Helper()
	r := Request{V: 1, ID: reqID(n), Type: "passkey-create", Capability: h.capability, Origin: "https://example.test", TabID: 1, DocumentID: "doc-1", Options: systemCreateOptions}
	if e := h.c.Handle(r); e != nil {
		t.Fatal(e)
	}
	return r
}

func (h *systemPasskeyHarness) get(t *testing.T, n int, credentialID string) Request {
	t.Helper()
	r := Request{V: 1, ID: reqID(n), Type: "passkey-get", Capability: h.capability, Origin: "https://example.test", TabID: 1, DocumentID: "doc-1",
		Options: `{"rpId":"example.test","challenge":"bmV3LWNoYWxsZW5nZS0wMTIzNDU2","userVerification":"required","allowCredentials":[{"type":"public-key","id":"` + credentialID + `"}]}`}
	if e := h.c.Handle(r); e != nil {
		t.Fatal(e)
	}
	return r
}

// credential parses the committed passkey-result delivered to the browser.
func (h *systemPasskeyHarness) credential(t *testing.T) (passkey.Response, bool, bool) {
	t.Helper()
	all := h.out.responses(t)
	if len(all) == 0 || all[len(all)-1].Type != "passkey-result" {
		t.Fatal("missing approved passkey result")
	}
	var credential passkey.Response
	if e := json.Unmarshal([]byte(all[len(all)-1].Credential), &credential); e != nil {
		t.Fatal("invalid credential response")
	}
	auth, e := base64.RawURLEncoding.DecodeString(credential.Response.AuthenticatorData)
	if e != nil || len(auth) < 33 {
		t.Fatal("invalid authenticator data")
	}
	return credential, auth[32]&0x01 != 0, auth[32]&0x04 != 0
}

func TestPasskeySystemApprovalUsesFreshVerificationPerOperation(t *testing.T) {
	h := newSystemPasskeyHarness(t)
	// A successful quick unlock first must not be reusable as WebAuthn UV.
	if unlocked, e := personal.UnlockWithSystem(h.path, h.store, time.Minute); e != nil {
		t.Fatal(e)
	} else {
		unlocked.Lock()
	}
	if h.store.count() != 0 {
		t.Fatal("quick unlock consulted the passkey verification adapter")
	}
	create := h.create(t, 2)
	p := waitPasskey(t, h.c)
	if len(p.Choices) != 1 {
		t.Fatalf("unexpected choices: %d", len(p.Choices))
	}
	if h.store.count() != 0 {
		t.Fatal("candidate review asked for a system prompt")
	}
	if e := h.c.ApprovePasskeyWithSystem(create.ID, p.Choices[0].ID, h.store); e != nil {
		t.Fatal(e)
	}
	if h.store.count() != 1 {
		t.Fatalf("create approval used %d adapter calls", h.store.count())
	}
	credential, up, uv := h.credential(t)
	if !up || !uv {
		t.Fatal("approved creation is missing UP and UV")
	}
	get := h.get(t, 50, credential.ID)
	p = waitPasskey(t, h.c)
	if len(p.Choices) != 1 {
		t.Fatalf("unexpected assertion choices: %d", len(p.Choices))
	}
	if e := h.c.ApprovePasskeyWithSystem(get.ID, p.Choices[0].ID, h.store); e != nil {
		t.Fatal(e)
	}
	if h.store.count() != 2 {
		t.Fatalf("second approval reused the first verification: %d adapter calls", h.store.count())
	}
	if _, up, uv = h.credential(t); !up || !uv {
		t.Fatal("approved assertion is missing UP and UV")
	}
	if _, e := h.s.List("active"); e != nil {
		t.Fatal("vault not readable after approval", e)
	}
}

func TestPasskeySystemApprovalRejectsAlteredCapsule(t *testing.T) {
	for _, mode := range []string{"expired", "malformed", "oversized", "unknown"} {
		mode := mode
		t.Run(mode, func(t *testing.T) {
			h := newSystemPasskeyHarness(t)
			raw := h.store.rawCapsule(t)
			altered := map[string][]byte{
				"malformed": []byte("{"),
				"oversized": append(bytes.Clone(raw), make([]byte, 8192)...),
				"unknown":   append(bytes.Clone(raw), []byte(`{"extra":1}`)...),
				"expired": func() []byte {
					var capsule struct {
						Version  int       `json:"version"`
						Path     string    `json:"path"`
						Slot     [32]byte  `json:"slot"`
						Identity []byte    `json:"identity"`
						Created  time.Time `json:"created"`
						Expires  time.Time `json:"expires"`
					}
					if json.Unmarshal(raw, &capsule) != nil {
						t.Fatal("bad enrolled capsule")
					}
					created := time.Now().Add(-25 * time.Hour)
					b, _ := json.Marshal(struct {
						Version  int       `json:"version"`
						Path     string    `json:"path"`
						Slot     [32]byte  `json:"slot"`
						Identity []byte    `json:"identity"`
						Created  time.Time `json:"created"`
						Expires  time.Time `json:"expires"`
					}{capsule.Version, capsule.Path, capsule.Slot, capsule.Identity, created, created.Add(24 * time.Hour)})
					return b
				}(),
			}[mode]
			h.store.setOverride(altered)
			r := h.create(t, 2)
			p := waitPasskey(t, h.c)
			if e := h.c.ApprovePasskeyWithSystem(r.ID, p.Choices[0].ID, h.store); e == nil {
				t.Fatal("altered capsule produced an approval")
			}
			for _, response := range h.out.responses(t) {
				if response.Type == "passkey-result" {
					t.Fatal("signature escaped a failed system verification")
				}
			}
			h.assertNoPasskeyCommit(t)
		})
	}
}

// assertNoPasskeyCommit opens the vault afresh and refuses any passkey audit
// event, so a refused or interrupted approval cannot have committed a signature.
func (h *systemPasskeyHarness) assertNoPasskeyCommit(t *testing.T) {
	t.Helper()
	audit, e := personal.UnlockSession(h.path, []byte("fixture"), h.key, time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	defer audit.Lock()
	events, e := audit.Audit()
	if e != nil {
		t.Fatal(e)
	}
	for _, event := range events {
		if event.Action == "item.passkey.create" || event.Action == "item.passkey.get" {
			t.Fatal("refused approval committed a passkey audit event")
		}
	}
}

func TestPasskeySystemApprovalRefusesInterruptedOSPrompt(t *testing.T) {
	for _, mode := range []string{"cancel", "lock", "deadline", "revision", "reject"} {
		mode := mode
		t.Run(mode, func(t *testing.T) {
			h := newSystemPasskeyHarness(t)
			r := h.create(t, 2)
			p := waitPasskey(t, h.c)
			if len(p.Choices) != 1 {
				t.Fatalf("unexpected choices: %d", len(p.Choices))
			}
			entered, release := h.store.block()
			done := make(chan error, 1)
			go func() { done <- h.c.ApprovePasskeyWithSystem(r.ID, p.Choices[0].ID, h.store) }()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("OS adapter was never asked")
			}
			// Neither the connection mutex nor the session mutex may be held.
			if v := h.c.Snapshot(); v.Busy {
				close(release)
				<-done
				t.Fatal("connection lock held while the OS prompt waited")
			}
			listed := make(chan error, 1)
			go func() {
				_, e := h.s.List("active")
				listed <- e
			}()
			select {
			case e := <-listed:
				if e != nil {
					close(release)
					<-done
					t.Fatal(e)
				}
			case <-time.After(3 * time.Second):
				close(release)
				<-done
				t.Fatal("session lock held while the OS prompt waited")
			}
			switch mode {
			case "cancel":
				if e := h.c.Handle(Request{V: 1, ID: reqID(30), Type: "cancel", Capability: h.capability}); e != nil {
					t.Fatal(e)
				}
			case "lock":
				h.c.Invalidate()
			case "deadline":
				h.c.now = func() time.Time { return time.Now().Add(3 * time.Minute) }
			case "revision":
				if _, e := h.s.Edit(personal.Edit{ID: p.Choices[0].ID, Revision: p.Choices[0].Revision, Field: "title", Value: "changed"}); e != nil {
					close(release)
					<-done
					t.Fatal(e)
				}
			case "reject":
				h.store.setDeny(true)
			}
			close(release)
			if e := <-done; e == nil {
				t.Fatal("interrupted approval reported success")
			}
			if h.store.count() != 1 {
				t.Fatalf("unexpected adapter call count %d", h.store.count())
			}
			for _, response := range h.out.responses(t) {
				if response.Type == "passkey-result" {
					t.Fatal("signature escaped an interrupted approval")
				}
			}
			h.assertNoPasskeyCommit(t)
		})
	}
}
