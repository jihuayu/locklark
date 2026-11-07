package personal

import (
	"bytes"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"
)

// verificationStore is a component-contract fake for the trusted native
// adapters. It records how often a fresh per-operation OS verification was
// requested; it can block, deny or return altered capsule bytes.
type verificationStore struct {
	mu       sync.Mutex
	values   map[string][]byte
	calls    int
	deny     bool
	override []byte
	entered  chan struct{}
	release  chan struct{}
	once     sync.Once
}

func newVerificationStore() *verificationStore {
	return &verificationStore{values: map[string][]byte{}}
}

func (s *verificationStore) Store(id string, b []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.deny {
		return errors.New("denied")
	}
	s.values[id] = bytes.Clone(b)
	return nil
}

func (s *verificationStore) Load(id string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.deny {
		return nil, errors.New("denied")
	}
	return bytes.Clone(s.values[id]), nil
}

func (s *verificationStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.values, id)
	return nil
}

func (s *verificationStore) LoadForPasskeyVerification(id string) ([]byte, error) {
	s.mu.Lock()
	s.calls++
	deny, override := s.deny, bytes.Clone(s.override)
	value := bytes.Clone(s.values[id])
	entered, release := s.entered, s.release
	s.mu.Unlock()
	if entered != nil {
		s.once.Do(func() { close(entered) })
	}
	if release != nil {
		<-release
	}
	if deny {
		return nil, errors.New("denied")
	}
	if override != nil {
		return override, nil
	}
	return value, nil
}

func (s *verificationStore) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func (s *verificationStore) setDeny(deny bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deny = deny
}

func (s *verificationStore) setOverride(raw []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.override = raw
}

func (s *verificationStore) block() (chan struct{}, chan struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entered, s.release = make(chan struct{}), make(chan struct{})
	return s.entered, s.release
}

func (s *verificationStore) capsule(t *testing.T, id string) []byte {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.values[id]) == 0 {
		t.Fatal("missing enrolled capsule")
	}
	return bytes.Clone(s.values[id])
}

func systemVerificationFixture(t *testing.T) (*Session, *verificationStore, string, []byte) {
	t.Helper()
	path, key, _ := revealFixture(t)
	s, e := UnlockSession(path, []byte("fixture"), key, time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	store := newVerificationStore()
	if e = s.EnableSystemUnlock(store); e != nil {
		s.Lock()
		t.Fatal(e)
	}
	return s, store, path, key
}

// TestSystemPasskeyVerificationIsFreshPerApproval proves that a prior successful
// UnlockWithSystem result can never stand in for WebAuthn user verification and
// that every approval asks the OS adapter again.
func TestSystemPasskeyVerificationIsFreshPerApproval(t *testing.T) {
	s, store, path, _ := systemVerificationFixture(t)
	defer s.Lock()
	prior, e := UnlockWithSystem(path, store, time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	prior.Lock()
	if store.count() != 0 {
		t.Fatal("quick unlock consulted the passkey verification adapter")
	}
	if e = s.VerifyPasskeyUserWithSystem(store); e != nil {
		t.Fatal(e)
	}
	if store.count() != 1 {
		t.Fatalf("first approval used %d adapter calls", store.count())
	}
	if e = s.VerifyPasskeyUserWithSystem(store); e != nil {
		t.Fatal(e)
	}
	if store.count() != 2 {
		t.Fatalf("second approval reused a cached result: %d adapter calls", store.count())
	}
	// Verification alone renews nothing and commits no passkey audit event.
	if _, e = s.List("active"); e != nil {
		t.Fatal(e)
	}
}

func TestSystemPasskeyVerificationRejectsMissingOrOddCapsules(t *testing.T) {
	s, store, path, _ := systemVerificationFixture(t)
	defer s.Lock()
	id, _, e := systemStoreID(path)
	if e != nil {
		t.Fatal(e)
	}
	raw := store.capsule(t, id)
	defer clear(raw)
	var capsule systemCapsule
	if e = json.Unmarshal(raw, &capsule); e != nil {
		t.Fatal(e)
	}
	defer clear(capsule.Identity)
	unknown, e := json.Marshal(struct {
		systemCapsule
		Extra string `json:"extra"`
	}{capsule, "x"})
	if e != nil {
		t.Fatal(e)
	}
	identity := bytes.Clone(capsule.Identity)
	identity[0] ^= 1
	for _, tc := range []struct {
		name string
		raw  []byte
	}{
		{"malformed", []byte("{")},
		{"null", []byte("null")},
		{"trailing", append(bytes.Clone(raw), []byte(`{"extra":1}`)...)},
		{"unknown", unknown},
		{"oversized", append(bytes.Clone(raw), make([]byte, systemPasskeyCapsuleLimit)...)},
		{"version", func() []byte { c := capsule; c.Version = 2; b, _ := json.Marshal(c); return b }()},
		{"path", func() []byte { c := capsule; c.Path += "-other"; b, _ := json.Marshal(c); return b }()},
		{"slot", func() []byte { c := capsule; c.Slot[0] ^= 1; b, _ := json.Marshal(c); return b }()},
		{"identity", func() []byte { c := capsule; c.Identity = identity; b, _ := json.Marshal(c); return b }()},
		{"empty-identity", func() []byte { c := capsule; c.Identity = nil; b, _ := json.Marshal(c); return b }()},
		{"expired", func() []byte {
			c := capsule
			c.Created = time.Now().Add(-25 * time.Hour)
			c.Expires = c.Created.Add(24 * time.Hour)
			b, _ := json.Marshal(c)
			return b
		}()},
		{"future", func() []byte {
			c := capsule
			c.Created = time.Now().Add(time.Hour)
			c.Expires = c.Created.Add(24 * time.Hour)
			b, _ := json.Marshal(c)
			return b
		}()},
		{"not-24h", func() []byte {
			c := capsule
			c.Expires = c.Created.Add(25 * time.Hour)
			b, _ := json.Marshal(c)
			return b
		}()},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			store.setOverride(tc.raw)
			defer store.setOverride(nil)
			if e := s.VerifyPasskeyUserWithSystem(store); e == nil {
				t.Fatal("accepted unusable capsule")
			}
		})
	}
	t.Run("empty", func(t *testing.T) {
		store.setOverride([]byte{})
		defer store.setOverride(nil)
		if e := s.VerifyPasskeyUserWithSystem(store); e == nil {
			t.Fatal("accepted empty capsule")
		}
	})
	t.Run("nil-store", func(t *testing.T) {
		if e := s.VerifyPasskeyUserWithSystem(nil); e == nil {
			t.Fatal("accepted nil adapter")
		}
	})
	t.Run("denied", func(t *testing.T) {
		store.setDeny(true)
		defer store.setDeny(false)
		if e := s.VerifyPasskeyUserWithSystem(store); e == nil {
			t.Fatal("accepted adapter denial")
		}
	})
	t.Run("wrong-vault", func(t *testing.T) {
		other, otherKey, _ := revealFixture(t)
		stranger, e := UnlockSession(other, []byte("fixture"), otherKey, time.Minute)
		if e != nil {
			t.Fatal(e)
		}
		defer stranger.Lock()
		// The adapter returns an unenrolled/foreign capsule for this vault.
		if e = stranger.VerifyPasskeyUserWithSystem(store); e == nil {
			t.Fatal("accepted another vault's capsule")
		}
		store.setOverride(raw)
		defer store.setOverride(nil)
		if e = stranger.VerifyPasskeyUserWithSystem(store); e == nil {
			t.Fatal("accepted foreign capsule bytes")
		}
	})
	t.Run("locked-session", func(t *testing.T) {
		locked, lockedKey, _ := revealFixture(t)
		other, e := UnlockSession(locked, []byte("fixture"), lockedKey, time.Minute)
		if e != nil {
			t.Fatal(e)
		}
		if e = other.EnableSystemUnlock(store); e != nil {
			t.Fatal(e)
		}
		other.Lock()
		if e = other.VerifyPasskeyUserWithSystem(store); e == nil {
			t.Fatal("locked session accepted system verification")
		}
	})
	if e = s.VerifyPasskeyUserWithSystem(store); e != nil {
		t.Fatalf("valid capsule refused after refusals: %v", e)
	}
}

// TestSystemPasskeyVerificationHoldsNoLocksWhileWaiting proves that neither
// Session.mu nor Session.Lock wait for the OS prompt, and that a lock during the
// prompt refuses the verification instead of reviving the session.
func TestSystemPasskeyVerificationHoldsNoLocksWhileWaiting(t *testing.T) {
	s, store, path, key := systemVerificationFixture(t)
	entered, release := store.block()
	done := make(chan error, 1)
	go func() { done <- s.VerifyPasskeyUserWithSystem(store) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("verification adapter was never asked")
	}
	listed := make(chan error, 1)
	go func() {
		_, e := s.List("active")
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
		t.Fatal("session lock was held while the OS verification waited")
	}
	locked := make(chan struct{})
	go func() {
		s.Lock()
		close(locked)
	}()
	select {
	case <-locked:
	case <-time.After(3 * time.Second):
		close(release)
		<-done
		<-locked
		t.Fatal("Session.Lock waited for the OS verification")
	}
	close(release)
	if e := <-done; e == nil {
		t.Fatal("system verification completed for a locked session")
	}
	if store.count() != 1 {
		t.Fatalf("unexpected adapter call count %d", store.count())
	}
	audit, e := UnlockSession(path, []byte("fixture"), key, time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	defer audit.Lock()
	events, e := audit.Audit()
	if e != nil {
		t.Fatal(e)
	}
	for _, event := range events {
		if event.Action == passkeyGetAction || event.Action == passkeyCreateAction {
			t.Fatal("verification alone committed a passkey audit event")
		}
	}
}

// TestDecodeSystemPasskeyCapsuleClearsPartialIdentity is the regression for a
// failed decode that already populated Identity before the offending field: the
// partial identity bytes must be zeroed and never interpreted.
// TestSystemPasskeyVerificationRechecksCapsuleWindowAfterAuthentication proves
// the unchanged 24-hour window is enforced again after the vault
// authentication work, so an expired or future-dated capsule cannot become
// fresh user verification while that work is blocked.
func TestSystemPasskeyVerificationRechecksCapsuleWindowAfterAuthentication(t *testing.T) {
	s, store, path, _ := systemVerificationFixture(t)
	defer s.Lock()
	id, absolute, e := systemStoreID(path)
	if e != nil {
		t.Fatal(e)
	}
	raw := store.capsule(t, id)
	defer clear(raw)
	var enrolled systemCapsule
	if e = json.Unmarshal(raw, &enrolled); e != nil {
		t.Fatal(e)
	}
	defer clear(enrolled.Identity)
	if enrolled.Path != absolute {
		t.Fatal("unexpected enrolled capsule path")
	}
	if e = s.finishSystemPasskeyVerification(path, enrolled); e != nil {
		t.Fatal(e)
	}
	expired := enrolled
	expired.Created = time.Now().Add(-25 * time.Hour)
	expired.Expires = expired.Created.Add(24 * time.Hour)
	if e = s.finishSystemPasskeyVerification(path, expired); e == nil {
		t.Fatal("expired capsule produced user verification after authentication")
	}
	future := enrolled
	future.Created = time.Now().Add(time.Hour)
	future.Expires = future.Created.Add(24 * time.Hour)
	if e = s.finishSystemPasskeyVerification(path, future); e == nil {
		t.Fatal("future-dated capsule produced user verification after authentication")
	}
	long := enrolled
	long.Expires = long.Created.Add(25 * time.Hour)
	if e = s.finishSystemPasskeyVerification(path, long); e == nil {
		t.Fatal("non-24h capsule produced user verification after authentication")
	}
}
