package personal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

type testSystemStore struct {
	values map[string][]byte
	deny   bool
}

func (s *testSystemStore) Store(id string, b []byte) error {
	if s.deny {
		return errors.New("denied")
	}
	s.values[id] = bytes.Clone(b)
	return nil
}
func (s *testSystemStore) Load(id string) ([]byte, error) {
	if s.deny {
		return nil, errors.New("denied")
	}
	return bytes.Clone(s.values[id]), nil
}
func (s *testSystemStore) Delete(id string) error { delete(s.values, id); return nil }
func TestSystemUnlockLifecycle(t *testing.T) {
	path, key, _ := revealFixture(t)
	store := &testSystemStore{values: map[string][]byte{}}
	if _, e := UnlockWithSystem(path, store, time.Minute); e == nil {
		t.Fatal("unenrolled unlock")
	}
	s, e := UnlockSession(path, []byte("fixture"), key, time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.EnableSystemUnlock(store); e != nil {
		t.Fatal(e)
	}
	s.Lock()
	store.deny = true
	if _, e = UnlockWithSystem(path, store, time.Minute); e == nil {
		t.Fatal("system denial bypass")
	}
	store.deny = false
	s, e = UnlockWithSystem(path, store, time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Lock()
	if _, e = s.List("active"); e != nil {
		t.Fatal(e)
	}
	if e = s.EnableSystemUnlock(store); e == nil {
		t.Fatal("quick unlock extended full-factor deadline")
	}
	if e = DisableSystemUnlock(path, store); e != nil {
		t.Fatal(e)
	}
	if _, e = UnlockWithSystem(path, store, time.Minute); e == nil {
		t.Fatal("disabled unlock")
	}
}

func TestSystemUnlockExpiryAndBinding(t *testing.T) {
	path, key, _ := revealFixture(t)
	store := &testSystemStore{values: map[string][]byte{}}
	s, e := UnlockSession(path, []byte("fixture"), key, time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Lock()
	if e = s.EnableSystemUnlock(store); e != nil {
		t.Fatal(e)
	}
	id, _, _ := systemStoreID(path)
	raw := bytes.Clone(store.values[id])
	defer clear(raw)
	var capsule systemCapsule
	if e = json.Unmarshal(raw, &capsule); e != nil {
		t.Fatal(e)
	}
	defer clear(capsule.Identity)
	for _, kind := range []string{"expired", "future", "duration", "slot", "path"} {
		t.Run(kind, func(t *testing.T) {
			altered := capsule
			switch kind {
			case "expired":
				altered.Created = time.Now().Add(-25 * time.Hour)
				altered.Expires = altered.Created.Add(24 * time.Hour)
			case "future":
				altered.Created = time.Now().Add(time.Hour)
				altered.Expires = altered.Created.Add(24 * time.Hour)
			case "duration":
				altered.Expires = altered.Created.Add(25 * time.Hour)
			case "slot":
				altered.Slot[0] ^= 1
			case "path":
				altered.Path += "-different"
			}
			store.values[id], e = json.Marshal(altered)
			if e != nil {
				t.Fatal(e)
			}
			if unlocked, e := UnlockWithSystem(path, store, time.Minute); e == nil {
				unlocked.Lock()
				t.Fatal("accepted changed capsule")
			}
		})
	}
	store.values[id] = raw
	if e = DisableSystemUnlock(path, store); e != nil {
		t.Fatal(e)
	}
}

// A native store failure or an expired capsule is not a locked vault. The UI
// must be able to tell the user to sign the app, enable the keychain, or
// perform a fresh full unlock instead of pointlessly asking to unlock again.
func TestSystemUnlockFailuresAreClassified(t *testing.T) {
	path, key, _ := revealFixture(t)
	s, e := UnlockSession(path, []byte("fixture"), key, time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Lock()
	store := &testSystemStore{values: map[string][]byte{}, deny: true}
	if e = s.EnableSystemUnlock(store); !errors.Is(e, ErrSystemUnlockUnavailable) || errors.Is(e, ErrSessionLocked) {
		t.Fatalf("store failure = %v, want ErrSystemUnlockUnavailable", e)
	}
	store.deny = false
	if e = s.EnableSystemUnlock(store); e != nil {
		t.Fatal(e)
	}
	s.Lock()
	store.deny = true
	if _, e = UnlockWithSystem(path, store, time.Minute); !errors.Is(e, ErrSystemUnlockUnavailable) || errors.Is(e, ErrSessionLocked) {
		t.Fatalf("load failure = %v, want ErrSystemUnlockUnavailable", e)
	}
	store.deny = false
	id, _, _ := systemStoreID(path)
	raw := bytes.Clone(store.values[id])
	defer clear(raw)
	var capsule systemCapsule
	if e = json.Unmarshal(raw, &capsule); e != nil {
		t.Fatal(e)
	}
	defer clear(capsule.Identity)
	capsule.Created = time.Now().Add(-25 * time.Hour)
	capsule.Expires = capsule.Created.Add(24 * time.Hour)
	if store.values[id], e = json.Marshal(capsule); e != nil {
		t.Fatal(e)
	}
	if _, e = UnlockWithSystem(path, store, time.Minute); !errors.Is(e, ErrSystemUnlockExpired) || errors.Is(e, ErrSessionLocked) {
		t.Fatalf("expired capsule = %v, want ErrSystemUnlockExpired", e)
	}
}

type waitingSystemStore struct {
	testSystemStore
	entered, release chan struct{}
}

func (s *waitingSystemStore) Store(id string, b []byte) error {
	close(s.entered)
	<-s.release
	return s.testSystemStore.Store(id, b)
}
func TestLockDoesNotWaitForSystemPrompt(t *testing.T) {
	path, key, _ := revealFixture(t)
	s, e := UnlockSession(path, []byte("fixture"), key, time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	store := &waitingSystemStore{testSystemStore: testSystemStore{values: map[string][]byte{}}, entered: make(chan struct{}), release: make(chan struct{})}
	done := make(chan error, 1)
	go func() { done <- s.EnableSystemUnlock(store) }()
	<-store.entered
	locked := make(chan struct{})
	go func() { s.Lock(); close(locked) }()
	select {
	case <-locked:
	case <-time.After(time.Second):
		close(store.release)
		<-done
		<-locked
		t.Fatal("system prompt blocked lock")
	}
	close(store.release)
	if e = <-done; e == nil {
		t.Fatal("late enrollment survived lock")
	}
	if len(store.values) != 0 {
		t.Fatal("cancelled enrollment retained")
	}
}

type waitingLoadStore struct {
	testSystemStore
	entered, release chan struct{}
}

func (s *waitingLoadStore) Load(id string) ([]byte, error) {
	close(s.entered)
	<-s.release
	return s.testSystemStore.Load(id)
}
func TestCancelledSystemUnlockDoesNotCommit(t *testing.T) {
	path, key, _ := revealFixture(t)
	s, e := UnlockSession(path, []byte("fixture"), key, time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Lock()
	store := &waitingLoadStore{testSystemStore: testSystemStore{values: map[string][]byte{}}, entered: make(chan struct{}), release: make(chan struct{})}
	if e = s.EnableSystemUnlock(store); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		unlocked, e := UnlockWithSystemContext(ctx, path, store, time.Minute)
		if unlocked != nil {
			unlocked.Lock()
		}
		done <- e
	}()
	<-store.entered
	cancel()
	close(store.release)
	if e = <-done; e == nil {
		t.Fatal("cancelled system prompt unlocked")
	}
	events, e := s.Audit()
	if e != nil {
		t.Fatal(e)
	}
	for _, event := range events {
		if event.Action == "desktop.system.unlock" {
			t.Fatal("cancelled operation committed unlock")
		}
		if event.Action == "desktop.system.enable" && event.Result != "intent" {
			t.Fatal("enrollment claimed success before OS result")
		}
	}
}
