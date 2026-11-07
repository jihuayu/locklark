package osunlock

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
)

// legacyLoadOnly mimics the existing quick-unlock surface: a Load method alone
// must never be enough to satisfy the passkey verification interface.
type legacyLoadOnly struct{}

func (legacyLoadOnly) Load(string) ([]byte, error) { return nil, ErrUnavailable }

type fakePasskeyStore struct{ value []byte }

func (f *fakePasskeyStore) LoadForPasskeyVerification(id string) ([]byte, error) {
	if !validID(id) {
		return nil, ErrUnavailable
	}
	return f.value, nil
}

const passkeyCapsuleID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestSystemUnlockPasskeyStoreShape(t *testing.T) {
	passkey := reflect.TypeOf((*PasskeyStore)(nil)).Elem()
	if passkey.NumMethod() != 1 {
		t.Fatalf("PasskeyStore exposes %d methods, want exactly 1", passkey.NumMethod())
	}
	method, ok := passkey.MethodByName("LoadForPasskeyVerification")
	if !ok {
		t.Fatal("PasskeyStore lost LoadForPasskeyVerification")
	}
	want := reflect.TypeOf(func(string) ([]byte, error) { return nil, nil })
	if method.Type != want {
		t.Fatalf("PasskeyStore method type = %v, want %v", method.Type, want)
	}
	// The existing quick-unlock Store must keep its three-method shape: passkey
	// verification is an additional capability, not a change to Store.
	store := reflect.TypeOf((*Store)(nil)).Elem()
	if store.NumMethod() != 3 {
		t.Fatalf("Store exposes %d methods, want 3", store.NumMethod())
	}
	for _, name := range []string{"Store", "Load", "Delete"} {
		if _, ok := store.MethodByName(name); !ok {
			t.Fatalf("Store lost method %s", name)
		}
	}
}

func TestSystemUnlockPasskeyStoreRequiresDedicatedMethod(t *testing.T) {
	if _, ok := any(legacyLoadOnly{}).(PasskeyStore); ok {
		t.Fatal("a Load-only quick-unlock adapter must not satisfy PasskeyStore")
	}
	var adapter PasskeyStore = &fakePasskeyStore{value: bytes.Repeat([]byte{0x5a}, 32)}
	got, err := adapter.LoadForPasskeyVerification(passkeyCapsuleID)
	if err != nil || len(got) != 32 {
		t.Fatalf("fake adapter returned %d bytes and %v, want 32 bytes and nil", len(got), err)
	}
	if _, err := adapter.LoadForPasskeyVerification("0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("non-lowercase capsule id returned %v, want ErrUnavailable", err)
	}
}

func TestSystemUnlockPasskeyCapsuleBound(t *testing.T) {
	if maxPasskeyCapsule != 8192 {
		t.Fatalf("maxPasskeyCapsule = %d, want 8192", maxPasskeyCapsule)
	}
}
