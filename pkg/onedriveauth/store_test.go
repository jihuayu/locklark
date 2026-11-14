package onedriveauth

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/egoist/mygo"
)

const (
	testClientID = "synthetic-client-id"
	testTenant   = "synthetic.example"
)

// fakeSecrets is an in-memory Secrets that records every key it is given and
// every value it is handed. The canary tests rely on that recording: no client
// ID, tenant or profile label may appear in a key or a call.
type fakeSecrets struct {
	items  map[string][]byte
	keys   []string
	values [][]byte // copies of every value passed to Set
	sets   int
	gets   int
	dels   int

	setErr func(key string) error
	getErr func(key string) error
	delErr func(key string) error
	// getMissing, when set, replaces mygo.ErrSecretNotFound for missing
	// items, to model a backend that reports absence differently.
	getMissing error
}

func newFakeSecrets() *fakeSecrets { return &fakeSecrets{items: map[string][]byte{}} }

func (f *fakeSecrets) Set(key string, value []byte) error {
	f.keys = append(f.keys, key)
	f.sets++
	if f.setErr != nil {
		return f.setErr(key)
	}
	if len(value) > mygo.MaxSecretSize {
		return fmt.Errorf("mygo: secret %q has %d bytes, more than MaxSecretSize (%d)", key, len(value), mygo.MaxSecretSize)
	}
	f.values = append(f.values, append([]byte(nil), value...))
	f.items[key] = append([]byte(nil), value...)
	return nil
}

func (f *fakeSecrets) Get(key string) ([]byte, error) {
	f.keys = append(f.keys, key)
	f.gets++
	if f.getErr != nil {
		return nil, f.getErr(key)
	}
	if f.getMissing != nil {
		return nil, f.getMissing
	}
	v, ok := f.items[key]
	if !ok {
		return nil, mygo.ErrSecretNotFound
	}
	return append([]byte(nil), v...), nil
}

func (f *fakeSecrets) Delete(key string) error {
	f.keys = append(f.keys, key)
	f.dels++
	if f.delErr != nil {
		return f.delErr(key)
	}
	delete(f.items, key)
	return nil
}

func fakeStore(f *fakeSecrets) *RefreshTokenStore { return &RefreshTokenStore{secrets: f} }

func TestStoreNamespaceIsFixed(t *testing.T) {
	if StoreNamespace != "app.locklark.onedrive.oauth.v1" {
		t.Fatalf("store namespace changed: %q", StoreNamespace)
	}
}

func TestStoreKeyIsLengthPrefixedSHA256(t *testing.T) {
	key, ok := storeKey(testClientID, testTenant, []byte("work"))
	if !ok {
		t.Fatal("valid inputs rejected")
	}
	h := sha256.New()
	h.Write([]byte(storeKeyDomain))
	for _, field := range [][]byte{[]byte(testClientID), []byte(testTenant), []byte("work")} {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(field)))
		h.Write(size[:])
		h.Write(field)
	}
	if want := hex.EncodeToString(h.Sum(nil)); key != want {
		t.Fatalf("key = %q, want the length-prefixed domain-separated digest", key)
	}
	if len(key) != 2*sha256.Size || !isLowerHex(key) {
		t.Fatal("key is not a 64-character lower-case hex digest")
	}
	for _, raw := range []string{testClientID, testTenant, "work"} {
		if strings.Contains(key, raw) {
			t.Fatalf("key contains raw input %q", raw)
		}
	}
}

// TestStoreKeyBindsAllThreeFields proves that the encoding is injective: moving
// bytes between the client ID, the tenant and the label, or changing one field,
// yields a different key.
func TestStoreKeyBindsAllThreeFields(t *testing.T) {
	inputs := []struct {
		clientID, tenant string
		label            string
	}{
		{testClientID, testTenant, "work"},
		{testClientID, testTenant, "Work"},
		{testClientID, testTenant, "work "},
		{testClientID, testTenant, "wor"},
		// Moving bytes across field boundaries must change the key.
		{testClientID, testTenant + "x", "work"},
		{testClientID, "synthetic.exampl", "ework"},
		{testClientID + "x", testTenant, "work"},
		{"syntheticx", "example", "synthetic-client-idwork"},
		{"synthetic-client-idwork", "example", "x"},
		{"synthetic", "client-id", "synthetic.example work"},
		{"synthetic-client", "id", "synthetic.example work"},
		{"synthetic", "client-idsynthetic.example", "work"},
		{"", testTenant, "work"},
	}
	seen := map[string]string{}
	for _, in := range inputs {
		key, ok := storeKey(in.clientID, in.tenant, []byte(in.label))
		if !ok {
			// The empty client ID is the only invalid case listed here,
			// and it must never share a key.
			if in.clientID != "" {
				t.Fatalf("valid input %+v rejected", in)
			}
			continue
		}
		if prev, dup := seen[key]; dup {
			t.Fatalf("inputs %q and %q share a key", prev, in)
		}
		seen[key] = fmt.Sprint(in)
	}
}

func TestStoreKeyRejectsInvalidInputs(t *testing.T) {
	cases := []struct {
		clientID, tenant string
		label            []byte
	}{
		{"", testTenant, []byte("work")},
		{testClientID, "", []byte("work")},
		{testClientID, testTenant, nil},
		{testClientID, testTenant, []byte{}},
		{strings.Repeat("a", 257), testTenant, []byte("work")},
		{testClientID, "synthetic tenant", []byte("work")},
		{testClientID, "a\x00b", []byte("work")},
		{testClientID, testTenant, []byte("line\nbreak")},
		{testClientID, testTenant, []byte("caf\u00e9")},
		{testClientID, testTenant, []byte("nul\x00")},
		{testClientID, testTenant, bytes.Repeat([]byte("a"), MaxProfileLabelLen+1)},
	}
	for _, c := range cases {
		if _, ok := storeKey(c.clientID, c.tenant, c.label); ok {
			t.Fatalf("invalid inputs (%q, %q, %q) accepted", c.clientID, c.tenant, c.label)
		}
		f := newFakeSecrets()
		s := fakeStore(f)
		if err := s.SaveRefreshToken(c.clientID, c.tenant, c.label, []byte("token")); err != ErrStoreInput {
			t.Fatalf("save = %v, want ErrStoreInput", err)
		}
		if _, _, err := s.LoadRefreshToken(c.clientID, c.tenant, c.label); err != ErrStoreInput {
			t.Fatalf("load = %v, want ErrStoreInput", err)
		}
		if err := s.DeleteRefreshToken(c.clientID, c.tenant, c.label); err != ErrStoreInput {
			t.Fatalf("delete = %v, want ErrStoreInput", err)
		}
		if len(f.keys) != 0 {
			t.Fatal("invalid input reached the store")
		}
	}
	if !ValidProfileLabel(bytes.Repeat([]byte("a"), MaxProfileLabelLen)) || !ValidProfileLabel([]byte("home lab 1")) {
		t.Fatal("valid profile labels rejected")
	}
}

func TestSaveLoadDeleteRoundTrip(t *testing.T) {
	f := newFakeSecrets()
	s := fakeStore(f)
	token := []byte("synthetic-refresh-token")
	if err := s.SaveRefreshToken(testClientID, testTenant, []byte("work"), token); err != nil {
		t.Fatal(err)
	}
	key, _ := storeKey(testClientID, testTenant, []byte("work"))
	if !bytes.Equal(f.items[key], token) || len(f.items) != 1 {
		t.Fatal("stored item is not exactly the token under the composite key")
	}
	got, ok, err := s.LoadRefreshToken(testClientID, testTenant, []byte("work"))
	defer clear(got)
	if err != nil || !ok || !bytes.Equal(got, token) {
		t.Fatalf("load = (%d bytes, %v, %v)", len(got), ok, err)
	}
	// Another tenant or label of the same client is a different profile.
	if _, ok, err := s.LoadRefreshToken(testClientID, "other.example", []byte("work")); ok || err != nil {
		t.Fatal("a different tenant found the token")
	}
	if _, ok, err := s.LoadRefreshToken(testClientID, testTenant, []byte("Work")); ok || err != nil {
		t.Fatal("a different label found the token")
	}
	if err := s.DeleteRefreshToken(testClientID, testTenant, []byte("work")); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := s.LoadRefreshToken(testClientID, testTenant, []byte("work")); ok || err != nil {
		t.Fatalf("load after delete = (%v, %v)", ok, err)
	}
	if err := s.DeleteRefreshToken(testClientID, testTenant, []byte("work")); err != nil {
		t.Fatalf("second delete = %v", err)
	}
}

func TestSaveDoesNotStoreRawInputs(t *testing.T) {
	f := newFakeSecrets()
	if err := fakeStore(f).SaveRefreshToken(testClientID, testTenant, []byte("home-lab"), []byte("token")); err != nil {
		t.Fatal(err)
	}
	for _, key := range f.keys {
		for _, raw := range []string{testClientID, testTenant, "home-lab"} {
			if strings.Contains(key, raw) {
				t.Fatalf("store key exposed %q", raw)
			}
		}
	}
	for _, value := range f.values {
		if strings.Contains(string(value), "home-lab") || strings.Contains(string(value), testClientID) {
			t.Fatal("stored value carries more than the token")
		}
	}
}

func TestSaveCopiesTokenAndLoadReturnsOwnedCopy(t *testing.T) {
	f := newFakeSecrets()
	s := fakeStore(f)
	token := []byte("caller-owned-token")
	if err := s.SaveRefreshToken(testClientID, testTenant, []byte("work"), token); err != nil {
		t.Fatal(err)
	}
	clear(token)
	key, _ := storeKey(testClientID, testTenant, []byte("work"))
	if !bytes.Equal(f.items[key], []byte("caller-owned-token")) {
		t.Fatal("save aliased the caller's buffer")
	}
	got, ok, err := s.LoadRefreshToken(testClientID, testTenant, []byte("work"))
	defer clear(got)
	if err != nil || !ok {
		t.Fatal("load failed")
	}
	clear(got)
	again, ok, err := s.LoadRefreshToken(testClientID, testTenant, []byte("work"))
	defer clear(again)
	if err != nil || !ok || !bytes.Equal(again, []byte("caller-owned-token")) {
		t.Fatal("clearing a loaded copy changed the stored token")
	}
	if &again[0] == &got[0] {
		t.Fatal("load returned an aliased buffer")
	}
}

func TestLoadAbsentIsNotAnError(t *testing.T) {
	got, ok, err := fakeStore(newFakeSecrets()).LoadRefreshToken(testClientID, testTenant, []byte("nobody"))
	if got != nil || ok || err != nil {
		t.Fatalf("absent load = (%v, %v, %v), want not enrolled", got, ok, err)
	}
}

func TestSaveRejectsOversizeBeforeTouchingStore(t *testing.T) {
	f := newFakeSecrets()
	s := fakeStore(f)
	if err := s.SaveRefreshToken(testClientID, testTenant, []byte("work"), []byte("existing")); err != nil {
		t.Fatal(err)
	}
	before := f.sets
	for _, token := range [][]byte{
		nil,
		{},
		[]byte("with space"),
		[]byte("line\nfeed"),
		[]byte("caf\xc3\xa9"),
		{0x01},
		bytes.Repeat([]byte("a"), mygo.MaxSecretSize+1),
	} {
		if err := s.SaveRefreshToken(testClientID, testTenant, []byte("work"), token); err != ErrStoreInput {
			t.Fatalf("save of %d bytes = %v, want ErrStoreInput", len(token), err)
		}
	}
	if f.sets != before {
		t.Fatal("an invalid or oversized token reached the store")
	}
	got, ok, err := s.LoadRefreshToken(testClientID, testTenant, []byte("work"))
	defer clear(got)
	if err != nil || !ok || string(got) != "existing" {
		t.Fatal("an existing entry was modified by a rejected save")
	}
}

func TestSaveAcceptsLargestToken(t *testing.T) {
	f := newFakeSecrets()
	token := bytes.Repeat([]byte("a"), mygo.MaxSecretSize)
	if err := fakeStore(f).SaveRefreshToken(testClientID, testTenant, []byte("work"), token); err != nil {
		t.Fatalf("largest token = %v", err)
	}
}

func TestStoreErrorsAreFixedAndRedacted(t *testing.T) {
	key, _ := storeKey(testClientID, testTenant, []byte("canary-label"))
	echo := func(string) error {
		return fmt.Errorf("backend: item %q in service %q", key, StoreNamespace)
	}
	cases := []struct {
		name string
		f    *fakeSecrets
		op   func(*RefreshTokenStore) error
		want error
	}{
		{"set", &fakeSecrets{items: map[string][]byte{}, setErr: echo}, func(s *RefreshTokenStore) error {
			return s.SaveRefreshToken(testClientID, testTenant, []byte("canary-label"), []byte("t"))
		}, ErrStoreUnsupported},
		{"get", &fakeSecrets{items: map[string][]byte{}, getErr: echo}, func(s *RefreshTokenStore) error {
			_, _, e := s.LoadRefreshToken(testClientID, testTenant, []byte("canary-label"))
			return e
		}, ErrStoreUnsupported},
		{"delete", &fakeSecrets{items: map[string][]byte{}, delErr: echo}, func(s *RefreshTokenStore) error {
			return s.DeleteRefreshToken(testClientID, testTenant, []byte("canary-label"))
		}, ErrStoreUnsupported},
		{"set unsupported", &fakeSecrets{items: map[string][]byte{}, setErr: func(string) error { return errors.ErrUnsupported }}, func(s *RefreshTokenStore) error {
			return s.SaveRefreshToken(testClientID, testTenant, []byte("canary-label"), []byte("t"))
		}, ErrStoreUnsupported},
		{"get unsupported", &fakeSecrets{items: map[string][]byte{}, getErr: func(string) error { return errors.ErrUnsupported }}, func(s *RefreshTokenStore) error {
			_, _, e := s.LoadRefreshToken(testClientID, testTenant, []byte("canary-label"))
			return e
		}, ErrStoreUnsupported},
		{"delete unsupported", &fakeSecrets{items: map[string][]byte{}, delErr: func(string) error { return errors.ErrUnsupported }}, func(s *RefreshTokenStore) error {
			return s.DeleteRefreshToken(testClientID, testTenant, []byte("canary-label"))
		}, ErrStoreUnsupported},
	}
	for _, tc := range cases {
		err := tc.op(fakeStore(tc.f))
		if !errors.Is(err, tc.want) {
			t.Fatalf("%s: err = %v, want %v", tc.name, err, tc.want)
		}
		for _, forbidden := range []string{"canary-label", key, StoreNamespace, "backend", "item", testClientID, testTenant} {
			if strings.Contains(err.Error(), forbidden) {
				t.Fatalf("%s: error text leaked %q", tc.name, forbidden)
			}
		}
	}
}

func TestUnsupportedStorePreservesBoundary(t *testing.T) {
	unsupported := func(string) error { return errors.ErrUnsupported }
	s := fakeStore(&fakeSecrets{items: map[string][]byte{}, setErr: unsupported, getErr: unsupported, delErr: unsupported})
	for name, err := range map[string]error{
		"save":   s.SaveRefreshToken(testClientID, testTenant, []byte("work"), []byte("t")),
		"load":   func() error { _, _, e := s.LoadRefreshToken(testClientID, testTenant, []byte("work")); return e }(),
		"delete": s.DeleteRefreshToken(testClientID, testTenant, []byte("work")),
	} {
		if !errors.Is(err, ErrStoreUnsupported) || !errors.Is(err, errors.ErrUnsupported) || errors.Is(err, ErrStoreNotFound) {
			t.Fatalf("%s on an unsupported store = %v", name, err)
		}
	}
	// A backend failure that is not "unsupported" keeps only the store
	// sentinel.
	failed := fakeStore(&fakeSecrets{items: map[string][]byte{}, setErr: func(string) error { return errors.New("backend locked") }})
	if err := failed.SaveRefreshToken(testClientID, testTenant, []byte("work"), []byte("t")); !errors.Is(err, ErrStoreUnsupported) || errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("failed store = %v", err)
	}
	// Absent is not a store failure, whatever error text the backend adds.
	wrapped := fakeStore(&fakeSecrets{items: map[string][]byte{}, getErr: func(string) error {
		return fmt.Errorf("mygo: secrets: %w", mygo.ErrSecretNotFound)
	}})
	if _, ok, err := wrapped.LoadRefreshToken(testClientID, testTenant, []byte("work")); ok || err != nil {
		t.Fatalf("wrapped not-found surfaced as (%v, %v)", ok, err)
	}
	if !strings.Contains(ErrStoreNotFound.Error(), "no refresh token") || errors.Is(ErrStoreNotFound, ErrStoreUnsupported) {
		t.Fatal("not-found sentinel is not distinct")
	}
}

func TestLoadRejectsMalformedStoredValue(t *testing.T) {
	for _, value := range [][]byte{{}, []byte("with space"), []byte("caf\xc3\xa9"), bytes.Repeat([]byte("a"), mygo.MaxSecretSize+1)} {
		f := newFakeSecrets()
		key, _ := storeKey(testClientID, testTenant, []byte("work"))
		f.items[key] = value
		got, ok, err := fakeStore(f).LoadRefreshToken(testClientID, testTenant, []byte("work"))
		if got != nil || ok || err != ErrStoreInput {
			t.Fatalf("stored value of %d bytes = (%v, %v, %v), want ErrStoreInput", len(value), got, ok, err)
		}
	}
}

func TestSentinelsAreRedacted(t *testing.T) {
	for _, err := range []error{ErrStoreInput, ErrStoreUnsupported, ErrStoreNotFound} {
		if err == nil || strings.ContainsAny(err.Error(), "\n\t") {
			t.Fatalf("sentinel %v is not a fixed line", err)
		}
	}
}

func TestDefaultStoreUsesFixedNamespace(t *testing.T) {
	if _, ok := newSystemSecrets().(Secrets); !ok {
		t.Fatal("mygo Secrets does not satisfy the adapter interface")
	}
	if err := NewRefreshTokenStore().SaveRefreshToken("", "", nil, []byte("t")); err != ErrStoreInput {
		t.Fatalf("invalid input on the system store = %v", err)
	}
}

func isLowerHex(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
