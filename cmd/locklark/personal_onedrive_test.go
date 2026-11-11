package main

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/jihuayu/locklark/pkg/onedriveauth"
)

const (
	testClientID = "canary-client-id"
	testTenant   = "canary.example"
	testLabel    = "canary-label"
	testToken    = "canary-refresh-token"
)

func TestOnedriveParse(t *testing.T) {
	reg := func(action string) []string {
		return []string{action, "--client-id", testClientID, "--tenant", testTenant}
	}
	login := func(scopes string) []string { return append(reg("login"), "--scopes", scopes) }
	for name, args := range map[string][]string{
		"empty":             {},
		"unknown action":    {"signin", "--client-id", testClientID, "--tenant", testTenant},
		"missing client id": {"login", "--tenant", testTenant, "--scopes", "offline_access"},
		"missing tenant":    {"login", "--client-id", testClientID, "--scopes", "offline_access"},
		"missing scopes":    reg("login"),
		"scopes on status":  append(reg("status"), "--scopes", "offline_access"),
		"scopes on logout":  append(reg("logout"), "--scopes", "offline_access"),
		"profile flag":      append(reg("status"), "--profile", testLabel),
		"label positional":  append(reg("logout"), testLabel),
		"client secret":     append(login("offline_access"), "--client-secret", "x"),
		"no offline_access": login("Files.Read"),
		"empty value":       {"status", "--client-id=", "--tenant", testTenant},
	} {
		if _, err := parseOnedrive(args); err != personalUsage {
			t.Fatalf("%s: parseOnedrive(%q) = %v, want personalUsage", name, args, err)
		}
	}
	// A tenant alias is not special-cased: any tenant-shaped value is kept
	// literally, exactly as validTenant returned it.
	for _, tenant := range []string{"organizations", "common", "consumers"} {
		args := []string{"status", "--client-id", testClientID, "--tenant", tenant}
		want := onedriveRequest{action: "status", config: onedriveauth.AuthorizeConfig{ClientID: testClientID, Tenant: tenant}}
		if got, err := parseOnedrive(args); err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("tenant %q parse = (%+v, %v), want %+v", tenant, got, err, want)
		}
	}
	scopes := []string{"Files.Read", "offline_access", "Files.ReadWrite"}
	for action, args := range map[string][]string{
		"login":  {"--tenant=" + testTenant, "--scopes=Files.Read,offline_access\tFiles.ReadWrite", "--client-id=" + testClientID},
		"status": {"--tenant", testTenant, "--client-id", testClientID},
		"logout": {"--tenant", testTenant, "--client-id", testClientID},
	} {
		want := onedriveRequest{action: action, config: onedriveauth.AuthorizeConfig{ClientID: testClientID, Tenant: testTenant}}
		if action == "login" {
			want.config.Scopes = scopes
		}
		if got, err := parseOnedrive(append([]string{action}, args...)); err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("%s parse = (%+v, %v), want %+v", action, got, err, want)
		}
	}
}

func TestOnedriveHelp(t *testing.T) {
	texts := map[string]string{"main": onedriveHelpText}
	for _, action := range []string{"login", "status", "logout"} {
		var out bytes.Buffer
		if err := runPersonalOnedrive([]string{action, "--help"}, &out); err != nil {
			t.Fatalf("%s --help: %v", action, err)
		}
		texts[action] = out.String()
		if header := "usage: locklark personal onedrive " + action + " --client-id ID --tenant TENANT"; !strings.HasPrefix(texts[action], header) {
			t.Fatalf("%s help header: %q", action, texts[action])
		}
	}
	for name, text := range texts {
		lower := strings.ToLower(text)
		for _, forbidden := range []string{"canary", "common", "consumers", "organizations", "microsoftonline", "@", "default:", "--profile", "--account"} {
			if strings.Contains(lower, forbidden) {
				t.Fatalf("%s help names %q", name, forbidden)
			}
		}
		// Every action help names each explicit field as required with no
		// default, and none of the help mentions a credential or a real
		// configuration value.
		if !strings.Contains(text, "no default") {
			t.Fatalf("%s help omits the no-default statement", name)
		}
	}
	// The identity caveat is a sentence of the top-level command help and may
	// be wrapped across lines there, so compare it with white space collapsed.
	if flat := onedriveFlatSpace(onedriveHelpText); !strings.Contains(flat, "it is not a verified Microsoft identity") ||
		!strings.Contains(flat, "status reports what this machine stored, not who signed in") {
		t.Fatalf("main help omits the identity caveat: %q", onedriveHelpText)
	}
}

// onedriveFlatSpace collapses each run of white space to one space and trims
// the result, so wrapped help text can be compared as one phrase.
func onedriveFlatSpace(s string) string { return strings.Join(strings.Fields(s), " ") }

// fakeOnedriveStore is an in-memory onedriveStore keyed by exactly the client
// ID, tenant and profile label bytes it is handed, recording each triple.
type fakeOnedriveStore struct {
	items   map[string][]byte
	keys    []string
	deletes int
	err     error
}

func (s *fakeOnedriveStore) key(clientID, tenant string, label []byte) string {
	k := strings.Join([]string{clientID, tenant, string(label)}, "\x00")
	s.keys = append(s.keys, k)
	return k
}

func (s *fakeOnedriveStore) SaveRefreshToken(clientID, tenant string, label, token []byte) error {
	s.items[s.key(clientID, tenant, label)] = append([]byte(nil), token...)
	return s.err
}

func (s *fakeOnedriveStore) LoadRefreshToken(clientID, tenant string, label []byte) ([]byte, bool, error) {
	v, ok := s.items[s.key(clientID, tenant, label)]
	return append([]byte(nil), v...), ok && s.err == nil, s.err
}

func (s *fakeOnedriveStore) DeleteRefreshToken(clientID, tenant string, label []byte) error {
	s.deletes++
	if s.err == nil {
		delete(s.items, s.key(clientID, tenant, label))
	}
	return s.err
}

// withOnedriveSeams queues one label per command and serves store; t.Cleanup
// restores both seams. Nothing here opens a browser, a socket or a real store.
func withOnedriveSeams(t *testing.T, store onedriveStore, labels ...string) {
	t.Helper()
	prompt, newStore := promptProfileLabel, newOnedriveStore
	t.Cleanup(func() { promptProfileLabel, newOnedriveStore = prompt, newStore })
	promptProfileLabel = func(ctx context.Context) ([]byte, error) {
		if len(labels) == 0 {
			return nil, errOnedriveTerminal
		}
		label := labels[0]
		labels = labels[1:]
		return []byte(label), nil
	}
	newOnedriveStore = func() (onedriveStore, error) { return store, nil }
}

func mustParseOnedrive(t *testing.T, action string) []string {
	t.Helper()
	args := []string{action, "--client-id", testClientID, "--tenant", testTenant}
	if _, err := parseOnedrive(args); err != nil {
		t.Fatalf("parseOnedrive(%q) = %v", args, err)
	}
	return args
}

func TestOnedriveStatusLogoutReuseCompositeKey(t *testing.T) {
	store := &fakeOnedriveStore{items: map[string][]byte{}}
	withOnedriveSeams(t, store, testLabel, testLabel, testLabel)
	want := strings.Join([]string{testClientID, testTenant, testLabel}, "\x00")
	receipts := []string{onedriveStatusNotEnrolled, onedriveStatusEnrolled, onedriveLogoutDone}
	for i, action := range []string{"status", "status", "logout"} {
		if i == 1 {
			store.items[want] = []byte(testToken)
		}
		var out bytes.Buffer
		if err := runPersonalOnedrive(mustParseOnedrive(t, action), &out); err != nil {
			t.Fatalf("%s = %v", action, err)
		}
		if got := out.String(); got != receipts[i] || strings.Contains(got, testLabel) || strings.Contains(got, testToken) {
			t.Fatalf("%s output = %q", action, got)
		}
	}
	if !reflect.DeepEqual(store.keys, []string{want, want, want}) || len(store.items) != 0 || store.deletes != 1 {
		t.Fatalf("store keys = %q, items = %d, deletes = %d", store.keys, len(store.items), store.deletes)
	}
}

func TestOnedriveFixedErrorMappings(t *testing.T) {
	const backendText = "credential store failed for key locklark/secret/abc123"
	failure := errors.New(backendText)
	cases := []struct {
		name        string
		err, want   error
		notReported []error
		resentinels []error
		leaked      string // backend text that must not reach the CLI error
		reported    bool   // errors.Is(err, errors.ErrUnsupported)
	}{
		{
			name:        "absent store at the platform boundary",
			err:         errors.Join(onedriveauth.ErrStoreUnsupported, errors.ErrUnsupported),
			want:        errOnedriveUnsupported,
			notReported: []error{errOnedriveStore},
			resentinels: []error{onedriveauth.ErrStoreUnsupported},
			reported:    true,
		},
		{
			name:        "adapter sentinel without the platform boundary",
			err:         errors.Join(onedriveauth.ErrStoreUnsupported, failure),
			want:        errOnedriveStore,
			notReported: []error{errOnedriveUnsupported},
			resentinels: []error{onedriveauth.ErrStoreUnsupported},
			leaked:      backendText,
		},
		{
			name:        "arbitrary failure",
			err:         failure,
			want:        errOnedriveStore,
			notReported: []error{errOnedriveUnsupported, onedriveauth.ErrStoreUnsupported},
			leaked:      backendText,
		},
	}
	check := func(t *testing.T, what string, err error, out *bytes.Buffer, tc struct {
		name        string
		err, want   error
		notReported []error
		resentinels []error
		leaked      string
		reported    bool
	}) {
		t.Helper()
		if !errors.Is(err, tc.want) {
			t.Fatalf("%s with %v = %v, want %v", what, tc.err, err, tc.want)
		}
		for _, other := range tc.notReported {
			if errors.Is(err, other) {
				t.Fatalf("%s with %v = %v, must not report %v", what, tc.err, err, other)
			}
		}
		for _, s := range tc.resentinels {
			if !errors.Is(err, s) {
				t.Fatalf("%s with %v = %v, must still report %v", what, tc.err, err, s)
			}
		}
		if errors.Is(err, errors.ErrUnsupported) != tc.reported {
			t.Fatalf("%s with %v = %v, errors.ErrUnsupported reported = %v", what, tc.err, err, !tc.reported)
		}
		if tc.leaked != "" && err != nil && strings.Contains(err.Error(), tc.leaked) {
			t.Fatalf("%s with %v = %q leaks backend text", what, tc.err, err.Error())
		}
		if out.Len() != 0 {
			t.Fatalf("%s out = %q", what, out.String())
		}
	}
	for _, tc := range cases {
		for _, action := range []string{"status", "logout"} {
			store := &fakeOnedriveStore{items: map[string][]byte{}, err: tc.err}
			withOnedriveSeams(t, store, testLabel)
			var out bytes.Buffer
			err := runPersonalOnedrive(mustParseOnedrive(t, action), &out)
			check(t, action, err, &out, tc)
		}
	}
	for _, tc := range cases {
		var out bytes.Buffer
		withOnedriveSeams(t, nil, testLabel)
		newOnedriveStore = func() (onedriveStore, error) { return nil, tc.err }
		err := runPersonalOnedrive([]string{"status", "--client-id=" + testClientID, "--tenant", testTenant}, &out)
		check(t, "newOnedriveStore "+tc.name, err, &out, tc)
	}
	// The generic path stays distinct from the unsupported one.
	if errors.Is(onedriveStoreError(failure), errOnedriveUnsupported) || errors.Is(errOnedriveStore, errOnedriveUnsupported) {
		t.Fatal("generic store failure must stay distinct from unsupported")
	}
}

func TestOnedriveExchangeErrorClassification(t *testing.T) {
	provider := errors.Join(onedriveauth.ErrProviderStatus, errors.New("provider detail"))
	for _, tc := range []struct {
		name        string
		err         error
		want        error // the CLI sentinel onedriveExchangeError reports
		retained    []error
		notReported []error
	}{
		{
			name:        "cancelled before sending",
			err:         onedriveauth.ErrCancelled,
			want:        errOnedriveExchangePre,
			retained:    []error{onedriveauth.ErrCancelled},
			notReported: []error{errOnedriveExchangeUnsure, errOnedriveExchangeFailed, onedriveauth.ErrOutcomeUnknown},
		},
		{
			name:        "outcome unknown after sending",
			err:         onedriveauth.ErrOutcomeUnknown,
			want:        errOnedriveExchangeUnsure,
			retained:    []error{onedriveauth.ErrOutcomeUnknown},
			notReported: []error{errOnedriveExchangePre, errOnedriveExchangeFailed, onedriveauth.ErrCancelled},
		},
		{
			name:        "provider failure",
			err:         provider,
			want:        errOnedriveExchangeFailed,
			retained:    []error{onedriveauth.ErrProviderStatus},
			notReported: []error{errOnedriveExchangePre, errOnedriveExchangeUnsure, onedriveauth.ErrCancelled, onedriveauth.ErrOutcomeUnknown},
		},
	} {
		got := onedriveExchangeError(tc.err)
		if !errors.Is(got, tc.want) {
			t.Fatalf("%s: %v does not report %v", tc.name, got, tc.want)
		}
		if !errors.Is(got, tc.err) {
			t.Fatalf("%s: %v does not retain its cause %v", tc.name, got, tc.err)
		}
		for _, e := range tc.retained {
			if !errors.Is(got, e) {
				t.Fatalf("%s: %v does not retain %v", tc.name, got, e)
			}
		}
		for _, e := range tc.notReported {
			if errors.Is(got, e) {
				t.Fatalf("%s: %v unexpectedly reports %v", tc.name, got, e)
			}
		}
	}
}

// TestBrowserCommandForLinux keeps the Linux opener a direct xdg-open call whose
// single argument is the URL exactly as given, shell metacharacters included.
func TestBrowserCommandForLinux(t *testing.T) {
	const rawURL = "https://login.example/authorize?client_id=a%26b&state=x;y|z$(id)`id`'" + "&redirect_uri=http%3A%2F%2F127.0.0.1%3A8080%2Foauth%2Fcallback"
	program, args, ok := browserCommandFor(rawURL, "linux")
	if !ok || program != "xdg-open" || len(args) != 1 || args[0] != rawURL {
		t.Fatalf("linux browser = (%q, %q, %v)", program, args, ok)
	}
	if _, _, ok := browserCommandFor(rawURL, "plan9"); ok {
		t.Fatal("an OS without an opener must fail closed")
	}
}
