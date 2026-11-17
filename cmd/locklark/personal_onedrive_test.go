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

		"refresh missing scopes": reg("refresh"),
		"refresh empty list":     append(reg("refresh"), "--scopes", " , "),
		"refresh profile flag":   append(append(reg("refresh"), "--scopes", "Files.Read"), "--profile", testLabel),
		"refresh label position": append(append(reg("refresh"), "--scopes", "Files.Read"), testLabel),
		"refresh client secret":  append(append(reg("refresh"), "--scopes", "Files.Read"), "--client-secret", "x"),
	} {
		if _, err := parseOnedrive(args); err != personalUsage {
			t.Fatalf("%s: parseOnedrive(%q) = %v, want personalUsage", name, args, err)
		}
	}
	// Refresh scopes are explicit and required but offline_access is neither
	// required nor added: the parsed list is exactly what the caller gave.
	refreshWant := onedriveRequest{
		action: "refresh",
		config: onedriveauth.AuthorizeConfig{
			ClientID: testClientID,
			Tenant:   testTenant,
			Scopes:   []string{"Files.Read", "Files.ReadWrite"},
		},
	}
	refreshArgs := []string{"refresh", "--tenant=" + testTenant, "--scopes=Files.Read\tFiles.ReadWrite", "--client-id=" + testClientID}
	if got, err := parseOnedrive(refreshArgs); err != nil || !reflect.DeepEqual(got, refreshWant) {
		t.Fatalf("refresh parse = (%+v, %v), want %+v", got, err, refreshWant)
	} else if hasScope(got.config.Scopes, "offline_access") {
		t.Fatalf("refresh parse added offline_access: %q", got.config.Scopes)
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
	for _, action := range []string{"login", "refresh", "status", "logout"} {
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
	// Refresh help requires the explicit scopes but never requires
	// offline_access, and both top-level usage texts list the new action.
	if !strings.Contains(texts["refresh"], "--scopes SCOPE_LIST") {
		t.Fatalf("refresh help omits the required scopes flag: %q", texts["refresh"])
	}
	if strings.Contains(texts["refresh"], "must include offline_access") {
		t.Fatalf("refresh help requires offline_access: %q", texts["refresh"])
	}
	if !strings.Contains(personalHelpText, "onedrive login|refresh") {
		t.Fatalf("personal usage omits refresh: %q", personalHelpText)
	}
	if !strings.Contains(usage, "personal onedrive login|refresh") {
		t.Fatalf("top-level usage omits refresh: %q", usage)
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

// fakeOnedriveRefreshSource is the injected refresh source of the CLI tests. It
// records the one AccessToken call and Close calls; it never touches the network
// or the credential store.
type fakeOnedriveRefreshSource struct {
	token  string
	err    error
	calls  int
	closes int
}

func (s *fakeOnedriveRefreshSource) AccessToken(context.Context) (string, error) {
	s.calls++
	return s.token, s.err
}

func (s *fakeOnedriveRefreshSource) Close() { s.closes++ }

// withOnedriveRefreshSeams serves one hidden label and one fake source through
// the production factory seam, recording the config the CLI hands the factory.
// t.Cleanup restores both seams.
func withOnedriveRefreshSeams(t *testing.T, src *fakeOnedriveRefreshSource, seen *onedriveauth.RefreshSourceConfig) {
	t.Helper()
	prompt, factory := promptProfileLabel, newOnedriveRefreshSource
	t.Cleanup(func() { promptProfileLabel, newOnedriveRefreshSource = prompt, factory })
	promptProfileLabel = func(context.Context) ([]byte, error) { return []byte(testLabel), nil }
	newOnedriveRefreshSource = func(cfg onedriveauth.RefreshSourceConfig) (onedriveRefreshSource, error) {
		if seen != nil {
			// The command clears its hidden label after the factory returns,
			// so record the bytes as the production factory would receive them.
			*seen = cfg
			seen.Profile = append([]byte(nil), cfg.Profile...)
			seen.Scopes = append([]string(nil), cfg.Scopes...)
		}
		return src, nil
	}
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

func TestOnedriveRefreshWiringAndReceipt(t *testing.T) {
	const accessToken = "canary-access-token"
	src := &fakeOnedriveRefreshSource{token: accessToken}
	var seen onedriveauth.RefreshSourceConfig
	withOnedriveRefreshSeams(t, src, &seen)
	args := []string{"refresh", "--client-id", testClientID, "--tenant", testTenant, "--scopes", "Files.Read Files.ReadWrite"}
	var out bytes.Buffer
	if err := runPersonalOnedrive(args, &out); err != nil {
		t.Fatalf("refresh = %v", err)
	}
	wantScopes := []string{"Files.Read", "Files.ReadWrite"}
	if seen.ClientID != testClientID || seen.Tenant != testTenant || string(seen.Profile) != testLabel {
		t.Fatalf("factory config = (%q, %q, %q), want (%q, %q, %q)", seen.ClientID, seen.Tenant, string(seen.Profile), testClientID, testTenant, testLabel)
	}
	if !reflect.DeepEqual(seen.Scopes, wantScopes) {
		t.Fatalf("factory scopes = %q, want %q", seen.Scopes, wantScopes)
	}
	if hasScope(seen.Scopes, "offline_access") {
		t.Fatalf("factory scopes added offline_access: %q", seen.Scopes)
	}
	if seen.Timeout != 0 {
		t.Fatalf("factory timeout = %v, want the zero value", seen.Timeout)
	}
	if src.calls != 1 || src.closes != 1 {
		t.Fatalf("source calls = %d, closes = %d, want 1 and 1", src.calls, src.closes)
	}
	if got := out.String(); got != onedriveRefreshDone {
		t.Fatalf("refresh output = %q, want %q", got, onedriveRefreshDone)
	}
	for _, secret := range []string{accessToken, testLabel, testClientID, testTenant, "Files.Read", "Files.ReadWrite", "offline_access", "verified", "Graph"} {
		if strings.Contains(out.String(), secret) {
			t.Fatalf("refresh output leaks %q: %q", secret, out.String())
		}
	}
}

func TestOnedriveRefreshErrorMappings(t *testing.T) {
	const leak = "canary-provider-body canary-access-token canary-refresh-token canary-label canary-client-id canary.example Files.Read https://login.example/token"
	cases := []struct {
		name     string
		err      error
		want     error
		retained error
		not      []error
	}{
		{
			name:     "pre-send cancellation",
			err:      errors.Join(onedriveauth.ErrRefreshCancelled, errors.New(leak)),
			want:     errOnedriveRefreshPre,
			retained: onedriveauth.ErrRefreshCancelled,
			not:      []error{errOnedriveRefreshUnknown, errOnedriveRefreshStoreUnknown},
		},
		{
			name:     "post-send outcome unknown",
			err:      errors.Join(onedriveauth.ErrRefreshOutcomeUnknown, errors.New(leak)),
			want:     errOnedriveRefreshUnknown,
			retained: onedriveauth.ErrRefreshOutcomeUnknown,
			not:      []error{errOnedriveRefreshPre, errOnedriveRefreshStoreUnknown},
		},
		{
			name: "caller cancellation after starting",
			err:  context.Canceled,
			want: errOnedriveRefreshUnknown,
			not:  []error{errOnedriveRefreshPre, errOnedriveRefreshStoreUnknown},
		},
		{
			name:     "validated replacement save unknown",
			err:      errors.Join(onedriveauth.ErrSourceStoreUnknown, errors.New(leak)),
			want:     errOnedriveRefreshStoreUnknown,
			retained: onedriveauth.ErrSourceStoreUnknown,
			not:      []error{errOnedriveRefreshPre, errOnedriveRefreshUnknown},
		},
		{
			name:     "provider status",
			err:      errors.Join(onedriveauth.ErrRefreshStatus, errors.New(leak)),
			want:     errOnedriveRefreshFailed,
			retained: onedriveauth.ErrRefreshStatus,
			not:      []error{errOnedriveRefreshPre, errOnedriveRefreshUnknown, errOnedriveRefreshStoreUnknown},
		},
		{
			name: "arbitrary source failure",
			err:  errors.New(leak),
			want: errOnedriveRefreshFailed,
			not:  []error{errOnedriveRefreshPre, errOnedriveRefreshUnknown, errOnedriveRefreshStoreUnknown},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := &fakeOnedriveRefreshSource{err: tc.err}
			withOnedriveRefreshSeams(t, src, nil)
			args := []string{"refresh", "--client-id", testClientID, "--tenant", testTenant, "--scopes", "Files.Read"}
			var out bytes.Buffer
			err := runPersonalOnedrive(args, &out)
			if err == nil || !errors.Is(err, tc.want) {
				t.Fatalf("refresh with %v = %v, want %v", tc.err, err, tc.want)
			}
			if tc.retained != nil && !errors.Is(err, tc.retained) {
				t.Fatalf("refresh with %v = %v, does not retain %v", tc.err, err, tc.retained)
			}
			for _, other := range tc.not {
				if errors.Is(err, other) {
					t.Fatalf("refresh with %v = %v, unexpectedly reports %v", tc.err, err, other)
				}
			}
			for _, secret := range []string{"canary-provider-body", "canary-access-token", "canary-refresh-token", "canary-label", "canary-client-id", "canary.example", "Files.Read", "https://login.example/token"} {
				if strings.Contains(err.Error(), secret) {
					t.Fatalf("refresh with %v error leaks %q: %q", tc.err, secret, err.Error())
				}
			}
			if out.Len() != 0 {
				t.Fatalf("refresh output = %q, want empty", out.String())
			}
			if src.calls != 1 || src.closes != 1 {
				t.Fatalf("source calls = %d, closes = %d, want 1 and 1", src.calls, src.closes)
			}
		})
	}
}

func TestOnedriveRefreshCancelledBeforeStart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	old := newOnedriveRefreshSource
	t.Cleanup(func() { newOnedriveRefreshSource = old })
	called := false
	newOnedriveRefreshSource = func(onedriveauth.RefreshSourceConfig) (onedriveRefreshSource, error) {
		called = true
		return &fakeOnedriveRefreshSource{}, nil
	}
	receipt, err := onedriveRefresh(ctx, onedriveauth.AuthorizeConfig{
		ClientID: testClientID,
		Tenant:   testTenant,
		Scopes:   []string{"Files.Read"},
	}, []byte(testLabel))
	if receipt != "" {
		t.Fatalf("cancelled refresh receipt = %q, want empty", receipt)
	}
	if !errors.Is(err, errOnedriveRefreshPre) || !errors.Is(err, onedriveauth.ErrRefreshCancelled) {
		t.Fatalf("cancelled refresh = %v, want %v and %v", err, errOnedriveRefreshPre, onedriveauth.ErrRefreshCancelled)
	}
	if errors.Is(err, errOnedriveRefreshUnknown) || errors.Is(err, errOnedriveRefreshStoreUnknown) {
		t.Fatalf("pre-send cancellation reports an unknown outcome: %v", err)
	}
	if called {
		t.Fatal("a refresh cancelled before start invoked the source factory")
	}
	for _, secret := range []string{testLabel, testClientID, testTenant, "Files.Read"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("pre-send cancellation error leaks %q: %q", secret, err.Error())
		}
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
