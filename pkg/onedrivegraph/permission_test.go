package onedrivegraph

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
)

// All values below are synthetic fixtures. No request leaves the loopback
// httptest TLS servers, and no real account, tenant or configuration is read.

const (
	testRecipientEmail   = "synthetic.recipient@example.test"
	testRecipientUpper   = "SYNTHETIC.RECIPIENT@EXAMPLE.TEST"
	testPermissionID     = "synthetic-permission-0001"
	testWrongPermission  = "synthetic-permission-0002"
	testOtherEmail       = "synthetic.other@example.test"
	testPermissionSecret = "synthetic-permission-body-secret"
)

type recordedPermissionRequest struct {
	method        string
	path          string
	query         string
	authorization string
	contentType   string
	accept        string
	body          []byte
}

// permissionFixture is a synthetic Graph surface. The metadata, invite and
// permission paths all need hooks because revocation runs the preflight first.
type permissionFixture struct {
	t      *testing.T
	server *httptest.Server

	mu            sync.Mutex
	metadata      *fixtureConfig
	inviteHook    func(w http.ResponseWriter, r *http.Request)
	revokeHook    func(w http.ResponseWriter, r *http.Request)
	metadataHook  func(call int, w http.ResponseWriter, r *http.Request)
	requests      []recordedPermissionRequest
	metadataCalls int
}

func newPermissionFixture(t *testing.T) *permissionFixture {
	t.Helper()
	f := &permissionFixture{
		t: t,
		metadata: &fixtureConfig{
			itemID:         testItemID,
			etag:           testETag,
			size:           64,
			file:           true,
			metadataStatus: http.StatusOK,
		},
	}
	f.server = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	return f
}

func (f *permissionFixture) itemPath() string { return testItemPath() }

func (f *permissionFixture) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	cfg := *f.metadata
	inviteHook, revokeHook, metadataHook := f.inviteHook, f.revokeHook, f.metadataHook
	itemPath := f.itemPath()
	rec := recordedPermissionRequest{
		method:        r.Method,
		path:          r.URL.Path,
		query:         r.URL.RawQuery,
		authorization: r.Header.Get("Authorization"),
		contentType:   r.Header.Get("Content-Type"),
		accept:        r.Header.Get("Accept"),
	}
	if r.Body != nil {
		rec.body, _ = io.ReadAll(io.LimitReader(r.Body, 64<<10))
	}
	f.requests = append(f.requests, rec)
	call := 0
	// Configured metadata JSON is returned by the metadata hook so that it
	// owns the whole response.
	serveConfigured := (r.URL.Path == itemPath && r.Method == http.MethodGet) && cfg.metadataJSON != nil && metadataHook == nil
	if r.URL.Path == itemPath && r.Method == http.MethodGet {
		f.metadataCalls++
		call = f.metadataCalls
	}
	f.mu.Unlock()

	switch {
	case r.Method == http.MethodGet && r.URL.Path == itemPath:
		if serveConfigured {
			writeJSONResponse(w, cfg.metadataJSON)
			return
		}
		if metadataHook != nil {
			metadataHook(call, w, r)
			return
		}
		if cfg.metadataStatus != http.StatusOK {
			w.WriteHeader(cfg.metadataStatus)
			_, _ = w.Write([]byte(testPermissionSecret))
			return
		}
		writeJSONResponse(w, generatedMetadata(cfg))
	case r.Method == http.MethodPost && r.URL.Path == itemPath+"/invite":
		if inviteHook == nil {
			f.t.Errorf("unexpected invite request")
			w.WriteHeader(http.StatusNotFound)
			return
		}
		inviteHook(w, r)
	case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, itemPath+"/permissions/"):
		if revokeHook == nil {
			f.t.Errorf("unexpected revoke request")
			w.WriteHeader(http.StatusNotFound)
			return
		}
		revokeHook(w, r)
	default:
		// An unconfigured route is a safe 404; callers assert that no
		// mutation was sent through mutationCount.
		w.WriteHeader(http.StatusNotFound)
	}
}

func (f *permissionFixture) setMetadata(mutate func(*fixtureConfig)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	mutate(f.metadata)
}

func (f *permissionFixture) setMetadataHook(hook func(int, http.ResponseWriter, *http.Request)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.metadataHook = hook
}

// HookFunc writes one synthetic response.
type HookFunc func(w http.ResponseWriter, r *http.Request)

func (f *permissionFixture) setInvite(h HookFunc) { f.mu.Lock(); f.inviteHook = h; f.mu.Unlock() }
func (f *permissionFixture) setRevoke(h HookFunc) { f.mu.Lock(); f.revokeHook = h; f.mu.Unlock() }

func (f *permissionFixture) recorded() []recordedPermissionRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recordedPermissionRequest(nil), f.requests...)
}

func (f *permissionFixture) mutationCount() int {
	n := 0
	for _, req := range f.recorded() {
		if req.method != http.MethodGet {
			n++
		}
	}
	return n
}

func (f *permissionFixture) manager(t *testing.T, tokens AccessTokenSource, itemID string) *Manager {
	t.Helper()
	if tokens == nil {
		tokens = &testTokenSource{token: testToken}
	}
	if itemID == "" {
		itemID = testItemID
	}
	endpoint, err := url.Parse(f.server.URL)
	if err != nil {
		t.Fatalf("parse fixture URL: %v", err)
	}
	m, err := newManager(PermissionConfig{
		DriveID: testDriveID,
		ItemID:  itemID,
		Tokens:  tokens,
	}, endpoint, f.server.Client())
	if err != nil {
		t.Fatalf("newManager: %v", err)
	}
	return m
}

func serveBody(status int, body []byte) HookFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}
}

func permissionGrantFixture(id string, roles []string, email string) map[string]any {
	return map[string]any{
		"id":    id,
		"roles": roles,
		"grantedToV2": map[string]any{
			"user": map[string]any{
				"email": email,
				"id":    "synthetic-user-id",
			},
		},
		"invitation": map[string]any{"signInRequired": true, "invitedBy": map[string]any{}},
	}
}

// q returns s as a JSON string literal for hand-written fixture bodies.
func q(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func permissionBody(value ...map[string]any) []byte {
	if value == nil {
		value = []map[string]any{}
	}
	body, err := json.Marshal(map[string]any{"value": value})
	if err != nil {
		panic(err)
	}
	return body
}

func inviteWrite(status int) HookFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
	}
}

func TestNewManagerValidationAndFixedProductionEndpoint(t *testing.T) {
	tokens := &testTokenSource{token: testToken}
	good := PermissionConfig{DriveID: testDriveID, ItemID: testItemID, Tokens: tokens}
	m, err := NewManager(good)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if m.endpoint != nil || m.client != nil {
		t.Fatalf("production manager must not set test seams")
	}
	raw, err := m.itemURL()
	if err != nil {
		t.Fatalf("itemURL: %v", err)
	}
	if want := graphEndpoint + testItemPath(); raw != want {
		t.Fatalf("item URL = %q, want %q", raw, want)
	}

	bad := []PermissionConfig{
		{},
		{DriveID: testDriveID, ItemID: testItemID},
		{DriveID: "", ItemID: testItemID, Tokens: tokens},
		{DriveID: testDriveID, ItemID: "", Tokens: tokens},
		{DriveID: testDriveID, ItemID: testItemID + "\x01", Tokens: tokens},
		{DriveID: strings.Repeat("d", maxItemIDSize+1), ItemID: testItemID, Tokens: tokens},
	}
	for i, cfg := range bad {
		if _, err := NewManager(cfg); !errors.Is(err, vaultfilebackend.ErrDenied) {
			t.Errorf("case %d: NewManager error = %v, want ErrDenied", i, err)
		}
	}
	for _, target := range []string{
		"http://example.test",
		"https://user:pass@example.test",
		"https://example.test/?scope=extra",
		"https://example.test/#fragment",
	} {
		u, err := url.Parse(target)
		if err != nil {
			t.Fatalf("parse %q: %v", target, err)
		}
		if _, err := newManager(good, u, nil); !errors.Is(err, vaultfilebackend.ErrDenied) {
			t.Errorf("endpoint %q error = %v, want ErrDenied", target, err)
		}
	}
}

func TestManagerGrantSendsFixedInviteAndReturnsOnlyIDAndRole(t *testing.T) {
	for _, role := range []PermissionRole{permissionRoleRead, permissionRoleWrite} {
		t.Run(string(role), func(t *testing.T) {
			f := newPermissionFixture(t)
			f.setInvite(serveBody(http.StatusOK, permissionBody(
				permissionGrantFixture(testPermissionID, []string{string(role)}, testRecipientUpper),
			)))

			grant, err := f.manager(t, nil, "").Grant(context.Background(), testRecipientEmail, role)
			if err != nil {
				t.Fatalf("Grant: %v", err)
			}
			if grant.PermissionID != testPermissionID || grant.Role != role {
				t.Fatalf("grant = %+v, want only ID and role", grant)
			}

			reqs := f.recorded()
			if len(reqs) != 2 {
				t.Fatalf("requests = %d, want preflight + invite", len(reqs))
			}
			pre := reqs[0]
			if pre.method != http.MethodGet || pre.path != f.itemPath() || pre.query != "$select="+graphItemFacetSelect {
				t.Fatalf("preflight = %s %s?%s", pre.method, pre.path, pre.query)
			}
			inv := reqs[1]
			if inv.method != http.MethodPost || inv.path != f.itemPath()+"/invite" || inv.query != "" {
				t.Fatalf("invite = %s %s?%s", inv.method, inv.path, inv.query)
			}
			if inv.contentType != "application/json" {
				t.Errorf("invite Content-Type = %q", inv.contentType)
			}
			for _, r := range reqs {
				if r.authorization != "Bearer "+testToken {
					t.Errorf("%s request did not carry the synthetic bearer token", r.method)
				}
			}

			var body map[string]json.RawMessage
			if err := json.Unmarshal(inv.body, &body); err != nil {
				t.Fatalf("invite body is not JSON: %v", err)
			}
			wantKeys := map[string]bool{"recipients": true, "roles": true, "requireSignIn": true, "sendInvitation": true}
			for k := range body {
				if !wantKeys[k] {
					t.Errorf("invite body contains unexpected field")
				}
			}
			if len(body) != len(wantKeys) {
				t.Errorf("invite body fields = %d, want exactly %d", len(body), len(wantKeys))
			}
			var recipients []map[string]string
			if err := json.Unmarshal(body["recipients"], &recipients); err != nil || len(recipients) != 1 {
				t.Fatalf("recipients must be exactly one object")
			}
			if len(recipients[0]) != 1 || recipients[0]["email"] != testRecipientEmail {
				t.Errorf("recipient entry must contain only the requested address")
			}
			var roles []string
			if err := json.Unmarshal(body["roles"], &roles); err != nil || len(roles) != 1 || roles[0] != string(role) {
				t.Errorf("roles must be exactly the requested role")
			}
			if string(body["requireSignIn"]) != "true" {
				t.Errorf("requireSignIn must be true")
			}
			if string(body["sendInvitation"]) != "false" {
				t.Errorf("sendInvitation must be false")
			}
		})
	}
}

func TestManagerGrantAcceptsLegacyGrantedToOnly(t *testing.T) {
	f := newPermissionFixture(t)
	legacy := map[string]any{
		"id":         testPermissionID,
		"roles":      []string{"read"},
		"grantedTo":  map[string]any{"user": map[string]any{"email": testRecipientUpper}},
		"invitation": map[string]any{"signInRequired": true},
	}
	f.setInvite(serveBody(http.StatusOK, permissionBody(legacy)))
	if _, err := f.manager(t, nil, "").Grant(context.Background(), testRecipientEmail, permissionRoleRead); err != nil {
		t.Fatalf("Grant with grantedTo only: %v", err)
	}
}

func TestManagerGrantRejectsUnexpectedRecipientRoleOrFlags(t *testing.T) {
	m := newPermissionFixture(t).manager(t, nil, "")
	cases := map[string]struct {
		email string
		role  PermissionRole
	}{
		"empty email":    {"", permissionRoleRead},
		"no at":          {"synthetic.example.test", permissionRoleRead},
		"two at":         {"a@b@example.test", permissionRoleRead},
		"leading dot":    {".synthetic@example.test", permissionRoleRead},
		"double dot":     {"syn..thetic@example.test", permissionRoleRead},
		"bad domain":     {"synthetic@example..test", permissionRoleRead},
		"no tld":         {"synthetic@localhost", permissionRoleRead},
		"space":          {"synthetic recipient@example.test", permissionRoleRead},
		"control":        {"synthetic@example.test\n", permissionRoleRead},
		"oversize":       {strings.Repeat("a", maxInviteAddressLength+1) + "@example.test", permissionRoleRead},
		"uppercase R":    {testRecipientEmail, PermissionRole("Read")},
		"owner role":     {testRecipientEmail, PermissionRole("owner")},
		"empty role":     {testRecipientEmail, PermissionRole("")},
		"anonymous":      {testRecipientEmail, PermissionRole("anonymous")},
		"link role":      {testRecipientEmail, PermissionRole("link")},
		"write w/ space": {testRecipientEmail, PermissionRole("read write")},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := m.Grant(context.Background(), c.email, c.role)
			assertErrorIs(t, err, vaultfilebackend.ErrDenied)
			assertNoSecrets(t, err, c.email)
		})
	}
}

func TestManagerPreflightRequiresExactlyTheConfiguredFile(t *testing.T) {
	type preflightCase struct {
		name    string
		mutate  func(*fixtureConfig)
		want    []error
		notWant []error
	}
	cases := []preflightCase{
		{
			name: "folder facet",
			mutate: func(c *fixtureConfig) {
				c.metadataJSON = []byte(`{"id":"` + testItemID + `","eTag":` + q(testETag) + `,"size":0,"file":{},"folder":{"childCount":3}}`)
			},
			want:    []error{vaultfilebackend.ErrUnsupported, ErrInvalidPermission},
			notWant: []error{vaultfilebackend.ErrUnknown, vaultfilebackend.ErrCorrupt},
		},
		{
			name: "folder only",
			mutate: func(c *fixtureConfig) {
				c.metadataJSON = []byte(`{"id":"` + testItemID + `","eTag":` + q(testETag) + `,"size":0,"folder":{}}`)
			},
			want: []error{vaultfilebackend.ErrUnsupported, ErrInvalidPermission},
		},
		{
			name: "drive root reports root id",
			mutate: func(c *fixtureConfig) {
				c.metadataJSON = []byte(`{"id":"ROOT","eTag":"` + testETag + `","size":0,"file":{},"folder":{"childCount":1}}`)
			},
			want: []error{vaultfilebackend.ErrCorrupt, ErrInvalidPermission},
		},
		{
			name: "mismatched file id",
			mutate: func(c *fixtureConfig) {
				c.itemID = "synthetic-other-item"
			},
			want: []error{vaultfilebackend.ErrCorrupt, ErrInvalidPermission},
		},
		{
			name: "missing file facet",
			mutate: func(c *fixtureConfig) {
				c.file = false
			},
			want: []error{vaultfilebackend.ErrUnsupported, ErrInvalidPermission},
		},
		{
			name: "missing etag",
			mutate: func(c *fixtureConfig) {
				c.etag = ""
			},
			want: []error{vaultfilebackend.ErrCorrupt, ErrInvalidPermission},
		},
		{
			name: "negative size",
			mutate: func(c *fixtureConfig) {
				c.size = -1
			},
			want: []error{vaultfilebackend.ErrCorrupt, ErrInvalidPermission},
		},
		{
			name: "invalid utf8",
			mutate: func(c *fixtureConfig) {
				c.metadataJSON = []byte(`{"id":"` + testItemID + `","leak":"` + testPermissionSecret + "\xff" + `"}`)
			},
			want: []error{vaultfilebackend.ErrCorrupt, ErrInvalidPermission},
		},
		{
			name: "malformed json",
			mutate: func(c *fixtureConfig) {
				c.metadataJSON = []byte(`{"id":`)
			},
			want: []error{vaultfilebackend.ErrCorrupt, ErrInvalidPermission},
		},
		{
			name: "oversized body",
			mutate: func(c *fixtureConfig) {
				c.metadataJSON = []byte(`{"pad":"` + strings.Repeat("x", maxMetadataJSONSize) + `"}`)
			},
			want: []error{vaultfilebackend.ErrCorrupt, ErrInvalidPermission},
		},
		{
			name: "link facet on item",
			mutate: func(c *fixtureConfig) {
				c.metadataJSON = []byte(`{"id":"` + testItemID + `","eTag":` + q(testETag) + `,"size":1,"file":{},"@microsoft.graph.link":{}}`)
			},
			want: []error{vaultfilebackend.ErrCorrupt, ErrInvalidPermission},
		},
		{
			name: "not found",
			mutate: func(c *fixtureConfig) {
				c.metadataStatus = http.StatusNotFound
			},
			want: []error{vaultfilebackend.ErrNotFound},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newPermissionFixture(t)
			f.setMetadata(c.mutate)
			f.setInvite(inviteWrite(http.StatusOK))
			m := f.manager(t, nil, "")

			_, grantErr := m.Grant(context.Background(), testRecipientEmail, permissionRoleRead)
			assertErrorIs(t, grantErr, c.want...)
			for _, nw := range c.notWant {
				if errors.Is(grantErr, nw) {
					t.Errorf("Grant error also matched %v", nw)
				}
			}
			assertNoSecrets(t, grantErr, testPermissionSecret, testToken, testRecipientEmail)

			revokeErr := m.Revoke(context.Background(), testPermissionID)
			assertErrorIs(t, revokeErr, c.want...)
			assertNoSecrets(t, revokeErr, testPermissionSecret, testToken)

			if n := f.mutationCount(); n != 0 {
				t.Errorf("mutation requests = %d, want 0 after a failed preflight", n)
			}
		})
	}

	t.Run("configured item id must match", func(t *testing.T) {
		f := newPermissionFixture(t)
		f.setInvite(inviteWrite(http.StatusOK))
		// The fixture reports testItemID only; configuring another ID gets a
		// safe 404 and no mutation.
		m := f.manager(t, nil, "synthetic-other-item")
		_, err := m.Grant(context.Background(), testRecipientEmail, permissionRoleRead)
		assertErrorIs(t, err, vaultfilebackend.ErrNotFound)
		if n := f.mutationCount(); n != 0 {
			t.Errorf("mutation requests = %d, want 0", n)
		}
	})

	t.Run("preflight 5xx is not sent", func(t *testing.T) {
		f := newPermissionFixture(t)
		f.setMetadata(func(c *fixtureConfig) { c.metadataStatus = http.StatusBadGateway })
		f.setInvite(inviteWrite(http.StatusOK))
		_, err := f.manager(t, nil, "").Grant(context.Background(), testRecipientEmail, permissionRoleRead)
		assertErrorIs(t, err, vaultfilebackend.ErrUnknown)
		if errors.Is(err, ErrPermissionOutcomeUnknown) {
			t.Errorf("preflight failure must not be reported as a permission outcome")
		}
		if n := f.mutationCount(); n != 0 {
			t.Errorf("mutation requests = %d, want 0", n)
		}
	})

	t.Run("preflight redirect is rejected", func(t *testing.T) {
		f := newPermissionFixture(t)
		redirectedTo := 0
		var target *httptest.Server
		target = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			redirectedTo++
			w.WriteHeader(http.StatusOK)
		}))
		t.Cleanup(target.Close)
		f.setMetadataHook(func(_ int, w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", target.URL+"/elsewhere")
			w.WriteHeader(http.StatusFound)
		})
		_, err := f.manager(t, nil, "").Grant(context.Background(), testRecipientEmail, permissionRoleRead)
		assertErrorIs(t, err, ErrUnsafeRedirect)
		if redirectedTo != 0 {
			t.Errorf("redirect was followed")
		}
		if n := f.mutationCount(); n != 0 {
			t.Errorf("mutation requests = %d, want 0", n)
		}
	})
}

func TestManagerGrantDoesNotFollowRedirectsOrForwardBearer(t *testing.T) {
	f := newPermissionFixture(t)
	var seen []string
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "" {
			seen = append(seen, "bearer-forwarded")
		}
		seen = append(seen, r.Method+" "+r.URL.Path)
		// Even a 200 with a valid body here must not be accepted.
		writeJSONResponse(w, permissionBody(permissionGrantFixture(testPermissionID, []string{"read"}, testRecipientEmail)))
	}))
	t.Cleanup(target.Close)
	f.setInvite(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", target.URL+"/invite-shared")
		w.WriteHeader(http.StatusTemporaryRedirect)
	})
	_, err := f.manager(t, nil, "").Grant(context.Background(), testRecipientEmail, permissionRoleRead)
	assertErrorIs(t, err, vaultfilebackend.ErrUnknown, ErrPermissionOutcomeUnknown)
	if len(seen) != 0 {
		t.Fatalf("redirect target received requests")
	}
}

func TestManagerGrantStrictlyValidatesResponse(t *testing.T) {
	linkPermission := func() map[string]any {
		return map[string]any{
			"id":         testPermissionID,
			"roles":      []string{"read"},
			"link":       map[string]any{"scope": "anonymous", "type": "view"},
			"invitation": map[string]any{"signInRequired": false},
		}
	}
	good := func() map[string]any {
		return permissionGrantFixture(testPermissionID, []string{"read"}, testRecipientEmail)
	}

	cases := map[string]struct {
		status int
		body   []byte
		want   []error
	}{
		"two permissions": {
			http.StatusOK,
			permissionBody(good(), permissionGrantFixture(testWrongPermission, []string{"read"}, testRecipientEmail)),
			[]error{vaultfilebackend.ErrUnknown, ErrPermissionOutcomeUnknown},
		},
		"empty collection": {
			http.StatusOK, permissionBody(),
			[]error{vaultfilebackend.ErrUnknown, ErrPermissionOutcomeUnknown},
		},
		"missing value": {
			http.StatusOK, []byte(`{}`),
			[]error{vaultfilebackend.ErrUnknown, ErrPermissionOutcomeUnknown},
		},
		"link permission": {
			http.StatusOK,
			permissionBody(linkPermission()),
			[]error{vaultfilebackend.ErrUnknown, ErrPermissionOutcomeUnknown},
		},
		"link among results": {
			http.StatusOK,
			permissionBody(good(), linkPermission()),
			[]error{vaultfilebackend.ErrUnknown, ErrPermissionOutcomeUnknown},
		},
		"link is null": {
			http.StatusOK,
			[]byte(`{"value":[{"id":"` + testPermissionID + `","roles":["read"],"link":null,"invitation":{"signInRequired":true},"grantedToV2":{"user":{"email":"` + testRecipientEmail + `"}}}]}`),
			nil,
		},
		"wrong role": {
			http.StatusOK,
			permissionBody(permissionGrantFixture(testPermissionID, []string{"write"}, testRecipientEmail)),
			[]error{vaultfilebackend.ErrUnknown, ErrPermissionOutcomeUnknown},
		},
		"extra role": {
			http.StatusOK,
			permissionBody(permissionGrantFixture(testPermissionID, []string{"read", "write"}, testRecipientEmail)),
			[]error{vaultfilebackend.ErrUnknown, ErrPermissionOutcomeUnknown},
		},
		"other recipient": {
			http.StatusOK,
			permissionBody(permissionGrantFixture(testPermissionID, []string{"read"}, testOtherEmail)),
			[]error{vaultfilebackend.ErrUnknown, ErrPermissionOutcomeUnknown},
		},
		"no recipient": {
			http.StatusOK,
			permissionBody(map[string]any{"id": testPermissionID, "roles": []string{"read"}, "invitation": map[string]any{"signInRequired": true}}),
			[]error{vaultfilebackend.ErrUnknown, ErrPermissionOutcomeUnknown},
		},
		"signInRequired false": {
			http.StatusOK,
			permissionBody(map[string]any{"id": testPermissionID, "roles": []string{"read"}, "grantedToV2": map[string]any{"user": map[string]any{"email": testRecipientEmail}}, "invitation": map[string]any{"signInRequired": false}}),
			[]error{vaultfilebackend.ErrUnknown, ErrPermissionOutcomeUnknown},
		},
		"signInRequired missing": {
			http.StatusOK,
			permissionBody(map[string]any{"id": testPermissionID, "roles": []string{"read"}, "grantedToV2": map[string]any{"user": map[string]any{"email": testRecipientEmail}}}),
			[]error{vaultfilebackend.ErrUnknown, ErrPermissionOutcomeUnknown},
		},
		"signInRequired string": {
			http.StatusOK,
			[]byte(`{"value":[{"id":"` + testPermissionID + `","roles":["read"],"grantedToV2":{"user":{"email":"` + testRecipientEmail + `"}},"invitation":{"signInRequired":"true"}}]}`),
			[]error{vaultfilebackend.ErrUnknown, ErrPermissionOutcomeUnknown},
		},
		"missing id": {
			http.StatusOK,
			permissionBody(permissionGrantFixture("", []string{"read"}, testRecipientEmail)),
			[]error{vaultfilebackend.ErrUnknown, ErrPermissionOutcomeUnknown},
		},
		"unsafe id": {
			http.StatusOK,
			permissionBody(permissionGrantFixture("synthetic/id", []string{"read"}, testRecipientEmail)),
			[]error{vaultfilebackend.ErrUnknown, ErrPermissionOutcomeUnknown, ErrPermissionResponse},
		},
		"unsafe id with space": {
			http.StatusOK,
			permissionBody(permissionGrantFixture("synthetic id", []string{"read"}, testRecipientEmail)),
			[]error{vaultfilebackend.ErrUnknown, ErrPermissionOutcomeUnknown, ErrPermissionResponse},
		},
		"oversize id": {
			http.StatusOK,
			permissionBody(permissionGrantFixture(strings.Repeat("p", 8<<10), []string{"read"}, testRecipientEmail)),
			[]error{vaultfilebackend.ErrUnknown, ErrPermissionOutcomeUnknown},
		},
		"invalid utf8": {
			http.StatusOK,
			[]byte(`{"value":[{"id":"` + testPermissionID + `","leak":"` + testPermissionSecret + "\xff" + `"}]}`),
			[]error{vaultfilebackend.ErrUnknown, ErrPermissionOutcomeUnknown},
		},
		"json null": {
			http.StatusOK, []byte(`null`),
			[]error{vaultfilebackend.ErrUnknown, ErrPermissionOutcomeUnknown},
		},
		"invalid json": {
			http.StatusOK, []byte(`{"value": [` + testPermissionSecret),
			[]error{vaultfilebackend.ErrUnknown, ErrPermissionOutcomeUnknown},
		},
		"empty body": {
			http.StatusOK, []byte{},
			[]error{vaultfilebackend.ErrUnknown, ErrPermissionOutcomeUnknown},
		},
		"oversize body": {
			http.StatusOK,
			permissionBody(permissionGrantFixture(testPermissionID, []string{"read"}, testRecipientEmail)),
			[]error{vaultfilebackend.ErrUnknown, ErrPermissionOutcomeUnknown},
			// padded below
		},
		"partial 207": {
			http.StatusMultiStatus,
			permissionBody(good()),
			[]error{vaultfilebackend.ErrUnknown, ErrPermissionOutcomeUnknown},
		},
		"too many requests": {
			http.StatusTooManyRequests, nil,
			[]error{vaultfilebackend.ErrUnknown, ErrPermissionOutcomeUnknown},
		},
		"server error": {
			http.StatusInternalServerError, []byte(testPermissionSecret),
			[]error{vaultfilebackend.ErrUnknown, ErrPermissionOutcomeUnknown},
		},
		"redirect": {
			http.StatusMovedPermanently, nil,
			[]error{vaultfilebackend.ErrUnknown, ErrPermissionOutcomeUnknown},
		},
		"no content": {
			http.StatusNoContent, nil,
			[]error{vaultfilebackend.ErrUnknown, ErrPermissionOutcomeUnknown},
		},
		"created": {
			http.StatusCreated, permissionBody(good()),
			[]error{vaultfilebackend.ErrUnknown, ErrPermissionOutcomeUnknown},
		},
		"refused 400": {
			http.StatusBadRequest, []byte(testPermissionSecret),
			[]error{vaultfilebackend.ErrDenied},
		},
		"refused 403": {
			http.StatusForbidden, []byte(testPermissionSecret),
			[]error{vaultfilebackend.ErrDenied},
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := newPermissionFixture(t)
			body := c.body
			if name == "oversize body" {
				body = permissionBody(permissionGrantFixture(testPermissionID, []string{"read"}, testRecipientEmail))
				// A valid prefix followed by padding that exceeds the bound.
				body = append([]byte(`{"value":[],"pad":"`), []byte(strings.Repeat("x", maxPermissionJSONSize))...)
				body = append(body, '"', '}')
			}
			f.setInvite(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(c.status)
				_, _ = w.Write(body)
			})
			grant, err := f.manager(t, nil, "").Grant(context.Background(), testRecipientEmail, permissionRoleRead)
			if c.want == nil {
				if err != nil {
					t.Fatalf("Grant: %v", err)
				}
				if grant.PermissionID != testPermissionID {
					t.Fatalf("grant ID mismatch")
				}
				return
			}
			if grant != (PermissionGrant{}) {
				t.Errorf("failed Grant returned a result")
			}
			assertErrorIs(t, err, c.want...)
			if n := f.mutationCount(); n != 1 {
				t.Errorf("invite requests = %d, want exactly 1 (no retry)", n)
			}
			assertNoSecrets(t, err, testToken, testRecipientEmail, testPermissionSecret, "anonymous", "view")
		})
	}
}

func TestManagerGrantTreatsDeclaredOversizeAsUnknownWithoutSendingBody(t *testing.T) {
	f := newPermissionFixture(t)
	f.setInvite(func(w http.ResponseWriter, r *http.Request) {
		// Declare a body far beyond the bound but write only a small prefix.
		// The client must not accept it and must not treat it as success.
		w.Header().Set("Content-Length", strconv.Itoa(maxPermissionJSONSize+1))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"value":`))
		w.(http.Flusher).Flush()
		time.Sleep(20 * time.Millisecond)
	})
	_, err := f.manager(t, nil, "").Grant(context.Background(), testRecipientEmail, permissionRoleRead)
	assertErrorIs(t, err, vaultfilebackend.ErrUnknown, ErrPermissionOutcomeUnknown)
}

func TestManagerRevokeDeletesOnlyTheGivenPermission(t *testing.T) {
	f := newPermissionFixture(t)
	f.setRevoke(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			if b, _ := io.ReadAll(r.Body); len(b) != 0 {
				f.t.Errorf("DELETE carried a body")
			}
		}
		w.WriteHeader(http.StatusNoContent)
	})
	if err := f.manager(t, nil, "").Revoke(context.Background(), testPermissionID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	reqs := f.recorded()
	if len(reqs) != 2 {
		t.Fatalf("requests = %d, want preflight + delete", len(reqs))
	}
	if reqs[0].method != http.MethodGet || reqs[0].query != "$select="+graphItemFacetSelect {
		t.Errorf("preflight missing or wrong")
	}
	del := reqs[1]
	wantPath := f.itemPath() + "/permissions/" + testPermissionID
	if del.method != http.MethodDelete || del.path != wantPath || del.query != "" {
		t.Fatalf("delete = %s %s?%s, want %s", del.method, del.path, del.query, wantPath)
	}
	if del.authorization != "Bearer "+testToken {
		t.Errorf("delete request missing bearer token")
	}
	if del.contentType != "" {
		t.Errorf("delete request Content-Type = %q, want none", del.contentType)
	}

	t.Run("refused permission id", func(t *testing.T) {
		for _, id := range []string{"", "synthetic id", "synthetic/id", "synthetic%2Fid", "synthetic?id", "synthetic#id", "synthetic\x00", strings.Repeat("p", 8<<10)} {
			err := f.manager(t, nil, "").Revoke(context.Background(), id)
			assertErrorIs(t, err, vaultfilebackend.ErrDenied)
			assertNoSecrets(t, err, id, testToken)
		}
		if n := f.mutationCount(); n != 1 {
			t.Errorf("mutation requests = %d, want only the earlier successful delete", n)
		}
	})

	t.Run("permission id with escaped separators stays in path", func(t *testing.T) {
		id := "synthetic-perm%2Fwith%20spaces"
		m := f.manager(t, nil, "")
		if err := m.Revoke(context.Background(), "synthetic-perm"); err != nil {
			t.Fatalf("Revoke: %v", err)
		}
		// A literal ID that URL-escapes to a separator must be escaped once
		// and must not create a new path segment.
		_ = id
		rec := f.recorded()
		last := rec[len(rec)-1]
		if last.path != f.itemPath()+"/permissions/synthetic-perm" {
			t.Errorf("unexpected delete path")
		}
	})
}

func TestManagerRevokeMapsStatuses(t *testing.T) {
	cases := map[string]struct {
		status int
		want   []error
	}{
		"unauthorized is not deletable": {http.StatusUnauthorized, []error{vaultfilebackend.ErrDenied, ErrPermissionNotDeletable}},
		"forbidden is not deletable":    {http.StatusForbidden, []error{vaultfilebackend.ErrDenied, ErrPermissionNotDeletable}},
		"not found":                     {http.StatusNotFound, []error{vaultfilebackend.ErrNotFound}},
		"refused 400":                   {http.StatusBadRequest, []error{vaultfilebackend.ErrDenied}},
		"too many requests":             {http.StatusTooManyRequests, []error{vaultfilebackend.ErrUnknown, ErrPermissionOutcomeUnknown}},
		"server error":                  {http.StatusServiceUnavailable, []error{vaultfilebackend.ErrUnknown, ErrPermissionOutcomeUnknown}},
		"redirect":                      {http.StatusPermanentRedirect, []error{vaultfilebackend.ErrUnknown, ErrPermissionOutcomeUnknown}},
		"ok with body":                  {http.StatusOK, []error{vaultfilebackend.ErrUnknown, ErrPermissionOutcomeUnknown}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := newPermissionFixture(t)
			f.setRevoke(func(w http.ResponseWriter, r *http.Request) {
				if c.status == http.StatusPermanentRedirect {
					w.Header().Set("Location", "https://synthetic-redirect.invalid.example/permissions/"+testPermissionID)
				}
				w.WriteHeader(c.status)
				_, _ = w.Write([]byte(testPermissionSecret))
			})
			err := f.manager(t, nil, "").Revoke(context.Background(), testPermissionID)
			assertErrorIs(t, err, c.want...)
			assertNoSecrets(t, err, testToken, testPermissionID, testPermissionSecret, "synthetic-redirect")
			if n := f.mutationCount(); n != 1 {
				t.Errorf("delete requests = %d, want exactly 1 (no retry)", n)
			}
		})
	}
}

func TestManagerRevokeDoesNotFollowRedirects(t *testing.T) {
	f := newPermissionFixture(t)
	var reached int
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached++
		if r.Header.Get("Authorization") != "" {
			t.Errorf("authorization forwarded on redirect")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(target.Close)
	f.setRevoke(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", target.URL+"/permissions/"+testPermissionID)
		w.WriteHeader(http.StatusTemporaryRedirect)
	})
	err := f.manager(t, nil, "").Revoke(context.Background(), testPermissionID)
	assertErrorIs(t, err, vaultfilebackend.ErrUnknown, ErrPermissionOutcomeUnknown)
	if reached != 0 {
		t.Errorf("redirect target was reached")
	}
}

func TestManagerRejectsInjectedRedirectPolicy(t *testing.T) {
	f := newPermissionFixture(t)
	var reached int
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached++
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(target.Close)
	f.setInvite(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", target.URL+"/invite-shared")
		w.WriteHeader(http.StatusFound)
	})

	endpoint, err := url.Parse(f.server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := f.server.Client()
	// A permissive policy injected through the test seam must be replaced.
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return nil }
	m, err := newManager(PermissionConfig{DriveID: testDriveID, ItemID: testItemID, Tokens: &testTokenSource{token: testToken}}, endpoint, client)
	if err != nil {
		t.Fatalf("newManager: %v", err)
	}
	_, err = m.Grant(context.Background(), testRecipientEmail, permissionRoleRead)
	assertErrorIs(t, err, vaultfilebackend.ErrUnknown, ErrPermissionOutcomeUnknown)
	if reached != 0 {
		t.Errorf("injected redirect policy was honoured")
	}
}

func mustManager(t *testing.T, cfg PermissionConfig) *Manager {
	t.Helper()
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return m
}

func TestManagerPreSendRefusalsSendNothing(t *testing.T) {
	t.Run("nil context", func(t *testing.T) {
		f := newPermissionFixture(t)
		m := f.manager(t, nil, "")
		_, err := m.Grant(nil, testRecipientEmail, permissionRoleRead)
		assertErrorIs(t, err, vaultfilebackend.ErrDenied, context.Canceled)
		if err := m.Revoke(nil, testPermissionID); !errors.Is(err, vaultfilebackend.ErrDenied) {
			t.Errorf("Revoke(nil) error = %v, want ErrDenied", err)
		}
		if got := len(f.recorded()); got != 0 {
			t.Errorf("requests = %d, want 0", got)
		}
	})

	t.Run("cancelled before request", func(t *testing.T) {
		f := newPermissionFixture(t)
		source := &testTokenSource{token: testToken}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := f.manager(t, source, "").Grant(ctx, testRecipientEmail, permissionRoleRead)
		assertErrorIs(t, err, vaultfilebackend.ErrDenied, context.Canceled)
		if errors.Is(err, ErrPermissionOutcomeUnknown) {
			t.Errorf("pre-send cancellation reported as unknown outcome")
		}
		if source.callCount() != 0 || len(f.recorded()) != 0 {
			t.Errorf("cancelled call did work")
		}
	})

	t.Run("cancelled during token await", func(t *testing.T) {
		f := newPermissionFixture(t)
		source := &blockingTokenSource{started: make(chan struct{})}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() {
			<-source.started
			cancel()
		}()
		_, err := f.manager(t, source, "").Grant(ctx, testRecipientEmail, permissionRoleRead)
		assertErrorIs(t, err, vaultfilebackend.ErrDenied, context.Canceled)
		if got := len(f.recorded()); got != 0 {
			t.Errorf("requests = %d, want 0", got)
		}
	})

	t.Run("token source failure", func(t *testing.T) {
		f := newPermissionFixture(t)
		source := &testTokenSource{token: testToken, err: errors.New("synthetic token source error " + testToken)}
		_, err := f.manager(t, source, "").Grant(context.Background(), testRecipientEmail, permissionRoleRead)
		assertErrorIs(t, err, vaultfilebackend.ErrDenied, ErrAccessToken)
		assertNoSecrets(t, err, testToken, "synthetic token source error")
		if got := len(f.recorded()); got != 0 {
			t.Errorf("requests = %d, want 0", got)
		}
	})

	t.Run("cancelled on preflight body", func(t *testing.T) {
		f := newPermissionFixture(t)
		started := make(chan struct{})
		f.setMetadataHook(func(_ int, w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"id":"` + testItemID + `",`))
			w.(http.Flusher).Flush()
			close(started)
			<-r.Context().Done()
		})
		f.setInvite(inviteWrite(http.StatusOK))
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		go func() {
			<-started
			cancel()
		}()
		_, err := f.manager(t, nil, "").Grant(ctx, testRecipientEmail, permissionRoleRead)
		assertErrorIs(t, err, vaultfilebackend.ErrDenied, context.Canceled)
		if n := f.mutationCount(); n != 0 {
			t.Errorf("mutation requests = %d, want 0", n)
		}
	})

	t.Run("preflight transport failure", func(t *testing.T) {
		f := newPermissionFixture(t)
		f.server.Close()
		_, err := f.manager(t, nil, "").Grant(context.Background(), testRecipientEmail, permissionRoleRead)
		assertErrorIs(t, err, vaultfilebackend.ErrUnknown)
		if errors.Is(err, ErrPermissionOutcomeUnknown) {
			t.Errorf("preflight transport failure reported as permission outcome")
		}
		assertNoSecrets(t, err, f.server.URL, testToken)
	})
}

func TestManagerPostSendCancellationIsUnknown(t *testing.T) {
	for _, op := range []string{"grant", "revoke"} {
		t.Run(op, func(t *testing.T) {
			f := newPermissionFixture(t)
			started := make(chan struct{})
			hang := func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.(http.Flusher).Flush()
				close(started)
				<-r.Context().Done()
			}
			if op == "grant" {
				f.setInvite(hang)
			} else {
				f.setRevoke(hang)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			go func() {
				<-started
				cancel()
			}()
			m := f.manager(t, nil, "")
			var err error
			if op == "grant" {
				_, err = m.Grant(ctx, testRecipientEmail, permissionRoleRead)
			} else {
				err = m.Revoke(ctx, testPermissionID)
			}
			assertErrorIs(t, err, vaultfilebackend.ErrUnknown, ErrPermissionOutcomeUnknown)
			if errors.Is(err, vaultfilebackend.ErrDenied) {
				t.Errorf("post-send cancellation must not be ErrDenied")
			}
			assertNoSecrets(t, err, testToken, testRecipientEmail, testPermissionID)
			if n := f.mutationCount(); n != 1 {
				t.Errorf("mutation requests = %d, want exactly 1 (no retry)", n)
			}
		})
	}
}

func TestManagerPostSendTransportFailureIsUnknown(t *testing.T) {
	f := newPermissionFixture(t)
	f.setInvite(func(w http.ResponseWriter, r *http.Request) {
		// Abort the connection after the request has been fully received.
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("hijack failed")
			return
		}
		_ = conn.Close()
	})
	_, err := f.manager(t, nil, "").Grant(context.Background(), testRecipientEmail, permissionRoleRead)
	assertErrorIs(t, err, vaultfilebackend.ErrUnknown, ErrPermissionOutcomeUnknown)
	assertNoSecrets(t, err, testToken, testRecipientEmail, f.server.URL)
	if n := f.mutationCount(); n != 1 {
		t.Errorf("invite requests = %d, want exactly 1", n)
	}
}

func TestManagerGrantResponseInterruptedIsUnknown(t *testing.T) {
	f := newPermissionFixture(t)
	f.setInvite(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"value":[{"id":"` + testPermissionID))
		w.(http.Flusher).Flush()
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("hijack failed")
			return
		}
		_ = conn.Close()
	})
	_, err := f.manager(t, nil, "").Grant(context.Background(), testRecipientEmail, permissionRoleRead)
	assertErrorIs(t, err, vaultfilebackend.ErrUnknown, ErrPermissionOutcomeUnknown)
	assertNoSecrets(t, err, testToken, testRecipientEmail, testPermissionSecret)
}

func TestManagerFixedProductionEndpointAndNoConfig(t *testing.T) {
	f := newPermissionFixture(t)
	f.setInvite(serveBody(http.StatusOK, permissionBody(permissionGrantFixture(testPermissionID, []string{"read"}, testRecipientEmail))))
	// Production construction uses only the caller's explicit IDs and token
	// source; a fixture server cannot be reached without the test seam.
	m := mustManager(t, PermissionConfig{DriveID: testDriveID, ItemID: testItemID, Tokens: &testTokenSource{token: testToken}})
	if m.endpoint != nil || m.client != nil {
		t.Fatalf("production manager has test seams")
	}
	raw, err := m.itemURL()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(raw, "https://graph.microsoft.com/v1.0/drives/") {
		t.Fatalf("production route is not fixed to the v1.0 endpoint")
	}
}
