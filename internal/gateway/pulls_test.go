package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const plan = `{"v":1,"action":"github.pulls.get","repo":"123","number":7}`
const githubResponse = `{"number":7,"state":"closed","merged_at":"2026-01-01T03:04:05Z","base":{"repo":{"id":123}},"body":"do not expose","title":"SYNTHETIC_PRIVATE"}`

var bound = Repository{ID: "123", Owner: "example", Name: "tools"}

type round func(*http.Request) (*http.Response, error)

func (f round) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func upstream(code int, body string, header http.Header) *http.Response {
	return &http.Response{StatusCode: code, Header: header, Body: io.NopCloser(strings.NewReader(body))}
}
func TestPullOnlyProjectsApprovedFields(t *testing.T) {
	checkPull(t, []byte(plan))
}
func checkPull(t *testing.T, proposal []byte) {
	t.Helper()
	calls := 0
	loads := 0
	h := pullReader{repo: bound, transport: round(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.String() != "https://api.github.com/repos/example/tools/pulls/7" || r.Method != "GET" || r.Header.Get("Authorization") != "Bearer SYNTHETIC_PRIVATE" {
			t.Fatal("upstream request did not match approved target")
		}
		return upstream(200, githubResponse, nil), nil
	})}
	result, err := h.read(context.Background(), Target{"123", 7}, proposal, func() ([]byte, error) { loads++; return []byte("SYNTHETIC_PRIVATE"), nil })
	if err != nil || loads != 1 || calls != 1 {
		t.Fatal(err, loads, calls)
	}
	b, _ := json.Marshal(result)
	if string(b) != `{"number":7,"state":"closed","merged_at":"2026-01-01T03:04:05Z"}` {
		t.Fatal("invalid public projection", string(b))
	}
}
func TestRejectsUnboundProposalBeforeTouchingSlot(t *testing.T) {
	for _, bad := range []string{strings.Replace(plan, "123", "124", 1), strings.Replace(plan, "7", "8", 1), strings.Replace(plan, "github.pulls.get", "http.fetch", 1), strings.Replace(plan, "}", `,"url":"https://unapproved.invalid"}`, 1), strings.Replace(plan, `"repo":"123"`, `"repo":"666","repo":"123"`, 1), strings.Replace(plan, `"repo"`, `"Repo"`, 1), plan + "{}", strings.Repeat(" ", 4096) + plan} {
		h := pullReader{repo: bound, transport: round(func(*http.Request) (*http.Response, error) { t.Fatal("unexpected request"); return nil, nil })}
		_, err := h.read(context.Background(), Target{"123", 7}, []byte(bad), func() ([]byte, error) { t.Fatal("read credential"); return nil, nil })
		if err == nil {
			t.Fatal("accepted bad plan")
		}
	}
}
func TestRedirectErrorAndHostileResponseRevealNothing(t *testing.T) {
	for _, item := range []struct {
		code int
		body string
	}{{302, "SYNTHETIC_PRIVATE"}, {401, "SYNTHETIC_PRIVATE"}, {200, strings.Replace(githubResponse, "123", "999", 1)}, {200, strings.Replace(githubResponse, `"number":7`, `"number":8`, 1)}, {200, strings.Replace(githubResponse, "closed", "SYNTHETIC_PRIVATE", 1)}, {200, strings.Replace(githubResponse, "2026-01-01T03:04:05Z", "SYNTHETIC_PRIVATE", 1)}, {200, githubResponse + " other"}, {200, strings.Repeat(" ", (1<<20)+1) + githubResponse}} {
		calls := 0
		h := pullReader{repo: bound, transport: round(func(r *http.Request) (*http.Response, error) {
			calls++
			if calls > 1 {
				t.Fatal("followed redirect")
			}
			return upstream(item.code, item.body, http.Header{"Location": []string{"https://unapproved.invalid/SYNTHETIC_PRIVATE"}}), nil
		})}
		result, err := h.read(context.Background(), Target{"123", 7}, []byte(plan), func() ([]byte, error) { return []byte("SYNTHETIC_PRIVATE"), nil })
		if err == nil || strings.Contains(err.Error(), "SYNTHETIC_PRIVATE") || result != (PullResult{}) {
			t.Fatal("leaked/error response", result, err)
		}
	}
}
func TestTransportNeverUsesImplicitNetworkConfiguration(t *testing.T) {
	for _, v := range []string{"127.0.0.1", "169.254.169.254", "10.0.0.1", "100.64.0.1", "::1", "224.0.0.1", "192.0.2.1"} {
		if _, err := NewPullReader(bound, netip.MustParseAddr(v)); err == nil {
			t.Fatal("accepted forbidden address", v)
		}
	}
	if _, err := NewPullReader(Repository{"123", "bad/../path", "tools"}, netip.MustParseAddr("1.1.1.1")); err == nil {
		t.Fatal("accepted injected path")
	}
	h, err := NewPullReader(bound, netip.MustParseAddr("1.1.1.1"))
	if err != nil {
		t.Fatal(err)
	}
	tr := h.transport.(*http.Transport)
	if tr.Proxy != nil || tr.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("unsafe TLS/proxy")
	}
	if _, err := tr.DialContext(context.Background(), "tcp", "other.invalid:443"); err == nil {
		t.Fatal("accepted wrong origin")
	}
}
func TestBuiltinBunToGoHost(t *testing.T) {
	exe := os.Getenv("LOCKLARK_TEST_BUN")
	if exe == "" {
		t.Skip("set LOCKLARK_TEST_BUN to the Bun executable to run the two-process test")
	}
	src, err := filepath.Abs("../../plugins/github-pull-reader/index.ts")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "run", src)
	cmd.Dir = t.TempDir()
	cmd.Env = []string{"SystemRoot=" + os.Getenv("SystemRoot")}
	cmd.Stdin = strings.NewReader(`{"repo":"123","number":7}`)
	var out, diag bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &diag
	if err := cmd.Run(); err != nil {
		t.Fatal(err, diag.String())
	}
	checkPull(t, out.Bytes())
}
func TestSecretLoadingFailureIsOpaque(t *testing.T) {
	h := pullReader{repo: bound, transport: round(func(*http.Request) (*http.Response, error) { t.Fatal("unexpected request"); return nil, nil })}
	_, err := h.read(context.Background(), Target{"123", 7}, []byte(plan), func() ([]byte, error) { return nil, errors.New("SYNTHETIC_PRIVATE") })
	if err == nil || strings.Contains(err.Error(), "SYNTHETIC_PRIVATE") {
		t.Fatal("leak")
	}
}
