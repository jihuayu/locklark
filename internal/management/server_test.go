package management

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBrokerRejectsWebOriginsAndAuthority(t *testing.T) {
	calls := 0
	h, e := NewHandler("127.0.0.1:3210", strings.Repeat("a", 64), func() (Summary, error) { calls++; return Summary{Version: 1, Mode: "frozen"}, nil })
	if e != nil {
		t.Fatal(e)
	}
	for _, test := range []struct {
		name, method, path, host, origin, token string
		want                                    int
	}{
		{"valid", "GET", "/v1/summary", "127.0.0.1:3210", "", strings.Repeat("a", 64), 200},
		{"no-token", "GET", "/v1/summary", "127.0.0.1:3210", "", "", 401},
		{"origin", "GET", "/v1/summary", "127.0.0.1:3210", "https://evil.test", strings.Repeat("a", 64), 403},
		{"host", "GET", "/v1/summary", "evil.test", "", strings.Repeat("a", 64), 403},
		{"mutation", "POST", "/v1/summary", "127.0.0.1:3210", "", strings.Repeat("a", 64), 405},
		{"unlock", "GET", "/v1/unlock", "127.0.0.1:3210", "", strings.Repeat("a", 64), 404},
		{"query-path", "GET", "/v1/summary?path=/tmp/vault", "127.0.0.1:3210", "", strings.Repeat("a", 64), 404},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := httptest.NewRequest(test.method, test.path, nil)
			r.Host = test.host
			r.RemoteAddr = "127.0.0.1:1234"
			if test.origin != "" {
				r.Header.Set("Origin", test.origin)
			}
			r.Header.Set("Authorization", "Bearer "+test.token)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != test.want {
				t.Fatal(w.Code)
			}
			if w.Header().Get("Access-Control-Allow-Origin") != "" {
				t.Fatal("CORS exposed")
			}
			if w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("cache enabled")
			}
		})
	}
	if calls != 1 {
		t.Fatal("unauthorized request reached directory", calls)
	}
}
func TestBrokerDoesNotReflectProviderErrors(t *testing.T) {
	h, _ := NewHandler("127.0.0.1:3210", strings.Repeat("a", 64), func() (Summary, error) { return Summary{}, fmt.Errorf("private path and token") })
	r := httptest.NewRequest("GET", "/v1/summary", nil)
	r.Host = "127.0.0.1:3210"
	r.RemoteAddr = "127.0.0.1:1234"
	r.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 64))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), "private") {
		t.Fatal("provider error reflected")
	}
}

func TestBrokerStrictRequestBoundary(t *testing.T) {
	token := strings.Repeat("a", 64)
	h, _ := NewHandler("127.0.0.1:3210", token, func() (Summary, error) { t.Fatal("rejected request reached directory"); return Summary{}, nil })
	for _, kind := range []string{"head", "options", "null-origin", "empty-origin", "remote", "forwarded", "body"} {
		t.Run(kind, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/v1/summary", nil)
			r.Host = "127.0.0.1:3210"
			r.RemoteAddr = "127.0.0.1:1234"
			r.Header.Set("Authorization", "Bearer "+token)
			switch kind {
			case "head":
				r.Method = "HEAD"
			case "options":
				r.Method = "OPTIONS"
			case "null-origin":
				r.Header.Set("Origin", "null")
			case "empty-origin":
				r.Header.Set("Origin", "")
			case "remote":
				r.RemoteAddr = "192.0.2.1:2345"
			case "forwarded":
				r.Header.Set("Forwarded", "for=127.0.0.1")
			case "body":
				r.ContentLength = 1
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code < 400 {
				t.Fatal("request accepted")
			}
		})
	}
}
