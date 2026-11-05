package gateway

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestRejectsAmbiguousIdentityAndCredentialEcho(t *testing.T) {
	for _, tc := range []struct{ name, body, key string }{
		{"echo", githubResponse, "2026-01-01T03:04:05Z"},
		{"case folded ID", strings.Replace(githubResponse, `"id":123`, `"id":987,"ID":123`, 1), "SYNTHETIC_PRIVATE"},
		{"repeated base", strings.Replace(githubResponse, `"body"`, `"base":{"repo":null},"body"`, 1), "SYNTHETIC_PRIVATE"},
		{"duplicate number", strings.Replace(githubResponse, `"number":7`, `"number":6,"number":7`, 1), "SYNTHETIC_PRIVATE"},
		{"case folded state", strings.Replace(githubResponse, `"state":"closed"`, `"state":"open","State":"closed"`, 1), "SYNTHETIC_PRIVATE"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := pullReader{repo: bound, transport: round(func(*http.Request) (*http.Response, error) { return upstream(200, tc.body, nil), nil })}
			result, err := h.ReadApproved(context.Background(), Target{"123", 7}, []byte(plan), func() ([]byte, error) { return []byte(tc.key), nil })
			if err == nil || result != (PullResult{}) || strings.Contains(err.Error(), tc.key) {
				t.Fatal("ambiguous result or credential echo accepted")
			}
		})
	}
}
