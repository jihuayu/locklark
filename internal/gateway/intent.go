package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/jihuayu/locklark/plugins/github-pull-reader"
	"io"
	"net/http"
)

const PullAction = action
const PullSlot = "op://synthetic-vault/login-sample/password"

// PullScope is signed by the owner at enrollment and by the session at request.
// This backend is deliberately disjoint from live GitHub so a recorded-response
// approval can never authorize a network request.
type PullScope struct {
	Repo    Repository `json:"repository"`
	Plugin  string     `json:"plugin"`
	Version string     `json:"version"`
	Digest  string     `json:"module_sha256"`
	Slot    string     `json:"slot"`
	Backend string     `json:"backend"`
}
type PullIntent struct {
	PullScope
	Number int `json:"number"`
}

func RecordedScope(r Repository) (PullScope, error) {
	if !r.valid() {
		return PullScope{}, errRejected
	}
	return PullScope{r, "locklark.builtin/github-pull-reader", "1", pullreader.Digest(), PullSlot, "recorded-response/v1"}, nil
}
func (p PullIntent) Valid() bool {
	s, e := RecordedScope(p.Repo)
	return e == nil && p.PullScope == s && p.Number > 0 && int64(p.Number) <= 2147483647
}
func RecordedIntent(r Repository, n int, proposal []byte) (PullIntent, error) {
	s, err := RecordedScope(r)
	p := PullIntent{s, n}
	if err != nil || !p.Valid() || !validPlan(proposal, Target{r.ID, n}) {
		return PullIntent{}, errRejected
	}
	return p, nil
}

type recording []byte

func (f recording) RoundTrip(_ *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(f))}, nil
}

// ReadRecording exercises the same projection and credential path without
// sending any network request. Recreate the proposal from the verified intent.
func (p PullIntent) ReadRecording(ctx context.Context, response []byte, load func() ([]byte, error)) (PullResult, error) {
	if !p.Valid() || len(response) > 1<<20 {
		return PullResult{}, errRejected
	}
	h := pullReader{p.Repo, recording(response)}
	id, _ := json.Marshal(p.Repo.ID)
	proposal := []byte(fmt.Sprintf(`{"v":1,"action":"github.pulls.get","repo":%s,"number":%d}`, id, p.Number))
	return h.ReadApproved(ctx, Target{p.Repo.ID, p.Number}, proposal, load)
}
