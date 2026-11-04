// Package gateway holds the trusted, fixed-purpose upstream adapters. No HTTP
// destination, header or secret is accepted from an agent or plugin.
package gateway

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"strconv"
	"time"
)

var errRejected = errors.New("pull request action rejected")
var errUpstream = errors.New("pull request result unavailable")

const action = "github.pulls.get"
const apiHost = "api.github.com"

// Repository is an owner-configured binding; ID is the stable numeric GitHub ID.
type Repository struct{ ID, Owner, Name string }
type Target struct {
	Repo   string
	Number int
}
type PullResult struct {
	Number   int     `json:"number"`
	State    string  `json:"state"`
	MergedAt *string `json:"merged_at"`
}
type pullReader struct {
	repo      Repository
	transport http.RoundTripper
}

var ownerName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9-]{0,38}$`)
var repoName = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9._-]{0,99}$`)

func validID(s string) bool {
	n, err := strconv.ParseInt(s, 10, 64)
	return err == nil && n > 0 && strconv.FormatInt(n, 10) == s
}
func (r Repository) valid() bool {
	return validID(r.ID) && ownerName.MatchString(r.Owner) && repoName.MatchString(r.Name)
}

// Conservative IPv4-only transport: owner pins the permitted address out of
// band. Do not discover it from the plugin, DNS, redirects or environment.
var forbidden = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

func NewPullReader(repo Repository, ip netip.Addr) (*pullReader, error) {
	if !repo.valid() || !ip.Is4() || !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return nil, errRejected
	}
	for _, p := range forbidden {
		if p.Contains(ip) {
			return nil, errRejected
		}
	}
	d := &net.Dialer{Timeout: 5 * time.Second}
	tr := &http.Transport{DisableKeepAlives: true, DisableCompression: true, MaxResponseHeaderBytes: 64 << 10,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: apiHost}, TLSHandshakeTimeout: 5 * time.Second,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if addr != apiHost+":443" || network != "tcp" {
				return nil, errRejected
			}
			return d.DialContext(ctx, "tcp4", net.JoinHostPort(ip.String(), "443"))
		}}
	return &pullReader{repo, tr}, nil
}

// The protocol has only four flat keys. Reject duplicates, alternate casing,
// missing keys, extra keys, trailing objects and unbounded frames.
func validPlan(raw []byte, t Target) bool {
	if len(raw) > 4096 || t.Number < 1 || int64(t.Number) > 2147483647 || !validID(t.Repo) {
		return false
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	first, err := dec.Token()
	if err != nil || first != json.Delim('{') {
		return false
	}
	seen := map[string]bool{}
	for dec.More() {
		k, err := dec.Token()
		s, ok := k.(string)
		if err != nil || !ok || seen[s] {
			return false
		}
		seen[s] = true
		switch s {
		case "v", "number":
			var n int
			if dec.Decode(&n) != nil || (s == "v" && n != 1) || (s == "number" && n != t.Number) {
				return false
			}
		case "action", "repo":
			var str string
			if dec.Decode(&str) != nil || (s == "action" && str != action) || (s == "repo" && str != t.Repo) {
				return false
			}
		default:
			return false
		}
	}
	close, err := dec.Token()
	if err != nil || close != json.Delim('}') || len(seen) != 4 {
		return false
	}
	_, err = dec.Token()
	return err == io.EOF
}

// ReadApproved takes a target from the trusted caller's already-claimed grant,
// never from a plugin. Production callers must commit authorization and audit
// intent before calling. The credential loader returns an owned, erasable copy.
func (h *pullReader) ReadApproved(ctx context.Context, t Target, plan []byte, credential func() ([]byte, error)) (PullResult, error) {
	return h.read(ctx, t, plan, credential)
}
func (h *pullReader) read(ctx context.Context, t Target, plan []byte, credential func() ([]byte, error)) (PullResult, error) {
	var zero PullResult
	if !h.repo.valid() || t.Repo != h.repo.ID || !validPlan(plan, t) || credential == nil || h.transport == nil {
		return zero, errRejected
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	path := fmt.Sprintf("https://%s/repos/%s/%s/pulls/%d", apiHost, h.repo.Owner, h.repo.Name, t.Number)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, path, nil)
	if err != nil || ctx.Err() != nil {
		return zero, errRejected
	}
	key, err := credential()
	defer clear(key)
	if err != nil || len(key) < 8 || len(key) > 512 {
		return zero, errRejected
	}
	for _, c := range key {
		if c <= 0x20 || c >= 0x7f {
			return zero, errRejected
		}
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+string(key))
	// One RoundTrip: no redirect following, cookies, ambient proxy or URL retries.
	resp, err := h.transport.RoundTrip(req)
	if err != nil {
		return zero, errUpstream
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return zero, errUpstream
	}
	const max = 1 << 20
	raw, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil || len(raw) > max {
		return zero, errUpstream
	}
	defer clear(raw)
	var wire struct {
		Number int
		State  string
		Merged json.RawMessage `json:"merged_at"`
		Base   struct{ Repo struct{ ID int64 } }
	}
	if json.Unmarshal(raw, &wire) != nil || wire.Number != t.Number || strconv.FormatInt(wire.Base.Repo.ID, 10) != t.Repo ||
		(wire.State != "open" && wire.State != "closed") || len(wire.Merged) == 0 {
		return zero, errUpstream
	}
	var merged *string
	if json.Unmarshal(wire.Merged, &merged) != nil {
		return zero, errUpstream
	}
	if merged != nil {
		tm, err := time.Parse(time.RFC3339, *merged)
		if err != nil || tm.UTC().Format("2006-01-02T15:04:05Z") != *merged || wire.State != "closed" {
			return zero, errUpstream
		}
	}
	return PullResult{t.Number, wire.State, merged}, nil
}
