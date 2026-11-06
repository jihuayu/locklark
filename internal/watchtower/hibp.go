package watchtower

import (
	"context"
	"errors"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	DefaultHIBPEndpoint = "https://api.pwnedpasswords.com/range/"
	defaultHIBPTimeout  = 10 * time.Second
	defaultHIBPCacheTTL = 15 * time.Minute
	maxHIBPResponse     = 256 << 10
)

// ErrHIBP is a fixed, non-secret refusal. Callers must not wrap it with
// response details because those could contain a queried prefix.
var ErrHIBP = errors.New("password range lookup unavailable")

var hibpPrefix = regexp.MustCompile(`^[0-9A-Fa-f]{5}$`)
var hibpSuffix = regexp.MustCompile(`^[0-9A-F]{35}$`)

// RangeLookup is the narrow k-anonymity transport. Lookup receives exactly the
// five-character SHA-1 prefix; the client never passes it a full hash.
type RangeLookup interface {
	Lookup(ctx context.Context, prefix string) (map[string]int, error)
}

// HIBPClient queries the Pwned Passwords range API. It caches parsed non-zero
// suffix counts per prefix for 15 minutes by default.
type HIBPClient struct {
	endpoint string
	client   *http.Client
	timeout  time.Duration
	ttl      time.Duration
	now      func() time.Time
	mu       sync.Mutex
	cache    map[string]hibpCacheEntry
}

type hibpCacheEntry struct {
	until  time.Time
	counts map[string]int
}

type HIBPOptions struct {
	Endpoint string        // default DefaultHIBPEndpoint; must be HTTPS without query/fragment
	Client   *http.Client  // optional; a TLS-trusting test client is supported
	Timeout  time.Duration // default 10s
	CacheTTL time.Duration // default 15m
	Now      func() time.Time
}

func NewHIBPClient(opts HIBPOptions) *HIBPClient {
	endpoint := opts.Endpoint
	if endpoint == "" {
		endpoint = DefaultHIBPEndpoint
	}
	if !strings.HasSuffix(endpoint, "/") {
		endpoint += "/"
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = defaultHIBPTimeout
	}
	ttl := opts.CacheTTL
	if ttl <= 0 {
		ttl = defaultHIBPCacheTTL
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	client := &http.Client{}
	if opts.Client != nil {
		clone := *opts.Client
		clone.Jar = nil // never let an injected cookie jar identify the caller
		client = &clone
	}
	client.Timeout = timeout
	return &HIBPClient{
		endpoint: endpoint,
		client:   client,
		timeout:  timeout,
		ttl:      ttl,
		now:      now,
		cache:    make(map[string]hibpCacheEntry),
	}
}

func (c *HIBPClient) valid() bool {
	return c != nil && strings.HasPrefix(c.endpoint, "https://") &&
		!strings.ContainsAny(c.endpoint, "?#") && len(c.endpoint) <= 2048
}

// Lookup validates and uppercases the prefix, consults the TTL cache, and only
// then issues one GET. The URL contains no suffix, password or full hash.
func (c *HIBPClient) Lookup(ctx context.Context, prefix string) (map[string]int, error) {
	if c == nil || !c.valid() || !hibpPrefix.MatchString(prefix) {
		return nil, ErrHIBP
	}
	prefix = strings.ToUpper(prefix)
	now := c.now()
	c.mu.Lock()
	if entry, ok := c.cache[prefix]; ok && now.Before(entry.until) {
		counts := cloneCounts(entry.counts)
		c.mu.Unlock()
		return counts, nil
	}
	c.mu.Unlock()

	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint+prefix, nil)
	if err != nil {
		return nil, ErrHIBP
	}
	req.Header.Set("Add-Padding", "true")
	req.Header.Set("User-Agent", "Locklark-Watchtower/1.0")
	req.Header.Set("Accept", "text/plain")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, ErrHIBP
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, ErrHIBP
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxHIBPResponse+1))
	if err != nil || len(body) > maxHIBPResponse {
		return nil, ErrHIBP
	}
	counts := parseHIBP(body)
	c.mu.Lock()
	c.cache[prefix] = hibpCacheEntry{until: now.Add(c.ttl), counts: cloneCounts(counts)}
	c.mu.Unlock()
	return counts, nil
}

func cloneCounts(counts map[string]int) map[string]int {
	out := make(map[string]int, len(counts))
	for suffix, count := range counts {
		out[suffix] = count
	}
	return out
}

// parseHIBP ignores malformed lines and zero-count padding entries. HIBP
// responses are normally CRLF-delimited; both forms are accepted.
func parseHIBP(body []byte) map[string]int {
	counts := make(map[string]int)
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		suffix, rawCount, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		suffix = strings.ToUpper(strings.TrimSpace(suffix))
		if !hibpSuffix.MatchString(suffix) {
			continue
		}
		count, err := strconv.Atoi(strings.TrimSpace(rawCount))
		if err != nil || count <= 0 {
			continue
		}
		counts[suffix] = count
	}
	return counts
}

// LookupCandidates deduplicates prefixes, queries each exactly once in sorted
// order, and returns itemID -> count. A successful empty candidate set returns
// a non-nil empty map so callers can distinguish "checked, nothing to query"
// from a failed lookup.
func LookupCandidates(ctx context.Context, lookup RangeLookup, candidates []HIBPCandidate) (map[string]int, error) {
	if lookup == nil {
		return nil, ErrHIBP
	}
	prefixes := make(map[string][]HIBPCandidate)
	for _, candidate := range candidates {
		if !hibpPrefix.MatchString(candidate.Prefix) {
			return nil, ErrHIBP
		}
		prefix := strings.ToUpper(candidate.Prefix)
		prefixes[prefix] = append(prefixes[prefix], candidate)
	}
	order := make([]string, 0, len(prefixes))
	for prefix := range prefixes {
		order = append(order, prefix)
	}
	sort.Strings(order)
	results := make(map[string]int, len(candidates))
	for _, prefix := range order {
		counts, err := lookup.Lookup(ctx, prefix)
		if err != nil {
			return nil, ErrHIBP
		}
		for _, candidate := range prefixes[prefix] {
			results[candidate.ID] = counts[candidate.Suffix]
		}
	}
	return results, nil
}
