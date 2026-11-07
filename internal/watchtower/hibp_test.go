package watchtower

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testHIBPPasswordSHA1 = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"
	testHIBPPrefix       = "5BAA6"
	testHIBPSuffix       = "1E4C9B93F3F0682250B6CF8331B7EE68FD8"
	testHIBPPadding      = "00000000000000000000000000000000000"
)

func TestHIBPClientPrefixOnlyAndParsing(t *testing.T) {
	var mu sync.Mutex
	var paths []string
	var queries []string
	var headers []http.Header
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		queries = append(queries, r.URL.RawQuery)
		headers = append(headers, r.Header.Clone())
		mu.Unlock()
		if r.Method != http.MethodGet {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "%s:0\r\n", testHIBPPadding)
		fmt.Fprintf(w, "%s:42\r\n", testHIBPSuffix)
		fmt.Fprintf(w, "NOT-A-SUFFIX:9\r\n")
		fmt.Fprintf(w, "%s:not-a-count\r\n", strings.Repeat("C", 35))
		fmt.Fprintf(w, "%s:-1\r\n", strings.Repeat("D", 35))
	}))
	defer server.Close()

	client := NewHIBPClient(HIBPOptions{Endpoint: server.URL + "/range/", Client: server.Client()})
	counts, err := client.Lookup(context.Background(), "5baa6")
	if err != nil {
		t.Fatal(err)
	}
	if counts[testHIBPSuffix] != 42 || len(counts) != 1 {
		t.Fatalf("parsed counts=%v", counts)
	}
	if _, ok := counts[testHIBPPadding]; ok {
		t.Fatal("zero-count padding retained")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(paths) != 1 || paths[0] != "/range/"+testHIBPPrefix {
		t.Fatalf("paths=%v", paths)
	}
	if queries[0] != "" {
		t.Fatal("query string sent")
	}
	header := headers[0]
	if header.Get("Add-Padding") != "true" || header.Get("User-Agent") != "Locklark-Watchtower/1.0" || header.Get("Accept") != "text/plain" {
		t.Fatalf("headers=%v", header)
	}
	for _, forbidden := range []string{"Cookie", "Referer", "Origin", "Authorization"} {
		if header.Get(forbidden) != "" {
			t.Fatalf("forbidden header %s", forbidden)
		}
	}
	url := server.URL + "/range/" + testHIBPPrefix
	for _, secret := range []string{testHIBPSuffix, testHIBPPasswordSHA1, "password", "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"} {
		if strings.Contains(strings.ToLower(url), strings.ToLower(secret)) {
			t.Fatalf("secret %q on the wire", secret)
		}
	}
}

func TestHIBPClientCacheClockAndCopy(t *testing.T) {
	var calls int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		fmt.Fprintf(w, "%s:5\r\n", testHIBPSuffix)
	}))
	defer server.Close()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	client := NewHIBPClient(HIBPOptions{
		Endpoint: server.URL + "/range/",
		Client:   server.Client(),
		Now:      func() time.Time { return now },
	})
	first, err := client.Lookup(context.Background(), testHIBPPrefix)
	if err != nil || first[testHIBPSuffix] != 5 {
		t.Fatalf("first lookup: %v %v", first, err)
	}
	first[testHIBPSuffix] = 999 // cache must not alias caller memory
	second, err := client.Lookup(context.Background(), strings.ToLower(testHIBPPrefix))
	if err != nil || second[testHIBPSuffix] != 5 {
		t.Fatalf("cached lookup: %v %v", second, err)
	}
	if calls != 1 {
		t.Fatalf("cache missed: %d calls", calls)
	}
	now = now.Add(16 * time.Minute)
	if _, err = client.Lookup(context.Background(), testHIBPPrefix); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("cache did not expire: %d calls", calls)
	}
}

func TestHIBPClientFixedRefusals(t *testing.T) {
	var calls int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if strings.HasSuffix(r.URL.Path, "AAAAA") {
			http.Error(w, "nope", http.StatusInternalServerError)
			return
		}
		if strings.HasSuffix(r.URL.Path, "BBBBB") {
			w.Write([]byte(strings.Repeat("A", maxHIBPResponse+1)))
			return
		}
		time.Sleep(100 * time.Millisecond)
		fmt.Fprintf(w, "%s:1\r\n", testHIBPSuffix)
	}))
	defer server.Close()
	client := NewHIBPClient(HIBPOptions{Endpoint: server.URL + "/range/", Client: server.Client()})
	for _, prefix := range []string{"", "1234", "123456", "ZZZZZ", "5BAA6\n", " 5BAA6"} {
		if _, err := client.Lookup(context.Background(), prefix); !errors.Is(err, ErrHIBP) {
			t.Fatalf("invalid prefix %q accepted: %v", prefix, err)
		}
	}
	if calls != 0 {
		t.Fatal("invalid prefix performed a request")
	}
	if _, err := client.Lookup(context.Background(), "AAAAA"); !errors.Is(err, ErrHIBP) {
		t.Fatalf("500 response: %v", err)
	}
	if _, err := client.Lookup(context.Background(), "BBBBB"); !errors.Is(err, ErrHIBP) {
		t.Fatalf("oversized body: %v", err)
	}
	httpServer := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer httpServer.Close()
	if _, err := NewHIBPClient(HIBPOptions{Endpoint: httpServer.URL + "/range/", Client: httpServer.Client()}).Lookup(context.Background(), "AAAAA"); !errors.Is(err, ErrHIBP) {
		t.Fatalf("non-HTTPS endpoint: %v", err)
	}
	slow := NewHIBPClient(HIBPOptions{Endpoint: server.URL + "/range/", Client: server.Client(), Timeout: 5 * time.Millisecond})
	if _, err := slow.Lookup(context.Background(), "CCCCC"); !errors.Is(err, ErrHIBP) {
		t.Fatalf("timeout: %v", err)
	}
}

type recordingLookup struct {
	mu      sync.Mutex
	prefix  []string
	results map[string]map[string]int
	err     error
}

func (r *recordingLookup) Lookup(_ context.Context, prefix string) (map[string]int, error) {
	r.mu.Lock()
	r.prefix = append(r.prefix, prefix)
	r.mu.Unlock()
	if r.err != nil {
		return nil, r.err
	}
	return r.results[prefix], nil
}

func TestLookupCandidatesGroupsPrefixes(t *testing.T) {
	lookup := &recordingLookup{results: map[string]map[string]int{
		"AAAAA": {"1": 10},
		"BBBBB": {"2": 20},
	}}
	candidates := []HIBPCandidate{
		{ID: "id1", Prefix: "bbbbb", Suffix: "2"},
		{ID: "id2", Prefix: "AAAAA", Suffix: "1"},
		{ID: "id3", Prefix: "AAAAA", Suffix: "1"},
	}
	results, err := LookupCandidates(context.Background(), lookup, candidates)
	if err != nil {
		t.Fatal(err)
	}
	if results["id1"] != 20 || results["id2"] != 10 || results["id3"] != 10 {
		t.Fatalf("results=%v", results)
	}
	if len(lookup.prefix) != 2 || lookup.prefix[0] != "AAAAA" || lookup.prefix[1] != "BBBBB" {
		t.Fatalf("prefix order=%v", lookup.prefix)
	}
	empty, err := LookupCandidates(context.Background(), lookup, nil)
	if err != nil || empty == nil || len(empty) != 0 {
		t.Fatalf("empty candidates: %v %v", empty, err)
	}
	if _, err = LookupCandidates(context.Background(), nil, candidates); !errors.Is(err, ErrHIBP) {
		t.Fatal("nil lookup accepted")
	}
	if _, err = LookupCandidates(context.Background(), lookup, []HIBPCandidate{{ID: "x", Prefix: "nope"}}); !errors.Is(err, ErrHIBP) {
		t.Fatal("invalid candidate prefix accepted")
	}
	lookup.err = errors.New("boom")
	if _, err = LookupCandidates(context.Background(), lookup, candidates); !errors.Is(err, ErrHIBP) {
		t.Fatal("lookup error not fixed")
	}
}
