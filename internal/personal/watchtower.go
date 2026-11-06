package personal

import (
	"context"
	"crypto/rand"

	"github.com/jihuayu/locklark/internal/origin"
	"github.com/jihuayu/locklark/internal/vault"
	"github.com/jihuayu/locklark/internal/watchtower"
)

const (
	watchtowerAction = "vault.health.watchtower"
	hibpAction       = "vault.health.hibp"
)

// watchtowerRequest is the local-only phase. It never carries a network client;
// the range lookup is a separate, explicitly audited phase.
type watchtowerRequest struct {
	origin  string
	key     []byte
	collect bool
}

func (r watchtowerRequest) valid() bool {
	return len(r.key) == 32 && validWatchtowerOrigin(r.origin)
}

// hibpRequest is either the pre-network intent or the post-lookup success
// phase. checked is true only when every required range request succeeded, so a
// nil results map means "unavailable" rather than "nothing to check".
type hibpRequest struct {
	origin  string
	key     []byte
	results map[string]int
	intent  bool
	checked bool
}

func (r hibpRequest) valid() bool {
	if r.intent {
		return r.origin == "" && r.key == nil && r.results == nil && !r.checked
	}
	return r.checked == (r.results != nil) && len(r.key) == 32 && validWatchtowerOrigin(r.origin)
}

func validWatchtowerOrigin(site string) bool {
	if site == "" {
		return true
	}
	parsed, err := origin.Parse(site)
	return err == nil && parsed == site
}

// watchtowerItems is the only conversion from the encrypted vault model to the
// pure package projection. Non-login items stay in Skipped.
func watchtowerItems(items []vault.Item, revisions map[string]string) ([]watchtower.Item, error) {
	out := make([]watchtower.Item, 0, len(items))
	for _, it := range items {
		if it.Kind != "login" {
			continue
		}
		revision := revisions[it.ID]
		if !idOK(it.ID) || !digestOK(revision) {
			return nil, invalid
		}
		out = append(out, watchtower.Item{
			ID:         it.ID,
			Revision:   revision,
			Kind:       it.Kind,
			Title:      it.Title,
			Username:   it.Username,
			URL:        it.URL,
			Password:   it.Password,
			OTP:        it.OTP,
			State:      it.State,
			HasPasskey: len(it.Passkey) > 0,
		})
	}
	return out, nil
}

func analyzeWatchtower(items []vault.Item, revisions map[string]string, req watchtowerRequest) (watchtower.Analysis, error) {
	mapped, err := watchtowerItems(items, revisions)
	if err != nil {
		return watchtower.Analysis{}, err
	}
	return watchtower.Analyze(mapped, watchtower.Options{
		Origin:      req.origin,
		Key:         req.key,
		CollectHIBP: req.collect,
	})
}

func analyzeHIBP(items []vault.Item, revisions map[string]string, req hibpRequest) (watchtower.Report, error) {
	mapped, err := watchtowerItems(items, revisions)
	if err != nil {
		return watchtower.Report{}, err
	}
	analysis, err := watchtower.Analyze(mapped, watchtower.Options{
		Origin:      req.origin,
		Key:         req.key,
		IncludeHIBP: true,
		HIBPResults: req.results,
	})
	if err != nil {
		return watchtower.Report{}, err
	}
	return analysis.Report, nil
}

// watchtowerKeyLocked returns a session-scoped HMAC key. It is only used for
// in-memory reuse grouping and is cleared on lock.
func (s *Session) watchtowerKeyLocked() ([]byte, error) {
	if len(s.watchtowerKey) == 0 {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, invalid
		}
		s.watchtowerKey = key
	}
	return s.watchtowerKey, nil
}

// Watchtower runs the authenticated local scan. HIBP is strictly opt-in and is
// split into three committed phases: local report, intent audit, then a final
// authenticated report with precomputed ids. No write transaction spans the
// network request. The local-only path performs exactly one read-only audit
// transaction and never contacts a network client.
func (s *Session) Watchtower(site string, includeHIBP bool) (watchtower.Report, error) {
	if !validWatchtowerOrigin(site) {
		return watchtower.Report{}, invalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.active(false); err != nil {
		return watchtower.Report{}, err
	}
	key, err := s.watchtowerKeyLocked()
	if err != nil {
		return watchtower.Report{}, err
	}
	local, err := s.executeActive(watchtowerAction, vault.Item{}, nil, commandOption{
		watchtower: &watchtowerRequest{origin: site, key: key, collect: includeHIBP},
	}, false)
	if err != nil {
		return watchtower.Report{}, err
	}
	if !includeHIBP {
		return local.watchtowerReport, nil
	}
	if _, err = s.executeActive(hibpAction, vault.Item{}, nil, commandOption{
		hibp: &hibpRequest{intent: true},
	}, false); err != nil {
		return watchtower.Report{}, err
	}
	var results map[string]int
	checked := false
	if s.hibp != nil {
		if got, lookupErr := watchtower.LookupCandidates(context.Background(), s.hibp, local.hibpCandidates); lookupErr == nil {
			results = got
			checked = got != nil
		}
	}
	final, err := s.executeActive(hibpAction, vault.Item{}, nil, commandOption{
		hibp: &hibpRequest{origin: site, key: key, results: results, checked: checked},
	}, false)
	if err != nil {
		return watchtower.Report{}, err
	}
	return final.watchtowerReport, nil
}
