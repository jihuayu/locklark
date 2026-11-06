package personal

import (
	"errors"
	"net/url"
	"strings"

	"github.com/jihuayu/locklark/internal/origin"
	"github.com/jihuayu/locklark/internal/vault"
	"github.com/jihuayu/locklark/internal/watchtower"
	"golang.org/x/net/publicsuffix"
)

const matchAction = "item.match"

var ErrCrossOrigin = errors.New("cross-origin frame matching refused")

type matchRequest struct{ top, frame string }

func ValidateMatchOrigins(top, frame string) error {
	if _, err := origin.Parse(top); err != nil {
		return err
	}
	_, err := origin.Parse(frame)
	return err
}

// Caller-supplied origins are selectors, not proof of a browser security
// context. A future adapter must obtain them from trusted platform APIs.
func MatchLogins(path, pw string, key []byte, top, frame string) ([]Row, error) {
	topOrigin, err := origin.Parse(top)
	if err != nil {
		return nil, err
	}
	frameOrigin, err := origin.Parse(frame)
	if err != nil {
		return nil, err
	}
	r, err := command(path, pw, key, matchAction, vault.Item{}, nil, commandOption{match: &matchRequest{topOrigin, frameOrigin}})
	if err != nil {
		return nil, err
	}
	return r.rows, nil
}

func hostnameOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

func registrableDomain(host string) string {
	if host == "" {
		return ""
	}
	domain, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		return ""
	}
	return domain
}

func urlMatches(itemURL string, mode, wantOrigin, wantHost string) (bool, error) {
	if _, err := origin.Website(itemURL); err != nil {
		return false, invalid
	}
	switch mode {
	case "", vault.URLMatchOrigin:
		site, err := origin.Website(itemURL)
		if err != nil {
			return false, invalid
		}
		return site == wantOrigin, nil
	case vault.URLMatchHost:
		host := hostnameOf(itemURL)
		return host != "" && host == wantHost, nil
	case vault.URLMatchDomain:
		domain := registrableDomain(hostnameOf(itemURL))
		return domain != "" && domain == registrableDomain(wantHost), nil
	case vault.URLMatchExact:
		return itemURL == wantOrigin, nil
	case vault.URLMatchNever:
		return false, nil
	default:
		return false, invalid
	}
}

func matchingRows(items []vault.Item, revisions map[string]string, want string) ([]Row, error) {
	wantHost := hostnameOf(want)
	rows := make([]Row, 0)
	for _, it := range items {
		if it.EffectiveCategory() != vault.CategoryLogin || it.State != "" {
			continue
		}
		matched := false
		for _, u := range it.AllURLs() {
			ok, err := urlMatches(u.URL, u.MatchMode, want, wantHost)
			if err != nil {
				return nil, err
			}
			if ok {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		if !idOK(it.ID) || !digestOK(revisions[it.ID]) {
			return nil, invalid
		}
		rows = append(rows, Row{Kind: it.Kind, ID: it.ID, Title: it.Title, Revision: revisions[it.ID], State: "active"})
	}
	if len(rows) == 0 {
		return rows, nil
	}
	mapped, err := watchtowerItems(items, revisions)
	if err != nil {
		return nil, err
	}
	// Badge data is local-only: no HIBP client and no network is involved in a
	// match, and reuse counts deliberately cover the whole active login set.
	analysis, err := watchtower.Analyze(mapped, watchtower.Options{})
	if err != nil {
		return nil, invalid
	}
	byID := make(map[string]watchtower.Finding, len(analysis.Report.Findings))
	for _, finding := range analysis.Report.Findings {
		byID[finding.ID] = finding
	}
	for i := range rows {
		finding, ok := byID[rows[i].ID]
		if !ok {
			continue
		}
		score := finding.StrengthScore
		rows[i].WatchtowerFlags = append([]string{}, finding.Flags...)
		rows[i].StrengthScore = &score
		rows[i].StrengthCategory = finding.StrengthCategory
		rows[i].ReuseCount = finding.ReuseCount
		rows[i].BreachCount = finding.BreachCount
	}
	return rows, nil
}
