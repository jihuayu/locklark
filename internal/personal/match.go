package personal

import (
	"errors"

	"github.com/jihuayu/locklark/internal/origin"
	"github.com/jihuayu/locklark/internal/vault"
	"github.com/jihuayu/locklark/internal/watchtower"
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

func matchingRows(items []vault.Item, revisions map[string]string, want string) ([]Row, error) {
	rows := make([]Row, 0)
	for _, it := range items {
		if it.Kind != "login" || it.State != "" || it.URL == "" {
			continue
		}
		site, err := origin.Website(it.URL)
		if err != nil {
			return nil, invalid
		}
		if site == want {
			rows = append(rows, Row{Kind: it.Kind, ID: it.ID, Title: it.Title, Revision: revisions[it.ID], State: "active"})
		}
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
