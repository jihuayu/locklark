package personal

import (
	"errors"
	"github.com/jihuayu/locklark/internal/origin"
	"github.com/jihuayu/locklark/internal/vault"
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
			rows = append(rows, Row{ID: it.ID, Title: it.Title, Revision: revisions[it.ID], State: "active"})
		}
	}
	return rows, nil
}
