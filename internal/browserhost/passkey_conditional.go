package browserhost

import (
	"encoding/json"

	"github.com/jihuayu/locklark/internal/personal"
)

// MaxPasskeyCandidates bounds one conditional account list. Larger result sets
// are trimmed and reported with truncated=true instead of emitting a huge frame.
const MaxPasskeyCandidates = 50

// passkeyCandidatesResponse builds the exact passkey-candidates frame. The
// projection is metadata only and the encoded body is kept strictly below
// MaxOutput, so a native frame is never split or partially written.
func passkeyCandidatesResponse(id string, candidates []personal.PasskeyCandidate) (Response, error) {
	passkeys := make([]BrowserPasskeyCandidate, 0, len(candidates))
	for _, candidate := range candidates {
		if len(passkeys) == MaxPasskeyCandidates {
			break
		}
		passkeys = append(passkeys, BrowserPasskeyCandidate{
			ItemID:       candidate.ItemID,
			Revision:     candidate.Revision,
			Title:        candidate.Title,
			CredentialID: candidate.CredentialID,
			RPID:         candidate.RPID,
			UserName:     candidate.UserName,
			DisplayName:  candidate.DisplayName,
		})
	}
	truncated := len(passkeys) < len(candidates)
	for {
		response := Response{V: 1, ID: id, Type: "passkey-candidates", Passkeys: passkeys, PasskeyTruncated: truncated}
		raw, e := json.Marshal(response)
		if e != nil {
			clear(raw)
			return Response{}, ErrProtocol
		}
		fit := len(raw) < MaxOutput
		clear(raw)
		if fit {
			return response, nil
		}
		if len(passkeys) == 0 {
			return Response{}, ErrProtocol
		}
		// Drop only whole entries: a truncated list stays valid JSON.
		passkeys = passkeys[:len(passkeys)-1]
		truncated = true
	}
}

// listPasskeyCandidates answers a conditional (discoverable credential) request
// from the native vault. The listing is strictly read-only and independent of
// any pending native approval: it reserves no MutationGate, creates no
// c.passkey approval surface, appends no audit event, mutates no snapshot and
// never renews idle authority.
func (c *Connection) listPasskeyCandidates(r Request) error {
	s := c.session.Load()
	if s == nil || !c.valid(r.Capability) {
		return c.refuse(r.ID)
	}
	epoch := c.epoch
	candidates, e := s.ConditionalPasskeyCandidates(personal.PasskeyTarget{Context: r.Context(), Options: []byte(r.Options)})
	if e != nil || epoch != c.generation.Load() || c.session.Load() != s || !s.Unlocked() {
		if !s.Unlocked() {
			c.invalidate()
		}
		return c.refuse(r.ID)
	}
	response, e := passkeyCandidatesResponse(r.ID, candidates)
	if e != nil {
		return c.refuse(r.ID)
	}
	// The frame may queue behind another writer. The grant revalidates the
	// current session, capability and generation so a list never escapes after
	// a lock, unpaired capability or revoked origin/document authority.
	e = c.writer.WriteGranted(c.until, nil, func() (Response, error) {
		if !c.valid(r.Capability) || c.session.Load() != s || epoch != c.generation.Load() {
			return Response{}, ErrProtocol
		}
		return response, nil
	})
	if e != nil && !c.closed.Load() && !c.valid(r.Capability) {
		_ = c.refuse(r.ID)
	}
	return e
}
