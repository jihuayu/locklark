package personal

import (
	"errors"
	"sort"

	"github.com/jihuayu/locklark/internal/passkey"
	bolt "go.etcd.io/bbolt"
)

// PasskeyCandidate is the public, metadata-only projection of one active login
// that can answer a conditional (discoverable credential) passkey request. It
// never carries the private key, the raw record, the user handle or any other
// secret material, so it is safe to copy into a native browser frame.
type PasskeyCandidate struct {
	ItemID       string
	Revision     string
	Title        string
	CredentialID string
	RPID         string
	UserName     string
	DisplayName  string
}

func (PasskeyCandidate) String() string   { return "[passkey candidate]" }
func (PasskeyCandidate) GoString() string { return "[passkey candidate]" }

// ConditionalPasskeyCandidates enumerates the passkey candidates a conditional
// (autofill) request may offer for the exact authenticated origin/document.
// The projection happens inside the authenticated read-only transaction while
// the validated record still exists; records are matched with the same
// passkey.Parse/Matches RP policy used by an assertion and are cleared before
// the transaction returns.
//
// This path is deliberately read-only: it registers no MutationGate, appends no
// audit event, never rewrites the signed snapshot and never renews idle time.
// A conditional listing therefore cannot be used to keep a session alive.
func (s *Session) ConditionalPasskeyCandidates(t PasskeyTarget) ([]PasskeyCandidate, error) {
	if s == nil {
		return nil, ErrSessionLocked
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	request, e := t.parse()
	if e != nil {
		return nil, e
	}
	// Conditional enumeration answers an assertion request only. Creation keeps
	// its explicit native review flow.
	if request.Create || t.ID != "" || t.Revision != "" {
		return nil, passkey.ErrRefused
	}
	if s.active(false) != nil {
		return nil, ErrSessionLocked
	}
	db, e := existingWithReadOnly(s.path, true)
	if e != nil {
		return nil, passkey.ErrRefused
	}
	candidates := []PasskeyCandidate{}
	e = db.View(func(tx *bolt.Tx) error {
		auth, e := authenticateState(tx, "", nil, passkeyGetAction, s)
		if e != nil {
			return e
		}
		defer auth.clear()
		for _, item := range auth.items {
			// Active login items only: archived/trashed states are never offered.
			if item.Kind != "login" || item.State != "" || len(item.Passkey) == 0 {
				continue
			}
			revision := auth.revisions[item.ID]
			if revision == "" {
				continue
			}
			record, e := passkey.Load(item.Passkey)
			if e != nil {
				continue
			}
			matches := request.Matches(record)
			var candidate PasskeyCandidate
			if matches {
				candidate = PasskeyCandidate{ItemID: item.ID, Revision: revision, Title: item.Title, CredentialID: record.ID, RPID: record.RPID, UserName: record.Name, DisplayName: record.DisplayName}
			}
			record.Clear()
			if matches {
				candidates = append(candidates, candidate)
			}
		}
		return nil
	})
	closeErr := db.Close()
	if errors.Is(e, invalid) {
		s.lock()
	}
	if e != nil || closeErr != nil {
		return nil, passkey.ErrRefused
	}
	if s.active(false) != nil {
		return nil, passkey.ErrRefused
	}
	// Stable presentation order: account name, then item title, then item ID.
	sort.SliceStable(candidates, func(a, b int) bool {
		left, right := candidates[a], candidates[b]
		if left.UserName != right.UserName {
			return left.UserName < right.UserName
		}
		if left.Title != right.Title {
			return left.Title < right.Title
		}
		return left.ItemID < right.ItemID
	})
	return candidates, nil
}
