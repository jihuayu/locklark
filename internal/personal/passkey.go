package personal

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/jihuayu/locklark/internal/origin"
	"github.com/jihuayu/locklark/internal/passkey"
	"github.com/jihuayu/locklark/internal/vault"
	bolt "go.etcd.io/bbolt"
)

const passkeyCreateAction = "item.passkey.create"
const passkeyGetAction = "item.passkey.get"

type PasskeyTarget struct {
	Context      BrowserContext
	Create       bool
	Options      []byte
	ID, Revision string
}
type PasskeyChoice struct{ ID, Revision, Title, Username string }

func (PasskeyTarget) String() string   { return "[passkey request]" }
func (PasskeyTarget) GoString() string { return "[passkey request]" }
func (t PasskeyTarget) parse() (*passkey.Request, error) {
	if !t.Context.Valid() {
		return nil, passkey.ErrRefused
	}
	if t.ID != "" && (!idOK(t.ID) || !digestOK(t.Revision)) {
		return nil, passkey.ErrRefused
	}
	if t.ID == "" && t.Revision != "" {
		return nil, passkey.ErrRefused
	}
	return passkey.Parse(t.Context.Origin, t.Create, t.Options)
}

// ReviewPasskey returns native-only choices, without revealing private keys.
// Browser polling cannot renew idle time.
func (s *Session) ReviewPasskey(t PasskeyTarget) ([]PasskeyChoice, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	request, e := t.parse()
	if e != nil {
		return nil, e
	}
	if s.active(false) != nil {
		return nil, ErrSessionLocked
	}
	db, e := existingWithReadOnly(s.path, true)
	if e != nil {
		return nil, passkey.ErrRefused
	}
	defer db.Close()
	choices := []PasskeyChoice{}
	e = db.View(func(tx *bolt.Tx) error {
		auth, e := authenticateState(tx, "", nil, passkeyGetAction, s)
		if e != nil {
			return e
		}
		defer auth.clear()
		for _, item := range auth.items {
			if item.Kind != "login" || item.State != "" {
				continue
			}
			if request.Create {
				site, err := origin.Website(item.URL)
				if err == nil && site == t.Context.Origin && len(item.Passkey) == 0 {
					choices = append(choices, PasskeyChoice{item.ID, auth.revisions[item.ID], item.Title, item.Username})
				}
				continue
			}
			record, e := passkey.Load(item.Passkey)
			if e != nil {
				continue
			}
			matches := request.Matches(record)
			record.Clear()
			if matches {
				choices = append(choices, PasskeyChoice{item.ID, auth.revisions[item.ID], item.Title, item.Username})
			}
		}
		return nil
	})
	if errors.Is(e, invalid) {
		s.lock()
	}
	if e != nil || s.active(false) != nil {
		return nil, passkey.ErrRefused
	}
	return choices, nil
}

// VerifyPasskeyUser performs fresh knowledge-factor verification on the native
// UI path. Secret Service retrieval alone must never be claimed as WebAuthn UV.
func (s *Session) VerifyPasskeyUser(password, key []byte) error {
	defer clear(password)
	defer clear(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active(false) != nil {
		return ErrSessionLocked
	}
	db, e := existingWithReadOnly(s.path, true)
	if e != nil {
		return passkey.ErrRefused
	}
	defer db.Close()
	e = db.View(func(tx *bolt.Tx) error {
		auth, e := authenticateState(tx, string(password), key, passkeyGetAction, nil)
		if e != nil {
			return passkey.ErrRefused
		}
		defer auth.clear()
		if sha256.Sum256(tx.Bucket(bucket).Get(slotKey)) != s.slotDigest || !bytes.Equal(auth.opened, s.material) {
			return passkey.ErrRefused
		}
		return nil
	})
	if e != nil {
		return passkey.ErrRefused
	}
	return s.active(false)
}

// PerformPasskey commits a dedicated audit and, for creation, the encrypted
// credential in the same transaction. No response escapes on commit/close failure.
func (s *Session) PerformPasskey(t PasskeyTarget, verified bool, g *MutationGate) (passkey.Response, error) {
	defer s.ReleaseMutation(g)
	s.mu.Lock()
	defer s.mu.Unlock()
	request, e := t.parse()
	if e != nil {
		return passkey.Response{}, e
	}
	if !s.registeredMutation(g) || s.active(true) != nil {
		return passkey.Response{}, ErrMutationCancelled
	}
	if request.RequiresVerification() && !verified {
		return passkey.Response{}, passkey.ErrRefused
	}
	action := passkeyGetAction
	if t.Create {
		action = passkeyCreateAction
	}
	db, e := existing(s.path)
	if e != nil {
		return passkey.Response{}, passkey.ErrRefused
	}
	var response passkey.Response
	e = db.Update(func(tx *bolt.Tx) error {
		auth, e := authenticateState(tx, "", nil, action, s)
		if e != nil {
			return e
		}
		defer auth.clear()
		items := auth.items
		index := -1
		for n, item := range items {
			if item.ID == t.ID {
				index = n
			}
		}
		if t.ID != "" && (index < 0 || auth.revisions[t.ID] != t.Revision || items[index].Kind != "login" || items[index].State != "") {
			return ErrConflict
		}
		itemID := t.ID
		if t.Create {
			if index >= 0 {
				site, err := origin.Website(items[index].URL)
				if err != nil || site != t.Context.Origin {
					return passkey.ErrRefused
				}
			}
			for _, item := range items {
				record, e := passkey.Load(item.Passkey)
				if e == nil {
					excluded := request.Excludes(record)
					record.Clear()
					if excluded {
						return passkey.ErrExcluded
					}
				}
			}
			// Never silently replace a previously registered credential.
			if index >= 0 && len(items[index].Passkey) > 0 {
				return passkey.ErrExcluded
			}
			var record []byte
			record, response, e = passkey.Create(request, verified)
			if e != nil {
				return e
			}
			defer clear(record)
			if index < 0 {
				itemID, e = randomID()
				if e != nil {
					return e
				}
				items = append(items, vault.Item{ID: itemID, Kind: "login", Title: request.RPID + " · " + request.Options.User.Name, URL: t.Context.Origin, Username: request.Options.User.Name, Passkey: record})
			} else {
				items[index].Passkey = record
			}
		} else {
			if index < 0 {
				return passkey.ErrRefused
			}
			record, e := passkey.Load(items[index].Passkey)
			if e != nil {
				return e
			}
			defer record.Clear()
			response, e = passkey.Get(request, record, verified)
			if e != nil {
				return e
			}
		}
		if vault.ValidateItems([]byte(schema), items) != nil {
			return passkey.ErrRefused
		}
		// Bind the origin, document, request, challenge/options, exact selected item
		// and UV result without publishing any of them as raw audit payloads.
		bound, _ := json.Marshal(struct {
			Target   PasskeyTarget
			Verified bool
		}{t, verified})
		mac := hmac.New(sha256.New, auth.identity.AuditEncryption)
		mac.Write([]byte("locklark/passkey/v1\x00"))
		mac.Write(bound)
		clear(bound)
		link := hex.EncodeToString(mac.Sum(nil))
		if !s.winBrowserSave(g) {
			return ErrMutationCancelled
		}
		snapshot := auth.snapshot
		if t.Create {
			snapshot, e = seal(tx.Bucket(bucket), auth.identity, snapshot.Epoch+1, items)
			if e != nil {
				return e
			}
		}
		result := "intent"
		if t.Create {
			result = "succeeded"
		}
		_, e = appendLinked(tx.Bucket(bucket), auth.identity, auth.tip, snapshot, action, itemID, result, auth.revisions[itemID], link, eventDetails{})
		return e
	})
	closeErr := db.Close()
	if errors.Is(e, invalid) {
		s.lock()
	}
	active := s.active(false) == nil
	if e != nil || closeErr != nil || !active {
		if g.CommitWon() {
			return passkey.Response{}, ErrMutationUnknown
		}
		if !active {
			return passkey.Response{}, ErrMutationCancelled
		}
		return passkey.Response{}, passkey.ErrRefused
	}
	return response, nil
}
