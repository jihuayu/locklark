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
	// CredentialID is the canonical credential selector of an assertion. It is
	// never accepted for creation: a new credential can only be added to a
	// login, never attached to an existing credential identity.
	CredentialID string
	// CredentialRevision is the optional opaque content revision of the exact
	// selected credential. When present it must match the durable record inside
	// the same parent-revision CAS transaction; it never replaces the parent CAS.
	CredentialRevision string
}

type PasskeyChoice struct {
	ID                 string
	Revision           string
	Title              string
	Username           string
	CredentialID       string
	CredentialRevision string
}

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
	// A credential selector must be canonical and can only ever narrow an
	// assertion. Creation is forbidden from carrying one, so a selector can
	// never be used to replace an existing credential.
	if t.CredentialID != "" && (t.Create || !passkey.ValidCredentialID(t.CredentialID)) {
		return nil, passkey.ErrRefused
	}
	// A child revision only ever narrows an existing credential, and only when
	// that exact credential is named. Creation can never carry one.
	if t.CredentialRevision != "" && (t.Create || t.CredentialID == "" || !digestOK(t.CredentialRevision)) {
		return nil, passkey.ErrRefused
	}
	return passkey.Parse(t.Context.Origin, t.Create, t.Options)
}

// pinned reports that the request selected one exact login. An assertion that
// pinned a target may only ever be reviewed or answered for that item and
// revision; anything else is refused instead of falling back to a list.
func (t PasskeyTarget) pinned() bool { return !t.Create && t.ID != "" }

// createRecordsMatch reports whether every durable credential of an existing
// login already carries exactly the identity (RP ID and user handle) this
// creation request registers. Appending is only allowed for the same account;
// a login never silently changes identity by collecting another credential.
func createRecordsMatch(request *passkey.Request, records [][]byte) bool {
	if len(records) == 0 {
		return true
	}
	for _, raw := range records {
		record, e := passkey.Load(raw)
		if e != nil {
			return false
		}
		matches := record.RPID == request.RPID && record.UserID == request.Options.User.ID
		record.Clear()
		if !matches {
			return false
		}
	}
	return true
}

// selectAssertionRecord resolves exactly one durable credential for an
// assertion. A canonical selector pins one record and nothing else; without a
// selector only a single-record login (legacy blob or singleton collection) can
// answer. Multiple records are ambiguous and MUST be refused: there is never a
// first-record fallback.
func selectAssertionRecord(records [][]byte, credentialID string) (*passkey.Record, error) {
	if credentialID == "" {
		if len(records) != 1 {
			return nil, passkey.ErrRefused
		}
		record, e := passkey.Load(records[0])
		if e != nil {
			return nil, passkey.ErrRefused
		}
		return record, nil
	}
	for _, raw := range records {
		record, e := passkey.Load(raw)
		if e != nil {
			continue
		}
		if record.ID == credentialID {
			return record, nil
		}
		record.Clear()
	}
	return nil, passkey.ErrRefused
}

// ReviewPasskey returns native-only choices, without revealing private keys.
// Browser polling cannot renew idle time. Choices are produced per durable
// credential, so one login may appear once for each credential it owns. When
// the assertion pinned an exact item/revision the review contains only that
// target, or fails.
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
		found := false
		for _, item := range auth.items {
			if item.Kind != "login" || item.State != "" {
				continue
			}
			if t.ID != "" {
				// A stale or missing pinned target is refused; it must never
				// widen into unrelated accounts. This applies to creation too:
				// attaching to an exact login never reaches a sibling login.
				if item.ID != t.ID || auth.revisions[item.ID] != t.Revision {
					continue
				}
				found = true
			}
			revision := auth.revisions[item.ID]
			if request.Create {
				site, err := origin.Website(item.URL)
				if err != nil || site != t.Context.Origin {
					continue
				}
				// Only a login that already belongs to this exact identity may
				// collect another credential; every other login is untouched.
				if !createRecordsMatch(request, item.PasskeyRecords()) {
					continue
				}
				choices = append(choices, PasskeyChoice{ID: item.ID, Revision: revision, Title: item.Title, Username: item.Username})
				continue
			}
			for _, raw := range item.PasskeyRecords() {
				record, e := passkey.Load(raw)
				if e != nil {
					continue
				}
				matches := request.Matches(record)
				credential := record.ID
				childRevision := ""
				if matches && (t.CredentialID == "" || t.CredentialID == credential) {
					childRevision, _ = credentialRevisionFromRecord(auth.identity.AuditEncryption, item.ID, record)
				}
				record.Clear()
				// An explicit selector selects only that exact record; it can
				// never widen to another credential of the same login.
				if !matches || t.CredentialID != "" && t.CredentialID != credential || childRevision == "" ||
					t.CredentialRevision != "" && !hmac.Equal([]byte(t.CredentialRevision), []byte(childRevision)) {
					continue
				}
				choices = append(choices, PasskeyChoice{ID: item.ID, Revision: revision, Title: item.Title, Username: item.Username, CredentialID: credential, CredentialRevision: childRevision})
			}
		}
		if t.ID != "" && !found {
			return passkey.ErrRefused
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
			// The exclusion policy applies to every credential of every item,
			// not only to a legacy single record or the selected login.
			for _, item := range items {
				for _, raw := range item.PasskeyRecords() {
					record, e := passkey.Load(raw)
					if e != nil {
						continue
					}
					excluded := request.Excludes(record)
					record.Clear()
					if excluded {
						return passkey.ErrExcluded
					}
				}
			}
			// Never silently replace or re-identify a previously registered
			// credential: attaching to an existing login is only allowed for
			// the exact same RP ID and user handle, and always appends.
			existing := [][]byte(nil)
			if index >= 0 {
				existing = items[index].PasskeyRecords()
				if !createRecordsMatch(request, existing) {
					return passkey.ErrExcluded
				}
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
			} else if len(existing) == 0 && len(items[index].Passkeys) == 0 {
				// The first credential of an otherwise empty login stays in the
				// legacy slot: existing readers and backups keep seeing the same
				// single-record form. A second credential migrates the login to
				// the versioned collection below.
				next := vault.CloneItem(items[index])
				if e := next.SetLegacyPasskey(record); e != nil {
					return passkey.ErrRefused
				}
				items[index].ClearPasskeys()
				items[index] = next
			} else {
				// Adding a sibling migrates the login to the versioned collection.
				// The merged list is cloned before the borrowed durable bytes are
				// zeroed.
				merged := make([][]byte, 0, len(existing)+1)
				merged = append(merged, existing...)
				merged = append(merged, record)
				next := vault.CloneItem(items[index])
				if e := next.SetPasskeyRecords(merged); e != nil {
					return passkey.ErrRefused
				}
				items[index].ClearPasskeys()
				items[index] = next
			}
		} else {
			if index < 0 {
				return passkey.ErrRefused
			}
			record, e := selectAssertionRecord(items[index].PasskeyRecords(), t.CredentialID)
			if e != nil {
				return e
			}
			defer record.Clear()
			if t.CredentialRevision != "" {
				actual, revisionErr := credentialRevisionFromRecord(auth.identity.AuditEncryption, items[index].ID, record)
				if revisionErr != nil || !hmac.Equal([]byte(actual), []byte(t.CredentialRevision)) {
					return passkey.ErrRefused
				}
			}
			response, e = passkey.Get(request, record, verified)
			if e != nil {
				return e
			}
		}
		if vault.ValidateItems([]byte(schema), items) != nil {
			return passkey.ErrRefused
		}
		// Bind the origin, document, request, challenge/options, exact selected
		// item, credential selector and UV result without publishing any of them
		// as raw audit payloads.
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
