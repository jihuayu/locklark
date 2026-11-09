package personal

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/jihuayu/locklark/internal/passkey"
	bolt "go.etcd.io/bbolt"
)

// credentialRevisionDomain separates credential content revisions from every
// other keyed digest in the vault. A credential revision is an opaque content
// HMAC, never a monotonic counter and never the parent item revision.
const credentialRevisionDomain = "locklark/passkey/credential-revision/v1\x00"

// ManagedPasskeyMetadata is the explicit managed-passkey projection. It does
// not embed passkey.Metadata: that type has a custom MarshalJSON that would
// silently drop Revision. Only these five public fields are projected; UserID,
// the private key and the raw record never leave the transaction.
type ManagedPasskeyMetadata struct {
	CredentialID string `json:"credential_id"`
	RPID         string `json:"rp_id"`
	UserName     string `json:"user_name"`
	DisplayName  string `json:"display_name"`
	Revision     string `json:"revision"`
}

func (ManagedPasskeyMetadata) String() string   { return "[managed passkey metadata]" }
func (ManagedPasskeyMetadata) GoString() string { return "[managed passkey metadata]" }

// credentialRevisionFromRecord derives the opaque child revision of one loaded
// record. itemID is length framed so no two (item, record) pairs can share an
// HMAC input prefix; the record is re-marshaled canonically, so equivalent JSON
// key orders produce the same token. Callers own record and must clear it.
func credentialRevisionFromRecord(key []byte, itemID string, record *passkey.Record) (string, error) {
	if len(key) == 0 || record == nil || !idOK(itemID) {
		return "", passkey.ErrRefused
	}
	canonical, err := json.Marshal(record)
	if len(canonical) > 0 {
		// The canonical form embeds the base64 private key. Never leave it in a
		// reusable buffer, on success or on any error path.
		defer clear(canonical)
	}
	if err != nil || len(canonical) == 0 {
		return "", passkey.ErrRefused
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(credentialRevisionDomain))
	var frame [8]byte
	binary.BigEndian.PutUint64(frame[:], uint64(len(itemID)))
	mac.Write(frame[:])
	mac.Write([]byte(itemID))
	mac.Write(canonical)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// credentialRevision loads and canonicalizes one durable record before deriving
// its child revision. Both the loaded private key and the canonical JSON are
// cleared before returning.
func credentialRevision(key []byte, itemID string, raw []byte) (string, error) {
	record, err := passkey.Load(raw)
	if err != nil {
		return "", passkey.ErrRefused
	}
	defer record.Clear()
	return credentialRevisionFromRecord(key, itemID, record)
}

// ReadManagedPasskeysMetadata returns public passkey metadata with an opaque
// per-credential content revision, keyed by item ID. The complete projection is
// produced inside one authenticated read transaction and under the native
// session mutex; callers never receive a raw record, user handle or private key.
// Restoring a backup under a rotated identity key may change every token.
func (s *Session) ReadManagedPasskeysMetadata(touch bool) (map[string][]ManagedPasskeyMetadata, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.active(touch); err != nil {
		return nil, err
	}
	db, err := existingWithReadOnly(s.path, true)
	if err != nil {
		return nil, err
	}
	metadata := map[string][]ManagedPasskeyMetadata{}
	err = db.View(func(tx *bolt.Tx) error {
		auth, err := authenticateState(tx, "", nil, passkeyGetAction, s)
		if err != nil {
			return err
		}
		defer auth.clear()
		for _, item := range auth.items {
			var values []ManagedPasskeyMetadata
			for _, raw := range item.PasskeyRecords() {
				record, err := passkey.Load(raw)
				if err != nil {
					continue
				}
				value := ManagedPasskeyMetadata{CredentialID: record.ID, RPID: record.RPID, UserName: record.Name, DisplayName: record.DisplayName}
				value.Revision, err = credentialRevisionFromRecord(auth.identity.AuditEncryption, item.ID, record)
				record.Clear()
				if err != nil || value.CredentialID == "" {
					continue
				}
				values = append(values, value)
			}
			if len(values) > 0 {
				metadata[item.ID] = values
			}
		}
		return nil
	})
	if closeErr := db.Close(); closeErr != nil && err == nil {
		err = ErrCommandClose
	}
	if errors.Is(err, invalid) {
		s.lock()
	}
	if err != nil {
		return nil, err
	}
	if s.active(false) != nil {
		return nil, ErrSessionLocked
	}
	return metadata, nil
}

// RemovePasskeyWithRevision removes one credential only when both the parent
// item revision and the credential's own opaque content revision match. The
// child revision is compared against the authenticated record before the
// commit gate; the exact parent CAS remains mandatory. The legacy RemovePasskey
// wrapper keeps its exact parent+credential-selector behavior unchanged.
func (s *Session) RemovePasskeyWithRevision(id, parentRevision, credentialID, credentialRevision string, g *MutationGate) (string, error) {
	if !digestOK(credentialRevision) {
		if g != nil {
			g.Cancel()
			s.ReleaseMutation(g)
		}
		return "", ErrMutationRefused
	}
	return s.removePasskey(id, parentRevision, credentialID, credentialRevision, g)
}
