package browserhost

import (
	"errors"
	"strings"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
)

// BrowserPasskey is the public metadata projection attached to popup list and
// detail DTOs. It never carries the private key, raw record or user handle.
type BrowserPasskey struct {
	CredentialID string `json:"credential_id"`
	RPID         string `json:"rp_id"`
	UserName     string `json:"user_name"`
	DisplayName  string `json:"display_name"`
	// CredentialRevision is the opaque per-credential content revision used as
	// the exact child selector by the popup and by native removal. It is never
	// the parent item revision and carries no private material.
	CredentialRevision string `json:"credential_revision,omitempty"`
}

func browserPasskey(metadata personal.ManagedPasskeyMetadata) *BrowserPasskey {
	return &BrowserPasskey{
		CredentialID:       metadata.CredentialID,
		RPID:               metadata.RPID,
		UserName:           metadata.UserName,
		DisplayName:        metadata.DisplayName,
		CredentialRevision: metadata.Revision,
	}
}

// MaxBrowserPasskeys is the detail-frame bound for per-credential metadata. A
// login cannot render an unbounded array; callers must not raise this without
// re-checking the encoded frame against MaxOutput.
const MaxBrowserPasskeys = 16

func passkeyMetadataMatches(metadata personal.ManagedPasskeyMetadata, query string) bool {
	if query == "" {
		return true
	}
	for _, value := range []string{metadata.RPID, metadata.UserName, metadata.DisplayName} {
		if strings.Contains(strings.ToLower(value), query) {
			return true
		}
	}
	return false
}

// passkeyRemove is dispatched through the v2 mutation table so the new request
// never needs a second, weaker persistence path. It is intentionally stateless:
// every selector is revalidated inside the authenticated Session transaction.
// passkeysMetadataMatch reports whether any credential of one login matches the
// public query. It scans every credential: a multi-credential login must never
// be judged by its first record.
func passkeysMetadataMatch(values []personal.ManagedPasskeyMetadata, query string) bool {
	if query == "" {
		return len(values) > 0
	}
	for _, metadata := range values {
		if passkeyMetadataMatches(metadata, query) {
			return true
		}
	}
	return false
}

func (c *Connection) passkeyRemove(r Request) error {
	// A preapproval passkey owns the Session's single mutation slot. Removal
	// must refuse busy instead of preempting a native approval; a queued result
	// after PerformPasskey has released the slot is revoked by the epoch.
	if c.passkey != nil || c.save != nil || c.otp != nil || c.pending != nil || c.stagedBusy || c.upload != nil {
		return c.refuse(r.ID)
	}
	s := c.session.Load()
	if s == nil || !s.Unlocked() {
		return c.refuse(r.ID)
	}
	gate := personal.NewMutationGate(minTime(c.until, c.now().Add(30*time.Second)))
	if s.RegisterMutation(gate) != nil {
		return c.refuse(r.ID)
	}
	var revision string
	var err error
	if r.CredentialRevision != "" {
		// A child revision, when supplied, binds the removal to the exact
		// reviewed credential content in addition to the mandatory parent CAS.
		revision, err = s.RemovePasskeyWithRevision(r.ItemID, r.Revision, r.CredentialID, r.CredentialRevision, gate)
	} else {
		// The legacy selector stays exact on parent + credential and never
		// becomes an implicit first-record choice.
		revision, err = s.RemovePasskey(r.ItemID, r.Revision, r.CredentialID, gate)
	}
	if err != nil {
		// The gate only wins after every selector and revision check. From that
		// point on the removal may have persisted, so never claim it failed.
		if errors.Is(err, personal.ErrMutationUnknown) || gate.CommitWon() {
			return c.response(Response{ID: r.ID, Type: "unknown"})
		}
		return c.refuse(r.ID)
	}
	// Revoke any approval surface on this connection before reporting success.
	// A running worker keeps its gate and suppresses its own queued result.
	if refuseID, _ := c.expireConcurrentPasskey(); refuseID != "" {
		if writeErr := c.refuse(refuseID); writeErr != nil {
			return writeErr
		}
	}
	// A successful commit whose connection/session authority changed while the
	// transaction ran still has a durable result: report it as unknown rather
	// than pretending the credential removal failed.
	if s != c.session.Load() || !s.Unlocked() || !c.valid(r.Capability) {
		return c.response(Response{ID: r.ID, Type: "unknown"})
	}
	return c.response(Response{ID: r.ID, Type: "passkey-removed", ItemID: r.ItemID, Revision: revision, CredentialID: r.CredentialID})
}
