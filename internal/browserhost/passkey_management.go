package browserhost

import (
	"errors"
	"strings"
	"time"

	"github.com/jihuayu/locklark/internal/passkey"
	"github.com/jihuayu/locklark/internal/personal"
)

// BrowserPasskey is the public metadata projection attached to popup list and
// detail DTOs. It never carries the private key, raw record or user handle.
type BrowserPasskey struct {
	CredentialID string `json:"credential_id"`
	RPID         string `json:"rp_id"`
	UserName     string `json:"user_name"`
	DisplayName  string `json:"display_name"`
}

func browserPasskey(metadata passkey.Metadata) *BrowserPasskey {
	return &BrowserPasskey{
		CredentialID: metadata.CredentialID,
		RPID:         metadata.RPID,
		UserName:     metadata.UserName,
		DisplayName:  metadata.DisplayName,
	}
}

func passkeyMetadataMatches(metadata passkey.Metadata, query string) bool {
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
	revision, err := s.RemovePasskey(r.ItemID, r.Revision, r.CredentialID, gate)
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
