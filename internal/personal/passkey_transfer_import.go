package personal

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"filippo.io/age"
	"github.com/jihuayu/locklark/internal/passkey"
	"github.com/jihuayu/locklark/internal/passkeytransfer"
	"github.com/jihuayu/locklark/internal/vault"
	bolt "go.etcd.io/bbolt"
)

const (
	passkeyTransferItemAction = "item.passkey.transfer"

	passkeyTransferGroupDomain     = "locklark/personal/passkey-transfer/group/v1\x00"
	passkeyTransferPlanDomain      = "locklark/personal/passkey-transfer/plan/v1\x00"
	passkeyTransferApplyLinkDomain = "locklark/personal/passkey-transfer/apply/v1\x00"

	maxPasskeyTransferCandidates = 100
	maxPasskeyTransferPlanBytes  = 192 << 10
	maxPasskeyTransferText       = 1024
)

// PasskeyTransferEligibleTarget is one existing active login that already owns
// only credentials for the same RP ID and WebAuthn user handle. ID and Revision
// are the exact frozen parent selectors the caller may map this group onto.
type PasskeyTransferEligibleTarget struct {
	ID       string `json:"id"`
	Revision string `json:"revision"`
	Title    string `json:"title"`
}

// PasskeyTransferGroup is the public grouping of incoming credentials by exact
// RP ID and WebAuthn user handle. GroupID is a keyed HMAC; the raw user handle
// never leaves the transaction. PublicUserNames are display names stored in the
// credential records, not the raw WebAuthn user ID.
type PasskeyTransferGroup struct {
	GroupID         string                          `json:"group_id"`
	RPID            string                          `json:"rp_id"`
	PublicUserNames []string                        `json:"public_user_names"`
	CredentialIDs   []string                        `json:"credential_ids"`
	EligibleTargets []PasskeyTransferEligibleTarget `json:"eligible_targets"`
}

// PasskeyTransferPlan is the complete public receiver preview. It carries only
// public selectors and HMAC group identifiers: never a raw record, private key
// or WebAuthn user handle.
type PasskeyTransferPlan struct {
	Digest            string                 `json:"digest"`
	InvitationID      string                 `json:"invitation_id"`
	ExpiresAt         time.Time              `json:"expires_at"`
	SourceFingerprint string                 `json:"source_fingerprint"`
	TargetFingerprint string                 `json:"target_fingerprint"`
	Groups            []PasskeyTransferGroup `json:"groups"`
}

func (PasskeyTransferPlan) String() string   { return "[passkey transfer plan]" }
func (PasskeyTransferPlan) GoString() string { return "[passkey transfer plan]" }

// MarshalJSON is an explicit allowlist. It exists so a future private field can
// never be exported accidentally by the default struct encoder.
func (p PasskeyTransferPlan) MarshalJSON() ([]byte, error) {
	type group struct {
		GroupID         string                          `json:"group_id"`
		RPID            string                          `json:"rp_id"`
		PublicUserNames []string                        `json:"public_user_names"`
		CredentialIDs   []string                        `json:"credential_ids"`
		EligibleTargets []PasskeyTransferEligibleTarget `json:"eligible_targets"`
	}
	groups := make([]group, len(p.Groups))
	for i, g := range p.Groups {
		groups[i] = group{g.GroupID, g.RPID, g.PublicUserNames, g.CredentialIDs, g.EligibleTargets}
	}
	return json.Marshal(struct {
		Digest            string    `json:"digest"`
		InvitationID      string    `json:"invitation_id"`
		ExpiresAt         time.Time `json:"expires_at"`
		SourceFingerprint string    `json:"source_fingerprint"`
		TargetFingerprint string    `json:"target_fingerprint"`
		Groups            []group   `json:"groups"`
	}{p.Digest, p.InvitationID, p.ExpiresAt, p.SourceFingerprint, p.TargetFingerprint, groups})
}

// PasskeyTransferMapping is the owner's explicit decision for exactly one
// plan group: either one existing eligible parent with its exact revision, or a
// new login with an explicit title and optional explicit username. NewTitle and
// NewUsername are never inferred from the first credential.
type PasskeyTransferMapping struct {
	GroupID          string
	ExistingTargetID string
	ExistingRevision string
	NewTitle         string
	NewUsername      string
}

// PasskeyTransferItemReceipt is one new parent item revision. It is returned
// only after the database close succeeded and the session is still active.
type PasskeyTransferItemReceipt struct {
	ID       string `json:"id"`
	Revision string `json:"revision"`
}

// PasskeyTransferApplyReceipt contains exactly the changed parent revisions.
type PasskeyTransferApplyReceipt struct {
	Items []PasskeyTransferItemReceipt `json:"items"`
}

func (PasskeyTransferApplyReceipt) String() string   { return "[passkey transfer receipt]" }
func (PasskeyTransferApplyReceipt) GoString() string { return "[passkey transfer receipt]" }

type passkeyTransferPlanBody struct {
	PacketDigest      string                 `json:"packet_digest"`
	PacketID          string                 `json:"packet_id"`
	InvitationDigest  string                 `json:"invitation_digest"`
	Creation          string                 `json:"creation"`
	InvitationID      string                 `json:"invitation_id"`
	ExpiresAt         int64                  `json:"expires_at"`
	SourceFingerprint string                 `json:"source_fingerprint"`
	TargetFingerprint string                 `json:"target_fingerprint"`
	Groups            []PasskeyTransferGroup `json:"groups"`
}

type passkeyTransferBuiltGroup struct {
	Public  PasskeyTransferGroup
	UserID  string
	Records []int
}

type passkeyTransferBuilt struct {
	Public           PasskeyTransferPlan
	Groups           []passkeyTransferBuiltGroup
	Decoded          []passkeytransfer.Decoded
	PacketDigest     string
	PacketID         string
	InvitationDigest string
	Creation         string
	InvitationLink   string
}

func (b *passkeyTransferBuilt) clear() {
	if b == nil {
		return
	}
	for i := range b.Decoded {
		b.Decoded[i].Clear()
	}
	b.Decoded = nil
}

func clearPasskeyTransferDecoded(records []passkeytransfer.Decoded) {
	for i := range records {
		records[i].Clear()
	}
}

func transferSafeText(value string, allowEmpty bool) bool {
	return (allowEmpty || value != "") && len(value) <= maxPasskeyTransferText && utf8.ValidString(value) && !strings.ContainsAny(value, "\x00\r\n")
}

func (s *PasskeyTransferPlan) validatePublicBudget() error {
	raw, err := json.Marshal(s)
	if err != nil || len(raw) == 0 || len(raw) > maxPasskeyTransferPlanBytes {
		return ErrMutationRefused
	}
	return nil
}

func passkeyTransferLengthFrame(mac []byte, value string) []byte {
	var frame [8]byte
	binary.BigEndian.PutUint64(frame[:], uint64(len(value)))
	mac = append(mac, frame[:]...)
	return append(mac, value...)
}

func passkeyTransferGroupID(key []byte, rpID, userID string) (string, error) {
	if len(key) == 0 || rpID == "" || userID == "" {
		return "", invalid
	}
	h := hmac.New(sha256.New, key)
	h.Write([]byte(passkeyTransferGroupDomain))
	buf := passkeyTransferLengthFrame(nil, rpID)
	buf = passkeyTransferLengthFrame(buf, userID)
	h.Write(buf)
	clear(buf)
	return hex.EncodeToString(h.Sum(nil)), nil
}

func passkeyTransferPlanDigest(key []byte, body passkeyTransferPlanBody) (string, error) {
	if len(key) == 0 || !digestOK(body.PacketDigest) || !idOK(body.PacketID) || !digestOK(body.InvitationDigest) || !digestOK(body.Creation) || !idOK(body.InvitationID) || !digestOK(body.SourceFingerprint) || !digestOK(body.TargetFingerprint) {
		return "", invalid
	}
	raw, err := json.Marshal(body)
	if err != nil || len(raw) == 0 {
		return "", invalid
	}
	defer clear(raw)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(passkeyTransferPlanDomain))
	var frame [8]byte
	binary.BigEndian.PutUint64(frame[:], uint64(len(raw)))
	h.Write(frame[:])
	h.Write(raw)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// buildPasskeyTransferPlan recomputes the complete preview from the current
// authenticated identity, items, revisions and full audit chain. It is shared
// by the read-only preview and the write transaction so APPLY cannot trust a
// caller-supplied plan.
func buildPasskeyTransferPlan(auth *authenticatedState, rawInvitation, packet []byte, expectedSourcePin string, now time.Time) (built *passkeyTransferBuilt, err error) {
	if auth == nil || len(rawInvitation) == 0 || len(rawInvitation) > maxPasskeyTransferInvitation || len(packet) == 0 || len(packet) > 2<<20 || !digestOK(expectedSourcePin) {
		return nil, ErrMutationRefused
	}
	public, err := transferPublicIdentity(auth.identity)
	if err != nil {
		return nil, invalid
	}
	device, err := age.ParseX25519Identity(auth.identity.Device)
	if err != nil {
		return nil, invalid
	}
	invitation, err := passkeytransfer.VerifyInvitation(rawInvitation, public.Fingerprint, now)
	if err != nil || invitation == nil {
		return nil, ErrMutationRefused
	}
	link, err := passkeyTransferInviteLink(auth.identity.AuditEncryption, invitation)
	if err != nil {
		return nil, invalid
	}
	creation, err := scanPasskeyTransferRows(auth.rows, invitation.ID, link)
	if err != nil {
		return nil, ErrMutationRefused
	}
	decoded, err := passkeytransfer.OpenSelection(packet, rawInvitation, device, public.Fingerprint, expectedSourcePin, now)
	if err != nil || len(decoded) == 0 || len(decoded) > maxPasskeyTransferExportTargets {
		clearPasskeyTransferDecoded(decoded)
		return nil, ErrMutationRefused
	}
	defer func() {
		if err != nil {
			clearPasskeyTransferDecoded(decoded)
		}
	}()
	var parsed passkeytransfer.Packet
	if json.Unmarshal(packet, &parsed) != nil || !idOK(parsed.ID) {
		return nil, invalid
	}
	packetDigest := sha256.Sum256(packet)
	invitationDigest := sha256.Sum256(rawInvitation)
	built = &passkeyTransferBuilt{
		Decoded:          decoded,
		PacketDigest:     hex.EncodeToString(packetDigest[:]),
		PacketID:         parsed.ID,
		InvitationDigest: hex.EncodeToString(invitationDigest[:]),
		Creation:         creation,
		InvitationLink:   link,
		Public: PasskeyTransferPlan{
			InvitationID:      invitation.ID,
			ExpiresAt:         time.Unix(invitation.ExpiresAt, 0),
			SourceFingerprint: expectedSourcePin,
			TargetFingerprint: public.Fingerprint,
			Groups:            []PasskeyTransferGroup{},
		},
	}

	// Group by exact (RP ID, raw WebAuthn user handle) internally. The raw user
	// handle remains private to this transaction; only GroupID and record display
	// names reach the public plan.
	groupIndex := make(map[string]int)
	incoming := make(map[string]bool, len(decoded))
	for recordIndex, record := range decoded {
		item, loadErr := passkey.Load(record.Record)
		if loadErr != nil || item.ID != record.CredentialID {
			return nil, ErrMutationRefused
		}
		if incoming[item.ID] {
			item.Clear()
			return nil, ErrMutationRefused
		}
		incoming[item.ID] = true
		key := item.RPID + "\x00" + item.UserID
		index, ok := groupIndex[key]
		if !ok {
			groupID, idErr := passkeyTransferGroupID(auth.identity.AuditEncryption, item.RPID, item.UserID)
			if idErr != nil {
				item.Clear()
				return nil, idErr
			}
			index = len(built.Groups)
			groupIndex[key] = index
			built.Groups = append(built.Groups, passkeyTransferBuiltGroup{
				Public: PasskeyTransferGroup{
					GroupID:         groupID,
					RPID:            item.RPID,
					PublicUserNames: []string{},
					CredentialIDs:   []string{},
					EligibleTargets: []PasskeyTransferEligibleTarget{},
				},
				UserID: item.UserID,
			})
		}
		group := &built.Groups[index]
		if item.Name != "" {
			group.Public.PublicUserNames = append(group.Public.PublicUserNames, item.Name)
		}
		group.Public.CredentialIDs = append(group.Public.CredentialIDs, item.ID)
		group.Records = append(group.Records, recordIndex)
		item.Clear()
	}
	for i := range built.Groups {
		group := &built.Groups[i]
		sort.Strings(group.Public.PublicUserNames)
		group.Public.PublicUserNames = uniqueStrings(group.Public.PublicUserNames)
		sort.Strings(group.Public.CredentialIDs)
	}

	// Any credential ID anywhere in the vault refuses the whole packet, even if
	// the item is archived or trashed. A transfer never overwrites or revives.
	for _, item := range auth.items {
		for _, raw := range item.PasskeyRecords() {
			record, loadErr := passkey.Load(raw)
			if loadErr != nil {
				return nil, invalid
			}
			if incoming[record.ID] {
				record.Clear()
				return nil, ErrMutationRefused
			}
			record.Clear()
		}
	}

	// Only an active login whose current records are non-empty and all match the
	// exact RP ID and user handle is an eligible existing parent. An empty login
	// is never guessed by title/username; the caller must explicitly create one.
	for i := range built.Groups {
		group := &built.Groups[i]
		for _, item := range auth.items {
			if item.State != "" || item.Kind != "login" || item.EffectiveCategory() != vault.CategoryLogin {
				continue
			}
			records := item.PasskeyRecords()
			if len(records) == 0 {
				continue
			}
			matches := true
			for _, raw := range records {
				record, loadErr := passkey.Load(raw)
				if loadErr != nil {
					return nil, invalid
				}
				if record.RPID != group.Public.RPID || record.UserID != group.UserID {
					matches = false
				}
				record.Clear()
			}
			if !matches {
				continue
			}
			revision := auth.revisions[item.ID]
			if !digestOK(revision) {
				return nil, invalid
			}
			group.Public.EligibleTargets = append(group.Public.EligibleTargets, PasskeyTransferEligibleTarget{ID: item.ID, Revision: revision, Title: item.Title})
			if len(group.Public.EligibleTargets) > maxPasskeyTransferCandidates {
				return nil, ErrMutationRefused
			}
		}
		sort.SliceStable(group.Public.EligibleTargets, func(a, b int) bool {
			if group.Public.EligibleTargets[a].ID != group.Public.EligibleTargets[b].ID {
				return group.Public.EligibleTargets[a].ID < group.Public.EligibleTargets[b].ID
			}
			return group.Public.EligibleTargets[a].Revision < group.Public.EligibleTargets[b].Revision
		})
	}
	sort.SliceStable(built.Groups, func(a, b int) bool { return built.Groups[a].Public.GroupID < built.Groups[b].Public.GroupID })
	for i := range built.Groups {
		built.Public.Groups = append(built.Public.Groups, built.Groups[i].Public)
	}
	body := passkeyTransferPlanBody{
		PacketDigest:      built.PacketDigest,
		PacketID:          built.PacketID,
		InvitationDigest:  built.InvitationDigest,
		Creation:          built.Creation,
		InvitationID:      built.Public.InvitationID,
		ExpiresAt:         built.Public.ExpiresAt.Unix(),
		SourceFingerprint: built.Public.SourceFingerprint,
		TargetFingerprint: built.Public.TargetFingerprint,
		Groups:            built.Public.Groups,
	}
	digest, err := passkeyTransferPlanDigest(auth.identity.AuditEncryption, body)
	if err != nil {
		return nil, err
	}
	built.Public.Digest = digest
	if built.Public.validatePublicBudget() != nil {
		return nil, ErrMutationRefused
	}
	return built, nil
}

func uniqueStrings(values []string) []string {
	if len(values) < 2 {
		return values
	}
	out := values[:1]
	for _, value := range values[1:] {
		if value != out[len(out)-1] {
			out = append(out, value)
		}
	}
	return out
}

// PlanPasskeyTransfer is a strictly read-only preview: no MutationGate, no
// audit append, no snapshot rewrite and no idle touch. The mandatory source pin
// is verified by the transfer codec against the signed packet.
func (s *Session) PlanPasskeyTransfer(rawInvitation, packet []byte, expectedSourcePin string) (out PasskeyTransferPlan, err error) {
	if s == nil {
		return PasskeyTransferPlan{}, ErrSessionLocked
	}
	if len(rawInvitation) == 0 || len(rawInvitation) > maxPasskeyTransferInvitation || len(packet) == 0 || len(packet) > 2<<20 || !digestOK(expectedSourcePin) {
		return PasskeyTransferPlan{}, ErrMutationRefused
	}
	raw := append([]byte(nil), rawInvitation...)
	pkt := append([]byte(nil), packet...)
	defer clear(raw)
	defer clear(pkt)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active(false) != nil {
		return PasskeyTransferPlan{}, ErrSessionLocked
	}
	// The preview decrypts the sealed packet with this device identity, so it
	// needs the same fresh full-factor proof as the mutating actions and is
	// refused before the database is opened.
	if freshErr := s.requireFreshFullFactor(); freshErr != nil {
		return PasskeyTransferPlan{}, freshErr
	}
	db, err := existingWithReadOnly(s.path, true)
	if err != nil {
		return PasskeyTransferPlan{}, ErrMutationRefused
	}
	var built *passkeyTransferBuilt
	err = db.View(func(tx *bolt.Tx) error {
		auth, authErr := authenticateState(tx, "", nil, passkeyTransferItemAction, s)
		if authErr != nil {
			return authErr
		}
		defer auth.clear()
		var buildErr error
		built, buildErr = buildPasskeyTransferPlan(auth, raw, pkt, expectedSourcePin, time.Now())
		return buildErr
	})
	closeErr := db.Close()
	if errors.Is(err, invalid) {
		s.lock()
	}
	if err != nil || closeErr != nil || built == nil {
		if built != nil {
			built.clear()
		}
		if err != nil && !errors.Is(err, invalid) {
			return PasskeyTransferPlan{}, ErrMutationRefused
		}
		if err != nil {
			return PasskeyTransferPlan{}, err
		}
		return PasskeyTransferPlan{}, ErrMutationRefused
	}
	if s.active(false) != nil {
		built.clear()
		return PasskeyTransferPlan{}, ErrSessionLocked
	}
	// The read transaction can hold the database read lock while the packet is
	// decrypted, so the proof may have expired since the pre-open check. Refuse
	// before any preview selectors are released.
	if freshErr := s.requireFreshFullFactor(); freshErr != nil {
		built.clear()
		return PasskeyTransferPlan{}, freshErr
	}
	out = built.Public
	built.clear()
	return out, nil
}
