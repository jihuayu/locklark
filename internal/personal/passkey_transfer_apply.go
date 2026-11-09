package personal

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/jihuayu/locklark/internal/passkey"
	"github.com/jihuayu/locklark/internal/vault"
	bolt "go.etcd.io/bbolt"
)

// passkeyTransferApplySelectors is the complete private selector set bound by
// one item event's keyed Link. It is never persisted as plaintext.
type passkeyTransferApplySelectors struct {
	ExistingTargetID string   `json:"existing_target_id,omitempty"`
	ExistingRevision string   `json:"existing_revision,omitempty"`
	NewTitle         string   `json:"new_title,omitempty"`
	NewUsername      string   `json:"new_username,omitempty"`
	CredentialIDs    []string `json:"credential_ids"`
}

type passkeyTransferApplyChange struct {
	itemID       string
	baseRevision string
	link         string
	selectors    passkeyTransferApplySelectors
}

type passkeyTransferApplyCandidate struct {
	items   []vault.Item
	changes []passkeyTransferApplyChange
	owned   []*vault.Item
}

func (c *passkeyTransferApplyCandidate) clear() {
	if c == nil {
		return
	}
	for _, item := range c.owned {
		item.ClearPasskeys()
	}
	c.owned = nil
}

// verifyPasskeyTransferItemEvent is the exact known-format gate for one
// imported parent revision. The base is either the previous parent revision or
// blank for a brand-new parent; the link is always a 64-character keyed HMAC.
func verifyPasskeyTransferItemEvent(e Event, n uint64) error {
	if n <= 1 || !idOK(e.Item) || e.Result != "succeeded" || !digestOK(e.Link) || e.ReportDigest != "" || e.Generation != nil {
		return invalid
	}
	if e.BaseRevision != "" && !digestOK(e.BaseRevision) {
		return invalid
	}
	return nil
}

func passkeyTransferApplyLink(key []byte, packetDigest, groupID, planDigest string, selectors passkeyTransferApplySelectors) (string, error) {
	if len(key) == 0 || !digestOK(packetDigest) || !digestOK(groupID) || !digestOK(planDigest) {
		return "", invalid
	}
	existing := selectors.ExistingTargetID != "" || selectors.ExistingRevision != ""
	fresh := selectors.NewTitle != "" || selectors.NewUsername != ""
	if existing == fresh {
		return "", invalid
	}
	if existing {
		if !idOK(selectors.ExistingTargetID) || !digestOK(selectors.ExistingRevision) || selectors.NewTitle != "" || selectors.NewUsername != "" {
			return "", invalid
		}
	} else if !transferSafeText(selectors.NewTitle, false) || !transferSafeText(selectors.NewUsername, true) {
		return "", invalid
	}
	if len(selectors.CredentialIDs) == 0 || len(selectors.CredentialIDs) > vault.MaxPasskeys {
		return "", invalid
	}
	seen := make(map[string]bool, len(selectors.CredentialIDs))
	for _, credentialID := range selectors.CredentialIDs {
		if !passkey.ValidCredentialID(credentialID) || seen[credentialID] {
			return "", invalid
		}
		seen[credentialID] = true
	}
	canonical, err := json.Marshal(selectors)
	if err != nil || len(canonical) == 0 {
		return "", invalid
	}
	defer clear(canonical)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(passkeyTransferApplyLinkDomain))
	mac.Write([]byte(packetDigest))
	mac.Write([]byte(groupID))
	mac.Write([]byte(planDigest))
	var frame [8]byte
	binary.BigEndian.PutUint64(frame[:], uint64(len(canonical)))
	mac.Write(frame[:])
	mac.Write(canonical)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func validatePasskeyTransferMappings(mappings []PasskeyTransferMapping) error {
	if len(mappings) == 0 || len(mappings) > maxPasskeyTransferExportTargets {
		return ErrMutationRefused
	}
	seenGroup := make(map[string]bool, len(mappings))
	seenTarget := make(map[string]bool, len(mappings))
	for _, mapping := range mappings {
		if !digestOK(mapping.GroupID) || seenGroup[mapping.GroupID] {
			return ErrMutationRefused
		}
		seenGroup[mapping.GroupID] = true
		existing := mapping.ExistingTargetID != "" || mapping.ExistingRevision != ""
		fresh := mapping.NewTitle != "" || mapping.NewUsername != ""
		if existing == fresh {
			return ErrMutationRefused
		}
		if existing {
			if !idOK(mapping.ExistingTargetID) || !digestOK(mapping.ExistingRevision) || mapping.NewTitle != "" || mapping.NewUsername != "" {
				return ErrMutationRefused
			}
			if seenTarget[mapping.ExistingTargetID] {
				return ErrMutationRefused
			}
			seenTarget[mapping.ExistingTargetID] = true
			continue
		}
		if mapping.ExistingTargetID != "" || mapping.ExistingRevision != "" || !transferSafeText(mapping.NewTitle, false) || !transferSafeText(mapping.NewUsername, true) {
			return ErrMutationRefused
		}
	}
	return nil
}

func validatePasskeyTransferGroupRecords(built *passkeyTransferBuilt, group *passkeyTransferBuiltGroup) error {
	if built == nil || group == nil || len(group.Records) == 0 || len(group.Records) > vault.MaxPasskeys {
		return ErrMutationRefused
	}
	for _, index := range group.Records {
		if index < 0 || index >= len(built.Decoded) {
			return ErrMutationRefused
		}
		decoded := &built.Decoded[index]
		record, err := passkey.Load(decoded.Record)
		if err != nil {
			return ErrMutationRefused
		}
		matches := record.ID == decoded.CredentialID && record.RPID == group.Public.RPID && record.UserID == group.UserID
		record.Clear()
		if !matches {
			return ErrMutationRefused
		}
	}
	return nil
}

func passkeyTransferApplySelectorsFor(mapping PasskeyTransferMapping, group *passkeyTransferBuiltGroup) passkeyTransferApplySelectors {
	return passkeyTransferApplySelectors{
		ExistingTargetID: mapping.ExistingTargetID,
		ExistingRevision: mapping.ExistingRevision,
		NewTitle:         mapping.NewTitle,
		NewUsername:      mapping.NewUsername,
		CredentialIDs:    append([]string(nil), group.Public.CredentialIDs...),
	}
}

// buildPasskeyTransferApplyCandidates verifies every explicit mapping against
// the freshly rebuilt plan and returns owned item copies plus the exact item
// events to append. It performs no gate or write.
func buildPasskeyTransferApplyCandidates(auth *authenticatedState, built *passkeyTransferBuilt, mappings []PasskeyTransferMapping) (out *passkeyTransferApplyCandidate, err error) {
	if auth == nil || built == nil || len(built.Groups) == 0 || len(built.Groups) > maxPasskeyTransferExportTargets {
		return nil, ErrMutationRefused
	}
	byGroup := make(map[string]PasskeyTransferMapping, len(mappings))
	for _, mapping := range mappings {
		if _, duplicate := byGroup[mapping.GroupID]; duplicate {
			return nil, ErrMutationRefused
		}
		byGroup[mapping.GroupID] = mapping
	}
	if len(byGroup) != len(built.Groups) {
		return nil, ErrMutationRefused
	}
	out = &passkeyTransferApplyCandidate{items: append([]vault.Item(nil), auth.items...)}
	defer func() {
		if err != nil {
			out.clear()
			out = nil
		}
	}()
	pendingTargets := make(map[string]bool, len(mappings))
	now := time.Now().Unix()
	for groupIndex := range built.Groups {
		group := &built.Groups[groupIndex]
		mapping, mapped := byGroup[group.Public.GroupID]
		delete(byGroup, group.Public.GroupID)
		if !mapped || validatePasskeyTransferGroupRecords(built, group) != nil {
			return nil, ErrMutationRefused
		}
		selectors := passkeyTransferApplySelectorsFor(mapping, group)
		if mapping.ExistingTargetID != "" {
			if pendingTargets[mapping.ExistingTargetID] {
				return nil, ErrMutationRefused
			}
			pendingTargets[mapping.ExistingTargetID] = true
			eligible := false
			for _, target := range group.Public.EligibleTargets {
				if target.ID == mapping.ExistingTargetID && target.Revision == mapping.ExistingRevision {
					eligible = true
					break
				}
			}
			if !eligible {
				return nil, ErrMutationRefused
			}
			row := -1
			for index := range auth.items {
				if auth.items[index].ID != mapping.ExistingTargetID {
					continue
				}
				if row >= 0 {
					return nil, invalid
				}
				row = index
			}
			if row < 0 || auth.revisions[mapping.ExistingTargetID] != mapping.ExistingRevision {
				return nil, ErrMutationRefused
			}
			current := auth.items[row]
			if current.State != "" || current.Kind != "login" || current.EffectiveCategory() != vault.CategoryLogin {
				return nil, ErrMutationRefused
			}
			existing := current.PasskeyRecords()
			if len(existing)+len(group.Records) > vault.MaxPasskeys {
				return nil, ErrMutationRefused
			}
			combined := make([][]byte, 0, len(existing)+len(group.Records))
			combined = append(combined, existing...)
			for _, index := range group.Records {
				combined = append(combined, built.Decoded[index].Record)
			}
			next := vault.CloneItem(current)
			if next.SetPasskeyRecords(combined) != nil {
				next.ClearPasskeys()
				return nil, ErrMutationRefused
			}
			out.owned = append(out.owned, &next)
			next.UpdatedAt = now
			out.items[row] = next
			link, linkErr := passkeyTransferApplyLink(auth.identity.AuditEncryption, built.PacketDigest, group.Public.GroupID, built.Public.Digest, selectors)
			if linkErr != nil {
				return nil, linkErr
			}
			out.changes = append(out.changes, passkeyTransferApplyChange{itemID: mapping.ExistingTargetID, baseRevision: mapping.ExistingRevision, link: link, selectors: selectors})
			continue
		}
		// A new login always gets its own parent. Matching titles, usernames or
		// records never merge it into an existing or earlier imported parent.
		id, idErr := randomID()
		if idErr != nil {
			return nil, idErr
		}
		next := vault.Item{ID: id, Kind: "login", Category: vault.CategoryLogin, Title: mapping.NewTitle, Username: mapping.NewUsername, CreatedAt: now, UpdatedAt: now}
		records := make([][]byte, 0, len(group.Records))
		for _, index := range group.Records {
			records = append(records, built.Decoded[index].Record)
		}
		if next.SetPasskeyRecords(records) != nil {
			next.ClearPasskeys()
			return nil, ErrMutationRefused
		}
		out.owned = append(out.owned, &next)
		out.items = append(out.items, next)
		link, linkErr := passkeyTransferApplyLink(auth.identity.AuditEncryption, built.PacketDigest, group.Public.GroupID, built.Public.Digest, selectors)
		if linkErr != nil {
			return nil, linkErr
		}
		out.changes = append(out.changes, passkeyTransferApplyChange{itemID: id, baseRevision: "", link: link, selectors: selectors})
	}
	if len(byGroup) != 0 || len(out.changes) != len(built.Groups) {
		return nil, ErrMutationRefused
	}
	if vault.ValidateItems([]byte(schema), out.items) != nil {
		return nil, ErrMutationRefused
	}
	return out, nil
}

// ApplyPasskeyTransfer imports an owner-reviewed transfer packet into exactly
// the explicit existing parents or new logins named by mappings. It never
// trusts a caller-supplied plan: the plan is rebuilt from the same current
// snapshot, invitation chain, pins and expiry inside the write transaction.
// One final snapshot, every item event and one invitation-consumption event are
// committed atomically; a success receipt is returned only after the database
// closed and the session is still active.
func (s *Session) ApplyPasskeyTransfer(rawInvite, packet []byte, sourcePin, planDigest string, mappings []PasskeyTransferMapping, g *MutationGate) (PasskeyTransferApplyReceipt, error) {
	return s.applyPasskeyTransfer(rawInvite, packet, sourcePin, planDigest, mappings, g, nil, nil)
}

func (s *Session) applyPasskeyTransfer(rawInvite, packet []byte, sourcePin, planDigest string, mappings []PasskeyTransferMapping, g *MutationGate, afterCommit func(), closeDB func(*bolt.DB) error) (out PasskeyTransferApplyReceipt, err error) {
	if s == nil {
		if g != nil {
			g.Cancel()
		}
		return PasskeyTransferApplyReceipt{}, ErrMutationRefused
	}
	defer s.ReleaseMutation(g)
	if len(rawInvite) == 0 || len(rawInvite) > maxPasskeyTransferInvitation || len(packet) == 0 || len(packet) > 2<<20 || !digestOK(sourcePin) || !digestOK(planDigest) {
		if g != nil {
			g.Cancel()
		}
		return PasskeyTransferApplyReceipt{}, ErrMutationRefused
	}
	raw := append([]byte(nil), rawInvite...)
	pkt := append([]byte(nil), packet...)
	ownedMappings := append([]PasskeyTransferMapping(nil), mappings...)
	defer clear(raw)
	defer clear(pkt)
	if validatePasskeyTransferMappings(ownedMappings) != nil {
		if g != nil {
			g.Cancel()
		}
		return PasskeyTransferApplyReceipt{}, ErrMutationRefused
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.registeredMutation(g) || s.active(true) != nil {
		return PasskeyTransferApplyReceipt{}, ErrMutationCancelled
	}
	// No database is opened and no packet is decrypted for an unproven
	// session.
	if freshErr := s.requireFreshFullFactor(); freshErr != nil {
		return PasskeyTransferApplyReceipt{}, freshErr
	}
	db, err := existing(s.path)
	if err != nil {
		return PasskeyTransferApplyReceipt{}, ErrMutationRefused
	}
	var built *passkeyTransferBuilt
	defer func() {
		if built != nil {
			built.clear()
		}
	}()
	var receipts []PasskeyTransferItemReceipt
	err = db.Update(func(tx *bolt.Tx) error {
		auth, authErr := authenticateState(tx, "", nil, passkeyTransferItemAction, s)
		if authErr != nil {
			return authErr
		}
		defer auth.clear()
		built, err = buildPasskeyTransferPlan(auth, raw, pkt, sourcePin, time.Now())
		if err != nil {
			return err
		}
		if built == nil {
			return invalid
		}
		if !hmac.Equal([]byte(built.Public.Digest), []byte(planDigest)) {
			return ErrMutationRefused
		}
		candidate, candidateErr := buildPasskeyTransferApplyCandidates(auth, built, ownedMappings)
		if candidateErr != nil {
			return candidateErr
		}
		defer candidate.clear()
		// The proof must still be fresh at commit time, not only when the
		// transaction started.
		if freshErr := s.requireFreshFullFactor(); freshErr != nil {
			return freshErr
		}
		// Every selector, candidate item and the complete item set are valid
		// before the one-shot gate is won.
		if !s.winBrowserSave(g) {
			return ErrMutationCancelled
		}
		// Conservative revocation of queued old authority even if a later
		// snapshot or audit append fails.
		s.passkeyEpoch.Add(1)
		snapshot, sealErr := seal(tx.Bucket(bucket), auth.identity, auth.snapshot.Epoch+1, candidate.items)
		if sealErr != nil {
			return sealErr
		}
		tip := auth.tip
		for _, change := range candidate.changes {
			event, appendErr := appendLinked(tx.Bucket(bucket), auth.identity, tip, snapshot, passkeyTransferItemAction, change.itemID, "succeeded", change.baseRevision, change.link)
			if appendErr != nil {
				return appendErr
			}
			tip = auditTip{Count: event.Sequence, Epoch: snapshot.Epoch, Last: event.hash(), Snapshot: hex.EncodeToString(snapshot.Signature), Origin: auth.tip.Origin}
			receipts = append(receipts, PasskeyTransferItemReceipt{ID: change.itemID, Revision: event.hash()})
		}
		if _, consumeErr := appendLinked(tx.Bucket(bucket), auth.identity, tip, snapshot, passkeyTransferConsumeAction, built.Public.InvitationID, "succeeded", built.Creation, built.InvitationLink); consumeErr != nil {
			return consumeErr
		}
		return nil
	})
	if afterCommit != nil {
		afterCommit()
	}
	closeErr := db.Close()
	if closeDB != nil {
		closeErr = closeDB(db)
	}
	if errors.Is(err, invalid) {
		s.lock()
	}
	active := s.active(false) == nil
	if err != nil || closeErr != nil || !active {
		out = PasskeyTransferApplyReceipt{}
		if g.CommitWon() {
			return out, ErrMutationUnknown
		}
		if !active {
			return out, ErrMutationCancelled
		}
		if err != nil {
			return out, err
		}
		return out, ErrMutationRefused
	}
	if len(receipts) == 0 || len(receipts) != len(built.Groups) {
		return PasskeyTransferApplyReceipt{}, ErrMutationUnknown
	}
	s.clearAuditCache()
	return PasskeyTransferApplyReceipt{Items: receipts}, nil
}
