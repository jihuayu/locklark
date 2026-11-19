package personal

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"reflect"

	"github.com/jihuayu/locklark/internal/vault"
	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
)

var (
	// ErrLegacyVaultPartitionSelector means the explicit source selector does
	// not name exactly one verified legacy partition.
	ErrLegacyVaultPartitionSelector = errors.New("legacy vault partition selector rejected")
	// ErrLegacyVaultPartitionPayload means the verified source partition cannot
	// be represented by the authenticated vault-file item format without losing
	// represented data, or the sealed successor did not reproduce it exactly.
	ErrLegacyVaultPartitionPayload = errors.New("legacy vault partition cannot be materialized as a vault-file successor")
)

// LegacyVaultPartitionSource is one caller-supplied authenticated recovery
// archive and the explicit original partition selector to materialize. VaultID
// is the verified source partition identity, never a display name: use
// vault.DefaultVaultID for the implicit default partition or the exact
// signed declaration ID for a custom partition.
type LegacyVaultPartitionSource struct {
	Archive     []byte
	Password    string
	Key         []byte
	RecoveryKit string
	VaultID     string
}

// OwnedVaultFileLegacyPartitionRequest is the narrow input to one owned
// pristine first-successor preparation from a verified legacy partition.
// JournalPath, Target, Checkpoint and ExpectedGenesis have the same meaning and
// trust requirements as SealOwnedVaultFileFirstItem. Archive and all recovery
// factors are transient caller inputs; no source item slice is accepted.
type OwnedVaultFileLegacyPartitionRequest struct {
	JournalPath     string
	Target          OwnedVaultFileFirstSuccessorTarget
	Checkpoint      *vaultfile.PolicyCheckpoint
	ExpectedGenesis []byte
	Password        []byte
	Key             []byte
	Source          LegacyVaultPartitionSource
}

// OwnedVaultFileLegacyPartitionVerificationRequest is the narrow input to one
// verification of an exact previously sealed legacy-partition successor. It
// reuses the seal request's destination authorization and Source unchanged,
// adding only the exact candidate bytes and the caller's independently
// persisted nonzero digest of the complete source archive.
type OwnedVaultFileLegacyPartitionVerificationRequest struct {
	OwnedVaultFileLegacyPartitionRequest
	Candidate                   []byte
	ExpectedSourceArchiveSHA256 [sha256.Size]byte
}

// VaultFileVerifiedLegacyPartition is the bounded result of reconstructing the
// legacy-to-destination provenance from one exact sealed candidate. It retains
// only the verified source archive digest, source partition identity and signed
// metadata, the destination vault identity and the preserved item mapping. It
// never retains candidate bytes, decrypted item content, recovery factors, a
// VUK or a signing key.
type VaultFileVerifiedLegacyPartition struct {
	SourceArchiveSHA256 [sha256.Size]byte
	SourceVaultID       string
	SourceVault         *vault.VaultMeta
	DestinationVaultID  string

	// ItemMapping maps each preserved source item ID to its verified
	// destination item ID.
	ItemMapping map[string]string
}

// Clear drops every retained mapping and provenance value. The strings were
// never secret, but dropping the references keeps the result ownership
// explicit and bounded.
func (v *VaultFileVerifiedLegacyPartition) Clear() {
	if v == nil {
		return
	}
	v.ItemMapping = nil
	v.SourceArchiveSHA256 = [sha256.Size]byte{}
	v.SourceVaultID = ""
	v.SourceVault = nil
	v.DestinationVaultID = ""
}

// VaultFileSealedLegacyPartition is the real signed, independently encrypted
// immediate successor for the selected source partition, plus the source
// provenance required by the later durable mapping stage. SourceArchiveSHA256
// identifies the complete original archive; SourceVaultID is the selected
// verified partition identity and SourceVault is its typed signed metadata
// (nil for the implicit default partition). It retains no decrypted source
// item, recovery factor, VUK or signing key.
type VaultFileSealedLegacyPartition struct {
	VaultFileSealedFirstItem
	SourceArchiveSHA256 [sha256.Size]byte
	SourceVaultID       string
	SourceVault         *vault.VaultMeta
}

// Clear releases every sealed byte buffer and drops the source provenance
// retained by v.
func (v *VaultFileSealedLegacyPartition) Clear() {
	if v == nil {
		return
	}
	v.VaultFileSealedFirstItem.Clear()
	v.SourceArchiveSHA256 = [sha256.Size]byte{}
	v.SourceVaultID = ""
	v.SourceVault = nil
}

// SealOwnedVaultFileFirstItemsFromLegacyPartition materializes the complete
// verified item set of one explicit legacy archive partition into the immediate
// signed first successor of one existing pristine owned genesis scope. It
// authenticates the destination exactly as SealOwnedVaultFileFirstItem does,
// then verifies the pinned canonical recovery archive with the existing
// recovery factors, reconciles the signed source partitions, and accepts only
// the records belonging to the selected partition. It never accepts caller
// item slices, never treats a preflight summary as authorization, never uses a
// display name as a selector and never mixes another source partition into the
// result.
//
// Item IDs are preserved exactly. The source vault selector is retained on
// custom-partition items, while an explicit default selector is represented by
// the format's normal empty default. Source fields with no distinct wire
// representation are normalized only where the authenticated format derives
// the same effective value (a legacy-matching category and the default vault
// ID). The sealed successor is opened again under its own target checkpoint and
// device, and every represented field, history entry, attachment byte and
// import provenance must compare exactly; otherwise the caller receives
// ErrLegacyVaultPartitionPayload and no sealed bytes. The exact named local
// backend object is also read once and both its bytes and opaque revision must
// match the authenticated genesis and journal revision used to seal; otherwise
// the result is cleared and returned incomplete. The current owner, session and
// idle context are rechecked after that storage read.
//
// The function reads the journal and backend but never writes either, and it
// writes no CAS state, mapping or original-vault change. It publishes nothing,
// performs no cutover or cleanup and returns no destination key.
func (s *Session) SealOwnedVaultFileFirstItemsFromLegacyPartition(req OwnedVaultFileLegacyPartitionRequest) (out VaultFileSealedLegacyPartition, retErr error) {
	if s == nil {
		return out, ErrSessionLocked
	}
	if req.JournalPath == "" || len(req.ExpectedGenesis) == 0 {
		return out, ErrVaultFileEditVerification
	}
	if len(req.Source.Archive) == 0 || req.Source.VaultID == "" || req.Source.RecoveryKit == "" {
		return out, ErrLegacyVaultPartitionPayload
	}

	scope, err := s.authenticateOwnedVaultFileWriteScope(req.Target, req.Checkpoint, req.Password, req.Key)
	if err != nil {
		return out, err
	}
	defer scope.clear()
	defer func() {
		if retErr != nil {
			out.Clear()
		}
	}()

	sourceDigest, declaration, items, err := authenticateLegacyVaultPartitionSource(req.Source)
	if err != nil {
		return out, err
	}
	defer clearAuthenticatedItems(items)

	sealed, err := s.sealOwnedVaultFileFirstItemsWithScope(scope, req.JournalPath, req.Target, req.Checkpoint, req.ExpectedGenesis, items)
	if err != nil {
		return out, err
	}
	// sealed.State carries the exact authenticated journal genesis bytes and
	// the opaque revision used to seal. Observation must bind both together.
	if err := readOwnedVaultFileSuccessorBackend(req.Target, sealed.State.BaseBytes, sealed.State.RemoteRevision); err != nil {
		sealed.Clear()
		return out, err
	}
	if err := s.revalidateOwnedVaultFileWriteScope(scope); err != nil {
		sealed.Clear()
		return out, err
	}
	if err := s.active(false); err != nil {
		sealed.Clear()
		return out, err
	}
	if !legacyPartitionSuccessorPreserves(sealed, req.Checkpoint, scope, items) {
		sealed.Clear()
		return out, ErrLegacyVaultPartitionPayload
	}

	out.VaultFileSealedFirstItem = sealed
	out.SourceArchiveSHA256 = sourceDigest
	out.SourceVaultID = req.Source.VaultID
	out.SourceVault = declaration
	return out, nil
}

// VerifyOwnedVaultFileLegacyPartition reconstructs the legacy-to-destination
// provenance from one exact previously sealed candidate. It never seals,
// publishes, acknowledges or writes the journal, backend, personal store or
// source archive; it does not need the in-memory result of the original seal
// and accepts no caller-provided receipt.
//
// The destination is authenticated with the same full factors, current owner
// record, exact named backend target and companion checkpoint as
// SealOwnedVaultFileFirstItemsFromLegacyPartition. The complete source archive
// is authenticated again with the same recovery factors and partitioned using
// the same signed declarations; the caller's independently persisted archive
// digest and explicit source selector must match. The exact pristine
// generation-zero journal baseline is authenticated under the pinned canonical
// genesis, its named live backend object is read with both bytes and opaque
// revision bound, and only then is the caller's candidate accepted as the
// complete immediate first content transition from those exact genesis bytes.
//
// The candidate is opened under the authorized owned key scope and every
// represented field, stable ID, history entry, current attachment byte and
// trash state must match the selected source records exactly. A foreign or
// wrong-root candidate, the other partition, a corrupt or valid-but-different
// payload, a changed live genesis revision and a wrong factor or scope all fail
// closed. The result retains only the verified source provenance and the
// identity-preserving item mapping; it retains no candidate bytes, decrypted
// item, recovery factor, VUK or signing key. The caller owns the result and
// should call Clear when finished.
func (s *Session) VerifyOwnedVaultFileLegacyPartition(req OwnedVaultFileLegacyPartitionVerificationRequest) (out VaultFileVerifiedLegacyPartition, retErr error) {
	if s == nil {
		return out, ErrSessionLocked
	}
	if len(req.Candidate) == 0 {
		return out, ErrVaultFileBaselineVerification
	}
	var zeroDigest [sha256.Size]byte
	if req.ExpectedSourceArchiveSHA256 == zeroDigest || len(req.Source.Archive) == 0 {
		return out, ErrLegacyVaultPartitionPayload
	}
	selector := req.Source.VaultID
	if selector == "" {
		return out, ErrLegacyVaultPartitionSelector
	}
	if req.JournalPath == "" || len(req.ExpectedGenesis) == 0 {
		return out, ErrVaultFileEditVerification
	}
	if req.Source.RecoveryKit == "" {
		return out, ErrLegacyVaultPartitionPayload
	}

	scope, err := s.authenticateOwnedVaultFileWriteScope(req.Target, req.Checkpoint, req.Password, req.Key)
	if err != nil {
		return out, err
	}
	defer scope.clear()
	defer func() {
		if retErr != nil {
			out.Clear()
		}
	}()

	if sha256.Sum256(req.Source.Archive) != req.ExpectedSourceArchiveSHA256 {
		return out, ErrLegacyVaultPartitionPayload
	}
	sourceDigest, declaration, items, err := authenticateLegacyVaultPartitionSource(req.Source)
	if err != nil {
		return out, err
	}
	defer clearAuthenticatedItems(items)
	if sourceDigest != req.ExpectedSourceArchiveSHA256 {
		return out, ErrLegacyVaultPartitionPayload
	}

	state, deviceID, _, err := verifyLegacyPartitionGenesisBaseline(req.JournalPath, req.Target, req.Checkpoint, req.ExpectedGenesis, scope)
	if err != nil {
		return out, err
	}
	defer func() {
		clear(state.BaseBytes)
		clear(state.WorkingBytes)
	}()

	mapping, err := verifyLegacyPartitionCandidate(req.Candidate, state, req.Checkpoint, scope, deviceID, items)
	if err != nil {
		return out, err
	}
	if err := verifyLegacyPartitionJournalUnchanged(req.JournalPath, state); err != nil {
		return out, err
	}
	if err := readOwnedVaultFileSuccessorBackend(req.Target, state.BaseBytes, state.RemoteRevision); err != nil {
		return out, err
	}
	if err := s.revalidateOwnedVaultFileWriteScope(scope); err != nil {
		return out, err
	}
	if err := s.active(false); err != nil {
		return out, err
	}

	out.SourceArchiveSHA256 = sourceDigest
	out.SourceVaultID = selector
	out.SourceVault = declaration
	out.DestinationVaultID = req.Checkpoint.VaultID
	out.ItemMapping = mapping
	return out, nil
}

// authenticateLegacyVaultPartitionSource is the shared archive authentication
// and partition materialization used by both the seal and verify paths. The
// returned items are caller-owned deep copies and are non-nil even for an
// empty selected partition. Any error returns no items.
func authenticateLegacyVaultPartitionSource(source LegacyVaultPartitionSource) ([sha256.Size]byte, *vault.VaultMeta, []vault.Item, error) {
	digest := sha256.Sum256(source.Archive)
	p, err := verifyRecoveryArchive(source.Archive, source.Password, source.Key, source.RecoveryKit, true)
	if err != nil {
		return digest, nil, nil, err
	}
	defer clearDecodedArchiveSensitive(p)

	group, declaration, err := selectLegacyVaultPartition(p, source.VaultID)
	if err != nil {
		return digest, nil, nil, err
	}
	items, err := materializeLegacyVaultPartitionItems(p, group, source.VaultID)
	if err != nil {
		return digest, nil, nil, err
	}
	if vault.ValidateItems([]byte{}, items) != nil {
		clearAuthenticatedItems(items)
		return digest, nil, nil, ErrLegacyVaultPartitionPayload
	}
	var metadata *vault.VaultMeta
	if declaration != nil {
		clone := *declaration
		metadata = &clone
	}
	return digest, metadata, items, nil
}

// verifyLegacyPartitionGenesisBaseline authenticates the exact pristine
// generation-zero journal baseline and its current account device authority.
// It returns owned state bytes that the caller must clear.
func verifyLegacyPartitionGenesisBaseline(journalPath string, target OwnedVaultFileFirstSuccessorTarget, checkpoint *vaultfile.PolicyCheckpoint, expectedGenesis []byte, scope *ownedVaultFileWriteScope) (state vaultfilejournal.State, deviceID, principalID string, retErr error) {
	if scope == nil || scope.ageIdentity == nil || journalPath == "" || len(expectedGenesis) == 0 ||
		!validOwnedVaultFileFirstSuccessorTarget(target) ||
		!ownedVaultFileFirstSuccessorMatchesCheckpoint(target, checkpoint) {
		return state, "", "", ErrVaultFileBaselineVerification
	}

	j, err := vaultfilejournal.OpenExisting(journalPath)
	if err != nil {
		return state, "", "", ErrVaultFileBaselineJournal
	}
	loaded, loadErr := j.LoadGenesisBaseline()
	closeErr := j.Close()
	if loadErr != nil || closeErr != nil {
		clear(loaded.BaseBytes)
		clear(loaded.WorkingBytes)
		return state, "", "", ErrVaultFileBaselineJournal
	}
	state = loaded
	defer func() {
		if retErr != nil {
			clear(state.BaseBytes)
			clear(state.WorkingBytes)
		}
	}()

	if !bytes.Equal(state.BaseBytes, expectedGenesis) {
		return state, "", "", ErrVaultFileBaselineVerification
	}
	deviceID, principal, err := verifyLegacyPartitionGenesisRecord(state.BaseBytes, target, checkpoint, scope)
	if err != nil {
		return state, "", "", err
	}
	return state, deviceID, principal, nil
}

// verifyLegacyPartitionJournalUnchanged re-reads the exact pristine baseline
// after candidate verification so a concurrent journal advance cannot be
// mistaken for the state that authorized the returned provenance.
func verifyLegacyPartitionJournalUnchanged(journalPath string, want vaultfilejournal.State) error {
	j, err := vaultfilejournal.OpenExisting(journalPath)
	if err != nil {
		return ErrVaultFileBaselineJournal
	}
	state, loadErr := j.LoadGenesisBaseline()
	closeErr := j.Close()
	defer clear(state.BaseBytes)
	defer clear(state.WorkingBytes)
	if loadErr != nil || closeErr != nil {
		return ErrVaultFileBaselineJournal
	}
	if state.Generation != want.Generation || state.RemoteRevision != want.RemoteRevision ||
		!bytes.Equal(state.BaseBytes, want.BaseBytes) || !bytes.Equal(state.WorkingBytes, want.WorkingBytes) {
		return ErrVaultFileBaselineJournal
	}
	return nil
}

// verifyLegacyPartitionCandidate requires the exact authenticated immediate
// first content transition and then exact semantic equivalence with the
// selected source records. Counts alone are never sufficient: stable IDs and
// every represented field are compared by sameLegacyPartitionItems.
func verifyLegacyPartitionCandidate(candidate []byte, state vaultfilejournal.State, checkpoint *vaultfile.PolicyCheckpoint, scope *ownedVaultFileWriteScope, deviceID string, want []vault.Item) (map[string]string, error) {
	if scope == nil || scope.ageIdentity == nil || checkpoint == nil || deviceID == "" || len(candidate) == 0 {
		return nil, ErrVaultFileBaselineVerification
	}
	if err := vaultfile.VerifyContentTransition(state.BaseBytes, candidate, checkpoint); err != nil {
		return nil, ErrVaultFileBaselineVerification
	}
	next, err := vaultfile.ParseFile(candidate)
	if err != nil || next.Header.AuthorDeviceID != deviceID ||
		next.Header.VaultID != checkpoint.VaultID ||
		next.Header.PolicySeq != checkpoint.PolicySeq ||
		!bytes.Equal(next.Header.PolicyDigest, checkpoint.PolicyDigest) ||
		next.Header.ContentSeq != 1 {
		return nil, ErrVaultFileBaselineVerification
	}
	_, metadata, got, err := vault.OpenAuthenticatedItems(candidate, checkpoint, deviceID, scope.ageIdentity)
	if err != nil {
		return nil, ErrVaultFileBaselineVerification
	}
	defer clear(metadata)
	defer clearAuthenticatedItems(got)
	if len(metadata) != 0 || !sameLegacyPartitionItems(want, got) {
		return nil, ErrLegacyVaultPartitionPayload
	}

	mapping := make(map[string]string, len(want))
	for i := range want {
		if want[i].ID == "" || got[i].ID != want[i].ID {
			return nil, ErrLegacyVaultPartitionPayload
		}
		if _, duplicate := mapping[want[i].ID]; duplicate {
			return nil, ErrLegacyVaultPartitionPayload
		}
		mapping[want[i].ID] = got[i].ID
	}
	return mapping, nil
}

// selectLegacyVaultPartition maps the explicit source selector to exactly one
// reconciled signed group. It does not accept an index, a display name, a
// preflight count or a caller-supplied group.
func selectLegacyVaultPartition(p *payload, selector string) (LegacyVaultSplitGroup, *vault.VaultMeta, error) {
	if p == nil || selector == "" {
		return LegacyVaultSplitGroup{}, nil, ErrLegacyVaultPartitionSelector
	}
	groups, err := reconcileLegacyVaultSplit(p)
	if err != nil {
		return LegacyVaultSplitGroup{}, nil, err
	}

	groupIndex := -1
	var declaration *vault.VaultMeta
	if selector == vault.DefaultVaultID {
		groupIndex = 0
	} else {
		for i := range p.Vaults {
			if p.Vaults[i].ID == selector {
				groupIndex = i + 1
				declaration = &p.Vaults[i]
				break
			}
		}
	}
	if groupIndex < 0 || groupIndex >= len(groups) {
		return LegacyVaultSplitGroup{}, nil, ErrLegacyVaultPartitionSelector
	}
	group := groups[groupIndex]
	for _, index := range group.ItemIndexes {
		if index < 0 || index >= len(p.Items) || p.Items[index].EffectiveVaultID() != selector {
			return LegacyVaultSplitGroup{}, nil, ErrLegacyVaultPartitionSelector
		}
	}
	return group, declaration, nil
}

// materializeLegacyVaultPartitionItems deep-copies exactly the selected
// indexes after rechecking that each record still belongs to the selector. The
// returned slice is non-nil even for an empty selected partition.
func materializeLegacyVaultPartitionItems(p *payload, group LegacyVaultSplitGroup, selector string) ([]vault.Item, error) {
	if p == nil || selector == "" {
		return nil, ErrLegacyVaultPartitionPayload
	}
	items := make([]vault.Item, 0, len(group.ItemIndexes))
	for _, index := range group.ItemIndexes {
		if index < 0 || index >= len(p.Items) || p.Items[index].EffectiveVaultID() != selector {
			clearAuthenticatedItems(items)
			return nil, ErrLegacyVaultPartitionPayload
		}
		items = append(items, canonicalLegacyPartitionItem(p.Items[index]))
	}
	return items, nil
}

// canonicalLegacyPartitionItem clones one verified source record and removes
// only distinctions the authenticated item format cannot represent separately:
// an explicit default vault selector and a category implied by the legacy kind.
// Empty byte buffers are returned to their canonical nil form. All identity,
// provenance, history, section, attachment, trash and typed values are kept.
func canonicalLegacyPartitionItem(item vault.Item) vault.Item {
	out := vault.CloneItem(item)
	if out.VaultID == vault.DefaultVaultID {
		out.VaultID = ""
	}
	if legacyPartitionCategoryMatchesKind(out.Category, out.Kind) {
		out.Category = ""
	}
	if len(out.Attachment) == 0 {
		out.Attachment = nil
	}
	if len(out.Passkey) == 0 {
		out.Passkey = nil
	}
	if len(out.Passkeys) == 0 {
		out.Passkeys = nil
	}
	for i := range out.Attachments {
		if len(out.Attachments[i].Content) == 0 {
			out.Attachments[i].Content = nil
		}
	}
	return out
}

func legacyPartitionCategoryMatchesKind(category vault.ItemCategory, kind string) bool {
	return category == vault.CategoryLogin && kind == "login" ||
		category == vault.CategoryDocument && kind == "document" ||
		category == vault.CategorySSHKey && kind == "ssh-key"
}

// legacyPartitionSuccessorPreserves opens the newly sealed payload under its
// own destination checkpoint and device and requires exact semantic equality
// with the selected records. The only comparison-only normalization is the
// location attached to a trash timestamp; the instant itself is compared.
func legacyPartitionSuccessorPreserves(sealed VaultFileSealedFirstItem, checkpoint *vaultfile.PolicyCheckpoint, scope *ownedVaultFileWriteScope, want []vault.Item) bool {
	if scope == nil || scope.ageIdentity == nil || sealed.AuthorDeviceID == "" || checkpoint == nil {
		return false
	}
	_, metadata, got, err := vault.OpenAuthenticatedItems(sealed.Sealed, checkpoint, sealed.AuthorDeviceID, scope.ageIdentity)
	if err != nil {
		return false
	}
	defer clear(metadata)
	defer clearAuthenticatedItems(got)
	if len(metadata) != 0 {
		return false
	}
	return sameLegacyPartitionItems(want, got)
}

// sameLegacyPartitionItems compares every represented field. Trash timestamps
// are compared as instants because a decoded time.Location pointer is not item
// data; all other values, including nil-versus-empty buffers already
// canonicalized by the format, must match exactly.
func sameLegacyPartitionItems(a, b []vault.Item) bool {
	left := cloneLegacyPartitionItemsForComparison(a)
	right := cloneLegacyPartitionItemsForComparison(b)
	defer clearAuthenticatedItems(left)
	defer clearAuthenticatedItems(right)
	return reflect.DeepEqual(left, right)
}

func cloneLegacyPartitionItemsForComparison(items []vault.Item) []vault.Item {
	out := make([]vault.Item, len(items))
	for i := range items {
		out[i] = vault.CloneItem(items[i])
		if out[i].TrashedAt != nil {
			instant := out[i].TrashedAt.UTC()
			out[i].TrashedAt = &instant
		}
	}
	return out
}
