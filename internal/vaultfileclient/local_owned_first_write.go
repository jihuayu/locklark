package vaultfileclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/teamfiles"
	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	"github.com/jihuayu/locklark/pkg/vaultfilejournal"
)

var (
	// ErrLocalOwnedFirstWriteReview rejects a request before any durable local
	// preparation: an invalid locator, manifest, companion, checkpoint, owner,
	// device, factor proof or account session.
	ErrLocalOwnedFirstWriteReview = errors.New("LOCAL_OWNED_FIRST_WRITE_REVIEW")
	// ErrLocalOwnedFirstWriteConflict reports an exact stale/replaced base, a
	// pending/advanced journal, or a CAS conflict. Nothing was acknowledged and
	// any recoverable preparation is preserved.
	ErrLocalOwnedFirstWriteConflict = errors.New("LOCAL_OWNED_FIRST_WRITE_CONFLICT")
	// ErrLocalOwnedFirstWriteIndeterminate reports that an observation or
	// acknowledgement did not establish a final outcome. The exact durable
	// preparation is preserved for one later exact resume; the caller must not
	// build or sign a new proposal.
	ErrLocalOwnedFirstWriteIndeterminate = errors.New("LOCAL_OWNED_FIRST_WRITE_INDETERMINATE")
	// ErrLocalOwnedFirstWriteUnsupported reports a platform or backend that
	// cannot provide the existing local-directory CAS semantics.
	ErrLocalOwnedFirstWriteUnsupported = errors.New("LOCAL_OWNED_FIRST_WRITE_UNSUPPORTED")
	// ErrLocalOwnedFirstWriteCanceled reports cancellation before any durable
	// preparation or backend publication.
	ErrLocalOwnedFirstWriteCanceled = errors.New("LOCAL_OWNED_FIRST_WRITE_CANCELED")
)

// LocalGenesisFirstItem is the minimal real login item accepted by one owned
// first-item write. It exists only in the protected call. The fields are never
// returned, logged or stored by this package; the durable journal retains only
// the sealed successor bytes.
type LocalGenesisFirstItem struct {
	ID       string
	Title    string
	Username string
	Password string
}

// LocalOwnedFirstWriteResult is the bounded public result of one acknowledged
// owned first-item write. It contains no item content, root key, signer, VUK,
// age identity or account material. A nil error means the local journal now
// holds exactly one typed owned successor at Revision, which is the exact
// observed backend revision for OperationID. Callers must explicitly re-open
// the reviewed read-only local-genesis path for the new item view.
type LocalOwnedFirstWriteResult struct {
	VaultID     string
	JournalPath string
	OperationID string
	Revision    string
}

// localGenesisPristine is one frozen pristine locator plus the exact
// generation-zero journal state. It owns its byte slices and checkpoint.
type localGenesisPristine struct {
	configPath     string
	workspaceRoot  string
	vaultID        string
	manifest       Manifest
	manifestSHA256 string
	companion      Companion
	checkpoint     *vaultfile.PolicyCheckpoint
	pin            vaultfilejournal.OwnedGenesisPin
	state          vaultfilejournal.State
}

func (p *localGenesisPristine) clear() {
	if p == nil {
		return
	}
	clear(p.state.BaseBytes)
	clear(p.state.WorkingBytes)
	clear(p.pin.Root.OwnerRootPublicKey)
	clearLocalGenesisCheckpoint(p.checkpoint)
	p.pin = vaultfilejournal.OwnedGenesisPin{}
	p.checkpoint = nil
	p.state = vaultfilejournal.State{}
}

func (p *localGenesisPristine) target() personal.OwnedVaultFileFirstSuccessorTarget {
	return personal.OwnedVaultFileFirstSuccessorTarget{
		BackendRoot: p.manifest.BackendRoot,
		BackendName: p.manifest.Name,
		Pin:         cloneLocalGenesisGenesisPin(p.pin),
	}
}

func (p *localGenesisPristine) confirm(s *personal.Session) error {
	manifest, digest, companion, err := readLocalGenesisLocator(s, p.configPath, p.workspaceRoot, p.vaultID)
	if err != nil || manifest != p.manifest || digest != p.manifestSHA256 ||
		!SameCompanion(companion, p.companion) {
		return errLocalOwnedFirstStale
	}
	j, err := vaultfilejournal.OpenExisting(manifest.Journal)
	if err != nil {
		return errLocalOwnedFirstStale
	}
	current, loadErr := j.LoadGenesisBaseline()
	closeErr := j.Close()
	defer clear(current.BaseBytes)
	defer clear(current.WorkingBytes)
	if loadErr != nil || closeErr != nil || !sameLocalOwnedFirstState(current, p.state) ||
		sha256.Sum256(current.BaseBytes) != p.pin.SealedSHA256 {
		return errLocalOwnedFirstStale
	}
	return nil
}

func readLocalGenesisPristine(s *personal.Session, configPath, workspaceRoot, vaultID, expectedJournal string) (*localGenesisPristine, error) {
	manifest, digest, companion, err := readLocalGenesisLocator(s, configPath, workspaceRoot, vaultID)
	if err != nil || expectedJournal == "" || manifest.Journal != expectedJournal {
		return nil, errLocalOwnedFirstStale
	}
	if companion.Resume.Checkpoint == nil {
		return nil, errLocalOwnedFirstReview
	}
	root, ok := DecodeHex(companion.Resume.Checkpoint.OwnerRootPublicKey)
	if !ok {
		return nil, errLocalOwnedFirstReview
	}
	defer clear(root)
	pin, ok := localGenesisOwnedGenesisPin(manifest, companion, root)
	if !ok {
		return nil, errLocalOwnedFirstReview
	}
	j, err := vaultfilejournal.OpenExisting(manifest.Journal)
	if err != nil {
		clear(pin.Root.OwnerRootPublicKey)
		return nil, errLocalOwnedFirstJournal
	}
	state, loadErr := j.LoadGenesisBaseline()
	closeErr := j.Close()
	if loadErr != nil || closeErr != nil {
		clear(pin.Root.OwnerRootPublicKey)
		clear(state.BaseBytes)
		clear(state.WorkingBytes)
		return nil, errLocalOwnedFirstJournal
	}
	fail := func(err error) (*localGenesisPristine, error) {
		clear(state.BaseBytes)
		clear(state.WorkingBytes)
		clear(pin.Root.OwnerRootPublicKey)
		return nil, err
	}
	if sha256.Sum256(state.BaseBytes) != pin.SealedSHA256 {
		return fail(errLocalOwnedFirstStale)
	}
	genesisCheckpoint, err := vaultfile.VerifyGenesis(state.BaseBytes, &pin.Root)
	if err != nil || !localGenesisCheckpointMatchesCompanion(genesisCheckpoint, companion.Resume.Checkpoint) {
		clearLocalGenesisCheckpoint(genesisCheckpoint)
		return fail(errLocalOwnedFirstReview)
	}
	genesis, err := vaultfile.ParseFile(state.BaseBytes)
	if err != nil || genesis.Header.OpID != companion.OperationID ||
		genesis.Header.OpID != pin.OperationID || genesis.Header.VaultID != manifest.VaultID {
		clearLocalGenesisCheckpoint(genesisCheckpoint)
		return fail(errLocalOwnedFirstStale)
	}
	return &localGenesisPristine{
		configPath: configPath, workspaceRoot: workspaceRoot, vaultID: vaultID,
		manifest: manifest, manifestSHA256: digest,
		companion: companion, checkpoint: genesisCheckpoint, pin: pin, state: state,
	}, nil
}

func localOwnedFirstTargetPinValid(target personal.OwnedVaultFileFirstSuccessorTarget, pin vaultfilejournal.OwnedGenesisPin) bool {
	return sameLocalGenesisGenesisPin(target.Pin, pin)
}

func confirmLocalGenesisLocator(s *personal.Session, configPath, workspaceRoot, vaultID, expectedJournal string, manifest Manifest, manifestSHA256 string, companion Companion) error {
	currentManifest, currentDigest, currentCompanion, err := readLocalGenesisLocator(s, configPath, workspaceRoot, vaultID)
	if err != nil || currentManifest != manifest || currentDigest != manifestSHA256 ||
		!SameCompanion(currentCompanion, companion) || currentManifest.Journal != expectedJournal {
		return errLocalOwnedFirstStale
	}
	return nil
}

// localOwnedFirstPendingCheckpoint derives the original genesis policy
// checkpoint from the exact pending journal base, not from the prospective
// successor and not by casting the companion configuration. It verifies the
// base bytes against the owned-genesis pin (sealed hash, operation ID and
// owner root), authenticates the genesis policy, and binds the result to the
// authenticated companion checkpoint before returning it to the write-owned
// recovery path. The caller owns and clears the returned checkpoint.
func localOwnedFirstPendingCheckpoint(journalPath string, pin vaultfilejournal.OwnedGenesisPin, companion *CheckpointConfig) (*vaultfile.PolicyCheckpoint, error) {
	if journalPath == "" || companion == nil {
		return nil, errLocalOwnedFirstJournal
	}
	j, err := vaultfilejournal.OpenExisting(journalPath)
	if err != nil {
		return nil, errLocalOwnedFirstJournal
	}
	pending, prepared, loadErr := j.LoadOwnedFirstPending()
	closeErr := j.Close()
	fail := func(err error) (*vaultfile.PolicyCheckpoint, error) {
		clear(pending.BaseBytes)
		clear(pending.WorkingBytes)
		clear(prepared.Proposal.Bytes)
		return nil, err
	}
	if loadErr != nil || closeErr != nil {
		return fail(errLocalOwnedFirstJournal)
	}
	if sha256.Sum256(pending.BaseBytes) != pin.SealedSHA256 {
		return fail(errLocalOwnedFirstStale)
	}
	genesis, err := vaultfile.ParseFile(pending.BaseBytes)
	if err != nil || genesis.Header.OpID != pin.OperationID {
		return fail(errLocalOwnedFirstReview)
	}
	checkpoint, verifyErr := vaultfile.VerifyGenesis(pending.BaseBytes, &pin.Root)
	clear(pending.BaseBytes)
	clear(pending.WorkingBytes)
	clear(prepared.Proposal.Bytes)
	if verifyErr != nil || !localGenesisCheckpointMatchesCompanion(checkpoint, companion) {
		clearLocalGenesisCheckpoint(checkpoint)
		return nil, errLocalOwnedFirstReview
	}
	return checkpoint, nil
}

// WriteLocalGenesisFirstItem performs one account-bound first-item write for a
// currently owned pristine local genesis vault. It uses the exact strict
// manifest/companion/checkpoint and expected journal, re-proves the full
// factors and current owner, reads the named local backend object at the
// journal's bootstrap revision, seals exactly one login item with the current
// account device and signs the immediate content transition.
//
// It then durably prepares that exact proposal with PrepareWorkingIfState,
// performs exactly one local CAS write, reads the backend back exactly once,
// and acknowledges only through AckOwnedFirstSuccessor using the original
// owned-genesis pin. A stale/replaced/locked, canceled, mismatched, foreign,
// unsupported or advanced/non-pristine request is rejected before publication.
// A CAS conflict or ambiguous result preserves the recoverable preparation;
// only an exact later ResumeLocalGenesisFirstItem may complete it.
//
// No arbitrary signed envelope is accepted, and no root key, signer, VUK or
// item secret is returned or logged. After success, use the reviewed read-only
// local-genesis re-open path for the new view.
func WriteLocalGenesisFirstItem(ctx context.Context, s *personal.Session, configPath, workspaceRoot, vaultID, expectedJournal string, password, key []byte, item LocalGenesisFirstItem) (LocalOwnedFirstWriteResult, error) {
	empty := LocalOwnedFirstWriteResult{}
	if ctx == nil {
		ctx = context.Background()
	}
	if s == nil || !s.Unlocked() || configPath == "" || workspaceRoot == "" ||
		vaultID == "" || !teamfiles.ValidPath(expectedJournal) ||
		item.ID == "" || item.Title == "" {
		return empty, fmt.Errorf("%w: invalid request", ErrLocalOwnedFirstWriteReview)
	}
	if err := ctx.Err(); err != nil {
		return empty, fmt.Errorf("%w: %w", ErrLocalOwnedFirstWriteCanceled, err)
	}
	pristine, err := readLocalGenesisPristine(s, configPath, workspaceRoot, vaultID, expectedJournal)
	if err != nil {
		return empty, mapLocalOwnedFirstPreflight(err)
	}
	defer pristine.clear()

	backend, err := vaultfilebackend.OpenExistingDir(pristine.manifest.BackendRoot)
	if err != nil {
		if errors.Is(err, vaultfilebackend.ErrUnsupported) {
			return empty, fmt.Errorf("%w: %w", ErrLocalOwnedFirstWriteUnsupported, err)
		}
		return empty, fmt.Errorf("%w: %w", ErrLocalOwnedFirstWriteReview, err)
	}
	defer func() { _ = backend.Close() }()
	if err := checkLocalOwnedFirstBase(ctx, backend, pristine.manifest.Name, pristine.state.BaseBytes, pristine.state.RemoteRevision); err != nil {
		return empty, err
	}

	sealed, err := s.SealOwnedVaultFileFirstItem(pristine.manifest.Journal, pristine.target(), pristine.checkpoint,
		pristine.state.BaseBytes, password, key, personal.VaultFileFirstItem{
			ID: item.ID, Title: item.Title, Username: item.Username, Password: item.Password,
		})
	if err != nil {
		return empty, mapLocalOwnedFirstPersonal(err)
	}
	defer sealed.Clear()
	if localOwnedFirstWriteAfterSealForTest != nil {
		localOwnedFirstWriteAfterSealForTest()
	}
	if !sameLocalOwnedFirstState(sealed.State, pristine.state) {
		return empty, fmt.Errorf("%w: sealing state changed", ErrLocalOwnedFirstWriteConflict)
	}
	successor, err := vaultfile.ParseFile(sealed.Sealed)
	if err != nil || successor.Header.OpID == "" {
		return empty, fmt.Errorf("%w: sealed transition", ErrLocalOwnedFirstWriteReview)
	}
	if err := pristine.confirm(s); err != nil {
		return empty, mapLocalOwnedFirstPreflight(err)
	}
	if err := ctx.Err(); err != nil {
		return empty, fmt.Errorf("%w: %w", ErrLocalOwnedFirstWriteCanceled, err)
	}
	if err := checkLocalOwnedFirstBase(ctx, backend, pristine.manifest.Name, sealed.State.BaseBytes, sealed.State.RemoteRevision); err != nil {
		return empty, err
	}

	j, err := vaultfilejournal.OpenExisting(pristine.manifest.Journal)
	if err != nil {
		return empty, fmt.Errorf("%w: %w", ErrLocalOwnedFirstWriteConflict, err)
	}
	defer func() { _ = j.Close() }()
	origin := sealed.State
	proposal := vaultfilejournal.Proposal{
		Generation:       origin.Generation + 1,
		OperationID:      successor.Header.OpID,
		ExpectedRevision: origin.RemoteRevision,
		Bytes:            sealed.Sealed,
	}
	if err := j.PrepareWorkingIfState(origin, proposal); err != nil {
		return empty, mapLocalOwnedFirstPrepare(err)
	}
	if localOwnedFirstWriteAfterPrepareForTest != nil {
		localOwnedFirstWriteAfterPrepareForTest()
	}
	if err := ctx.Err(); err != nil {
		return empty, fmt.Errorf("%w: prepared before write: %w", ErrLocalOwnedFirstWriteIndeterminate, err)
	}

	writeErr := backend.ReplaceIfVersion(ctx, pristine.manifest.Name, origin.RemoteRevision, proposal.Bytes)
	if localOwnedFirstWriteAfterPublishForTest != nil {
		localOwnedFirstWriteAfterPublishForTest()
	}
	return finishLocalOwnedFirstWrite(ctx, j, backend, pristine, origin, proposal,
		sealed.AuthorDeviceID, writeErr)
}

// WriteFirstItem is the normal entry for a caller that already holds the
// reviewed registered scoped child. It revalidates this exact wrapper and its
// frozen pristine locator, then performs the same account-bound write and
// full-factor/current-owner proof. Success or an unresolved prepared result
// retires the now-stale wrapper; callers must explicitly re-open the read-only
// path for the new view. A rejected request leaves the wrapper available.
func (l *LocalGenesisSession) WriteFirstItem(ctx context.Context, password, key []byte, item LocalGenesisFirstItem) (LocalOwnedFirstWriteResult, error) {
	empty := LocalOwnedFirstWriteResult{}
	if l == nil || l.state == nil {
		return empty, fmt.Errorf("%w: no scoped child", ErrLocalOwnedFirstWriteReview)
	}
	s := l.state
	s.mu.Lock()
	closed := s.closed
	parent := s.parent
	configPath := s.configPath
	manifest := s.manifest
	successor := s.successor
	s.mu.Unlock()
	if closed || parent == nil {
		return empty, fmt.Errorf("%w: scoped child closed", ErrLocalOwnedFirstWriteReview)
	}
	if successor != nil {
		return empty, fmt.Errorf("%w: scoped child is not pristine", ErrLocalOwnedFirstWriteConflict)
	}
	if err := s.revalidateLocator(); err != nil {
		_ = l.Close()
		return empty, fmt.Errorf("%w: scoped child stale", ErrLocalOwnedFirstWriteConflict)
	}
	result, err := WriteLocalGenesisFirstItem(ctx, parent, configPath, manifest.BackendRoot,
		manifest.VaultID, manifest.Journal, password, key, item)
	if err == nil || errors.Is(err, ErrLocalOwnedFirstWriteIndeterminate) {
		_ = l.Close()
	}
	return result, err
}

// ResumeLocalGenesisFirstItem recovers exactly one durably prepared owned
// first write directly through the narrow write-owned journal/owner path. The
// read-only A1 APIs deliberately reject a pending journal and are not used.
// It re-proves the current account factors/owner and the original trusted
// companion/checkpoint, then requires the journal's only pending shape to be
// the exact generation-1 state plus prepared proposal, signed by the current
// account device with writer authority.
//
// It never accepts caller-supplied ciphertext or proposal versions, never
// creates a second item or nonce, and never depends on a prior in-memory
// wrapper. It reads the named local backend object exactly once to classify
// the outcome. An exact already-written proposal is acknowledged with its
// observed revision; an exact original base at the original revision may
// retry the same CAS once. Any other observation returns a typed conflict or
// indeterminate error and leaves the journal intact.
func ResumeLocalGenesisFirstItem(ctx context.Context, s *personal.Session, configPath, workspaceRoot, vaultID, expectedJournal string, password, key []byte) (LocalOwnedFirstWriteResult, error) {
	empty := LocalOwnedFirstWriteResult{}
	if ctx == nil {
		ctx = context.Background()
	}
	if s == nil || !s.Unlocked() || configPath == "" || workspaceRoot == "" ||
		vaultID == "" || !teamfiles.ValidPath(expectedJournal) {
		return empty, fmt.Errorf("%w: invalid request", ErrLocalOwnedFirstWriteReview)
	}
	if err := ctx.Err(); err != nil {
		return empty, fmt.Errorf("%w: %w", ErrLocalOwnedFirstWriteCanceled, err)
	}
	manifest, manifestSHA256, companion, err := readLocalGenesisLocator(s, configPath, workspaceRoot, vaultID)
	if err != nil || manifest.Journal != expectedJournal || companion.Resume.Checkpoint == nil {
		return empty, fmt.Errorf("%w: locator", ErrLocalOwnedFirstWriteReview)
	}
	root, ok := DecodeHex(companion.Resume.Checkpoint.OwnerRootPublicKey)
	if !ok {
		return empty, fmt.Errorf("%w: owner root", ErrLocalOwnedFirstWriteReview)
	}
	defer clear(root)
	pin, ok := localGenesisOwnedGenesisPin(manifest, companion, root)
	if !ok {
		return empty, fmt.Errorf("%w: owner pin", ErrLocalOwnedFirstWriteReview)
	}
	defer clear(pin.Root.OwnerRootPublicKey)
	target := personal.OwnedVaultFileFirstSuccessorTarget{
		BackendRoot: manifest.BackendRoot, BackendName: manifest.Name,
		Pin: cloneLocalGenesisGenesisPin(pin),
	}
	defer clear(target.Pin.Root.OwnerRootPublicKey)
	genesisCheckpoint, err := localOwnedFirstPendingCheckpoint(manifest.Journal, pin, companion.Resume.Checkpoint)
	if err != nil {
		return empty, mapLocalOwnedFirstPreflight(err)
	}
	defer clearLocalGenesisCheckpoint(genesisCheckpoint)

	proof, err := s.RecoverOwnedVaultFileFirstWrite(manifest.Journal, target, genesisCheckpoint, password, key)
	if err != nil {
		return empty, mapLocalOwnedFirstPersonal(err)
	}
	defer proof.Clear()
	if !localOwnedFirstTargetPinValid(target, pin) ||
		proof.Origin.Generation != 0 ||
		proof.Pending.Generation != 1 ||
		proof.Prepared.WorkingGeneration != 1 ||
		proof.Prepared.Proposal.Generation != 1 ||
		proof.Prepared.Proposal.ExpectedRevision != proof.Origin.RemoteRevision ||
		!bytes.Equal(proof.Prepared.Proposal.Bytes, proof.Pending.WorkingBytes) ||
		!bytes.Equal(proof.Origin.BaseBytes, proof.Pending.BaseBytes) {
		return empty, fmt.Errorf("%w: pending tuple", ErrLocalOwnedFirstWriteConflict)
	}

	j, err := vaultfilejournal.OpenExisting(manifest.Journal)
	if err != nil {
		return empty, fmt.Errorf("%w: %w", ErrLocalOwnedFirstWriteConflict, err)
	}
	defer func() { _ = j.Close() }()
	pending, prepared, err := j.LoadOwnedFirstPending()
	defer clear(pending.BaseBytes)
	defer clear(pending.WorkingBytes)
	defer clear(prepared.Proposal.Bytes)
	if err != nil || !sameLocalOwnedFirstState(pending, proof.Pending) ||
		!sameLocalOwnedFirstPrepared(prepared, proof.Prepared) {
		return empty, fmt.Errorf("%w: pending changed", ErrLocalOwnedFirstWriteConflict)
	}

	backend, err := vaultfilebackend.OpenExistingDir(manifest.BackendRoot)
	if err != nil {
		if errors.Is(err, vaultfilebackend.ErrUnsupported) {
			return empty, fmt.Errorf("%w: %w", ErrLocalOwnedFirstWriteUnsupported, err)
		}
		return empty, fmt.Errorf("%w: %w", ErrLocalOwnedFirstWriteReview, err)
	}
	defer func() { _ = backend.Close() }()

	data, revision, err := readLocalOwnedFirstObservation(ctx, backend, manifest.Name, proof.Origin, proof.Prepared.Proposal)
	if err != nil {
		return empty, err
	}
	defer clear(data)
	if err := confirmLocalGenesisLocator(s, configPath, workspaceRoot, vaultID, expectedJournal,
		manifest, manifestSHA256, companion); err != nil {
		return empty, mapLocalOwnedFirstPreflight(err)
	}
	switch {
	case bytes.Equal(data, proof.Prepared.Proposal.Bytes):
		return acknowledgeLocalOwnedFirstWrite(ctx, j, manifest, pin, proof.Origin,
			proof.Prepared.Proposal, data, revision, genesisCheckpoint, proof.AuthorDeviceID)
	case bytes.Equal(data, proof.Origin.BaseBytes):
		if revision != proof.Origin.RemoteRevision {
			return empty, fmt.Errorf("%w: original bytes at a new revision", ErrLocalOwnedFirstWriteConflict)
		}
		proposal := proof.Prepared.Proposal
		if err := verifyLocalOwnedFirstProposal(pin, proof.Origin, proposal, genesisCheckpoint, proof.AuthorDeviceID); err != nil {
			return empty, fmt.Errorf("%w: %w", ErrLocalOwnedFirstWriteConflict, err)
		}
		if err := ctx.Err(); err != nil {
			return empty, fmt.Errorf("%w: %w", ErrLocalOwnedFirstWriteCanceled, err)
		}
		writeErr := backend.ReplaceIfVersion(ctx, manifest.Name, proof.Origin.RemoteRevision, proposal.Bytes)
		if localOwnedFirstWriteAfterPublishForTest != nil {
			localOwnedFirstWriteAfterPublishForTest()
		}
		return finishLocalOwnedFirstWrite(ctx, j, backend, &localGenesisPristine{
			manifest: manifest, pin: pin, checkpoint: genesisCheckpoint,
		}, proof.Origin, proposal, proof.AuthorDeviceID, writeErr)
	default:
		return empty, fmt.Errorf("%w: different backend successor", ErrLocalOwnedFirstWriteConflict)
	}
}

func mapLocalOwnedFirstPreflight(err error) error {
	switch {
	case errors.Is(err, errLocalOwnedFirstJournal):
		return fmt.Errorf("%w: %w", ErrLocalOwnedFirstWriteConflict, err)
	case errors.Is(err, errLocalOwnedFirstStale):
		return fmt.Errorf("%w: %w", ErrLocalOwnedFirstWriteConflict, err)
	case errors.Is(err, errLocalOwnedFirstReview):
		return fmt.Errorf("%w: %w", ErrLocalOwnedFirstWriteReview, err)
	default:
		return fmt.Errorf("%w: %w", ErrLocalOwnedFirstWriteReview, err)
	}
}

func mapLocalOwnedFirstPersonal(err error) error {
	switch {
	case errors.Is(err, personal.ErrVaultFileBaselineJournal):
		return fmt.Errorf("%w: %w", ErrLocalOwnedFirstWriteConflict, err)
	case errors.Is(err, personal.ErrVaultFileScopedFactors),
		errors.Is(err, personal.ErrVaultFileOwnership),
		errors.Is(err, personal.ErrVaultFileBaselineVerification),
		errors.Is(err, personal.ErrVaultFileEditReview),
		errors.Is(err, personal.ErrVaultFileEditVerification),
		errors.Is(err, personal.ErrVaultFileFullFactorRequired),
		errors.Is(err, personal.ErrSessionLocked):
		return fmt.Errorf("%w: %w", ErrLocalOwnedFirstWriteReview, err)
	default:
		return fmt.Errorf("%w: %w", ErrLocalOwnedFirstWriteReview, err)
	}
}

func sameLocalOwnedFirstState(a, b vaultfilejournal.State) bool {
	return a.Generation == b.Generation && a.RemoteRevision == b.RemoteRevision &&
		bytes.Equal(a.BaseBytes, b.BaseBytes) && bytes.Equal(a.WorkingBytes, b.WorkingBytes)
}

func sameLocalOwnedFirstPrepared(a, b vaultfilejournal.PreparedProposal) bool {
	return a.WorkingGeneration == b.WorkingGeneration &&
		a.Proposal.Generation == b.Proposal.Generation &&
		a.Proposal.OperationID == b.Proposal.OperationID &&
		a.Proposal.ExpectedRevision == b.Proposal.ExpectedRevision &&
		bytes.Equal(a.Proposal.Bytes, b.Proposal.Bytes)
}
