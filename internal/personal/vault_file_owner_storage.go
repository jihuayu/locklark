package personal

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"

	"github.com/jihuayu/locklark/pkg/vaultfile"
	"github.com/jihuayu/locklark/pkg/vaultfilebackend"
	bolt "go.etcd.io/bbolt"
)

var ErrVaultFileOwnership = errors.New("vault-file ownership custody unavailable")

// ErrVaultFileBackupCustodyTarget reports that the independently trusted named
// local backend object is absent, unsupported or is not the exact authenticated
// source version. It is distinct from a wrong artifact/factor, which is
// ErrVaultFileBackupCustody.
var ErrVaultFileBackupCustodyTarget = errors.New("vault-file backup custody local target rejected")

// ErrVaultFileBackupCustodyRestoreUnconfirmed reports that the import may
// already be durable although a post-commit context, lock, freshness or close
// check failed. An exact retry is safe and either proves the same private owner
// or reports a real refusal; callers must not assume the import was rolled back
// and must not replace or overwrite the destination store.
var ErrVaultFileBackupCustodyRestoreUnconfirmed = errors.New("vault-file backup custody restore outcome unconfirmed")

// vaultFileOwnerRecoveryBeforeCommitForTest is a private nil-by-default fault
// point. It runs inside the destination transaction after every check and
// before the imported owner record is written, so tests can prove that a lock
// immediately before commit leaves no durable import. Production leaves it nil.
var vaultFileOwnerRecoveryBeforeCommitForTest func()

const (
	vaultFileOwnerPrepareAction = "vault-file.owner.prepare"
	vaultFileOwnerRestoreAction = "vault-file.owner.restore"
	vaultFileOwnerListAction    = "vault-file.owner.list"
)

var vaultFileOwnerKey = []byte("vault-file-owners/v1")
var vaultFileOwnerLabel = []byte("locklark/personal/vault-file-owners/v1\x00")

func latestVaultFileOwnerDigest(rows []Event) string {
	latest := ""
	for _, event := range rows {
		if event.Action == vaultFileOwnerPrepareAction || event.Action == vaultFileOwnerRestoreAction {
			latest = event.Link
		}
	}
	return latest
}

// The last signed chain is the live personal device's history. Older chains
// are anchored by vault.restore, but their old custody ciphertext is not a
// record in the newly restored device's database.
func validateBackupVaultFileOwners(p *payload) error {
	if p == nil || len(p.Chains) == 0 {
		return invalid
	}
	expected := latestVaultFileOwnerDigest(p.Chains[len(p.Chains)-1].Events)
	if expected == "" && len(p.VaultFileOwners) == 0 {
		return nil
	}
	if expected == "" || len(p.VaultFileOwners) == 0 {
		return invalid
	}
	actual, err := vaultFileOwnersDigest(p.VaultFileOwners)
	if err != nil || actual != expected {
		return invalid
	}
	return nil
}

func loadVaultFileOwners(b *bolt.Bucket, i identity, rows []Event) ([]vaultFileOwnerRecord, error) {
	expected := latestVaultFileOwnerDigest(rows)
	raw := b.Get(vaultFileOwnerKey)
	if expected == "" && raw == nil {
		return nil, nil // pre-feature personal vault
	}
	if expected == "" || raw == nil || len(raw) > maxVaultFileOwnerBytes+64 {
		return nil, invalid
	}
	a, err := auditCipher(i)
	if err != nil {
		return nil, invalid
	}
	plain, err := a.Open(nil, nil, raw, vaultFileOwnerLabel)
	if err != nil {
		return nil, invalid
	}
	defer clear(plain)
	if len(plain) > maxVaultFileOwnerBytes {
		return nil, invalid
	}
	var records []vaultFileOwnerRecord
	decoder := json.NewDecoder(bytes.NewReader(plain))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&records) != nil || decoder.Decode(new(any)) != io.EOF || len(records) == 0 {
		clearVaultFileOwners(records)
		return nil, invalid
	}
	canonical, err := json.Marshal(records)
	if err != nil || !bytes.Equal(canonical, plain) {
		clear(canonical)
		clearVaultFileOwners(records)
		return nil, invalid
	}
	clear(canonical)
	actual, err := vaultFileOwnersDigest(records)
	if err != nil || actual != expected {
		clearVaultFileOwners(records)
		return nil, invalid
	}
	return records, nil
}

func saveVaultFileOwners(b *bolt.Bucket, i identity, records []vaultFileOwnerRecord) error {
	if _, err := vaultFileOwnersDigest(records); err != nil {
		return err
	}
	a, err := auditCipher(i)
	if err != nil {
		return invalid
	}
	sealed, err := sealedJSON(a, vaultFileOwnerLabel, records)
	if err != nil || len(sealed) > maxVaultFileOwnerBytes+64 {
		return invalid
	}
	return b.Put(vaultFileOwnerKey, sealed)
}

// PrepareVaultFileOwnership creates only unpublished owner and recovery-device
// custody for a caller-persisted local vault ID. An exact retry authenticates
// the same records and returns the same public projection without generating
// another key or changing the snapshot. The ID is a selector, not authority.
func (s *Session) PrepareVaultFileOwnership(vaultID string) (VaultFileOwnershipPublic, error) {
	if s == nil {
		return VaultFileOwnershipPublic{}, ErrSessionLocked
	}
	if !idOK(vaultID) {
		return VaultFileOwnershipPublic{}, ErrVaultFileOwnership
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.active(true); err != nil {
		return VaultFileOwnershipPublic{}, err
	}
	if s.requireFreshFullFactor() != nil {
		return VaultFileOwnershipPublic{}, ErrVaultFileFullFactorRequired
	}
	var projection VaultFileOwnershipPublic
	mutated := false
	db, err := existing(s.path)
	if err != nil {
		return VaultFileOwnershipPublic{}, err
	}
	err = db.Update(func(tx *bolt.Tx) error {
		auth, err := authenticateStateItems(tx, "", nil, vaultFileOwnerPrepareAction, s, true)
		if err != nil {
			return err
		}
		defer auth.clear()
		if s.active(false) != nil || s.requireFreshFullFactor() != nil {
			return ErrSessionLocked
		}
		b := tx.Bucket(bucket)
		records, err := loadVaultFileOwners(b, auth.identity, auth.rows)
		if err != nil {
			return err
		}
		defer func() { clearVaultFileOwners(records) }()
		index := 0
		for index < len(records) && records[index].VaultID < vaultID {
			index++
		}
		if index < len(records) && records[index].VaultID == vaultID {
			projection, err = vaultFileOwnerPublic(records[index])
			return err
		}
		if len(records) >= maxVaultFileOwnerRecords {
			return ErrArchiveLimit
		}
		record, err := newVaultFileOwnerRecord()
		if err != nil {
			return ErrVaultFileOwnership
		}
		defer clearVaultFileOwners([]vaultFileOwnerRecord{record})
		record.VaultID = vaultID
		projection, err = vaultFileOwnerPublic(record)
		if err != nil {
			return ErrVaultFileOwnership
		}
		records = append(records, vaultFileOwnerRecord{})
		copy(records[index+1:], records[index:])
		records[index] = record
		if err := saveVaultFileOwners(b, auth.identity, records); err != nil {
			return err
		}
		digest, err := vaultFileOwnersDigest(records)
		if err != nil {
			return err
		}
		if auth.snapshot.Epoch == math.MaxUint64 {
			return ErrVaultFileOwnership
		}
		snapshot, err := seal(b, auth.identity, auth.snapshot.Epoch+1, auth.items)
		if err != nil {
			return err
		}
		_, err = appendLinked(b, auth.identity, auth.tip, snapshot, vaultFileOwnerPrepareAction, "", "succeeded", "", digest)
		if err != nil {
			return err
		}
		if s.active(false) != nil {
			return ErrSessionLocked
		}
		if s.requireFreshFullFactor() != nil {
			return ErrVaultFileFullFactorRequired
		}
		mutated = true
		return nil
	})
	closeErr := db.Close()
	if errors.Is(err, invalid) {
		s.lock()
	}
	if err != nil {
		return VaultFileOwnershipPublic{}, err
	}
	if closeErr != nil {
		return VaultFileOwnershipPublic{}, ErrCommandClose
	}
	if s.active(false) != nil {
		return VaultFileOwnershipPublic{}, ErrSessionLocked
	}
	if s.requireFreshFullFactor() != nil {
		return VaultFileOwnershipPublic{}, ErrVaultFileFullFactorRequired
	}
	if mutated {
		s.clearAuditCache()
	}
	return projection, nil
}

// VaultFileBackupCustodyRestoreSourceBinding is the independently issued,
// public source binding for one transferred custody artifact. It carries the
// exact authenticated source scope that the destination must match before it
// observes the local target or opens the owner store. SourceIdentity is the
// canonical personal VaultFileBackupCustodySourceIdentity produced by the
// custody opener, not the client-local LocalOwnedBackupSource identity digest.
// It contains no ciphertext, plaintext item, factor, owner seed, path or
// checkpoint bytes.
type VaultFileBackupCustodyRestoreSourceBinding struct {
	VaultID         string
	SourceIdentity  [sha256.Size]byte
	JournalRevision string
	BackendRevision string
	OriginRevision  string
	ContentSeq      uint64
}

func (b VaultFileBackupCustodyRestoreSourceBinding) valid() bool {
	return idOK(b.VaultID) && b.SourceIdentity != ([sha256.Size]byte{}) &&
		b.JournalRevision != "" && b.BackendRevision != "" &&
		(b.OriginRevision == "") == (b.ContentSeq == 0)
}

// VaultFileBackupCustodyRestoreTarget is the caller's independently trusted
// locator for the existing LOCAL backend object that must already contain the
// exact authenticated source version. Root and Name must be transported
// separately and must not be derived from the custody artifact.
type VaultFileBackupCustodyRestoreTarget struct {
	Root string
	Name string
}

func (t VaultFileBackupCustodyRestoreTarget) valid() bool {
	return validVaultFileGenesisPath(t.Root) && vaultfilebackend.ValidName(t.Name)
}

// RestoreVaultFileBackupCustodyOwner preserves the single authenticated private
// owner/recovery record from one independently pinned transferred custody
// artifact in this fresh destination personal account's existing encrypted
// owner store. It authenticates the artifact with the expected checkpoint and
// separate recovery factor through the owning in-package opener, requires the
// opened source to match sourceBinding exactly, reads the caller-located
// existing LOCAL backend object non-creating, and requires exact byte and
// opaque revision equality to the authenticated source. Only then does it
// insert one record under the recovery-specific owner.restore audit action.
// SourceBinding is the caller's independent pin for the source identity,
// opaque revisions and content sequence; a wrong binding is refused before the
// target read and before any owner-store transaction.
//
// The destination ordinary device identity is never read into the owner record
// or replaced. Up to maxVaultFileOwnerRecords existing unrelated records are
// preserved in order. An existing record for the same vault ID is accepted only
// when every private owner/recovery field is identical; that exact retry
// returns the same public projection without generating material, advancing the
// snapshot or appending an event. A different record for the same vault ID, a
// missing/replaced target, a wrong artifact/factor/checkpoint/source binding or
// a request from a non-fresh or locked session leaves the store unchanged. The
// target read buffer is cleared before the transaction. That read is a local
// point-in-time observation: it does not fence, stop or prove the absence of
// remote writers.
//
// A post-commit context expiry, lock or fresh-factor refusal is reported
// honestly as an error even though the import may already be durable; an exact
// retry is safe and proves the same private owner. A close error is reported as
// ErrVaultFileBackupCustodyRestoreUnconfirmed with the same uncertainty. The returned public projection is
// local metadata only. It is not a signed policy, an activated device, a remote
// freshness proof, an invitation or authority for any later write, which must
// independently re-check current policy and CAS.
func (s *Session) RestoreVaultFileBackupCustodyOwner(ctx context.Context, artifact []byte,
	expected vaultfile.PolicyCheckpoint, factor *VaultFileBackupRecoveryFactor,
	sourceBinding VaultFileBackupCustodyRestoreSourceBinding,
	target VaultFileBackupCustodyRestoreTarget) (VaultFileOwnershipPublic, error) {
	if s == nil {
		return VaultFileOwnershipPublic{}, ErrSessionLocked
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if factor == nil || !validVaultFileBackupCustodyCheckpoint(expected) ||
		!sourceBinding.valid() || !target.valid() {
		return VaultFileOwnershipPublic{}, vaultFileBackupCustodyError(ErrVaultFileBackupCustody, "restore request")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.active(true); err != nil {
		return VaultFileOwnershipPublic{}, err
	}
	if err := s.requireFreshFullFactor(); err != nil {
		return VaultFileOwnershipPublic{}, err
	}

	source, ownership, owner, err := openVaultFileBackupCustodyRecord(ctx, artifact, expected, factor)
	if err != nil {
		source.Clear()
		clearVaultFileOwners([]vaultFileOwnerRecord{owner})
		return VaultFileOwnershipPublic{}, err
	}
	defer source.Clear()
	defer clearVaultFileOwners([]vaultFileOwnerRecord{owner})
	if source.VaultID != sourceBinding.VaultID ||
		source.SourceIdentity != sourceBinding.SourceIdentity ||
		source.JournalRevision != sourceBinding.JournalRevision ||
		source.BackendRevision != sourceBinding.BackendRevision ||
		source.OriginRevision != sourceBinding.OriginRevision ||
		source.ContentSeq != sourceBinding.ContentSeq {
		return VaultFileOwnershipPublic{}, vaultFileBackupCustodyError(ErrVaultFileBackupCustody, "restore source binding")
	}
	if source.VaultID != expected.VaultID || ownership.VaultID != expected.VaultID ||
		ownership.OwnerRootKeyID != expected.OwnerRootKeyID {
		return VaultFileOwnershipPublic{}, vaultFileBackupCustodyError(ErrVaultFileBackupCustody, "restore binding")
	}
	if err := readVaultFileBackupCustodyRestoreTarget(ctx, source, target); err != nil {
		return VaultFileOwnershipPublic{}, err
	}
	if err := ctx.Err(); err != nil {
		return VaultFileOwnershipPublic{}, vaultFileBackupCustodyError(ErrVaultFileBackupCustodyCanceled, "context")
	}

	db, err := existing(s.path)
	if err != nil {
		return VaultFileOwnershipPublic{}, err
	}
	var projection VaultFileOwnershipPublic
	mutated := false
	err = db.Update(func(tx *bolt.Tx) error {
		auth, err := authenticateStateItems(tx, "", nil, vaultFileOwnerRestoreAction, s, true)
		if err != nil {
			return err
		}
		defer auth.clear()
		if s.active(false) != nil {
			return ErrSessionLocked
		}
		if s.requireFreshFullFactor() != nil {
			return ErrVaultFileFullFactorRequired
		}
		records, err := loadVaultFileOwners(tx.Bucket(bucket), auth.identity, auth.rows)
		if err != nil {
			return err
		}
		// A direct defer would capture the pre-append header and could retain the
		// deep-cloned owner when append reallocates or inserts at the end.
		defer func() { clearVaultFileOwners(records) }()
		index := 0
		for index < len(records) && records[index].VaultID < owner.VaultID {
			index++
		}
		if index < len(records) && records[index].VaultID == owner.VaultID {
			existingProjection, err := vaultFileOwnerPublic(records[index])
			if err != nil || existingProjection != ownership ||
				!sameVaultFileGenesisOwner(records[index], owner) {
				return vaultFileBackupCustodyError(ErrVaultFileOwnership, "owner collision")
			}
			projection = existingProjection
			return nil
		}
		if len(records) >= maxVaultFileOwnerRecords {
			return ErrArchiveLimit
		}
		if err := ctx.Err(); err != nil {
			return vaultFileBackupCustodyError(ErrVaultFileBackupCustodyCanceled, "context")
		}
		if vaultFileOwnerRecoveryBeforeCommitForTest != nil {
			vaultFileOwnerRecoveryBeforeCommitForTest()
		}
		if s.active(false) != nil {
			return ErrSessionLocked
		}
		if s.requireFreshFullFactor() != nil {
			return ErrVaultFileFullFactorRequired
		}
		inserted := cloneVaultFileOwners([]vaultFileOwnerRecord{owner})[0]
		records = append(records, vaultFileOwnerRecord{})
		copy(records[index+1:], records[index:])
		records[index] = inserted
		if err := saveVaultFileOwners(tx.Bucket(bucket), auth.identity, records); err != nil {
			return err
		}
		digest, err := vaultFileOwnersDigest(records)
		if err != nil {
			return err
		}
		if auth.snapshot.Epoch == math.MaxUint64 {
			return ErrVaultFileOwnership
		}
		snapshot, err := seal(tx.Bucket(bucket), auth.identity, auth.snapshot.Epoch+1, auth.items)
		if err != nil {
			return err
		}
		if _, err := appendLinked(tx.Bucket(bucket), auth.identity, auth.tip, snapshot,
			vaultFileOwnerRestoreAction, "", "succeeded", "", digest); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return vaultFileBackupCustodyError(ErrVaultFileBackupCustodyCanceled, "context")
		}
		projection, err = vaultFileOwnerPublic(owner)
		if err != nil {
			return ErrVaultFileOwnership
		}
		mutated = true
		return nil
	})
	closeErr := db.Close()
	if mutated {
		s.clearAuditCache()
	}
	if errors.Is(err, invalid) {
		s.lock()
	}
	if err != nil {
		return VaultFileOwnershipPublic{}, err
	}
	if closeErr != nil {
		return VaultFileOwnershipPublic{}, fmt.Errorf("%w: close", ErrVaultFileBackupCustodyRestoreUnconfirmed)
	}
	if s.active(false) != nil {
		return VaultFileOwnershipPublic{}, fmt.Errorf("%w: session", ErrVaultFileBackupCustodyRestoreUnconfirmed)
	}
	if s.requireFreshFullFactor() != nil {
		return VaultFileOwnershipPublic{}, fmt.Errorf("%w: freshness", ErrVaultFileBackupCustodyRestoreUnconfirmed)
	}
	if err := ctx.Err(); err != nil {
		return VaultFileOwnershipPublic{}, fmt.Errorf("%w: context", ErrVaultFileBackupCustodyRestoreUnconfirmed)
	}
	return projection, nil
}

// readVaultFileBackupCustodyRestoreTarget reads the caller-located existing
// LOCAL backend object once. The artifact opener already verified the source
// checkpoint, key epoch, policy proof, source identity and opaque journal/backend
// revision, so exact byte and revision equality is required rather than parsing
// the target a second time. The read buffer is always cleared.
func readVaultFileBackupCustodyRestoreTarget(ctx context.Context, source VaultFileBackupCustodySource, target VaultFileBackupCustodyRestoreTarget) error {
	if !target.valid() || !validVaultFileBackupCustodyCheckpoint(source.Checkpoint) ||
		len(source.Current) == 0 || len(source.BackendRevision) == 0 {
		return vaultFileBackupCustodyError(ErrVaultFileBackupCustodyTarget, "target request")
	}
	backend, err := vaultfilebackend.OpenExistingDir(target.Root)
	if err != nil {
		return mapVaultFileBackupCustodyRestoreTargetError(err)
	}
	result, readErr := backend.Read(ctx, target.Name)
	closeErr := backend.Close()
	defer clear(result.Bytes)
	if readErr != nil {
		return mapVaultFileBackupCustodyRestoreTargetError(readErr)
	}
	if closeErr != nil {
		return mapVaultFileBackupCustodyRestoreTargetError(closeErr)
	}
	if result.Revision != vaultfilebackend.Revision(source.BackendRevision) ||
		!bytes.Equal(result.Bytes, source.Current) {
		return vaultFileBackupCustodyError(ErrVaultFileBackupCustodyTarget, "target")
	}
	if err := ctx.Err(); err != nil {
		return vaultFileBackupCustodyError(ErrVaultFileBackupCustodyCanceled, "context")
	}
	return nil
}

func mapVaultFileBackupCustodyRestoreTargetError(err error) error {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return vaultFileBackupCustodyError(ErrVaultFileBackupCustodyCanceled, "context")
	default:
		return fmt.Errorf("%w: %w", ErrVaultFileBackupCustodyTarget, err)
	}
}

// VaultFileOwnerships reads only public projections of unpublished custody
// records after full-factor authentication. It never returns a private key.
func (s *Session) VaultFileOwnerships() ([]VaultFileOwnershipPublic, error) {
	if s == nil {
		return nil, ErrSessionLocked
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.active(true); err != nil {
		return nil, err
	}
	if s.requireFreshFullFactor() != nil {
		return nil, ErrVaultFileFullFactorRequired
	}
	db, err := existingWithReadOnly(s.path, true)
	if err != nil {
		return nil, err
	}
	var projections []VaultFileOwnershipPublic
	err = db.View(func(tx *bolt.Tx) error {
		auth, err := authenticateStateItems(tx, "", nil, vaultFileOwnerListAction, s, false)
		if err != nil {
			return err
		}
		defer auth.clear()
		records, err := loadVaultFileOwners(tx.Bucket(bucket), auth.identity, auth.rows)
		if err != nil {
			return err
		}
		defer clearVaultFileOwners(records)
		for _, record := range records {
			projection, err := vaultFileOwnerPublic(record)
			if err != nil {
				return err
			}
			projections = append(projections, projection)
		}
		return nil
	})
	closeErr := db.Close()
	if errors.Is(err, invalid) {
		s.lock()
	}
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		return nil, ErrCommandClose
	}
	if s.active(false) != nil {
		return nil, ErrSessionLocked
	}
	if s.requireFreshFullFactor() != nil {
		return nil, ErrVaultFileFullFactorRequired
	}
	return projections, nil
}
