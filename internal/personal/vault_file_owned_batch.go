package personal

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"time"

	"github.com/jihuayu/locklark/pkg/vaultfile"
	bolt "go.etcd.io/bbolt"
)

const (
	maxOwnedVaultFileBatchTargets = 64
	maxOwnedVaultFileBatchPath    = 4096
	maxOwnedVaultFileBatchVaultID = 128
	maxOwnedVaultFileBatchRootID  = 256
)

// OwnedVaultFileTarget freezes one exact journal and candidate checkpoint for
// an initial owned-child batch. The checkpoint is copied before any
// authentication; its target root becomes trusted only through the separately
// authenticated local owner record. The caller may mutate its slices after this
// call returns.
type OwnedVaultFileTarget struct {
	JournalPath string
	Checkpoint  vaultfile.PolicyCheckpoint
	Options     VaultFileChildOptions
}

// OwnedVaultFileChildResult reports one original target index. A nil Err means
// the exact token/items were registered in the returned parent. Duplicate exact
// targets share one child but receive one result per original index.
type OwnedVaultFileChildResult struct {
	Index int
	Token VaultFileChildToken
	Items []VaultFileBaselineItem
	Err   error
}

type ownedVaultFileBatchRequest struct {
	journalPath string
	checkpoint  vaultfile.PolicyCheckpoint
	options     VaultFileChildOptions
	indices     []int
}

// vaultFileOwnedBatchAuthForTest observes the single combined account and
// owner-custody authentication phase. It is nil in production and carries no
// credential, material, identity, path or authority.
var vaultFileOwnedBatchAuthForTest func()

// vaultFileOwnedBatchUndeliveredForTest observes only public summary buffer
// references just before an undelivered batch clears them. It is nil in
// production and carries no token, parent, path, identity, material or
// authority.
var vaultFileOwnedBatchUndeliveredForTest func(current []VaultFileBaselineItem, accumulated [][]VaultFileBaselineItem)

func clearOwnedVaultFileBatchResults(results []OwnedVaultFileChildResult) {
	for i := range results {
		clearVaultFileChildItems(results[i].Items)
		results[i] = OwnedVaultFileChildResult{}
	}
}

func validOwnedVaultFileTarget(target OwnedVaultFileTarget) bool {
	checkpoint := target.Checkpoint
	return target.JournalPath != "" && len(target.JournalPath) <= maxOwnedVaultFileBatchPath &&
		checkpoint.VaultID != "" && len(checkpoint.VaultID) <= maxOwnedVaultFileBatchVaultID &&
		checkpoint.OwnerRootKeyID != "" && len(checkpoint.OwnerRootKeyID) <= maxOwnedVaultFileBatchRootID &&
		len(checkpoint.OwnerRootPublicKey) == ed25519.PublicKeySize &&
		len(checkpoint.PolicyDigest) == sha256.Size
}

func sameOwnedVaultFileBatchRequest(a, b ownedVaultFileBatchRequest) bool {
	return a.journalPath == b.journalPath && a.options == b.options &&
		a.checkpoint.VaultID == b.checkpoint.VaultID &&
		a.checkpoint.OwnerRootKeyID == b.checkpoint.OwnerRootKeyID &&
		a.checkpoint.PolicySeq == b.checkpoint.PolicySeq &&
		bytes.Equal(a.checkpoint.OwnerRootPublicKey, b.checkpoint.OwnerRootPublicKey) &&
		bytes.Equal(a.checkpoint.PolicyDigest, b.checkpoint.PolicyDigest)
}

func prepareOwnedVaultFileBatch(targets []OwnedVaultFileTarget) ([]ownedVaultFileBatchRequest, error) {
	if len(targets) > maxOwnedVaultFileBatchTargets {
		return nil, ErrVaultFileBaselineVerification
	}
	if len(targets) == 0 {
		return nil, nil
	}
	out := make([]ownedVaultFileBatchRequest, 0, len(targets))
	for index, target := range targets {
		if !validOwnedVaultFileTarget(target) {
			return nil, ErrVaultFileBaselineVerification
		}
		cp := cloneVaultFileCheckpoint(&target.Checkpoint)
		request := ownedVaultFileBatchRequest{
			journalPath: target.JournalPath,
			checkpoint:  cp,
			options:     target.Options,
			indices:     []int{index},
		}
		found := false
		for i := range out {
			if out[i].journalPath != request.journalPath {
				continue
			}
			if !sameOwnedVaultFileBatchRequest(out[i], request) {
				// A journal path has exactly one registered child. Conflicting
				// requests for that same path are rejected before authentication.
				return nil, ErrVaultFileScopedChild
			}
			out[i].indices = append(out[i].indices, index)
			found = true
			break
		}
		if !found {
			out = append(out, request)
		}
	}
	return out, nil
}

// authenticateVaultFileOwnedTargets authenticates the account state, audit and
// owner custody once for the whole captured target set, then projects only the
// public target snapshots requested. It uses the already verified parent
// material/slot digest and performs no password KDF.
func (s *Session) authenticateVaultFileOwnedTargets(path string, material []byte, slotDigest [32]byte, vaultIDs []string) (map[string]VaultFileOwnershipPublic, error) {
	if s == nil || path == "" || len(material) == 0 || len(vaultIDs) == 0 {
		return nil, errVaultFileChildInvalidSlot
	}
	db, err := existingWithReadOnly(path, true)
	if err != nil {
		return nil, errVaultFileChildInvalidSlot
	}
	verified := &Session{material: material, slotDigest: slotDigest}
	projections := make(map[string]VaultFileOwnershipPublic, len(vaultIDs))
	viewErr := db.View(func(tx *bolt.Tx) error {
		auth, err := authenticateStateItems(tx, "", nil, vaultFileOwnerListAction, verified, false)
		if err != nil {
			return errVaultFileChildInvalidSlot
		}
		defer auth.clear()
		records, err := loadVaultFileOwners(tx.Bucket(bucket), auth.identity, auth.rows)
		if err != nil {
			return errVaultFileChildInvalidSlot
		}
		defer clearVaultFileOwners(records)
		for _, vaultID := range vaultIDs {
			if _, exists := projections[vaultID]; exists {
				continue
			}
			snapshot, err := vaultFileOwnedProjection(records, vaultID)
			switch {
			case errors.Is(err, ErrVaultFileOwnership):
				// Missing target is target-local and is omitted.
			case err != nil:
				return errVaultFileChildInvalidSlot
			default:
				projections[vaultID] = snapshot
			}
		}
		return nil
	})
	closeErr := db.Close()
	if viewErr != nil || closeErr != nil {
		return nil, errVaultFileChildInvalidSlot
	}
	return projections, nil
}

func ownedBatchTargetErrorLocal(err error) bool {
	switch {
	case errors.Is(err, ErrVaultFileOwnership),
		errors.Is(err, ErrVaultFileBaselineJournal),
		errors.Is(err, ErrVaultFileBaselineVerification),
		errors.Is(err, ErrVaultFileScopedChild):
		return true
	default:
		return false
	}
}

func cloneOwnedVaultFileChildItems(items []VaultFileBaselineItem) []VaultFileBaselineItem {
	if len(items) == 0 {
		return nil
	}
	return append([]VaultFileBaselineItem(nil), items...)
}

// UnlockSessionWithOwnedVaultFileChildren performs one complete fresh account
// unlock and constructs a bounded fixed batch of independently owned child
// sessions. Requests are validated, deep-copied and deduplicated before the
// single authentication. The returned parent is unpublished until the batch is
// delivered; any account-level failure, cancellation, common-budget expiry or
// account-level inability to deliver locks and drains only this new parent and
// waits for its children's real Close completion. Existing other sessions and
// siblings are never touched.
func UnlockSessionWithOwnedVaultFileChildren(ctx context.Context, path string, password, key []byte, idle time.Duration, targets []OwnedVaultFileTarget) (*Session, []OwnedVaultFileChildResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if !validSessionIdle(idle) {
		return nil, nil, ErrSessionLocked
	}
	requests, err := prepareOwnedVaultFileBatch(targets)
	if err != nil {
		return nil, nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}

	authStarted := time.Now()
	fullFactorDeadline := authStarted.Add(passkeyTransferFullFactorWindow)
	parent, err := UnlockSession(path, password, key, idle)
	if err != nil {
		return nil, nil, err
	}
	results := make([]OwnedVaultFileChildResult, len(targets))
	for i := range results {
		results[i].Index = i
	}
	drainWith := func(current []VaultFileBaselineItem, err error) (*Session, []OwnedVaultFileChildResult, error) {
		if vaultFileOwnedBatchUndeliveredForTest != nil {
			accumulated := make([][]VaultFileBaselineItem, len(results))
			for i := range results {
				accumulated[i] = results[i].Items
			}
			vaultFileOwnedBatchUndeliveredForTest(current, accumulated)
		}
		clearVaultFileChildItems(current)
		clearOwnedVaultFileBatchResults(results)
		parent.Lock()
		return nil, nil, err
	}
	drain := func(err error) (*Session, []OwnedVaultFileChildResult, error) {
		return drainWith(nil, err)
	}
	if vaultFileOwnedBatchAuthForTest != nil {
		vaultFileOwnedBatchAuthForTest()
	}
	if err := ctx.Err(); err != nil {
		return drain(err)
	}
	if !time.Now().Before(fullFactorDeadline) {
		return drain(context.DeadlineExceeded)
	}

	parent.mu.Lock()
	if err := parent.active(false); err != nil {
		parent.mu.Unlock()
		return drain(err)
	}
	parentOwner := parent.vaultFileOwner
	parentMaterial := parent.material
	parentSlot := parent.slotDigest
	parentPath := parent.path
	idleDeadline, hasIdle := parent.idleDeadline()
	parent.mu.Unlock()
	if parentOwner == nil || len(parentMaterial) == 0 {
		return drain(ErrSessionLocked)
	}

	var snapshots map[string]VaultFileOwnershipPublic
	if len(requests) > 0 {
		vaultIDs := make([]string, 0, len(requests))
		for _, request := range requests {
			vaultIDs = append(vaultIDs, request.checkpoint.VaultID)
		}
		snapshots, err = parent.authenticateVaultFileOwnedTargets(parentPath, parentMaterial, parentSlot, vaultIDs)
		if err != nil {
			return drain(err)
		}
	}
	if err := ctx.Err(); err != nil {
		return drain(err)
	}
	if !time.Now().Before(fullFactorDeadline) {
		return drain(context.DeadlineExceeded)
	}

	batch := &vaultFileOwnedBatchAuth{
		parentOwner:        parentOwner,
		parentMaterial:     parentMaterial,
		parentSlot:         parentSlot,
		parentPath:         parentPath,
		idleDeadline:       idleDeadline,
		hasIdle:            hasIdle,
		fullFactorDeadline: fullFactorDeadline,
		snapshots:          snapshots,
	}
	for _, request := range requests {
		if err := ctx.Err(); err != nil {
			return drain(err)
		}
		if !time.Now().Before(fullFactorDeadline) {
			return drain(context.DeadlineExceeded)
		}
		token, items, openErr := parent.openVaultFileChild(request.journalPath, &request.checkpoint, nil, nil, request.options, vaultFileChildOpenMode{owned: true, batch: batch})
		if err := ctx.Err(); err != nil {
			return drainWith(items, err)
		}
		if !time.Now().Before(fullFactorDeadline) {
			return drainWith(items, context.DeadlineExceeded)
		}
		if openErr != nil {
			clearVaultFileChildItems(items)
			if !ownedBatchTargetErrorLocal(openErr) {
				return drain(openErr)
			}
			for _, index := range request.indices {
				results[index].Err = openErr
			}
			continue
		}
		for _, index := range request.indices {
			results[index].Index = index
			results[index].Token = token
			results[index].Items = cloneOwnedVaultFileChildItems(items)
		}
		clearVaultFileChildItems(items)
	}
	// Delivery boundary: a valid account remains deliverable even when every
	// target failed locally or the target set was empty. This recheck does not
	// touch or refresh proof/idle timestamps.
	if err := ctx.Err(); err != nil {
		return drain(err)
	}
	if !time.Now().Before(fullFactorDeadline) {
		return drain(context.DeadlineExceeded)
	}
	parent.mu.Lock()
	activeErr := parent.active(false)
	parent.mu.Unlock()
	if activeErr != nil {
		return drain(activeErr)
	}
	return parent, results, nil
}
