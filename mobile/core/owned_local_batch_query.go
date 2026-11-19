package mobilecore

import (
	"errors"
	"sync"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/vaultfileclient"
)

const (
	ownedLocalExactBatchPathMax    = 4096
	ownedLocalExactBatchVaultIDMax = 128
)

// Bounded per-target status values. The literals are stable because native
// bindings consume strings, not Go constants.
const (
	// OwnedLocalExactStatusOK means the target was read successfully. Count()
	// may still be zero: that is a successful query with no exact-title hits.
	OwnedLocalExactStatusOK = "ok"
	// OwnedLocalExactStatusRefused means that target's locator, ownership,
	// factors or verified bytes/revision were refused. It grants nothing.
	OwnedLocalExactStatusRefused = "refused"
	// OwnedLocalExactStatusUnavailable means the target's authenticated local
	// storage could not be observed. It grants nothing.
	OwnedLocalExactStatusUnavailable = "unavailable"
)

// OwnedLocalExactTargets is a bounded, mutable list of explicit native-owned
// targets for one aggregate exact-title query. All targets share the
// workspaceRoot supplied to SearchOwnedLocalExactBatch. Add deep-copies plain
// selectors only; it never accepts a path-free, vault-ID-only or foreign
// authority claim. The list is snapshotted at the start of a query, so adding
// more targets later cannot change that query.
type OwnedLocalExactTargets struct {
	mu      sync.Mutex
	targets []ownedLocalExactTarget
}

type ownedLocalExactTarget struct {
	configPath  string
	vaultID     string
	journalPath string
}

// NewOwnedLocalExactTargets returns an empty bounded target list. A zero-value
// OwnedLocalExactTargets is also usable.
func NewOwnedLocalExactTargets() *OwnedLocalExactTargets {
	return &OwnedLocalExactTargets{}
}

// Add appends one explicit config/vault/journal locator. configPath and
// journalPath must be absolute and clean; vaultID must be non-empty. The
// already-named local path and vault-ID bounds apply. Add rejects a malformed
// target and an over-capacity list without partially appending. Exact duplicate
// locators are accepted and collapse to one read; differing locators that share
// a config path, journal path or vault ID are marked as conflicts during the
// query, not silently aliased.
func (t *OwnedLocalExactTargets) Add(configPath, vaultID, journalPath string) error {
	if t == nil || !ownedLocalExactBatchPath(configPath) ||
		!ownedLocalExactBatchPath(journalPath) || vaultID == "" ||
		len(vaultID) > ownedLocalExactBatchVaultIDMax {
		return errInvalid
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.targets) >= vaultfileclient.MaxLocalGenesisBatchTargets {
		return errInvalid
	}
	t.targets = append(t.targets, ownedLocalExactTarget{
		configPath:  configPath,
		vaultID:     vaultID,
		journalPath: journalPath,
	})
	return nil
}

// Count reports the number of targets currently added.
func (t *OwnedLocalExactTargets) Count() int {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.targets)
}

func (t *OwnedLocalExactTargets) snapshot() ([]ownedLocalExactTarget, bool) {
	if t == nil {
		return nil, false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.targets) == 0 || len(t.targets) > vaultfileclient.MaxLocalGenesisBatchTargets {
		return nil, false
	}
	out := make([]ownedLocalExactTarget, len(t.targets))
	copy(out, t.targets)
	return out, true
}

func ownedLocalExactBatchPath(value string) bool {
	return ownedLocalPath(value) && len(value) <= ownedLocalExactBatchPathMax
}

func clearOwnedLocalExactTargets(targets []ownedLocalExactTarget) {
	for index := range targets {
		targets[index] = ownedLocalExactTarget{}
	}
}

// clearOwnedLocalExactBatchEntries drops every staged metadata reference from
// an aggregate that has not reached its successful epoch handoff. Hit elements
// are cleared before their slot is zeroed, so duplicate slots that share an
// internal slice are handled consistently. Go string storage is immutable, so
// only the slice and struct references can be dropped, not their bytes.
func clearOwnedLocalExactBatchEntries(entries []OwnedLocalExactBatchEntry) {
	for index := range entries {
		hits := entries[index].hits
		for hit := range hits {
			hits[hit] = OwnedLocalExactHit{}
		}
		entries[index] = OwnedLocalExactBatchEntry{}
	}
}

// OwnedLocalExactBatchEntry is one immutable original-index result slot. Status
// is one of the bounded OwnedLocalExactStatus literals. VaultID is the bounded
// target selector supplied by the caller; it is not authority. On a refused or
// unavailable target, BackendRevision is empty, Truncated is false and Count is
// zero. On status ok, BackendRevision is the opaque backend equality token for
// that target's independent read only; it is not an item revision, a durable
// ordering or an atomically consistent snapshot across targets.
type OwnedLocalExactBatchEntry struct {
	VaultID         string
	Status          string
	BackendRevision string
	Truncated       bool
	hits            []OwnedLocalExactHit
}

// Count reports the bounded number of exact-title hits for this target. Zero
// with status ok is a successful zero-hit query, not a target failure.
func (e *OwnedLocalExactBatchEntry) Count() int {
	if e == nil {
		return 0
	}
	return len(e.hits)
}

func (e *OwnedLocalExactBatchEntry) At(index int) (*OwnedLocalExactHit, error) {
	if e == nil || index < 0 || index >= len(e.hits) {
		return nil, errInvalid
	}
	hit := e.hits[index]
	return &hit, nil
}

// OwnedLocalExactBatchResult is the deterministic result list for one aggregate
// exact-title query. Entries preserve the target list's original order. An
// aggregate error is returned instead of this value when the operation itself
// lost the account/epoch or a transient child close could not be confirmed, so
// no partial per-target result escapes a global failure.
type OwnedLocalExactBatchResult struct {
	entries []OwnedLocalExactBatchEntry
}

func (r *OwnedLocalExactBatchResult) Count() int {
	if r == nil {
		return 0
	}
	return len(r.entries)
}

func (r *OwnedLocalExactBatchResult) At(index int) (*OwnedLocalExactBatchEntry, error) {
	if r == nil || index < 0 || index >= len(r.entries) {
		return nil, errInvalid
	}
	entry := r.entries[index]
	return &entry, nil
}

type ownedLocalExactBatchGroup struct {
	locator  ownedLocalExactTarget
	indices  []int
	conflict bool
}

// ownedLocalExactBatchGroups collapses exact duplicates and marks every group
// that shares a config path, journal path or vault ID with a different locator.
// The returned order is first occurrence, which keeps reads deterministic.
func ownedLocalExactBatchGroups(targets []ownedLocalExactTarget) []*ownedLocalExactBatchGroup {
	byLocator := make(map[ownedLocalExactTarget]*ownedLocalExactBatchGroup)
	groups := make([]*ownedLocalExactBatchGroup, 0, len(targets))
	for index, target := range targets {
		group := byLocator[target]
		if group == nil {
			group = &ownedLocalExactBatchGroup{locator: target}
			byLocator[target] = group
			groups = append(groups, group)
		}
		group.indices = append(group.indices, index)
	}

	byConfig := make(map[string][]*ownedLocalExactBatchGroup)
	byJournal := make(map[string][]*ownedLocalExactBatchGroup)
	byVaultID := make(map[string][]*ownedLocalExactBatchGroup)
	for _, group := range groups {
		byConfig[group.locator.configPath] = append(byConfig[group.locator.configPath], group)
		byJournal[group.locator.journalPath] = append(byJournal[group.locator.journalPath], group)
		byVaultID[group.locator.vaultID] = append(byVaultID[group.locator.vaultID], group)
	}
	markConflicts := func(list []*ownedLocalExactBatchGroup) {
		if len(list) < 2 {
			return
		}
		for _, group := range list {
			group.conflict = true
		}
	}
	for _, list := range byConfig {
		markConflicts(list)
	}
	for _, list := range byJournal {
		markConflicts(list)
	}
	for _, list := range byVaultID {
		markConflicts(list)
	}
	return groups
}

func setOwnedLocalExactBatchStatus(entries []OwnedLocalExactBatchEntry, indices []int, status string) {
	for _, index := range indices {
		entries[index].Status = status
		entries[index].BackendRevision = ""
		entries[index].Truncated = false
		entries[index].hits = nil
	}
}

func ownedLocalExactTargetStatus(e error) (string, bool) {
	switch {
	case errors.Is(e, errInvalid):
		return OwnedLocalExactStatusRefused, true
	case errors.Is(e, errUnavailable):
		return OwnedLocalExactStatusUnavailable, true
	default:
		return "", false
	}
}

func (v *Vault) ownedLocalAccountCurrent(s *personal.Session, epoch uint64) bool {
	return v.current(s, epoch) && s.Unlocked()
}

// SearchOwnedLocalExactBatch performs one bounded exact-title aggregate over
// multiple explicit target-only owned local children inside the currently
// active mobile Vault operation. All targets must belong to workspaceRoot and
// the already active personal account. The method reuses the single query's
// exact account/session/epoch, factor policy, pinned locator/manifest/companion/
// journal validation and independently verified named-backend bytes/revision;
// it never performs a second account unlock, writes, repairs, adopts remote
// state, or returns paths, factors, keys, tokens or trust evidence.
//
// The target list is snapshotted in original order. Exact duplicates collapse
// to one read but still receive one entry per original index. Differing
// locators that share a config path, journal path or vault ID are conflicts:
// all involved entries report refused without opening a child. Other
// target-local failures report the bounded refused/unavailable status and never
// affect a valid sibling. Each target opens, queries and closes exactly one
// transient child before the next target, and a target whose exact journal
// already has a registered child is refused without replacing or closing it.
// Per-target metadata is not granted until every opened child has closed and
// the same account/epoch passes the one final grant. RequestLock, account disappearance, cancellation or an
// unconfirmed child close therefore returns no aggregate at all. Each entry's
// BackendRevision is observed independently; this is not an atomically
// consistent cross-backend snapshot.
//
// password and secretKey are the complete factors, used for every target's
// existing owned-child factor proof and consumed and cleared by this call on
// every path. title and limit use the established exact-query bounds (1..64
// hits per target, at most 512 title bytes).
func (v *Vault) SearchOwnedLocalExactBatch(workspaceRoot, title string, limit int, targets *OwnedLocalExactTargets, password, secretKey []byte) (*OwnedLocalExactBatchResult, error) {
	defer clear(password)
	defer clear(secretKey)

	list, ok := targets.snapshot()
	if !ok || !ownedLocalExactBatchPath(workspaceRoot) ||
		title == "" || len([]byte(title)) > vaultfileclient.LocalGenesisExactQueryTitleBytesMax ||
		limit < 1 || limit > vaultfileclient.LocalGenesisExactQueryHitsMax {
		return nil, errInvalid
	}
	defer clearOwnedLocalExactTargets(list)

	epoch, e := v.enterOperation()
	if e != nil {
		return nil, e
	}
	defer v.op.Unlock()

	s, activeEpoch, e := v.active()
	if e != nil {
		return nil, e
	}
	if activeEpoch != epoch {
		return nil, errCancelled
	}

	groups := ownedLocalExactBatchGroups(list)
	entries := make([]OwnedLocalExactBatchEntry, len(list))
	for index := range entries {
		entries[index].VaultID = list[index].vaultID
	}
	// Every exit before the final successful epoch handoff drops the staged
	// vault IDs, revisions, hit IDs and titles; only the delivered result may
	// keep those copies reachable.
	delivered := false
	defer func() {
		if !delivered {
			clearOwnedLocalExactBatchEntries(entries)
		}
	}()

	for _, group := range groups {
		// Stop before another open when the exact account generation vanished.
		if !v.ownedLocalAccountCurrent(s, epoch) {
			return nil, errLocked
		}
		if group.conflict {
			setOwnedLocalExactBatchStatus(entries, group.indices, OwnedLocalExactStatusRefused)
			continue
		}

		read, targetErr, closeErr := readOwnedLocalExactTarget(s, workspaceRoot,
			group.locator.configPath, group.locator.vaultID, group.locator.journalPath,
			title, limit, true, password, secretKey)
		if closeErr != nil {
			// A close that cannot be confirmed withholds the whole aggregate:
			// no target result may escape while a transient child is uncertain.
			return nil, closeErr
		}
		if targetErr != nil {
			if !v.ownedLocalAccountCurrent(s, epoch) {
				return nil, errLocked
			}
			status, known := ownedLocalExactTargetStatus(targetErr)
			if !known {
				return nil, targetErr
			}
			setOwnedLocalExactBatchStatus(entries, group.indices, status)
			continue
		}
		if read == nil {
			return nil, errUnavailable
		}
		for _, index := range group.indices {
			entries[index].VaultID = read.vaultID
			entries[index].Status = OwnedLocalExactStatusOK
			entries[index].BackendRevision = read.backendRevision
			entries[index].Truncated = read.truncated
			entries[index].hits = append([]OwnedLocalExactHit(nil), read.hits...)
		}
	}

	// No authoritative read occurs after this short final grant. RequestLock
	// shares this mutex, so a stale captured view cannot reveal any entry.
	if ownedLocalBeforeGrantForTest != nil {
		ownedLocalBeforeGrantForTest()
	}
	if !v.grantOwnedLocalExact(s, epoch) {
		return nil, errLocked
	}
	delivered = true
	return &OwnedLocalExactBatchResult{entries: entries}, nil
}
