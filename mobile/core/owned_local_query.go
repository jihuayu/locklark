package mobilecore

import (
	"errors"
	"path/filepath"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/vaultfileclient"
)

// OwnedLocalExactHit is one bounded exact-title metadata hit. It carries only
// the opaque item selector and the already exact title; it is never a grant,
// item revision or proof of a current backend.
type OwnedLocalExactHit struct {
	ID    string
	Title string
}

// OwnedLocalExactResult is the bounded metadata result of one transient read
// over one explicit owned local vault child.
//
// VaultID identifies that independent vault. BackendRevision is the opaque
// backend equality token observed for this read only; it is not an item
// revision, a monotonic version or a durable ordering. Comparing it for
// equality is the only supported use. No config/workspace/journal path, key,
// token, proof or raw item value is exposed.
type OwnedLocalExactResult struct {
	VaultID         string
	BackendRevision string
	Truncated       bool
	hits            []OwnedLocalExactHit
}

func (r *OwnedLocalExactResult) Count() int {
	if r == nil {
		return 0
	}
	return len(r.hits)
}

func (r *OwnedLocalExactResult) At(index int) (*OwnedLocalExactHit, error) {
	if r == nil || index < 0 || index >= len(r.hits) {
		return nil, errInvalid
	}
	hit := r.hits[index]
	return &hit, nil
}

// SearchOwnedLocalExact reads one explicit owned local independent vault in
// the already active personal account. workspaceRoot, configPath and
// journalPath must be native-app-owned absolute clean paths; vaultID must be
// that config's independent vault ID. title and limit use the established
// exact-query bounds (1..64 hits, at most 512 title bytes).
//
// password and secretKey are the complete factors and are consumed and
// cleared by this call on every path. The call opens one transient owned child
// through the existing pinned constructor, performs one exact-title query over
// authenticated current bytes and the opaque backend revision, then closes
// that exact child before the final in-memory epoch grant. It never writes,
// repairs, falls back to a journal cache or reads an arbitrary backend blob.
func (v *Vault) SearchOwnedLocalExact(workspaceRoot, configPath, vaultID, journalPath, title string, limit int, password, secretKey []byte) (*OwnedLocalExactResult, error) {
	defer clear(password)
	defer clear(secretKey)

	if !ownedLocalPath(workspaceRoot) || !ownedLocalPath(configPath) ||
		!ownedLocalPath(journalPath) || vaultID == "" ||
		title == "" || len([]byte(title)) > vaultfileclient.LocalGenesisExactQueryTitleBytesMax ||
		limit < 1 || limit > vaultfileclient.LocalGenesisExactQueryHitsMax {
		return nil, errInvalid
	}

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

	child, _, e := vaultfileclient.OpenLocalGenesisSessionForJournal(
		s, configPath, workspaceRoot, vaultID, journalPath, password, secretKey)
	if e != nil {
		return nil, sanitizedOwnedLocalExact(e)
	}
	if child == nil {
		return nil, errUnavailable
	}

	closed := false
	defer func() {
		if !closed {
			_ = child.Close()
		}
	}()

	raw, queryErr := child.QueryExactTitle(vaultfileclient.LocalGenesisExactQuery{Title: title, Limit: limit})
	// The exact child must be closed before the delivery gate, including when
	// the query failed. Siblings and the parent Session are not locked here.
	closed = true
	closeErr := child.Close()
	if queryErr != nil {
		return nil, sanitizedOwnedLocalExact(queryErr)
	}
	if closeErr != nil {
		return nil, sanitized(closeErr)
	}

	if raw.VaultID != vaultID || raw.JournalRevision == "" ||
		len(raw.Hits) > limit ||
		len(raw.Hits) > vaultfileclient.LocalGenesisExactQueryHitsMax {
		return nil, errInvalid
	}
	out := &OwnedLocalExactResult{
		VaultID:         raw.VaultID,
		BackendRevision: raw.JournalRevision,
		Truncated:       raw.Truncated,
		hits:            make([]OwnedLocalExactHit, 0, len(raw.Hits)),
	}
	for _, hit := range raw.Hits {
		if hit.ID == "" || hit.Title != title {
			return nil, errInvalid
		}
		out.hits = append(out.hits, OwnedLocalExactHit{ID: hit.ID, Title: hit.Title})
	}
	clearOwnedLocalRawHits(raw.Hits)

	// No authoritative read occurs after this short final grant. RequestLock
	// shares this mutex, so a stale captured view cannot reveal this result.
	if ownedLocalBeforeGrantForTest != nil {
		ownedLocalBeforeGrantForTest()
	}
	if !v.grantOwnedLocalExact(s, epoch) {
		return nil, errLocked
	}
	return out, nil
}

// ownedLocalBeforeGrantForTest is nil in production. Tests use it to stop one
// worker exactly after the real child close and before the final grant, without
// receiving factors, paths, metadata or a capability.
var ownedLocalBeforeGrantForTest func()

func (v *Vault) grantOwnedLocalExact(s *personal.Session, epoch uint64) bool {
	if !v.ready() {
		return false
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed || v.epoch != epoch || v.session != s ||
		(v.bound && v.expectedEpoch != epoch) {
		return false
	}
	return s.Unlocked()
}

func ownedLocalPath(value string) bool {
	return value != "" && filepath.IsAbs(value) && filepath.Clean(value) == value
}

func sanitizedOwnedLocalExact(e error) error {
	switch {
	case e == nil:
		return nil
	case errors.Is(e, personal.ErrSessionLocked):
		return errLocked
	case errors.Is(e, personal.ErrMutationCancelled):
		return errCancelled
	case errors.Is(e, vaultfileclient.ErrLocalGenesisExactQueryBound),
		errors.Is(e, vaultfileclient.ErrLocalReview),
		errors.Is(e, personal.ErrVaultFileScopedFactors),
		errors.Is(e, personal.ErrVaultFileScopedChild),
		errors.Is(e, personal.ErrVaultFileOwnership),
		errors.Is(e, personal.ErrVaultFileBaselineJournal),
		errors.Is(e, personal.ErrVaultFileBaselineVerification),
		errors.Is(e, personal.ErrVaultFileFullFactorRequired):
		return errInvalid
	default:
		return sanitized(e)
	}
}

func clearOwnedLocalRawHits(hits []personal.VaultFileBaselineItem) {
	for i := range hits {
		hits[i] = personal.VaultFileBaselineItem{}
	}
}
