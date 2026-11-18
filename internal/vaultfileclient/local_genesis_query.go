package vaultfileclient

import (
	"errors"
	"slices"
	"weak"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/vault"
)

const (
	// LocalGenesisExactQueryTitleBytesMax bounds the exact selector accepted by
	// one query.
	LocalGenesisExactQueryTitleBytesMax = 512
	// LocalGenesisExactQueryHitsMax bounds disclosed matching items.
	LocalGenesisExactQueryHitsMax = 64
	// LocalGenesisExactQueryScanItemsMax bounds the summaries scanned per query.
	LocalGenesisExactQueryScanItemsMax = vault.MaxItems
)

// ErrLocalGenesisExactQueryBound rejects an oversized selector, limit or
// projection. It never closes an otherwise current child.
var ErrLocalGenesisExactQueryBound = errors.New("local genesis exact query bound rejected")

// localGenesisExactQueryProjectionForTest is a parameterless private seam. It
// is nil in production. Tests use it to replace only the post-read synthetic
// item projection after the real owned-child read/ownership check has already
// run; it receives no factor, key, token, handle or capability.
var localGenesisExactQueryProjectionForTest func() []personal.VaultFileBaselineItem

// LocalGenesisExactQuery is one bounded, exact-title read over an already
// opened local-genesis child. It is not a generic personal search and grants no
// account, workspace or VaultRef authority.
type LocalGenesisExactQuery struct {
	Title string
	Limit int
}

// LocalGenesisExactQueryResult binds matching item summaries to the exact
// frozen local child scope that produced them. ConfigPath, WorkspaceRoot,
// VaultID, JournalPath, ManifestSHA256 and JournalRevision let the caller
// dispatch by exact scope rather than by name. Hits contain only the existing
// public baseline fields, including the item selector when present. No key,
// token, handle or account material is exposed.
type LocalGenesisExactQueryResult struct {
	ConfigPath      string
	WorkspaceRoot   string
	VaultID         string
	JournalPath     string
	ManifestSHA256  string
	JournalRevision string
	Hits            []personal.VaultFileBaselineItem
	Truncated       bool

	activation *localGenesisExactQueryActivation
}

// localGenesisExactQueryBinding is the locator and vault version at query time.
type localGenesisExactQueryBinding struct {
	configPath      string
	workspaceRoot   string
	vaultID         string
	journalPath     string
	manifestSHA256  string
	journalRevision string
}

func (r LocalGenesisExactQueryResult) binding() localGenesisExactQueryBinding {
	return localGenesisExactQueryBinding{
		configPath:      r.ConfigPath,
		workspaceRoot:   r.WorkspaceRoot,
		vaultID:         r.VaultID,
		journalPath:     r.JournalPath,
		manifestSHA256:  r.ManifestSHA256,
		journalRevision: r.JournalRevision,
	}
}

type localGenesisExactQueryHit struct {
	id    string
	title string
}

type localGenesisExactQueryActivation struct {
	receiver  weak.Pointer[LocalGenesisSession]
	binding   localGenesisExactQueryBinding
	hits      []localGenesisExactQueryHit
	truncated bool
}

// QueryExactTitle returns exact-title matches from the receiver's verified
// child. The item database enforces the item limit during the child read.
// The query checks the returned summaries against the same limit before scanning.
//
// Invalid query bounds and oversized projections return
// ErrLocalGenesisExactQueryBound without closing the child.
func (l *LocalGenesisSession) QueryExactTitle(query LocalGenesisExactQuery) (LocalGenesisExactQueryResult, error) {
	empty := LocalGenesisExactQueryResult{}
	if l == nil || l.state == nil {
		return empty, ErrLocalReview
	}
	result, err := l.state.queryExactTitle(query)
	if err != nil || len(result.Hits) == 0 {
		return result, err
	}
	proof := &localGenesisExactQueryActivation{
		receiver:  weak.Make(l),
		binding:   result.binding(),
		hits:      make([]localGenesisExactQueryHit, 0, len(result.Hits)),
		truncated: result.Truncated,
	}
	for _, item := range result.Hits {
		proof.hits = append(proof.hits, localGenesisExactQueryHit{id: item.ID, title: item.Title})
	}
	result.activation = proof
	return result, nil

}

// ValidateExactQueryHit checks whether the exact receiver can still read the
// original query hit with the same locator and vault version. The exported Hits
// slice is presentation data. Membership comes from an immutable private copy
// of the original ID and title pairs returned to the caller.
// A nil error describes this verified read and does not reserve the child or
// grant permission for a later operation. Callers must also check their own
// selection and session lifetimes before using the result.
func (l *LocalGenesisSession) ValidateExactQueryHit(result LocalGenesisExactQueryResult, itemID, title string) error {
	proof := result.activation
	hit := localGenesisExactQueryHit{id: itemID, title: title}
	if l == nil || l.state == nil || proof == nil || proof.receiver != weak.Make(l) ||
		result.binding() != proof.binding || result.Truncated != proof.truncated ||
		itemID == "" || !slices.Contains(proof.hits, hit) {
		return ErrLocalReview
	}

	current, items, err := l.state.readExactQueryItems()
	if err != nil {
		return err
	}
	defer clearLocalGenesisItems(items)
	if current.binding() != proof.binding {
		return ErrLocalReview
	}
	for _, item := range items {
		if item.ID == itemID && item.Title == title {
			return nil
		}
	}
	return ErrLocalReview
}

func (s *localGenesisSessionState) queryExactTitle(query LocalGenesisExactQuery) (LocalGenesisExactQueryResult, error) {
	empty := LocalGenesisExactQueryResult{}
	if query.Title == "" || len([]byte(query.Title)) > LocalGenesisExactQueryTitleBytesMax ||
		query.Limit < 1 || query.Limit > LocalGenesisExactQueryHitsMax {
		return empty, ErrLocalGenesisExactQueryBound
	}

	scope, items, err := s.readExactQueryItems()
	if err != nil {
		return empty, err
	}

	hits := make([]personal.VaultFileBaselineItem, 0, query.Limit)
	truncated := false
	for _, item := range items {
		if item.Title != query.Title {
			continue
		}
		if len(hits) == query.Limit {
			truncated = true
			break
		}
		hits = append(hits, item)
	}
	clearLocalGenesisItems(items)
	scope.Hits = hits
	scope.Truncated = truncated
	return scope, nil
}

func (s *localGenesisSessionState) readExactQueryItems() (LocalGenesisExactQueryResult, []personal.VaultFileBaselineItem, error) {
	empty := LocalGenesisExactQueryResult{}

	s.mu.Lock()
	if s.closed || s.parent == nil {
		s.mu.Unlock()
		return empty, nil, ErrLocalReview
	}
	parent := s.parent
	token := s.token
	scope := LocalGenesisExactQueryResult{
		ConfigPath:      s.configPath,
		WorkspaceRoot:   s.manifest.BackendRoot,
		VaultID:         s.manifest.VaultID,
		JournalPath:     s.manifest.Journal,
		ManifestSHA256:  s.manifestSHA256,
		JournalRevision: s.revision,
	}
	s.mu.Unlock()

	if err := s.revalidateLocator(); err != nil {
		_ = s.close()
		return empty, nil, err
	}
	items, err := parent.ReadVaultFileChild(token, personal.VaultFileChildOptions{IncludeItemIDs: true})
	if err != nil {
		_ = s.close()
		return empty, nil, err
	}
	if localGenesisExactQueryProjectionForTest != nil {
		clearLocalGenesisItems(items)
		items = localGenesisExactQueryProjectionForTest()
	}
	if len(items) > LocalGenesisExactQueryScanItemsMax {
		clearLocalGenesisItems(items)
		return empty, nil, ErrLocalGenesisExactQueryBound
	}

	if localGenesisSummaryReadyForTest != nil {
		localGenesisSummaryReadyForTest()
	}

	if err := s.revalidateLocator(); err != nil {
		clearLocalGenesisItems(items)
		_ = s.close()
		return empty, nil, err
	}
	if err := parent.RevalidateVaultFileChildOwnership(token); err != nil {
		clearLocalGenesisItems(items)
		_ = s.close()
		return empty, nil, err
	}
	if err := s.revalidateLocator(); err != nil {
		clearLocalGenesisItems(items)
		_ = s.close()
		return empty, nil, err
	}

	s.mu.Lock()
	open := !s.closed && s.token == token
	s.mu.Unlock()
	if !open {
		clearLocalGenesisItems(items)
		return empty, nil, ErrLocalReview
	}

	return scope, items, nil
}
