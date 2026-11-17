package vaultfileclient

import (
	"errors"

	"github.com/jihuayu/locklark/internal/personal"
)

const (
	// LocalGenesisExactQueryTitleBytesMax bounds the exact selector accepted by
	// one query.
	LocalGenesisExactQueryTitleBytesMax = 512
	// LocalGenesisExactQueryHitsMax bounds disclosed matching items.
	LocalGenesisExactQueryHitsMax = 64
	// LocalGenesisExactQueryScanItemsMax bounds the post-read projection work.
	LocalGenesisExactQueryScanItemsMax = 4096
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
}

// QueryExactTitle reads exact-title item summaries from an already opened
// local-genesis child. It reuses personal.Session.ReadVaultFileChild and the
// existing owned-child ownership revalidation. A locator, journal, parent,
// child or ownership failure is terminal for only this wrapper and closes only
// this child; siblings and the parent remain untouched. Oversized selectors,
// limits or projections return ErrLocalGenesisExactQueryBound without closing
// a healthy child.
func (l *LocalGenesisSession) QueryExactTitle(query LocalGenesisExactQuery) (LocalGenesisExactQueryResult, error) {
	empty := LocalGenesisExactQueryResult{}
	if l == nil || l.state == nil {
		return empty, ErrLocalReview
	}
	return l.state.queryExactTitle(query)
}

func (s *localGenesisSessionState) queryExactTitle(query LocalGenesisExactQuery) (LocalGenesisExactQueryResult, error) {
	empty := LocalGenesisExactQueryResult{}
	if query.Title == "" || len([]byte(query.Title)) > LocalGenesisExactQueryTitleBytesMax ||
		query.Limit < 1 || query.Limit > LocalGenesisExactQueryHitsMax {
		return empty, ErrLocalGenesisExactQueryBound
	}

	s.mu.Lock()
	if s.closed || s.parent == nil {
		s.mu.Unlock()
		return empty, ErrLocalReview
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
		Hits:            make([]personal.VaultFileBaselineItem, 0, query.Limit),
	}
	s.mu.Unlock()

	if err := s.revalidateLocator(); err != nil {
		_ = s.close()
		return empty, err
	}
	items, err := parent.ReadVaultFileChild(token, personal.VaultFileChildOptions{IncludeItemIDs: true})
	if err != nil {
		_ = s.close()
		return empty, err
	}
	if localGenesisExactQueryProjectionForTest != nil {
		clearLocalGenesisItems(items)
		items = localGenesisExactQueryProjectionForTest()
	}
	if len(items) > LocalGenesisExactQueryScanItemsMax {
		clearLocalGenesisItems(items)
		return empty, ErrLocalGenesisExactQueryBound
	}

	if localGenesisSummaryReadyForTest != nil {
		localGenesisSummaryReadyForTest()
	}

	if err := s.revalidateLocator(); err != nil {
		clearLocalGenesisItems(items)
		_ = s.close()
		return empty, err
	}
	if err := parent.RevalidateVaultFileChildOwnership(token); err != nil {
		clearLocalGenesisItems(items)
		_ = s.close()
		return empty, err
	}
	if err := s.revalidateLocator(); err != nil {
		clearLocalGenesisItems(items)
		_ = s.close()
		return empty, err
	}

	s.mu.Lock()
	open := !s.closed && s.token == token
	s.mu.Unlock()
	if !open {
		clearLocalGenesisItems(items)
		return empty, ErrLocalReview
	}

	hits := scope.Hits
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
