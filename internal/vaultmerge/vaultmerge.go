// Package vaultmerge is the conservative three-way item merge core for the
// vault-file work.
//
// Merge takes a common base branch and the local and remote branches derived
// from it and returns either merged items or, per identifier, an explicit
// conflict that preserves both complete sides. It is a pure in-memory package:
// it performs no cryptography, KDBX Seal/Open, decoding, encryption, journaling,
// network access or product integration.
//
// Items are indexed by exact, case-sensitive vault.Item.ID and never by title.
// For each identifier only three whole-item rules are used:
//
//   - L == R: keep that value (or omit the identifier when both are absent);
//   - L == B: keep R;
//   - R == B: keep L;
//   - otherwise: report a conflict carrying deep copies of B, L and R.
//
// Whole-item equality is deliberate: fields are never merged individually,
// and UpdatedAt/TrashedAt timestamps or wall-clock last-writer-wins are never
// used to choose a side. Any same-identifier edit on both sides, addition
// collision, delete-versus-edit, attachment change combined with an edit, or
// sensitive-field combination is therefore a conflict that preserves every
// side in full. A nil side of a conflict means the identifier is absent from
// that branch.
//
// Trust boundary. Branch.KeyEpoch is caller-declared metadata only; the
// package does not authenticate it, does not bind branches to a key, and does
// not verify signatures or envelopes. Callers must validate and authenticate
// the branches and confirm that local and remote policy, member and role state
// match and are unchanged before calling Merge, and must apply the result only
// to a target whose policy is unchanged. This API has no policy fields and does
// not authorize membership, roles or policy transitions of any kind.
//
// Ownership. Every returned item and conflict side is a deep copy, including
// byte slices, nested slices, pointers (AutoSubmit, TrashedAt, CreditCard,
// Identity), passkey collections, section and history data, and attachment
// content. Inputs are never modified and no returned slice or pointer aliases
// input memory. vault.Item currently has no map fields; none are claimed.
package vaultmerge

import (
	"errors"
	"sort"

	"github.com/jihuayu/locklark/internal/vault"
)

var (
	// ErrMissingBase reports a nil base branch. An empty but non-nil base is
	// valid.
	ErrMissingBase = errors.New("vaultmerge: missing base branch")
	// ErrKeyEpoch reports a zero branch key epoch or key epochs that differ
	// between the base, local and remote branches.
	ErrKeyEpoch = errors.New("vaultmerge: branch key epochs do not match")
	// ErrEmptyID reports an item whose ID is empty on any branch.
	ErrEmptyID = errors.New("vaultmerge: item ID is empty")
	// ErrIDTooLong reports an item ID longer than the vault model's
	// maxIDLength, the same bound used when persisting an item snapshot.
	ErrIDTooLong = errors.New("vaultmerge: item ID exceeds model limit")
	// ErrDuplicateID reports the same exact ID twice on one branch.
	ErrDuplicateID = errors.New("vaultmerge: duplicate item ID on one branch")
	// ErrTooManyItems reports a branch with more than vault.MaxItems items, or
	// a merged result that would exceed vault.MaxItems and could not be
	// persisted. In both cases the result is zero.
	ErrTooManyItems = errors.New("vaultmerge: item count exceeds limit")
)

// maxIDLength is the strict model limit enforced by vault.validItems when an
// item snapshot is persisted.
const maxIDLength = 256

// Branch is one side of a three-way merge. KeyEpoch is caller-declared and is
// not authenticated by this package.
type Branch struct {
	KeyEpoch uint64
	Items    []vault.Item
}

// Conflict records one identifier that changed differently on both sides.
// Each present side is a deep copy of that branch's complete item; a nil side
// means the identifier is absent from that branch.
type Conflict struct {
	ID    string
	Base  *vault.Item
	Local *vault.Item
	// Remote is the remote side's item, or nil when the remote branch lacks
	// the identifier.
	Remote *vault.Item
}

// Result is the deterministic outcome of a merge. Items and Conflicts are both
// sorted by exact ID; a conflicted ID never appears in Items.
//
// On success both slices are non-nil, so an empty merge yields []vault.Item{}
// and []Conflict{} rather than nil; vault.ValidateItems accepts the former and
// rejects a nil item slice. Every error return is the zero Result{}.
type Result struct {
	Items     []vault.Item
	Conflicts []Conflict
}

// Merge performs the conservative three-way merge described in the package
// documentation. A nil base is ErrMissingBase; a zero or mismatched KeyEpoch
// is ErrKeyEpoch; an empty, over-long or duplicate ID on any branch is
// rejected, as are branches or merged results above vault.MaxItems. Every
// error returns a zero Result. Errors never include item contents.
func Merge(base *Branch, local, remote Branch) (Result, error) {
	if base == nil {
		return Result{}, ErrMissingBase
	}
	if base.KeyEpoch == 0 || local.KeyEpoch != base.KeyEpoch || remote.KeyEpoch != base.KeyEpoch {
		return Result{}, ErrKeyEpoch
	}
	baseIdx, err := index(base.Items)
	if err != nil {
		return Result{}, err
	}
	localIdx, err := index(local.Items)
	if err != nil {
		return Result{}, err
	}
	remoteIdx, err := index(remote.Items)
	if err != nil {
		return Result{}, err
	}

	ids := make([]string, 0, len(baseIdx)+len(localIdx)+len(remoteIdx))
	seen := make(map[string]struct{}, len(baseIdx)+len(localIdx)+len(remoteIdx))
	for _, idx := range []map[string]vault.Item{baseIdx, localIdx, remoteIdx} {
		for id := range idx {
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)

	// Successful results always carry non-nil slices: vault.ValidateItems
	// rejects a nil item slice even when it is semantically empty.
	out := Result{Items: []vault.Item{}, Conflicts: []Conflict{}}
	for _, id := range ids {
		b, inBase := baseIdx[id]
		l, inLocal := localIdx[id]
		r, inRemote := remoteIdx[id]
		switch {
		case itemEqual(l, inLocal, r, inRemote):
			if inLocal {
				out.Items = append(out.Items, cloneItem(l))
			}
		case itemEqual(l, inLocal, b, inBase):
			if inRemote {
				out.Items = append(out.Items, cloneItem(r))
			}
		case itemEqual(r, inRemote, b, inBase):
			if inLocal {
				out.Items = append(out.Items, cloneItem(l))
			}
		default:
			out.Conflicts = append(out.Conflicts, Conflict{
				ID:     id,
				Base:   cloneOptional(b, inBase),
				Local:  cloneOptional(l, inLocal),
				Remote: cloneOptional(r, inRemote),
			})
		}
	}
	// Independent additions can push the union past the persistable bound.
	// Never return a partial or unpersistable result.
	if len(out.Items) > vault.MaxItems {
		return Result{}, ErrTooManyItems
	}
	return out, nil
}

// index validates one branch and returns its items by exact ID.
func index(items []vault.Item) (map[string]vault.Item, error) {
	if len(items) > vault.MaxItems {
		return nil, ErrTooManyItems
	}
	idx := make(map[string]vault.Item, len(items))
	for _, it := range items {
		if it.ID == "" {
			return nil, ErrEmptyID
		}
		if len(it.ID) > maxIDLength {
			return nil, ErrIDTooLong
		}
		if _, dup := idx[it.ID]; dup {
			return nil, ErrDuplicateID
		}
		idx[it.ID] = it
	}
	return idx, nil
}

// itemEqual reports whether two possibly absent items are identical.
func itemEqual(a vault.Item, aOK bool, b vault.Item, bOK bool) bool {
	return aOK == bOK && (!aOK || itemEqualPresent(a, b))
}

func cloneOptional(it vault.Item, present bool) *vault.Item {
	if !present {
		return nil
	}
	c := cloneItem(it)
	return &c
}
