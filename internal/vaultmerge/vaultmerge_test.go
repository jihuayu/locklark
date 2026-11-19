package vaultmerge

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/vault"
)

const epoch = uint64(7)

func item(id, title, password string) vault.Item {
	return vault.Item{ID: id, Kind: "login", Title: title, Username: "user-" + id, Password: password}
}

func withUpdated(it vault.Item, at int64) vault.Item {
	it.UpdatedAt = at
	return it
}

func withPassword(it vault.Item, password string) vault.Item {
	it.Password = password
	return it
}

func branch(items ...vault.Item) Branch { return Branch{KeyEpoch: epoch, Items: items} }

// zeroEpoch is a branch that declares no (zero) key epoch.
func zeroEpoch(items ...vault.Item) Branch { return Branch{Items: items} }

// base returns a pointer branch for Merge's base argument.
func base(items ...vault.Item) *Branch { b := branch(items...); return &b }

func idsOf[T any](s []T, id func(T) string) []string {
	out := make([]string, len(s))
	for i, v := range s {
		out[i] = id(v)
	}
	return out
}

func itemIDs(items []vault.Item) []string {
	return idsOf(items, func(i vault.Item) string { return i.ID })
}

func conflictIDs(cs []Conflict) []string { return idsOf(cs, func(c Conflict) string { return c.ID }) }

func mustEqual[T any](t *testing.T, got, want T, what string) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s:\n got %#v\nwant %#v", what, got, want)
	}
}

func mustMerge(t *testing.T, base *Branch, local, remote Branch) Result {
	t.Helper()
	res, err := Merge(base, local, remote)
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	return res
}

func TestMergeErrors(t *testing.T) {
	ptr := func(b Branch) *Branch { return &b }
	empty := branch()
	fullAtLimit := func(n int) []vault.Item {
		out := make([]vault.Item, n)
		for i := range out {
			out[i] = item(fmt.Sprintf("id-%04d", i), "t", "p")
		}
		return out
	}
	dupItems := []vault.Item{item("dup", "one", "p"), item("dup", "two", "q")}

	tests := []struct {
		name          string
		base          *Branch
		local, remote Branch
		want          error
	}{
		{name: "missing base", base: nil, local: empty, remote: empty, want: ErrMissingBase},
		{name: "zero epoch base", base: ptr(zeroEpoch()), local: empty, remote: empty, want: ErrKeyEpoch},
		{name: "zero epoch local", base: ptr(empty), local: zeroEpoch(), remote: empty, want: ErrKeyEpoch},
		{name: "zero epoch remote", base: ptr(empty), local: empty, remote: zeroEpoch(item("a", "a", "p")), want: ErrKeyEpoch},
		{name: "local epoch differs", base: ptr(empty), local: Branch{KeyEpoch: epoch + 1}, remote: empty, want: ErrKeyEpoch},
		{name: "remote epoch differs", base: ptr(empty), local: empty, remote: Branch{KeyEpoch: epoch + 2}, want: ErrKeyEpoch},
		{name: "empty ID base", base: ptr(branch(vault.Item{Kind: "login", Title: "secret-title"})), local: empty, remote: empty, want: ErrEmptyID},
		{name: "empty ID local", base: ptr(empty), local: branch(item("a", "a", "p"), vault.Item{Kind: "login"}), remote: empty, want: ErrEmptyID},
		{name: "empty ID remote", base: ptr(empty), local: empty, remote: branch(vault.Item{Password: "hunter2"}), want: ErrEmptyID},
		{name: "ID at 256 bytes", base: ptr(empty), local: branch(item(strings.Repeat("i", 256), "t", "p")), remote: empty},
		{name: "ID over 256 bytes base", base: ptr(branch(item(strings.Repeat("i", 257), "t", "p"))), local: empty, remote: empty, want: ErrIDTooLong},
		{name: "ID over 256 bytes local", base: ptr(empty), local: branch(item(strings.Repeat("é", 129), "t", "p")), remote: empty, want: ErrIDTooLong},
		{name: "ID over 256 bytes remote", base: ptr(empty), local: empty, remote: branch(item(strings.Repeat("i", 300), "t", "p")), want: ErrIDTooLong},
		{name: "duplicate ID base", base: ptr(branch(dupItems...)), local: empty, remote: empty, want: ErrDuplicateID},
		{name: "duplicate ID local", base: ptr(empty), local: branch(item("x", "x", "p"), item("dup", "a", "p"), item("dup", "b", "p")), remote: empty, want: ErrDuplicateID},
		{name: "duplicate ID remote", base: ptr(empty), local: empty, remote: branch(dupItems...), want: ErrDuplicateID},
		{name: "too many base", base: ptr(branch(fullAtLimit(vault.MaxItems + 1)...)), local: empty, remote: empty, want: ErrTooManyItems},
		{name: "too many local", base: ptr(empty), local: branch(fullAtLimit(vault.MaxItems + 1)...), remote: empty, want: ErrTooManyItems},
		{name: "too many remote", base: ptr(empty), local: empty, remote: branch(fullAtLimit(vault.MaxItems + 1)...), want: ErrTooManyItems},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res, err := Merge(tc.base, tc.local, tc.remote)
			if tc.want != nil {
				if !errors.Is(err, tc.want) {
					t.Fatalf("err = %v, want %v", err, tc.want)
				}
				if !reflect.DeepEqual(res, Result{}) {
					t.Fatalf("result on error is not zero: %#v", res)
				}
				if res.Items != nil || res.Conflicts != nil {
					t.Fatalf("error result has non-nil slices: %#v", res)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
		})
	}
}

// Duplicate detection is per branch: a distinct ID in each branch is valid.
func TestMergeSameIDInDifferentBranchesIsNotDuplicate(t *testing.T) {
	a := item("x", "X", "p")
	res := mustMerge(t, base(a), branch(a), branch(withPassword(a, "q")))
	mustEqual(t, res.Items, []vault.Item{withPassword(a, "q")}, "one-sided edit")
	mustEqual(t, res.Conflicts, []Conflict{}, "conflicts")
}

// Error text must never echo item contents.
func TestMergeErrorsDoNotLeakContents(t *testing.T) {
	secret := "Very-Secret-Password"
	dupInOneBranch := append([]vault.Item{item("dup", "Secret Title", secret)},
		item("dup", "Secret Title", secret+"2"))
	inputs := []struct {
		base          *Branch
		local, remote Branch
	}{
		{base(dupInOneBranch...), branch(), branch()},
		{base(), branch(dupInOneBranch...), branch()},
		{base(), branch(), branch(dupInOneBranch...)},
	}
	for _, in := range inputs {
		_, err := Merge(in.base, in.local, in.remote)
		if !errors.Is(err, ErrDuplicateID) {
			t.Fatalf("err = %v, want ErrDuplicateID", err)
		}
		for _, err := range []error{ErrMissingBase, ErrKeyEpoch, ErrEmptyID, ErrIDTooLong, ErrDuplicateID, ErrTooManyItems, err} {
			msg := err.Error()
			if strings.Contains(msg, "Secret") || strings.Contains(msg, secret) {
				t.Fatalf("error leaks item content: %q", msg)
			}
		}
	}
}

// Exactly vault.MaxItems is accepted on every branch.
func TestMergeAtLimit(t *testing.T) {
	full := make([]vault.Item, vault.MaxItems)
	for i := range full {
		full[i] = item(fmt.Sprintf("id-%04d", i), "t", "p")
	}
	res := mustMerge(t, base(full...), branch(full...), branch(full...))
	mustEqual(t, len(res.Items), vault.MaxItems, "items at limit")
	mustEqual(t, len(res.Conflicts), 0, "conflicts at limit")

	// A one-sided replacement at the limit stays at the limit.
	edited := append([]vault.Item(nil), full...)
	edited[0] = withPassword(edited[0], "new")
	res = mustMerge(t, base(full...), branch(edited...), branch(full...))
	mustEqual(t, len(res.Items), vault.MaxItems, "one-sided edit at limit")
}

// Independently added IDs can push the merged result past vault.MaxItems.
func TestMergeResultOverflow(t *testing.T) {
	baseItems := make([]vault.Item, vault.MaxItems-2)
	for i := range baseItems {
		baseItems[i] = item(fmt.Sprintf("id-%04d", i), "t", "p")
	}
	localItems := append(append([]vault.Item(nil), baseItems...), item("l1", "l", "p"))
	remoteItems := append(append([]vault.Item(nil), baseItems...), item("r1", "r", "p"))
	// base-2, local base+1, remote base+1, union base+2: exactly MaxItems.
	res := mustMerge(t, base(baseItems...), branch(localItems...), branch(remoteItems...))
	mustEqual(t, len(res.Items), vault.MaxItems, "union at limit")

	// Every input stays within MaxItems, but the union is MaxItems+1.
	remoteItems = append(remoteItems, item("r2", "r", "p"))
	res, err := Merge(base(baseItems...), branch(localItems...), branch(remoteItems...))
	if !errors.Is(err, ErrTooManyItems) {
		t.Fatalf("err = %v, want ErrTooManyItems", err)
	}
	if !reflect.DeepEqual(res, Result{}) {
		t.Fatalf("overflow returned a partial result: %#v", res)
	}

	// Conflicted IDs are never counted in Items, so the same union with one
	// two-sided addition collision fits at one item fewer.
	confLocal := append(append([]vault.Item(nil), baseItems...), item("l1", "l", "p"))
	confRemote := append(append([]vault.Item(nil), baseItems...), item("l1", "conflict", "p"))
	res = mustMerge(t, base(baseItems...), branch(confLocal...), branch(confRemote...))
	mustEqual(t, len(res.Items), vault.MaxItems-2, "conflict excludes ID")
	mustEqual(t, len(res.Conflicts), 1, "conflict kept")
}

func TestMergeEmptyBranches(t *testing.T) {
	// An empty but present base is valid; empty everywhere gives empty output.
	res := mustMerge(t, &Branch{KeyEpoch: epoch}, branch(), Branch{KeyEpoch: epoch, Items: []vault.Item{}})
	mustEqual(t, res.Items, []vault.Item{}, "items")
	mustEqual(t, res.Conflicts, []Conflict{}, "conflicts")
}

// A successful merge with no unconflicted items must return a non-nil empty
// item slice, because vault.ValidateItems rejects nil even when semantically
// empty.
func TestMergeEmptyResultIsValid(t *testing.T) {
	t.Run("empty branches", func(t *testing.T) {
		res := mustMerge(t, base(), branch(), branch())
		if res.Items == nil {
			t.Fatal("successful empty merge returned nil Items")
		}
		mustEqual(t, res.Items, []vault.Item{}, "items")
		if err := vault.ValidateItems(nil, res.Items); err != nil {
			t.Fatalf("ValidateItems rejected empty result: %v", err)
		}
	})

	t.Run("all deleted on both sides", func(t *testing.T) {
		b := item("x", "X", "p")
		res := mustMerge(t, base(b), branch(), branch())
		if res.Items == nil {
			t.Fatal("delete-all merge returned nil Items")
		}
		mustEqual(t, res.Items, []vault.Item{}, "items")
		mustEqual(t, res.Conflicts, []Conflict{}, "conflicts")
		if err := vault.ValidateItems(nil, res.Items); err != nil {
			t.Fatalf("ValidateItems rejected delete-all result: %v", err)
		}
	})

	t.Run("conflict only leaves empty valid items", func(t *testing.T) {
		b := item("x", "X", "base")
		res := mustMerge(t, base(b), branch(withPassword(b, "l")), branch(withPassword(b, "r")))
		mustEqual(t, res.Items, []vault.Item{}, "items")
		mustEqual(t, len(res.Conflicts), 1, "conflicts")
		if err := vault.ValidateItems(nil, res.Items); err != nil {
			t.Fatalf("ValidateItems rejected conflict-only result: %v", err)
		}
	})
}

// Titles never identify items; IDs match exactly and case-sensitively.
func TestMergeDuplicateTitlesDistinctIDs(t *testing.T) {
	b1 := item("id-A", "Same Title", "one")
	b2 := item("id-a", "Same Title", "two")
	res := mustMerge(t, base(b1, b2), branch(b1, withPassword(b2, "two-l")), branch(withPassword(b1, "one-r"), b2))
	mustEqual(t, itemIDs(res.Items), []string{"id-A", "id-a"}, "items")
	got := map[string]vault.Item{}
	for _, it := range res.Items {
		got[it.ID] = it
	}
	mustEqual(t, got["id-A"].Password, "one-r", "id-A")
	mustEqual(t, got["id-a"].Password, "two-l", "id-a")
	mustEqual(t, len(res.Conflicts), 0, "conflicts")
}

// Independent entries plus one-sided edits, additions and deletions merge.
func TestMergeAutoMerge(t *testing.T) {
	a, b, c, d := item("a", "A", "pa"), item("b", "B", "pb"), item("c", "C", "pc"), item("d", "D", "pd")
	base := branch(a, b, c, d)
	local := branch(
		withPassword(a, "pa-local"), // only local edits a
		b,                           // independent
		c,                           // independent
		item("ladd", "L Add", "pl"), // only local adds
	)
	remote := branch(
		a,                            // a unchanged remotely
		b,                            // independent
		withPassword(c, "pc-remote"), // only remote edits c
		item("radd", "R Add", "pr"),  // only remote adds; d is deleted remotely
	)
	res := mustMerge(t, &base, local, remote)
	mustEqual(t, len(res.Conflicts), 0, "conflicts")
	mustEqual(t, itemIDs(res.Items), []string{"a", "b", "c", "ladd", "radd"}, "items")
	want := map[string]vault.Item{
		"a":    withPassword(a, "pa-local"),
		"b":    b,
		"c":    withPassword(c, "pc-remote"),
		"ladd": item("ladd", "L Add", "pl"),
		"radd": item("radd", "R Add", "pr"),
	}
	for _, it := range res.Items {
		mustEqual(t, it, want[it.ID], it.ID)
	}
}

func TestMergeSameIDDivergentEditConflict(t *testing.T) {
	b := item("x", "X", "base")
	loc := withPassword(b, "local")
	rem := withPassword(b, "remote")
	res := mustMerge(t, base(b), branch(loc), branch(rem))
	mustEqual(t, res.Items, []vault.Item{}, "no items")
	mustEqual(t, conflictIDs(res.Conflicts), []string{"x"}, "conflicts")
	c := res.Conflicts[0]
	mustEqual(t, *c.Base, b, "base")
	mustEqual(t, *c.Local, loc, "local")
	mustEqual(t, *c.Remote, rem, "remote")
}

func TestMergeSameIDConvergence(t *testing.T) {
	b := item("x", "X", "base")
	same := withPassword(b, "converged")
	res := mustMerge(t, base(b), branch(same), branch(same))
	mustEqual(t, itemIDs(res.Items), []string{"x"}, "converged kept")
	mustEqual(t, res.Items[0], same, "converged value")
	mustEqual(t, len(res.Conflicts), 0, "conflicts")

	// Both sides apply the same edit to a freshly added ID.
	added := item("y", "Y", "p")
	res = mustMerge(t, base(b), branch(b, added), branch(b, added))
	mustEqual(t, itemIDs(res.Items), []string{"x", "y"}, "converged addition")
	mustEqual(t, len(res.Conflicts), 0, "conflicts")
}

func TestMergeDeleteVsEditConflict(t *testing.T) {
	b := item("x", "X", "base")
	edited := withPassword(b, "edited")
	keep := item("keep", "K", "p")
	for _, tc := range []struct {
		name             string
		local, remote    Branch
		localHas, remHas bool
	}{
		{"local delete remote edit", branch(keep), branch(edited, keep), false, true},
		{"local edit remote delete", branch(edited, keep), branch(keep), true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := mustMerge(t, base(b, keep), tc.local, tc.remote)
			mustEqual(t, itemIDs(res.Items), []string{"keep"}, "items exclude conflicted ID")
			mustEqual(t, conflictIDs(res.Conflicts), []string{"x"}, "conflicts")
			c := res.Conflicts[0]
			mustEqual(t, *c.Base, b, "base present")
			mustEqual(t, c.Local != nil, tc.localHas, "local presence")
			mustEqual(t, c.Remote != nil, tc.remHas, "remote presence")
			present := c.Local
			if present == nil {
				present = c.Remote
			}
			mustEqual(t, *present, edited, "edited side preserved whole")
		})
	}
}

// A longer UpdatedAt never wins; any two-sided change is a conflict.
func TestMergeUpdatedAtDoesNotWin(t *testing.T) {
	b := withUpdated(item("x", "X", "base"), 100)
	later := withUpdated(item("x", "X", "local-newer"), 9999)
	earlier := withUpdated(item("x", "X", "remote-older"), 1)
	res := mustMerge(t, base(b), branch(later), branch(earlier))
	mustEqual(t, len(res.Items), 0, "no winner")
	mustEqual(t, len(res.Conflicts), 1, "conflict")
	mustEqual(t, *res.Conflicts[0].Local, later, "local")
	mustEqual(t, *res.Conflicts[0].Remote, earlier, "remote")

	// Trash-vs-edit is an ordinary edit conflict too.
	trashedAt := time.Unix(500, 0).UTC()
	trashed := b
	trashed.State, trashed.TrashedAt = "trashed", &trashedAt
	res = mustMerge(t, base(b), branch(trashed), branch(withUpdated(b, 1000)))
	mustEqual(t, len(res.Conflicts), 1, "trash-vs-edit conflict")
	mustEqual(t, *res.Conflicts[0].Local.TrashedAt, trashedAt, "local trash time")
}

func richItem(id, secret string) vault.Item {
	yes := true
	trashedAt := time.Unix(1700000000, 0).UTC()
	return vault.Item{
		ID:            id,
		Kind:          "login",
		Title:         "Rich " + id,
		Username:      "user",
		Password:      "pass",
		OTP:           "otpauth://totp/x?secret=ABC",
		Notes:         "notes",
		SSHSeed:       []byte(secret + "-seed"),
		SSHPublicKey:  []byte("ssh-ed25519 AAAA " + secret),
		Passkey:       []byte(secret + "-passkey"),
		Passkeys:      [][]byte{[]byte(secret + "-pk0"), []byte(secret + "-pk1")},
		ImportSource:  []byte("imported-by:" + secret),
		Tags:          []string{"tag1", "tag2"},
		URLs:          []vault.ItemURL{{URL: "https://example.com", MatchMode: "origin", Primary: true}},
		Sections:      []vault.ItemSection{{ID: "s1", Title: "Secrets", Fields: []vault.CustomField{{ID: "f1", Label: "PIN", Type: "concealed", Value: secret, Protected: true}}}},
		CreditCard:    &vault.CreditCardDetails{Number: "4111" + secret, Verification: secret},
		Identity:      &vault.IdentityDetails{SSN: secret, PassportNumber: secret},
		History:       []vault.ItemHistoryEntry{{Timestamp: 1, Action: "password-change", Password: secret, Sections: []vault.ItemSection{{ID: "h", Title: "old", Fields: []vault.CustomField{{ID: "hf", Value: secret}}}}}},
		Attachments:   []vault.AttachmentMeta{{ID: "att1", FileName: "a.bin", Size: int64(len(secret)), MIMEType: "application/octet-stream", SHA256: "00", Protected: true, Content: []byte(secret + "-attachment")}},
		TrashedAt:     &trashedAt,
		CreatedAt:     10,
		UpdatedAt:     20,
		AutoSubmit:    &yes,
		Favorite:      true,
		VaultID:       "personal",
		State:         "trashed",
		PreviousState: "archived",
	}
}

func TestMergeSensitiveAndAttachmentChangesPreserveBothSides(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(it vault.Item) vault.Item
	}{
		{"password", func(it vault.Item) vault.Item { it.Password = "changed"; return it }},
		{"concealed section field", func(it vault.Item) vault.Item {
			it.Sections = []vault.ItemSection{{ID: "s1", Title: "Secrets", Fields: []vault.CustomField{{ID: "f1", Value: "changed", Protected: true}}}}
			return it
		}},
		{"credit card pin", func(it vault.Item) vault.Item {
			cc := *it.CreditCard
			cc.PIN = "9999"
			it.CreditCard = &cc
			return it
		}},
		{"identity ssn", func(it vault.Item) vault.Item {
			id := *it.Identity
			id.SSN = "000-00-0000"
			it.Identity = &id
			return it
		}},
		{"attachment content", func(it vault.Item) vault.Item {
			it.Attachments = append([]vault.AttachmentMeta{}, it.Attachments...)
			it.Attachments[0].Content = []byte("new attachment bytes")
			return it
		}},
		{"attachment added", func(it vault.Item) vault.Item {
			it.Attachments = append(append([]vault.AttachmentMeta{}, it.Attachments...), vault.AttachmentMeta{ID: "att2", FileName: "b.bin", Content: []byte("two")})
			return it
		}},
		{"attachment removed", func(it vault.Item) vault.Item { it.Attachments = nil; return it }},
		{"passkey collection", func(it vault.Item) vault.Item { it.Passkeys = [][]byte{[]byte("new-pk")}; return it }},
		{"ssh seed", func(it vault.Item) vault.Item { it.SSHSeed = []byte("new-seed"); return it }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := richItem("x", "base")
			local := tc.mutate(richItem("x", "base"))
			remote := richItem("x", "base")
			remote.Notes = "remote notes" // unrelated edit on the other side
			res := mustMerge(t, base(b), branch(local), branch(remote))
			mustEqual(t, len(res.Items), 0, "no items")
			mustEqual(t, len(res.Conflicts), 1, "one conflict")
			c := res.Conflicts[0]
			mustEqual(t, *c.Base, b, "base side complete")
			mustEqual(t, *c.Local, local, "local side complete")
			mustEqual(t, *c.Remote, remote, "remote side complete")
		})
	}

	// Attachment change on one side plus an edit on the other keeps both
	// complete attachment sets.
	b := richItem("x", "base")
	local := richItem("x", "base")
	local.Attachments = append([]vault.AttachmentMeta{}, local.Attachments...)
	local.Attachments[0].Content = []byte("local-new-attachment")
	remote := richItem("x", "base")
	remote.Title = "Remote Rename"
	c := mustMerge(t, base(b), branch(local), branch(remote)).Conflicts[0]
	mustEqual(t, c.Local.Attachments, local.Attachments, "local attachments")
	mustEqual(t, c.Remote.Attachments, remote.Attachments, "remote attachments")
}

// Nil and empty slices are distinct model values.
func TestMergeNilVersusEmpty(t *testing.T) {
	b := richItem("x", "base")
	b.Tags = nil
	loc := b
	loc.Tags = []string{}
	rem := withPassword(b, "r")
	c := mustMerge(t, base(b), branch(loc), branch(rem)).Conflicts[0]
	if c.Local.Tags == nil || c.Remote.Tags != nil {
		t.Fatalf("nil-ness not preserved: local=%#v remote=%#v", c.Local.Tags, c.Remote.Tags)
	}
}

func TestMergeDeterministicOrdering(t *testing.T) {
	// Byte order: upper-case before lower-case, "a" before "a10" before "a2".
	all := []string{"b", "B", "a10", "a2", "A", "_x", "aa", "a"}
	build := func(tag string, skip map[string]bool, edit func(vault.Item) vault.Item) Branch {
		var items []vault.Item
		for _, id := range all {
			if skip[id] {
				continue
			}
			items = append(items, edit(item(id, tag, "p")))
		}
		return branch(items...)
	}
	conflicted := map[string]bool{"a2": true, "B": true, "_x": true}
	edited := func(it vault.Item) vault.Item {
		if conflicted[it.ID] {
			return withPassword(it, "local-"+it.ID)
		}
		return it
	}
	base := build("base", nil, func(it vault.Item) vault.Item { return it })
	local := build("base", map[string]bool{"a10": true}, edited)
	local.Items = append(local.Items, item("zz", "added", "p"))
	remote := build("base", map[string]bool{"a10": true}, func(it vault.Item) vault.Item {
		if conflicted[it.ID] {
			return withPassword(it, "remote-"+it.ID)
		}
		return it
	})
	reverse := func(b Branch) Branch {
		out := Branch{KeyEpoch: b.KeyEpoch, Items: make([]vault.Item, len(b.Items))}
		for i, it := range b.Items {
			out.Items[len(b.Items)-1-i] = it
		}
		return out
	}
	first := mustMerge(t, &base, local, remote)
	rb := reverse(base)
	second := mustMerge(t, &rb, reverse(local), reverse(remote))
	mustEqual(t, first, second, "input order independence")
	mustEqual(t, itemIDs(first.Items), []string{"A", "a", "aa", "b", "zz"}, "item byte order")
	mustEqual(t, conflictIDs(first.Conflicts), []string{"B", "_x", "a2"}, "conflict byte order")
}

// snapshot returns a deep copy of a branch's items to record input state.
// snapshot records input state through an implementation independent of
// cloneItem: if it reused cloneItem, a missed deep copy would silently corrupt
// both the input and its snapshot alike and the comparison could not fail.
func snapshot(b Branch) []vault.Item {
	out := make([]vault.Item, len(b.Items))
	for i, it := range b.Items {
		out[i] = copyForSnapshot(it)
	}
	return out
}

// copyForSnapshot deep-copies every slice and pointer field explicitly.
func copyForSnapshot(it vault.Item) vault.Item {
	c := it
	cp := func(b []byte) []byte {
		if b == nil {
			return nil
		}
		return append([]byte(nil), b...)
	}
	c.Attachment = cp(it.Attachment)
	c.ImportSource = cp(it.ImportSource)
	c.SSHSeed = cp(it.SSHSeed)
	c.SSHPublicKey = cp(it.SSHPublicKey)
	c.Passkey = cp(it.Passkey)
	if it.Passkeys != nil {
		c.Passkeys = make([][]byte, len(it.Passkeys))
		for i := range it.Passkeys {
			c.Passkeys[i] = cp(it.Passkeys[i])
		}
	}
	if it.AutoSubmit != nil {
		v := *it.AutoSubmit
		c.AutoSubmit = &v
	}
	if it.Tags != nil {
		c.Tags = append([]string(nil), it.Tags...)
	}
	if it.URLs != nil {
		c.URLs = append([]vault.ItemURL(nil), it.URLs...)
	}
	copySections := func(s []vault.ItemSection) []vault.ItemSection {
		if s == nil {
			return nil
		}
		out := make([]vault.ItemSection, len(s))
		for i, sec := range s {
			out[i] = sec
			if sec.Fields != nil {
				out[i].Fields = append([]vault.CustomField(nil), sec.Fields...)
			}
		}
		return out
	}
	c.Sections = copySections(it.Sections)
	if it.CreditCard != nil {
		v := *it.CreditCard
		c.CreditCard = &v
	}
	if it.Identity != nil {
		v := *it.Identity
		c.Identity = &v
	}
	if it.History != nil {
		c.History = make([]vault.ItemHistoryEntry, len(it.History))
		for i, h := range it.History {
			c.History[i] = h
			c.History[i].Sections = copySections(h.Sections)
		}
	}
	if it.Attachments != nil {
		c.Attachments = make([]vault.AttachmentMeta, len(it.Attachments))
		for i, a := range it.Attachments {
			c.Attachments[i] = a
			c.Attachments[i].Content = cp(a.Content)
		}
	}
	if it.TrashedAt != nil {
		t := *it.TrashedAt
		c.TrashedAt = &t
	}
	return c
}

// mutateAll flips every returned buffer and pointer through its own pointer.
func mutateAll(it *vault.Item) {
	for _, b := range []*[]byte{&it.Attachment, &it.ImportSource, &it.SSHSeed, &it.SSHPublicKey, &it.Passkey} {
		if *b != nil {
			(*b)[0] ^= 0xff
		}
	}
	for _, pk := range it.Passkeys {
		if pk != nil {
			pk[0] ^= 0xff
		}
	}
	for i := range it.Tags {
		it.Tags[i] = "mutated"
	}
	for i := range it.URLs {
		it.URLs[i].URL = "mutated"
	}
	for i := range it.Sections {
		it.Sections[i].Title = "mutated"
		for j := range it.Sections[i].Fields {
			it.Sections[i].Fields[j].Value = "mutated"
		}
	}
	if it.CreditCard != nil {
		it.CreditCard.Number = "mutated"
	}
	if it.Identity != nil {
		it.Identity.SSN = "mutated"
	}
	for i := range it.History {
		it.History[i].Password = "mutated"
		for j := range it.History[i].Sections {
			for k := range it.History[i].Sections[j].Fields {
				it.History[i].Sections[j].Fields[k].Value = "mutated"
			}
		}
	}
	for i := range it.Attachments {
		if it.Attachments[i].Content != nil {
			it.Attachments[i].Content[0] ^= 0xff
		}
	}
	if it.AutoSubmit != nil {
		*it.AutoSubmit = !*it.AutoSubmit
	}
	if it.TrashedAt != nil {
		*it.TrashedAt = it.TrashedAt.Add(time.Hour)
	}
}

func TestMergeOutputMutationIsolation(t *testing.T) {
	baseItem := richItem("x", "base")
	localItem := richItem("x", "base")
	localItem.Passkeys[0][0] = 'L'
	localItem.Attachments[0].Content[0] = 'L'
	*localItem.AutoSubmit = false
	localTrashed := time.Unix(7, 0).UTC()
	localItem.TrashedAt = &localTrashed
	remoteItem := richItem("x", "base")
	remoteItem.Passkeys[1][0] = 'R'
	remoteItem.Attachments[0].Content[0] = 'R'
	remoteTrashed := time.Unix(42, 0).UTC()
	remoteItem.TrashedAt = &remoteTrashed
	onlyLocal := richItem("only-local", "s")
	onlyLocal.Attachments = nil
	base, local, remote := branch(baseItem), branch(localItem, onlyLocal), branch(remoteItem)

	wantBase, wantLocal, wantRemote := snapshot(base), snapshot(local), snapshot(remote)
	res := mustMerge(t, &base, local, remote)
	mustEqual(t, itemIDs(res.Items), []string{"only-local"}, "merged item")
	mustEqual(t, conflictIDs(res.Conflicts), []string{"x"}, "conflict")

	// Mutate every returned buffer, nested slice and pointer target.
	for i := range res.Items {
		mutateAll(&res.Items[i])
	}
	c := &res.Conflicts[0]
	for _, side := range []*vault.Item{c.Base, c.Local, c.Remote} {
		if side == nil {
			t.Fatal("expected three sides")
		}
		mutateAll(side)
	}

	// No returned side may share pointer targets or backing arrays with an
	// input: assert identity, not just value.
	pairs := []struct {
		name       string
		got, input *vault.Item
	}{
		{"base", c.Base, &base.Items[0]},
		{"local", c.Local, &local.Items[0]},
		{"remote", c.Remote, &remote.Items[0]},
	}
	for _, p := range pairs {
		if p.got.AutoSubmit == p.input.AutoSubmit {
			t.Fatalf("%s side aliases AutoSubmit pointer", p.name)
		}
		if p.input.TrashedAt == nil {
			t.Fatalf("%s input fixture must carry TrashedAt", p.name)
		}
		if p.got.TrashedAt == p.input.TrashedAt {
			t.Fatalf("%s side aliases TrashedAt pointer", p.name)
		}
		if p.input.CreditCard != nil && p.got.CreditCard == p.input.CreditCard {
			t.Fatalf("%s side aliases CreditCard pointer", p.name)
		}
		if p.input.Identity != nil && p.got.Identity == p.input.Identity {
			t.Fatalf("%s side aliases Identity pointer", p.name)
		}
		// Byte buffers and nested slices must not share backing arrays.
		for _, bc := range []struct {
			name       string
			got, input []byte
		}{
			{"Attachment", p.got.Attachment, p.input.Attachment},
			{"ImportSource", p.got.ImportSource, p.input.ImportSource},
			{"SSHSeed", p.got.SSHSeed, p.input.SSHSeed},
			{"SSHPublicKey", p.got.SSHPublicKey, p.input.SSHPublicKey},
			{"Passkey", p.got.Passkey, p.input.Passkey},
		} {
			if len(bc.input) > 0 && &bc.got[0] == &bc.input[0] {
				t.Fatalf("%s side aliases %s buffer", p.name, bc.name)
			}
		}
		for i := range p.input.Passkeys {
			if len(p.input.Passkeys[i]) > 0 && &p.got.Passkeys[i][0] == &p.input.Passkeys[i][0] {
				t.Fatalf("%s side aliases Passkeys[%d] buffer", p.name, i)
			}
		}
		if len(p.input.Tags) > 0 && &p.got.Tags[0] == &p.input.Tags[0] {
			t.Fatalf("%s side aliases Tags backing array", p.name)
		}
		if len(p.input.URLs) > 0 && &p.got.URLs[0] == &p.input.URLs[0] {
			t.Fatalf("%s side aliases URLs backing array", p.name)
		}
		if len(p.input.Sections) > 0 && &p.got.Sections[0] == &p.input.Sections[0] {
			t.Fatalf("%s side aliases Sections backing array", p.name)
		}
		if len(p.got.Sections) > 0 && len(p.got.Sections[0].Fields) > 0 &&
			&p.got.Sections[0].Fields[0] == &p.input.Sections[0].Fields[0] {
			t.Fatalf("%s side aliases section fields backing array", p.name)
		}
		if len(p.input.History) > 0 && &p.got.History[0] == &p.input.History[0] {
			t.Fatalf("%s side aliases History backing array", p.name)
		}
		if len(p.got.History) > 0 && len(p.got.History[0].Sections) > 0 &&
			&p.got.History[0].Sections[0] == &p.input.History[0].Sections[0] {
			t.Fatalf("%s side aliases history sections backing array", p.name)
		}
		if len(p.got.History) > 0 && len(p.got.History[0].Sections) > 0 &&
			len(p.got.History[0].Sections[0].Fields) > 0 &&
			&p.got.History[0].Sections[0].Fields[0] == &p.input.History[0].Sections[0].Fields[0] {
			t.Fatalf("%s side aliases history section fields backing array", p.name)
		}
		if len(p.input.Attachments) > 0 && &p.got.Attachments[0] == &p.input.Attachments[0] {
			t.Fatalf("%s side aliases Attachments backing array", p.name)
		}
		if len(p.input.Attachments) > 0 && len(p.input.Attachments[0].Content) > 0 &&
			&p.got.Attachments[0].Content[0] == &p.input.Attachments[0].Content[0] {
			t.Fatalf("%s side aliases attachment content", p.name)
		}
	}

	// Inputs (including pointer targets) are unchanged.
	mustEqual(t, base.Items, wantBase, "base input unchanged")
	mustEqual(t, local.Items, wantLocal, "local input unchanged")
	mustEqual(t, remote.Items, wantRemote, "remote input unchanged")

	// A fresh merge from the same inputs reproduces the original sides, so
	// the mutation above went only into the returned copies.
	res2 := mustMerge(t, &base, local, remote)
	mustEqual(t, *res2.Conflicts[0].Base, wantBase[0], "base side")
	mustEqual(t, *res2.Conflicts[0].Local, wantLocal[0], "local side")
	mustEqual(t, *res2.Conflicts[0].Remote, wantRemote[0], "remote side")
	mustEqual(t, res2.Items[0], wantLocal[1], "merged item")

	// Mutating inputs afterwards leaves the returned copies untouched.
	res3 := mustMerge(t, &base, local, remote)
	wantItem, wantSide := res3.Items[0], *res3.Conflicts[0].Local
	for i := range local.Items {
		mutateAll(&local.Items[i])
	}
	for i := range base.Items {
		mutateAll(&base.Items[i])
	}
	mustEqual(t, res3.Items[0], wantItem, "item not aliased to input")
	mustEqual(t, *res3.Conflicts[0].Local, wantSide, "conflict side not aliased to input")
}
