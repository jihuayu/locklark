package personal

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"runtime"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/vault"
)

// Owned temporary clones are cleared at the end of the transaction callback,
// transferred or not. These tests drive the local tracker directly; no package
// hook is installed, and the end-to-end checks below prove that the persisted
// value was sealed before the tracker cleared the clones that fed it.

func zeroed(b []byte) bool { return len(b) > 0 && bytes.Equal(b, make([]byte, len(b))) }

// expectZeroed records a byte slice through a local to defeat compile-time
// constant propagation and fails when any of them retains data.
func expectZeroed(t *testing.T, pairs ...any) {
	t.Helper()
	for n := 0; n < len(pairs); n += 2 {
		if v := pairs[n+1].([]byte); !zeroed(v) {
			t.Fatalf("%s retained %q", pairs[n], v)
		}
	}
}

func cloneFixtureBytes() (body, own, seed, passkey []byte) {
	body = []byte("synthetic-clone-body")
	own = []byte("synthetic-clone-attachment")
	seed = append([]byte(nil), ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))[:ed25519.SeedSize]...)
	passkey = make([]byte, 32)
	passkey[0] = 1
	return body, own, seed, passkey
}

func cloneFixtureItem(body, own, seed, passkey []byte) vault.Item {
	return vault.Item{
		Attachment:  body,
		Attachments: []vault.AttachmentMeta{{Content: own}},
		SSHSeed:     seed,
		Passkeys:    [][]byte{passkey},
	}
}

// The tracker's cleanup zeroes every CloneItem buffer it owns, including the
// ImportSource only clearCloneItem covers, keeps slice presence, and leaves the
// stored item it cloned untouched.
func TestOwnedClonesClearZeroesTrackedBuffers(t *testing.T) {
	body, own, seed, passkey := cloneFixtureBytes()
	source := []byte("synthetic-clone-provenance")
	body0, own0, seed0, passkey0 := cloneFixtureBytes()
	source0 := []byte("synthetic-clone-provenance")
	stored := cloneFixtureItem(body, own, seed, passkey)
	stored.ImportSource = source
	temporaries := &ownedClones{}
	next := temporaries.track(stored)
	if len(temporaries.clones) != 1 || next == &stored {
		t.Fatal("track did not register a clone")
	}
	if next.ImportSource == nil || &next.ImportSource[0] == &stored.ImportSource[0] {
		t.Fatal("track did not clone the provenance buffer")
	}
	clonedSource := next.ImportSource

	temporaries.clear()

	expectZeroed(t, "body", next.Attachment, "attachment", next.Attachments[0].Content, "provenance", clonedSource, "seed", next.SSHSeed, "passkey", next.Passkeys[0])
	if next.Attachment == nil || len(next.Attachments) != 1 || next.SSHSeed == nil || len(next.Passkeys) != 1 {
		t.Fatal("cleanup dropped slice presence")
	}
	if temporaries.clones != nil || temporaries.inputs != nil {
		t.Fatal("cleanup retained tracker references")
	}
	if !bytes.Equal(stored.Attachment, body0) || !bytes.Equal(stored.Attachments[0].Content, own0) || !bytes.Equal(stored.SSHSeed, seed0) || !bytes.Equal(stored.Passkeys[0], passkey0) || !bytes.Equal(stored.ImportSource, source0) {
		t.Fatal("cleanup touched the cloned item")
	}
	// clear runs after the seal for transferred clones too; a second clear
	// must be harmless.
	temporaries.clear()
}

// An edit adjusts an owned clone to the stored item, replacing the clone's copy
// of the caller's bytes; the tracked input copy keeps them clearable, the
// caller's input is untouched, and clearing twice (tracker and then the
// transaction's final items) is harmless.
func TestOwnedClonesClearZeroesReplacedEditInput(t *testing.T) {
	source := []byte("synthetic-import-provenance")
	attachment := []byte("synthetic-edit-attachment")
	passkey := make([]byte, 32)
	passkey[0] = 2
	input := v2LoginItem()
	input.ImportSource, input.Attachments, input.Passkeys = source, []vault.AttachmentMeta{{Content: attachment}}, [][]byte{passkey}
	input0 := vault.CloneItem(input)
	// stock stands in for the stored item: the adjust step keeps its
	// provenance, attachments and passkeys, so the clone's copy of the caller's
	// bytes is replaced and can only be cleared through the input copy.
	stock := v2LoginItem()
	stock.ImportSource = []byte("stored-provenance")
	stock.Attachments = []vault.AttachmentMeta{{Content: []byte("stored-attachment")}}
	stock.Passkeys = [][]byte{bytes.Repeat([]byte{3}, 32)}

	temporaries := &ownedClones{}
	next := temporaries.track(input)
	temporaries.inputs = append(temporaries.inputs, vault.CloneItem(input))
	next.ImportSource, next.Attachments, next.Passkeys = stock.ImportSource, stock.Attachments, stock.Passkeys
	items := []vault.Item{*next}
	// Each slice is recorded through a local so the zeroing is observable.
	inputCopy := &temporaries.inputs[0]
	inputProvenance, inputAttachment, inputPasskey := inputCopy.ImportSource, inputCopy.Attachments[0].Content, inputCopy.Passkeys[0]
	finalProvenance, finalAttachment, finalPasskey := items[0].ImportSource, items[0].Attachments[0].Content, items[0].Passkeys[0]
	temporaries.clear()
	clearAuthenticatedItems(items)

	expectZeroed(t, "input provenance", inputProvenance, "input attachment", inputAttachment, "input passkey", inputPasskey)
	expectZeroed(t, "final provenance", finalProvenance, "final attachment", finalAttachment, "final passkey", finalPasskey)
	if !bytes.Equal(input0.ImportSource, source) || !bytes.Equal(input0.Attachments[0].Content, attachment) || !bytes.Equal(input0.Passkeys[0], passkey) {
		t.Fatal("tracker clear reached the caller's edit input")
	}
}

// A nil tracker keeps working (read-only call sites) and clear is a no-op.
func TestOwnedClonesNilTracker(t *testing.T) {
	var temporaries *ownedClones
	temporaries.clear()
	item := cloneStoredItem(temporaries, []vault.Item{v2LoginItem()}, 0)
	if item == nil || item.Title != "V2 Login" {
		t.Fatal("nil tracker did not clone")
	}
}

// The attachment-remove compaction rebuilds the owned clone's Attachments in
// place, so the matched element leaves the clone's length or gets overwritten.
// removeOwnedAttachment zeroes that clone copy and only that one: kept clone
// entries and their contents stay byte-exact, and the stored item's original
// slice and buffers are never written.
func TestRemoveOwnedAttachmentClearsOnlyMatchedClone(t *testing.T) {
	// doomed sits between kept so the compaction provably overwrites its slot
	// instead of merely shortening the slice.
	storedFirst, storedDoomed, storedKept := []byte("synthetic-first"), []byte("synthetic-doomed"), []byte("synthetic-kept")
	stored := []vault.AttachmentMeta{{ID: "first", Content: storedFirst}, {ID: "doomed", Content: storedDoomed}, {ID: "kept", Content: storedKept}}
	owned := vault.CloneItem(vault.Item{Attachments: stored})
	first, kept := owned.Attachments[0].Content, owned.Attachments[2].Content
	// The removed Content must be zeroed even if the compaction overwrites its
	// slot, so it is observed through the heap so the write cannot be elided.
	seen := new([]byte)
	*seen = owned.Attachments[1].Content
	runtime.KeepAlive(*seen)

	got := removeOwnedAttachment(owned.Attachments, "doomed")

	if got == nil || len(got) != 2 || got[0].ID != "first" || got[1].ID != "kept" {
		t.Fatalf("compaction kept the wrong entries: %+v", got)
	}
	if !zeroed(*seen) {
		t.Fatal("removed clone attachment was not zeroed")
	}
	runtime.KeepAlive(*seen)
	if string(first) != "synthetic-first" || string(kept) != "synthetic-kept" || string(got[0].Content) != "synthetic-first" || string(got[1].Content) != "synthetic-kept" {
		t.Fatal("compaction changed a kept clone attachment")
	}
	for n, want := range []string{"synthetic-first", "synthetic-doomed", "synthetic-kept"} {
		if got := string(stored[n].Content); got != want {
			t.Fatalf("stored attachment %d changed to %q", n, got)
		}
	}
	if &stored[0].Content[0] != &storedFirst[0] || &stored[1].Content[0] != &storedDoomed[0] || &stored[2].Content[0] != &storedKept[0] {
		t.Fatal("stored attachment slice was rebuilt")
	}
	if string(storedDoomed) != "synthetic-doomed" {
		t.Fatal("removal zeroed the stored item's buffer")
	}

	before := append([]vault.AttachmentMeta(nil), owned.Attachments...)
	if removeOwnedAttachment(owned.Attachments, "missing") != nil {
		t.Fatal("missing attachment reported as removed")
	}
	for n := range before {
		if !bytes.Equal(before[n].Content, owned.Attachments[n].Content) {
			t.Fatalf("missing-ID removal changed attachment %d", n)
		}
	}
}

// End to end: RemoveAttachment keeps the persisted value byte-exact, leaves the
// caller's attachment buffers alone, and reopens from disk.
func TestV2AttachmentRemoveClearsMatchedClone(t *testing.T) {
	s, path, key := v2Session(t)
	id, rev, err := s.AddItem(v2LoginItem(), v2Gate(t, s))
	if err != nil {
		t.Fatal(err)
	}
	doomed := []byte("synthetic-doomed-bytes")
	middle := []byte("synthetic-middle-bytes")
	kept := []byte("synthetic-kept-bytes")
	doomedID, rev, err := s.AddAttachment(id, rev, "doomed.txt", "text/plain", doomed, v2Gate(t, s))
	if err != nil {
		t.Fatal(err)
	}
	middleID, rev, err := s.AddAttachment(id, rev, "middle.txt", "text/plain", middle, v2Gate(t, s))
	if err != nil {
		t.Fatal(err)
	}
	keptID, rev, err := s.AddAttachment(id, rev, "kept.txt", "text/plain", kept, v2Gate(t, s))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RemoveAttachment(id, rev, "missing-attachment", v2Gate(t, s)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown attachment reported as removed")
	}
	attRev, err := s.RemoveAttachment(id, rev, middleID, v2Gate(t, s))
	if err != nil {
		t.Fatalf("attachment remove failed: %v", err)
	}
	if !bytes.Equal(doomed, []byte("synthetic-doomed-bytes")) || !bytes.Equal(middle, []byte("synthetic-middle-bytes")) || !bytes.Equal(kept, []byte("synthetic-kept-bytes")) {
		t.Fatal("attachment remove modified a caller buffer")
	}

	reopened, err := UnlockSession(path, []byte("v2-fixture"), key, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Lock()
	for _, it := range rawItems(t, reopened) {
		if it.ID != id {
			continue
		}
		if len(it.Attachments) != 2 || it.Attachments[0].ID != doomedID || it.Attachments[1].ID != keptID {
			t.Fatalf("attachment order lost after remove: %+v", it.Attachments)
		}
		if !bytes.Equal(it.Attachments[0].Content, doomed) || !bytes.Equal(it.Attachments[1].Content, kept) {
			t.Fatal("kept attachments did not reopen byte-exact")
		}
		if meta, body, err := reopened.GetAttachment(id, attRev, keptID); err != nil || meta.FileName != "kept.txt" || !bytes.Equal(body, kept) {
			t.Fatalf("kept attachment did not reopen byte-exact: %+v %q %v", meta, body, err)
		}
		if _, _, err := reopened.GetAttachment(id, attRev, middleID); !errors.Is(err, ErrNotFound) {
			t.Fatalf("removed attachment still readable: %v", err)
		}
		return
	}
	t.Fatal("login item missing after reopen")
}

// A successful v2-edit-family mutation (MoveItemVault clones the stored item)
// completes after the tracker cleared that clone at the transaction-end: the
// new vault is persisted, the moved item stays byte-exact, and the stored vault
// reopens from disk.
func TestV2MoveSuccessClearsClonesAndReopens(t *testing.T) {
	s, path, key := v2Session(t)
	content := []byte("synthetic-kept-body")
	id, rev, err := s.AddItem(v2LoginItem(), v2Gate(t, s))
	if err != nil {
		t.Fatal(err)
	}
	attID, rev, err := s.AddAttachment(id, rev, "kept.txt", "text/plain", content, v2Gate(t, s))
	if err != nil {
		t.Fatal(err)
	}
	sub, err := s.CreateVault("Work", "", "", v2Gate(t, s))
	if err != nil {
		t.Fatal(err)
	}
	_, moved, err := s.MoveItemVault(id, rev, sub.ID, false, v2Gate(t, s))
	if err != nil {
		t.Fatalf("move failed: %v", err)
	}
	if !bytes.Equal(content, []byte("synthetic-kept-body")) {
		t.Fatal("move modified a caller buffer")
	}
	if detail, err := s.GetItemDetail(id, moved, false); err != nil || detail.VaultID != sub.ID {
		t.Fatalf("move not persisted: %+v %v", detail, err)
	}

	reopened, err := UnlockSession(path, []byte("v2-fixture"), key, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Lock()
	for _, it := range rawItems(t, reopened) {
		if it.ID != id {
			continue
		}
		if it.VaultID != sub.ID || it.Password != "old-password" || len(it.Attachments) != 1 {
			t.Fatalf("moved item did not reopen intact: %+v", it)
		}
		if meta, body, err := reopened.GetAttachment(id, moved, attID); err != nil || meta.FileName != "kept.txt" || !bytes.Equal(body, content) {
			t.Fatalf("attachment did not reopen byte-exact: %+v %q %v", meta, body, err)
		}
		return
	}
	t.Fatal("moved item missing after reopen")
}

// A refused v2 edit leaves both the caller's input and the stored item
// untouched, and the stored vault still reopens.
func TestV2EditRefusalKeepsCallerAndStored(t *testing.T) {
	s, path, key := v2Session(t)
	id, rev, err := s.AddItem(v2LoginItem(), v2Gate(t, s))
	if err != nil {
		t.Fatal(err)
	}
	source := []byte("synthetic-import-provenance\n")
	content := []byte("synthetic-edit-attachment")
	updated := v2LoginItem()
	updated.Password = "edited-password"
	updated.ImportSource = source
	updated.Attachments = []vault.AttachmentMeta{{FileName: "edit.txt", MIMEType: "text/plain", Content: content}}
	// A field ID that escapes the KDBX text model makes the edit fail after the
	// owned clones were built.
	updated.Sections[0].Fields[1].ID = "bad\x00field"
	if _, err := s.EditItem(id, rev, updated, v2Gate(t, s)); !errors.Is(err, ErrMutationRefused) {
		t.Fatalf("invalid edit was not refused: %v", err)
	}
	if !bytes.Equal(source, []byte("synthetic-import-provenance\n")) || !bytes.Equal(content, []byte("synthetic-edit-attachment")) || updated.Sections[0].Fields[1].ID != "bad\x00field" {
		t.Fatal("refused edit modified the caller's buffers")
	}

	reopened, err := UnlockSession(path, []byte("v2-fixture"), key, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Lock()
	for _, it := range rawItems(t, reopened) {
		if it.ID != id {
			continue
		}
		if it.Password != "old-password" || it.ImportSource != nil || len(it.Attachments) != 0 {
			t.Fatalf("refused edit was persisted: %+v", it)
		}
		if detail, err := reopened.GetItemDetail(id, rev, true); err != nil || detail.Password != "old-password" {
			t.Fatalf("stored item changed by refused edit: %+v %v", detail, err)
		}
		return
	}
	t.Fatal("stored item missing after reopen")
}

// A successful v2 add seals its clone before the transaction clears it; the
// caller's document and attachment buffers stay intact and the value reopens.
func TestV2AddSuccessKeepsCallerAndReopens(t *testing.T) {
	s, path, key := v2Session(t)
	item := vault.Item{Kind: "document", Category: vault.CategoryDocument, Title: "V2 Document", Filename: "body.bin", Attachment: []byte("synthetic-document-body"), Attachments: []vault.AttachmentMeta{{FileName: "note.txt", MIMEType: "text/plain", Content: []byte("synthetic-attachment")}}}
	id, _, err := s.AddItem(item, v2Gate(t, s))
	if err != nil {
		t.Fatalf("add failed: %v", err)
	}
	if !bytes.Equal(item.Attachment, []byte("synthetic-document-body")) || !bytes.Equal(item.Attachments[0].Content, []byte("synthetic-attachment")) {
		t.Fatal("successful add modified the caller's buffers")
	}

	reopened, err := UnlockSession(path, []byte("v2-fixture"), key, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Lock()
	for _, it := range rawItems(t, reopened) {
		if it.ID != id {
			continue
		}
		if !bytes.Equal(it.Attachment, []byte("synthetic-document-body")) || len(it.Attachments) != 1 || !bytes.Equal(it.Attachments[0].Content, []byte("synthetic-attachment")) {
			t.Fatalf("added document did not reopen byte-exact: %+v", it)
		}
		return
	}
	t.Fatal("added item missing after reopen")
}
