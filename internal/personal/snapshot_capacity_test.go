package personal

import (
	"bytes"
	"errors"
	"testing"

	"github.com/jihuayu/locklark/internal/vault"
	bolt "go.etcd.io/bbolt"
)

// storedSnapshotValue returns the persisted JSON snapshot bytes.
func storedSnapshotValue(t *testing.T, path string) []byte {
	t.Helper()
	db, err := existingWithReadOnly(path, true)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var state []byte
	err = db.View(func(tx *bolt.Tx) error {
		if b := tx.Bucket(bucket); b != nil {
			state = bytes.Clone(b.Get(snapshotKey))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return state
}

// A schema-valid item whose encrypted snapshot exceeds MaxStoredSnapshot must
// be refused with the capacity error, leave the stored snapshot byte-for-byte
// unchanged, and keep the session unlocked with the original item available.
func TestAddItemOverStoredCapacityRollsBackAndStaysUnlocked(t *testing.T) {
	s, path, _ := v2Session(t)
	id, revision, err := s.AddItem(v2LoginItem(), v2Gate(t, s))
	if err != nil {
		t.Fatal(err)
	}
	before := storedSnapshotValue(t, path)
	defer clear(before)
	if len(before) == 0 {
		t.Fatal("baseline snapshot missing")
	}

	item := personalCapacityItem() // Kind is normalized to the category on write.
	item.Kind = string(item.Category)
	// v2LoginItem carries OTP + passkey slots that the personal schema rejects;
	// the capacity item alone is the schema-valid probe.
	if err := vault.ValidateItems([]byte(schema), []vault.Item{item}); err != nil {
		t.Fatalf("capacity fixture is not schema-valid for the personal store: %v", err)
	}
	if _, _, err := s.AddItem(item, v2Gate(t, s)); !errors.Is(err, ErrSnapshotCapacity) || errors.Is(err, ErrMutationUnknown) || errors.Is(err, ErrMutationRefused) {
		t.Fatalf("AddItem over capacity = %v, want only ErrSnapshotCapacity", err)
	}
	if !s.Unlocked() {
		t.Fatal("capacity refusal locked the session")
	}
	after := storedSnapshotValue(t, path)
	defer clear(after)
	if !bytes.Equal(before, after) {
		t.Fatal("capacity refusal changed the stored snapshot")
	}
	rows, err := s.List("active")
	if err != nil || len(rows) != 1 || rows[0].ID != id || rows[0].Revision != revision {
		t.Fatalf("original item state not preserved: %+v %v", rows, err)
	}
	if detail, err := s.GetItemDetail(id, revision, false); err != nil || detail.Title != v2LoginItem().Title {
		t.Fatalf("original item unavailable after refusal: %v", err)
	}
	// The unlocked session must still accept a normal, small write.
	if _, _, err := s.AddItem(v2LoginItem(), v2Gate(t, s)); err != nil {
		t.Fatalf("small write after capacity refusal failed: %v", err)
	}
}

// Malformed items keep the generic invalid-snapshot refusal (the caller maps
// it to a refusal) and must not be reported as capacity.
func TestAddItemMalformedStillReportsInvalidNotCapacity(t *testing.T) {
	s, path, _ := v2Session(t)
	before := storedSnapshotValue(t, path)
	defer clear(before)
	item := v2LoginItem()
	// Card details that KDBX XML cannot carry on a login: schema-invalid.
	item.CreditCard = &vault.CreditCardDetails{Number: "\x00"}
	_, _, err := s.AddItem(item, v2Gate(t, s))
	if errors.Is(err, ErrSnapshotCapacity) || !errors.Is(err, ErrMutationRefused) {
		t.Fatalf("malformed item = %v, want ErrMutationRefused without capacity", err)
	}
	if !s.Unlocked() {
		t.Fatal("malformed refusal locked the session")
	}
	after := storedSnapshotValue(t, path)
	defer clear(after)
	if !bytes.Equal(before, after) {
		t.Fatal("malformed refusal changed the stored snapshot")
	}
}

// Editing an existing item past the stored bound is refused transactionally
// and the session stays unlocked with the previous revision intact.
func TestEditItemOverStoredCapacityRollsBack(t *testing.T) {
	s, path, _ := v2Session(t)
	id, revision, err := s.AddItem(v2LoginItem(), v2Gate(t, s))
	if err != nil {
		t.Fatal(err)
	}
	before := storedSnapshotValue(t, path)
	defer clear(before)
	updated := v2LoginItem()
	updated.Sections = append(updated.Sections, personalCapacityItem().Sections...)
	if _, err := s.EditItem(id, revision, updated, v2Gate(t, s)); !errors.Is(err, ErrSnapshotCapacity) {
		t.Fatalf("EditItem over capacity = %v, want ErrSnapshotCapacity", err)
	}
	if !s.Unlocked() {
		t.Fatal("capacity refusal locked the session")
	}
	after := storedSnapshotValue(t, path)
	defer clear(after)
	if !bytes.Equal(before, after) {
		t.Fatal("capacity refusal changed the stored snapshot")
	}
	if detail, err := s.GetItemDetail(id, revision, false); err != nil || len(detail.Sections) != len(v2LoginItem().Sections) {
		t.Fatalf("previous revision not preserved: %v", err)
	}
}

// A native mutation that overflows the vault refuses through the won commit
// gate with the capacity error, not the ambiguous ErrMutationUnknown: the
// transaction rolled back and nothing was written.
func TestAddNativeItemOverStoredCapacityRefusedNotUnknown(t *testing.T) {
	s, path, _ := v2Session(t)
	if _, _, err := s.AddItem(v2LoginItem(), v2Gate(t, s)); err != nil {
		t.Fatal(err)
	}
	before := storedSnapshotValue(t, path)
	defer clear(before)
	// AddItem is the ready commit gate consumers use; an over-capacity body
	// that passes item validation must surface as a definite refusal.
	item := personalCapacityItem()
	item.Kind = string(item.Category)
	if _, _, err := s.AddItem(item, v2Gate(t, s)); !errors.Is(err, ErrSnapshotCapacity) || errors.Is(err, ErrMutationUnknown) {
		t.Fatalf("native AddItem over capacity = %v, want only ErrSnapshotCapacity", err)
	}
	if !s.Unlocked() {
		t.Fatal("capacity refusal locked the session")
	}
	after := storedSnapshotValue(t, path)
	defer clear(after)
	if !bytes.Equal(before, after) {
		t.Fatal("capacity refusal changed the stored snapshot")
	}
	if rows, err := s.List("active"); err != nil || len(rows) != 1 || rows[0].Title != v2LoginItem().Title {
		t.Fatalf("original item state not preserved: %+v %v", rows, err)
	}
}
