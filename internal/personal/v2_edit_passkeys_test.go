package personal

import (
	"testing"
)

func TestEditItemPreservesVersionedPasskeyCollection(t *testing.T) {
	s, target, _, _, revision := passkeyMultiFixture(t)
	updated := v2LoginItem()
	updated.Password = "edited-password"
	updated.Notes = "edited notes"
	newRevision, err := s.EditItem(target.ID, revision, updated, v2Gate(t, s))
	if err != nil {
		t.Fatalf("edit failed: %v", err)
	}
	if newRevision == revision {
		t.Fatal("edit did not advance the revision")
	}
	items := rawItems(t, s)
	defer func() {
		for index := range items {
			items[index].ClearPasskeys()
		}
	}()
	for _, item := range items {
		if item.ID != target.ID {
			continue
		}
		if item.Password != "edited-password" || item.Notes != "edited notes" {
			t.Fatalf("edit did not persist fields: password=%q notes=%q", item.Password, item.Notes)
		}
		if len(item.Passkeys) != 2 || len(item.Passkey) != 0 {
			t.Fatalf("edit lost the versioned collection: collection=%d legacy=%d",
				len(item.Passkeys), len(item.Passkey))
		}
		return
	}
	t.Fatal("edited login missing")
}
