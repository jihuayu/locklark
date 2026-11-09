package personal

import "testing"

func collectionRow(t *testing.T, s *Session, id string) ItemSummary {
	t.Helper()
	rows, err := s.ListByFilter(ItemFilter{State: "active"})
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.ID == id {
			return row
		}
	}
	t.Fatalf("login %q missing from native summary", id)
	return ItemSummary{}
}

func passkeyConsumerContainsFlag(flags []string, want string) bool {
	for _, flag := range flags {
		if flag == want {
			return true
		}
	}
	return false
}

func watchtowerFlagsFor(t *testing.T, s *Session, id string) []string {
	t.Helper()
	report, err := s.Watchtower("https://example.test", false)
	if err != nil {
		t.Fatalf("watchtower: %v", err)
	}
	for _, finding := range report.Findings {
		if finding.ID == id {
			return finding.Flags
		}
	}
	return nil
}

func browserFlagsFor(t *testing.T, s *Session, id string) []string {
	t.Helper()
	summary, err := s.WatchtowerSummary("https://example.test")
	if err != nil {
		t.Fatalf("browser watchtower: %v", err)
	}
	for _, finding := range summary.Findings {
		if finding.ID == id {
			return finding.Flags
		}
	}
	return nil
}

// TestPasskeyCollectionConsumersReportPresence proves that the native summary,
// native detail, desktop watchtower and browser watchtower consumers all read
// the versioned passkey collection, not just the legacy single-record field.
// The login is a real authenticated fixture holding two credentials created
// through the passkey path, so its legacy field is empty by construction.
func TestPasskeyCollectionConsumersReportPresence(t *testing.T) {
	s, target, first, second, revision := passkeyMultiFixture(t)
	items := useReadAuthenticatedItems(t, s)
	deferClearPasskeys(t, items)
	seen := false
	for _, item := range items {
		if item.ID != target.ID {
			continue
		}
		seen = true
		if len(item.Passkeys) != 2 || len(item.Passkey) != 0 {
			t.Fatalf("fixture layout: collection=%d legacy=%d", len(item.Passkeys), len(item.Passkey))
		}
	}
	if !seen {
		t.Fatal("fixture login missing from authenticated read")
	}

	row := collectionRow(t, s, target.ID)
	if !row.HasPasskey {
		t.Fatal("native summary lost a collection-only passkey")
	}
	detail, err := s.GetItemDetail(target.ID, row.Revision, false)
	if err != nil || !detail.HasPasskey {
		t.Fatalf("native detail: has_passkey=%v err=%v", detail.HasPasskey, err)
	}
	if flags := watchtowerFlagsFor(t, s, target.ID); passkeyConsumerContainsFlag(flags, "passkey-not-stored") || passkeyConsumerContainsFlag(flags, "totp-not-stored") {
		t.Fatalf("watchtower flags for collection login: %v", flags)
	}
	if flags := browserFlagsFor(t, s, target.ID); passkeyConsumerContainsFlag(flags, "totp-not-stored") {
		t.Fatalf("browser flags for collection login: %v", flags)
	}

	// Removing one of two credentials must keep the login passkey-capable.
	remaining, err := s.RemovePasskey(target.ID, revision, first.ID, dailyGate(t, s))
	if err != nil {
		t.Fatalf("remove first credential: %v", err)
	}
	row = collectionRow(t, s, target.ID)
	if row.Revision != remaining || !row.HasPasskey {
		t.Fatalf("after one removal: revision=%q want %q has_passkey=%v", row.Revision, remaining, row.HasPasskey)
	}
	detail, err = s.GetItemDetail(target.ID, remaining, false)
	if err != nil || !detail.HasPasskey {
		t.Fatalf("detail after one removal: has_passkey=%v err=%v", detail.HasPasskey, err)
	}
	if flags := watchtowerFlagsFor(t, s, target.ID); passkeyConsumerContainsFlag(flags, "passkey-not-stored") || passkeyConsumerContainsFlag(flags, "totp-not-stored") {
		t.Fatalf("watchtower flags after one removal: %v", flags)
	}
	if flags := browserFlagsFor(t, s, target.ID); passkeyConsumerContainsFlag(flags, "totp-not-stored") {
		t.Fatalf("browser flags after one removal: %v", flags)
	}

	// Removing the last credential must clear every passkey-presence signal.
	if _, err = s.RemovePasskey(target.ID, remaining, second.ID, dailyGate(t, s)); err != nil {
		t.Fatalf("remove last credential: %v", err)
	}
	row = collectionRow(t, s, target.ID)
	if row.HasPasskey {
		t.Fatal("native summary still reports a passkey after the last removal")
	}
	detail, err = s.GetItemDetail(target.ID, row.Revision, false)
	if err != nil || detail.HasPasskey {
		t.Fatalf("detail after last removal: has_passkey=%v err=%v", detail.HasPasskey, err)
	}
	if flags := watchtowerFlagsFor(t, s, target.ID); !passkeyConsumerContainsFlag(flags, "passkey-not-stored") || !passkeyConsumerContainsFlag(flags, "totp-not-stored") {
		t.Fatalf("watchtower flags after last removal: %v", flags)
	}
	if flags := browserFlagsFor(t, s, target.ID); !passkeyConsumerContainsFlag(flags, "totp-not-stored") {
		t.Fatalf("browser flags after last removal: %v", flags)
	}
}
