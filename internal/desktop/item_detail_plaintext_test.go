package desktop

import (
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
)

func detailPlainFixture() *personal.ItemDetail {
	return &personal.ItemDetail{
		ID:       "item-plain",
		Revision: "revision-plain",
		Username: "synthetic-user",
		Password: "synthetic-password",
		Notes:    "synthetic-notes",
	}
}

func TestRevealFieldHidingOneFieldKeepsTimerAndPlaintextForTheRest(t *testing.T) {
	a := New()
	a.v2.detail = detailPlainFixture()
	a.v2.detailPlain = detailPlainFixture()
	a.v2.revealed = map[string]bool{"password": true, "notes": true}
	until := time.Now().Add(10 * time.Second)
	a.v2.revealUntil = until

	a.revealField("notes")

	if a.v2.revealed["notes"] || !a.v2.revealed["password"] {
		t.Fatalf("revealed = %#v after hiding one field", a.v2.revealed)
	}
	if a.v2.revealUntil != until {
		t.Fatal("hiding one field disarmed the remaining field's timer")
	}
	if a.v2.detailPlain == nil {
		t.Fatal("hiding one field dropped plaintext still needed by the other")
	}

	a.revealField("password")
	if !a.v2.revealUntil.IsZero() {
		t.Fatal("hiding the last field left the timer armed")
	}
	if a.v2.detailPlain != nil {
		t.Fatal("hiding the last field retained the plaintext detail")
	}
}

func TestHidingLastFieldWhileLargeTypeOpenRetainsPlaintextUntilClose(t *testing.T) {
	a := New()
	a.v2.detail = detailPlainFixture()
	a.v2.detailPlain = detailPlainFixture()
	a.v2.revealed = map[string]bool{"password": true}
	a.v2.revealUntil = time.Now().Add(10 * time.Second)
	a.v2.largeTypeOpen = true
	a.v2.largeTypeValue = "synthetic-password"

	a.revealField("password")
	if !a.v2.revealUntil.IsZero() {
		t.Fatal("hiding the last revealed field left the timer armed")
	}
	if a.v2.detailPlain == nil {
		t.Fatal("large type lost the plaintext detail it still owns")
	}

	a.closeLargeType()
	if a.v2.largeTypeOpen || a.v2.largeTypeValue != "" {
		t.Fatal("close large type retained its display state")
	}
	if a.v2.detailPlain != nil {
		t.Fatal("close large type retained the plaintext detail")
	}
}

func TestClosingLargeTypeKeepsPlaintextWhileAFieldRemainsRevealed(t *testing.T) {
	a := New()
	a.v2.detail = detailPlainFixture()
	a.v2.detailPlain = detailPlainFixture()
	a.v2.revealed = map[string]bool{"password": true}
	a.v2.largeTypeOpen = true
	a.v2.largeTypeValue = "synthetic-password"

	a.closeLargeType()

	if a.v2.detailPlain == nil {
		t.Fatal("closing large type dropped plaintext still needed by the revealed field")
	}
}

func TestCopyNonConcealedFieldUsesMaskedDetailAndReleasesPlaintext(t *testing.T) {
	a := New()
	clip := attachFakeClipboard(a)
	a.v2.detail = detailPlainFixture()
	a.v2.detailPlain = detailPlainFixture()

	a.copyField("username")

	if clip.value != "synthetic-user" {
		t.Fatalf("copied %q, want the masked detail's username", clip.value)
	}
	if a.v2.detailPlain != nil {
		t.Fatal("copying a non-concealed field loaded or retained the full plaintext detail")
	}
}

func TestCopyConcealedFieldReleasesPlaintextAfterTheClipboardWrite(t *testing.T) {
	a := dailyAppFixture(t)
	a.launch = func(fn func()) { fn() }
	a.dispatch = func(fn func()) { fn() }
	clip := attachFakeClipboard(a)
	id, err := a.session.AddLogin("synthetic copy", "synthetic-user", "synthetic-secret")
	if err != nil {
		t.Fatal(err)
	}
	row := bugfixRow(t, a, id)
	a.v2.detail = &personal.ItemDetail{ID: row.ID, Revision: row.Revision, Kind: "login"}

	a.copyField("password")

	if clip.value != "synthetic-secret" {
		t.Fatalf("copied %q, want the concealed password", clip.value)
	}
	if a.v2.detailPlain != nil {
		t.Fatal("copy retained the full plaintext detail without an active disclosure")
	}
}
