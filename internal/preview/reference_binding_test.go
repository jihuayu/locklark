package preview

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/jihuayu/locklark/internal/reference"
)

func TestBindFixtureReferenceMetadata(t *testing.T) {
	m, items, pin := nativeReferenceFixture(t)
	for _, tc := range []struct {
		section, field string
		slot           reference.NativeSlot
		kind           reference.ValueType
	}{{"", "password", reference.SlotPassword, reference.TypePassword}, {"ops", "otp-demo", reference.SlotOTP, reference.TypeOTP}} {
		target := reference.Target{VaultID: "synthetic-vault", ItemID: "login-sample", SectionID: tc.section, FieldID: tc.field, Revision: fixtureReferenceRevision + pin}
		got, err := BindFixtureReferenceMetadata(nativeReferenceJSON(t, m), items, pin, target)
		want := reference.Binding{Profile: fixtureReferenceProfile, Target: target, Slot: tc.slot, Type: tc.kind}
		if err != nil || got != want {
			t.Fatal("source field mapped to wrong native slot/type", got, err)
		}
		raw, _ := json.Marshal(got)
		for _, secret := range []string{items[0].Password, items[0].OTP, items[1].Filename, string(items[1].Attachment)} {
			if secret != "" && bytes.Contains(raw, []byte(secret)) {
				t.Fatal("source binding copied private values")
			}
		}
		items[0].Password, items[0].OTP = "", ""
		again, err := BindFixtureReferenceMetadata(nativeReferenceJSON(t, m), items, pin, target)
		if err != nil || again != got {
			t.Fatal("private values changed source binding", err)
		}
		m, items, pin = nativeReferenceFixture(t)
	}
}

func TestBindFixtureRejectsUnboundTargets(t *testing.T) {
	for _, problem := range []string{"stale", "document", "personal-field", "root-fallback", "source-alias", "cross-profile", "missing-profile", "rebound-slot"} {
		t.Run(problem, func(t *testing.T) {
			m, items, pin := nativeReferenceFixture(t)
			target := reference.Target{VaultID: "synthetic-vault", ItemID: "login-sample", SectionID: "ops", FieldID: "otp-demo", Revision: fixtureReferenceRevision + pin}
			want := error(reference.ErrNotFound)
			switch problem {
			case "stale":
				target.Revision = fixtureReferenceRevision + strings.Repeat("b", 128)
				want = reference.ErrStale
			case "document":
				target.ItemID = "document-sample"
			case "personal-field":
				target.FieldID = "otp"
			case "root-fallback":
				target.SectionID = ""
			case "source-alias":
				target.FieldID = "TOTP"
			case "cross-profile":
				target = reference.Target{VaultID: "personal-vault", ItemID: strings.Repeat("a", 32), FieldID: "otp", Revision: strings.Repeat("1", 64)}
			case "missing-profile":
				m.Layout = nil
				want = ErrFixtureReferenceProfile
			case "rebound-slot":
				m.Layout.Slots[0], m.Layout.Slots[1] = m.Layout.Slots[1], m.Layout.Slots[0]
				want = ErrFixtureReferenceMetadata
			}
			got, err := BindFixtureReferenceMetadata(nativeReferenceJSON(t, m), items, pin, target)
			if !errors.Is(err, want) || got != (reference.Binding{}) {
				t.Fatal("unbound source target returned a descriptor", got, err)
			}
		})
	}
}
