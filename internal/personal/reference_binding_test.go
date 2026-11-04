package personal

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/jihuayu/locklark/internal/reference"
)

func TestBindPersonalReferenceMetadata(t *testing.T) {
	items, revs := referenceFixture()
	for _, tc := range []struct {
		field string
		slot  reference.NativeSlot
		kind  reference.ValueType
	}{{"username", reference.SlotUsername, reference.TypeText}, {"password", reference.SlotPassword, reference.TypePassword}, {"otp", reference.SlotOTP, reference.TypeOTP}} {
		target := reference.Target{VaultID: "personal-vault", ItemID: items[0].ID, FieldID: tc.field, Revision: revs[items[0].ID]}
		got, err := BindReferenceMetadata([]byte(schema), "personal-vault", "Work", items, revs, target)
		want := reference.Binding{Profile: schema, Target: target, Slot: tc.slot, Type: tc.kind}
		if err != nil || got != want {
			t.Fatal("native slot/type binding failed", got, err)
		}
		raw, _ := json.Marshal(got)
		for _, secret := range []string{items[0].Username, items[0].Password, items[0].OTP, items[1].Filename, string(items[1].Attachment)} {
			if bytes.Contains(raw, []byte(secret)) {
				t.Fatal("binding copied native private values")
			}
		}
		items[0].Username, items[0].Password, items[0].OTP = "", "", ""
		again, err := BindReferenceMetadata([]byte(schema), "personal-vault", "Work", items, revs, target)
		if err != nil || again != got {
			t.Fatal("empty native values changed binding", err)
		}
		items, revs = referenceFixture()
	}
}

func TestBindPersonalRejectsUnboundTargets(t *testing.T) {
	for _, problem := range []string{"stale", "document", "section", "alias", "source-field", "cross-profile", "unknown-profile", "missing-revision"} {
		t.Run(problem, func(t *testing.T) {
			items, revs := referenceFixture()
			meta := []byte(schema)
			target := reference.Target{VaultID: "personal-vault", ItemID: items[0].ID, FieldID: "password", Revision: revs[items[0].ID]}
			want := error(reference.ErrNotFound)
			switch problem {
			case "stale":
				target.Revision = "old-revision"
				want = reference.ErrStale
			case "document":
				target.ItemID, target.Revision = items[1].ID, revs[items[1].ID]
			case "section":
				target.SectionID = "ops"
			case "alias":
				target.FieldID = "PASSWORD"
			case "source-field":
				target.SectionID, target.FieldID = "ops", "otp-demo"
			case "cross-profile":
				target = reference.Target{VaultID: "synthetic-vault", ItemID: "login-sample", FieldID: "password", Revision: "snapshot-signature-v1:" + strings.Repeat("a", 128)}
			case "unknown-profile":
				meta = []byte("locklark/synthetic/native-fixture/v1")
				want = ErrReferenceProfile
			case "missing-revision":
				delete(revs, items[1].ID)
				want = ErrReferenceMetadata
			}
			got, err := BindReferenceMetadata(meta, "personal-vault", "Work", items, revs, target)
			if !errors.Is(err, want) || got != (reference.Binding{}) {
				t.Fatal("unbound target returned a descriptor", got, err)
			}
		})
	}
}
