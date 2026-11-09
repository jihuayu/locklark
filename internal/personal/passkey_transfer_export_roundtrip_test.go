package personal

import (
	"bytes"
	"reflect"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/passkey"
	"github.com/jihuayu/locklark/internal/passkeytransfer"
)

func TestPasskeyTransferExportRoundTripExactSelectorsAndNoSourceChange(t *testing.T) {
	s, target, _, _, _ := passkeyMultiFixture(t)
	receiver, public := exportTestReceiver(t)
	invite, err := receiver.NewPasskeyTransferInvitation(5*time.Minute, dailyGate(t, receiver))
	if err != nil {
		t.Fatal(err)
	}
	targets := exportTestTargets(t, s, target.ID)
	if len(targets) != 2 {
		t.Fatalf("targets: %d", len(targets))
	}
	before := rawItems(t, s)
	parentBefore := suggestionsRevision(t, s, target.ID)
	countBefore := rawAuditActionCount(t, s, passkeyTransferExportAction)
	g := dailyGate(t, s)
	export, err := s.ExportPasskeyTransfer(invite.Raw, public.Fingerprint, targets, g)
	if err != nil {
		t.Fatal(err)
	}
	if !g.CommitWon() || !idOK(export.PacketID) || len(export.Raw) == 0 || export.TargetFingerprint != public.Fingerprint {
		t.Fatalf("bad receipt: %+v won=%v", export, g.CommitWon())
	}
	if export.SourceFingerprint != transferTestPublic(t, s).Fingerprint {
		t.Fatal("source fingerprint mismatch")
	}
	if after := rawItems(t, s); !reflect.DeepEqual(after, before) {
		t.Fatal("export changed source encrypted items")
	}
	if parentAfter := suggestionsRevision(t, s, target.ID); parentAfter != parentBefore {
		t.Fatal("export changed the source parent revision")
	}
	if rawAuditActionCount(t, s, passkeyTransferExportAction) != countBefore+1 {
		t.Fatal("export audit count mismatch")
	}
	event := exportTestEvent(t, s, passkeyTransferExportAction)
	if event.Item != export.PacketID || event.BaseRevision != "" || event.Result != "intent" || !digestOK(event.Link) {
		t.Fatalf("unexpected export event: %+v", event)
	}
	own := exportTestRecipient(t, receiver)
	decoded, err := passkeytransfer.OpenSelection(export.Raw, invite.Raw, own, public.Fingerprint, export.SourceFingerprint, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for i := range decoded {
			decoded[i].Clear()
		}
	}()
	if len(decoded) != len(targets) {
		t.Fatalf("decoded %d records, want %d", len(decoded), len(targets))
	}
	for _, target := range targets {
		var found *passkeytransfer.Decoded
		for i := range decoded {
			if decoded[i].CredentialID == target.CredentialID {
				found = &decoded[i]
			}
		}
		if found == nil || found.SourceItemID != target.ItemID || found.SourceRevision != target.Revision || found.CredentialRevision != target.CredentialRevision {
			t.Fatalf("exact selector/opaque revisions lost: %+v", found)
		}
		originalRaw := passkeyRecord(t, s, target.ItemID, target.CredentialID)
		defer clear(originalRaw)
		original, err := passkey.Load(originalRaw)
		if err != nil {
			t.Fatal(err)
		}
		opened, err := passkey.Load(found.Record)
		if err != nil {
			original.Clear()
			t.Fatal(err)
		}
		if !bytes.Equal(original.PrivateKey, opened.PrivateKey) {
			t.Fatal("private key did not round-trip")
		}
		original.Clear()
		opened.Clear()
	}
}
