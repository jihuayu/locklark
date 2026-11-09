package personal

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestPasskeyTransferExportPublicReceiptAndInvitationFmtRedacted(t *testing.T) {
	id := strings.Repeat("a", 32)
	fingerprint := strings.Repeat("b", 64)
	export := PasskeyTransferExport{Raw: []byte("ciphertext-marker"), PacketID: id, SourceFingerprint: fingerprint, TargetFingerprint: fingerprint}
	for _, got := range []string{fmt.Sprintf("%v", export), fmt.Sprintf("%+v", export), fmt.Sprintf("%#v", export)} {
		if strings.Contains(got, "ciphertext-marker") || strings.Contains(got, id) {
			t.Fatalf("export fmt leaked bytes: %q", got)
		}
	}
	if _, err := json.Marshal(export); err == nil {
		t.Fatal("export receipt JSON was not refused")
	}
	invite := PasskeyTransferInvitation{Raw: []byte("invite-marker"), ID: id}
	for _, got := range []string{fmt.Sprintf("%v", invite), fmt.Sprintf("%+v", invite), fmt.Sprintf("%#v", invite), fmt.Sprintf("%v", &invite), fmt.Sprintf("%#v", &invite)} {
		if strings.Contains(got, "invite-marker") || strings.Contains(got, id) {
			t.Fatalf("invitation fmt leaked bytes: %q", got)
		}
	}
}

func TestPasskeyTransferExportAuditColdReplayAndNoRawSelectors(t *testing.T) {
	s, target, path, key := exportTestSource(t)
	if _, err := s.PerformPasskey(target, false, dailyGate(t, s)); err != nil {
		t.Fatal(err)
	}
	receiver, public := exportTestReceiver(t)
	invite, err := receiver.NewPasskeyTransferInvitation(5*time.Minute, dailyGate(t, receiver))
	if err != nil {
		t.Fatal(err)
	}
	targets := exportTestTargets(t, s, target.ID)
	export, err := s.ExportPasskeyTransfer(invite.Raw, public.Fingerprint, targets, dailyGate(t, s))
	if err != nil {
		t.Fatal(err)
	}
	event := exportTestEvent(t, s, passkeyTransferExportAction)
	if event.Action != passkeyTransferExportAction || event.Item != export.PacketID || event.Result != "intent" || event.BaseRevision != "" || !digestOK(event.Link) {
		t.Fatalf("unexpected export event: %+v", event)
	}
	eventJSON, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range targets {
		for _, raw := range [][]byte{[]byte(target.ItemID), []byte(target.CredentialID), []byte(target.Revision), []byte(target.CredentialRevision)} {
			if bytes.Contains(eventJSON, raw) {
				t.Fatalf("raw selector leaked into audit event: %q", raw)
			}
		}
	}
	revisions := map[string]string{}
	if err := applyAuditRevision(event, event.hash(), revisions); err != nil || len(revisions) != 0 {
		t.Fatalf("export intent changed item revisions: %v %v", err, revisions)
	}
	fresh, err := UnlockSession(path, []byte("fixture"), key, time.Minute)
	if err != nil {
		t.Fatalf("cold reopen failed: %v", err)
	}
	defer fresh.Lock()
	events, err := fresh.Audit()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, candidate := range events {
		if candidate.Action == passkeyTransferExportAction && candidate.Item == export.PacketID {
			found = true
		}
	}
	if !found {
		t.Fatal("cold replay lost the export intent")
	}
}
