package personal

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestPasskeyTransferExportRefusalsLeaveNoAuditIntent(t *testing.T) {
	s, target, _, _, _ := passkeyMultiFixture(t)
	receiver, public := exportTestReceiver(t)
	invite, err := receiver.NewPasskeyTransferInvitation(5*time.Minute, dailyGate(t, receiver))
	if err != nil {
		t.Fatal(err)
	}
	targets := exportTestTargets(t, s, target.ID)
	if len(targets) == 0 {
		t.Fatal("no export targets")
	}
	expired := exportTestExpiredInvite(t, receiver, public.Fingerprint)
	sourcePin := transferTestPublic(t, s).Fingerprint
	staleParent := exportCloneTargets(targets)
	staleParent[0].Revision = strings.Repeat("a", 64)
	staleChild := exportCloneTargets(targets)
	staleChild[0].CredentialRevision = strings.Repeat("b", 64)
	duplicate := append(exportCloneTargets(targets), targets[0])
	wrongItem := []PasskeyTransferTarget{{ItemID: strings.Repeat("b", 32), Revision: targets[0].Revision, CredentialID: targets[0].CredentialID, CredentialRevision: targets[0].CredentialRevision}}
	badSelector := exportCloneTargets(targets)
	badSelector[0].ItemID = "short"
	cases := []struct {
		name    string
		raw     []byte
		pin     string
		targets []PasskeyTransferTarget
	}{
		{"stale-parent", invite.Raw, public.Fingerprint, staleParent},
		{"stale-child", invite.Raw, public.Fingerprint, staleChild},
		{"foreign-pin", invite.Raw, sourcePin, exportCloneTargets(targets)},
		{"expired", expired, public.Fingerprint, exportCloneTargets(targets)},
		{"duplicate", invite.Raw, public.Fingerprint, duplicate},
		{"wrong-item", invite.Raw, public.Fingerprint, wrongItem},
		{"bad-selector", invite.Raw, public.Fingerprint, badSelector},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := rawAuditActionCount(t, s, passkeyTransferExportAction)
			g := dailyGate(t, s)
			out, err := s.ExportPasskeyTransfer(tc.raw, tc.pin, tc.targets, g)
			if err == nil {
				t.Fatalf("refusal accepted: %+v won=%v", out, g.CommitWon())
			}
			if out.PacketID != "" || out.Raw != nil {
				t.Fatal("refusal returned a packet")
			}
			if rawAuditActionCount(t, s, passkeyTransferExportAction) != before {
				t.Fatal("refusal appended an export intent")
			}
		})
	}
	before := rawAuditActionCount(t, s, passkeyTransferExportAction)
	unregistered := NewMutationGate(time.Now().Add(time.Minute))
	if _, err := s.ExportPasskeyTransfer(invite.Raw, public.Fingerprint, targets, unregistered); !errors.Is(err, ErrMutationCancelled) {
		t.Fatalf("unregistered gate returned %v", err)
	}
	if rawAuditActionCount(t, s, passkeyTransferExportAction) != before {
		t.Fatal("unregistered gate appended an export intent")
	}
}
