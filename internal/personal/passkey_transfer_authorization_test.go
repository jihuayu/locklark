package personal

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/vault"
)

// quickUnlockTransferSession converts a full-factor session into a real OS
// quick-unlock session through the existing fake OS store adapter: enroll,
// lock, then unlock through UnlockWithSystem. The returned session is usable
// for ordinary vault work but carries no full-factor proof at all, which is
// exactly the session shape the transfer authorization check must refuse.
func quickUnlockTransferSession(t *testing.T, s *Session) *Session {
	t.Helper()
	store := &testSystemStore{values: map[string][]byte{}}
	if err := s.EnableSystemUnlock(store); err != nil {
		t.Fatalf("enable system unlock: %v", err)
	}
	path := s.path
	s.Lock()
	quick, err := UnlockWithSystem(path, store, time.Minute)
	if err != nil {
		t.Fatalf("system unlock: %v", err)
	}
	if !quick.Unlocked() {
		quick.Lock()
		t.Fatal("quick-unlock session is not active")
	}
	if _, err := quick.List("active"); err != nil {
		quick.Lock()
		t.Fatalf("quick-unlock session cannot read the vault: %v", err)
	}
	// The audit trail of the enrollment does not matter here; what matters is
	// that OS quick unlock never fabricates a full-factor timestamp.
	quick.mu.Lock()
	zero := quick.fullUnlock.IsZero()
	quick.mu.Unlock()
	if !zero {
		quick.Lock()
		t.Fatal("OS quick unlock copied a full-factor timestamp into the session")
	}
	t.Cleanup(quick.Lock)
	return quick
}

// setFullFactorTime rewrites the session's full-factor timestamp under
// Session.mu, which is the only mutex that ever guards that field.
func setFullFactorTime(t *testing.T, s *Session, at time.Time) {
	t.Helper()
	if at.IsZero() {
		t.Fatal("test must set an explicit full-factor timestamp")
	}
	s.mu.Lock()
	s.fullUnlock = at
	s.mu.Unlock()
}

func transferItemsForCompare(t *testing.T, s *Session) []vault.Item {
	t.Helper()
	items := rawItems(t, s)
	for i := range items {
		items[i].ClearPasskeys()
	}
	return items
}

// expectTransferRefused requires the shared full-factor refusal with no
// observable vault progress: no audit row of any transfer action, no item or
// revocation-epoch change, no released output and no won or still-registered
// mutation gate.
func expectTransferRefused(t *testing.T, s *Session, label string, act func(g *MutationGate) error) {
	t.Helper()
	beforeItems := transferItemsForCompare(t, s)
	beforeAudit := rawAuditCountNoSession(t, s.path)
	beforeInvites := rawAuditActionCount(t, s, passkeyTransferInviteAction)
	beforeRevokes := rawAuditActionCount(t, s, passkeyTransferRevokeAction)
	beforeExports := rawAuditActionCount(t, s, passkeyTransferExportAction)
	beforeConsumes := rawAuditActionCount(t, s, passkeyTransferConsumeAction)
	beforeEpoch := s.PasskeyRevocationEpoch()

	g := dailyGate(t, s)
	err := act(g)
	if !errors.Is(err, ErrFullFactorRequired) {
		t.Fatalf("%s returned %v, want ErrFullFactorRequired", label, err)
	}
	if g.CommitWon() || s.registeredMutation(g) {
		t.Fatalf("%s won or kept the mutation gate", label)
	}
	if rawAuditCountNoSession(t, s.path) != beforeAudit {
		t.Fatalf("%s appended an audit event", label)
	}
	if rawAuditActionCount(t, s, passkeyTransferInviteAction) != beforeInvites {
		t.Fatalf("%s changed the invitation count", label)
	}
	if rawAuditActionCount(t, s, passkeyTransferRevokeAction) != beforeRevokes {
		t.Fatalf("%s changed the revocation count", label)
	}
	if rawAuditActionCount(t, s, passkeyTransferExportAction) != beforeExports {
		t.Fatalf("%s changed the export count", label)
	}
	if rawAuditActionCount(t, s, passkeyTransferConsumeAction) != beforeConsumes {
		t.Fatalf("%s consumed the invitation", label)
	}
	if s.PasskeyRevocationEpoch() != beforeEpoch {
		t.Fatalf("%s revoked queued passkey authority", label)
	}
	if afterItems := transferItemsForCompare(t, s); !reflect.DeepEqual(beforeItems, afterItems) {
		t.Fatalf("%s changed encrypted items", label)
	}
}

// TestPasskeyTransferRefusesRealQuickUnlockSession is the material
// authorization case: an OS quick-unlock session can read and edit the vault,
// but it must refuse invitation creation, revocation, preview and import
// without opening the database or returning any output.
func TestPasskeyTransferRefusesRealQuickUnlockSession(t *testing.T) {
	_, receiver, invite, export, plan, _, _, _ := transferApplyPlanFixture(t, 5*time.Minute)
	mapping := transferApplyNewMapping(plan, "Quick Unlock Parent", "")
	quick := quickUnlockTransferSession(t, receiver)

	expectTransferRefused(t, quick, "quick-unlock invite", func(g *MutationGate) error {
		out, err := quick.NewPasskeyTransferInvitation(5*time.Minute, g)
		if out.Raw != nil || out.ID != "" || out.Public.Fingerprint != "" {
			t.Fatalf("refused invitation leaked output: %+v", out)
		}
		return err
	})
	expectTransferRefused(t, quick, "quick-unlock revoke", func(g *MutationGate) error {
		return quick.RevokePasskeyTransferInvitation(invite.Raw, g)
	})
	expectTransferRefused(t, quick, "quick-unlock plan", func(g *MutationGate) error {
		g.Cancel()
		quick.ReleaseMutation(g)
		out, err := quick.PlanPasskeyTransfer(invite.Raw, export.Raw, export.SourceFingerprint)
		if out.Digest != "" || len(out.Groups) != 0 || out.InvitationID != "" {
			t.Fatalf("refused plan leaked preview: %+v", out)
		}
		return err
	})
	expectTransferRefused(t, quick, "quick-unlock apply", func(g *MutationGate) error {
		out, err := quick.ApplyPasskeyTransfer(invite.Raw, export.Raw, export.SourceFingerprint, plan.Digest, []PasskeyTransferMapping{mapping}, g)
		if len(out.Items) != 0 {
			t.Fatalf("refused import leaked receipt: %+v", out)
		}
		return err
	})
}

// TestPasskeyTransferExportRefusesRealQuickUnlockSession covers the source side
// of the same gap with a real OS quick-unlock session.
func TestPasskeyTransferExportRefusesRealQuickUnlockSession(t *testing.T) {
	source, sourceTarget, _, _, _ := passkeyMultiFixture(t)
	receiver, public := exportTestReceiver(t)
	invite, err := receiver.NewPasskeyTransferInvitation(5*time.Minute, dailyGate(t, receiver))
	if err != nil {
		t.Fatalf("invite: %v", err)
	}
	targets := exportTestTargets(t, source, sourceTarget.ID)
	quick := quickUnlockTransferSession(t, source)

	expectTransferRefused(t, quick, "quick-unlock export", func(g *MutationGate) error {
		out, err := quick.ExportPasskeyTransfer(invite.Raw, public.Fingerprint, targets, g)
		if out.Raw != nil || out.PacketID != "" || out.SourceFingerprint != "" || out.TargetFingerprint != "" {
			t.Fatalf("refused export leaked a packet: %+v", out)
		}
		return err
	})
}

// TestPasskeyTransferRefusesStaleOrFutureFullFactor pins the explicit window:
// an expired proof and a future proof both fail closed for every entry point,
// and ordinary activity in the same session does not renew the proof.
func TestPasskeyTransferRefusesStaleOrFutureFullFactor(t *testing.T) {
	for _, tc := range []struct {
		name string
		at   func() time.Time
	}{
		{"stale-exactly-window", func() time.Time { return time.Now().Add(-passkeyTransferFullFactorWindow) }},
		{"future", func() time.Time { return time.Now().Add(time.Minute) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source, sourceTarget, _, _, _ := passkeyMultiFixture(t)
			receiver, public := exportTestReceiver(t)
			context := BrowserContext{RequestID: "55555555555555555555555555555555", Origin: "https://example.test", TabID: 5, DocumentID: "document-5"}
			if _, err := receiver.PerformPasskey(transferPlanLoginTarget(context, "", ""), false, dailyGate(t, receiver)); err != nil {
				t.Fatalf("receiver login: %v", err)
			}
			invite, err := receiver.NewPasskeyTransferInvitation(5*time.Minute, dailyGate(t, receiver))
			if err != nil {
				t.Fatalf("invite: %v", err)
			}
			targets := exportTestTargets(t, source, sourceTarget.ID)
			export, err := source.ExportPasskeyTransfer(invite.Raw, public.Fingerprint, targets, dailyGate(t, source))
			if err != nil {
				t.Fatalf("export: %v", err)
			}
			plan, err := receiver.PlanPasskeyTransfer(invite.Raw, export.Raw, export.SourceFingerprint)
			if err != nil {
				t.Fatalf("plan: %v", err)
			}
			mapping := transferApplyNewMapping(plan, "Unproven Parent", "")

			setFullFactorTime(t, receiver, tc.at())
			// An ordinary read keeps the idle timer warm but must never renew
			// the full-factor proof.
			if _, err := receiver.List("active"); err != nil {
				t.Fatalf("stale session read: %v", err)
			}
			expectTransferRefused(t, receiver, tc.name+" invite", func(g *MutationGate) error {
				out, err := receiver.NewPasskeyTransferInvitation(5*time.Minute, g)
				if out.Raw != nil || out.ID != "" {
					t.Fatalf("refused invitation leaked output: %+v", out)
				}
				return err
			})
			expectTransferRefused(t, receiver, tc.name+" revoke", func(g *MutationGate) error {
				return receiver.RevokePasskeyTransferInvitation(invite.Raw, g)
			})
			expectTransferRefused(t, receiver, tc.name+" plan", func(g *MutationGate) error {
				g.Cancel()
				receiver.ReleaseMutation(g)
				out, err := receiver.PlanPasskeyTransfer(invite.Raw, export.Raw, export.SourceFingerprint)
				if out.Digest != "" || len(out.Groups) != 0 {
					t.Fatalf("refused plan leaked preview: %+v", out)
				}
				return err
			})
			expectTransferRefused(t, receiver, tc.name+" apply", func(g *MutationGate) error {
				out, err := receiver.ApplyPasskeyTransfer(invite.Raw, export.Raw, export.SourceFingerprint, plan.Digest, []PasskeyTransferMapping{mapping}, g)
				if len(out.Items) != 0 {
					t.Fatalf("refused import leaked receipt: %+v", out)
				}
				return err
			})

			setFullFactorTime(t, source, tc.at())
			expectTransferRefused(t, source, tc.name+" export", func(g *MutationGate) error {
				out, err := source.ExportPasskeyTransfer(invite.Raw, public.Fingerprint, targets, g)
				if out.Raw != nil || out.PacketID != "" {
					t.Fatalf("refused export leaked a packet: %+v", out)
				}
				return err
			})
		})
	}
}

// TestPasskeyTransferFreshFullFactorStillAuthorizes is the positive control:
// every transfer entry point still works immediately after an explicit full
// unlock, including export, preview and import in one chained fixture.
func TestPasskeyTransferFreshFullFactorStillAuthorizes(t *testing.T) {
	source, receiver, invite, export, plan, targets, _, _ := transferApplyPlanFixture(t, 5*time.Minute)

	preview, err := receiver.PlanPasskeyTransfer(invite.Raw, export.Raw, export.SourceFingerprint)
	if err != nil || preview.Digest != plan.Digest {
		t.Fatalf("fresh plan: err=%v digest=%q want=%q", err, preview.Digest, plan.Digest)
	}
	receipt, err := receiver.ApplyPasskeyTransfer(invite.Raw, export.Raw, export.SourceFingerprint, plan.Digest, []PasskeyTransferMapping{transferApplyNewMapping(plan, "Fresh Parent", "")}, dailyGate(t, receiver))
	if err != nil || len(receipt.Items) != 1 {
		t.Fatalf("fresh import: err=%v receipt=%+v", err, receipt)
	}

	next, err := receiver.NewPasskeyTransferInvitation(5*time.Minute, dailyGate(t, receiver))
	if err != nil {
		t.Fatalf("fresh invite: %v", err)
	}
	second, err := source.ExportPasskeyTransfer(next.Raw, next.Public.Fingerprint, targets, dailyGate(t, source))
	if err != nil || second.PacketID == "" || second.TargetFingerprint != next.Public.Fingerprint {
		t.Fatalf("fresh export: err=%v packet=%+v", err, second)
	}
	if err := receiver.RevokePasskeyTransferInvitation(next.Raw, dailyGate(t, receiver)); err != nil {
		t.Fatalf("fresh revoke: %v", err)
	}
}

// TestPasskeyTransferPlanRequiresFreshFullFactor pins the read-only preview to
// the same proof as the mutating actions. This package has no seam that can
// pause a bbolt read transaction, so the case here is the observable one: a
// stale, future or absent proof is refused with no preview and no vault change,
// and a fresh explicit unlock immediately plans again.
func TestPasskeyTransferPlanRequiresFreshFullFactor(t *testing.T) {
	_, receiver, invite, export, plan, _, _, _ := transferApplyPlanFixture(t, 5*time.Minute)
	preview, err := receiver.PlanPasskeyTransfer(invite.Raw, export.Raw, export.SourceFingerprint)
	if err != nil || preview.Digest != plan.Digest {
		t.Fatalf("fresh plan: err=%v digest=%q want=%q", err, preview.Digest, plan.Digest)
	}
	for _, tc := range []struct {
		name string
		at   time.Time
	}{
		{"stale-exactly-window", time.Now().Add(-passkeyTransferFullFactorWindow)},
		{"future", time.Now().Add(time.Minute)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setFullFactorTime(t, receiver, tc.at)
			// Session reads are themselves audited, so the baseline is taken
			// immediately before the refused preview.
			beforeAudit := rawAuditCountNoSession(t, receiver.path)
			beforeItems := transferItemsForCompare(t, receiver)
			out, err := receiver.PlanPasskeyTransfer(invite.Raw, export.Raw, export.SourceFingerprint)
			if !errors.Is(err, ErrFullFactorRequired) {
				t.Fatalf("%s plan returned %v, want ErrFullFactorRequired", tc.name, err)
			}
			if out.Digest != "" || out.InvitationID != "" || len(out.Groups) != 0 || !out.ExpiresAt.IsZero() {
				t.Fatalf("%s plan released a preview: %+v", tc.name, out)
			}
			if now := rawAuditCountNoSession(t, receiver.path); now != beforeAudit {
				t.Fatalf("%s plan changed the audit count: %d -> %d", tc.name, beforeAudit, now)
			}
			if afterItems := transferItemsForCompare(t, receiver); !reflect.DeepEqual(beforeItems, afterItems) {
				t.Fatalf("%s plan changed encrypted items", tc.name)
			}
			// The session is still unlocked for ordinary work: only the
			// transfer proof is missing. This read is audited, so it runs
			// after the audit-count comparison.
			if _, err := receiver.List("active"); err != nil {
				t.Fatalf("%s session read: %v", tc.name, err)
			}
		})
	}
	setFullFactorTime(t, receiver, time.Now())
	again, err := receiver.PlanPasskeyTransfer(invite.Raw, export.Raw, export.SourceFingerprint)
	if err != nil || again.Digest != plan.Digest {
		t.Fatalf("restored fresh plan: err=%v digest=%q want=%q", err, again.Digest, plan.Digest)
	}
}
