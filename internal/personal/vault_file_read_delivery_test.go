//go:build darwin || linux

package personal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"
)

type readDeliveryChildren struct {
	selected VaultFileChildToken
	sibling  VaultFileChildToken
	vault    ownedChildVault
}

func clearReadDeliveryItems(items []VaultFileBaselineItem) {
	for i := range items {
		items[i] = VaultFileBaselineItem{}
	}
}

func openReadDeliveryChildren(t *testing.T, fx *ownedChildFixture) readDeliveryChildren {
	t.Helper()
	sibling := fx.addVault(t, "b")
	selected, selectedItems, err := fx.session.OpenOwnedVaultFileChild(
		fx.a.journal, fx.a.checkpoint, fx.password, fx.key, VaultFileChildOptions{})
	if err != nil {
		t.Fatal("READ_DELIVERY_SELECTED_OPEN_FAILED")
	}
	clearReadDeliveryItems(selectedItems)
	siblingToken, siblingItems, err := fx.session.OpenOwnedVaultFileChild(
		sibling.journal, sibling.checkpoint, fx.password, fx.key, VaultFileChildOptions{})
	if err != nil {
		t.Fatal("READ_DELIVERY_SIBLING_OPEN_FAILED")
	}
	clearReadDeliveryItems(siblingItems)
	return readDeliveryChildren{selected: selected, sibling: siblingToken, vault: sibling}
}

func beginReadDeliveryClaim(t *testing.T, s *Session, token VaultFileChildToken) *VaultFileReadDeliveryClaim {
	t.Helper()
	claim, err := s.BeginVaultFileReadDeliveryClaim(token)
	if err != nil || claim == nil {
		t.Fatal("READ_DELIVERY_BEGIN_FAILED")
	}
	return claim
}

func closeReadDeliveryClaim(t *testing.T, claim *VaultFileReadDeliveryClaim, s *Session) {
	t.Helper()
	if err := claim.CloseChild(s); err != nil {
		t.Fatal("READ_DELIVERY_CLOSE_FAILED")
	}
}

func readDeliveryMaterialLen(s *Session) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.material)
}

func readDeliverySiblingOK(t *testing.T, s *Session, token VaultFileChildToken) {
	t.Helper()
	items, err := s.ReadVaultFileChild(token, VaultFileChildOptions{})
	if err != nil {
		t.Fatal("READ_DELIVERY_SIBLING_REVOKED")
	}
	clearReadDeliveryItems(items)
}

func TestVaultFileReadDeliveryClaimParentIdleCleanup(t *testing.T) {
	fx := newOwnedChildFixture(t)
	if err := fx.session.SetIdleTimeout(0); err != nil {
		t.Fatal("READ_DELIVERY_IDLE_DISABLE_FAILED")
	}
	children := openReadDeliveryChildren(t, fx)
	if err := fx.session.SetIdleTimeout(30 * time.Second); err != nil {
		t.Fatal("READ_DELIVERY_IDLE_SET_FAILED")
	}
	claim := beginReadDeliveryClaim(t, fx.session, children.selected)
	closeReadDeliveryClaim(t, claim, fx.session)
	sample := time.Now().Add(time.Minute)
	vaultFileReadDeliveryClaimTestHook = func(stage string) time.Time {
		if stage != "sample-time" {
			return time.Now()
		}
		return sample
	}
	defer func() { vaultFileReadDeliveryClaimTestHook = nil }()

	if err := claim.Consume(context.Background(), fx.session); !errors.Is(err, ErrSessionLocked) {
		t.Fatal("READ_DELIVERY_PARENT_IDLE_NOT_DISTINGUISHED")
	}
	if readDeliveryMaterialLen(fx.session) != 0 {
		t.Fatal("READ_DELIVERY_PARENT_MATERIAL_NOT_DRAINED")
	}
	if ownedChildAt(fx.session, children.vault.journal) != nil || ownedChildAllCount(fx.session) != 0 {
		t.Fatal("READ_DELIVERY_SIBLING_NOT_REVOKED")
	}
	if _, err := fx.session.ReadVaultFileChild(children.sibling, VaultFileChildOptions{}); err == nil {
		t.Fatal("READ_DELIVERY_SIBLING_STILL_READABLE")
	}
}

func TestVaultFileReadDeliveryClaimChildExpiryPreservesParent(t *testing.T) {
	fx := newOwnedChildFixture(t)
	if err := fx.session.SetIdleTimeout(0); err != nil {
		t.Fatal("READ_DELIVERY_CHILD_IDLE_DISABLE_FAILED")
	}
	children := openReadDeliveryChildren(t, fx)
	claim := beginReadDeliveryClaim(t, fx.session, children.selected)
	closeReadDeliveryClaim(t, claim, fx.session)
	if _, err := fx.session.BeginVaultFileReadDeliveryClaim(children.selected); !errors.Is(err, ErrVaultFileScopedChild) {
		t.Fatal("READ_DELIVERY_RETIRED_TOKEN_REAUTHORIZED")
	}
	vaultFileReadDeliveryClaimTestHook = func(stage string) time.Time {
		if stage != "sample-time" {
			return time.Now()
		}
		return claim.state.fullFactorDeadline.Add(time.Nanosecond)
	}
	defer func() { vaultFileReadDeliveryClaimTestHook = nil }()

	if err := claim.Consume(context.Background(), fx.session); !errors.Is(err, ErrVaultFileScopedChild) {
		t.Fatal("READ_DELIVERY_EXPIRED_CHILD_ACCEPTED")
	}
	if readDeliveryMaterialLen(fx.session) == 0 {
		t.Fatal("READ_DELIVERY_CHILD_EXPIRY_LOCKED_PARENT")
	}
	if ownedChildAt(fx.session, children.vault.journal) == nil {
		t.Fatal("READ_DELIVERY_CHILD_EXPIRY_DRAINED_SIBLING")
	}
	readDeliverySiblingOK(t, fx.session, children.sibling)
}

func TestVaultFileReadDeliveryClaimCancellationPreservesParent(t *testing.T) {
	fx := newOwnedChildFixture(t)
	if err := fx.session.SetIdleTimeout(0); err != nil {
		t.Fatal("READ_DELIVERY_CANCEL_IDLE_DISABLE_FAILED")
	}
	children := openReadDeliveryChildren(t, fx)
	claim := beginReadDeliveryClaim(t, fx.session, children.selected)
	closeReadDeliveryClaim(t, claim, fx.session)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := claim.Consume(ctx, fx.session); !errors.Is(err, context.Canceled) {
		t.Fatal("READ_DELIVERY_CANCEL_NOT_PRESERVED")
	}
	if readDeliveryMaterialLen(fx.session) == 0 {
		t.Fatal("READ_DELIVERY_CANCEL_LOCKED_PARENT")
	}
	if ownedChildAt(fx.session, children.vault.journal) == nil {
		t.Fatal("READ_DELIVERY_CANCEL_DRAINED_SIBLING")
	}
	readDeliverySiblingOK(t, fx.session, children.sibling)
}

func TestVaultFileReadDeliveryClaimSuccessAcrossCopy(t *testing.T) {
	fx := newOwnedChildFixture(t)
	token, items, err := fx.session.OpenOwnedVaultFileChild(
		fx.a.journal, fx.a.checkpoint, fx.password, fx.key, VaultFileChildOptions{})
	if err != nil {
		t.Fatal("READ_DELIVERY_SUCCESS_OPEN_FAILED")
	}
	clearReadDeliveryItems(items)
	claim := beginReadDeliveryClaim(t, fx.session, token)
	closeReadDeliveryClaim(t, claim, fx.session)
	copyClaim := *claim
	if err := copyClaim.Consume(context.Background(), fx.session); err != nil {
		t.Fatal("READ_DELIVERY_SUCCESS_CONSUME_FAILED")
	}
	if err := claim.Consume(context.Background(), fx.session); !errors.Is(err, ErrVaultFileScopedChild) {
		t.Fatal("READ_DELIVERY_CLAIM_REUSED_ACROSS_COPY")
	}
}

func TestVaultFileReadDeliveryClaimRedactionAndSharedState(t *testing.T) {
	const redacted = "[vault-file read delivery claim]"
	claim := &VaultFileReadDeliveryClaim{state: &vaultFileReadDeliveryClaimState{
		path: "private-path-marker",
	}}
	value := *claim
	if value.state != claim.state {
		t.Fatal("READ_DELIVERY_COPY_STATE_NOT_SHARED")
	}
	for _, candidate := range []struct {
		name  string
		value any
	}{
		{"pointer", claim},
		{"value", value},
		{"value-pointer", &value},
	} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if got := fmt.Sprintf(format, candidate.value); got != redacted {
				t.Fatal("READ_DELIVERY_FORMAT_NOT_REDACTED")
			}
		}
		raw, err := json.Marshal(candidate.value)
		if err != nil || string(raw) != "{}" {
			t.Fatal("READ_DELIVERY_JSON_NOT_REDACTED")
		}
	}
	claim.state.mu.Lock()
	claim.state.consumed = true
	claim.state.mu.Unlock()
	value.state.mu.Lock()
	consumed := value.state.consumed
	value.state.mu.Unlock()
	if !consumed {
		t.Fatal("READ_DELIVERY_COPY_STATE_NOT_CONSUMED")
	}
}
