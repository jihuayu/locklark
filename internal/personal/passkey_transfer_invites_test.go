package personal

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/passkeytransfer"
)

func transferTestPublic(t *testing.T, s *Session) publicTransferIdentity {
	t.Helper()
	var i identity
	if err := json.Unmarshal(s.material, &i); err != nil {
		t.Fatal(err)
	}
	defer i.clear()
	public, err := transferPublicIdentity(i)
	if err != nil {
		t.Fatal(err)
	}
	return public
}

func transferTestLink(t *testing.T, s *Session, raw []byte) string {
	t.Helper()
	var i identity
	if err := json.Unmarshal(s.material, &i); err != nil {
		t.Fatal(err)
	}
	defer i.clear()
	var invite passkeytransfer.Invitation
	if err := json.Unmarshal(raw, &invite); err != nil {
		t.Fatal(err)
	}
	link, err := passkeyTransferInviteLink(i.AuditEncryption, &invite)
	if err != nil {
		t.Fatal(err)
	}
	return link
}

func TestPasskeyTransferInvitationCreateRevokeBoundToCurrentChain(t *testing.T) {
	s, target := passkeyTarget(t)
	defer s.Lock()
	if _, err := s.PerformPasskey(target, false, dailyGate(t, s)); err != nil {
		t.Fatal(err)
	}
	before := rawItems(t, s)
	public := transferTestPublic(t, s)
	g := dailyGate(t, s)
	invite, err := s.NewPasskeyTransferInvitation(5*time.Minute, g)
	if err != nil {
		t.Fatal(err)
	}
	if !g.CommitWon() || !idOK(invite.ID) || !bytes.Equal(invite.Raw, bytes.TrimSpace(invite.Raw)) {
		t.Fatal("invitation did not report a committed canonical receipt")
	}
	if invite.Public != public {
		t.Fatal("invitation public identity did not match the unlocked session")
	}
	verified, err := passkeytransfer.VerifyInvitation(invite.Raw, public.Fingerprint, time.Now())
	if err != nil || verified.ID != invite.ID || verified.Recipient != public.Recipient || verified.AuditPublic != public.AuditPublic {
		t.Fatal("signed invitation did not verify against the session identity")
	}
	link := transferTestLink(t, s, invite.Raw)
	created := lastAuditEvent(t, s)
	if created.Action != passkeyTransferInviteAction || created.Item != invite.ID || created.BaseRevision != "" || created.Result != "succeeded" || created.Link != link {
		t.Fatalf("unexpected creation event: %+v", created)
	}
	if after := rawItems(t, s); !reflect.DeepEqual(after, before) {
		t.Fatal("invitation creation changed encrypted items")
	}
	if rawAuditActionCount(t, s, passkeyTransferInviteAction) != 1 {
		t.Fatal("invitation creation audit count mismatch")
	}
	// Populate the warm audit prefix, then require revocation to consult the
	// complete authenticated chain instead of the cached item-revision tail.
	if _, err = s.List("all"); err != nil {
		t.Fatal(err)
	}

	beforeRevoke := rawAuditActionCount(t, s, passkeyTransferRevokeAction)
	revokeGate := dailyGate(t, s)
	if err = s.RevokePasskeyTransferInvitation(invite.Raw, revokeGate); err != nil || !revokeGate.CommitWon() {
		t.Fatalf("revoke failed: %v", err)
	}
	revoked := lastAuditEvent(t, s)
	if revoked.Action != passkeyTransferRevokeAction || revoked.Item != invite.ID || revoked.BaseRevision != created.hash() || revoked.Link != link || revoked.Result != "succeeded" {
		t.Fatalf("unexpected revocation event: %+v", revoked)
	}
	if rawAuditActionCount(t, s, passkeyTransferRevokeAction) != beforeRevoke+1 {
		t.Fatal("revocation audit count mismatch")
	}

	beforeRepeat := rawAuditActionCount(t, s, passkeyTransferRevokeAction)
	if err = s.RevokePasskeyTransferInvitation(invite.Raw, dailyGate(t, s)); !errors.Is(err, ErrMutationRefused) {
		t.Fatalf("repeated revoke returned %v", err)
	}
	if rawAuditActionCount(t, s, passkeyTransferRevokeAction) != beforeRepeat {
		t.Fatal("repeated revoke appended an audit event")
	}

	reopened, err := UnlockSession(s.path, []byte("fixture"), bytes.Repeat([]byte{4}, 16), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Lock()
	if err = reopened.RevokePasskeyTransferInvitation(invite.Raw, dailyGate(t, reopened)); !errors.Is(err, ErrMutationRefused) {
		t.Fatalf("cold-chain repeated revoke returned %v", err)
	}
}

func TestPasskeyTransferInvitationGateForeignIdentityAndBounds(t *testing.T) {
	path, key, _ := revealFixture(t)
	s, err := UnlockSession(path, []byte("fixture"), key, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Lock()

	unregistered := NewMutationGate(time.Now().Add(time.Minute))
	if _, err = s.NewPasskeyTransferInvitation(time.Minute, unregistered); !errors.Is(err, ErrMutationCancelled) {
		t.Fatalf("unregistered gate returned %v", err)
	}
	cancelled := dailyGate(t, s)
	cancelled.Cancel()
	if _, err = s.NewPasskeyTransferInvitation(time.Minute, cancelled); !errors.Is(err, ErrMutationCancelled) {
		t.Fatalf("cancelled gate returned %v", err)
	}
	if _, err = s.NewPasskeyTransferInvitation(16*time.Minute, dailyGate(t, s)); !errors.Is(err, ErrMutationRefused) {
		t.Fatalf("oversized TTL returned %v", err)
	}
	if rawAuditActionCount(t, s, passkeyTransferInviteAction) != 0 {
		t.Fatal("refused invitation appended an audit event")
	}

	invite, err := s.NewPasskeyTransferInvitation(time.Minute, dailyGate(t, s))
	if err != nil {
		t.Fatal(err)
	}
	otherPath := path + ".other"
	otherKey := bytes.Repeat([]byte{5}, 16)
	if err = Create(otherPath, "fixture", otherKey); err != nil {
		t.Fatal(err)
	}
	other, err := UnlockSession(otherPath, []byte("fixture"), otherKey, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Lock()
	foreign, err := other.NewPasskeyTransferInvitation(time.Minute, dailyGate(t, other))
	if err != nil {
		t.Fatal(err)
	}
	before := rawAuditActionCount(t, s, passkeyTransferRevokeAction)
	if err = s.RevokePasskeyTransferInvitation(foreign.Raw, dailyGate(t, s)); !errors.Is(err, ErrMutationRefused) {
		t.Fatalf("foreign invitation returned %v", err)
	}
	if rawAuditActionCount(t, s, passkeyTransferRevokeAction) != before {
		t.Fatal("foreign invitation appended a revocation event")
	}
	if err = s.RevokePasskeyTransferInvitation(nil, dailyGate(t, s)); !errors.Is(err, ErrMutationRefused) {
		t.Fatalf("empty invitation returned %v", err)
	}
	if err = s.RevokePasskeyTransferInvitation(invite.Raw, dailyGate(t, s)); err != nil {
		t.Fatalf("valid current invitation revoke failed: %v", err)
	}
}

func TestPasskeyTransferInvitationPublicOutputRedacted(t *testing.T) {
	s, target := passkeyTarget(t)
	defer s.Lock()
	if _, err := s.PerformPasskey(target, false, dailyGate(t, s)); err != nil {
		t.Fatal(err)
	}
	var records [][]byte
	for _, item := range rawItems(t, s) {
		if item.ID != target.ID {
			continue
		}
		for _, raw := range item.PasskeyRecords() {
			records = append(records, bytes.Clone(raw))
		}
	}
	for _, raw := range records {
		defer clear(raw)
	}
	if len(records) == 0 {
		t.Fatal("fixture did not contain a private passkey record")
	}
	invite, err := s.NewPasskeyTransferInvitation(time.Minute, dailyGate(t, s))
	if err != nil {
		t.Fatal(err)
	}
	publicJSON, err := json.Marshal(invite.Public)
	if err != nil {
		t.Fatal(err)
	}
	eventJSON, err := json.Marshal(lastAuditEvent(t, s))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(invite.Raw, []byte("fixture-user")) || bytes.Contains(publicJSON, []byte("fixture-user")) || bytes.Contains(eventJSON, []byte("fixture-user")) {
		t.Fatal("user handle leaked into invitation or audit metadata")
	}
	for _, record := range records {
		if bytes.Contains(invite.Raw, record) || bytes.Contains(publicJSON, record) || bytes.Contains(eventJSON, record) {
			t.Fatal("private passkey record leaked into public output or audit metadata")
		}
	}
	if invite.String() != "[passkey transfer invitation]" || invite.GoString() != "[passkey transfer invitation]" {
		t.Fatal("invitation metadata string is not redacted")
	}
	if invite.Public.String() != invite.Public.Fingerprint || invite.Public.GoString() != "[public transfer identity "+invite.Public.Fingerprint+"]" {
		t.Fatal("public identity debug output exposed unexpected fields")
	}
}

func TestPasskeyTransferScannerAndRevisionReplayFailClosed(t *testing.T) {
	id := strings.Repeat("a", 32)
	link := strings.Repeat("b", 64)
	creation := Event{Action: passkeyTransferInviteAction, Item: id, Result: "succeeded", Link: link, Sequence: 2}
	revoke := Event{Action: passkeyTransferRevokeAction, Item: id, BaseRevision: creation.hash(), Result: "succeeded", Link: link, Sequence: 3}
	if _, err := scanPasskeyTransferRows([]Event{creation}, id, link); err != nil {
		t.Fatal(err)
	}
	if _, err := scanPasskeyTransferRows([]Event{creation, revoke}, id, link); err == nil {
		t.Fatal("revoked invitation was still usable")
	}
	if _, err := scanPasskeyTransferRows([]Event{creation, creation}, id, link); err == nil {
		t.Fatal("duplicate creation was accepted")
	}
	if _, err := scanPasskeyTransferRows([]Event{revoke}, id, link); err == nil {
		t.Fatal("out-of-order revocation was accepted")
	}
	badBase := revoke
	badBase.BaseRevision = strings.Repeat("c", 64)
	if _, err := scanPasskeyTransferRows([]Event{creation, badBase}, id, link); err == nil {
		t.Fatal("unknown revocation base was accepted")
	}
	revisions := make(map[string]string)
	if err := applyAuditRevision(creation, creation.hash(), revisions); err != nil || len(revisions) != 0 {
		t.Fatal("invitation event created a fake item revision")
	}
}
