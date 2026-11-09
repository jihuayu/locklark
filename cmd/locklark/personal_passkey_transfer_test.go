package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/passkey"
	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/teamfiles"
)

// These are the stable public audit action spellings for the invitation and
// export mutations. Tests count them instead of the whole journal because a
// read-only Audit call may append its own read event.
const (
	testPasskeyTransferInviteAction = "vault.passkey.transfer.invite"
	testPasskeyTransferRevokeAction = "vault.passkey.transfer.revoke"
	testPasskeyTransferExportAction = "vault.passkey.transfer.export"
)

func passkeyTransferTestVault(t *testing.T) (path string, pw, key []byte) {
	t.Helper()
	dir := t.TempDir()
	path = filepath.Join(dir, "two-factor.ll")
	pw = []byte("passkey-transfer-master")
	key = bytes.Repeat([]byte{0x42}, 16)
	if err := personal.Create(path, string(pw), key); err != nil {
		t.Fatalf("create fixture vault: %v", err)
	}
	return path, pw, key
}

func passkeyTransferActionCount(t *testing.T, path string, pw, key []byte, action string) int {
	t.Helper()
	events, err := personal.Audit(path, string(pw), key)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	n := 0
	for _, event := range events {
		if event.Action == action {
			n++
		}
	}
	return n
}

func passkeyTransferInviteOpts(file, out, ttl string) map[string]string {
	return map[string]string{"--file": file, "--out": out, "--ttl": ttl}
}

func passkeyTransferAsk(phrase string, seen *[]string) func(string) ([]byte, error) {
	return func(prompt string) ([]byte, error) {
		if seen != nil {
			*seen = append(*seen, prompt)
		}
		return []byte(phrase), nil
	}
}

func passkeyTransferRowRevision(t *testing.T, rows []personal.Row, id string) string {
	t.Helper()
	for _, row := range rows {
		if row.ID == id {
			return row.Revision
		}
	}
	t.Fatalf("item %q missing from active list", id)
	return ""
}

const passkeyTransferCreateOptions = `{"challenge":"Y2hhbGxlbmdlLTAxMjM0NTY3ODk","rp":{"id":"example.test","name":"Example"},"user":{"id":"dXNlcjE","name":"passkey-fixture-user","displayName":"Fixture"},"pubKeyCredParams":[{"type":"public-key","alg":-7}]}`

// passkeyTransferSourceWithCredential builds one real source vault and one
// passkey through public Session APIs only. It returns the live parent revision
// and the credential's opaque content revision as exposed by the public list and
// metadata APIs used by `passkey-list`.
func passkeyTransferSourceWithCredential(t *testing.T) (path string, pw, key []byte, itemID, parentRevision, credentialID, childRevision, creationPublicKey string) {
	t.Helper()
	path, pw, key = passkeyTransferTestVault(t)
	session, err := personal.UnlockSession(path, pw, key, time.Minute)
	if err != nil {
		t.Fatalf("unlock source fixture: %v", err)
	}
	defer session.Lock()
	itemID, err = session.AddLogin("Source Login", "source-user", "source-password")
	if err != nil {
		t.Fatalf("source add-login: %v", err)
	}
	rows, err := session.List("active")
	if err != nil {
		t.Fatalf("source list: %v", err)
	}
	revision := passkeyTransferRowRevision(t, rows, itemID)
	revision, err = session.Edit(personal.Edit{ID: itemID, Revision: revision, Field: "url", Value: "https://example.test/login"})
	if err != nil {
		t.Fatalf("source url edit: %v", err)
	}
	target := personal.PasskeyTarget{
		Context:  personal.BrowserContext{RequestID: strings.Repeat("1", 32), Origin: "https://example.test", TabID: 1, DocumentID: "document-1"},
		Create:   true,
		ID:       itemID,
		Revision: revision,
		Options:  []byte(passkeyTransferCreateOptions),
	}
	gate := personal.NewMutationGate(time.Now().Add(30 * time.Second))
	if err := session.RegisterMutation(gate); err != nil {
		t.Fatalf("source gate: %v", err)
	}
	response, err := session.PerformPasskey(target, false, gate)
	if err != nil {
		t.Fatalf("source passkey create: %v", err)
	}
	credentialID = response.ID
	creationPublicKey = response.Response.PublicKey
	rows, err = session.List("active")
	if err != nil {
		t.Fatalf("source list after create: %v", err)
	}
	parentRevision = passkeyTransferRowRevision(t, rows, itemID)
	metadata, err := session.ReadManagedPasskeysMetadata(false)
	if err != nil {
		t.Fatalf("source metadata: %v", err)
	}
	for _, credential := range metadata[itemID] {
		if credential.CredentialID == credentialID {
			childRevision = credential.Revision
		}
	}
	if parentRevision == "" || childRevision == "" {
		t.Fatalf("source selectors missing: parent=%q child=%q", parentRevision, childRevision)
	}
	return path, pw, key, itemID, parentRevision, credentialID, childRevision, creationPublicKey
}

// passkeyTransferReceiverInvitation creates one real receiver invitation and
// returns its raw bytes plus public target fingerprint.
func passkeyTransferReceiverInvitation(t *testing.T) (path string, pw, key, raw []byte, fingerprint string) {
	t.Helper()
	path, pw, key = passkeyTransferTestVault(t)
	session, err := personal.UnlockSession(path, pw, key, time.Minute)
	if err != nil {
		t.Fatalf("unlock receiver fixture: %v", err)
	}
	defer session.Lock()
	gate := personal.NewMutationGate(time.Now().Add(30 * time.Second))
	if err := session.RegisterMutation(gate); err != nil {
		t.Fatalf("receiver gate: %v", err)
	}
	invite, err := session.NewPasskeyTransferInvitation(5*time.Minute, gate)
	if err != nil {
		t.Fatalf("receiver invite: %v", err)
	}
	return path, pw, key, append([]byte(nil), invite.Raw...), invite.Public.Fingerprint
}

func passkeyTransferSelectionDocument(itemID, revision, credentialID, credentialRevision string) []byte {
	raw, err := json.Marshal([]map[string]string{{
		"item_id":             itemID,
		"revision":            revision,
		"credential_id":       credentialID,
		"credential_revision": credentialRevision,
	}})
	if err != nil {
		panic(err)
	}
	return raw
}

func passkeyTransferExportOpts(file, invitation, pin, selection, out string) map[string]string {
	return map[string]string{"--file": file, "--invitation": invitation, "--target-pin": pin, "--selection": selection, "--out": out}
}

func TestParsePasskeyTransferArgs(t *testing.T) {
	for _, tc := range []struct {
		args   []string
		action string
		out    string
	}{
		{[]string{"passkey-invite", "--file", "/a/v.ll", "--out", "/a/i.json", "--ttl", "900"}, "passkey-invite", "/a/i.json"},
		{[]string{"passkey-revoke", "--file", "/a/v.ll", "--invitation", "/a/i.json"}, "passkey-revoke", ""},
		{[]string{"passkey-list", "--file", "/a/v.ll"}, "passkey-list", ""},
		{[]string{"passkey-export", "--file", "/a/v.ll", "--invitation", "/a/i.json", "--target-pin", strings.Repeat("a", 64), "--selection", "/a/s.json", "--out", "/a/p.json"}, "passkey-export", "/a/p.json"},
	} {
		action, opts, ok := parsePasskeyTransferArgs(tc.args)
		if !ok || action != tc.action {
			t.Fatalf("valid shape refused: %v action=%q ok=%v", tc.args, action, ok)
		}
		if tc.out != "" && opts["--out"] != tc.out {
			t.Fatalf("output option lost: %+v", opts)
		}
	}

	for _, args := range [][]string{
		{},
		{"passkey-invite"},
		{"passkey-invite", "--file", "/a/v.ll"},
		{"passkey-invite", "--file", "/a/v.ll", "--out", "/a/i.json"},
		{"passkey-invite", "--file", "/a/v.ll", "--out", "/a/i.json", "--ttl", ""},
		{"passkey-invite", "--file", "/a/v.ll", "--out", "/a/i.json", "--ttl", "0"},
		{"passkey-invite", "--file", "/a/v.ll", "--out", "/a/i.json", "--ttl", "901"},
		{"passkey-invite", "--file", "/a/v.ll", "--out", "/a/i.json", "--ttl", "01"},
		{"passkey-invite", "--file", "/a/v.ll", "--out", "/a/i.json", "--ttl", "abc"},
		{"passkey-invite", "--file", "/a/v.ll", "--file", "/b/v.ll", "--ttl", "60"},
		{"passkey-invite", "--file", "/a/v.ll", "--out", "/a/i.json", "--ttl", "60", "--extra", "x"},
		{"passkey-invite", "--file", "/a/v.ll", "--out", "/a/i.json", "--ttl", "60", "--target-pin", strings.Repeat("a", 64)},
		{"passkey-revoke", "--file", "/a/v.ll", "--out", "/a/i.json"},
		{"passkey-revoke", "--file", "/a/v.ll", "--invitation", "/a/i.json", "--ttl", "60"},
		{"passkey-revoke", "--file", "/a/v.ll", "--invitation", ""},
		{"passkey-list", "--file", "/a/v.ll", "--out", "/a/i.json"},
		{"passkey-list"},
		{"passkey-export", "--file", "/a/v.ll", "--invitation", "/a/i.json", "--target-pin", strings.Repeat("a", 64), "--selection", "/a/s.json"},
		{"passkey-export", "--file", "/a/v.ll", "--invitation", "/a/i.json", "--target-pin", strings.Repeat("A", 64), "--selection", "/a/s.json", "--out", "/a/p.json"},
		{"passkey-export", "--file", "/a/v.ll", "--invitation", "/a/i.json", "--target-pin", strings.Repeat("g", 64), "--selection", "/a/s.json", "--out", "/a/p.json"},
		{"passkey-export", "--file", "/a/v.ll", "--invitation", "/a/i.json", "--target-pin", strings.Repeat("a", 63), "--selection", "/a/s.json", "--out", "/a/p.json"},
		{"passkey-export", "--file", "/a/v.ll", "--invitation", "/a/i.json", "--target-pin", strings.Repeat("a", 64), "--selection", "/a/s.json", "--out", "/a/p.json", "--extra", "x"},
		{"passkey-export", "--file", "/a/v.ll", "--invitation", "/a/i.json", "--target-pin", strings.Repeat("a", 64), "--selection", "/a/s.json", "--selection", "/b/s.json", "--out", "/a/p.json"},
		{"passkey-import", "--file", "/a/v.ll"},
	} {
		if action, _, ok := parsePasskeyTransferArgs(args); ok {
			t.Fatalf("invalid shape accepted: %v action=%q", args, action)
		}
	}
}

func TestRunPersonalPasskeyDispatchRejectsBadShapes(t *testing.T) {
	for _, args := range [][]string{
		{"passkey-invite", "--file", "/a/v.ll", "--out", "/a/i.json", "--ttl", "0"},
		{"passkey-invite", "--file", "/a/v.ll", "--out", "/a/i.json", "--ttl", "901"},
		{"passkey-revoke", "--file", "/a/v.ll"},
		{"passkey-revoke", "--file", "/a/v.ll", "--invitation", "/a/i.json", "--extra", "x"},
		{"passkey-list", "--file", "/a/v.ll", "--out", "/a/i.json"},
		{"passkey-export", "--file", "/a/v.ll", "--invitation", "/a/i.json", "--target-pin", "bad", "--selection", "/a/s.json", "--out", "/a/p.json"},
	} {
		var out bytes.Buffer
		if err := runPersonal(args, &out); err != personalUsage || out.Len() != 0 {
			t.Fatalf("bad passkey shape: err=%v out=%q args=%v", err, out.String(), args)
		}
	}
	for _, args := range [][]string{{"passkey-invite"}, {"passkey-revoke"}, {"passkey-list"}, {"passkey-export"}, {"passkey-plan"}, {"passkey-import"}} {
		if !isPasskeyTransferAction(args) {
			t.Fatalf("exact passkey action was not dispatched: %v", args)
		}
	}
	for _, args := range [][]string{nil, {"list"}, {"passkey-invitex"}, {"passkey-importx"}, {"passkey-planx"}} {
		if isPasskeyTransferAction(args) {
			t.Fatalf("non-passkey action was dispatched: %v", args)
		}
	}
}

func TestPasskeyTransferSelectionStrictSchema(t *testing.T) {
	const itemID = "item-1"
	revision := strings.Repeat("a", 64)
	credentialID := "Y3JlZGVudGlhbC0wMTIzNDU2Nzg5MDEyMzQ1"
	child := strings.Repeat("b", 64)
	valid := passkeyTransferSelectionDocument(itemID, revision, credentialID, child)
	if targets, err := parsePasskeyTransferSelection(valid); err != nil || len(targets) != 1 || targets[0].ItemID != itemID || targets[0].Revision != revision || targets[0].CredentialID != credentialID || targets[0].CredentialRevision != child {
		t.Fatalf("valid selection refused: %+v err=%v", targets, err)
	}

	cases := map[string][]byte{
		"empty":          {},
		"not-array":      []byte(`{"item_id":"item-1"}`),
		"empty-array":    []byte(`[]`),
		"unknown-key":    []byte(`[{"item_id":"item-1","revision":"` + revision + `","credential_id":"` + credentialID + `","credential_revision":"` + child + `","private_key":"x"}]`),
		"case-alias":     []byte(`[{"ITEM_ID":"item-1","revision":"` + revision + `","credential_id":"` + credentialID + `","credential_revision":"` + child + `"}]`),
		"duplicate-case": []byte(`[{"item_id":"item-1","ITEM_ID":"item-2","revision":"` + revision + `","credential_id":"` + credentialID + `","credential_revision":"` + child + `"}]`),
		"duplicate":      []byte(`[{"item_id":"item-1","item_id":"item-2","revision":"` + revision + `","credential_id":"` + credentialID + `","credential_revision":"` + child + `"}]`),
		"missing-key":    []byte(`[{"item_id":"item-1","revision":"` + revision + `","credential_id":"` + credentialID + `"}]`),
		"nested-value":   []byte(`[{"item_id":{"x":1},"revision":"` + revision + `","credential_id":"` + credentialID + `","credential_revision":"` + child + `"}]`),
		"bad-revision":   []byte(`[{"item_id":"item-1","revision":"short","credential_id":"` + credentialID + `","credential_revision":"` + child + `"}]`),
		"upper-revision": []byte(`[{"item_id":"item-1","revision":"` + strings.Repeat("A", 64) + `","credential_id":"` + credentialID + `","credential_revision":"` + child + `"}]`),
		"bad-credential": []byte(`[{"item_id":"item-1","revision":"` + revision + `","credential_id":"not base64!","credential_revision":"` + child + `"}]`),
		"trailing":       append(append([]byte(nil), valid...), []byte(`{"x":1}`)...),
		"malformed":      []byte(`[{"item_id":`),
	}
	// Seventeen otherwise valid records exceed the native per-packet limit.
	seventeen := bytes.Repeat(append(append([]byte(nil), valid[1:len(valid)-1]...), ','), 17)
	seventeen = append([]byte{'['}, append(seventeen[:len(seventeen)-1], ']')...)
	cases["too-many"] = seventeen
	for name, raw := range cases {
		if _, err := parsePasskeyTransferSelection(raw); !errors.Is(err, errPasskeyTransferSelectionRefused) {
			t.Fatalf("%s selection was not refused: %v", name, err)
		}
	}
}

func TestPasskeyTransferInviteNoOverwriteBeforeConsent(t *testing.T) {
	vaultPath, _, _ := passkeyTransferTestVault(t)
	dir := t.TempDir()
	out := filepath.Join(dir, "invitation.json")
	passkeyTransferWritePrivate(t, out, []byte("foreign output"))
	if _, err := preparePasskeyTransfer("passkey-invite", passkeyTransferInviteOpts(vaultPath, out, "60")); err != personalUsage {
		t.Fatalf("existing output was accepted: %v", err)
	}
	raw, err := os.ReadFile(out)
	if err != nil || string(raw) != "foreign output" {
		t.Fatalf("foreign output changed: %q err=%v", raw, err)
	}
	if _, err := preparePasskeyTransfer("passkey-invite", passkeyTransferInviteOpts(vaultPath, vaultPath, "60")); err != personalUsage {
		t.Fatalf("aliased output was accepted: %v", err)
	}
}

func TestPasskeyTransferInputFilePermissionsAndBound(t *testing.T) {
	vaultPath, _, _ := passkeyTransferTestVault(t)
	dir := t.TempDir()
	public := filepath.Join(dir, "invitation.json")
	opts := map[string]string{"--file": vaultPath, "--invitation": public}

	passkeyTransferWriteShared(t, public, []byte(`{"v":1}`))
	if _, err := preparePasskeyTransfer("passkey-revoke", opts); err == nil || err == personalUsage {
		t.Fatalf("group-readable invitation accepted: %v", err)
	}

	passkeyTransferWritePrivate(t, public, []byte(`{"v":1}`))
	input, err := preparePasskeyTransfer("passkey-revoke", opts)
	if err != nil || input == nil || string(input.invitation) != `{"v":1}` {
		t.Fatalf("owner-only invitation refused: input=%+v err=%v", input, err)
	}
	input.clear()

	large := bytes.Repeat([]byte{'x'}, maxPasskeyTransferInvitationBytes+1)
	passkeyTransferWritePrivate(t, public, large)
	if _, err := preparePasskeyTransfer("passkey-revoke", opts); err == nil || err == personalUsage {
		t.Fatalf("oversized invitation accepted: %v", err)
	}
}

func TestPasskeyTransferInviteConsentCancelAndActualSession(t *testing.T) {
	vaultPath, pw, key := passkeyTransferTestVault(t)
	dir := t.TempDir()
	out := filepath.Join(dir, "invitation.json")
	opts := passkeyTransferInviteOpts(vaultPath, out, "120")

	var cancelledOut bytes.Buffer
	var prompts []string
	if err := executePasskeyTransferAction("passkey-invite", opts, nil, &cancelledOut, pw, key, passkeyTransferAsk("NOPE", &prompts), &bytes.Buffer{}); !errors.Is(err, errPasskeyTransferCancelled) {
		t.Fatalf("wrong consent: err=%v", err)
	}
	if cancelledOut.Len() != 0 {
		t.Fatalf("cancelled invite wrote a receipt: %q", cancelledOut.String())
	}
	if _, err := os.Lstat(out); !os.IsNotExist(err) {
		t.Fatalf("cancelled invite created an output file: %v", err)
	}
	if got := passkeyTransferActionCount(t, vaultPath, pw, key, testPasskeyTransferInviteAction); got != 0 {
		t.Fatalf("cancelled invite changed the audit: %d invite events", got)
	}
	if len(prompts) != 1 || prompts[0] != "Enter INVITE to confirm invitation creation" {
		t.Fatalf("unexpected consent prompts: %v", prompts)
	}

	var receipt bytes.Buffer
	if err := executePasskeyTransferAction("passkey-invite", opts, nil, &receipt, pw, key, passkeyTransferAsk("INVITE", nil), &bytes.Buffer{}); err != nil {
		t.Fatalf("invite: %v", err)
	}
	var value map[string]any
	if err := json.Unmarshal(receipt.Bytes(), &value); err != nil {
		t.Fatalf("receipt is not JSON: %v", err)
	}
	if len(value) != 4 || value["status"] != "invited" || value["invitation_id"] == "" || value["fingerprint"] == "" || value["expires_at"] == "" {
		t.Fatalf("receipt allowlist mismatch: %s", receipt.String())
	}
	id, _ := value["invitation_id"].(string)
	fingerprint, _ := value["fingerprint"].(string)
	if len(id) != 32 {
		t.Fatalf("invitation id is not an opaque 16-byte hex id: %q", id)
	}
	if _, err := hex.DecodeString(id); err != nil {
		t.Fatalf("invitation id is not hex: %v", err)
	}
	if len(fingerprint) != 64 {
		t.Fatalf("fingerprint is not a 64-hex digest: %q", fingerprint)
	}
	if _, err := hex.DecodeString(fingerprint); err != nil {
		t.Fatalf("fingerprint is not hex: %v", err)
	}
	expires, err := time.Parse(time.RFC3339Nano, value["expires_at"].(string))
	if err != nil || !expires.After(time.Now()) {
		t.Fatalf("bad expiry: %v %v", value["expires_at"], err)
	}
	for _, forbidden := range []string{"recipient", "audit_public", "signature", "\"raw\"", "secret"} {
		if strings.Contains(receipt.String(), forbidden) {
			t.Fatalf("receipt leaked %q: %s", forbidden, receipt.String())
		}
	}

	passkeyTransferAssertOwnerPrivate(t, out)
	raw, err := teamfiles.Read(out, maxPasskeyTransferInvitationBytes, true)
	if err != nil || len(raw) == 0 {
		t.Fatalf("invitation output is not a private readable file: len=%d err=%v", len(raw), err)
	}
	if bytes.Contains(receipt.Bytes(), raw) {
		t.Fatal("raw invitation bytes reached stdout")
	}
	clear(raw)
	if got := passkeyTransferActionCount(t, vaultPath, pw, key, testPasskeyTransferInviteAction); got != 1 {
		t.Fatalf("invite audit not appended: %d invite events", got)
	}
}

func TestPasskeyTransferRevokeCancelAndConsumedInvitation(t *testing.T) {
	vaultPath, pw, key := passkeyTransferTestVault(t)
	dir := t.TempDir()
	out := filepath.Join(dir, "invitation.json")
	if err := executePasskeyTransferAction("passkey-invite", passkeyTransferInviteOpts(vaultPath, out, "120"), nil, &bytes.Buffer{}, pw, key, passkeyTransferAsk("INVITE", nil), &bytes.Buffer{}); err != nil {
		t.Fatalf("invite fixture: %v", err)
	}
	raw, err := teamfiles.Read(out, maxPasskeyTransferInvitationBytes, true)
	if err != nil {
		t.Fatalf("read invitation fixture: %v", err)
	}
	defer clear(raw)
	input := &passkeyTransferInput{invitation: raw}
	opts := map[string]string{"--file": vaultPath, "--invitation": out}

	var cancelled bytes.Buffer
	if err := executePasskeyTransferAction("passkey-revoke", opts, input, &cancelled, pw, key, passkeyTransferAsk("NOPE", nil), &bytes.Buffer{}); !errors.Is(err, errPasskeyTransferCancelled) {
		t.Fatalf("wrong revoke consent: %v", err)
	}
	if cancelled.Len() != 0 {
		t.Fatalf("cancelled revoke wrote a receipt: %q", cancelled.String())
	}
	if got := passkeyTransferActionCount(t, vaultPath, pw, key, testPasskeyTransferRevokeAction); got != 0 {
		t.Fatalf("cancelled revoke changed audit: %d revoke events", got)
	}

	var receipt bytes.Buffer
	if err := executePasskeyTransferAction("passkey-revoke", opts, input, &receipt, pw, key, passkeyTransferAsk("REVOKE", nil), &bytes.Buffer{}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	var value map[string]any
	if err := json.Unmarshal(receipt.Bytes(), &value); err != nil || len(value) != 1 || value["status"] != "revoked" {
		t.Fatalf("revoke receipt allowlist mismatch: %s err=%v", receipt.String(), err)
	}
	if got := passkeyTransferActionCount(t, vaultPath, pw, key, testPasskeyTransferRevokeAction); got != 1 {
		t.Fatalf("revoke audit not appended: %d revoke events", got)
	}
	var replay bytes.Buffer
	if err := executePasskeyTransferAction("passkey-revoke", opts, input, &replay, pw, key, passkeyTransferAsk("REVOKE", nil), &bytes.Buffer{}); err == nil {
		t.Fatal("replayed revoke unexpectedly succeeded")
	}
	if replay.Len() != 0 {
		t.Fatalf("failed revoke wrote a receipt: %q", replay.String())
	}
	if got := passkeyTransferActionCount(t, vaultPath, pw, key, testPasskeyTransferRevokeAction); got != 1 {
		t.Fatalf("failed revoke appended audit: %d revoke events", got)
	}
}

func TestPasskeyTransferPublicationUnknownKeepsForeignOutput(t *testing.T) {
	vaultPath, pw, key := passkeyTransferTestVault(t)
	dir := t.TempDir()
	out := filepath.Join(dir, "invitation.json")
	opts := passkeyTransferInviteOpts(vaultPath, out, "120")

	if _, err := preparePasskeyTransfer("passkey-invite", opts); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	passkeyTransferWritePrivate(t, out, []byte("foreign output"))

	var receipt bytes.Buffer
	err := executePasskeyTransferAction("passkey-invite", opts, nil, &receipt, pw, key, passkeyTransferAsk("INVITE", nil), &bytes.Buffer{})
	if !errors.Is(err, errPasskeyTransferPublicationUnknown) {
		t.Fatalf("publication failure was not fixed UNKNOWN: %v", err)
	}
	if receipt.Len() != 0 {
		t.Fatalf("publication UNKNOWN returned a receipt: %q", receipt.String())
	}
	raw, readErr := os.ReadFile(out)
	if readErr != nil || string(raw) != "foreign output" {
		t.Fatalf("foreign output was replaced or deleted: %q err=%v", raw, readErr)
	}
	if got := passkeyTransferActionCount(t, vaultPath, pw, key, testPasskeyTransferInviteAction); got != 1 {
		t.Fatalf("DB may have committed but invite audit count is %d", got)
	}
}

func TestPasskeyTransferListActualSession(t *testing.T) {
	// An empty vault still yields a JSON array, never null.
	emptyPath, pw, key := passkeyTransferTestVault(t)
	var empty bytes.Buffer
	if err := executePasskeyTransferAction("passkey-list", map[string]string{"--file": emptyPath}, nil, &empty, pw, key, nil, &bytes.Buffer{}); err != nil {
		t.Fatalf("empty list: %v", err)
	}
	if strings.TrimSpace(empty.String()) != "[]" {
		t.Fatalf("empty list is not an array: %q", empty.String())
	}

	sourcePath, sourcePW, sourceKey, itemID, parentRevision, credentialID, childRevision, _ := passkeyTransferSourceWithCredential(t)
	var out bytes.Buffer
	if err := executePasskeyTransferAction("passkey-list", map[string]string{"--file": sourcePath}, nil, &out, sourcePW, sourceKey, nil, &bytes.Buffer{}); err != nil {
		t.Fatalf("list: %v", err)
	}
	var rows []map[string]any
	if err := json.Unmarshal(out.Bytes(), &rows); err != nil || len(rows) != 1 {
		t.Fatalf("list payload: %s err=%v", out.String(), err)
	}
	row := rows[0]
	if len(row) != 3 || row["item_id"] != itemID || row["revision"] != parentRevision {
		t.Fatalf("list row allowlist mismatch: %+v", row)
	}
	credentials, ok := row["credentials"].([]any)
	if !ok || len(credentials) != 1 {
		t.Fatalf("list credentials: %+v", row["credentials"])
	}
	credential := credentials[0].(map[string]any)
	if len(credential) != 4 || credential["credential_id"] != credentialID || credential["credential_revision"] != childRevision || credential["rp_id"] != "example.test" || credential["name"] != "passkey-fixture-user" {
		t.Fatalf("credential allowlist mismatch: %+v", credential)
	}
	for _, forbidden := range []string{"user_id", "private_key", "record", "seed", "handle"} {
		if strings.Contains(out.String(), forbidden) {
			t.Fatalf("list leaked %q: %s", forbidden, out.String())
		}
	}
}

func TestPasskeyTransferExportActualSessionAndForgedSelector(t *testing.T) {
	sourcePath, sourcePW, sourceKey, itemID, parentRevision, credentialID, childRevision, _ := passkeyTransferSourceWithCredential(t)
	receiverPath, receiverPW, receiverKey, inviteRaw, targetPin := passkeyTransferReceiverInvitation(t)
	defer clear(inviteRaw)
	if _, err := hex.DecodeString(targetPin); err != nil || len(targetPin) != 64 {
		t.Fatalf("receiver fingerprint is not a public hex64 pin: %q", targetPin)
	}
	dir := t.TempDir()
	invitationPath := filepath.Join(dir, "invitation.json")
	selectionPath := filepath.Join(dir, "selection.json")
	packetPath := filepath.Join(dir, "packet.json")
	passkeyTransferWritePrivate(t, invitationPath, inviteRaw)
	selection := passkeyTransferSelectionDocument(itemID, parentRevision, credentialID, childRevision)
	passkeyTransferWritePrivate(t, selectionPath, selection)
	opts := passkeyTransferExportOpts(sourcePath, invitationPath, targetPin, selectionPath, packetPath)

	input, err := preparePasskeyTransfer("passkey-export", opts)
	if err != nil || input == nil || len(input.targets) != 1 || input.targets[0].CredentialID != credentialID {
		t.Fatalf("prepare export: input=%+v err=%v", input, err)
	}
	defer input.clear()

	// Wrong consent must not create a packet or append an export intent.
	var cancelled bytes.Buffer
	if err := executePasskeyTransferAction("passkey-export", opts, input, &cancelled, sourcePW, sourceKey, passkeyTransferAsk("NOPE", nil), &bytes.Buffer{}); !errors.Is(err, errPasskeyTransferCancelled) {
		t.Fatalf("wrong export consent: %v", err)
	}
	if cancelled.Len() != 0 {
		t.Fatalf("cancelled export wrote a receipt: %q", cancelled.String())
	}
	if _, err := os.Lstat(packetPath); !os.IsNotExist(err) {
		t.Fatalf("cancelled export created a packet: %v", err)
	}
	if got := passkeyTransferActionCount(t, sourcePath, sourcePW, sourceKey, testPasskeyTransferExportAction); got != 0 {
		t.Fatalf("cancelled export changed audit: %d export events", got)
	}

	var receipt bytes.Buffer
	if err := executePasskeyTransferAction("passkey-export", opts, input, &receipt, sourcePW, sourceKey, passkeyTransferAsk("EXPORT", nil), &bytes.Buffer{}); err != nil {
		t.Fatalf("export: %v", err)
	}
	var value map[string]any
	if err := json.Unmarshal(receipt.Bytes(), &value); err != nil || len(value) != 4 || value["status"] != "exported" || value["packet_id"] == "" || value["source_fingerprint"] == "" || value["target_fingerprint"] != targetPin {
		t.Fatalf("export receipt allowlist mismatch: %s err=%v", receipt.String(), err)
	}
	for _, forbidden := range []string{"\"raw\"", "private_key", "record", "ciphertext", "recipient"} {
		if strings.Contains(receipt.String(), forbidden) {
			t.Fatalf("export receipt leaked %q: %s", forbidden, receipt.String())
		}
	}
	passkeyTransferAssertOwnerPrivate(t, packetPath)
	packet, err := teamfiles.Read(packetPath, 2<<20, true)
	if err != nil || len(packet) == 0 {
		t.Fatalf("packet unreadable: len=%d err=%v", len(packet), err)
	}
	if bytes.Contains(receipt.Bytes(), packet) {
		t.Fatal("raw packet bytes reached stdout")
	}
	if got := passkeyTransferActionCount(t, sourcePath, sourcePW, sourceKey, testPasskeyTransferExportAction); got != 1 {
		t.Fatalf("export audit not appended: %d export events", got)
	}

	// The receiver can decrypt and plan the packet with the public source pin,
	// proving the sealed target is the invited vault.
	receiver, err := personal.UnlockSession(receiverPath, receiverPW, receiverKey, time.Minute)
	if err != nil {
		t.Fatalf("unlock receiver for plan: %v", err)
	}
	plan, err := receiver.PlanPasskeyTransfer(inviteRaw, packet, value["source_fingerprint"].(string))
	receiver.Lock()
	clear(packet)
	if err != nil {
		t.Fatalf("receiver plan: %v", err)
	}
	if plan.TargetFingerprint != targetPin || plan.SourceFingerprint != value["source_fingerprint"] || len(plan.Groups) != 1 || len(plan.Groups[0].CredentialIDs) != 1 || plan.Groups[0].CredentialIDs[0] != credentialID {
		t.Fatalf("plan does not match exported selectors: %+v", plan)
	}
	if _, err := hex.DecodeString(plan.Digest); err != nil {
		t.Fatalf("plan digest is not hex: %v", err)
	}

	// A structurally valid but forged child revision must be refused by the
	// source session before any packet is published.
	forgedPath := filepath.Join(dir, "forged-selection.json")
	forged := passkeyTransferSelectionDocument(itemID, parentRevision, credentialID, strings.Repeat("0", 64))
	passkeyTransferWritePrivate(t, forgedPath, forged)
	forgedOut := filepath.Join(dir, "forged-packet.json")
	forgedOpts := passkeyTransferExportOpts(sourcePath, invitationPath, targetPin, forgedPath, forgedOut)
	forgedInput, err := preparePasskeyTransfer("passkey-export", forgedOpts)
	if err != nil {
		t.Fatalf("forged selection should be structurally valid: %v", err)
	}
	defer forgedInput.clear()
	var forgedReceipt bytes.Buffer
	if err := executePasskeyTransferAction("passkey-export", forgedOpts, forgedInput, &forgedReceipt, sourcePW, sourceKey, passkeyTransferAsk("EXPORT", nil), &bytes.Buffer{}); err == nil {
		t.Fatal("forged child revision exported a packet")
	}
	if forgedReceipt.Len() != 0 {
		t.Fatalf("forged export wrote a receipt: %q", forgedReceipt.String())
	}
	if _, err := os.Lstat(forgedOut); !os.IsNotExist(err) {
		t.Fatalf("forged export created a packet: %v", err)
	}
	if got := passkeyTransferActionCount(t, sourcePath, sourcePW, sourceKey, testPasskeyTransferExportAction); got != 1 {
		t.Fatalf("forged export appended audit: %d export events", got)
	}
}

func TestPasskeyTransferExportNoOverwriteAndBadPermissions(t *testing.T) {
	sourcePath, _, _, itemID, parentRevision, credentialID, childRevision, _ := passkeyTransferSourceWithCredential(t)
	_, _, _, inviteRaw, targetPin := passkeyTransferReceiverInvitation(t)
	defer clear(inviteRaw)
	dir := t.TempDir()
	invitationPath := filepath.Join(dir, "invitation.json")
	selectionPath := filepath.Join(dir, "selection.json")
	passkeyTransferWritePrivate(t, invitationPath, inviteRaw)
	passkeyTransferWritePrivate(t, selectionPath, passkeyTransferSelectionDocument(itemID, parentRevision, credentialID, childRevision))

	existing := filepath.Join(dir, "packet.json")
	passkeyTransferWritePrivate(t, existing, []byte("foreign packet"))
	opts := passkeyTransferExportOpts(sourcePath, invitationPath, targetPin, selectionPath, existing)
	if _, err := preparePasskeyTransfer("passkey-export", opts); err != personalUsage {
		t.Fatalf("existing packet output accepted: %v", err)
	}
	raw, err := os.ReadFile(existing)
	if err != nil || string(raw) != "foreign packet" {
		t.Fatalf("foreign packet output changed: %q err=%v", raw, err)
	}

	// Group-readable private selector is refused before factors or consent.
	passkeyTransferWriteShared(t, selectionPath, passkeyTransferSelectionDocument(itemID, parentRevision, credentialID, childRevision))
	newOut := filepath.Join(dir, "new-packet.json")
	opts = passkeyTransferExportOpts(sourcePath, invitationPath, targetPin, selectionPath, newOut)
	if _, err := preparePasskeyTransfer("passkey-export", opts); err == nil || err == personalUsage {
		t.Fatalf("group-readable selection accepted: %v", err)
	}
}

func passkeyTransferMappingDoc(objects ...map[string]string) []byte {
	raw, err := json.Marshal(objects)
	if err != nil {
		panic(err)
	}
	return raw
}

func passkeyTransferReceiverItemCount(t *testing.T, path string, pw, key []byte, want int) int {
	t.Helper()
	session, err := personal.UnlockSession(path, pw, key, time.Minute)
	if err != nil {
		t.Fatalf("unlock receiver for count: %v", err)
	}
	defer session.Lock()
	metadata, err := session.ReadManagedPasskeysMetadata(false)
	if err != nil {
		t.Fatalf("receiver metadata: %v", err)
	}
	n := 0
	for _, credentials := range metadata {
		n += len(credentials)
	}
	if n != want {
		t.Fatalf("receiver credential count = %d, want %d", n, want)
	}
	return n
}

func verifyPasskeyTransferAssertion(t *testing.T, creationPublicKey string, response passkey.Response) {
	t.Helper()
	publicRaw, err := base64.RawURLEncoding.Strict().DecodeString(creationPublicKey)
	if err != nil {
		t.Fatalf("creation public key encoding: %v", err)
	}
	parsed, err := x509.ParsePKIXPublicKey(publicRaw)
	if err != nil {
		t.Fatalf("creation public key parse: %v", err)
	}
	public, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("creation public key is not ECDSA")
	}
	authData, err := base64.RawURLEncoding.Strict().DecodeString(response.Response.AuthenticatorData)
	if err != nil {
		t.Fatalf("authenticator data: %v", err)
	}
	clientData, err := base64.RawURLEncoding.Strict().DecodeString(response.Response.ClientDataJSON)
	if err != nil {
		t.Fatalf("client data: %v", err)
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(response.Response.Signature)
	if err != nil {
		t.Fatalf("signature: %v", err)
	}
	clientHash := sha256.Sum256(clientData)
	signed := append(append([]byte{}, authData...), clientHash[:]...)
	digest := sha256.Sum256(signed)
	if !ecdsa.VerifyASN1(public, digest[:], signature) {
		t.Fatal("imported credential produced an invalid assertion signature")
	}
}

func TestParsePasskeyPlanImportArgs(t *testing.T) {
	pin := strings.Repeat("a", 64)
	for _, args := range [][]string{
		{"passkey-plan", "--file", "/a/v.ll", "--invitation", "/a/i.json", "--packet", "/a/p.json", "--source-pin", pin},
		{"passkey-import", "--file", "/a/v.ll", "--invitation", "/a/i.json", "--packet", "/a/p.json", "--source-pin", pin, "--digest", pin, "--mapping", "/a/m.json"},
	} {
		if action, _, ok := parsePasskeyTransferArgs(args); !ok || action != args[0] {
			t.Fatalf("valid plan/import shape refused: %v", args)
		}
	}
	for _, args := range [][]string{
		{"passkey-plan", "--file", "/a/v.ll", "--invitation", "/a/i.json", "--packet", "/a/p.json"},
		{"passkey-plan", "--file", "/a/v.ll", "--invitation", "/a/i.json", "--packet", "/a/p.json", "--source-pin", strings.Repeat("A", 64)},
		{"passkey-plan", "--file", "/a/v.ll", "--invitation", "/a/i.json", "--packet", "/a/p.json", "--source-pin", pin, "--extra", "x"},
		{"passkey-import", "--file", "/a/v.ll", "--invitation", "/a/i.json", "--packet", "/a/p.json", "--source-pin", pin, "--mapping", "/a/m.json"},
		{"passkey-import", "--file", "/a/v.ll", "--invitation", "/a/i.json", "--packet", "/a/p.json", "--source-pin", pin, "--digest", "bad", "--mapping", "/a/m.json"},
		{"passkey-import", "--file", "/a/v.ll", "--invitation", "/a/i.json", "--packet", "/a/p.json", "--source-pin", pin, "--digest", pin, "--mapping", "/a/m.json", "--target-pin", pin},
	} {
		if _, _, ok := parsePasskeyTransferArgs(args); ok {
			t.Fatalf("invalid plan/import shape accepted: %v", args)
		}
	}
}

func TestPasskeyTransferMappingStrictSchema(t *testing.T) {
	group := strings.Repeat("c", 64)
	revision := strings.Repeat("d", 64)
	validNew := passkeyTransferMappingDoc(map[string]string{"group_id": group, "new_title": "Imported", "new_username": "user"})
	validExisting := passkeyTransferMappingDoc(map[string]string{"group_id": group, "existing_target_id": "item-1", "existing_revision": revision})

	mappings, err := parsePasskeyTransferMappings(validNew)
	if err != nil || len(mappings) != 1 || mappings[0].GroupID != group || mappings[0].NewTitle != "Imported" || mappings[0].NewUsername != "user" || mappings[0].ExistingTargetID != "" {
		t.Fatalf("valid new mapping refused: %+v err=%v", mappings, err)
	}
	mappings, err = parsePasskeyTransferMappings(validExisting)
	if err != nil || len(mappings) != 1 || mappings[0].ExistingTargetID != "item-1" || mappings[0].ExistingRevision != revision || mappings[0].NewTitle != "" {
		t.Fatalf("valid existing mapping refused: %+v err=%v", mappings, err)
	}
	if mappings, err = parsePasskeyTransferMappings(passkeyTransferMappingDoc(map[string]string{"group_id": group, "new_title": "Imported", "new_username": ""})); err != nil || len(mappings) != 1 || mappings[0].NewUsername != "" {
		t.Fatalf("explicit empty username refused: %+v err=%v", mappings, err)
	}

	tooMany := bytes.Repeat([]byte(`{"group_id":"`+group+`","new_title":"Imported","new_username":"user"},`), 17)
	tooMany = append([]byte{'['}, append(tooMany[:len(tooMany)-1], ']')...)
	cases := map[string][]byte{
		"empty":                {},
		"not-array":            []byte(`{"group_id":"` + group + `"}`),
		"empty-array":          []byte(`[]`),
		"unknown-key":          []byte(`[{"group_id":"` + group + `","new_title":"Imported","new_username":"user","private_key":"x"}]`),
		"raw-credential":       []byte(`[{"group_id":"` + group + `","new_title":"Imported","new_username":"user","credential_id":"x"}]`),
		"case-alias":           []byte(`[{"GROUP_ID":"` + group + `","new_title":"Imported","new_username":"user"}]`),
		"duplicate":            []byte(`[{"group_id":"` + group + `","group_id":"` + group + `","new_title":"Imported","new_username":"user"}]`),
		"duplicate-case":       []byte(`[{"group_id":"` + group + `","GROUP_ID":"` + group + `","new_title":"Imported","new_username":"user"}]`),
		"mixed":                []byte(`[{"group_id":"` + group + `","existing_target_id":"item-1","existing_revision":"` + revision + `","new_title":"Imported"}]`),
		"missing-username":     []byte(`[{"group_id":"` + group + `","new_title":"Imported"}]`),
		"existing-missing-rev": []byte(`[{"group_id":"` + group + `","existing_target_id":"item-1"}]`),
		"nested":               []byte(`[{"group_id":"` + group + `","new_title":{"x":1},"new_username":"user"}]`),
		"bad-group":            []byte(`[{"group_id":"short","new_title":"Imported","new_username":"user"}]`),
		"empty-title":          []byte(`[{"group_id":"` + group + `","new_title":"","new_username":"user"}]`),
		"trailing":             append(append([]byte(nil), validNew...), []byte(`{"x":1}`)...),
		"malformed":            []byte(`[{"group_id":`),
		"too-many":             tooMany,
	}
	for name, raw := range cases {
		if _, err := parsePasskeyTransferMappings(raw); !errors.Is(err, errPasskeyTransferMappingRefused) {
			t.Fatalf("%s mapping was not refused: %v", name, err)
		}
	}
}

func TestPasskeyTransferPlanImportInputBoundaries(t *testing.T) {
	vaultPath, _, _ := passkeyTransferTestVault(t)
	_, _, _, inviteRaw, targetPin := passkeyTransferReceiverInvitation(t)
	defer clear(inviteRaw)
	dir := t.TempDir()
	invitationPath := filepath.Join(dir, "invitation.json")
	packetPath := filepath.Join(dir, "packet.json")
	mappingPath := filepath.Join(dir, "mapping.json")
	passkeyTransferWritePrivate(t, invitationPath, inviteRaw)
	passkeyTransferWritePrivate(t, packetPath, []byte(`{"packet":"dummy"}`))

	planOpts := map[string]string{"--file": vaultPath, "--invitation": invitationPath, "--packet": packetPath, "--source-pin": targetPin}
	if _, err := preparePasskeyTransfer("passkey-plan", planOpts); err != nil {
		t.Fatalf("valid plan inputs refused: %v", err)
	}
	alias := map[string]string{"--file": vaultPath, "--invitation": invitationPath, "--packet": vaultPath, "--source-pin": targetPin}
	if _, err := preparePasskeyTransfer("passkey-plan", alias); err != personalUsage {
		t.Fatalf("plan packet aliasing vault accepted: %v", err)
	}

	passkeyTransferWriteShared(t, invitationPath, inviteRaw)
	if _, err := preparePasskeyTransfer("passkey-plan", planOpts); err == nil || err == personalUsage {
		t.Fatalf("group-readable invitation accepted: %v", err)
	}
	passkeyTransferWritePrivate(t, invitationPath, inviteRaw)
	passkeyTransferWriteShared(t, packetPath, []byte(`{"packet":"dummy"}`))
	if _, err := preparePasskeyTransfer("passkey-plan", planOpts); err == nil || err == personalUsage {
		t.Fatalf("group-readable packet accepted: %v", err)
	}
	large := bytes.Repeat([]byte{'x'}, maxPasskeyTransferPacketBytes+1)
	passkeyTransferWritePrivate(t, packetPath, large)
	if _, err := preparePasskeyTransfer("passkey-plan", planOpts); err == nil || err == personalUsage {
		t.Fatalf("oversized packet accepted: %v", err)
	}
	passkeyTransferWritePrivate(t, packetPath, []byte(`{"packet":"dummy"}`))

	group := strings.Repeat("c", 64)
	passkeyTransferWritePrivate(t, mappingPath, passkeyTransferMappingDoc(map[string]string{"group_id": group, "new_title": "Imported", "new_username": "user"}))
	importOpts := map[string]string{"--file": vaultPath, "--invitation": invitationPath, "--packet": packetPath, "--source-pin": targetPin, "--digest": strings.Repeat("e", 64), "--mapping": mappingPath}
	if _, err := preparePasskeyTransfer("passkey-import", importOpts); err != nil {
		t.Fatalf("valid import inputs refused: %v", err)
	}
	passkeyTransferWriteShared(t, mappingPath, passkeyTransferMappingDoc(map[string]string{"group_id": group, "new_title": "Imported", "new_username": "user"}))
	if _, err := preparePasskeyTransfer("passkey-import", importOpts); err == nil || err == personalUsage {
		t.Fatalf("group-readable mapping accepted: %v", err)
	}
	passkeyTransferWritePrivate(t, mappingPath, []byte(`[{"group_id":"`+group+`","new_title":"Imported","new_username":"user","private_key":"x"}]`))
	if _, err := preparePasskeyTransfer("passkey-import", importOpts); !errors.Is(err, errPasskeyTransferMappingRefused) {
		t.Fatalf("malformed mapping not refused: %v", err)
	}
	mappingAlias := map[string]string{"--file": vaultPath, "--invitation": invitationPath, "--packet": packetPath, "--source-pin": targetPin, "--digest": strings.Repeat("e", 64), "--mapping": vaultPath}
	if _, err := preparePasskeyTransfer("passkey-import", mappingAlias); err != personalUsage {
		t.Fatalf("mapping aliasing vault accepted: %v", err)
	}
}

func TestPasskeyTransferTwoVaultCLIEndToEnd(t *testing.T) {
	sourcePath, sourcePW, sourceKey, itemID, parentRevision, credentialID, childRevision, creationPublicKey := passkeyTransferSourceWithCredential(t)
	receiverPath, receiverPW, receiverKey := passkeyTransferTestVault(t)
	dir := t.TempDir()
	invitationPath := filepath.Join(dir, "invitation.json")
	packetPath := filepath.Join(dir, "packet.json")
	selectionPath := filepath.Join(dir, "selection.json")
	mappingPath := filepath.Join(dir, "mapping.json")
	passkeyTransferWritePrivate(t, selectionPath, passkeyTransferSelectionDocument(itemID, parentRevision, credentialID, childRevision))

	var inviteReceipt bytes.Buffer
	if err := executePasskeyTransferAction("passkey-invite", passkeyTransferInviteOpts(receiverPath, invitationPath, "300"), nil, &inviteReceipt, receiverPW, receiverKey, passkeyTransferAsk("INVITE", nil), &bytes.Buffer{}); err != nil {
		t.Fatalf("cli invite: %v", err)
	}
	var inviteValue map[string]any
	if err := json.Unmarshal(inviteReceipt.Bytes(), &inviteValue); err != nil {
		t.Fatalf("invite receipt: %v", err)
	}
	targetPin, _ := inviteValue["fingerprint"].(string)
	if !validPasskeyTransferHex64(targetPin) {
		t.Fatalf("invite target pin is not canonical hex64: %q", targetPin)
	}

	exportOpts := passkeyTransferExportOpts(sourcePath, invitationPath, targetPin, selectionPath, packetPath)
	exportInput, err := preparePasskeyTransfer("passkey-export", exportOpts)
	if err != nil {
		t.Fatalf("prepare cli export: %v", err)
	}
	defer exportInput.clear()
	var exportReceipt bytes.Buffer
	if err := executePasskeyTransferAction("passkey-export", exportOpts, exportInput, &exportReceipt, sourcePW, sourceKey, passkeyTransferAsk("EXPORT", nil), &bytes.Buffer{}); err != nil {
		t.Fatalf("cli export: %v", err)
	}
	var exportValue map[string]any
	if err := json.Unmarshal(exportReceipt.Bytes(), &exportValue); err != nil {
		t.Fatalf("export receipt: %v", err)
	}
	sourcePin, _ := exportValue["source_fingerprint"].(string)
	if !validPasskeyTransferHex64(sourcePin) {
		t.Fatalf("export source pin is not canonical hex64: %q", sourcePin)
	}

	planOpts := map[string]string{"--file": receiverPath, "--invitation": invitationPath, "--packet": packetPath, "--source-pin": sourcePin}
	planInput, err := preparePasskeyTransfer("passkey-plan", planOpts)
	if err != nil {
		t.Fatalf("prepare cli plan: %v", err)
	}
	defer planInput.clear()
	var planCancelled bytes.Buffer
	if err := executePasskeyTransferAction("passkey-plan", planOpts, planInput, &planCancelled, receiverPW, receiverKey, passkeyTransferAsk("NOPE", nil), &bytes.Buffer{}); !errors.Is(err, errPasskeyTransferCancelled) {
		t.Fatalf("wrong plan consent: %v", err)
	}
	if planCancelled.Len() != 0 {
		t.Fatalf("cancelled plan wrote output: %q", planCancelled.String())
	}
	var planOut bytes.Buffer
	if err := executePasskeyTransferAction("passkey-plan", planOpts, planInput, &planOut, receiverPW, receiverKey, passkeyTransferAsk("PLAN", nil), &bytes.Buffer{}); err != nil {
		t.Fatalf("cli plan: %v", err)
	}
	for _, forbidden := range []string{"user_id", "seed", "packet", "private_key", "record"} {
		if strings.Contains(planOut.String(), forbidden) {
			t.Fatalf("plan leaked %q: %s", forbidden, planOut.String())
		}
	}
	var planValue struct {
		Digest            string `json:"digest"`
		SourceFingerprint string `json:"source_fingerprint"`
		TargetFingerprint string `json:"target_fingerprint"`
		Groups            []struct {
			GroupID       string   `json:"group_id"`
			RPID          string   `json:"rp_id"`
			CredentialIDs []string `json:"credential_ids"`
		} `json:"groups"`
	}
	if err := json.Unmarshal(planOut.Bytes(), &planValue); err != nil {
		t.Fatalf("plan receipt: %v", err)
	}
	if !validPasskeyTransferHex64(planValue.Digest) || planValue.SourceFingerprint != sourcePin || planValue.TargetFingerprint != targetPin || len(planValue.Groups) != 1 || planValue.Groups[0].RPID != "example.test" || len(planValue.Groups[0].CredentialIDs) != 1 || planValue.Groups[0].CredentialIDs[0] != credentialID {
		t.Fatalf("plan does not match exported selectors: %+v", planValue)
	}
	groupID := planValue.Groups[0].GroupID

	passkeyTransferWritePrivate(t, mappingPath, passkeyTransferMappingDoc(map[string]string{"group_id": groupID, "new_title": "Imported Passkey Login", "new_username": "imported-user"}))
	importOpts := map[string]string{"--file": receiverPath, "--invitation": invitationPath, "--packet": packetPath, "--source-pin": sourcePin, "--digest": planValue.Digest, "--mapping": mappingPath}
	importInput, err := preparePasskeyTransfer("passkey-import", importOpts)
	if err != nil {
		t.Fatalf("prepare cli import: %v", err)
	}
	defer importInput.clear()

	var importCancelled bytes.Buffer
	if err := executePasskeyTransferAction("passkey-import", importOpts, importInput, &importCancelled, receiverPW, receiverKey, passkeyTransferAsk("NOPE", nil), &bytes.Buffer{}); !errors.Is(err, errPasskeyTransferCancelled) {
		t.Fatalf("wrong import consent: %v", err)
	}
	if importCancelled.Len() != 0 {
		t.Fatalf("cancelled import wrote a receipt: %q", importCancelled.String())
	}
	passkeyTransferReceiverItemCount(t, receiverPath, receiverPW, receiverKey, 0)

	// A stale mapping is refused as a whole and leaves the invitation usable.
	stalePath := filepath.Join(dir, "stale.json")
	passkeyTransferWritePrivate(t, stalePath, passkeyTransferMappingDoc(map[string]string{"group_id": groupID, "existing_target_id": "missing-item", "existing_revision": strings.Repeat("0", 64)}))
	staleOpts := map[string]string{"--file": receiverPath, "--invitation": invitationPath, "--packet": packetPath, "--source-pin": sourcePin, "--digest": planValue.Digest, "--mapping": stalePath}
	staleInput, err := preparePasskeyTransfer("passkey-import", staleOpts)
	if err != nil {
		t.Fatalf("prepare stale import: %v", err)
	}
	defer staleInput.clear()
	var staleOut bytes.Buffer
	if err := executePasskeyTransferAction("passkey-import", staleOpts, staleInput, &staleOut, receiverPW, receiverKey, passkeyTransferAsk("IMPORT", nil), &bytes.Buffer{}); err == nil {
		t.Fatal("stale mapping unexpectedly imported")
	}
	if staleOut.Len() != 0 {
		t.Fatalf("stale import wrote a receipt: %q", staleOut.String())
	}
	passkeyTransferReceiverItemCount(t, receiverPath, receiverPW, receiverKey, 0)
	var planAgain bytes.Buffer
	if err := executePasskeyTransferAction("passkey-plan", planOpts, planInput, &planAgain, receiverPW, receiverKey, passkeyTransferAsk("PLAN", nil), &bytes.Buffer{}); err != nil {
		t.Fatalf("plan after refused import: %v", err)
	}

	var importReceipt bytes.Buffer
	if err := executePasskeyTransferAction("passkey-import", importOpts, importInput, &importReceipt, receiverPW, receiverKey, passkeyTransferAsk("IMPORT", nil), &bytes.Buffer{}); err != nil {
		t.Fatalf("cli import: %v", err)
	}
	var importValue struct {
		Status string `json:"status"`
		Items  []struct {
			ID       string `json:"id"`
			Revision string `json:"revision"`
		} `json:"items"`
	}
	if err := json.Unmarshal(importReceipt.Bytes(), &importValue); err != nil {
		t.Fatalf("import receipt: %v", err)
	}
	if importValue.Status != "imported" || len(importValue.Items) != 1 || !validPasskeyTransferToken(importValue.Items[0].ID) || !validPasskeyTransferHex64(importValue.Items[0].Revision) {
		t.Fatalf("import receipt allowlist mismatch: %s", importReceipt.String())
	}
	for _, forbidden := range []string{"private_key", "credential", "user_id", "seed"} {
		if strings.Contains(importReceipt.String(), forbidden) {
			t.Fatalf("import receipt leaked %q: %s", forbidden, importReceipt.String())
		}
	}
	importedID, importedRevision := importValue.Items[0].ID, importValue.Items[0].Revision
	passkeyTransferReceiverItemCount(t, receiverPath, receiverPW, receiverKey, 1)

	// Ordinary public Session APIs verify the imported credential assertion.
	receiver, err := personal.UnlockSession(receiverPath, receiverPW, receiverKey, time.Minute)
	if err != nil {
		t.Fatalf("unlock imported receiver: %v", err)
	}
	metadata, err := receiver.ReadManagedPasskeysMetadata(false)
	if err != nil {
		receiver.Lock()
		t.Fatalf("imported metadata: %v", err)
	}
	found := false
	for _, credential := range metadata[importedID] {
		if credential.CredentialID == credentialID {
			found = true
		}
	}
	if !found {
		receiver.Lock()
		t.Fatalf("imported credential %q missing from parent %q", credentialID, importedID)
	}
	getOptions := []byte(`{"rpId":"example.test","challenge":"Y2hhbGxlbmdlLTAxMjM0NTY3ODk","allowCredentials":[{"type":"public-key","id":"` + credentialID + `"}]}`)
	target := personal.PasskeyTarget{Context: personal.BrowserContext{RequestID: strings.Repeat("5", 32), Origin: "https://example.test", TabID: 5, DocumentID: "document-5"}, ID: importedID, Revision: importedRevision, CredentialID: credentialID, Options: getOptions}
	gate := personal.NewMutationGate(time.Now().Add(30 * time.Second))
	if err := receiver.RegisterMutation(gate); err != nil {
		receiver.Lock()
		t.Fatalf("assertion gate: %v", err)
	}
	response, err := receiver.PerformPasskey(target, false, gate)
	receiver.Lock()
	if err != nil {
		t.Fatalf("imported assertion: %v", err)
	}
	if response.ID != credentialID {
		t.Fatalf("assertion used %q, want %q", response.ID, credentialID)
	}
	verifyPasskeyTransferAssertion(t, creationPublicKey, response)

	// Replay of the consumed invitation is refused and changes nothing.
	var replay bytes.Buffer
	if err := executePasskeyTransferAction("passkey-import", importOpts, importInput, &replay, receiverPW, receiverKey, passkeyTransferAsk("IMPORT", nil), &bytes.Buffer{}); err == nil {
		t.Fatal("replayed import unexpectedly succeeded")
	}
	if replay.Len() != 0 {
		t.Fatalf("replayed import wrote a receipt: %q", replay.String())
	}
	passkeyTransferReceiverItemCount(t, receiverPath, receiverPW, receiverKey, 1)
}

type passkeyTransferFailWriter struct{}

func (passkeyTransferFailWriter) Write([]byte) (int, error) {
	return 0, errors.New("writer failure")
}

func TestPasskeyTransferImportReceiptFailureIsUnknown(t *testing.T) {
	sourcePath, sourcePW, sourceKey, itemID, parentRevision, credentialID, childRevision, _ := passkeyTransferSourceWithCredential(t)
	receiverPath, receiverPW, receiverKey := passkeyTransferTestVault(t)
	dir := t.TempDir()
	invitationPath := filepath.Join(dir, "invitation.json")
	packetPath := filepath.Join(dir, "packet.json")
	selectionPath := filepath.Join(dir, "selection.json")
	mappingPath := filepath.Join(dir, "mapping.json")
	passkeyTransferWritePrivate(t, selectionPath, passkeyTransferSelectionDocument(itemID, parentRevision, credentialID, childRevision))

	var inviteReceipt bytes.Buffer
	if err := executePasskeyTransferAction("passkey-invite", passkeyTransferInviteOpts(receiverPath, invitationPath, "300"), nil, &inviteReceipt, receiverPW, receiverKey, passkeyTransferAsk("INVITE", nil), &bytes.Buffer{}); err != nil {
		t.Fatalf("invite: %v", err)
	}
	var inviteValue map[string]any
	if err := json.Unmarshal(inviteReceipt.Bytes(), &inviteValue); err != nil {
		t.Fatalf("invite receipt: %v", err)
	}
	targetPin := inviteValue["fingerprint"].(string)
	exportOpts := passkeyTransferExportOpts(sourcePath, invitationPath, targetPin, selectionPath, packetPath)
	exportInput, err := preparePasskeyTransfer("passkey-export", exportOpts)
	if err != nil {
		t.Fatalf("prepare export: %v", err)
	}
	defer exportInput.clear()
	var exportReceipt bytes.Buffer
	if err := executePasskeyTransferAction("passkey-export", exportOpts, exportInput, &exportReceipt, sourcePW, sourceKey, passkeyTransferAsk("EXPORT", nil), &bytes.Buffer{}); err != nil {
		t.Fatalf("export: %v", err)
	}
	var exportValue map[string]any
	if err := json.Unmarshal(exportReceipt.Bytes(), &exportValue); err != nil {
		t.Fatalf("export receipt: %v", err)
	}
	sourcePin := exportValue["source_fingerprint"].(string)

	planOpts := map[string]string{"--file": receiverPath, "--invitation": invitationPath, "--packet": packetPath, "--source-pin": sourcePin}
	planInput, err := preparePasskeyTransfer("passkey-plan", planOpts)
	if err != nil {
		t.Fatalf("prepare plan: %v", err)
	}
	defer planInput.clear()
	var planOut bytes.Buffer
	if err := executePasskeyTransferAction("passkey-plan", planOpts, planInput, &planOut, receiverPW, receiverKey, passkeyTransferAsk("PLAN", nil), &bytes.Buffer{}); err != nil {
		t.Fatalf("plan: %v", err)
	}
	var planValue struct {
		Digest string `json:"digest"`
		Groups []struct {
			GroupID string `json:"group_id"`
		} `json:"groups"`
	}
	if err := json.Unmarshal(planOut.Bytes(), &planValue); err != nil || len(planValue.Groups) != 1 {
		t.Fatalf("plan receipt: %v %s", err, planOut.String())
	}
	passkeyTransferWritePrivate(t, mappingPath, passkeyTransferMappingDoc(map[string]string{"group_id": planValue.Groups[0].GroupID, "new_title": "Unknown Receipt Login", "new_username": "unknown-user"}))
	importOpts := map[string]string{"--file": receiverPath, "--invitation": invitationPath, "--packet": packetPath, "--source-pin": sourcePin, "--digest": planValue.Digest, "--mapping": mappingPath}
	importInput, err := preparePasskeyTransfer("passkey-import", importOpts)
	if err != nil {
		t.Fatalf("prepare import: %v", err)
	}
	defer importInput.clear()

	if err := executePasskeyTransferAction("passkey-import", importOpts, importInput, passkeyTransferFailWriter{}, receiverPW, receiverKey, passkeyTransferAsk("IMPORT", nil), &bytes.Buffer{}); !errors.Is(err, errPasskeyTransferPublicationUnknown) {
		t.Fatalf("receipt failure after mutation was not fixed UNKNOWN: %v", err)
	}
	passkeyTransferReceiverItemCount(t, receiverPath, receiverPW, receiverKey, 1)
}
