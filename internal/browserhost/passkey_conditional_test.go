package browserhost

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/passkey"
	"github.com/jihuayu/locklark/internal/personal"
	bolt "go.etcd.io/bbolt"
)

func passkeyGetWire(rpID string, allow ...string) string {
	options := map[string]any{"rpId": rpID, "challenge": "Y2hhbGxlbmdlLTAxMjM0NTY3ODk"}
	if len(allow) > 0 {
		list := make([]map[string]string, 0, len(allow))
		for _, id := range allow {
			list = append(list, map[string]string{"type": "public-key", "id": id})
		}
		options["allowCredentials"] = list
	}
	raw, e := json.Marshal(options)
	if e != nil {
		panic(e)
	}
	return string(raw)
}

func passkeyCreateWire(userID, userName, displayName string) []byte {
	raw, e := json.Marshal(map[string]any{
		"challenge":        "Y2hhbGxlbmdlLTAxMjM0NTY3ODk",
		"rp":               map[string]string{"id": "example.test", "name": "Example"},
		"user":             map[string]string{"id": userID, "name": userName, "displayName": displayName},
		"pubKeyCredParams": []map[string]any{{"type": "public-key", "alg": -7}},
	})
	if e != nil {
		panic(e)
	}
	return raw
}

// conditionalPasskey attaches a fresh credential to one existing login through
// the native mutation path and returns its public credential ID.
func conditionalPasskey(t *testing.T, s *personal.Session, itemID, userID, userName, displayName string) string {
	t.Helper()
	revision := ""
	rows, e := s.List("active")
	if e != nil {
		t.Fatal(e)
	}
	for _, row := range rows {
		if row.ID == itemID {
			revision = row.Revision
		}
	}
	if revision == "" {
		t.Fatal("passkey target item missing")
	}
	gate := personal.NewMutationGate(time.Now().Add(time.Minute))
	if e = s.RegisterMutation(gate); e != nil {
		t.Fatal(e)
	}
	created, e := s.PerformPasskey(personal.PasskeyTarget{
		Context:  personal.BrowserContext{RequestID: reqID(77), Origin: "https://example.test", TabID: 1, DocumentID: "doc-77"},
		Create:   true,
		ID:       itemID,
		Revision: revision,
		Options:  passkeyCreateWire(userID, userName, displayName),
	}, false, gate)
	if e != nil {
		t.Fatal(e)
	}
	return created.ID
}

func revisionOf(t *testing.T, s *personal.Session, itemID string) string {
	t.Helper()
	rows, e := s.List("active")
	if e != nil {
		t.Fatal(e)
	}
	for _, row := range rows {
		if row.ID == itemID {
			return row.Revision
		}
	}
	t.Fatal("item missing")
	return ""
}

func frames(t *testing.T, out *memoryPipe) []map[string]any {
	t.Helper()
	out.Lock()
	raw := bytes.Clone(out.Bytes())
	out.Unlock()
	var out2 []map[string]any
	for len(raw) >= 4 {
		n := int(raw[0]) | int(raw[1])<<8 | int(raw[2])<<16 | int(raw[3])<<24
		raw = raw[4:]
		if n < 0 || n > len(raw) {
			t.Fatal("bad frame")
		}
		var value map[string]any
		if json.Unmarshal(raw[:n], &value) != nil {
			t.Fatal("bad response")
		}
		out2 = append(out2, value)
		raw = raw[n:]
	}
	return out2
}

func candidatesFrame(t *testing.T, out *memoryPipe, id string) map[string]any {
	t.Helper()
	for _, frame := range frames(t, out) {
		if frame["type"] == "passkey-candidates" && frame["id"] == id {
			return frame
		}
	}
	t.Fatal("missing passkey-candidates frame")
	return nil
}

func TestPasskeyConditionalCapabilityAndStrictWire(t *testing.T) {
	count := 0
	for _, capability := range SupportedCapabilities() {
		if capability == "passkey-conditional-v1" {
			count++
		}
	}
	if count != 1 {
		t.Fatal("passkey-conditional-v1 capability not advertised exactly once")
	}
	options := passkeyGetWire("example.test")
	list := map[string]any{"v": 1, "id": reqID(90), "type": "passkey-list", "capability": reqID(9), "origin": "https://example.test", "tab_id": 1, "document_id": "doc-1", "options": options}
	read := func(value map[string]any) error {
		raw, e := json.Marshal(value)
		if e != nil {
			t.Fatal(e)
		}
		_, e = ReadRequest(bytes.NewReader(frame(string(raw))))
		return e
	}
	if e := read(list); e != nil {
		t.Fatalf("valid passkey-list refused: %v", e)
	}
	for _, extra := range []map[string]any{
		{"item_id": reqID(3)},
		{"revision": strings.Repeat("a", 64)},
		{"user": "alice"},
		{"create": true},
		{"credential_id": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
		{"window_id": 1},
		{"selector": "x"},
		{"item_json": "{}"},
	} {
		value := map[string]any{}
		for k, v := range list {
			value[k] = v
		}
		for k, v := range extra {
			value[k] = v
		}
		if e := read(value); e == nil {
			t.Fatalf("passkey-list accepted extra field %v", extra)
		}
	}
	missing := map[string]any{}
	for k, v := range list {
		if k != "options" {
			missing[k] = v
		}
	}
	if read(missing) == nil {
		t.Fatal("passkey-list without options accepted")
	}
	emptyOptions := map[string]any{}
	for k, v := range list {
		emptyOptions[k] = v
	}
	emptyOptions["options"] = ""
	if read(emptyOptions) == nil {
		t.Fatal("passkey-list with empty options accepted")
	}

	get := map[string]any{"v": 1, "id": reqID(91), "type": "passkey-get", "capability": reqID(9), "origin": "https://example.test", "tab_id": 1, "document_id": "doc-1", "options": options}
	if e := read(get); e != nil {
		t.Fatalf("legacy passkey-get refused: %v", e)
	}
	for _, extra := range []map[string]any{
		{"item_id": reqID(5), "revision": strings.Repeat("a", 64)},
		{"item_id": reqID(5)},
		{"revision": strings.Repeat("a", 64)},
		{"item_id": "not-an-item-id", "revision": strings.Repeat("a", 64)},
		{"item_id": reqID(5), "revision": "short"},
	} {
		value := map[string]any{}
		for k, v := range get {
			value[k] = v
		}
		for k, v := range extra {
			value[k] = v
		}
		pinned := len(extra) == 2 && extra["item_id"] == reqID(5) && extra["revision"] == strings.Repeat("a", 64)
		if e := read(value); pinned && e != nil {
			t.Fatalf("pinned passkey-get refused: %v", e)
		} else if !pinned && e == nil {
			t.Fatalf("passkey-get accepted selector %v", extra)
		}
	}
	create := map[string]any{"v": 1, "id": reqID(92), "type": "passkey-create", "capability": reqID(9), "origin": "https://example.test", "tab_id": 1, "document_id": "doc-1", "options": string(passkeyCreateWire("dXNlcjE", "alice", "Alice"))}
	if e := read(create); e != nil {
		t.Fatalf("create refused: %v", e)
	}
	pinnedCreate := map[string]any{}
	for k, v := range create {
		pinnedCreate[k] = v
	}
	pinnedCreate["item_id"] = reqID(5)
	pinnedCreate["revision"] = strings.Repeat("a", 64)
	if read(pinnedCreate) == nil {
		t.Fatal("passkey-create accepted a selector pair")
	}

	// Programmatic requests bypass requestKeys; valid() must still refuse
	// unrelated selector/mutation fields on a conditional list.
	c, _, _, base := paired(t)
	defer c.Close()
	request := base
	request.ID = reqID(93)
	request.Type = "passkey-list"
	request.ItemID, request.Revision = "", ""
	request.Options = options
	request.Query = "leak"
	if e := c.Handle(request); e == nil {
		t.Fatal("passkey-list accepted an unrelated selector field")
	}
}

func TestPasskeyConditionalListMetadataOnlyAndReadOnly(t *testing.T) {
	c, s, out, base := paired(t)
	defer c.Close()
	rows, e := s.List("active")
	if e != nil || len(rows) != 1 {
		t.Fatalf("fixture: %v", e)
	}
	login := rows[0].ID
	credential := conditionalPasskey(t, s, login, "dXNlcjE", "fixture-user", "Fixture User")
	epoch := s.PasskeyRevocationEpoch()
	revision := revisionOf(t, s, login)
	managed, err := s.ReadManagedPasskeysMetadata(false)
	if err != nil || len(managed[login]) != 1 || managed[login][0].CredentialID != credential {
		t.Fatalf("managed metadata: %v %#v", err, managed[login])
	}
	want := map[string]string{
		"item_id": login, "revision": revision, "title": rows[0].Title,
		"credential_id": credential, "credential_revision": managed[login][0].Revision,
		"rp_id": "example.test", "user_name": "fixture-user", "display_name": "Fixture User",
	}
	baseline := readVaultReceipt(t, s.VaultPath())
	idle, _ := s.IdleDeadline()

	r := base
	r.ID = reqID(20)
	r.Type = "passkey-list"
	r.ItemID, r.Revision = "", ""
	r.Options = passkeyGetWire("example.test")
	if e = c.Handle(r); e != nil {
		t.Fatal(e)
	}
	frame := candidatesFrame(t, out, r.ID)
	if len(frame) != 5 || frame["v"] != float64(1) || frame["type"] != "passkey-candidates" || frame["truncated"] != false {
		t.Fatalf("unexpected frame %v", frame)
	}
	passkeys, ok := frame["passkeys"].([]any)
	if !ok || len(passkeys) != 1 {
		t.Fatalf("unexpected candidates %v", frame["passkeys"])
	}
	entry := passkeys[0].(map[string]any)
	if len(entry) != 8 {
		t.Fatalf("candidate carried extra fields: %v", entry)
	}
	for key, value := range want {
		if entry[key] != value {
			t.Fatalf("candidate %s = %v want %v", key, entry[key], value)
		}
	}
	for _, forbidden := range []string{"private_key", "user_id", "user_handle", "record", "password", "private"} {
		if strings.Contains(strings.ToLower(spewFrame(t, frame)), forbidden) {
			t.Fatalf("candidate frame leaked %q", forbidden)
		}
	}

	// A read-only listing must not create an approval surface, mutate data,
	// append audit or renew idle authority. Idle is checked before any further
	// session call, because a plain Audit() read is itself an audited action.
	if later, ok := s.IdleDeadline(); !ok || !later.Equal(idle) {
		t.Fatalf("conditional list renewed idle authority: %v %v %v", idle, later, ok)
	}
	if c.Snapshot().Passkey != nil || c.passkey != nil || c.passkeyStatus != "" {
		t.Fatal("conditional list created a native approval")
	}
	// Independent read-only proof of the durable effect: the device slot, the
	// signed snapshot, the audit tip and every audit event raw must be identical.
	if after := readVaultReceipt(t, s.VaultPath()); after != baseline {
		t.Fatalf("conditional list changed durable state: %+v != %+v", after, baseline)
	}
	if s.PasskeyRevocationEpoch() != epoch {
		t.Fatal("conditional list advanced the passkey epoch")
	}
	if revisionOf(t, s, login) != want["revision"] {
		t.Fatal("conditional list mutated the vault")
	}

	// Listing coexists with a pending native approval because it only reads.
	create := base
	create.ID = reqID(21)
	create.Type = "passkey-create"
	create.ItemID, create.Revision = "", ""
	create.Options = string(passkeyCreateWire("dXNlcjk", "new-user", "New User"))
	if e = c.Handle(create); e != nil {
		t.Fatal(e)
	}
	waitPasskey(t, c)
	r.ID = reqID(22)
	if e = c.Handle(r); e != nil {
		t.Fatal(e)
	}
	if got := candidatesFrame(t, out, r.ID); len(got["passkeys"].([]any)) != 1 {
		t.Fatal("list refused while a native approval was pending")
	}
	if pending := c.Snapshot().Passkey; pending == nil || pending.ID != create.ID || pending.Create != true {
		t.Fatal("list disturbed the pending native approval")
	}
	if e = c.RejectPasskey(create.ID); e != nil {
		t.Fatal(e)
	}
}

// vaultReceipt is a raw, read-only digest of the durable vault: the device
// slot, the signed snapshot, the audit tip and every audit event key/value. It
// never reads item plaintext or private keys and is comparable across calls.
type vaultReceipt struct {
	slot, snapshot, tip, audit string
	events                     int
}

func readVaultReceipt(t *testing.T, path string) vaultReceipt {
	t.Helper()
	db, e := bolt.Open(path, 0600, &bolt.Options{ReadOnly: true, Timeout: 5 * time.Second})
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	digest := func(raw []byte) string {
		sum := sha256.Sum256(raw)
		return hex.EncodeToString(sum[:])
	}
	var receipt vaultReceipt
	e = db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("locklark.personal/v1"))
		if b == nil {
			return errors.New("vault bucket missing")
		}
		receipt.slot = digest(b.Get([]byte("device-slot")))
		receipt.snapshot = digest(b.Get([]byte("snapshot")))
		receipt.tip = digest(b.Get([]byte("audit-tip")))
		events := b.Bucket([]byte("audit-events"))
		if events == nil {
			return errors.New("audit bucket missing")
		}
		hash := sha256.New()
		if e := events.ForEach(func(key, value []byte) error {
			receipt.events++
			hash.Write(key)
			hash.Write(value)
			return nil
		}); e != nil {
			return e
		}
		receipt.audit = hex.EncodeToString(hash.Sum(nil))
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	return receipt
}

func spewFrame(t *testing.T, frame map[string]any) string {
	t.Helper()
	raw, e := json.Marshal(frame)
	if e != nil {
		t.Fatal(e)
	}
	return string(raw)
}

func TestPasskeyConditionalListCrossSiteAllowlistAndState(t *testing.T) {
	c, s, out, base := paired(t)
	defer c.Close()
	rows, e := s.List("active")
	if e != nil || len(rows) != 1 {
		t.Fatalf("fixture: %v", e)
	}
	login := rows[0].ID
	credential := conditionalPasskey(t, s, login, "dXNlcjE", "fixture-user", "Fixture User")

	list := func(id string, origin, options string) []any {
		r := base
		r.ID = id
		r.Type = "passkey-list"
		r.Origin = origin
		r.ItemID, r.Revision = "", ""
		r.Options = options
		if e := c.Handle(r); e != nil {
			t.Fatal(e)
		}
		if frame := candidatesFrame(t, out, id); frame["truncated"] != false {
			t.Fatal("empty list must not be truncated")
		}
		return candidatesFrame(t, out, id)["passkeys"].([]any)
	}
	// Cross-site: a valid other-site request never sees this credential.
	if got := list(reqID(30), "https://other.test", passkeyGetWire("other.test")); len(got) != 0 {
		t.Fatal("cross-site list leaked a candidate")
	}
	// A page allow-list that omits the stored credential stays empty.
	foreign := strings.Repeat("A", 43)
	if got := list(reqID(31), "https://example.test", passkeyGetWire("example.test", foreign)); len(got) != 0 {
		t.Fatal("foreign allowCredentials leaked a candidate")
	}
	// The matching allow-list is honoured.
	if got := list(reqID(32), "https://example.test", passkeyGetWire("example.test", credential)); len(got) != 1 {
		t.Fatal("matching allowCredentials lost the candidate")
	}
	// Archived and trashed logins are never offered.
	revision := revisionOf(t, s, login)
	if revision, e = s.SetState(login, revision, "item.archive"); e != nil {
		t.Fatal(e)
	}
	if got := list(reqID(33), "https://example.test", passkeyGetWire("example.test")); len(got) != 0 {
		t.Fatal("archived login was offered")
	}
	if revision, e = s.SetState(login, revision, "item.archive"); e == nil {
		t.Fatal("archived item re-archived")
	}
}

func candidateManaged(candidates []personal.PasskeyCandidate) map[string][]personal.ManagedPasskeyMetadata {
	managed := map[string][]personal.ManagedPasskeyMetadata{}
	for index, candidate := range candidates {
		managed[candidate.ItemID] = append(managed[candidate.ItemID], personal.ManagedPasskeyMetadata{
			CredentialID: candidate.CredentialID,
			Revision:     fmt.Sprintf("%064x", index+1),
		})
	}
	return managed
}

func TestPasskeyCandidatesFrameBounds(t *testing.T) {
	id := reqID(60)
	empty, e := passkeyCandidatesResponse(id, nil, nil)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := json.Marshal(empty)
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(string(raw), `"passkeys":[]`) || !strings.Contains(string(raw), `"truncated":false`) {
		t.Fatalf("empty list must be [] not null: %s", raw)
	}

	many := make([]personal.PasskeyCandidate, 0, MaxPasskeyCandidates+1)
	for n := 0; n <= MaxPasskeyCandidates; n++ {
		many = append(many, personal.PasskeyCandidate{ItemID: reqID(1000 + n), Revision: strings.Repeat("b", 64), Title: "t", CredentialID: strings.Repeat("A", 43), RPID: "example.test", UserName: "u", DisplayName: "d"})
	}
	capped, e := passkeyCandidatesResponse(id, many, candidateManaged(many))
	if e != nil {
		t.Fatal(e)
	}
	if len(capped.Passkeys) != MaxPasskeyCandidates || !capped.PasskeyTruncated {
		t.Fatalf("candidate cap not applied: %d %v", len(capped.Passkeys), capped.PasskeyTruncated)
	}

	huge := make([]personal.PasskeyCandidate, 0, MaxPasskeyCandidates)
	for n := 0; n < MaxPasskeyCandidates; n++ {
		huge = append(huge, personal.PasskeyCandidate{
			ItemID:       reqID(2000 + n),
			Revision:     strings.Repeat("c", 64),
			Title:        strings.Repeat("<&>", 300),
			CredentialID: strings.Repeat("A", 43),
			RPID:         strings.Repeat("<", 200),
			UserName:     strings.Repeat("&", 200),
			DisplayName:  strings.Repeat(">", 200),
		})
	}
	bounded, e := passkeyCandidatesResponse(id, huge, candidateManaged(huge))
	if e != nil {
		t.Fatal(e)
	}
	raw, e = json.Marshal(bounded)
	if e != nil {
		t.Fatal(e)
	}
	if len(raw) >= MaxOutput {
		t.Fatalf("candidate frame exceeds budget: %d", len(raw))
	}
	var decoded struct {
		Passkeys  []BrowserPasskeyCandidate `json:"passkeys"`
		Truncated bool                      `json:"truncated"`
	}
	if e = json.Unmarshal(raw, &decoded); e != nil || !decoded.Truncated || len(decoded.Passkeys) == 0 || len(decoded.Passkeys) >= len(huge) {
		t.Fatalf("budget trim must stay a valid truncated frame: %v %d", e, len(decoded.Passkeys))
	}
}

func TestPasskeySelectedTargetReviewAndNativeApproveGuard(t *testing.T) {
	c, s, out, base := paired(t)
	defer c.Close()
	rows, e := s.List("active")
	if e != nil || len(rows) != 1 {
		t.Fatalf("fixture: %v", e)
	}
	first := rows[0].ID
	firstCredential := conditionalPasskey(t, s, first, "dXNlcjE", "fixture-user", "Fixture User")
	if _, e = s.AddLogin("Second login", "second-user", "second-password"); e != nil {
		t.Fatal(e)
	}
	rows, e = s.List("active")
	if e != nil {
		t.Fatal(e)
	}
	second := ""
	for _, row := range rows {
		if row.ID != first {
			second = row.ID
		}
	}
	if second == "" {
		t.Fatal("second login missing")
	}
	if _, e = s.Edit(personal.Edit{ID: second, Revision: revisionOf(t, s, second), Field: "url", Value: "https://example.test/login"}); e != nil {
		t.Fatal(e)
	}
	secondCredential := conditionalPasskey(t, s, second, "dXNlcjI", "second-user", "Second User")
	if secondCredential == firstCredential {
		t.Fatal("fixture credentials collided")
	}

	// Ordinary get still lists every matching login.
	get := base
	get.ID = reqID(40)
	get.Type = "passkey-get"
	get.ItemID, get.Revision = "", ""
	get.Options = passkeyGetWire("example.test")
	if e = c.Handle(get); e != nil {
		t.Fatal(e)
	}
	if view := waitPasskey(t, c); len(view.Choices) != 2 {
		t.Fatalf("ordinary get choices: %d", len(view.Choices))
	}
	if e = c.RejectPasskey(get.ID); e != nil {
		t.Fatal(e)
	}

	// A pinned get reviews exactly the selected login.
	pinned := base
	pinned.ID = reqID(41)
	pinned.Type = "passkey-get"
	pinned.ItemID = first
	pinned.Revision = revisionOf(t, s, first)
	pinned.Options = passkeyGetWire("example.test")
	if e = c.Handle(pinned); e != nil {
		t.Fatal(e)
	}
	if view := waitPasskey(t, c); len(view.Choices) != 1 || view.Choices[0].ID != first {
		t.Fatalf("pinned review leaked other accounts: %v", view.Choices)
	}
	// The UI cannot promote another account, or skip selection entirely.
	if e = c.ApprovePasskey(pinned.ID, second, nil, nil); e == nil {
		t.Fatal("native approval accepted an unpinned account")
	}
	if e = c.ApprovePasskey(pinned.ID, "", nil, nil); e == nil {
		t.Fatal("native approval accepted an empty selection for a pinned target")
	}
	for _, frame := range frames(t, out) {
		if frame["type"] == "passkey-result" {
			t.Fatal("unselected account was signed")
		}
	}
	if pending := c.Snapshot().Passkey; pending == nil || pending.ID != pinned.ID {
		t.Fatal("refused promotion dropped the pinned request")
	}
	if e = c.ApprovePasskey(pinned.ID, first, nil, nil); e != nil {
		t.Fatal(e)
	}
	var signed passkey.Response
	found := false
	for _, frame := range frames(t, out) {
		if frame["type"] == "passkey-result" {
			if e = json.Unmarshal([]byte(frame["credential"].(string)), &signed); e != nil {
				t.Fatal(e)
			}
			found = true
		}
	}
	if !found || signed.ID != firstCredential {
		t.Fatalf("wrong credential signed: %v", signed.ID)
	}

	// A stale pinned revision is refused instead of widening to other choices.
	stale := base
	stale.ID = reqID(42)
	stale.Type = "passkey-get"
	stale.ItemID = first
	stale.Revision = strings.Repeat("a", 64)
	stale.Options = passkeyGetWire("example.test")
	if e = c.Handle(stale); e != nil {
		t.Fatal(e)
	}
	refused := false
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && !refused {
		for _, frame := range frames(t, out) {
			if frame["id"] == stale.ID && frame["type"] == "error" {
				refused = true
			}
		}
		time.Sleep(time.Millisecond * 5)
	}
	if !refused {
		t.Fatal("stale pinned target was not refused")
	}
	if c.Snapshot().Passkey != nil {
		t.Fatal("stale pinned target stayed pending")
	}
}
