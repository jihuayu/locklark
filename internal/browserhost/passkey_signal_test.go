package browserhost

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/passkey"
	"github.com/jihuayu/locklark/internal/personal"
	bolt "go.etcd.io/bbolt"
)

func signalOptions(t *testing.T, raw string) string {
	t.Helper()
	var check map[string]any
	if err := json.Unmarshal([]byte(raw), &check); err != nil {
		t.Fatalf("signal options: %v", err)
	}
	return raw
}

func signalWire(t *testing.T, value map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func rawFrames(t *testing.T, out *memoryPipe) []json.RawMessage {
	t.Helper()
	out.Lock()
	raw := bytes.Clone(out.Bytes())
	out.Unlock()
	var frames []json.RawMessage
	for len(raw) > 0 {
		if len(raw) < 4 {
			t.Fatal("short frame")
		}
		n := int(binary.NativeEndian.Uint32(raw))
		raw = raw[4:]
		if n > len(raw) {
			t.Fatal("bad frame")
		}
		frames = append(frames, append(json.RawMessage(nil), raw[:n]...))
		raw = raw[n:]
	}
	return frames
}

func waitSignal(t *testing.T, c *Connection) *SignalView {
	t.Helper()
	until := time.Now().Add(3 * time.Second)
	for time.Now().Before(until) {
		if view := c.Snapshot(); view.Signal != nil && !view.Signal.Working {
			return view.Signal
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("signal review never completed")
	return nil
}

func waitSignalStatus(t *testing.T, c *Connection, want string) {
	t.Helper()
	until := time.Now().Add(3 * time.Second)
	for time.Now().Before(until) {
		if view := c.Snapshot(); strings.Contains(view.SignalStatus, want) {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("signal status never reported %q", want)
}

func signalDictionaries(t *testing.T, credential, userID string) []string {
	t.Helper()
	return []string{
		signalOptions(t, `{"kind":"unknown","rpId":"example.test","credentialId":"`+credential+`"}`),
		signalOptions(t, `{"kind":"accepted","rpId":"example.test","userId":"`+userID+`","allAcceptedCredentialIds":[]}`),
		signalOptions(t, `{"kind":"user","rpId":"example.test","userId":"`+userID+`","name":"renamed","displayName":"Renamed"}`),
	}
}

func TestPasskeySignalWireIsStrictAndAckIsExact(t *testing.T) {
	c, out, _, capability, itemID, _, credential := fixturePasskey(t)
	defer c.Close()
	userID := "dXNlcjE"
	base := map[string]any{"v": 1, "id": reqID(200), "type": "passkey-signal", "capability": capability, "origin": "https://example.test", "tab_id": 1, "document_id": "doc-1"}
	for n, options := range signalDictionaries(t, credential, userID) {
		value := map[string]any{}
		for k, v := range base {
			value[k] = v
		}
		value["id"] = reqID(201 + n)
		value["options"] = options
		request := mustReadRequest(t, value)
		if request.Options != options || request.ItemID != "" || request.CredentialID != "" {
			t.Fatalf("parsed signal fields: %#v", request)
		}
	}
	// Wire strictness: every non-signal key, a missing options document and an
	// oversize options document are refused before any ACK can be written.
	before := len(rawFrames(t, out))
	for name, value := range map[string]map[string]any{
		"missing options": func() map[string]any {
			v := map[string]any{}
			for k, x := range base {
				v[k] = x
			}
			v["id"] = reqID(210)
			return v
		}(),
		"extra wire key": func() map[string]any {
			v := map[string]any{}
			for k, x := range base {
				v[k] = x
			}
			v["id"], v["options"], v["kind"] = reqID(211), signalDictionaries(t, credential, userID)[0], "unknown"
			return v
		}(),
		"item selector": func() map[string]any {
			v := map[string]any{}
			for k, x := range base {
				v[k] = x
			}
			v["id"], v["options"], v["item_id"] = reqID(212), signalDictionaries(t, credential, userID)[0], itemID
			return v
		}(),
		"credential field": func() map[string]any {
			v := map[string]any{}
			for k, x := range base {
				v[k] = x
			}
			v["id"], v["options"], v["credential_id"] = reqID(213), signalDictionaries(t, credential, userID)[0], credential
			return v
		}(),
		"missing capability": func() map[string]any {
			v := map[string]any{}
			for k, x := range base {
				v[k] = x
			}
			delete(v, "capability")
			v["id"], v["options"] = reqID(214), signalDictionaries(t, credential, userID)[0]
			return v
		}(),
		"oversize options": func() map[string]any {
			v := map[string]any{}
			for k, x := range base {
				v[k] = x
			}
			v["id"] = reqID(215)
			v["options"] = `{"kind":"unknown","rpId":"example.test","credentialId":"x","pad":"` + strings.Repeat("a", 33<<10) + `"}`
			return v
		}(),
	} {
		if _, err := ReadRequest(bytes.NewReader(frame(signalWire(t, value)))); err == nil {
			t.Fatalf("strict wire accepted %s", name)
		}
	}
	if len(rawFrames(t, out)) != before {
		t.Fatal("refused wire wrote a frame")
	}
	// A valid dictionary that matches nothing still gets the identical fixed
	// acknowledgement, and no follow-up frame of any kind.
	unknown := signalOptions(t, `{"kind":"unknown","rpId":"example.test","credentialId":"`+base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))+`"}`)
	value := map[string]any{}
	for k, x := range base {
		value[k] = x
	}
	value["id"], value["options"] = reqID(220), unknown
	if err := c.Handle(mustReadRequest(t, value)); err != nil {
		t.Fatal(err)
	}
	frames := rawFrames(t, out)
	if len(frames) != before+1 {
		t.Fatalf("no-candidate signal frames: %d", len(frames)-before)
	}
	frames = frames[len(frames)-1:]
	want, _ := json.Marshal(struct {
		V    int    `json:"v"`
		ID   string `json:"id"`
		Type string `json:"type"`
	}{1, reqID(220), "passkey-signal-accepted"})
	if !bytes.Equal(frames[0], want) {
		t.Fatalf("ack frame is not exact: %s want %s", frames[0], want)
	}
	waitSignalStatus(t, c, "没有需要更新")
	if view := c.Snapshot(); view.Signal != nil {
		t.Fatalf("no-candidate signal remained pending: %#v", view.Signal)
	}
}

func TestPasskeySignalMalformedOptionsRefusedWithoutAck(t *testing.T) {
	c, out, _, capability, _, _, credential := fixturePasskey(t)
	defer c.Close()
	base := map[string]any{"v": 1, "type": "passkey-signal", "capability": capability, "origin": "https://example.test", "tab_id": 1, "document_id": "doc-1"}
	n := 0
	for name, options := range map[string]string{
		"unknown key":       `{"kind":"unknown","rpId":"example.test","credentialId":"` + credential + `","extra":1}`,
		"foreign rp":        `{"kind":"unknown","rpId":"evil.test","credentialId":"` + credential + `"}`,
		"public suffix rp":  `{"kind":"unknown","rpId":"test","credentialId":"` + credential + `"}`,
		"duplicate keys":    `{"kind":"unknown","rpId":"example.test","rpId":"example.test","credentialId":"` + credential + `"}`,
		"wrong kind":        `{"kind":"all","rpId":"example.test","credentialId":"` + credential + `"}`,
		"padded credential": `{"kind":"unknown","rpId":"example.test","credentialId":"` + credential + `="}`,
		"not json":          `{"kind":`,
	} {
		value := map[string]any{}
		for k, x := range base {
			value[k] = x
		}
		n++
		value["id"], value["options"] = reqID(230+n), options
		before := len(rawFrames(t, out))
		if err := c.Handle(mustReadRequest(t, value)); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		frames := rawFrames(t, out)
		if len(frames) != before+1 {
			t.Fatalf("%s: %d frames", name, len(frames)-before)
		}
		var refusal Response
		if err := json.Unmarshal(frames[len(frames)-1], &refusal); err != nil || refusal.Type != "error" || refusal.ID != reqID(230+n) {
			t.Fatalf("%s: refusal frame %s", name, frames[len(frames)-1])
		}
		if c.Snapshot().Signal != nil {
			t.Fatalf("%s: malformed options created a pending signal", name)
		}
	}
}

func TestPasskeySignalAcknowledgesAndIgnoresWhileNativeRequestPending(t *testing.T) {
	c, out, _, capability, _, _, credential := fixturePasskey(t)
	defer c.Close()
	create := Request{
		V: 1, ID: reqID(240), Type: "passkey-create", Capability: capability,
		Origin: "https://example.test", TabID: 1, DocumentID: "doc-1",
		Options: `{"challenge":"Y2hhbGxlbmdlLTAxMjM0NTY3ODk","rp":{"id":"example.test","name":"Example"},"user":{"id":"dXNlcjM","name":"third-user","displayName":"Third"},"pubKeyCredParams":[{"type":"public-key","alg":-7}]}`,
	}
	if err := c.Handle(create); err != nil {
		t.Fatal(err)
	}
	pending := waitPasskey(t, c)
	value := map[string]any{"v": 1, "id": reqID(241), "type": "passkey-signal", "capability": capability, "origin": "https://example.test", "tab_id": 1, "document_id": "doc-1", "options": signalDictionaries(t, credential, "dXNlcjE")[0]}
	if err := c.Handle(mustReadRequest(t, value)); err != nil {
		t.Fatal(err)
	}
	frames := rawFrames(t, out)
	var ack Response
	if err := json.Unmarshal(frames[len(frames)-1], &ack); err != nil || ack.Type != "passkey-signal-accepted" || ack.ID != reqID(241) {
		t.Fatalf("busy ack: %s", frames[len(frames)-1])
	}
	view := c.Snapshot()
	if view.Signal != nil {
		t.Fatal("busy hint created a pending signal")
	}
	if after := view.Passkey; after == nil || after.ID != create.ID || len(after.Choices) != len(pending.Choices) {
		t.Fatalf("busy hint disturbed the pending passkey request: %#v", after)
	}
	if err := c.RejectPasskey(create.ID); err != nil {
		t.Fatal(err)
	}
}

func TestPasskeySignalOwnerApprovalAppliesWithoutFollowUpFrame(t *testing.T) {
	c, out, s, capability, itemID, _, credential := fixturePasskey(t)
	defer c.Close()
	options := signalOptions(t, `{"kind":"user","rpId":"example.test","userId":"dXNlcjE","name":"renamed","displayName":"Renamed"}`)
	value := map[string]any{"v": 1, "id": reqID(250), "type": "passkey-signal", "capability": capability, "origin": "https://example.test", "tab_id": 1, "document_id": "doc-1", "options": options}
	before := len(rawFrames(t, out))
	if err := c.Handle(mustReadRequest(t, value)); err != nil {
		t.Fatal(err)
	}
	proposal := waitSignal(t, c)
	if proposal.ID != reqID(250) || proposal.Kind != "user" || len(proposal.Changes) != 1 || proposal.Changes[0].ItemID != itemID || proposal.Changes[0].Name != "renamed" {
		t.Fatalf("owner review: %#v", proposal)
	}
	// The page received exactly the acknowledgement; the review itself emits
	// nothing and the origin is the browser-asserted one.
	if frames := rawFrames(t, out); len(frames) != before+1 {
		t.Fatalf("signal review frames: %d", len(frames)-before)
	}
	if proposal.Origin != "https://example.test" || proposal.RPID != "example.test" {
		t.Fatalf("review origin/rp: %#v", proposal)
	}
	if err := c.ApprovePasskeySignal(reqID(250)); err != nil {
		t.Fatal(err)
	}
	if frames := rawFrames(t, out); len(frames) != before+1 {
		t.Fatalf("signal commit wrote a follow-up frame: %d", len(frames)-before)
	}
	view := c.Snapshot()
	if view.Signal != nil || !strings.Contains(view.SignalStatus, "已按网站信号") {
		t.Fatalf("owner status after commit: %#v %q", view.Signal, view.SignalStatus)
	}
	metadata, err := s.ReadPasskeyMetadata(false)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := metadata[itemID]; !ok || got.CredentialID != credential || got.UserName != "renamed" || got.DisplayName != "Renamed" || got.RPID != "example.test" {
		t.Fatalf("owner approval did not update the exact credential names: %#v", got)
	}
	// A second approval cannot replay the same bounded surface.
	if err := c.ApprovePasskeySignal(reqID(250)); err == nil {
		t.Fatal("completed signal was approved twice")
	}
}

func TestPasskeySignalOwnerApprovalRemovalAndReject(t *testing.T) {
	c, out, s, capability, itemID, _, credential := fixturePasskey(t)
	defer c.Close()
	epoch := s.PasskeyRevocationEpoch()
	options := signalOptions(t, `{"kind":"unknown","rpId":"example.test","credentialId":"`+credential+`"}`)
	value := map[string]any{"v": 1, "id": reqID(260), "type": "passkey-signal", "capability": capability, "origin": "https://example.test", "tab_id": 1, "document_id": "doc-1", "options": options}
	before := len(rawFrames(t, out))
	if err := c.Handle(mustReadRequest(t, value)); err != nil {
		t.Fatal(err)
	}
	if view := waitSignal(t, c); len(view.Changes) != 1 || view.Changes[0].Action != "remove" {
		t.Fatalf("removal review: %#v", view)
	}
	if err := c.RejectPasskeySignal(reqID(260)); err != nil {
		t.Fatal(err)
	}
	if view := c.Snapshot(); view.Signal != nil || !strings.Contains(view.SignalStatus, "已忽略") {
		t.Fatalf("reject status: %#v %q", view.Signal, view.SignalStatus)
	}
	metadata, err := s.ReadPasskeyMetadata(false)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := metadata[itemID]; !ok {
		t.Fatal("rejected signal removed the credential")
	}
	if s.PasskeyRevocationEpoch() != epoch {
		t.Fatal("rejected signal advanced the revocation epoch")
	}
	if frames := rawFrames(t, out); len(frames) != before+1 {
		t.Fatalf("reject/ack frames: %d", len(frames)-before)
	}
	// Now a fresh hint is approved and removes the credential; the page still
	// sees no follow-up frame and the conservative epoch advances.
	value["id"] = reqID(261)
	if err := c.Handle(mustReadRequest(t, value)); err != nil {
		t.Fatal(err)
	}
	if view := waitSignal(t, c); len(view.Changes) != 1 {
		t.Fatalf("second removal review: %#v", view)
	}
	if err := c.ApprovePasskeySignal(reqID(261)); err != nil {
		t.Fatal(err)
	}
	metadata, err = s.ReadPasskeyMetadata(false)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := metadata[itemID]; ok {
		t.Fatal("approved signal did not remove the credential")
	}
	if s.PasskeyRevocationEpoch() != epoch+1 {
		t.Fatal("approved removal did not advance the revocation epoch")
	}
	if frames := rawFrames(t, out); len(frames) != before+2 {
		t.Fatalf("removal commit frames: %d", len(frames)-before)
	}
}

func TestPasskeySignalClearedOnLockAndRejectsStaleApproval(t *testing.T) {
	c, out, s, capability, itemID, _, credential := fixturePasskey(t)
	defer c.Close()
	options := signalOptions(t, `{"kind":"unknown","rpId":"example.test","credentialId":"`+credential+`"}`)
	value := map[string]any{"v": 1, "id": reqID(270), "type": "passkey-signal", "capability": capability, "origin": "https://example.test", "tab_id": 1, "document_id": "doc-1", "options": options}
	if err := c.Handle(mustReadRequest(t, value)); err != nil {
		t.Fatal(err)
	}
	waitSignal(t, c)
	c.InvalidateDesktopLock()
	for until := time.Now().Add(time.Second); time.Now().Before(until); {
		if c.Snapshot().Signal == nil {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if c.Snapshot().Signal != nil {
		t.Fatal("lock left the signal approval surface pending")
	}
	if err := c.ApprovePasskeySignal(reqID(270)); err == nil {
		t.Fatal("signal approved after lock")
	}
	// The locked hint is refused as an authenticated error and never produces
	// a fixed acknowledgement.
	locked := map[string]any{}
	for k, v := range value {
		locked[k] = v
	}
	locked["id"] = reqID(271)
	if err := c.Handle(mustReadRequest(t, locked)); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, frame := range rawFrames(t, out) {
		var response Response
		if json.Unmarshal(frame, &response) != nil {
			t.Fatalf("bad frame %s", frame)
		}
		if response.ID == reqID(271) {
			found = response.Type == "error"
			if response.Type == "passkey-signal-accepted" {
				t.Fatal("locked hint acknowledged")
			}
		}
	}
	if !found {
		t.Fatal("locked hint produced no refusal")
	}
	_ = itemID
	if got := s.PasskeyRevocationEpoch(); got != 0 {
		t.Fatalf("lock advanced the revocation epoch: %d", got)
	}
}

// signalConnectionFixture creates a paired connection, one login and one
// passkey credential, and also returns the vault path so a test can hold a
// real bbolt write transaction and block the owner confirmation mid-commit.
func signalConnectionFixture(t *testing.T) (*Connection, *memoryPipe, *personal.Session, string, string, string, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "signal.ll")
	key := bytes.Repeat([]byte{5}, 16)
	if err := personal.Create(path, "fixture", key); err != nil {
		t.Fatal(err)
	}
	s, err := personal.UnlockSession(path, []byte("fixture"), key, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Lock)
	id, err := s.AddLogin("Existing", "alice", "old-password")
	if err != nil {
		t.Fatal(err)
	}
	rows, err := s.List("active")
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.ID == id {
			if _, err := s.Edit(personal.Edit{ID: id, Revision: row.Revision, Field: "url", Value: "https://example.test/login"}); err != nil {
				t.Fatal(err)
			}
		}
	}
	out := &memoryPipe{}
	c := NewConnection(NewWriter(out, time.Second), nil)
	if err := c.Handle(Request{V: 1, ID: reqID(1), Type: "hello"}); err != nil {
		t.Fatal(err)
	}
	if err := c.ApproveQuickPair(s); err != nil {
		t.Fatal(err)
	}
	capability := out.responses(t)[0].Capability
	create := Request{
		V: 1, ID: reqID(30), Type: "passkey-create", Capability: capability,
		Origin: "https://example.test", TabID: 1, DocumentID: "doc-1",
		Options: `{"challenge":"Y2hhbGxlbmdlLTAxMjM0NTY3ODk","rp":{"id":"example.test","name":"Example"},"user":{"id":"dXNlcjE","name":"signal-fixture-user","displayName":"Signal Fixture"},"pubKeyCredParams":[{"type":"public-key","alg":-7}]}`,
	}
	if err := c.Handle(create); err != nil {
		t.Fatal(err)
	}
	pending := waitPasskey(t, c)
	itemID := pending.Choices[0].ID
	if err := c.ApprovePasskey(create.ID, itemID, nil, nil); err != nil {
		t.Fatal(err)
	}
	metadata, err := s.ReadPasskeyMetadata(false)
	if err != nil {
		t.Fatal(err)
	}
	credential := metadata[itemID].CredentialID
	if !passkey.ValidCredentialID(credential) {
		t.Fatalf("fixture credential: %q", credential)
	}
	return c, out, s, capability, itemID, credential, path
}

// blockVaultWrites holds the single bbolt writer for path until the returned
// release function is called. The aborted transaction writes nothing.
func blockVaultWrites(t *testing.T, path string) func() {
	t.Helper()
	db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	started, release := make(chan struct{}), make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		_ = db.Update(func(*bolt.Tx) error {
			close(started)
			<-release
			return errors.New("blocking transaction aborted")
		})
		_ = db.Close()
	}()
	<-started
	return func() {
		close(release)
		<-finished
	}
}

func waitApplyBlocked(t *testing.T) {
	t.Helper()
	until := time.Now().Add(5 * time.Second)
	for time.Now().Before(until) {
		stack := make([]byte, 1<<18)
		n := runtime.Stack(stack, true)
		for _, goroutine := range strings.Split(string(stack[:n]), "\n\n") {
			if strings.Contains(goroutine, "(*Session).ApplyPasskeySignal") {
				return
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("owner confirmation never reached the blocked transaction")
}

func assertSignalWroteNothing(t *testing.T, path, itemID string) {
	t.Helper()
	key := bytes.Repeat([]byte{5}, 16)
	next, err := personal.UnlockSession(path, []byte("fixture"), key, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Lock()
	metadata, err := next.ReadPasskeyMetadata(false)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := metadata[itemID]; !ok {
		t.Fatal("cancelled signal removed the credential")
	}
	events, err := next.Audit()
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		if event.Action == "item.passkey.signal" {
			t.Fatal("cancelled signal appended an audit event")
		}
	}
}

func TestPasskeySignalRejectWhileApplyWaitsCancelsCommit(t *testing.T) {
	c, out, _, capability, itemID, credential, path := signalConnectionFixture(t)
	defer c.Close()
	options := signalOptions(t, `{"kind":"unknown","rpId":"example.test","credentialId":"`+credential+`"}`)
	value := map[string]any{"v": 1, "id": reqID(300), "type": "passkey-signal", "capability": capability, "origin": "https://example.test", "tab_id": 1, "document_id": "doc-1", "options": options}
	before := len(rawFrames(t, out))
	if err := c.Handle(mustReadRequest(t, value)); err != nil {
		t.Fatal(err)
	}
	if view := waitSignal(t, c); len(view.Changes) != 1 || view.Changes[0].Action != "remove" {
		t.Fatalf("review: %#v", view)
	}
	release := blockVaultWrites(t, path)
	done := make(chan error, 1)
	go func() { done <- c.ApprovePasskeySignal(reqID(300)) }()
	waitApplyBlocked(t)
	if err := c.RejectPasskeySignal(reqID(300)); err != nil {
		t.Fatal(err)
	}
	release()
	if err := <-done; err == nil {
		t.Fatal("rejected confirmation reported success")
	}
	view := c.Snapshot()
	if view.Signal != nil || !strings.Contains(view.SignalStatus, "未应用") {
		t.Fatalf("owner status after rejected commit: %#v %q", view.Signal, view.SignalStatus)
	}
	if frames := rawFrames(t, out); len(frames) != before+1 {
		t.Fatalf("rejected confirmation wrote a page frame: %d", len(frames)-before)
	}
	assertSignalWroteNothing(t, path, itemID)
}

func TestPasskeySignalLockWhileApplyWaitsWritesNothing(t *testing.T) {
	c, out, _, capability, itemID, credential, path := signalConnectionFixture(t)
	defer c.Close()
	options := signalOptions(t, `{"kind":"unknown","rpId":"example.test","credentialId":"`+credential+`"}`)
	value := map[string]any{"v": 1, "id": reqID(310), "type": "passkey-signal", "capability": capability, "origin": "https://example.test", "tab_id": 1, "document_id": "doc-1", "options": options}
	if err := c.Handle(mustReadRequest(t, value)); err != nil {
		t.Fatal(err)
	}
	waitSignal(t, c)
	release := blockVaultWrites(t, path)
	done := make(chan error, 1)
	go func() { done <- c.ApprovePasskeySignal(reqID(310)) }()
	waitApplyBlocked(t)
	c.InvalidateDesktopLock()
	release()
	if err := <-done; err == nil {
		t.Fatal("locked confirmation reported success")
	}
	view := c.Snapshot()
	if view.Signal != nil || !strings.Contains(view.SignalStatus, "未应用") {
		t.Fatalf("owner status after locked commit: %#v %q", view.Signal, view.SignalStatus)
	}
	for _, frame := range rawFrames(t, out) {
		var response Response
		if json.Unmarshal(frame, &response) == nil && response.Type == "passkey-signal-accepted" && response.ID != reqID(310) {
			t.Fatalf("unexpected acknowledgement: %s", frame)
		}
	}
	assertSignalWroteNothing(t, path, itemID)
}

func TestPasskeySignalResultNeverClaimsSuccessAfterLateRevocation(t *testing.T) {
	c, _, s, _, _, credential, _ := signalConnectionFixture(t)
	defer c.Close()
	options := signalOptions(t, `{"kind":"unknown","rpId":"example.test","credentialId":"`+credential+`"}`)
	request, err := personal.ParsePasskeySignal("https://example.test", []byte(options))
	if err != nil {
		t.Fatal(err)
	}
	proposal, err := s.ReviewPasskeySignal(request)
	if err != nil || len(proposal.Changes) != 1 {
		t.Fatalf("review: %#v %v", proposal, err)
	}
	gate := personal.NewMutationGate(time.Now().Add(time.Minute))
	if err := s.RegisterMutation(gate); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApplyPasskeySignal(request, proposal.Changes, gate); err != nil {
		t.Fatal(err)
	}
	if !gate.CommitWon() {
		t.Fatal("successful apply did not win the commit")
	}
	if status, ok := signalResult(nil, gate, false); ok || !strings.Contains(status, "未确认") {
		t.Fatalf("late revocation after commit claimed success: %q %v", status, ok)
	}
	if status, ok := signalResult(nil, gate, true); !ok || !strings.Contains(status, "已按网站信号") {
		t.Fatalf("live commit: %q %v", status, ok)
	}
	cancelled := personal.NewMutationGate(time.Now().Add(time.Minute))
	cancelled.Cancel()
	if status, ok := signalResult(personal.ErrMutationCancelled, cancelled, false); ok || !strings.Contains(status, "未应用") {
		t.Fatalf("pre-commit cancellation: %q %v", status, ok)
	}
	if status, ok := signalResult(personal.ErrMutationUnknown, gate, false); ok || !strings.Contains(status, "未确认") {
		t.Fatalf("unknown commit: %q %v", status, ok)
	}
}

func TestPasskeySignalConcurrentRejectApproveAndSnapshot(t *testing.T) {
	c, out, _, capability, _, _, _ := signalConnectionFixture(t)
	defer c.Close()
	options := signalOptions(t, `{"kind":"user","rpId":"example.test","userId":"dXNlcjE","name":"race","displayName":"Race"}`)
	value := map[string]any{"v": 1, "id": reqID(320), "type": "passkey-signal", "capability": capability, "origin": "https://example.test", "tab_id": 1, "document_id": "doc-1", "options": options}
	before := len(rawFrames(t, out))
	if err := c.Handle(mustReadRequest(t, value)); err != nil {
		t.Fatal(err)
	}
	waitSignal(t, c)
	var wg sync.WaitGroup
	wg.Add(3)
	go func() { defer wg.Done(); _ = c.ApprovePasskeySignal(reqID(320)) }()
	go func() { defer wg.Done(); _ = c.RejectPasskeySignal(reqID(320)) }()
	go func() {
		defer wg.Done()
		for n := 0; n < 64; n++ {
			_ = c.Snapshot()
		}
	}()
	wg.Wait()
	if frames := rawFrames(t, out); len(frames) != before+1 {
		t.Fatalf("concurrent owner actions wrote a page frame: %d", len(frames)-before)
	}
}
