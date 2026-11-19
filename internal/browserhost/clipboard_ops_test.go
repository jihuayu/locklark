package browserhost

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/nativeclipboard"
	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/vault"
)

type clipboardFake struct {
	mu             sync.Mutex
	queue          []func()
	writes         int
	clears         int
	values         [][]byte
	lastClearUntil time.Time
	fail           bool
}

func (f *clipboardFake) dispatch(fn func()) bool {
	f.mu.Lock()
	f.queue = append(f.queue, fn)
	f.mu.Unlock()
	return true
}

func (f *clipboardFake) runNext() bool {
	f.mu.Lock()
	if len(f.queue) == 0 {
		f.mu.Unlock()
		return false
	}
	fn := f.queue[0]
	f.queue = f.queue[1:]
	f.mu.Unlock()
	fn()
	return true
}

func (f *clipboardFake) runAll() {
	for f.runNext() {
	}
}

func (f *clipboardFake) write(value []byte, clearUntil time.Time, valid func() bool) (*nativeclipboard.Lease, error) {
	if !valid() {
		return nil, nativeclipboard.ErrWrite
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.writes++
	f.values = append(f.values, bytes.Clone(value))
	f.lastClearUntil = clearUntil
	if f.fail {
		return nil, nativeclipboard.ErrWrite
	}
	return &nativeclipboard.Lease{}, nil
}

func (f *clipboardFake) clear(*nativeclipboard.Lease) nativeclipboard.Result {
	f.mu.Lock()
	f.clears++
	f.mu.Unlock()
	return nativeclipboard.Cleared
}

func (f *clipboardFake) count() (int, [][]byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([][]byte, len(f.values))
	for i := range f.values {
		out[i] = bytes.Clone(f.values[i])
	}
	return f.writes, out
}

func (f *clipboardFake) clearCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.clears
}

func (f *clipboardFake) deadline() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastClearUntil
}

func clipboardManager(c *Connection) *nativeclipboard.Manager {
	if state := c.clipboard.Load(); state != nil {
		return state.manager
	}
	return nil
}

// clipboardOfferPending is a test-only observation of the unexported Manager
// field. It adds no product hook and is used to prove a stale continuation
// never leaves a secret offer behind.
func clipboardOfferPending(m *nativeclipboard.Manager) bool {
	if m == nil {
		return false
	}
	return !reflect.ValueOf(m).Elem().FieldByName("offer").IsNil()
}

// clipboardDigest builds a 64-hex opaque ticket shape for negative tests.
func clipboardDigest(n int) string { return reqID(n) + reqID(n) }

func clipboardFixture(t *testing.T, fake *clipboardFake, ttl time.Duration) (*Connection, *memoryPipe, *personal.Session, string, string) {
	t.Helper()
	if !nativeclipboard.NativeLeaseSupported() {
		t.Skip("native clipboard leases are unavailable; platform fallback has separate coverage")
	}
	path := filepath.Join(t.TempDir(), "clipboard.ll")
	key := bytes.Repeat([]byte{5}, 16)
	if e := personal.Create(path, "clipboard", key); e != nil {
		t.Fatal(e)
	}
	s, e := personal.UnlockSession(path, []byte("clipboard"), key, 2*time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(s.Lock)
	id, e := s.AddLogin("Clipboard", "clipboard-user", "clipboard-secret")
	if e != nil {
		t.Fatal(e)
	}
	rows, e := s.List("active")
	if e != nil || len(rows) != 1 {
		t.Fatalf("rows: %v %#v", e, rows)
	}
	out := &memoryPipe{}
	c := NewDesktopConnection(NewWriter(out, time.Second), nil)
	if fake != nil {
		m := nativeclipboard.NewManagerWithWriter(fake.dispatch, fake.write, fake.clear)
		c.setClipboard(m, ttl)
	}
	if e = c.bindDesktopSession(s, 1, false, false); e != nil {
		t.Fatal(e)
	}
	return c, out, s, id, rows[0].Revision
}

func clipboardRequest(c *Connection, id int, kind string) Request {
	return Request{V: 1, ID: reqID(id), Type: kind, Capability: c.capability}
}

// clipboardHandle runs one request and returns only the response whose ID
// matches it. Async work for other request IDs may append its response first,
// so the last newly observed frame is not necessarily the requested reply.
func clipboardHandle(t *testing.T, c *Connection, out *memoryPipe, r Request) Response {
	t.Helper()
	if e := c.Handle(r); e != nil {
		t.Fatalf("handle %s: %v", r.Type, e)
	}
	return clipboardReply(t, out, r.ID)
}

// clipboardReply waits up to one second for the response carrying id.
func clipboardReply(t *testing.T, out *memoryPipe, id string) Response {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		for _, resp := range out.responses(t) {
			if resp.ID == id {
				return resp
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("no response for request id")
	return Response{}
}

func clipboardWait(t *testing.T, out *memoryPipe, before int) Response {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		all := out.responses(t)
		if len(all) > before {
			return all[len(all)-1]
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("clipboard response timed out")
	return Response{}
}

func TestClipboardPrepareNativeNoWriteNoSecret(t *testing.T) {
	fake := &clipboardFake{}
	c, out, _, id, rev := clipboardFixture(t, fake, 5*time.Second)
	t.Cleanup(c.Close)
	r := clipboardRequest(c, 10, "prepare-copy-field")
	r.ItemID, r.Revision, r.Field = id, rev, "password"
	resp := clipboardHandle(t, c, out, r)
	if resp.Type != "copy-prepared" || !revision.MatchString(resp.CopyTicket) {
		t.Fatalf("prepare: %#v", resp)
	}
	// The configured clear interval starts after the slow read, so the report
	// is a real bounded remainder, never a blind five-second constant.
	if resp.CopyMode != "native" || resp.CleanupTTLSeconds < 4 || resp.CleanupTTLSeconds > 5 {
		t.Fatalf("prepare metadata: %#v", resp)
	}
	if resp.ExpiresInSeconds <= 0 || resp.ExpiresInSeconds > 10 {
		t.Fatalf("offer lease metadata: %#v", resp)
	}
	if resp.FieldValue != "" || resp.Password != "" {
		t.Fatalf("prepare leaked a value: %#v", resp)
	}
	raw, e := resp.MarshalJSON()
	if e != nil || bytes.Contains(raw, []byte("clipboard-secret")) || bytes.Contains(raw, []byte(`"value"`)) {
		t.Fatalf("prepare wire leaked: %s %v", raw, e)
	}
	if writes, _ := fake.count(); writes != 0 {
		t.Fatalf("prepare wrote natively: %d", writes)
	}
}

func TestClipboardCommitExactOneNativeWrite(t *testing.T) {
	fake := &clipboardFake{}
	c, out, _, id, rev := clipboardFixture(t, fake, 0)
	t.Cleanup(c.Close)
	prep := clipboardRequest(c, 11, "prepare-copy-field")
	prep.ItemID, prep.Revision, prep.Field = id, rev, "password"
	ticket := clipboardHandle(t, c, out, prep).CopyTicket
	commit := clipboardRequest(c, 12, "commit-copy-field")
	commit.CopyTicket = ticket
	before := len(out.responses(t))
	if e := c.Handle(commit); e != nil {
		t.Fatal(e)
	}
	if writes, _ := fake.count(); writes != 0 {
		t.Fatal("commit wrote before native dispatch ran")
	}
	if !fake.runNext() {
		t.Fatal("commit was not dispatched")
	}
	resp := clipboardWait(t, out, before)
	if resp.Type != "copy-result" || resp.State != "confirmed" || !resp.Copied || resp.CopyTicket != ticket || resp.CopyMode != "native" {
		t.Fatalf("commit receipt: %#v", resp)
	}
	if resp.FieldValue != "" || resp.Password != "" {
		t.Fatalf("commit leaked a value: %#v", resp)
	}
	writes, values := fake.count()
	if writes != 1 || len(values) != 1 || string(values[0]) != "clipboard-secret" {
		t.Fatalf("native writes: %d %q", writes, values)
	}
}

func TestClipboardUnknownNeverRetried(t *testing.T) {
	fake := &clipboardFake{fail: true}
	c, out, _, id, rev := clipboardFixture(t, fake, 0)
	t.Cleanup(c.Close)
	prep := clipboardRequest(c, 13, "prepare-copy-field")
	prep.ItemID, prep.Revision, prep.Field = id, rev, "password"
	ticket := clipboardHandle(t, c, out, prep).CopyTicket
	commit := clipboardRequest(c, 14, "commit-copy-field")
	commit.CopyTicket = ticket
	before := len(out.responses(t))
	if e := c.Handle(commit); e != nil {
		t.Fatal(e)
	}
	fake.runNext()
	resp := clipboardWait(t, out, before)
	if resp.Type != "copy-result" || resp.State != "unknown" || resp.Copied || resp.FieldValue != "" {
		t.Fatalf("unknown receipt: %#v", resp)
	}
	if fake.runNext() {
		t.Fatal("unknown outcome was retried")
	}
	if writes, _ := fake.count(); writes != 1 {
		t.Fatalf("unknown retried writes: %d", writes)
	}
}

func TestClipboardStrictRefusalsAndQueuedCancelNoWrite(t *testing.T) {
	fake := &clipboardFake{}
	c, out, s, id, rev := clipboardFixture(t, fake, 0)
	t.Cleanup(c.Close)
	wrongCap := clipboardRequest(c, 15, "prepare-copy-field")
	wrongCap.Capability = reqID(9999)
	wrongCap.ItemID, wrongCap.Revision, wrongCap.Field = id, rev, "password"
	if resp := clipboardHandle(t, c, out, wrongCap); resp.Type != "error" {
		t.Fatalf("wrong capability: %#v", resp)
	}
	stale := clipboardRequest(c, 16, "prepare-copy-field")
	stale.ItemID, stale.Revision, stale.Field = id, clipboardDigest(77), "password"
	if resp := clipboardHandle(t, c, out, stale); resp.Type != "error" {
		t.Fatalf("stale parent: %#v", resp)
	}
	extra := clipboardRequest(c, 17, "prepare-copy-field")
	extra.ItemID, extra.Revision, extra.Field, extra.FieldAction = id, rev, "password", "copy"
	if extra.valid() {
		t.Fatal("extra selector was accepted")
	}
	prep := clipboardRequest(c, 18, "prepare-copy-field")
	prep.ItemID, prep.Revision, prep.Field = id, rev, "password"
	ticket := clipboardHandle(t, c, out, prep).CopyTicket
	wrong := clipboardRequest(c, 19, "commit-copy-field")
	wrong.CopyTicket = clipboardDigest(88)
	if resp := clipboardHandle(t, c, out, wrong); resp.Type != "error" {
		t.Fatalf("wrong ticket: %#v", resp)
	}
	if writes, _ := fake.count(); writes != 0 {
		t.Fatal("refusals wrote natively")
	}
	commit := clipboardRequest(c, 20, "commit-copy-field")
	commit.CopyTicket = ticket
	before := len(out.responses(t))
	if e := c.Handle(commit); e != nil {
		t.Fatal(e)
	}
	cancel := clipboardRequest(c, 21, "cancel-copy-field")
	cancel.CopyTicket = ticket
	if e := c.Handle(cancel); e != nil {
		t.Fatal(e)
	}
	if !fake.runNext() {
		t.Fatal("cancelled commit did not dispatch")
	}
	resp := clipboardWait(t, out, before+1)
	if resp.Type != "copy-result" || resp.State != "refused" {
		t.Fatalf("queued cancel receipt: %#v", resp)
	}
	if writes, _ := fake.count(); writes != 0 {
		t.Fatalf("queued cancel wrote natively: %d", writes)
	}
	s.Lock()
	expired := clipboardRequest(c, 22, "prepare-copy-field")
	expired.ItemID, expired.Revision, expired.Field = id, rev, "password"
	if resp := clipboardHandle(t, c, out, expired); resp.Type != "error" {
		t.Fatalf("locked session: %#v", resp)
	}
}

func TestClipboardCapabilityOnlyFromBrokerCallback(t *testing.T) {
	c, out, _, id, rev := clipboardFixture(t, nil, 0)
	t.Cleanup(c.Close)
	for _, capability := range c.capabilities() {
		if capability == clipboardCapability {
			t.Fatal("clipboard capability was standalone")
		}
	}
	prep := clipboardRequest(c, 23, "prepare-copy-field")
	prep.ItemID, prep.Revision, prep.Field = id, rev, "password"
	if resp := clipboardHandle(t, c, out, prep); resp.Type != "error" {
		t.Fatalf("prepare without callback: %#v", resp)
	}
	fake := &clipboardFake{}
	broker := NewBroker(BrokerCallbacks{NewClipboard: func() (*nativeclipboard.Manager, time.Duration) {
		return nativeclipboard.NewManagerWithWriter(fake.dispatch, fake.write, fake.clear), 3 * time.Second
	}})
	c.SetBroker(broker)
	found := false
	for _, capability := range c.capabilities() {
		found = found || capability == clipboardCapability
	}
	if !found {
		t.Fatal("callback did not advertise clipboard capability")
	}
	// A refused id is replay-guarded, so the retry uses a fresh request id.
	prep = clipboardRequest(c, 24, "prepare-copy-field")
	prep.ItemID, prep.Revision, prep.Field = id, rev, "password"
	resp := clipboardHandle(t, c, out, prep)
	if resp.Type != "copy-prepared" || resp.CleanupTTLSeconds != 3 {
		t.Fatalf("callback prepare: %#v", resp)
	}
}

func TestClipboardConfiguredClearIntervalNotOfferLease(t *testing.T) {
	for _, seconds := range []int{30, 3600} {
		fake := &clipboardFake{}
		ttl := time.Duration(seconds) * time.Second
		c, out, _, id, rev := clipboardFixture(t, fake, ttl)
		prep := clipboardRequest(c, 30+seconds, "prepare-copy-field")
		prep.ItemID, prep.Revision, prep.Field = id, rev, "password"
		resp := clipboardHandle(t, c, out, prep)
		if resp.Type != "copy-prepared" || resp.CleanupTTLSeconds < seconds-1 || resp.CleanupTTLSeconds > seconds {
			t.Fatalf("%ds configured clear reported %#v", seconds, resp)
		}
		if resp.ExpiresInSeconds < 1 || resp.ExpiresInSeconds > 10 {
			t.Fatalf("%ds offer lease was not separate: %#v", seconds, resp)
		}
		commit := clipboardRequest(c, 31+seconds, "commit-copy-field")
		commit.CopyTicket = resp.CopyTicket
		before := len(out.responses(t))
		if e := c.Handle(commit); e != nil {
			t.Fatal(e)
		}
		if !fake.runNext() {
			t.Fatal("commit was not dispatched")
		}
		if got := clipboardWait(t, out, before); got.State != "confirmed" {
			t.Fatalf("commit: %#v", got)
		}
		remaining := time.Until(fake.deadline())
		if remaining < ttl-time.Second || remaining > ttl {
			t.Fatalf("%ds native clear deadline is not configured interval: %v", seconds, remaining)
		}
		c.Close()
	}
}

func TestClipboardInvalidConfiguredClearFailsClosed(t *testing.T) {
	for _, ttl := range []time.Duration{-time.Second, 2 * time.Hour} {
		fake := &clipboardFake{}
		c, out, _, id, rev := clipboardFixture(t, fake, ttl)
		t.Cleanup(c.Close)
		for _, capability := range c.capabilities() {
			if capability == clipboardCapability {
				t.Fatalf("invalid ttl %v advertised capability", ttl)
			}
		}
		prep := clipboardRequest(c, 41, "prepare-copy-field")
		prep.ItemID, prep.Revision, prep.Field = id, rev, "password"
		if resp := clipboardHandle(t, c, out, prep); resp.Type != "error" {
			t.Fatalf("invalid ttl %v prepared: %#v", ttl, resp)
		}
		if writes, _ := fake.count(); writes != 0 {
			t.Fatalf("invalid ttl %v wrote", ttl)
		}
	}
}

func TestClipboardOTPAbsoluteExpiryConfigOff(t *testing.T) {
	fake := &clipboardFake{}
	c, out, s, _, _ := clipboardFixture(t, fake, 0)
	t.Cleanup(c.Close)
	gate := personal.NewMutationGate(time.Now().Add(time.Minute))
	if e := s.RegisterMutation(gate); e != nil {
		t.Fatal(e)
	}
	otpID, otpRev, e := s.AddItem(vault.Item{Kind: "login", Category: vault.CategoryLogin, Title: "OTP",
		Username: "otp-user", Password: "otp-secret", OTP: "otpauth://totp/Example?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&period=30"}, gate)
	if e != nil {
		t.Fatal(e)
	}
	prep := clipboardRequest(c, 42, "prepare-copy-field")
	prep.ItemID, prep.Revision, prep.Field = otpID, otpRev, "otp"
	resp := clipboardHandle(t, c, out, prep)
	if resp.Type != "copy-prepared" || resp.CleanupTTLSeconds < 1 || resp.CleanupTTLSeconds > 30 {
		t.Fatalf("otp prepare: %s %s", resp.Type, resp.Error)
	}
	commit := clipboardRequest(c, 43, "commit-copy-field")
	commit.CopyTicket = resp.CopyTicket
	before := len(out.responses(t))
	if e := c.Handle(commit); e != nil {
		t.Fatal(e)
	}
	if !fake.runNext() {
		t.Fatal("otp commit was not dispatched")
	}
	if got := clipboardWait(t, out, before); got.State != "confirmed" {
		t.Fatalf("otp commit: %#v", got)
	}
	// Config zero disables the ordinary interval, but the OTP code still
	// clears at its absolute window expiry, never at a reconstructed floor.
	deadline := fake.deadline()
	if deadline.IsZero() || deadline.Nanosecond() != 0 || !time.Now().Before(deadline) || time.Until(deadline) > 30*time.Second {
		t.Fatalf("otp clear deadline is not absolute expiry: %v", deadline)
	}
}

func TestClipboardExpiredGrantAllowsNewPrepare(t *testing.T) {
	fake := &clipboardFake{}
	c, out, _, id, rev := clipboardFixture(t, fake, 0)
	t.Cleanup(c.Close)
	prep := clipboardRequest(c, 50, "prepare-copy-field")
	prep.ItemID, prep.Revision, prep.Field = id, rev, "password"
	first := clipboardHandle(t, c, out, prep).CopyTicket
	c.clipboardMu.Lock()
	c.clipboardGrant.until = time.Now().Add(-time.Second)
	c.clipboardMu.Unlock()
	prep = clipboardRequest(c, 51, "prepare-copy-field")
	prep.ItemID, prep.Revision, prep.Field = id, rev, "password"
	second := clipboardHandle(t, c, out, prep)
	if second.Type != "copy-prepared" || second.CopyTicket == "" || second.CopyTicket == first {
		t.Fatalf("expired grant blocked a fresh prepare: %#v", second)
	}
}

func clipboardGrantForTest(c *Connection, s *personal.Session, id, rev string) *clipboardGrant {
	capability, epoch, _ := c.clipboardAuthSnapshot()
	return &clipboardGrant{
		itemID: id, revision: rev, field: "password", session: s,
		capability: capability, until: c.now().Add(maxClipboardLease),
		epoch: epoch, generation: c.generation.Load(), cancel: c.cancelEpoch.Load(),
	}
}

func TestClipboardStaleContinuationNeverInstallsGrant(t *testing.T) {
	for name, advance := range map[string]func(*Connection){
		"invalidate": func(c *Connection) { c.Invalidate() },
		"cancel":     func(c *Connection) { c.cancelEpoch.Add(1) },
	} {
		t.Run(name, func(t *testing.T) {
			fake := &clipboardFake{}
			c, _, s, id, rev := clipboardFixture(t, fake, 0)
			t.Cleanup(c.Close)
			state := c.clipboard.Load()
			g := clipboardGrantForTest(c, s, id, rev)
			advance(c)
			if _, ok := c.prepareClipboardGrant(state, g, []byte("clipboard-secret")); ok {
				t.Fatal("stale continuation installed a grant")
			}
			if c.clipboardGrant != nil || clipboardOfferPending(state.manager) {
				t.Fatal("stale continuation left grant or manager offer")
			}
		})
	}
}

func TestClipboardGenericCancelDropsPendingButKeepsConfirmedLease(t *testing.T) {
	fake := &clipboardFake{}
	c, out, _, id, rev := clipboardFixture(t, fake, 0)
	t.Cleanup(c.Close)
	prep := clipboardRequest(c, 60, "prepare-copy-field")
	prep.ItemID, prep.Revision, prep.Field = id, rev, "password"
	ticket := clipboardHandle(t, c, out, prep).CopyTicket
	cancel := clipboardRequest(c, 61, "cancel")
	if resp := clipboardHandle(t, c, out, cancel); resp.Type != "cancelled" {
		t.Fatalf("cancel: %#v", resp)
	}
	if clipboardOfferPending(clipboardManager(c)) {
		t.Fatal("generic cancel left a pending offer")
	}
	commit := clipboardRequest(c, 62, "commit-copy-field")
	commit.CopyTicket = ticket
	if resp := clipboardHandle(t, c, out, commit); resp.Type != "error" {
		t.Fatalf("cancelled pending offer committed: %#v", resp)
	}
	if writes, _ := fake.count(); writes != 0 {
		t.Fatal("cancelled pending offer wrote")
	}

	// A confirmed lease is owned native state, not a pending offer.
	prep = clipboardRequest(c, 63, "prepare-copy-field")
	prep.ItemID, prep.Revision, prep.Field = id, rev, "password"
	ticket = clipboardHandle(t, c, out, prep).CopyTicket
	commit = clipboardRequest(c, 64, "commit-copy-field")
	commit.CopyTicket = ticket
	before := len(out.responses(t))
	if e := c.Handle(commit); e != nil {
		t.Fatal(e)
	}
	if !fake.runNext() {
		t.Fatal("commit was not dispatched")
	}
	if got := clipboardWait(t, out, before); got.State != "confirmed" {
		t.Fatalf("commit: %#v", got)
	}
	cancel = clipboardRequest(c, 65, "cancel")
	if resp := clipboardHandle(t, c, out, cancel); resp.Type != "cancelled" {
		t.Fatalf("cancel after commit: %#v", resp)
	}
	fake.runAll()
	if fake.clearCount() != 0 {
		t.Fatal("generic cancel cleared a confirmed lease")
	}
	c.Invalidate()
	fake.runAll()
	if fake.clearCount() == 0 {
		t.Fatal("invalidate did not clear the owned lease")
	}
}

func TestClipboardGenericCancelDropsQueuedJob(t *testing.T) {
	fake := &clipboardFake{}
	c, out, _, id, rev := clipboardFixture(t, fake, 0)
	t.Cleanup(c.Close)
	prep := clipboardRequest(c, 72, "prepare-copy-field")
	prep.ItemID, prep.Revision, prep.Field = id, rev, "password"
	ticket := clipboardHandle(t, c, out, prep).CopyTicket
	commit := clipboardRequest(c, 73, "commit-copy-field")
	commit.CopyTicket = ticket
	if e := c.Handle(commit); e != nil {
		t.Fatal(e)
	}
	cancel := clipboardRequest(c, 74, "cancel")
	if resp := clipboardHandle(t, c, out, cancel); resp.Type != "cancelled" {
		t.Fatalf("cancel: %#v", resp)
	}
	if !fake.runNext() {
		t.Fatal("cancelled job did not dispatch")
	}
	if fake.runNext() {
		t.Fatal("cancelled job or later work dispatched again")
	}
	if writes, _ := fake.count(); writes != 0 {
		t.Fatalf("cancelled queued job wrote natively: %d", writes)
	}
	if clipboardOfferPending(clipboardManager(c)) {
		t.Fatal("cancelled queued job left a pending offer")
	}
}

// TestClipboardGenericCancelIgnoresInterleavedResponse pins request-ID
// correlation on the wire. A cancelled response for the cancel request is
// followed by an unrelated asynchronous redacted copy-result, as async work for
// another request can append after it; the selector must return the frame whose
// ID equals the cancel request, not the last frame.
func TestClipboardGenericCancelIgnoresInterleavedResponse(t *testing.T) {
	out := &memoryPipe{}
	cancelID, asyncID := reqID(90), reqID(91)
	writeResponse(t, out, Response{ID: cancelID, Type: "cancelled"})
	writeResponse(t, out, Response{ID: asyncID, Type: "copy-result", CopyMode: "native", State: "refused"})

	cancel := Request{V: 1, ID: cancelID, Type: "cancel"}
	if got := clipboardReply(t, out, cancel.ID); got.ID != cancel.ID || got.Type != "cancelled" {
		t.Fatalf("cancel reply id match=%t type=%q", got.ID == cancel.ID, got.Type)
	}
	if got := clipboardReply(t, out, asyncID); got.ID != asyncID || got.Type != "copy-result" || got.State != "refused" || got.Copied {
		t.Fatalf("async reply id match=%t type=%q state=%q", got.ID == asyncID, got.Type, got.State)
	}
}

// writeResponse appends one framed response to out using the wire encoding
// memoryPipe records. It carries only the metadata supplied by the caller.
func writeResponse(t *testing.T, out *memoryPipe, r Response) {
	t.Helper()
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	frame := binary.NativeEndian.AppendUint32(nil, uint32(len(raw)))
	if _, err := out.Write(append(frame, raw...)); err != nil {
		t.Fatal(err)
	}
}

func TestClipboardRefusalDropsOffer(t *testing.T) {
	fake := &clipboardFake{}
	c, out, s, id, rev := clipboardFixture(t, fake, 0)
	t.Cleanup(c.Close)
	prep := clipboardRequest(c, 66, "prepare-copy-field")
	prep.ItemID, prep.Revision, prep.Field = id, rev, "password"
	ticket := clipboardHandle(t, c, out, prep).CopyTicket
	if _, e := s.Edit(personal.Edit{ID: id, Revision: rev, Field: "password", Value: "changed"}); e != nil {
		t.Fatal(e)
	}
	commit := clipboardRequest(c, 67, "commit-copy-field")
	commit.CopyTicket = ticket
	if resp := clipboardHandle(t, c, out, commit); resp.Type != "error" {
		t.Fatalf("stale commit: %#v", resp)
	}
	if clipboardOfferPending(clipboardManager(c)) {
		t.Fatal("refused commit left a manager offer")
	}
	commit = clipboardRequest(c, 68, "commit-copy-field")
	commit.CopyTicket = ticket
	if resp := clipboardHandle(t, c, out, commit); resp.Type != "error" {
		t.Fatalf("replayed commit: %#v", resp)
	}
	if writes, _ := fake.count(); writes != 0 {
		t.Fatal("refused commit wrote")
	}
}

func TestClipboardLiveClearDurationOverridesFallback(t *testing.T) {
	fake := &clipboardFake{}
	c, out, _, id, rev := clipboardFixture(t, nil, 0)
	t.Cleanup(c.Close)
	var live atomic.Int64
	live.Store(int64(5 * time.Second))
	broker := NewBroker(BrokerCallbacks{
		NewClipboard: func() (*nativeclipboard.Manager, time.Duration) {
			return nativeclipboard.NewManagerWithWriter(fake.dispatch, fake.write, fake.clear), 5 * time.Second
		},
		ClipboardClearDuration: func() time.Duration { return time.Duration(live.Load()) },
	})
	c.SetBroker(broker)
	live.Store(int64(30 * time.Second))
	prep := clipboardRequest(c, 70, "prepare-copy-field")
	prep.ItemID, prep.Revision, prep.Field = id, rev, "password"
	resp := clipboardHandle(t, c, out, prep)
	if resp.Type != "copy-prepared" || resp.CleanupTTLSeconds < 29 || resp.CleanupTTLSeconds > 30 {
		t.Fatalf("live clear duration ignored: %#v", resp)
	}
	live.Store(int64(2 * time.Hour))
	prep = clipboardRequest(c, 71, "prepare-copy-field")
	prep.ItemID, prep.Revision, prep.Field = id, rev, "password"
	if resp := clipboardHandle(t, c, out, prep); resp.Type != "error" {
		t.Fatalf("invalid live duration did not fail closed: %#v", resp)
	}
}

func TestClipboardConcurrentBindRace(t *testing.T) {
	fake := &clipboardFake{}
	c, out, s, id, rev := clipboardFixture(t, fake, 0)
	t.Cleanup(c.Close)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			_ = c.BindDesktopSession(s, uint64(i+2), false)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			r := Request{V: 1, ID: reqID(1000 + i), Type: "prepare-copy-field", Capability: reqID(4242)}
			r.ItemID, r.Revision, r.Field = id, rev, "password"
			_ = c.handleClipboard(r, true)
		}
	}()
	wg.Wait()
	_ = out.responses(t)
}
