package browserhost

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
)

func pendingSaveFixture(t *testing.T) (*Connection, *personal.Session, *memoryPipe, Request, *pendingSave) {
	t.Helper()
	c, s, out, r := paired(t)
	r.Type = "save-new"
	r.ID = reqID(20)
	r.ItemID = ""
	r.Revision = ""
	r.WindowID = 1
	r.payload = &savePayload{[]byte("save-user"), []byte("save-password")}
	if c.Handle(r) != nil {
		t.Fatal("save pending")
	}
	p := c.save
	if p == nil || !p.gate.Pending() {
		t.Fatal("missing private save")
	}
	t.Cleanup(func() {
		c.mu.Lock()
		if c.save != nil {
			c.clearSave(c.save)
		}
		c.mu.Unlock()
	})
	return c, s, out, r, p
}
func readySave(t *testing.T, c *Connection, out *memoryPipe, r Request) string {
	t.Helper()
	if e := c.ApproveSave(r.ID, r.Origin); e != nil {
		t.Fatal(e)
	}
	all := out.responses(t)
	last := all[len(all)-1]
	if last.Type != "save-ready" || !revision.MatchString(last.Nonce) {
		t.Fatal("challenge")
	}
	return last.Nonce
}
func awaitTerminal(t *testing.T, out *memoryPipe, id string) Response {
	t.Helper()
	end := time.Now().Add(5 * time.Second)
	for time.Now().Before(end) {
		for _, r := range out.responses(t) {
			if r.ID == id {
				return r
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("no terminal response")
	return Response{}
}
func TestSaveHandshakeDoesNotWriteBeforeFinalDocumentAcknowledgement(t *testing.T) {
	c, s, out, r, p := pendingSaveFixture(t)
	encoded, e := json.Marshal(c.Snapshot())
	if e != nil || strings.Contains(string(encoded), "save-password") || strings.Contains(fmt.Sprintf("%#v", p), "save-password") {
		t.Fatal("pending secret serialization")
	}
	nonce := readySave(t, c, out, r)
	rows, e := s.List("active")
	if e != nil || len(rows) != 1 {
		t.Fatal("approval persisted before commit-ready")
	}
	commit := Request{V: 1, ID: reqID(21), Type: "commit-ready", Capability: r.Capability, RequestID: r.ID, Nonce: nonce}
	if c.Handle(commit) != nil {
		t.Fatal("commit-ready")
	}
	response := awaitTerminal(t, out, commit.ID)
	if response.Type != "saved" || !token.MatchString(response.ItemID) || !revision.MatchString(response.Revision) {
		t.Fatal("saved receipt")
	}
	if c.Handle(commit) != nil {
		t.Fatal("replay should be silently ignored")
	}
	rows, e = s.List("active")
	if e != nil || len(rows) != 2 {
		t.Fatal("duplicate mutation")
	}
}

func TestSaveUpdateAcceptsEmptyCandidateTitle(t *testing.T) {
	c, _, _, r := paired(t)
	r.Revision = ""
	if e := c.Handle(r); e != nil {
		t.Fatal("match", e)
	}
	if len(c.rows) != 1 {
		t.Fatal("missing candidate")
	}
	// Empty titles are allowed in authenticated snapshots. This host test
	// isolates their metadata handling; the core test exercises the snapshot.
	c.rows[0].Title = ""
	r.ID, r.Type, r.WindowID = reqID(20), "save-update", 1
	r.ItemID, r.Revision = c.rows[0].ID, c.rows[0].Revision
	r.payload = &savePayload{[]byte("updated-user"), []byte("updated-password")}
	if e := c.Handle(r); e != nil || c.Snapshot().Save == nil {
		t.Fatal("empty title update was rejected", e)
	}
	t.Cleanup(func() { _ = c.RejectSave(r.ID) })
	if c.Snapshot().Save.Title != "" {
		t.Fatal("host replaced empty metadata title")
	}
}
func TestWrongNonceOldCancelAndReplayDoNotCancelSave(t *testing.T) {
	c, _, out, r, p := pendingSaveFixture(t)
	readySave(t, c, out, r)
	bad := Request{V: 1, ID: reqID(21), Type: "commit-ready", Capability: r.Capability, RequestID: r.ID, Nonce: strings.Repeat("0", 64)}
	for _, q := range []Request{bad, bad, {V: 1, ID: reqID(22), Type: "cancel", Capability: r.Capability}, {V: 1, ID: reqID(23), Type: "cancel-save", Capability: r.Capability, RequestID: reqID(999)}} {
		if c.Handle(q) != nil || !p.gate.Pending() || c.save != p {
			t.Fatal("old or wrong message cancelled new save")
		}
	}
}

func TestLateSaveTimerAndNativeCallbackPreserveNewRequest(t *testing.T) {
	c, _, out, old, expired := pendingSaveFixture(t)
	if c.RejectSave(old.ID) != nil {
		t.Fatal("reject old request")
	}
	fresh := old
	fresh.ID = reqID(24)
	fresh.payload = &savePayload{[]byte("new-user"), []byte("new-password")}
	if c.Handle(fresh) != nil {
		t.Fatal("new pending request")
	}
	p := c.save
	if p == nil || p == expired {
		t.Fatal("missing new request")
	}
	c.expireSave(expired)
	if c.RejectSave(old.ID) == nil || c.ApproveSave(old.ID, old.Origin) == nil {
		t.Fatal("old native callback accepted")
	}
	if c.save != p || !p.gate.Pending() || len(p.payload.password) == 0 {
		t.Fatal("late old action cleared new request")
	}
	readySave(t, c, out, fresh)
	if c.ApproveSave(fresh.ID, fresh.Origin) == nil {
		t.Fatal("approval challenge repeated")
	}
}

func TestConcurrentNativeSaveApprovalHasOneChallenge(t *testing.T) {
	c, _, out, r, _ := pendingSaveFixture(t)
	entered, release := make(chan struct{}, 2), make(chan struct{})
	results := make(chan error, 2)
	touch := func(p *pendingSave) error {
		entered <- struct{}{}
		<-release
		return p.session.TouchBrowserSave(p.gate)
	}
	for i := 0; i < 2; i++ {
		go func() { results <- c.approveSaveWithTouch(r.ID, r.Origin, touch) }()
	}
	<-entered
	<-entered
	close(release)
	first, second := <-results, <-results
	if (first == nil) == (second == nil) {
		t.Fatal("concurrent approvals did not have exactly one winner")
	}
	count := 0
	for _, reply := range out.responses(t) {
		if reply.ID == r.ID && reply.Type == "save-ready" {
			count++
		}
	}
	if count != 1 {
		t.Fatal("concurrent approval emitted multiple challenges")
	}
}
func TestSaveDeadlineAndNativeRejectHaveOneCommitTerminal(t *testing.T) {
	c, _, out, r, p := pendingSaveFixture(t)
	readySave(t, c, out, r)
	p.committing = true
	p.consumed = true
	p.commitID = reqID(21)
	payload := p.payload
	p.payload = nil
	started, resume, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		c.commitSaveWith(p, payload, func(personal.BrowserSaveTarget, []byte, []byte, *personal.BrowserSaveGate) (personal.BrowserSaveReceipt, error) {
			close(started)
			<-resume
			return personal.BrowserSaveReceipt{}, personal.ErrBrowserSaveCancelled
		})
		close(done)
	}()
	<-started
	c.expireSave(p)
	if c.RejectSave(r.ID) != nil {
		t.Fatal("native reject")
	}
	for _, reply := range out.responses(t) {
		if reply.ID == p.commitID {
			t.Fatal("timer/reject replied before worker")
		}
	}
	close(resume)
	<-done
	reply := awaitTerminal(t, out, p.commitID)
	if reply.Type != "error" {
		t.Fatal("cancelled worker result")
	}
	count := 0
	for _, q := range out.responses(t) {
		if q.ID == p.commitID {
			count++
		}
	}
	if count != 1 {
		t.Fatal("duplicate terminal")
	}
}
func TestNativeRejectAfterPersistenceWinnerIsUnknown(t *testing.T) {
	c, s, out, r, p := pendingSaveFixture(t)
	readySave(t, c, out, r)
	p.committing = true
	p.consumed = true
	p.commitID = reqID(21)
	payload := p.payload
	p.payload = nil
	persisted, resume, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		c.commitSaveWith(p, payload, func(target personal.BrowserSaveTarget, u, password []byte, g *personal.BrowserSaveGate) (personal.BrowserSaveReceipt, error) {
			receipt, e := s.SaveBrowser(target, u, password, g)
			close(persisted)
			<-resume
			return receipt, e
		})
		close(done)
	}()
	<-persisted
	if !p.gate.CommitWon() || c.RejectSave(r.ID) != nil || !c.SaveUnknown() {
		t.Fatal("late native reject misreported unsaved")
	}
	close(resume)
	<-done
	if awaitTerminal(t, out, p.commitID).Type != "unknown" {
		t.Fatal("late cancellation receipt")
	}
}

func TestSaveCancelBranchClassifiesTheGateWinnerIndependently(t *testing.T) {
	for _, committed := range []bool{false, true} {
		t.Run(fmt.Sprint("committed=", committed), func(t *testing.T) {
			c, s, out, r, p := pendingSaveFixture(t)
			readySave(t, c, out, r)
			p.committing = true
			p.commitID = reqID(21)
			if committed {
				if _, e := s.SaveBrowser(p.target, p.payload.username, p.payload.password, p.gate); e != nil {
					t.Fatal("persistence winner", e)
				}
			}
			cancel := Request{V: 1, ID: reqID(22), Type: "cancel-save", Capability: r.Capability, RequestID: r.ID}
			// Exercise this branch without registerRequest's earlier CAS. The
			// normal serialized wire path is already protected by that CAS.
			c.mu.Lock()
			handled, e := c.saveMessage(cancel)
			c.mu.Unlock()
			if !handled || e != nil {
				t.Fatal("cancel branch", e)
			}
			want := "cancelled"
			if committed {
				want = "unknown"
			}
			if awaitTerminal(t, out, cancel.ID).Type != want || p.gate.Pending() || c.SaveUnknown() != committed {
				t.Fatal("cancel result did not reflect gate winner")
			}
		})
	}
}
func TestSaveTimerClearsPayloadWithoutViewPolling(t *testing.T) {
	c, _, _, _, p := pendingSaveFixture(t)
	payload := p.payload
	c.mu.Lock()
	p.timer.Stop()
	p.gate.Shorten(time.Now().Add(20 * time.Millisecond))
	p.timer = time.AfterFunc(20*time.Millisecond, func() { c.expireSave(p) })
	c.mu.Unlock()
	time.Sleep(50 * time.Millisecond)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.save != nil || len(payload.username) != 0 || len(payload.password) != 0 {
		t.Fatal("timed-out secret retained without Snapshot")
	}
}
