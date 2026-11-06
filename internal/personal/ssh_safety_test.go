package personal

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/vault"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/crypto/ssh"
)

func preparedSSH(t *testing.T, s *Session, row SSHKeyRow) *SSHSignIntent {
	t.Helper()
	i, e := s.PrepareSSHSign(SSHKeyTarget{row.ID, row.Revision}, sshRequest(t, row), time.Now().Add(20*time.Second))
	if e != nil {
		t.Fatal("SSH prepare", e)
	}
	return i
}

func TestSSHDeadlineClearsWithoutPollingOrAnotherRequest(t *testing.T) {
	s, _, row := sshFixture(t)
	i, e := s.PrepareSSHSign(SSHKeyTarget{row.ID, row.Revision}, sshRequest(t, row), time.Now().Add(50*time.Millisecond))
	if e != nil {
		t.Fatal("deadline prepare")
	}
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-deadline.C:
			t.Fatal("SSH timer did not retire holder")
		case <-tick.C:
			if _, ok := s.sshPending.Load(i.inner); !ok {
				assertSSHRetired(t, s, i)
				return
			}
		}
	}
}

func TestSSHConcurrentNativeApprovalsRecordOneIntent(t *testing.T) {
	s, _, row := sshFixture(t)
	i := preparedSSH(t, s, row)
	s.mu.Lock()
	done := make(chan error, 1)
	go func() {
		o, e := s.ApproveSSHSign(i)
		if e == nil {
			s.DiscardSSHSignature(o)
		}
		done <- e
	}()
	until := time.Now().Add(time.Second)
	for {
		i.inner.mu.Lock()
		entered := i.inner.approving
		i.inner.mu.Unlock()
		if entered {
			break
		}
		if !time.Now().Before(until) {
			s.mu.Unlock()
			t.Fatal("approval did not enter")
		}
		runtime.Gosched()
	}
	if o, e := s.ApproveSSHSign(i); o != nil || !errors.Is(e, ErrSSHSign) {
		s.mu.Unlock()
		t.Fatal("duplicate native approval accepted")
	}
	s.mu.Unlock()
	select {
	case e := <-done:
		if e != nil {
			t.Fatal("first approval failed", e)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("native approval hung")
	}
	events, e := s.Audit()
	if e != nil {
		t.Fatal("approval audit")
	}
	count := 0
	for _, ev := range events {
		if ev.Action == sshSignAction {
			count++
		}
	}
	if count != 1 {
		t.Fatal("duplicate native callback recorded multiple intents")
	}
}
func runSSHOption(s *Session, row SSHKeyRow, o commandOption) (result, error) {
	return command(s.path, "", nil, sshSignAction, vault.Item{}, &Edit{ID: row.ID, Revision: row.Revision}, o)
}
func assertSSHRetired(t *testing.T, s *Session, i *SSHSignIntent) {
	t.Helper()
	x := i.inner
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.status.Load() == 0 || len(x.request.Data) != 0 || len(x.signature) != 0 {
		t.Fatal("SSH holder not cancelled and cleared")
	}
	if _, ok := s.sshPending.Load(x); ok {
		t.Fatal("SSH holder registration leaked")
	}
}

func TestSSHCancelAndRequestLockDoNotWaitForSlowIntent(t *testing.T) {
	for _, lock := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancel", true: "lock"}[lock], func(t *testing.T) {
			s, _, row := sshFixture(t)
			i := preparedSSH(t, s, row)
			entered, release := make(chan struct{}), make(chan struct{})
			done := make(chan error, 1)
			go func() {
				o, e := s.approveSSHSignWith(i, func(option commandOption) (result, error) {
					close(entered)
					<-release
					return runSSHOption(s, row, option)
				})
				if o != nil {
					e = errors.New("unexpected output")
				}
				done <- e
			}()
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("SSH worker did not enter")
			}
			cancelled := make(chan struct{})
			go func() {
				if lock {
					s.RequestLock()
				} else {
					i.Cancel()
				}
				close(cancelled)
			}()
			select {
			case <-cancelled:
			case <-time.After(time.Second):
				close(release)
				t.Fatal("SSH cancellation waited for disk")
			}
			close(release)
			select {
			case e := <-done:
				if e == nil {
					t.Fatal("cancelled signing succeeded")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("SSH cancelled worker hung")
			}
			assertSSHRetired(t, s, i)
		})
	}
}

func TestSSHIntentRollbackAndCloseFailureNeverReleaseSignature(t *testing.T) {
	for _, failure := range []string{"rollback", "close"} {
		t.Run(failure, func(t *testing.T) {
			s, _, row := sshFixture(t)
			i := preparedSSH(t, s, row)
			var retained []byte
			o, e := s.approveSSHSignWith(i, func(option commandOption) (result, error) {
				if failure == "close" {
					return commandWithClose(func() (result, error) { r, e := runSSHOption(s, row, option); retained = r.sshSeed; return r, e }, func() error { return errors.New("synthetic close failure") })
				}
				db, e := existing(s.path)
				if e != nil {
					return result{}, e
				}
				defer db.Close()
				return commandWithUpdate(func(fn func(*bolt.Tx) error) error {
					return db.Update(func(tx *bolt.Tx) error {
						if e := fn(tx); e != nil {
							return e
						}
						return errors.New("synthetic rollback")
					})
				}, "", nil, sshSignAction, vault.Item{}, &Edit{ID: row.ID, Revision: row.Revision}, option)
			})
			if o != nil || !errors.Is(e, ErrMutationUnknown) {
				t.Fatal("uncertain intent returned output or false certainty", e)
			}
			if len(retained) > 0 && !bytes.Equal(retained, make([]byte, len(retained))) {
				t.Fatal("failed close retained seed")
			}
			assertSSHRetired(t, s, i)
			events, e := s.Audit()
			if e != nil {
				t.Fatal("SSH audit after fault")
			}
			n := 0
			for _, ev := range events {
				if ev.Action == sshSignAction {
					n++
				}
			}
			if (n == 1) != (failure == "close") {
				t.Fatal("SSH rollback/commit audit mismatch")
			}
		})
	}
}

func TestSSHStaleCrossSessionAndLockBeforeOutput(t *testing.T) {
	s, key, row := sshFixture(t)
	i := preparedSSH(t, s, row)
	other, e := UnlockSession(s.path, []byte("fixture"), key, time.Minute)
	if e != nil {
		t.Fatal("second session")
	}
	defer other.Lock()
	if o, e := other.ApproveSSHSign(i); o != nil || !errors.Is(e, ErrSSHSign) {
		t.Fatal("cross-session intent accepted")
	}
	if _, e = other.SetState(row.ID, row.Revision, "item.archive"); e != nil {
		t.Fatal("SSH archive", e)
	}
	if o, e := s.ApproveSSHSign(i); o != nil || !errors.Is(e, ErrConflict) {
		t.Fatal("stale SSH target signed", e)
	}
	assertSSHRetired(t, s, i)
	rows, e := s.ListSSHKeys()
	if e != nil || len(rows) != 0 {
		t.Fatal("archived key listed")
	}
	all, e := ListState(s.path, "fixture", key, "archived")
	if e != nil {
		t.Fatal("archived metadata")
	}
	var current string
	for _, r := range all {
		if r.ID == row.ID {
			current = r.Revision
		}
	}
	if current == "" {
		t.Fatal("SSH archive metadata missing")
	}
	revision, e := other.SetState(row.ID, current, "item.unarchive")
	if e != nil {
		t.Fatal("SSH unarchive")
	}
	rows, e = s.ListSSHKeys()
	if e != nil || len(rows) != 1 || rows[0].Revision != revision {
		t.Fatal("unarchived key missing")
	}
	i = preparedSSH(t, s, rows[0])
	o, e := s.ApproveSSHSign(i)
	if e != nil {
		t.Fatal("SSH approval")
	}
	copyOutput := *o
	s.RequestLock()
	if wire, e := s.ConsumeSSHSignature(&copyOutput); e == nil || len(wire) != 0 {
		t.Fatal("signature escaped after lock")
	}
	assertSSHRetired(t, s, i)
}

func TestSSHPrepareBoundsImmutableViewAndExpiry(t *testing.T) {
	s, _, row := sshFixture(t)
	r := sshRequest(t, row)
	sum := sha256.Sum256(r.Data)
	i, e := s.PrepareSSHSign(SSHKeyTarget{row.ID, row.Revision}, r, time.Now().Add(10*time.Second))
	if e != nil {
		t.Fatal("SSH prepare")
	}
	clear(r.Data)
	clear(r.PublicKey)
	v := i.View()
	if v.PayloadDigest != hex.EncodeToString(sum[:]) || v.DataBytes != len("exact SSH client message") || v.Algorithm != "ssh-ed25519" || v.Flags != 0 || v.Key.Fingerprint != row.Fingerprint {
		t.Fatal("SSH view was not derived from immutable request")
	}
	i.inner.mu.Lock()
	i.inner.timer.Stop()
	i.inner.until = time.Now().Add(-time.Second)
	i.inner.mu.Unlock()
	if o, e := s.ApproveSSHSign(i); o != nil || !errors.Is(e, ErrSSHSign) {
		t.Fatal("expired signing accepted")
	}
	assertSSHRetired(t, s, i)
	for _, change := range []func(*SSHSignRequest){func(r *SSHSignRequest) { r.Flags = 1 }, func(r *SSHSignRequest) { r.RequestID = "bad" }, func(r *SSHSignRequest) { r.ConnectionID = "bad" }, func(r *SSHSignRequest) { r.Peer = "" }, func(r *SSHSignRequest) { r.Data = make([]byte, MaxSSHSignData+1) }} {
		bad := sshRequest(t, row)
		change(&bad)
		if _, e = s.PrepareSSHSign(SSHKeyTarget{row.ID, row.Revision}, bad, time.Now().Add(time.Second)); e == nil {
			t.Fatal("invalid signing request accepted")
		}
	}
	if _, e = s.PrepareSSHSign(SSHKeyTarget{row.ID, row.Revision}, sshRequest(t, row), time.Now().Add(SSHSignLifetime+time.Second)); e == nil {
		t.Fatal("unbounded approval lifetime")
	}
}

func TestSSHBindingCoversEverySelectorAndPayload(t *testing.T) {
	seed := bytes.Repeat([]byte{8}, 32)
	r := SSHSignRequest{RequestID: strings.Repeat("1", 32), ConnectionID: strings.Repeat("2", 32), Peer: "uid=1000 pid=1", Data: []byte("payload")}
	private := ed25519.NewKeyFromSeed(seed)
	defer clear(private)
	public, e := ssh.NewPublicKey(private.Public())
	if e != nil {
		t.Fatal("binding public key")
	}
	r.PublicKey = public.Marshal()
	target := SSHKeyTarget{strings.Repeat("a", 32), strings.Repeat("b", 64)}
	base, e := (&sshStoreRequest{sign: &r, target: target}).binding(seed)
	if e != nil {
		t.Fatal("SSH binding fixture")
	}
	for _, change := range []func(*SSHSignRequest, *SSHKeyTarget){func(r *SSHSignRequest, _ *SSHKeyTarget) { r.RequestID = strings.Repeat("3", 32) }, func(r *SSHSignRequest, _ *SSHKeyTarget) { r.ConnectionID = strings.Repeat("3", 32) }, func(r *SSHSignRequest, _ *SSHKeyTarget) { r.Peer = "uid=1000 pid=2" }, func(r *SSHSignRequest, _ *SSHKeyTarget) { r.Data = []byte("other") }, func(_ *SSHSignRequest, t *SSHKeyTarget) { t.ID = strings.Repeat("c", 32) }, func(_ *SSHSignRequest, t *SSHKeyTarget) { t.Revision = strings.Repeat("c", 64) }} {
		copy := r
		next := target
		change(&copy, &next)
		got, e := (&sshStoreRequest{sign: &copy, target: next}).binding(seed)
		if e != nil || got == base {
			t.Fatal("SSH binding omitted selector")
		}
	}
}
