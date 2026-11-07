package personal

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/vault"
	bolt "go.etcd.io/bbolt"
)

func TestBrowserOTPTransactionAndCloseFailureNeverYieldCode(t *testing.T) {
	for _, closeFail := range []bool{false, true} {
		s, target := browserOTPFixture(t)
		before := dailyDiskState(t, s.path)
		db, err := existing(s.path)
		if err != nil {
			t.Fatal(err)
		}
		injected := errors.New("fixed persistence fault")
		control := NewBrowserOTPControl(time.Now().Add(time.Second))
		p, err := s.prepareBrowserOTPWith(target, dailyGate(t, s), control, func(option commandOption) (result, error) {
			update := db.Update
			if !closeFail {
				update = func(body func(*bolt.Tx) error) error {
					return db.Update(func(tx *bolt.Tx) error {
						if e := body(tx); e != nil {
							return e
						}
						return injected
					})
				}
			}
			return commandWithClose(func() (result, error) {
				return commandWithUpdate(update, "", nil, browserOTPAction, vault.Item{}, &Edit{ID: target.ID, Revision: target.Revision}, option)
			}, func() error {
				e := db.Close()
				if e != nil {
					return e
				}
				if closeFail {
					return injected
				}
				return nil
			})
		})
		if p != nil || !errors.Is(err, ErrMutationUnknown) || control.Granted() {
			t.Fatal("persistence failure prepared code or lost unknown boundary")
		}
		if !closeFail && !bytes.Equal(before, dailyDiskState(t, s.path)) {
			t.Fatal("rolled back intent changed durable state")
		}
		events, e := s.Audit()
		if e != nil {
			t.Fatal("failed history revalidation")
		}
		intents := 0
		for _, event := range events {
			if event.Action == browserOTPAction {
				intents++
			}
		}
		if closeFail && intents != 1 || !closeFail && intents != 0 {
			t.Fatal("intent commit boundary was misreported")
		}
	}
}

func TestBrowserOTPHistorySurvivesBackupRestore(t *testing.T) {
	path, key, login := revealFixture(t)
	defer clear(key)
	rev, err := EditLogin(path, "fixture", key, Edit{ID: login.ID, Revision: login.Revision, Field: "url", Value: "https://example.test/login"})
	if err != nil {
		t.Fatal(err)
	}
	period := int64(3600)
	for time.Now().Unix()%period > period-15 {
		period--
	}
	rev, err = EditLogin(path, "fixture", key, Edit{ID: login.ID, Revision: rev, Field: "otp", Value: fmt.Sprintf("otpauth://totp/Test?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&period=%d", period)})
	if err != nil {
		t.Fatal(err)
	}
	s, err := UnlockSession(path, []byte("fixture"), key, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Lock()
	target := BrowserOTPTarget{Context: BrowserOTPContext{BrowserContext: BrowserContext{RequestID: strings.Repeat("1", 32), Origin: "https://example.test", TabID: 1, DocumentID: "doc"}, WindowID: 1}, ID: login.ID, Revision: rev, ProfileVersion: 1}
	c := NewBrowserOTPControl(time.Now().Add(time.Second))
	p, err := s.PrepareBrowserOTP(target, dailyGate(t, s), c)
	if err != nil {
		t.Fatal(err)
	}
	s.DiscardBrowserOTP(p)
	archive, restored := filepath.Join(t.TempDir(), "backup.llb"), filepath.Join(t.TempDir(), "restored.ll")
	kit, err := Backup(path, archive, "fixture", key)
	if err != nil {
		t.Fatal("backup failed")
	}
	newKey, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(newKey)
	if err = Restore(archive, restored, "fixture", key, kit, newKey); err != nil {
		t.Fatal("restore rejected OTP history")
	}
	if _, err = List(restored, "fixture", newKey); err != nil {
		t.Fatal("restored history did not authenticate")
	}
	r, err := command(restored, "fixture", newKey, "audit.archived", vault.Item{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, chain := range r.chains {
		for _, event := range chain.Events {
			if event.Action == browserOTPAction && event.Result == "intent" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("OTP intent did not survive restore")
	}
}

func TestBrowserOTPReadonlyRevalidationRejectsSecondSessionRevision(t *testing.T) {
	s, target := browserOTPFixture(t)
	// This test proves the readonly revision revalidation branch, not control
	// expiry. The second-session edit performs real disk work and can outlast
	// a one-second control under CI load, so this semantic test uses an ample
	// but still bounded lifetime; expiry itself has dedicated tests.
	control := NewBrowserOTPControl(time.Now().Add(time.Minute))
	t.Cleanup(func() { control.Cancel() })
	p, err := s.PrepareBrowserOTP(target, dailyGate(t, s), control)
	if err != nil {
		t.Fatal(err)
	}
	other := &Session{path: s.path, material: bytes.Clone(s.material), slotDigest: s.slotDigest, last: time.Now(), idle: time.Minute}
	t.Cleanup(other.Lock)
	if _, err = other.Edit(Edit{ID: target.ID, Revision: target.Revision, Field: "title", Value: "second session changed"}); err != nil {
		t.Fatal(err)
	}
	before := dailyDiskState(t, s.path)
	// Keep the control branch live so a rejection can only come from the
	// readonly revision comparison rather than an expired pending control.
	if !control.Pending() {
		t.Fatal("control expired before readonly verification; revision branch is unreachable")
	}
	if _, err = s.AuthorizeBrowserOTP(p); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale preparation passed readonly verification: %v", err)
	}
	if !bytes.Equal(before, dailyDiskState(t, s.path)) {
		t.Fatal("readonly verification appended audit or changed snapshot")
	}
}

func TestBrowserOTPReadonlyCloseFailureIsTerminal(t *testing.T) {
	s, target := browserOTPFixture(t)
	control := NewBrowserOTPControl(time.Now().Add(time.Second))
	p, err := s.PrepareBrowserOTP(target, dailyGate(t, s), control)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.authorizeBrowserOTPWith(p, func(target BrowserOTPTarget) error {
		if e := s.readNativeTargetWithPurpose(target.ID, target.Revision, "browser.otp.verify", func(vault.Item) error { return nil }); e != nil {
			return e
		}
		return s.finishNativeRead(nil, errors.New("fixed close failure"))
	})
	p.cap.mu.Lock()
	remaining := len(p.cap.code)
	p.cap.mu.Unlock()
	if !errors.Is(err, ErrCommandClose) || control.Granted() || remaining != 0 {
		t.Fatal("readonly close failure retained delivery")
	}
}

func TestBrowserOTPAuthenticatedRefusalsPreserveSnapshotAndHistory(t *testing.T) {
	s, target := browserOTPFixture(t)
	cases := []BrowserOTPTarget{target, target, target}
	cases[0].Revision = strings.Repeat("b", 64)
	cases[1].Context.Origin = "https://other.test"
	cases[2].ID = strings.Repeat("3", 32)
	for _, bad := range cases {
		var before []byte
		db, e := existingWithReadOnly(s.path, true)
		if e != nil {
			t.Fatal(e)
		}
		db.View(func(tx *bolt.Tx) error { before = bytes.Clone(tx.Bucket(bucket).Get(snapshotKey)); return nil })
		db.Close()
		c := NewBrowserOTPControl(time.Now().Add(time.Second))
		if _, e = s.PrepareBrowserOTP(bad, dailyGate(t, s), c); e == nil {
			t.Fatal("invalid target produced a preparation")
		}
		db, e = existingWithReadOnly(s.path, true)
		if e != nil {
			t.Fatal(e)
		}
		same := false
		db.View(func(tx *bolt.Tx) error { same = bytes.Equal(before, tx.Bucket(bucket).Get(snapshotKey)); return nil })
		db.Close()
		if !same {
			t.Fatal("authenticated refusal changed snapshot")
		}
	}
	if _, e := s.Audit(); e != nil {
		t.Fatal("refusal history could not reopen")
	}
}
