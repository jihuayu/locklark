package personal

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/password"
	"github.com/jihuayu/locklark/internal/vault"
	bolt "go.etcd.io/bbolt"
)

func dailyGate(t *testing.T, s *Session) *MutationGate {
	t.Helper()
	g := NewMutationGate(time.Now().Add(time.Minute))
	if e := s.RegisterMutation(g); e != nil {
		t.Fatal(e)
	}
	return g
}
func TestDailyAtomicLoginGenerationAndRevision(t *testing.T) {
	s, fill := browserFixture(t)
	meta := NativeLoginMetadata{Title: "Generated", URL: "https://example.test/path"}
	r, e := s.GenerateNativeLogin(meta, []byte("unicode-user"), 24, dailyGate(t, s))
	if e != nil {
		t.Fatal(e)
	}
	v, e := s.ReviewNativeLogin(r.ID, r.Revision)
	if e != nil || v.URL != meta.URL {
		t.Fatal("atomic website", e)
	}
	f, e := s.PrepareField(RevealTarget{ID: r.ID, Revision: r.Revision, Field: "password"}, "show")
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Consume(f, func(p []byte) error {
		if len(p) != 24 || strings.Trim(string(p), "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") != "" {
			t.Fatal("policy")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	g := dailyGate(t, s)
	g.Cancel()
	if _, e = s.RegenerateNativePassword(r.ID, r.Revision, 24, g); !errors.Is(e, ErrMutationCancelled) {
		t.Fatal("cancel", e)
	}
	if _, e = s.RegenerateNativePassword(fill.ID, strings.Repeat("a", 64), 24, dailyGate(t, s)); !errors.Is(e, ErrConflict) {
		t.Fatal("stale", e)
	}
}
func TestDailyOTPRequiresDurableRevalidationAndSingleDelivery(t *testing.T) {
	s, fill := browserFixture(t)
	rev, e := s.Edit(Edit{ID: fill.ID, Revision: fill.Revision, Field: "otp", Value: "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"})
	if e != nil {
		t.Fatal(e)
	}
	target := NativeOTPTarget{ID: fill.ID, Revision: rev}
	p, e := s.PrepareOTP(target, "show", dailyGate(t, s))
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(fmt.Sprintf("%#v", p), "JBSWY") {
		t.Fatal("seed formatting")
	}
	other, e := UnlockSession(s.path, []byte("fixture"), bytes.Repeat([]byte{4}, 16), time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	defer other.Lock()
	if _, e = other.Edit(Edit{ID: target.ID, Revision: target.Revision, Field: "password", Value: "changed"}); e != nil {
		t.Fatal(e)
	}
	if _, e = s.AuthorizeOTP(p); !errors.Is(e, ErrConflict) {
		t.Fatal("stale OTP authorized", e)
	}
	rows, e := s.List("active")
	if e != nil {
		t.Fatal(e)
	}
	for _, row := range rows {
		if row.ID == target.ID {
			target.Revision = row.Revision
		}
	}
	p, e = s.PrepareOTP(target, "copy", dailyGate(t, s))
	if e != nil {
		t.Fatal(e)
	}
	d, e := s.AuthorizeOTP(p)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.AuthorizeOTP(p); e == nil {
		t.Fatal("prepared replay")
	}
	delivered := false
	if e = s.DeliverOTP(d, target, func(code []byte, b OTPBounds) error {
		delivered = true
		if len(code) != 6 || !b.Valid(time.Now()) {
			t.Fatal("code lease")
		}
		return nil
	}); e != nil || !delivered {
		t.Fatal("delivery", e)
	}
	if s.DeliverOTP(d, target, func([]byte, OTPBounds) error { return nil }) == nil {
		t.Fatal("delivery replay")
	}
}

func TestDailyOTPFinalClockSampleRejectsRollbackAndExpiredWindow(t *testing.T) {
	for _, rollback := range []bool{true, false} {
		t.Run(fmt.Sprint(rollback), func(t *testing.T) {
			s, fill := browserFixture(t)
			rev, e := s.Edit(Edit{ID: fill.ID, Revision: fill.Revision, Field: "otp", Value: "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"})
			if e != nil {
				t.Fatal(e)
			}
			base := time.Now().Add(time.Minute).Truncate(30 * time.Second).Add(10 * time.Second)
			s.otpNow = func() time.Time { return base }
			target := NativeOTPTarget{fill.ID, rev}
			p, e := s.PrepareOTP(target, "show", dailyGate(t, s))
			if e != nil {
				t.Fatal(e)
			}
			d, e := s.AuthorizeOTP(p)
			if e != nil {
				t.Fatal(e)
			}
			samples := 0
			s.otpNow = func() time.Time {
				samples++
				if samples == 1 {
					return base
				}
				if rollback {
					return base.Add(-time.Second)
				}
				return time.Unix(d.cap.bounds.Until, 0)
			}
			called := false
			e = s.DeliverOTP(d, target, func([]byte, OTPBounds) error { called = true; return nil })
			if e == nil || called {
				t.Fatal("invalid final sample delivered OTP")
			}
		})
	}
}

func deliveryFixture() (*Session, *NativeOTPDelivery, []byte) {
	now := time.Now()
	target := NativeOTPTarget{ID: strings.Repeat("1", 32), Revision: strings.Repeat("a", 64)}
	value := []byte("123456")
	d := &NativeOTPDelivery{cap: &otpCap{code: value, target: target, purpose: "show", bounds: OTPBounds{From: now.Unix() - 1, Until: now.Unix() + 30, WallSample: now.Round(0), Deadline: now.Add(time.Second)}}}
	s := &Session{material: []byte{1}, last: now, idle: time.Minute, otpDeliveries: map[*NativeOTPDelivery]bool{d: true}}
	s.registerOTPCap(d.cap)
	return s, d, value
}
func TestDailyOTPLockBeforeFinalGrantPreventsDelivery(t *testing.T) {
	s, d, _ := deliveryFixture()
	entered, resume, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	now := time.Now()
	samples := 0
	s.otpNow = func() time.Time {
		samples++
		if samples == 2 {
			close(entered)
			<-resume
		}
		return now
	}
	called := false
	go func() {
		done <- s.DeliverOTP(d, d.cap.target, func([]byte, OTPBounds) error { called = true; return nil })
	}()
	<-entered
	locked := make(chan struct{})
	go func() { s.RequestLock(); close(locked) }()
	select {
	case <-locked:
	case <-time.After(time.Second):
		t.Fatal("RequestLock waited for UI callback")
	}
	close(resume)
	e := <-done
	if e == nil || called {
		t.Fatal("lock winner still delivered OTP")
	}
}
func TestDailyOTPPanickingCallbackReleasesAndClears(t *testing.T) {
	s, d, value := deliveryFixture()
	done := make(chan struct{})
	go func() {
		defer func() { _ = recover(); close(done) }()
		_ = s.DeliverOTP(d, d.cap.target, func([]byte, OTPBounds) error { panic("synthetic callback failure") })
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("panic cleanup deadlocked")
	}
	if !bytes.Equal(value, make([]byte, len(value))) {
		t.Fatal("panic retained code")
	}
	if s.DeliverOTP(d, d.cap.target, func([]byte, OTPBounds) error { return nil }) == nil {
		t.Fatal("panic cap replay")
	}
}

func TestDailyMutationFaultsAndRefusalAudit(t *testing.T) {
	for _, fault := range []string{"rng", "rollback", "close", "refusal-close", "cancel", "cancel-refusal", "late-lock"} {
		t.Run(fault, func(t *testing.T) {
			s, _ := browserFixture(t)
			g := dailyGate(t, s)
			before := dailyDiskState(t, s.path)
			action := "item.generate"
			add := vault.Item{Kind: "login", Title: "native", URL: "https://example.test/", Username: "user"}
			opt, _ := generationOption(24)
			if strings.Contains(fault, "refusal") {
				add.URL = "http://[bad"
			}
			if fault == "rng" {
				opt.generation.generate = func(password.Policy) (password.Secret, error) { return password.Secret{}, password.ErrRandom }
			}
			run := func(o commandOption) (result, error) {
				if fault == "close" || fault == "refusal-close" {
					return commandWithClose(func() (result, error) { return command(s.path, "", nil, action, add, nil, o) }, func() error { return errors.New("synthetic close") })
				}
				db, e := existing(s.path)
				if e != nil {
					return result{}, e
				}
				defer db.Close()
				return commandWithUpdate(func(fn func(*bolt.Tx) error) error {
					return db.Update(func(tx *bolt.Tx) error {
						if strings.HasPrefix(fault, "cancel") {
							g.Cancel()
						}
						if e := fn(tx); e != nil {
							return e
						}
						if fault == "rollback" {
							return errors.New("synthetic rollback")
						}
						if fault == "late-lock" {
							s.RequestLock()
						}
						return nil
					})
				}, "", nil, action, add, nil, o)
			}
			_, e := s.nativeMutationWith(action, add, nil, opt, g, run)
			want := ErrMutationUnknown
			if fault == "rng" {
				want = password.ErrRandom
			}
			if strings.HasPrefix(fault, "cancel") {
				want = ErrMutationCancelled
			}
			if !errors.Is(e, want) {
				t.Fatal("fault classification", e)
			}
			if fault == "rng" || strings.HasPrefix(fault, "cancel") || fault == "rollback" {
				if !bytes.Equal(before, dailyDiskState(t, s.path)) {
					t.Fatal("failed/cancelled transaction persisted")
				}
			}
		})
	}
	s, _ := browserFixture(t)
	before := readStoredItems(t, s.path, "fixture", bytes.Repeat([]byte{4}, 16))
	g := dailyGate(t, s)
	if _, e := s.GenerateNativeLogin(NativeLoginMetadata{Title: "invalid", URL: "http://[bad"}, nil, 24, g); !errors.Is(e, ErrMutationRefused) {
		t.Fatal(e)
	}
	after := readStoredItems(t, s.path, "fixture", bytes.Repeat([]byte{4}, 16))
	if !reflect.DeepEqual(before, after) {
		t.Fatal("refusal changed items")
	}
	if _, e := s.Audit(); e != nil {
		t.Fatal("refusal history", e)
	}
}
func dailyDiskState(t *testing.T, path string) []byte {
	t.Helper()
	db, e := existingWithReadOnly(path, true)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	var out []byte
	db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		out = append(out, b.Get(snapshotKey)...)
		out = append(out, b.Get(tipKey)...)
		return nil
	})
	return out
}
func TestDailyOTPReadonlyLimitsLockAndFormatting(t *testing.T) {
	s, fill := browserFixture(t)
	rev, e := s.Edit(Edit{ID: fill.ID, Revision: fill.Revision, Field: "otp", Value: "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"})
	if e != nil {
		t.Fatal(e)
	}
	target := NativeOTPTarget{fill.ID, rev}
	base := time.Now().Add(time.Minute).Truncate(30 * time.Second).Add(10 * time.Second)
	s.otpNow = func() time.Time { return base }
	p, e := s.PrepareOTP(target, "show", dailyGate(t, s))
	if e != nil {
		t.Fatal(e)
	}
	before := dailyDiskState(t, s.path)
	d, e := s.AuthorizeOTP(p)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(before, dailyDiskState(t, s.path)) {
		t.Fatal("readonly verification wrote audit")
	}
	codeCanary := string(d.cap.code)
	if len(codeCanary) != 6 {
		t.Fatal("missing code canary")
	}
	for _, v := range []any{p, *p, d, *d} {
		for _, f := range []string{"%v", "%+v", "%#v"} {
			formatted := fmt.Sprintf(f, v)
			if formatted != "[native OTP preparation]" && formatted != "[native OTP delivery]" {
				t.Fatal("nonredacted native OTP formatting")
			}
			if strings.Contains(formatted, "JBSWY") || strings.Contains(formatted, codeCanary) {
				t.Fatal("seed formatting")
			}
		}
		if raw, e := json.Marshal(v); e == nil || len(raw) > 0 {
			t.Fatal("serialized native code")
		}
	}
	for i := 0; i < 7; i++ {
		if _, e = s.PrepareOTP(target, "copy", dailyGate(t, s)); e != nil {
			t.Fatal(e)
		}
	}
	if _, e = s.PrepareOTP(target, "show", dailyGate(t, s)); e == nil {
		t.Fatal("unbounded native OTP caps")
	}
	s.Lock()
	count := 0
	s.otpCaps.Range(func(_, _ any) bool { count++; return true })
	if count != 0 || len(s.otpPrepared) != 0 || len(s.otpDeliveries) != 0 {
		t.Fatal("lock retained cap registry")
	}
	if s.DeliverOTP(d, target, func([]byte, OTPBounds) error { return nil }) == nil {
		t.Fatal("locked cap delivered")
	}
}

func TestDailyOTPSecondSessionChangesAreRejected(t *testing.T) {
	for _, field := range []string{"otp", "url", "trash"} {
		t.Run(field, func(t *testing.T) {
			s, fill := browserFixture(t)
			rev, e := s.Edit(Edit{ID: fill.ID, Revision: fill.Revision, Field: "otp", Value: "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"})
			if e != nil {
				t.Fatal(e)
			}
			target := NativeOTPTarget{fill.ID, rev}
			p, e := s.PrepareOTP(target, "copy", dailyGate(t, s))
			if e != nil {
				t.Fatal(e)
			}
			code := p.cap.code
			other, e := UnlockSession(s.path, []byte("fixture"), bytes.Repeat([]byte{4}, 16), time.Minute)
			if e != nil {
				t.Fatal(e)
			}
			defer other.Lock()
			if field == "trash" {
				_, e = other.SetState(target.ID, target.Revision, "item.trash")
			} else {
				value := "https://other.test"
				if field == "otp" {
					value = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
				}
				_, e = other.Edit(Edit{ID: target.ID, Revision: target.Revision, Field: field, Value: value})
			}
			if e != nil {
				t.Fatal(e)
			}
			if d, e := s.AuthorizeOTP(p); e == nil || d != nil {
				t.Fatal("changed persistent target authorized")
			}
			if !bytes.Equal(code, make([]byte, len(code))) {
				t.Fatal("rejected cap retained code")
			}
		})
	}
}
func TestDailyOTPExpiryClearsCodeWithoutSessionOrViewPolling(t *testing.T) {
	s, d, code := deliveryFixture()
	s.mu.Lock()
	d.cap.mu.Lock()
	d.cap.timer = time.AfterFunc(10*time.Millisecond, func() {
		d.cap.clear()
		s.otpCaps.Delete(d.cap)
		s.mu.Lock()
		delete(s.otpDeliveries, d)
		s.mu.Unlock()
	})
	d.cap.mu.Unlock()
	time.Sleep(30 * time.Millisecond)
	d.cap.mu.Lock()
	cleared := bytes.Equal(code, make([]byte, len(code)))
	d.cap.mu.Unlock()
	s.mu.Unlock()
	if !cleared {
		t.Fatal("deadline waited for disk/UI mutex to clear code")
	}
}
func TestDailyNewManualURLAndNativeAuditRestore(t *testing.T) {
	s, fill := browserFixture(t)
	g := dailyGate(t, s)
	user, value := []byte("new-user"), []byte("new-password")
	r, e := s.SaveNativeLogin(NativeLoginMetadata{Title: "manual", URL: "https://example.test/path"}, user, value, g)
	if e != nil || r.ID == "" || r.Revision == "" {
		t.Fatal(e)
	}
	if !bytes.Equal(user, make([]byte, len(user))) || !bytes.Equal(value, make([]byte, len(value))) {
		t.Fatal("manual native payload retained")
	}
	view, e := s.ReviewNativeLogin(r.ID, r.Revision)
	if e != nil || view.URL != "https://example.test/path" {
		t.Fatal("manual URL not atomic", e)
	}
	rev, e := s.Edit(Edit{ID: fill.ID, Revision: fill.Revision, Field: "otp", Value: "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"})
	if e != nil {
		t.Fatal(e)
	}
	p, e := s.PrepareOTP(NativeOTPTarget{fill.ID, rev}, "show", dailyGate(t, s))
	if e != nil {
		t.Fatal(e)
	}
	s.DiscardOTP(p)
	archived := filepath.Join(t.TempDir(), "backup.age")
	kit, e := Backup(s.path, archived, "fixture", bytes.Repeat([]byte{4}, 16))
	if e != nil {
		t.Fatal(e)
	}
	restored := filepath.Join(t.TempDir(), "restored.ll")
	key := bytes.Repeat([]byte{5}, 16)
	if e = Restore(archived, restored, "fixture", bytes.Repeat([]byte{4}, 16), kit, key); e != nil {
		t.Fatal(e)
	}
	if _, e = ArchivedAudit(restored, "fixture", key); e != nil {
		t.Fatal("native OTP history restore", e)
	}
}

func TestDailyOTPPrepareRetainsItsLatestWallObservation(t *testing.T) {
	s, fill := browserFixture(t)
	rev, e := s.Edit(Edit{ID: fill.ID, Revision: fill.Revision, Field: "otp", Value: "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"})
	if e != nil {
		t.Fatal(e)
	}
	base := time.Now().Add(time.Minute).Truncate(30 * time.Second).Add(10 * time.Second)
	sample := 0
	s.otpNow = func() time.Time { sample++; return base.Add(time.Duration(sample) * time.Second) }
	p, e := s.PrepareOTP(NativeOTPTarget{fill.ID, rev}, "show", dailyGate(t, s))
	if e != nil {
		t.Fatal(e)
	}
	latest := base.Add(time.Duration(sample) * time.Second)
	s.otpNow = func() time.Time { return latest.Add(-time.Millisecond) }
	if d, e := s.AuthorizeOTP(p); e == nil || d != nil {
		t.Fatal("rollback since last prepare observation was ignored")
	}
}

func TestDailyOTPRevalidationKeepsCodeCancellableDuringIO(t *testing.T) {
	s, d, code := deliveryFixture()
	delete(s.otpDeliveries, d)
	p := &NativeOTP{cap: d.cap}
	s.otpPrepared = map[*NativeOTP]bool{p: true}
	entered, resume, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		delivery, e := s.authorizeOTPWith(p, func(NativeOTPTarget) error { close(entered); <-resume; return nil })
		if delivery != nil {
			done <- errors.New("unexpected delivery")
			return
		}
		done <- e
	}()
	<-entered
	s.RequestLock()
	cleared := bytes.Equal(code, make([]byte, len(code)))
	close(resume)
	e := <-done
	if !cleared || e == nil {
		t.Fatal("blocked readonly verification retained OTP after lock")
	}
}

func TestDailyOTPExpiredHolderCannotBeTransferred(t *testing.T) {
	s, d, code := deliveryFixture()
	delete(s.otpDeliveries, d)
	p := &NativeOTP{cap: d.cap}
	s.otpPrepared = map[*NativeOTP]bool{p: true}
	entered, resume, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		delivery, e := s.authorizeOTPWith(p, func(NativeOTPTarget) error { close(entered); <-resume; return nil })
		if delivery != nil {
			done <- errors.New("unexpected transfer")
			return
		}
		done <- e
	}()
	<-entered
	p.cap.clear()
	s.otpCaps.Delete(p.cap)
	cleared := bytes.Equal(code, make([]byte, len(code)))
	close(resume)
	if e := <-done; e == nil || !cleared {
		t.Fatal("expired/cleared holder became a delivery")
	}
}

func TestDailyNativeReadInvalidAndCloseFailureStillLocks(t *testing.T) {
	s := &Session{material: []byte{1}, last: time.Now(), idle: time.Minute}
	s.mu.Lock()
	e := s.finishNativeRead(invalid, errors.New("synthetic close"))
	s.mu.Unlock()
	if !errors.Is(e, ErrCommandClose) || s.Unlocked() {
		t.Fatal("close error hid failed authentication from lock")
	}
}
