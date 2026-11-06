package mobilecore

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
	bolt "go.etcd.io/bbolt"
)

func mobileFixture(t *testing.T) (*Vault, string, []byte) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "personal.ll")
	v, e := Open(path)
	if e != nil {
		t.Fatal("open failed")
	}
	key := bytes.Repeat([]byte{47}, 16)
	if e = v.Create([]byte("mobile-fixture"), bytes.Clone(key)); e != nil {
		t.Fatal("create failed")
	}
	if v.IsUnlocked() {
		t.Fatal("creation left vault unlocked")
	}
	if e = v.Unlock([]byte("mobile-fixture"), bytes.Clone(key)); e != nil {
		t.Fatal("unlock failed")
	}
	t.Cleanup(v.Close)
	t.Cleanup(func() { clear(key) })
	return v, path, key
}

func TestMobileOfflineTwoFactorsGeneratedEditAndDisclosure(t *testing.T) {
	v, _, key := mobileFixture(t)
	r, e := v.GenerateLogin("Straße login", "https://example.test", []byte("private-username-canary"), 24)
	if e != nil || r.ID == "" || len(r.Revision) != 64 || r.Length != 24 {
		t.Fatal("generate receipt invalid")
	}
	rows, e := v.Search("STRASSE", "active")
	if e != nil || rows.Count() != 1 {
		t.Fatal("title search failed")
	}
	row, e := rows.At(0)
	if e != nil || row.ID != r.ID || row.Revision != r.Revision {
		t.Fatal("metadata identity changed")
	}
	for _, obj := range []any{rows, row, r} {
		raw, e := json.Marshal(obj)
		if e != nil || bytes.Contains(raw, []byte("private-username-canary")) {
			t.Fatal("ordinary metadata exposed a value")
		}
	}
	secret, e := v.RevealField(r.ID, r.Revision, "password")
	if e != nil {
		t.Fatal("explicit reveal failed")
	}
	if _, e = json.Marshal(secret); e == nil {
		t.Fatal("secret serializable")
	}
	if strings.Contains(fmt.Sprintf("%v %#v", secret, secret), "private-") {
		t.Fatal("secret formatting leaked")
	}
	password, e := secret.Take()
	defer clear(password)
	if e != nil || len(password) != 24 || secret.UntilUnixMilli() > time.Now().Add(15*time.Second).UnixMilli() {
		t.Fatal("generated disclosure invalid")
	}
	if _, e = secret.Take(); e == nil {
		t.Fatal("disclosure reusable")
	}
	value := []byte("private-password-canary")
	changed, e := v.EditField(r.ID, r.Revision, "password", value)
	if e != nil || changed.Revision == r.Revision || !bytes.Equal(value, make([]byte, len(value))) {
		t.Fatal("exact edit failed or input retained")
	}
	if _, e = v.EditField(r.ID, r.Revision, "title", []byte("stale mutation")); !errors.Is(e, errConflict) {
		t.Fatal("stale mutation accepted")
	}
	pending, e := v.RevealField(changed.ID, changed.Revision, "password")
	if e != nil {
		t.Fatal("prepare before lock failed")
	}
	v.RequestLock()
	if v.IsUnlocked() {
		t.Fatal("lock status late")
	}
	if _, e = pending.Take(); e == nil {
		t.Fatal("late disclosure after lock")
	}
	if e = v.Unlock([]byte("wrong-factor"), bytes.Clone(key)); e == nil {
		t.Fatal("wrong password unlocked")
	}
	if e = v.Unlock([]byte("mobile-fixture"), bytes.Repeat([]byte{48}, 16)); e == nil {
		t.Fatal("wrong Secret Key unlocked")
	}
	if e = v.Unlock([]byte("mobile-fixture"), bytes.Clone(key)); e != nil {
		t.Fatal("offline reopen failed")
	}
	rows, e = v.List("active")
	if e != nil || rows.Count() != 1 {
		t.Fatal("offline persistence failed")
	}
}

func TestMobileBoundedOTPAndAudit(t *testing.T) {
	v, path, key := mobileFixture(t)
	r, e := v.CreateLogin("OTP", "", []byte("account-canary"), []byte("password-canary"))
	if e != nil {
		t.Fatal("create login failed")
	}
	r, e = v.EditField(r.ID, r.Revision, "otp", []byte("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"))
	if e != nil {
		t.Fatal("configure OTP failed")
	}
	otp, e := v.RevealOTP(r.ID, r.Revision)
	if e != nil {
		t.Fatal("prepare OTP failed")
	}
	code, e := otp.Take()
	defer clear(code)
	if e != nil || len(code) != 6 || otp.UntilUnixMilli() <= time.Now().UnixMilli() || otp.UntilUnixMilli() > time.Now().Add(15*time.Second).UnixMilli() {
		t.Fatal("OTP bounds invalid")
	}
	if _, e = v.RevealField(r.ID, r.Revision, "otp"); e == nil {
		t.Fatal("OTP seed disclosed")
	}
	field, e := v.RevealField(r.ID, r.Revision, "password")
	if e != nil {
		t.Fatal("prepare audited field failed")
	}
	value, e := field.Take()
	clear(value)
	if e != nil {
		t.Fatal("audited field delivery failed")
	}
	for i := 0; i < 8; i++ {
		if _, e = v.RevealField(r.ID, r.Revision, "password"); e != nil {
			t.Fatal("bounded preparation failed")
		}
	}
	if _, e = v.RevealField(r.ID, r.Revision, "password"); e == nil {
		t.Fatal("unbounded handles")
	}
	v.Lock()
	events, e := personal.Audit(path, "mobile-fixture", key)
	if e != nil {
		t.Fatal("audit authentication failed")
	}
	found := map[string]bool{}
	for _, event := range events {
		found[event.Action] = true
	}
	for _, action := range []string{"desktop.unlock", "item.add", "item.edit.otp", "item.desktop.show.otp-code", "item.desktop.show.password"} {
		if !found[action] {
			t.Fatal("missing signed audit action", action)
		}
	}
}

type mobileStore struct {
	mu               sync.Mutex
	values           map[string][]byte
	entered, release chan struct{}
}

func (s *mobileStore) Store(id string, b []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.values == nil {
		s.values = map[string][]byte{}
	}
	s.values[id] = bytes.Clone(b)
	return nil
}
func (s *mobileStore) Load(id string) ([]byte, error) {
	if s.entered != nil {
		close(s.entered)
		<-s.release
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return bytes.Clone(s.values[id]), nil
}
func (s *mobileStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	clear(s.values[id])
	delete(s.values, id)
	return nil
}

func TestMobileCancelledSystemCallbackCannotReopen(t *testing.T) {
	v, _, _ := mobileFixture(t)
	store := &mobileStore{}
	if e := v.EnableSystemUnlock(store); e != nil {
		t.Fatal("system enrollment failed")
	}
	v.Lock()
	store.entered, store.release = make(chan struct{}), make(chan struct{})
	result := make(chan error, 1)
	go func() { result <- v.UnlockWithSystem(store) }()
	<-store.entered
	done := make(chan struct{})
	go func() { v.RequestLock(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("lock waited for OS callback")
	}
	close(store.release)
	if e := <-result; e == nil || v.IsUnlocked() {
		t.Fatal("cancelled callback reopened vault")
	}
}

func TestMobileLockCancelsMutationBeforeDiskCommit(t *testing.T) {
	v, path, key := mobileFixture(t)
	r, e := v.CreateLogin("original", "", []byte("username"), []byte("password"))
	if e != nil {
		t.Fatal("create fixture login failed")
	}
	db, e := bolt.Open(path, 0600, nil)
	if e != nil {
		t.Fatal("hold fixture database failed")
	}
	result := make(chan error, 1)
	go func() { _, e := v.EditField(r.ID, r.Revision, "title", []byte("must not commit")); result <- e }()
	deadline := time.Now().Add(time.Second)
	for {
		v.mu.Lock()
		started := v.gate != nil
		v.mu.Unlock()
		if started {
			break
		}
		if time.Now().After(deadline) {
			db.Close()
			t.Fatal("mutation did not start")
		}
		time.Sleep(time.Millisecond)
	}
	locked := make(chan struct{})
	go func() { v.RequestLock(); close(locked) }()
	select {
	case <-locked:
	case <-time.After(time.Second):
		db.Close()
		t.Fatal("lock waited for vault disk")
	}
	if e = db.Close(); e != nil {
		t.Fatal("release database failed")
	}
	if e = <-result; e == nil {
		t.Fatal("cancelled mutation reported success")
	}
	rows, e := personal.List(path, "mobile-fixture", key)
	if e != nil || len(rows) != 1 || rows[0].Title != "original" || rows[0].Revision != r.Revision {
		t.Fatal("cancelled mutation changed persistent state")
	}
}

func TestMobileLockBeforeFinalGrantRefusesCopiedBytes(t *testing.T) {
	v, _, _ := mobileFixture(t)
	r, e := v.CreateLogin("grant target", "", []byte("username"), []byte("password"))
	if e != nil {
		t.Fatal("create grant target failed")
	}
	secret, e := v.RevealField(r.ID, r.Revision, "password")
	if e != nil {
		t.Fatal("prepare grant target failed")
	}
	value, e := secret.takeWithGrantBarriers(v.RequestLock, nil)
	defer clear(value)
	if e == nil || len(value) != 0 {
		t.Fatal("lock won before final grant but copied bytes escaped")
	}
}

func TestMobileGrantBeforeLockBeginsDeliveryNativeMustRejectStaleUI(t *testing.T) {
	v, _, _ := mobileFixture(t)
	r, e := v.CreateLogin("grant target", "", []byte("username"), []byte("password"))
	if e != nil {
		t.Fatal("create grant target failed")
	}
	secret, e := v.RevealField(r.ID, r.Revision, "password")
	if e != nil {
		t.Fatal("prepare grant target failed")
	}
	value, e := secret.takeWithGrantBarriers(nil, v.RequestLock)
	defer clear(value)
	if e != nil || len(value) == 0 || v.IsUnlocked() {
		t.Fatal("grant-first delivery semantics invalid")
	}
}

func TestMobileFieldHandleDefersDisclosureAndRejectsOtherSessionEdit(t *testing.T) {
	v, path, key := mobileFixture(t)
	r, e := v.CreateLogin("deferred target", "", []byte("username"), []byte("obsolete-password"))
	if e != nil {
		t.Fatal("create deferred target failed")
	}
	secret, e := v.RevealField(r.ID, r.Revision, "password")
	if e != nil {
		t.Fatal("metadata handle failed")
	}
	events, e := personal.Audit(path, "mobile-fixture", key)
	if e != nil {
		t.Fatal("inspect disclosure audit failed")
	}
	for _, event := range events {
		if event.Action == "item.desktop.show.password" {
			t.Fatal("metadata handle prefetched and audited a secret before explicit Take")
		}
	}
	if _, e = personal.EditLogin(path, "mobile-fixture", key, personal.Edit{ID: r.ID, Revision: r.Revision, Field: "password", Value: "new-password"}); e != nil {
		t.Fatal("other session edit failed")
	}
	value, e := secret.Take()
	defer clear(value)
	if !errors.Is(e, errConflict) || len(value) != 0 {
		t.Fatal("stale handle disclosed a value after another session edited it")
	}
}

func TestMobileClearCancelsWithoutWaitingForTakeWorker(t *testing.T) {
	v, _, _ := mobileFixture(t)
	r, e := v.CreateLogin("clear target", "", []byte("username"), []byte("password"))
	if e != nil {
		t.Fatal("create clear target failed")
	}
	secret, e := v.RevealField(r.ID, r.Revision, "password")
	if e != nil {
		t.Fatal("prepare clear target failed")
	}
	entered, release := make(chan struct{}), make(chan struct{})
	result := make(chan error, 1)
	go func() {
		value, e := secret.takeWithGrantBarriers(func() { close(entered); <-release }, nil)
		clear(value)
		result <- e
	}()
	<-entered
	cleared := make(chan struct{})
	go func() { secret.Clear(); close(cleared) }()
	blocked := false
	select {
	case <-cleared:
	case <-time.After(100 * time.Millisecond):
		blocked = true
	}
	close(release)
	e = <-result
	<-cleared
	if blocked {
		t.Fatal("Clear blocked on a disclosure worker")
	}
	if e == nil {
		t.Fatal("clear before final grant did not cancel delivery")
	}
}

func mobileOTPForGrant(t *testing.T, v *Vault) *SecretValue {
	t.Helper()
	r, e := v.CreateLogin("clock target", "", []byte("username"), []byte("password"))
	if e != nil {
		t.Fatal("create clock target failed")
	}
	period := int64(3600)
	for time.Now().Unix()%period < 5 {
		period--
	}
	config := fmt.Sprintf("otpauth://totp/Mobile?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&period=%d", period)
	r, e = v.EditField(r.ID, r.Revision, "otp", []byte(config))
	if e != nil {
		t.Fatal("configure clock target failed")
	}
	secret, e := v.RevealOTP(r.ID, r.Revision)
	if e != nil {
		t.Fatal("prepare clock target failed")
	}
	return secret
}

func TestMobileOTPGrantRejectsRollbackWithinOriginalPeriod(t *testing.T) {
	v, _, _ := mobileFixture(t)
	secret := mobileOTPForGrant(t, v)
	secret.grantClock = func() time.Time { return secret.otpBounds.WallSample.Add(-time.Millisecond) }
	value, e := secret.Take()
	defer clear(value)
	if e == nil || len(value) != 0 {
		t.Fatal("clock rolled backward before final grant but OTP escaped")
	}
}

func TestMobileOTPFromIsLatestValidatedGrantSample(t *testing.T) {
	v, _, _ := mobileFixture(t)
	secret := mobileOTPForGrant(t, v)
	var granted time.Time
	secret.grantClock = func() time.Time { granted = time.Now(); return granted }
	value, e := secret.Take()
	defer clear(value)
	if e != nil || len(value) != 6 {
		t.Fatal("valid OTP grant failed")
	}
	if secret.FromUnixMilli() != granted.UnixMilli() {
		t.Fatal("native lower bound was not the latest verified grant sample")
	}
}

func TestMobileQueuedUnlockCannotAdoptEpochAfterRequestLock(t *testing.T) {
	v, _, key := mobileFixture(t)
	v.Lock()
	entered, release := make(chan struct{}), make(chan struct{})
	v.operationQueued = func() { close(entered); <-release }
	result := make(chan error, 1)
	go func() { result <- v.Unlock([]byte("mobile-fixture"), bytes.Clone(key)) }()
	<-entered
	v.RequestLock()
	close(release)
	e := <-result
	v.operationQueued = nil
	if e == nil || v.IsUnlocked() {
		t.Fatal("queued old unlock adopted a fresh lifecycle epoch")
	}
}

func TestMobileLockReturnsLockedAfterConcurrentUnlockOvertakes(t *testing.T) {
	v, _, key := mobileFixture(t)
	invalidated, release := make(chan struct{}), make(chan struct{})
	v.lockWaiting = func() { close(invalidated); <-release }
	done := make(chan struct{})
	go func() { v.Lock(); close(done) }()
	<-invalidated
	if e := v.Unlock([]byte("mobile-fixture"), bytes.Clone(key)); e != nil {
		t.Fatal("concurrent explicit unlock setup failed")
	}
	close(release)
	<-done
	v.lockWaiting = nil
	if v.IsUnlocked() {
		t.Fatal("Lock returned with an overtaking session still unlocked")
	}
}

func TestMobileQueuedMutationCannotUseFreshSessionAfterLock(t *testing.T) {
	v, _, key := mobileFixture(t)
	r, e := v.CreateLogin("original", "", []byte("username"), []byte("password"))
	if e != nil {
		t.Fatal("queued mutation fixture failed")
	}
	entered, release := make(chan struct{}), make(chan struct{})
	v.operationQueued = func() {
		select {
		case <-entered:
			return
		default:
			close(entered)
			<-release
		}
	}
	result := make(chan error, 1)
	go func() { _, e := v.EditField(r.ID, r.Revision, "title", []byte("stale intent")); result <- e }()
	<-entered
	v.RequestLock()
	if e = v.Unlock([]byte("mobile-fixture"), bytes.Clone(key)); e != nil {
		t.Fatal("fresh unlock setup failed")
	}
	close(release)
	e = <-result
	v.operationQueued = nil
	if e == nil {
		t.Fatal("queued old mutation was authorized by a fresh session")
	}
}

func TestMobileEmptyNativeFieldDisclosureIsSuccessfulAndSingleUse(t *testing.T) {
	v, _, _ := mobileFixture(t)
	r, e := v.CreateLogin("empty fields", "", nil, []byte("password"))
	if e != nil {
		t.Fatal("empty username fixture failed")
	}
	for _, field := range []string{"username", "notes"} {
		secret, e := v.RevealField(r.ID, r.Revision, field)
		if e != nil {
			t.Fatal("prepare empty disclosure failed")
		}
		value, e := secret.Take()
		clear(value)
		if e != nil || len(value) != 0 {
			t.Fatal("empty field was not a successful empty disclosure")
		}
		if _, e = secret.Take(); e == nil {
			t.Fatal("empty field disclosure was reusable")
		}
	}
}
