package desktop

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/jihuayu/locklark/internal/personal"
)

func TestDailyNativeControls(t *testing.T) {
	a := New()
	v := ui.NewTester(a.addView, 1000, 760)
	for _, label := range []string{"网站（可选）", "密码长度（22–256）", "生成强密码并保存"} {
		if !v.HasText(label) {
			t.Fatal("missing daily control", label)
		}
	}
	a.selected = &personal.Row{ID: "11111111111111111111111111111111", Revision: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Title: "Login", State: "active"}
	v = ui.NewTester(a.itemsView, 1100, 820)
	for _, label := range []string{"重新生成本地密码", "显示验证码", "复制验证码"} {
		if !v.HasText(label) {
			t.Fatal("missing selected action", label)
		}
	}
}

func dailyAppFixture(t *testing.T) *App {
	t.Helper()
	a := New()
	a.path = filepath.Join(t.TempDir(), "daily.ll")
	key := bytes.Repeat([]byte{4}, 16)
	if e := personal.Create(a.path, "fixture", key); e != nil {
		t.Fatal(e)
	}
	s, e := personal.UnlockSession(a.path, []byte("fixture"), key, time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	a.session = s
	t.Cleanup(s.Lock)
	return a
}
func TestDailyRegisterRefusalClearsUntransferredBuffers(t *testing.T) {
	a := dailyAppFixture(t)
	g := personal.NewMutationGate(time.Now().Add(time.Minute))
	if e := a.session.RegisterMutation(g); e != nil {
		t.Fatal(e)
	}
	defer a.session.ReleaseMutation(g)
	a.launch = func(func()) { t.Fatal("rejected registration launched worker") }
	user, value := []byte("private-user"), []byte("private-value")
	a.saveNativeCaptured(personal.NativeLoginMetadata{Title: "new"}, user, value, "active", false, 24)
	if !bytes.Equal(user, make([]byte, len(user))) || !bytes.Equal(value, make([]byte, len(value))) {
		t.Fatal("registration rejection retained buffers")
	}
}
func TestDailyLockAfterCommitBeforeDispatchRetainsUnknown(t *testing.T) {
	a := dailyAppFixture(t)
	var queue []func()
	var complete func()
	a.launch = func(fn func()) { queue = append(queue, fn) }
	a.dispatch = func(fn func()) { complete = fn }
	a.title = "generated"
	a.saveNative(true)
	if a.operation == nil {
		t.Fatal("no operation before worker")
	}
	queue[0]()
	if !a.operation.gate.CommitWon() {
		t.Fatal("no committed native mutation")
	}
	a.Lock()
	if !a.mutationUnknown {
		t.Fatal("released session gate hid unacknowledged commit")
	}
	complete()
	if !a.mutationUnknown || !strings.Contains(a.status, "结果未确认") {
		t.Fatal("late receipt cleared unknown")
	}
	for _, fn := range queue[1:] {
		fn()
	}
}
func TestDailyLateRegenerationMetadataDoesNotReopenConfirmation(t *testing.T) {
	a := dailyAppFixture(t)
	id, e := a.session.AddLogin("target", "u", "p")
	if e != nil {
		t.Fatal(e)
	}
	rows, e := a.session.List("active")
	if e != nil {
		t.Fatal(e)
	}
	for _, row := range rows {
		if row.ID == id {
			selected := row
			a.selected = &selected
		}
	}
	var work, complete func()
	a.launch = func(fn func()) { work = fn }
	a.dispatch = func(fn func()) { complete = fn }
	a.reviewRegeneration()
	work()
	a.clearDailyExposure()
	a.page = "activity"
	complete()
	if a.regenerate != nil {
		t.Fatal("late metadata reopened old confirmation")
	}
}
func TestDailyExposureClearsOnClockRollbackAndPreservesOtherClipboard(t *testing.T) {
	a := New()
	a.selected = &personal.Row{ID: "id", Revision: "rev"}
	a.page = "vault"
	now := time.Now()
	bounds := personal.OTPBounds{From: now.Unix() - 1, Until: now.Unix() + 30, WallSample: now.Round(0), Deadline: now.Add(time.Second)}
	a.otpDisplay = "123456"
	a.otpDisplayBounds = &bounds
	a.otpDisplayTarget = personal.NativeOTPTarget{ID: "id", Revision: "rev"}
	clip := attachFakeClipboard(a)
	lease, _ := clip.write([]byte("old-code"))
	a.recordClipboardOwner(lease, now.Add(time.Second))
	clip.replace("later-user-clipboard")
	copyBounds := bounds
	a.otpClipboard = &copyBounds
	a.otpClipboardTarget = a.otpDisplayTarget
	a.checkOTPExposure(now.Add(-time.Second))
	if a.otpDisplay != "" || a.otpClipboard != nil || clip.value != "later-user-clipboard" {
		t.Fatal("OTP rollback cleanup or clipboard ownership failed")
	}
}

func TestDailyOrdinaryDisclosureCannotReturnAfterPageABAOrHide(t *testing.T) {
	for _, action := range []string{"page-aba", "hide"} {
		t.Run(action, func(t *testing.T) {
			a := dailyAppFixture(t)
			id, e := a.session.AddLogin("target", "user", "private-value")
			if e != nil {
				t.Fatal(e)
			}
			rows, e := a.session.List("active")
			if e != nil {
				t.Fatal(e)
			}
			for _, row := range rows {
				if row.ID == id {
					selected := row
					a.selected = &selected
				}
			}
			a.display = "previously-authorized"
			a.displayUntil = time.Now().Add(time.Minute)
			var worker, complete func()
			a.launch = func(fn func()) { worker = fn }
			a.dispatch = func(fn func()) { complete = fn }
			a.disclose("password", "show")
			worker()
			if action == "page-aba" {
				a.clearDailyExposure()
				a.page = "activity"
				a.clearDailyExposure()
				a.page = "vault"
			} else {
				tt := ui.NewTester(a.itemsView, 1100, 1600)
				if e := tt.Click("立即隐藏"); e != nil {
					t.Fatal(e)
				}
			}
			complete()
			if a.display != "" {
				t.Fatal("late disclosure restored a cleared secret")
			}
		})
	}
}
func TestDailyKnownReceiptSurvivesListRefreshFailure(t *testing.T) {
	a := dailyAppFixture(t)
	a.launch = func(fn func()) { fn() }
	a.title = "generated"
	a.scope = "invalid"
	a.saveNative(true)
	if !strings.Contains(a.status, "已生成并保存") || !strings.Contains(a.status, "列表未刷新") || a.operation != nil || a.mutationUnknown {
		t.Fatal("refresh failure replaced known saved receipt")
	}
}

func TestDailyOldOTPTimerCannotClearLaterOrdinaryCopy(t *testing.T) {
	a := dailyAppFixture(t)
	id, e := a.session.AddLogin("target", "user", "private-password")
	if e != nil {
		t.Fatal(e)
	}
	rows, e := a.session.List("active")
	if e != nil {
		t.Fatal(e)
	}
	rev := rows[0].Revision
	period := int64(3600)
	for time.Now().Unix()%period > period-30 {
		period--
	}
	rev, e = a.session.Edit(personal.Edit{ID: id, Revision: rev, Field: "otp", Value: fmt.Sprintf("otpauth://totp/Test?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&period=%d", period)})
	if e != nil {
		t.Fatal(e)
	}
	a.selected = &personal.Row{ID: id, Revision: rev, Title: "target", State: "active"}
	clip := attachFakeClipboard(a)
	dispatch := make(chan func(), 8)
	a.launch = func(fn func()) { fn() }
	a.dispatch = func(fn func()) { dispatch <- fn }
	a.requestOTP("copy")
	(<-dispatch)()
	if a.otpClipboardTimer == nil {
		t.Fatal("OTP copy not prepared")
	}
	a.otpClipboardTimer.Reset(0)
	var oldExpiry func()
	select {
	case oldExpiry = <-dispatch:
	case <-time.After(time.Second):
		t.Fatal("OTP expiry was not queued")
	}
	a.disclose("password", "copy")
	(<-dispatch)()
	oldExpiry()
	if clip.value != "private-password" || a.otpClipboard != nil {
		t.Fatal("old OTP ownership expired a later ordinary copy")
	}
	a.clearClipboard()
}

func TestDailyClipboardClearDetachesBeforeNestedView(t *testing.T) {
	a := New()
	clip := attachFakeClipboard(a)
	lease, _ := clip.write([]byte("old-owned"))
	a.recordClipboardOwner(lease, time.Now().Add(-time.Second))
	calls := 0
	clip.beforeClear = func() {
		calls++
		if calls == 1 {
			_ = ui.NewTester(a.View, 1100, 820)
		}
	}
	a.clearClipboard()
	if calls != 1 || clip.value != "" || !a.clipboardUntil.IsZero() {
		t.Fatal("metadata cleanup reentered ownership")
	}
}

func TestDailyClipboardOldClearPreservesReentrantSameValueOwner(t *testing.T) {
	a := New()
	clip := attachFakeClipboard(a)
	lease, _ := clip.write([]byte("same-value"))
	a.recordClipboardOwner(lease, time.Now().Add(time.Minute))
	clip.beforeClear = func() {
		clip.beforeClear = nil
		next, _ := clip.write([]byte("same-value"))
		a.recordClipboardOwner(next, time.Now().Add(time.Minute))
	}
	a.clearClipboard()
	if clip.value != "same-value" || a.clipboardLease == nil {
		t.Fatal("old cleanup erased a new same-value acquisition")
	}
	a.clearClipboard()
}

func TestDailyClipboardWriteReentryRevokesOldResult(t *testing.T) {
	for _, change := range []string{"lock", "select", "new-owner"} {
		t.Run(change, func(t *testing.T) {
			a := dailyAppFixture(t)
			clip := attachFakeClipboard(a)
			a.selected = &personal.Row{ID: "target", Revision: "rev"}
			generation, exposure, s := a.generation, a.exposureGeneration, a.session
			var queue []func()
			a.launch = func(fn func()) { queue = append(queue, fn) }
			clip.beforeWrite = func() {
				clip.beforeWrite = nil
				switch change {
				case "lock":
					a.Lock()
				case "select":
					a.clearDailyExposure()
					a.selected = nil
				case "new-owner":
					next, _ := clip.write([]byte("new-value"))
					a.recordClipboardOwner(next, time.Now().Add(time.Minute))
				}
			}
			valid := func() bool {
				return a.exposureCurrent(s, personal.NativeOTPTarget{ID: "target", Revision: "rev"}, generation, exposure)
			}
			if e := a.writeClipboard([]byte("old-value"), time.Now().Add(time.Minute), valid); e == nil {
				t.Fatal("reentered old copy reported success")
			}
			if a.clipboardLease != nil && change != "new-owner" {
				t.Fatal("revoked write remained owned")
			}
			if clip.value == "old-value" {
				t.Fatal("revoked outer copy remained available")
			}
			for _, fn := range queue {
				fn()
			}
			a.clearClipboard()
		})
	}
}

func TestDailyLockRevokesSessionAndMemoryBeforeClipboardIO(t *testing.T) {
	a := dailyAppFixture(t)
	s, generation := a.session, a.generation
	a.password, a.secret, a.value, a.display, a.otpDisplay = "factor", "secret", "edit", "shown", "123456"
	clip := attachFakeClipboard(a)
	lease, _ := clip.write([]byte("owned"))
	a.recordClipboardOwner(lease, time.Now().Add(time.Minute))
	var queue []func()
	a.launch = func(fn func()) { queue = append(queue, fn) }
	revoked := false
	clip.beforeClear = func() {
		revoked = a.session == nil && a.generation > generation && !s.Unlocked() && a.password == "" && a.secret == "" && a.value == "" && a.display == "" && a.otpDisplay == ""
	}
	a.Lock()
	for _, fn := range queue {
		fn()
	}
	if !revoked || clip.value != "" {
		t.Fatal("native cleanup preceded revocation or failed to clear owned value")
	}
}

func TestDailyOTPOriginalDeadlineSurvivesNativeWrite(t *testing.T) {
	a := New()
	clip := attachFakeClipboard(a)
	deadline := time.Now().Add(20 * time.Millisecond)
	clip.beforeWrite = func() { time.Sleep(30 * time.Millisecond) }
	if e := a.writeClipboard([]byte("123456"), deadline, func() bool { return true }); e == nil {
		t.Fatal("late native write reported success")
	}
	if clip.value != "" || a.clipboardLease != nil {
		t.Fatal("late native write renewed the original deadline")
	}
}
