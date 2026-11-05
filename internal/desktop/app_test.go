package desktop

import (
	"crypto/sha256"
	"github.com/egoist/mygo/ui"
	"testing"
	"time"
)

func TestNativeUnlockFieldsAreMasked(t *testing.T) {
	a := New()
	a.password = "private-master"
	a.secret = "private-secret"
	a.path = "owner.ll"
	tt := ui.NewTester(a.View, 1100, 760)
	for _, s := range tt.Texts() {
		if s == a.password || s == a.secret {
			t.Fatal("unlock factor rendered as label")
		}
	}
	if !tt.HasText("解锁金库") {
		t.Fatal("missing unlock entry")
	}
	a.Lock()
	if a.password != "" || a.secret != "" {
		t.Fatal("lock retained factors")
	}
}

func TestLockDropsLateNativeResults(t *testing.T) {
	a := New()
	var worker, completion func()
	a.launch = func(f func()) { worker = f }
	a.dispatch = func(f func()) { completion = f }
	applied, dropped := false, false
	a.run(func() outcome { return outcome{apply: func() { applied = true }, drop: func() { dropped = true }} })
	worker()
	a.Lock()
	completion()
	if applied || !dropped || a.busy {
		t.Fatal("late result survived lock")
	}
}
func TestClipboardExpiryPreservesExternalReplacement(t *testing.T) {
	for _, replace := range []bool{false, true} {
		a := New()
		contents := "copied-secret"
		cleared := false
		a.clipboardRead = func() string { return contents }
		a.clipboardClear = func() { contents = ""; cleared = true }
		a.clipboardHash = sha256.Sum256([]byte(contents))
		a.clipboardUntil = time.Now().Add(time.Second)
		if replace {
			contents = "user replacement"
		}
		a.Lock()
		if cleared == replace {
			t.Fatal("clipboard ownership check failed")
		}
		if replace && contents != "user replacement" {
			t.Fatal("external clipboard erased")
		}
	}
}
