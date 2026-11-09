package desktop

import (
	"testing"

	"github.com/egoist/mygo/ui"
	"github.com/jihuayu/locklark/internal/osunlock"
)

// The security page is the only place that tells the user which OS
// verification will be used. Pin the capability label and description so a
// build without Touch ID (or with CGO disabled) cannot silently advertise a
// prompt it cannot show.
func TestSecurityViewShowsSystemUnlockCapability(t *testing.T) {
	a := New()
	tester := ui.NewTester(a.securityView, 1100, 820)
	for _, want := range []string{
		"快捷解锁：" + osunlock.Label(),
		osunlock.Description(),
		"启用系统快捷解锁（有效期 24 小时）",
		"停用系统快捷解锁",
	} {
		if !tester.HasText(want) {
			t.Fatalf("security page missing %q", want)
		}
	}
	// 980x680 is the classic window minimum. Both action buttons must still be
	// inside the viewport; otherwise the native acceptance driver cannot click
	// them and users cannot turn quick unlock off.
	small := ui.NewTester(a.securityView, 980, 680)
	for _, label := range []string{"启用系统快捷解锁（有效期 24 小时）", "停用系统快捷解锁"} {
		rect, ok := small.Find(label)
		if !ok {
			t.Fatalf("security page at minimum size missing %q", label)
		}
		if rect.Y+rect.H > 680 {
			t.Fatalf("security page at minimum size clips %q at y=%.1f h=%.1f", label, rect.Y, rect.H)
		}
	}
}
