package personal

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func browserOTPFixture(t *testing.T) (*Session, BrowserOTPTarget) {
	t.Helper()
	s, login := browserFixture(t)
	period := int64(3600)
	for time.Now().Unix()%period > period-15 {
		period--
	}
	rev, err := s.Edit(Edit{ID: login.ID, Revision: login.Revision, Field: "otp", Value: fmt.Sprintf("otpauth://totp/Test?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&period=%d", period)})
	if err != nil {
		t.Fatal(err)
	}
	// A stable point in an original TOTP window with ample margin.
	base := time.Now()
	s.otpNow = func() time.Time { return base }
	return s, BrowserOTPTarget{ID: login.ID, Revision: rev, Context: BrowserOTPContext{BrowserContext: login.Context, WindowID: 1}, ProfileVersion: 1}
}

func TestBrowserOTPIntentAuthorizeGrantAndPurposeIsolation(t *testing.T) {
	s, target := browserOTPFixture(t)
	last := s.last
	control := NewBrowserOTPControl(time.Now().Add(time.Second))
	p, err := s.PrepareBrowserOTP(target, dailyGate(t, s), control)
	if err != nil {
		t.Fatal(err)
	}
	if s.last != last {
		t.Fatal("browser ack refreshed native idle time")
	}
	d, err := s.AuthorizeBrowserOTP(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{p, *p, d, *d, control, *control} {
		if bytes.Contains([]byte(fmt.Sprintf("%#v", value)), []byte("JBSWY")) {
			t.Fatal("OTP holder leaked configuration")
		}
		if raw, e := json.Marshal(value); e == nil && bytes.Contains(raw, []byte("JBSWY")) {
			t.Fatal("OTP JSON leaked configuration")
		}
	}
	output, err := s.GrantBrowserOTP(d)
	if err != nil || !control.Granted() || control.Cancel() {
		t.Fatal("output grant arbitration failed")
	}
	if err = output.Consume(func(code []byte, bounds OTPBounds) error {
		if len(code) != 6 || !bounds.Check(time.Now()) {
			t.Fatal("invalid code lease")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if output.Consume(func([]byte, OTPBounds) error { t.Fatal("output replayed"); return nil }) == nil {
		t.Fatal("output replay accepted")
	}
	if _, err = s.GrantBrowserOTP(d); err == nil {
		t.Fatal("delivery replay accepted")
	}
	events, err := s.Audit()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, event := range events {
		if event.Action == "item.browser.fill.otp-code" {
			found = true
			if event.Result != "intent" || len(event.Link) != 64 || event.BaseRevision != target.Revision {
				t.Fatal("unbound OTP intent")
			}
		}
	}
	if !found {
		t.Fatal("dedicated OTP intent missing")
	}
}

func TestBrowserOTPEarlyCancelCannotPrepare(t *testing.T) {
	s, target := browserOTPFixture(t)
	c := NewBrowserOTPControl(time.Now().Add(time.Second))
	if !c.Cancel() {
		t.Fatal("early cancellation lost")
	}
	if _, err := s.PrepareBrowserOTP(target, dailyGate(t, s), c); err == nil {
		t.Fatal("cancelled control prepared OTP")
	}
}
