package personal

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	bolt "go.etcd.io/bbolt"
)

func TestBrowserOTPCapDeadlineClearsIndependentOfLongControl(t *testing.T) {
	// The holder expiry is owned by the production control timer, which
	// PrepareBrowserOTP shortens to the capability deadline. A real-clock
	// observation can lose the timer callback to scheduler ordering and then
	// misreport an unusable holder as still usable. Drive the same production
	// timer and callback in virtual time and quiesce the due work before
	// inspecting the holder, while a distinct outer control stays on its exact
	// longer deadline.
	synctest.Test(t, func(t *testing.T) {
		s, target := browserOTPFixture(t)
		outerDeadline := time.Now().Add(5 * time.Second)
		outer := NewBrowserOTPControl(outerDeadline)
		defer outer.Cancel()
		c := NewBrowserOTPControl(outerDeadline)
		p, err := s.PrepareBrowserOTP(target, dailyGate(t, s), c)
		if err != nil {
			t.Fatal(err)
		}
		defer s.DiscardBrowserOTP(p)
		p.cap.mu.Lock()
		shortDeadline := p.cap.bounds.Deadline
		held := len(p.cap.code) != 0 && validBrowserOTPCode(p.cap.code)
		p.cap.mu.Unlock()
		if !held {
			t.Fatal("holder had no meaningful prepared code")
		}
		if !shortDeadline.After(time.Now()) || !outerDeadline.After(shortDeadline) {
			t.Fatal("holder and outer deadlines were not distinct and still pending")
		}
		if !c.Pending() || !c.Deadline().Equal(shortDeadline) {
			t.Fatal("holder control was not shortened to the holder deadline")
		}
		if !outer.Pending() || !outer.Deadline().Equal(outerDeadline) {
			t.Fatal("outer control left its exact deadline before holder expiry")
		}
		// Step only as far as the holder deadline; the outer control remains
		// live and no explicit Cancel runs before the assertions below.
		time.Sleep(time.Until(shortDeadline))
		synctest.Wait()
		if time.Now().Before(shortDeadline) || !time.Now().Before(outerDeadline) {
			t.Fatal("virtual clock did not stop at the holder deadline")
		}
		p.cap.mu.Lock()
		remaining, retired := len(p.cap.code), p.cap.used
		p.cap.mu.Unlock()
		if remaining != 0 {
			t.Fatal("short OTP holder outlived its own deadline")
		}
		if !retired || c.Pending() || !outer.Pending() || !outer.Deadline().Equal(outerDeadline) {
			t.Fatal("holder expiry disturbed lifecycle or the exact outer control")
		}
		retiredLifecycle := false
		s.browserOTPControls.Range(func(key, _ any) bool {
			if key == c.inner {
				retiredLifecycle = true
			}
			return true
		})
		s.otpCaps.Range(func(key, _ any) bool {
			if key == p.cap {
				retiredLifecycle = true
			}
			return true
		})
		s.mu.Lock()
		stillPrepared := s.browserOTPPrepared[p]
		s.mu.Unlock()
		if retiredLifecycle || stillPrepared {
			t.Fatal("holder lifecycle survived its own deadline")
		}
	})
}

func TestBrowserOTPClockMarginAndFinalGrantBounds(t *testing.T) {
	// Wall-clock margin/grant assertions must reach their intended boundary,
	// rather than race a one-second control timer during authenticated disk I/O.
	// Keep the production budgets and timers unchanged in one virtual-time bubble;
	// separate tests below/alongside this one exercise real deadline cancellation.
	synctest.Test(t, func(t *testing.T) {
		started := time.Now()
		testBrowserOTPClockMarginAndFinalGrantBounds(t)
		if !time.Now().Equal(started) {
			t.Fatal("clock semantic test unexpectedly advanced virtual time")
		}
	})
}

func testBrowserOTPClockMarginAndFinalGrantBounds(t *testing.T) {
	s, target := browserOTPFixture(t)
	base := time.Now()
	samples := 0
	s.otpNow = func() time.Time {
		samples++
		if samples == 1 {
			return base
		}
		return base.Add(-time.Nanosecond)
	}
	c := NewBrowserOTPControl(time.Now().Add(time.Second))
	if p, err := s.PrepareBrowserOTP(target, dailyGate(t, s), c); p != nil || !errors.Is(err, ErrOTPTime) {
		t.Fatal("prepare clock rollback was accepted")
	}
	rev, err := s.Edit(Edit{ID: target.ID, Revision: target.Revision, Field: "otp", Value: "otpauth://totp/Test?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&period=30"})
	if err != nil {
		t.Fatal(err)
	}
	target.Revision = rev
	nearEnd := time.Now().Truncate(30 * time.Second).Add(30*time.Second - 1599*time.Millisecond)
	s.otpNow = func() time.Time { return nearEnd }
	c = NewBrowserOTPControl(time.Now().Add(time.Second))
	if p, err := s.PrepareBrowserOTP(target, dailyGate(t, s), c); p != nil || !errors.Is(err, ErrOTPTime) {
		t.Fatal("code lacked the full budget plus margin")
	}
	period := int64(3600)
	for time.Now().Unix()%period > period-15 {
		period--
	}
	rev, err = s.Edit(Edit{ID: target.ID, Revision: target.Revision, Field: "otp", Value: fmt.Sprintf("otpauth://totp/Test?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&period=%d", period)})
	if err != nil {
		t.Fatal(err)
	}
	target.Revision = rev
	for _, rollback := range []bool{false, true} {
		s.otpNow = time.Now
		c = NewBrowserOTPControl(time.Now().Add(time.Second))
		p, e := s.PrepareBrowserOTP(target, dailyGate(t, s), c)
		if e != nil {
			t.Fatal(e)
		}
		d, e := s.AuthorizeBrowserOTP(p)
		if e != nil {
			t.Fatal(e)
		}
		d.cap.mu.Lock()
		if rollback {
			sample := d.cap.bounds.WallSample
			s.otpNow = func() time.Time { return sample.Add(-time.Nanosecond) }
		} else {
			d.cap.bounds.Deadline = time.Now().Add(-time.Nanosecond)
		}
		d.cap.mu.Unlock()
		if output, e := s.GrantBrowserOTP(d); output != nil || e == nil {
			if output != nil {
				output.Clear()
			}
			t.Fatal("final grant accepted expired or rolled-back bounds")
		}
		c.Cancel()
	}
}

func otpSnapshotForTest(t *testing.T, path string) []byte {
	t.Helper()
	db, err := existingWithReadOnly(path, true)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var raw []byte
	if err = db.View(func(tx *bolt.Tx) error { raw = bytes.Clone(tx.Bucket(bucket).Get(snapshotKey)); return nil }); err != nil {
		t.Fatal(err)
	}
	return raw
}
func TestBrowserOTPUnconfiguredAndInactiveRefusals(t *testing.T) {
	s, target := browserOTPFixture(t)
	rev, err := s.Edit(Edit{ID: target.ID, Revision: target.Revision, Field: "otp", Value: ""})
	if err != nil {
		t.Fatal(err)
	}
	target.Revision = rev
	before := otpSnapshotForTest(t, s.path)
	c := NewBrowserOTPControl(time.Now().Add(time.Second))
	if p, e := s.PrepareBrowserOTP(target, dailyGate(t, s), c); p != nil || !errors.Is(e, ErrOTPNotConfigured) {
		t.Fatal("missing configuration was not a fixed refusal")
	}
	if !bytes.Equal(before, otpSnapshotForTest(t, s.path)) {
		t.Fatal("configuration refusal changed item snapshot")
	}
	for _, action := range []string{"item.archive", "item.unarchive", "item.trash"} {
		rev, err = s.SetState(target.ID, target.Revision, action)
		if err != nil {
			t.Fatal(err)
		}
		target.Revision = rev
		if action == "item.unarchive" {
			continue
		}
		before = otpSnapshotForTest(t, s.path)
		c = NewBrowserOTPControl(time.Now().Add(time.Second))
		if p, e := s.PrepareBrowserOTP(target, dailyGate(t, s), c); p != nil || !errors.Is(e, ErrBrowserOTP) {
			t.Fatal("inactive login was accepted")
		}
		if !bytes.Equal(before, otpSnapshotForTest(t, s.path)) {
			t.Fatal("inactive refusal changed snapshot")
		}
	}
	if _, err = s.Audit(); err != nil {
		t.Fatal("refusal history did not revalidate")
	}
}

func TestBrowserOTPBusyGrantDiscardClearsRegisteredHolder(t *testing.T) {
	s, target := browserOTPFixture(t)
	c := NewBrowserOTPControl(time.Now().Add(time.Second))
	p, err := s.PrepareBrowserOTP(target, dailyGate(t, s), c)
	if err != nil {
		t.Fatal(err)
	}
	d, err := s.AuthorizeBrowserOTP(p)
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	output, err := s.GrantBrowserOTP(d)
	s.DiscardBrowserOTPDelivery(d) // cancellation must not wait for this mutex
	d.cap.mu.Lock()
	remaining := len(d.cap.code)
	d.cap.mu.Unlock()
	s.mu.Unlock()
	if output != nil || err == nil || c.Pending() || remaining != 0 {
		t.Fatal("failed slot/grant cleanup retained a usable holder")
	}
}

func TestBrowserOTPAndNativeShareHolderLimit(t *testing.T) {
	s := &Session{}
	g := NewMutationGate(time.Now().Add(5 * time.Second))
	s.saveGate = g
	target := BrowserOTPTarget{ID: strings.Repeat("1", 32), Revision: strings.Repeat("a", 64), ProfileVersion: 1, Context: BrowserOTPContext{WindowID: 1, BrowserContext: BrowserContext{RequestID: strings.Repeat("2", 32), Origin: "https://example.test", TabID: 1, DocumentID: "doc"}}}
	var controls []*BrowserOTPControl
	defer func() {
		for _, c := range controls {
			c.Cancel()
		}
	}()
	for range 8 {
		c := NewBrowserOTPControl(time.Now().Add(5 * time.Second))
		controls = append(controls, c)
		if _, err := s.registerBrowserControl(c, g, target); err != nil {
			t.Fatal("holder capacity refused before shared limit")
		}
	}
	c := NewBrowserOTPControl(time.Now().Add(5 * time.Second))
	defer c.Cancel()
	if _, err := s.registerBrowserControl(c, g, target); err == nil {
		t.Fatal("browser exceeded shared holder limit")
	}
	if s.registerOTPCap(&otpCap{}) {
		t.Fatal("desktop OTP bypassed browser holder reservations")
	}
}
