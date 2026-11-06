package personal

import (
	"bytes"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestBrowserOTPBindingEverySelectorAndPurpose(t *testing.T) {
	target := BrowserOTPTarget{Context: BrowserOTPContext{BrowserContext: BrowserContext{RequestID: strings.Repeat("1", 32), Origin: "https://example.test", TabID: 1, DocumentID: "document-1"}, WindowID: 1}, ID: strings.Repeat("2", 32), Revision: strings.Repeat("a", 64), ProfileVersion: 1}
	key := bytes.Repeat([]byte{8}, 32)
	base, err := target.binding(key)
	if err != nil {
		t.Fatal(err)
	}
	changes := []func(*BrowserOTPTarget){
		func(t *BrowserOTPTarget) { t.Context.RequestID = strings.Repeat("3", 32) },
		func(t *BrowserOTPTarget) { t.Context.Origin = "https://other.test" },
		func(t *BrowserOTPTarget) { t.Context.TabID++ }, func(t *BrowserOTPTarget) { t.Context.DocumentID = "document-2" },
		func(t *BrowserOTPTarget) { t.Context.WindowID++ }, func(t *BrowserOTPTarget) { t.ID = strings.Repeat("4", 32) },
		func(t *BrowserOTPTarget) { t.Revision = strings.Repeat("b", 64) }, func(t *BrowserOTPTarget) { t.ProfileVersion++ },
	}
	for n, change := range changes {
		different := target
		change(&different)
		digest, e := different.binding(key)
		if e != nil || digest == base {
			t.Fatalf("binding omitted selector %d", n)
		}
	}
	fill, _ := (BrowserFillTarget{ID: target.ID, Revision: target.Revision, Context: target.Context.BrowserContext}).binding(key)
	save, _ := (&browserSaveRequest{target: BrowserSaveTarget{ID: target.ID, Revision: target.Revision, Context: BrowserSaveContext{BrowserContext: target.Context.BrowserContext, WindowID: 1}}}).binding(key)
	if fill == base || save == base || fill == save {
		t.Fatal("OTP purpose was not separated")
	}
}

func TestBrowserOTPSlowReadonlyVerificationIsImmediatelyCancellable(t *testing.T) {
	for _, lock := range []bool{false, true} {
		t.Run(fmt.Sprint(lock), func(t *testing.T) {
			s, target := browserOTPFixture(t)
			control := NewBrowserOTPControl(time.Now().Add(time.Second))
			p, err := s.PrepareBrowserOTP(target, dailyGate(t, s), control)
			if err != nil {
				t.Fatal(err)
			}
			p.cap.mu.Lock()
			canary := p.cap.code
			p.cap.mu.Unlock()
			entered, resume, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
			go func() {
				_, e := s.authorizeBrowserOTPWith(p, func(BrowserOTPTarget) error { close(entered); <-resume; return nil })
				done <- e
			}()
			<-entered
			cancelled := make(chan struct{})
			go func() {
				if lock {
					s.RequestLock()
				} else {
					control.Cancel()
				}
				close(cancelled)
			}()
			immediate := true
			select {
			case <-cancelled:
			case <-time.After(time.Second):
				immediate = false
			}
			p.cap.mu.Lock()
			zeroed := bytes.Equal(canary, make([]byte, len(canary)))
			p.cap.mu.Unlock()
			close(resume)
			err = <-done
			if !immediate || !zeroed || err == nil || control.Granted() {
				t.Fatal("cancellation waited for I/O or allowed delivery")
			}
		})
	}
}

func TestBrowserOTPRequestLockWinsBeforeOutputGrant(t *testing.T) {
	s, target := browserOTPFixture(t)
	control := NewBrowserOTPControl(time.Now().Add(time.Second))
	p, err := s.PrepareBrowserOTP(target, dailyGate(t, s), control)
	if err != nil {
		t.Fatal(err)
	}
	d, err := s.AuthorizeBrowserOTP(p)
	if err != nil {
		t.Fatal(err)
	}
	entered, resume, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	base := time.Now()
	s.otpNow = func() time.Time { close(entered); <-resume; return base }
	go func() {
		output, e := s.GrantBrowserOTP(d)
		if output != nil {
			output.Clear()
		}
		done <- e
	}()
	<-entered
	locked := make(chan struct{})
	go func() { s.RequestLock(); close(locked) }()
	immediate := true
	select {
	case <-locked:
	case <-time.After(time.Second):
		immediate = false
	}
	close(resume)
	err = <-done
	if !immediate || err == nil || control.Granted() {
		t.Fatal("lock lost before grant or waited for preparation")
	}
}

func TestBrowserOTPConcurrentGrantAndOutputAreSingleUse(t *testing.T) {
	s, target := browserOTPFixture(t)
	control := NewBrowserOTPControl(time.Now().Add(time.Second))
	p, err := s.PrepareBrowserOTP(target, dailyGate(t, s), control)
	if err != nil {
		t.Fatal(err)
	}
	copyP := *p
	if _, err = s.AuthorizeBrowserOTP(&copyP); err == nil {
		t.Fatal("copied preparation gained authority")
	}
	other := &Session{}
	if _, err = other.AuthorizeBrowserOTP(p); err == nil {
		t.Fatal("cross-session preparation accepted")
	}
	d, err := s.AuthorizeBrowserOTP(p)
	if err != nil {
		t.Fatal(err)
	}
	copyD := *d
	if _, err = s.GrantBrowserOTP(&copyD); err == nil {
		t.Fatal("copied delivery gained authority")
	}
	if _, err = other.GrantBrowserOTP(d); err == nil {
		t.Fatal("cross-session delivery accepted")
	}
	outputs := make(chan *BrowserOTPOutput, 2)
	for range 2 {
		go func() { o, _ := s.GrantBrowserOTP(d); outputs <- o }()
	}
	var output *BrowserOTPOutput
	for range 2 {
		if o := <-outputs; o != nil {
			if output != nil {
				t.Fatal("concurrent output grants duplicated")
			}
			output = o
		}
	}
	if output == nil {
		t.Fatal("no output grant won")
	}
	canary := bytes.Clone(output.inner.code)
	defer clear(canary)
	allowed := map[string]bool{"[browser OTP preparation]": true, "[browser OTP delivery]": true, "[browser OTP control]": true, "[browser OTP output]": true}
	for _, value := range []any{p, *p, d, *d, control, *control, output, *output} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if !allowed[fmt.Sprintf(format, value)] {
				t.Fatal("OTP formatting was not a fixed redaction")
			}
		}
	}
	copyOutput := *output
	var calls atomic.Int32
	results := make(chan error, 2)
	for _, o := range []*BrowserOTPOutput{output, &copyOutput} {
		go func() {
			results <- o.Consume(func(code []byte, _ OTPBounds) error {
				if !bytes.Equal(code, canary) {
					t.Error("code changed")
				}
				calls.Add(1)
				return nil
			})
		}()
	}
	<-results
	<-results
	if calls.Load() != 1 || output.inner.code != nil {
		t.Fatal("copied or concurrent output was reusable")
	}
}

func TestBrowserOTPRejectsPurposeAndControlReplacement(t *testing.T) {
	s, target := browserOTPFixture(t)
	for _, stage := range []string{"authorize-purpose", "grant-purpose", "grant-control"} {
		control := NewBrowserOTPControl(time.Now().Add(time.Second))
		p, err := s.PrepareBrowserOTP(target, dailyGate(t, s), control)
		if err != nil {
			t.Fatal(err)
		}
		if stage == "authorize-purpose" {
			p.cap.mu.Lock()
			p.cap.purpose = "show"
			p.cap.mu.Unlock()
			d, e := s.AuthorizeBrowserOTP(p)
			if d != nil {
				s.DiscardBrowserOTPDelivery(d)
			}
			control.Cancel()
			if e == nil {
				t.Error("desktop-purpose holder authorized for browser")
			}
			continue
		}
		d, err := s.AuthorizeBrowserOTP(p)
		if err != nil {
			t.Fatal(err)
		}
		if stage == "grant-purpose" {
			d.cap.mu.Lock()
			d.cap.purpose = "copy"
			d.cap.mu.Unlock()
		} else {
			d.control = NewBrowserOTPControl(time.Now().Add(time.Second))
		}
		output, e := s.GrantBrowserOTP(d)
		if output != nil {
			output.Clear()
		}
		d.control.Cancel()
		control.Cancel()
		if e == nil {
			t.Error("wrong purpose or replacement control gained output grant")
		}
	}
}
