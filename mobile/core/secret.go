package mobilecore

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
)

// SecretValue is a bounded, one-use native delivery, never a metadata DTO.
// No plaintext is retained by this wrapper; the existing audited Session owns
// the cancellable prepared field/code until explicit Take.
type SecretValue struct {
	mu           sync.Mutex
	vault        *Vault
	session      *personal.Session
	epoch        uint64
	id, revision string
	fieldName    string
	otp          *personal.NativeOTP
	used         bool
	expires      time.Time
	from, until  int64
	timer        *time.Timer
	cancelled    atomic.Bool
	clearOnce    sync.Once
	otpBounds    *personal.OTPBounds
	grantClock   func() time.Time // deterministic final-grant clock in tests
}

func (*SecretValue) String() string               { return "[native mobile disclosure]" }
func (*SecretValue) GoString() string             { return "[native mobile disclosure]" }
func (*SecretValue) MarshalJSON() ([]byte, error) { return nil, errInvalid }
func (s *SecretValue) FromUnixMilli() int64       { s.mu.Lock(); defer s.mu.Unlock(); return s.from }
func (s *SecretValue) UntilUnixMilli() int64      { s.mu.Lock(); defer s.mu.Unlock(); return s.until }
func (s *SecretValue) detach() {
	if s.vault == nil {
		return
	}
	s.vault.mu.Lock()
	delete(s.vault.handles, s)
	s.vault.mu.Unlock()
}
func (s *SecretValue) clearLocked() {
	s.used = true
	if s.timer != nil {
		s.timer.Stop()
	}
	s.fieldName = ""
	if s.otp != nil {
		s.session.DiscardOTP(s.otp)
		s.otp = nil
	}
}
func (s *SecretValue) Clear() {
	if s == nil {
		return
	}
	// Native selection/background callbacks must never wait for a worker
	// holding the disclosure mutex during authenticated disk access.
	s.cancelled.Store(true)
	s.detach()
	s.clearOnce.Do(func() { go func() { s.mu.Lock(); s.clearLocked(); s.mu.Unlock() }() })
}
func (s *SecretValue) Take() ([]byte, error) {
	return s.takeWithGrantBarriers(nil, nil)
}

// Barriers are used by deterministic concurrency tests around the delivery
// arbitration point. Public callers always use Take with no barriers.
func (s *SecretValue) takeWithGrantBarriers(beforeGrant, afterGrant func()) ([]byte, error) {
	if s == nil || s.vault == nil || s.session == nil {
		return nil, errExpired
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	defer s.detach()
	if s.cancelled.Load() || s.used || !time.Now().Before(s.expires) || !s.vault.current(s.session, s.epoch) || !s.session.Unlocked() {
		s.clearLocked()
		return nil, errExpired
	}
	s.used = true
	if s.timer != nil {
		s.timer.Stop()
	}
	var value []byte
	var e error
	now := time.Now()
	s.from, s.until = now.UnixMilli(), now.Add(15*time.Second).UnixMilli()
	if s.otp != nil {
		prepared := s.otp
		s.otp = nil
		delivery, err := s.session.AuthorizeOTP(prepared)
		if err != nil {
			return nil, sanitized(err)
		}
		defer s.session.DiscardOTPDelivery(delivery)
		e = s.session.DeliverOTP(delivery, personal.NativeOTPTarget{ID: s.id, Revision: s.revision}, func(code []byte, bounds personal.OTPBounds) error {
			value = append([]byte(nil), code...)
			observed := bounds
			s.otpBounds = &observed
			s.from = bounds.From * 1000
			s.until = bounds.Until * 1000
			if deadline := bounds.Deadline.UnixMilli(); deadline < s.until {
				s.until = deadline
			}
			return nil
		})
	} else if s.fieldName != "" {
		// Read the value only now, in one fresh exact-revision authenticated
		// transaction that durably records this disclosure's single intent.
		field, err := s.session.PrepareField(personal.RevealTarget{ID: s.id, Revision: s.revision, Field: s.fieldName}, "show")
		s.fieldName = ""
		if err != nil {
			return nil, sanitized(err)
		}
		defer s.session.Discard(field)
		e = s.session.Consume(field, func(raw []byte) error { value = append([]byte(nil), raw...); return nil })
	} else {
		return nil, errExpired
	}
	check := time.Now().UnixMilli()
	if e != nil || !s.vault.current(s.session, s.epoch) || !s.session.Unlocked() || check < s.from || check >= s.until {
		clear(value)
		if e != nil {
			return nil, sanitized(e)
		}
		return nil, errLocked
	}
	if beforeGrant != nil {
		beforeGrant()
	}
	if e := s.vault.grantDelivery(s, s.from, s.until); e != nil {
		clear(value)
		return nil, e
	}
	if afterGrant != nil {
		afterGrant()
	}
	return value, nil
}
func (v *Vault) addSecret(s *SecretValue) (*SecretValue, error) {
	v.mu.Lock()
	if v.closed || v.epoch != s.epoch || v.session != s.session {
		v.mu.Unlock()
		s.Clear()
		return nil, errLocked
	}
	if len(v.handles) >= 8 {
		v.mu.Unlock()
		s.Clear()
		return nil, errCapacity
	}
	v.handles[s] = true
	v.mu.Unlock()
	s.mu.Lock()
	s.timer = time.AfterFunc(time.Until(s.expires), s.Clear)
	s.mu.Unlock()
	return s, nil
}
func (v *Vault) RevealField(id, revision, field string) (*SecretValue, error) {
	if field != "username" && field != "password" && field != "notes" {
		return nil, errInvalid
	}
	_, e := v.enterOperation()
	if e != nil {
		return nil, e
	}
	defer v.op.Unlock()
	s, epoch, e := v.active()
	if e != nil {
		return nil, e
	}
	v.mu.Lock()
	capacity := len(v.handles) < 8
	v.mu.Unlock()
	if !capacity {
		return nil, errCapacity
	}
	_, e = s.ReviewNativeLogin(id, revision)
	if e != nil {
		return nil, sanitized(e)
	}
	return v.addSecret(&SecretValue{vault: v, session: s, epoch: epoch, id: id, revision: revision, fieldName: field, expires: time.Now().Add(9 * time.Second)})
}
func (v *Vault) RevealOTP(id, revision string) (*SecretValue, error) {
	var prepared *personal.NativeOTP
	var session *personal.Session
	var epoch uint64
	_, e := v.mutation(func(s *personal.Session, g *personal.MutationGate) (personal.GenerationReceipt, error) {
		v.mu.Lock()
		session, epoch = s, v.epoch
		current := v.session == s
		v.mu.Unlock()
		if !current {
			return personal.GenerationReceipt{}, personal.ErrMutationCancelled
		}
		var e error
		prepared, e = s.PrepareOTP(personal.NativeOTPTarget{ID: id, Revision: revision}, "show", g)
		return personal.GenerationReceipt{}, e
	})
	if e != nil {
		return nil, e
	}
	return v.addSecret(&SecretValue{vault: v, session: session, epoch: epoch, id: id, revision: revision, otp: prepared, expires: time.Now().Add(9 * time.Second)})
}
