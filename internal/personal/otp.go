package personal

import (
	"errors"
	"io"
	"time"

	"github.com/jihuayu/locklark/internal/vault"
)

const otpDisclosureAction = "item.reveal.otp-code"

var ErrOTPNotConfigured = errors.New("no TOTP configuration for this login")
var ErrOTPTime = errors.New("OTP clock moved backward or validity window elapsed; intent recorded, retry explicitly")

type OTPReceipt struct {
	DisclosureReceipt
	From  int64 `json:"valid_from"`
	Until int64 `json:"valid_until"`
}

// RevealOTP grants no access to the seed. The caller must obtain local-owner
// consent and provide an interactive terminal; public callers cannot set time.
func RevealOTP(path, pw string, key []byte, id, revision string, terminal io.Writer) (OTPReceipt, error) {
	if !idOK(id) || !digestOK(revision) {
		return OTPReceipt{}, errors.New("invalid login ID or revision")
	}
	return revealOTP(terminal, time.Now, func() (result, error) {
		return command(path, pw, key, otpDisclosureAction, vault.Item{}, &Edit{ID: id, Revision: revision})
	})
}

func revealOTP(terminal io.Writer, now func() time.Time, prepare func() (result, error)) (OTPReceipt, error) {
	if terminal == nil || now == nil {
		return OTPReceipt{}, invalid
	}
	// Compare wall clocks, not Go's monotonic clock, to detect local time jumps.
	started := now().Round(0)
	r, err := prepare()
	if r.otp != nil {
		defer r.otp.Clear()
	}
	if err != nil {
		return OTPReceipt{}, err
	}
	if r.otp == nil {
		return OTPReceipt{}, invalid
	}
	sample := now().Round(0)
	if sample.Before(started) {
		return OTPReceipt{}, ErrOTPTime
	}
	code, err := r.otp.At(sample.Unix()) // Only after the durable intent and DB close.
	if err != nil {
		return OTPReceipt{}, err
	}
	window := code.Window()
	value := []byte(code.Value())
	defer clear(value)
	quoted := quoteDisclosure(value)
	defer clear(quoted)
	check := now().Round(0)
	if check.Before(sample) || check.Unix() < window.From || check.Unix() >= window.Until {
		return OTPReceipt{}, ErrOTPTime
	}
	receipt, err := writeDisclosure(terminal, quoted, r.session, r.intent)
	if err != nil {
		return OTPReceipt{}, err
	}
	return OTPReceipt{receipt, window.From, window.Until}, nil
}
