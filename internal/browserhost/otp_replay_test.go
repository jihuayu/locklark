package browserhost

import (
	"strings"
	"testing"
)

func TestOTPReplayIgnoredWithoutSecondReply(t *testing.T) {
	for _, phase := range []string{"O", "O-ready", "A-granted", "C", "mixed"} {
		t.Run(phase, func(t *testing.T) {
			c, s, out, r := pendingOTPFixture(t)
			p := c.otp
			replay := r
			switch phase {
			case "O-ready", "A-granted":
				if c.ApproveOTP(r.ID) != nil {
					t.Fatal("challenge")
				}
				if phase == "A-granted" {
					all := out.responses(t)
					nonce := all[len(all)-1].Nonce
					replay = Request{V: 1, ID: reqID(21), Type: "otp-ack", Capability: r.Capability, RequestID: r.ID, Nonce: nonce}
					if c.Handle(replay) != nil || awaitTerminal(t, out, replay.ID).Type != "otp-fill" {
						t.Fatal("output precondition")
					}
				}
			case "C":
				replay = Request{V: 1, ID: reqID(21), Type: "cancel-otp", Capability: r.Capability, RequestID: r.ID}
				if c.Handle(replay) != nil || awaitTerminal(t, out, replay.ID).Type != "cancelled" {
					t.Fatal("cancel precondition")
				}
			case "mixed":
				replay = Request{V: 1, ID: r.ID, Type: "cancel-otp", Capability: r.Capability, RequestID: r.ID}
			}
			before := len(out.responses(t))
			if c.Handle(replay) != nil {
				t.Fatal("duplicate ID was not silently ignored")
			}
			if len(out.responses(t)) != before {
				t.Fatal("duplicate ID received a second terminal reply")
			}
			if c.closed.Load() || !s.Unlocked() || (phase != "C" && phase != "A-granted" && !p.control.Pending()) {
				t.Fatal("duplicate message changed current authority")
			}

		})
	}
}

func TestOldOTPMessageIDsCannotCancelNewSave(t *testing.T) {
	c, _, out, r := pendingOTPFixture(t)
	if c.ApproveOTP(r.ID) != nil {
		t.Fatal("challenge")
	}
	bad := Request{V: 1, ID: reqID(21), Type: "otp-ack", Capability: r.Capability, RequestID: r.ID, Nonce: strings.Repeat("0", 64)}
	if c.Handle(bad) != nil {
		t.Fatal("wrong nonce precondition")
	}
	cancel := Request{V: 1, ID: reqID(22), Type: "cancel-otp", Capability: r.Capability, RequestID: r.ID}
	if c.Handle(cancel) != nil {
		t.Fatal("cancel precondition")
	}
	save := Request{V: 1, ID: reqID(23), Type: "save-new", Capability: r.Capability, WindowID: r.WindowID, Origin: r.Origin, TabID: r.TabID, DocumentID: r.DocumentID, payload: &savePayload{[]byte("new-user"), []byte("new-password")}}
	if c.Handle(save) != nil || c.save == nil {
		t.Fatal("new save precondition")
	}
	pending := c.save
	before := len(out.responses(t))
	mixed := Request{V: 1, ID: r.ID, Type: "cancel-save", Capability: r.Capability, RequestID: save.ID}
	for _, old := range []Request{r, bad, cancel, mixed} {
		if c.Handle(old) != nil || c.save != pending || !pending.gate.Pending() || c.closed.Load() {
			t.Fatal("old OTP ID affected a newer save")
		}
	}
	if len(out.responses(t)) != before {
		t.Fatal("replayed ID received a second terminal")
	}
}
