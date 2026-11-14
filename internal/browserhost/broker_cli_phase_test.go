package browserhost

import (
	"bytes"
	"encoding/base64"
	"errors"
	"net"
	"testing"
	"time"
)

func TestControlPhaseCodec(t *testing.T) {
	challengeA := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, cliRunControlChallengeBytes))
	challengeB := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, cliRunControlChallengeBytes))
	clientRaw := `{"v":1,"op":"commit","challenge":"` + challengeA + `"}`
	ackRaw := `{"v":1,"op":"commit","challenge":"` + challengeA + `","ack":true}`
	phase := ControlClientPhase{V: 1, Op: ControlPhaseCommit, Challenge: challengeA}
	ack := ControlServerAck{V: 1, Op: ControlPhaseCommit, Challenge: challengeA, Ack: true}

	gotClient, err := MarshalControlClientPhase(phase)
	if err != nil || string(gotClient) != clientRaw {
		t.Fatalf("client encoder mismatch: %q %v", gotClient, err)
	}
	gotAck, err := MarshalControlServerAck(ack)
	if err != nil || string(gotAck) != ackRaw {
		t.Fatalf("server encoder mismatch: %q %v", gotAck, err)
	}
	if decoded, err := DecodeControlClientPhase(gotClient); err != nil || decoded != phase {
		t.Fatalf("client decode mismatch: %#v %v", decoded, err)
	}
	if decoded, err := DecodeControlServerAck(gotAck); err != nil || decoded != ack {
		t.Fatalf("server decode mismatch: %#v %v", decoded, err)
	}
	// A parseable different challenge is field data, not a state-machine match.
	other := ControlClientPhase{V: 1, Op: ControlPhaseDetach, Challenge: challengeB}
	rawOther, err := MarshalControlClientPhase(other)
	if err != nil {
		t.Fatal(err)
	}
	if decoded, err := DecodeControlClientPhase(rawOther); err != nil || decoded.Challenge != challengeB {
		t.Fatalf("different challenge was not decoded as a field: %#v %v", decoded, err)
	}

	for _, raw := range []string{
		`{"v":1,"op":"commit","challenge":"` + challengeA + `","ack":true}`,
		`{"v":1,"op":"commit","challenge":"` + challengeA + `"} ` + "x",
		`{"v":1,"op":"commit","challenge":"` + challengeA + `","unknown":1}`,
		`{"v":1,"op":"commit","challenge":"` + challengeA + `","challenge":"` + challengeA + `"}`,
		`{"v":1,"op":"activate","challenge":"` + challengeA + `"}`,
		`{"v":1,"op":null,"challenge":"` + challengeA + `"}`,
		`{"v":null,"op":"commit","challenge":"` + challengeA + `"}`,
		`{"v":"1","op":"commit","challenge":"` + challengeA + `"}`,
		`{"v":1,"op":1,"challenge":"` + challengeA + `"}`,
		`{"v":1,"op":"commit","challenge":123}`,
		`{"v":1,"op":"commit","challenge":null}`,
		`{"v":1,"op":"commit","challenge":"` + challengeA[:len(challengeA)-1] + `\r` + `A"}`,
		`{"v":1,"op":"commit","challenge":"` + challengeA[:len(challengeA)-1] + `\n` + `A"}`,
		`{"v":1,"op":"commit","challenge":"` + challengeA[:len(challengeA)-1] + `\r\n` + `A"}`,
	} {
		if _, err := DecodeControlClientPhase([]byte(raw)); err == nil {
			t.Fatalf("client phase accepted invalid raw %q", raw)
		}
	}
	if _, err := DecodeControlClientPhase([]byte(clientRaw + " \r\n")); err != nil {
		t.Fatalf("client phase rejected trailing whitespace: %v", err)
	}
	if _, err := DecodeControlServerAck([]byte(clientRaw)); err == nil {
		t.Fatal("server decoder accepted client phase")
	}
	if _, err := DecodeControlClientPhase([]byte(ackRaw)); err == nil {
		t.Fatal("client decoder accepted server ack")
	}
	for _, raw := range []string{
		`{"v":1,"op":"commit","challenge":"` + challengeA + `"}`,
		`{"v":1,"op":"commit","challenge":"` + challengeA + `","ack":false}`,
		`{"v":1,"op":"commit","challenge":"` + challengeA + `","ack":null}`,
		`{"v":1,"op":"commit","challenge":"` + challengeA + `","ack":"true"}`,
		`{"v":1,"op":"commit","challenge":"` + challengeA + `","ack":1}`,
		`{"v":1,"op":"activate","challenge":"` + challengeA + `","ack":true}`,
		`{"v":1,"op":"commit","challenge":null,"ack":true}`,
		`{"v":1,"op":"commit","challenge":"` + challengeA + `","ack":true,"x":1}`,
	} {
		if _, err := DecodeControlServerAck([]byte(raw)); err == nil {
			t.Fatalf("server ack accepted invalid raw %q", raw)
		}
	}
	for _, invalid := range []ControlClientPhase{
		{V: 2, Op: ControlPhaseCommit, Challenge: challengeA},
		{V: 1, Op: "activate", Challenge: challengeA},
		{V: 1, Op: ControlPhaseCommit, Challenge: ""},
		{V: 1, Op: ControlPhaseCommit, Challenge: challengeA + "\r"},
	} {
		if _, err := MarshalControlClientPhase(invalid); err == nil {
			t.Fatalf("client encoder accepted %#v", invalid)
		}
	}
	for _, invalid := range []ControlServerAck{
		{V: 1, Op: ControlPhaseCommit, Challenge: challengeA},
		{V: 1, Op: ControlPhaseCommit, Challenge: challengeA, Ack: false},
		{V: 1, Op: "activate", Challenge: challengeA, Ack: true},
		{V: 1, Op: ControlPhaseCommit, Challenge: "", Ack: true},
	} {
		if _, err := MarshalControlServerAck(invalid); err == nil {
			t.Fatalf("server encoder accepted %#v", invalid)
		}
	}
}

func TestControlPendingTransition(t *testing.T) {
	challengeA := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{5}, cliRunControlChallengeBytes))
	challengeB := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{6}, cliRunControlChallengeBytes))
	now := time.Unix(1000, 0)
	deadline := now.Add(time.Minute)
	commitA := ControlClientPhase{V: 1, Op: ControlPhaseCommit, Challenge: challengeA}

	pending, err := newCLIRunControlPending(challengeA, deadline)
	if err != nil {
		t.Fatal("pending state construction failed")
	}
	if !pending.matches(commitA, now) {
		t.Fatal("pending state did not match the exact commit phase")
	}
	if _, err := pending.accept(ControlClientPhase{V: 1, Op: ControlPhaseCancel, Challenge: challengeA}, now); err == nil {
		t.Fatal("cancel phase transitioned the pending state")
	}
	if pending.state != cliRunControlPhasePending {
		t.Fatal("cancel phase changed the pending state")
	}
	if _, err := pending.accept(ControlClientPhase{V: 1, Op: ControlPhaseCommit, Challenge: challengeB}, now); err == nil {
		t.Fatal("wrong challenge transitioned the pending state")
	}
	if _, err := pending.accept(commitA, deadline); err == nil {
		t.Fatal("deadline transitioned the pending state")
	}
	ack, err := pending.accept(commitA, now)
	if err != nil {
		t.Fatal("exact commit did not transition the pending state")
	}
	if ack.Op != ControlPhaseCommit || ack.Challenge != challengeA || !ack.Ack {
		t.Fatal("transition produced a non-exact acknowledgement")
	}
	if pending.state != cliRunControlPhaseAccepted || pending.challenge != "" {
		t.Fatal("transition did not clear the pending challenge")
	}
	if _, err := pending.accept(commitA, now); err == nil {
		t.Fatal("duplicate commit reused the accepted state")
	}
	if _, err := newCLIRunControlPending(challengeA, time.Time{}); err == nil {
		t.Fatal("pending state accepted no absolute deadline")
	}
	if _, err := newCLIRunControlPending("", deadline); err == nil {
		t.Fatal("pending state accepted an invalid challenge")
	}
}

// controlCloseWriteConn supplies the unit-only half-close seam for net.Pipe.
// It never authorizes anything; the real transport positive is Unix-only.
type controlCloseWriteConn struct{ net.Conn }

func (controlCloseWriteConn) CloseWrite() error { return nil }

func TestCLIRunControlCommitAcceptsExactAck(t *testing.T) {
	challenge := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, cliRunControlChallengeBytes))
	server, client := net.Pipe()
	control := &CLIRunControl{
		conn:      controlCloseWriteConn{Conn: client},
		challenge: challenge,
		state:     cliRunControlHandlePending,
	}
	handled := make(chan bool, 1)
	go func() {
		defer server.Close()
		raw, err := readFrame(server, MaxOutput)
		if err != nil {
			handled <- false
			return
		}
		phase, err := DecodeControlClientPhase(raw)
		clear(raw)
		if err != nil || phase.Op != ControlPhaseCommit || phase.Challenge != challenge {
			handled <- false
			return
		}
		ackRaw, err := MarshalControlServerAck(ControlServerAck{V: 1, Op: ControlPhaseCommit, Challenge: challenge, Ack: true})
		if err != nil {
			handled <- false
			return
		}
		writeErr := writeFrame(server, ackRaw)
		clear(ackRaw)
		handled <- writeErr == nil
	}()
	if err := control.Commit(); err != nil {
		t.Fatal("exact acknowledgement did not commit the handle")
	}
	if !<-handled {
		t.Fatal("unit peer did not deliver the selected acknowledgement")
	}
	control.mu.Lock()
	accepted := control.state == cliRunControlHandleAccepted && control.challenge == ""
	control.mu.Unlock()
	if !accepted {
		t.Fatal("commit did not record the inactive accepted state")
	}
	if err := control.Commit(); !errors.Is(err, errCLIRunControl) {
		t.Fatal("duplicate commit did not close the handle with a fixed error")
	}
	_ = control.Close()
}

func TestCLIRunControlCommitRejectsAck(t *testing.T) {
	challengeA := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{8}, cliRunControlChallengeBytes))
	challengeB := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, cliRunControlChallengeBytes))
	ackFalse := `{"v":1,"op":"commit","challenge":"` + challengeA + `","ack":false}`
	cases := []struct {
		name    string
		missing bool
		ack     func() []byte
	}{
		{
			name: "wrong-challenge",
			ack: func() []byte {
				raw, _ := MarshalControlServerAck(ControlServerAck{V: 1, Op: ControlPhaseCommit, Challenge: challengeB, Ack: true})
				return raw
			},
		},
		{
			name: "wrong-operation",
			ack: func() []byte {
				raw, _ := MarshalControlServerAck(ControlServerAck{V: 1, Op: ControlPhaseCancel, Challenge: challengeA, Ack: true})
				return raw
			},
		},
		{
			name: "ack-false",
			ack:  func() []byte { return []byte(ackFalse) },
		},
		{name: "missing-ack", missing: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server, client := net.Pipe()
			control := &CLIRunControl{
				conn:      controlCloseWriteConn{Conn: client},
				challenge: challengeA,
				state:     cliRunControlHandlePending,
			}
			handled := make(chan bool, 1)
			go func() {
				defer server.Close()
				raw, err := readFrame(server, MaxOutput)
				if err != nil {
					handled <- false
					return
				}
				phase, err := DecodeControlClientPhase(raw)
				clear(raw)
				if err != nil || phase.Op != ControlPhaseCommit || phase.Challenge != challengeA {
					handled <- false
					return
				}
				if tc.missing {
					handled <- true
					return
				}
				ackRaw := tc.ack()
				writeErr := writeFrame(server, ackRaw)
				clear(ackRaw)
				handled <- writeErr == nil
			}()
			if err := control.Commit(); !errors.Is(err, errCLIRunControl) {
				t.Fatal("invalid acknowledgement did not close with a fixed error")
			}
			if !<-handled {
				t.Fatal("unit peer did not deliver the selected acknowledgement")
			}
			control.mu.Lock()
			closed := control.state == cliRunControlHandleClosed && control.challenge == ""
			control.mu.Unlock()
			if !closed {
				t.Fatal("invalid acknowledgement left the handle open")
			}
		})
	}
}

func TestControlServerAckCodec(t *testing.T) {
	challengeA := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, cliRunControlChallengeBytes))
	challengeB := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{4}, cliRunControlChallengeBytes))
	commitRaw := `{"v":1,"op":"commit","challenge":"` + challengeA + `","ack":true}`
	cancelRaw := `{"v":1,"op":"cancel","challenge":"` + challengeB + `","ack":true}`

	if decoded, err := DecodeControlServerAck([]byte(commitRaw)); err != nil || decoded.Challenge != challengeA || !decoded.Ack {
		t.Fatalf("commit ack decode mismatch: %#v %v", decoded, err)
	}
	if decoded, err := DecodeControlServerAck([]byte(cancelRaw)); err != nil || decoded.Op != ControlPhaseCancel || decoded.Challenge != challengeB || !decoded.Ack {
		t.Fatalf("cancel ack did not preserve fields: %#v %v", decoded, err)
	}
	if _, err := DecodeControlServerAck([]byte(commitRaw + " \r\n")); err != nil {
		t.Fatalf("server ack rejected legal trailing whitespace: %v", err)
	}
	if _, err := DecodeControlServerAck([]byte(commitRaw + "x")); err == nil {
		t.Fatal("server ack accepted non-whitespace trailing data")
	}

	ack := ControlServerAck{V: 1, Op: ControlPhaseCancel, Challenge: challengeB, Ack: true}
	got, err := MarshalControlServerAck(ack)
	if err != nil || string(got) != cancelRaw {
		t.Fatalf("cancel ack encoder mismatch: %q %v", got, err)
	}
	other := ControlServerAck{V: 1, Op: ControlPhaseCommit, Challenge: challengeB, Ack: true}
	gotOther, err := MarshalControlServerAck(other)
	if err != nil {
		t.Fatal(err)
	}
	if decoded, err := DecodeControlServerAck(gotOther); err != nil || decoded.Challenge != challengeB {
		t.Fatalf("different canonical challenge was not preserved: %#v %v", decoded, err)
	}

	for _, raw := range []string{
		`{"v":null,"op":"commit","challenge":"` + challengeA + `","ack":true}`,
		`{"v":true,"op":"commit","challenge":"` + challengeA + `","ack":true}`,
		`{"v":[],"op":"commit","challenge":"` + challengeA + `","ack":true}`,
		`{"v":1,"op":null,"challenge":"` + challengeA + `","ack":true}`,
		`{"v":1,"op":1,"challenge":"` + challengeA + `","ack":true}`,
		`{"v":1,"op":{},"challenge":"` + challengeA + `","ack":true}`,
		`{"v":1,"op":"commit","challenge":"` + challengeA + `","ack":false}`,
		`{"v":1,"op":"commit","challenge":"` + challengeA + `","ack":null}`,
		`{"v":1,"op":"commit","challenge":"` + challengeA + `","ack":"true"}`,
		`{"v":1,"op":"commit","challenge":"` + challengeA + `","ack":true,"x":1}`,
		`{"v":1,"op":"commit","challenge":"` + challengeA + `","ack":true,"ack":true}`,
		`{"v":1,"op":"commit","challenge":"` + challengeA + `","ack":true} ` + "x",
	} {
		if _, err := DecodeControlServerAck([]byte(raw)); err == nil {
			t.Fatalf("server ack accepted invalid raw %q", raw)
		}
	}
	if _, err := DecodeControlServerAck([]byte(`{"v":1,"op":"commit","challenge":"` + challengeA + `"}`)); err == nil {
		t.Fatal("server ack accepted client direction")
	}
	if _, err := DecodeControlClientPhase([]byte(commitRaw)); err == nil {
		t.Fatal("client phase accepted server ack direction")
	}
	for _, invalid := range []ControlServerAck{
		{V: 1, Op: ControlPhaseCancel, Challenge: challengeB},
		{V: 1, Op: ControlPhaseCancel, Challenge: challengeB, Ack: false},
		{V: 2, Op: ControlPhaseCancel, Challenge: challengeB, Ack: true},
		{V: 1, Op: "activate", Challenge: challengeB, Ack: true},
		{V: 1, Op: ControlPhaseCancel, Challenge: "", Ack: true},
	} {
		if _, err := MarshalControlServerAck(invalid); err == nil {
			t.Fatalf("server ack encoder accepted %#v", invalid)
		}
	}
}
