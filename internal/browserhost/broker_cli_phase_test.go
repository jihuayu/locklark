package browserhost

import (
	"bytes"
	"encoding/base64"
	"testing"
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
