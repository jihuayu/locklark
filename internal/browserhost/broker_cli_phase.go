package browserhost

import (
	"encoding/json"
	"errors"
)

var errControlPhase = errors.New("invalid CLI control phase")

const (
	ControlPhaseCommit = "commit"
	ControlPhaseDetach = "detach"
	ControlPhaseCancel = "cancel"
)

// ControlClientPhase is a strict client-to-server control message. It carries
// fields only: decoding here does not compare a ready challenge, consult state,
// read a socket, call a callback, or authorize anything.
type ControlClientPhase struct {
	V         int
	Op        string
	Challenge string
}

// ControlServerAck is the strict server acknowledgement direction. Ack must be
// true on the wire.
type ControlServerAck struct {
	V         int
	Op        string
	Challenge string
	Ack       bool
}

func validControlPhaseOp(op string) bool {
	return op == ControlPhaseCommit || op == ControlPhaseDetach || op == ControlPhaseCancel
}

func validControlClientPhase(phase ControlClientPhase) bool {
	return phase.V == 1 && validControlPhaseOp(phase.Op) && validCLIRunControlChallenge(phase.Challenge)
}

func validControlServerAck(ack ControlServerAck) bool {
	return ack.V == 1 && validControlPhaseOp(ack.Op) && validCLIRunControlChallenge(ack.Challenge) && ack.Ack
}

func MarshalControlClientPhase(phase ControlClientPhase) ([]byte, error) {
	if !validControlClientPhase(phase) {
		return nil, errControlPhase
	}
	return json.Marshal(struct {
		V         int    `json:"v"`
		Op        string `json:"op"`
		Challenge string `json:"challenge"`
	}{V: 1, Op: phase.Op, Challenge: phase.Challenge})
}

func MarshalControlServerAck(ack ControlServerAck) ([]byte, error) {
	if !validControlServerAck(ack) {
		return nil, errControlPhase
	}
	return json.Marshal(struct {
		V         int    `json:"v"`
		Op        string `json:"op"`
		Challenge string `json:"challenge"`
		Ack       bool   `json:"ack"`
	}{V: 1, Op: ack.Op, Challenge: ack.Challenge, Ack: true})
}

func DecodeControlClientPhase(raw []byte) (ControlClientPhase, error) {
	keys, values, ok := strictJSONObject(raw)
	defer clearCLIRunRawMessages(values)
	if !ok || len(keys) != 3 {
		return ControlClientPhase{}, errControlPhase
	}
	for _, field := range []string{"v", "op", "challenge"} {
		if _, present := keys[field]; !present {
			return ControlClientPhase{}, errControlPhase
		}
	}
	var v int
	if json.Unmarshal(values["v"], &v) != nil || v != 1 {
		return ControlClientPhase{}, errControlPhase
	}
	var op string
	if json.Unmarshal(values["op"], &op) != nil || !validControlPhaseOp(op) {
		return ControlClientPhase{}, errControlPhase
	}
	var challenge string
	if json.Unmarshal(values["challenge"], &challenge) != nil || !validCLIRunControlChallenge(challenge) {
		return ControlClientPhase{}, errControlPhase
	}
	return ControlClientPhase{V: 1, Op: op, Challenge: challenge}, nil
}

func DecodeControlServerAck(raw []byte) (ControlServerAck, error) {
	keys, values, ok := strictJSONObject(raw)
	defer clearCLIRunRawMessages(values)
	if !ok || len(keys) != 4 {
		return ControlServerAck{}, errControlPhase
	}
	for _, field := range []string{"v", "op", "challenge", "ack"} {
		if _, present := keys[field]; !present {
			return ControlServerAck{}, errControlPhase
		}
	}
	var v int
	if json.Unmarshal(values["v"], &v) != nil || v != 1 {
		return ControlServerAck{}, errControlPhase
	}
	var op string
	if json.Unmarshal(values["op"], &op) != nil || !validControlPhaseOp(op) {
		return ControlServerAck{}, errControlPhase
	}
	var challenge string
	if json.Unmarshal(values["challenge"], &challenge) != nil || !validCLIRunControlChallenge(challenge) {
		return ControlServerAck{}, errControlPhase
	}
	var ack bool
	if json.Unmarshal(values["ack"], &ack) != nil || !ack {
		return ControlServerAck{}, errControlPhase
	}
	return ControlServerAck{V: 1, Op: op, Challenge: challenge, Ack: true}, nil
}
