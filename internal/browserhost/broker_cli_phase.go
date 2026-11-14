package browserhost

import (
	"encoding/json"
	"errors"
	"time"
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

// cliRunControlPhaseState is the complete per-connection control state. The
// accepted state is inactive: it records only that this one connection's
// commit frame passed the strict transport and phase checks. It is not a lease,
// a session, a secret, or a native-approval result, and no later authorization
// decision reads it.
type cliRunControlPhaseState uint8

const (
	cliRunControlPhasePending cliRunControlPhaseState = iota
	cliRunControlPhaseAccepted
)

// cliRunControlPending binds one retained connection to the exact challenge
// that was written in its control-ready frame. It is never shared between
// connections and is cleared when the handler returns.
type cliRunControlPending struct {
	challenge string
	state     cliRunControlPhaseState
	deadline  time.Time
}

func newCLIRunControlPending(challenge string, deadline time.Time) (*cliRunControlPending, error) {
	if !validCLIRunControlChallenge(challenge) || deadline.IsZero() {
		return nil, errControlPhase
	}
	return &cliRunControlPending{challenge: challenge, deadline: deadline}, nil
}

// matches validates the commit operation, the exact connection challenge, the
// original absolute deadline, and the one-time pending state. It does not
// mutate state and never emits an acknowledgement.
func (p *cliRunControlPending) matches(phase ControlClientPhase, now time.Time) bool {
	if p == nil || p.state != cliRunControlPhasePending || !now.Before(p.deadline) {
		return false
	}
	if phase.Op != ControlPhaseCommit || !validControlClientPhase(phase) {
		return false
	}
	return sameCLIRunControlChallenge(phase.Challenge, p.challenge)
}

// accept performs the single pending-to-accepted transition and returns the
// acknowledgement only after that transition. The caller must already have
// validated the strict transport frame and clean EOF. The accepted state grants
// no authority and is cleared with the connection.
func (p *cliRunControlPending) accept(phase ControlClientPhase, now time.Time) (ControlServerAck, error) {
	if !p.matches(phase, now) {
		return ControlServerAck{}, errControlPhase
	}
	challenge := p.challenge
	p.state = cliRunControlPhaseAccepted
	p.challenge = ""
	return ControlServerAck{V: 1, Op: phase.Op, Challenge: challenge, Ack: true}, nil
}

func (p *cliRunControlPending) clear() {
	if p == nil {
		return
	}
	p.challenge = ""
}
