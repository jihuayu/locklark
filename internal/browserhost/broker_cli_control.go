package browserhost

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

var errCLIRunControl = errors.New("CLI-run delivery control unavailable")
var errCLIRunControlDeadline = errors.New("CLI-run delivery control requires a caller deadline")

const cliRunControlChallengeBytes = 32

func newCLIRunControlChallenge() (string, error) {
	var raw [cliRunControlChallengeBytes]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", errCLIRunControl
	}
	return base64.StdEncoding.EncodeToString(raw[:]), nil
}

func validCLIRunControlChallenge(challenge string) bool {
	if len(challenge) != base64.StdEncoding.EncodedLen(cliRunControlChallengeBytes) {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(challenge)
	if err != nil || len(raw) != cliRunControlChallengeBytes {
		return false
	}
	return base64.StdEncoding.EncodeToString(raw) == challenge
}

func sameCLIRunControlChallenge(got, want string) bool {
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

var cliRunControlReady = []byte(`{"v":1,"delivery_control":true}`)

type cliRunControlHandleState uint8

const (
	cliRunControlHandlePending cliRunControlHandleState = iota
	cliRunControlHandleCommitting
	cliRunControlHandleAccepted
	cliRunControlHandleClosed
)

// CLIRunControl is the opt-in post-delivery handle. It carries no authority:
// Close ends the retained authenticated socket, and Commit only proves that
// this connection completed one strict phase round-trip. The server still owns
// proof, nonce, scope, approval, secrets, and any future lease lifecycle.
type CLIRunControl struct {
	once      sync.Once
	mu        sync.Mutex
	conn      net.Conn
	stop      func() bool
	challenge string
	state     cliRunControlHandleState
}

func (c *CLIRunControl) Close() error {
	if c == nil {
		return nil
	}
	c.once.Do(func() {
		c.mu.Lock()
		c.state = cliRunControlHandleClosed
		c.challenge = ""
		stop := c.stop
		conn := c.conn
		c.mu.Unlock()
		if stop != nil {
			stop()
		}
		if conn != nil {
			_ = conn.Close()
		}
	})
	return nil
}

func (c *CLIRunControl) beginCommit() (net.Conn, string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state != cliRunControlHandlePending || c.conn == nil || !validCLIRunControlChallenge(c.challenge) {
		return nil, "", errCLIRunControl
	}
	c.state = cliRunControlHandleCommitting
	return c.conn, c.challenge, nil
}

// Commit sends exactly one commit phase, half-closes the client write side, and
// returns only after the broker's canonical ack preserves this connection's
// exact challenge and operation. The one-time accepted state is recorded only
// after that ack; it is transport-only and activates no lease, discloses no
// secret, and enters no native approval or secret callback. Every write, read,
// decode, and mismatch failure, as well as any concurrent Close or original
// context deadline, closes the handle without accepting.
func (c *CLIRunControl) Commit() error {
	if c == nil {
		return errCLIRunControl
	}
	conn, challenge, err := c.beginCommit()
	if err != nil {
		_ = c.Close()
		return err
	}
	phase := ControlClientPhase{V: 1, Op: ControlPhaseCommit, Challenge: challenge}
	raw, err := MarshalControlClientPhase(phase)
	if err != nil {
		_ = c.Close()
		return errControlPhase
	}
	writeErr := writeFrame(conn, raw)
	clear(raw)
	if writeErr != nil {
		_ = c.Close()
		return errCLIRunControl
	}
	if err := closeCLIRunControlWrite(conn); err != nil {
		_ = c.Close()
		return errCLIRunControl
	}
	ackRaw, err := readFrame(conn, MaxOutput)
	if err != nil {
		_ = c.Close()
		return errCLIRunControl
	}
	defer clear(ackRaw)
	ack, err := DecodeControlServerAck(ackRaw)
	if err != nil || ack.Op != ControlPhaseCommit || !sameCLIRunControlChallenge(ack.Challenge, challenge) || !ack.Ack {
		_ = c.Close()
		return errCLIRunControl
	}
	c.mu.Lock()
	if c.state != cliRunControlHandleCommitting {
		c.mu.Unlock()
		_ = c.Close()
		return errCLIRunControl
	}
	c.state = cliRunControlHandleAccepted
	c.challenge = ""
	c.mu.Unlock()
	return nil
}

type cliRunControlHalfCloser interface {
	CloseWrite() error
}

func closeCLIRunControlWrite(conn net.Conn) error {
	if conn == nil {
		return errCLIRunControl
	}
	closer, ok := conn.(cliRunControlHalfCloser)
	if !ok {
		return errCLIRunControl
	}
	if closer.CloseWrite() != nil {
		return errCLIRunControl
	}
	return nil
}

// requireCLIRunControlEOF proves that the peer sent exactly one complete phase
// frame and then a clean write-side EOF. A second complete frame, a partial
// header, trailing bytes, a reset, or the control deadline is a refusal.
func requireCLIRunControlEOF(conn net.Conn, deadline time.Time) error {
	if conn == nil || deadline.IsZero() {
		return errCLIRunControl
	}
	if conn.SetReadDeadline(deadline) != nil {
		return errCLIRunControl
	}
	raw, err := readFrame(conn, MaxOutput)
	clear(raw)
	if errors.Is(err, io.EOF) {
		return nil
	}
	return errControlPhase
}

func writeCLIRunControlReady(conn net.Conn, challenge string) error {
	if conn == nil || !validCLIRunControlChallenge(challenge) {
		return errCLIRunControl
	}
	raw, err := json.Marshal(struct {
		V               int    `json:"v"`
		DeliveryControl bool   `json:"delivery_control"`
		Challenge       string `json:"challenge"`
	}{V: 1, DeliveryControl: true, Challenge: challenge})
	if err != nil {
		return errCLIRunControl
	}
	defer clear(raw)
	return writeFrame(conn, raw)
}

func readCLIRunControlReady(conn net.Conn) (string, error) {
	if conn == nil {
		return "", errCLIRunControl
	}
	raw, err := readFrame(conn, MaxOutput)
	if err != nil {
		return "", errCLIRunControl
	}
	defer clear(raw)
	keys, values, ok := strictJSONObject(raw)
	defer clearCLIRunRawMessages(values)
	if !ok || len(keys) != 3 {
		return "", errCLIRunControl
	}
	for _, field := range []string{"v", "delivery_control", "challenge"} {
		if _, present := keys[field]; !present {
			return "", errCLIRunControl
		}
	}
	var v int
	if json.Unmarshal(values["v"], &v) != nil || v != 1 {
		return "", errCLIRunControl
	}
	var deliveryControl bool
	if json.Unmarshal(values["delivery_control"], &deliveryControl) != nil || !deliveryControl {
		return "", errCLIRunControl
	}
	var challenge string
	if json.Unmarshal(values["challenge"], &challenge) != nil || !validCLIRunControlChallenge(challenge) {
		return "", errCLIRunControl
	}
	return challenge, nil
}

// RequestCLIRunControl is the explicit opt-in API. It sends one request with
// delivery_control=true and returns a handle only after the broker writes the
// exact post-response control-ready frame. An older broker refuses the unknown
// field; a broker that does not retain the socket cannot produce the frame.
// The handle can then round-trip one strict commit phase, closes the same
// authenticated connection on Close or on the original context
// deadline/cancellation, and does not activate a lease.
func RequestCLIRunControl(ctx context.Context, req CLIRunBrokerRequest) (CLIRunBrokerResponse, *CLIRunControl, error) {
	if ctx == nil {
		return CLIRunBrokerResponse{}, nil, errCLIRunInvalid
	}
	if _, ok := ctx.Deadline(); !ok {
		return CLIRunBrokerResponse{}, nil, errCLIRunControlDeadline
	}
	if !validCLIRunRequest(req.V, req.VaultPath, req.Scope, req.Targets) {
		return CLIRunBrokerResponse{}, nil, errCLIRunInvalid
	}
	if ce := ctx.Err(); ce != nil {
		return CLIRunBrokerResponse{}, nil, ce
	}
	endpoint, e := DefaultBrokerEndpoint()
	if e != nil {
		if ce := ctx.Err(); ce != nil {
			return CLIRunBrokerResponse{}, nil, ce
		}
		return CLIRunBrokerResponse{}, nil, errCLIRunEndpoint
	}
	conn, e := dialLocal(ctx, endpoint)
	if e != nil {
		if ce := ctx.Err(); ce != nil {
			return CLIRunBrokerResponse{}, nil, ce
		}
		if dialAbsent(e) {
			return CLIRunBrokerResponse{}, nil, ErrBrokerUnavailable
		}
		return CLIRunBrokerResponse{}, nil, errCLIRunDial
	}
	req.DeliveryControl = true
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	resp, e := cliRunExchange(ctx, conn, req)
	if e != nil {
		stop()
		_ = conn.Close()
		if e != ErrBrokerUnavailable {
			if ce := ctx.Err(); ce != nil {
				return CLIRunBrokerResponse{}, nil, cliRunContextError(ce)
			}
		}
		return CLIRunBrokerResponse{}, nil, e
	}
	challenge, e := readCLIRunControlReady(conn)
	if e != nil {
		stop()
		_ = conn.Close()
		if ce := ctx.Err(); ce != nil {
			return CLIRunBrokerResponse{}, nil, cliRunContextError(ce)
		}
		return CLIRunBrokerResponse{}, nil, e
	}
	if !stop() {
		_ = conn.Close()
		if ce := ctx.Err(); ce != nil {
			return CLIRunBrokerResponse{}, nil, cliRunContextError(ce)
		}
		return CLIRunBrokerResponse{}, nil, errCLIRunControl
	}
	if ce := ctx.Err(); ce != nil {
		_ = conn.Close()
		return CLIRunBrokerResponse{}, nil, cliRunContextError(ce)
	}
	control := &CLIRunControl{conn: conn, challenge: challenge, state: cliRunControlHandlePending}
	control.stop = context.AfterFunc(ctx, func() { _ = control.Close() })
	return resp, control, nil
}
