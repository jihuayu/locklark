package browserhost

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"sync"
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

var cliRunControlReady = []byte(`{"v":1,"delivery_control":true}`)

// CLIRunControl is the opt-in post-delivery handle. It carries no authority:
// its Close only ends the retained authenticated socket. The server still owns
// proof, nonce, scope, and any future lease lifecycle.
type CLIRunControl struct {
	once      sync.Once
	conn      net.Conn
	stop      func() bool
	challenge string
}

func (c *CLIRunControl) Close() error {
	if c == nil {
		return nil
	}
	c.once.Do(func() {
		c.challenge = ""
		if c.stop != nil {
			c.stop()
		}
		if c.conn != nil {
			_ = c.conn.Close()
		}
	})
	return nil
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
// The handle closes the same authenticated connection on Close or on the
// original context deadline/cancellation. It does not activate a lease.
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
	control := &CLIRunControl{conn: conn, challenge: challenge}
	control.stop = context.AfterFunc(ctx, func() { _ = control.Close() })
	return resp, control, nil
}
