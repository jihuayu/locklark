package browserhost

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// RequestCLIRunV2 performs the single one-shot cli-run v2 exchange with a
// running desktop broker. The request is validated and rebuilt from the trusted
// profile registry before any connection is opened, so a local refusal never
// writes a byte to the socket.
//
// Outcome classification is strict:
//   - ErrBrokerUnavailable only when the trusted endpoint was never reached.
//   - ErrBrokerRefused for a local refusal or a fixed server refusal that
//     precedes the intended disclosure.
//   - ErrBrokerUnknown for anything after the request frame was submitted, or
//     for a reply that cannot be verified. Neither sentinel permits a retry or
//     a fallback to the legacy per-field path.
func RequestCLIRunV2(ctx context.Context, params CLIRunV2Params) (CLIRunV2Result, error) {
	if ctx == nil || ctx.Err() != nil {
		return CLIRunV2Result{}, ErrBrokerRefused
	}
	// Validate and pin the trusted scope before opening any socket. The profile
	// name, versioned spec id and canonical spec digest are resolved here from
	// the local built-in, never supplied by the caller.
	probe := buildCLIRunV2Request(params, strings.Repeat("0", cliRunV2NonceHexLen), 0)
	if !validCLIRunV2Wire(probe) {
		return CLIRunV2Result{}, ErrBrokerRefused
	}
	if _, _, _, ok := trustedCLIRunV2Request(probe); !ok {
		return CLIRunV2Result{}, ErrBrokerRefused
	}

	endpoint, err := brokerEndpointForClient()
	if err != nil {
		return CLIRunV2Result{}, err
	}
	conn, err := dialVerifiedBroker(ctx, endpoint)
	if err != nil {
		if errors.Is(err, ErrBrokerUnavailable) {
			return CLIRunV2Result{}, ErrBrokerUnavailable
		}
		return CLIRunV2Result{}, ErrBrokerRefused
	}
	defer conn.Close()

	// One absolute client deadline: ctx may shorten it, nothing extends it.
	deadline := time.Now().Add(cliRunV2HandshakeTTL + cliRunV2ApprovalTTL)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)
	stop := watchCLIRunContext(ctx, conn)
	defer stop()

	hello, err := json.Marshal(BrokerHello{V: cliRunV2Version, Mode: cliRunV2Mode})
	if err != nil {
		return CLIRunV2Result{}, ErrBrokerRefused
	}
	if err = writeFrame(conn, hello); err != nil {
		clear(hello)
		return CLIRunV2Result{}, cliRunFailure(ctx, false)
	}
	clear(hello)

	challengeRaw, err := readFrame(conn, 4096)
	if err != nil {
		return CLIRunV2Result{}, ErrBrokerUnknown
	}
	defer clear(challengeRaw)
	challenge, err := decodeCLIRunV2Challenge(challengeRaw)
	if err != nil {
		return CLIRunV2Result{}, ErrBrokerUnknown
	}
	if challenge.Error != "" {
		switch challenge.Error {
		case "refused", "unsupported":
			return CLIRunV2Result{}, ErrBrokerRefused
		default:
			return CLIRunV2Result{}, ErrBrokerUnknown
		}
	}

	request := buildCLIRunV2Request(params, challenge.Nonce, challenge.Epoch)
	if !validCLIRunV2Wire(request) {
		return CLIRunV2Result{}, ErrBrokerRefused
	}
	digest := cliRunV2ScopeDigest(request)
	if digest == "" {
		return CLIRunV2Result{}, ErrBrokerRefused
	}
	raw, err := json.Marshal(request)
	if err != nil {
		return CLIRunV2Result{}, ErrBrokerRefused
	}
	defer clear(raw)
	// The disclosure request is about to be submitted. From this point on, no
	// outcome may be reported as a fallback-safe "unavailable".
	if ctx.Err() != nil {
		return CLIRunV2Result{}, ErrBrokerRefused
	}
	if err = writeFrame(conn, raw); err != nil {
		clear(raw)
		return CLIRunV2Result{}, ErrBrokerUnknown
	}
	clear(raw)

	replyRaw, err := readFrame(conn, MaxOutput)
	if err != nil {
		return CLIRunV2Result{}, ErrBrokerUnknown
	}
	defer clear(replyRaw)
	reply, err := decodeCLIRunV2Reply(replyRaw)
	if err != nil {
		return CLIRunV2Result{}, ErrBrokerUnknown
	}
	return verifyCLIRunV2Reply(ctx, request, digest, reply)
}

func verifyCLIRunV2Reply(ctx context.Context, request CLIRunV2Request, digest string, reply CLIRunV2Reply) (CLIRunV2Result, error) {
	transferred := false
	defer func() {
		if !transferred {
			wipeCLIRunV2Values(reply.Values)
		}
	}()
	if reply.Nonce != request.Nonce || reply.Epoch != request.Epoch {
		return CLIRunV2Result{}, ErrBrokerUnknown
	}
	if reply.Error != "" {
		// An error reply must never carry values. Values on an error frame are a
		// malformed or unverifiable outcome, never a pre-disclosure refusal.
		if len(reply.Values) != 0 {
			return CLIRunV2Result{}, ErrBrokerUnknown
		}
		switch reply.Error {
		case "refused", "unsupported":
			return CLIRunV2Result{}, ErrBrokerRefused
		default:
			return CLIRunV2Result{}, ErrBrokerUnknown
		}
	}
	if reply.ScopeDigest != digest || reply.Receipt == nil || !validCLIRunV2WireReceipt(*reply.Receipt) {
		return CLIRunV2Result{}, ErrBrokerUnknown
	}
	if !cliRunV2ValuesMatch(request.Targets, reply.Values) {
		return CLIRunV2Result{}, ErrBrokerUnknown
	}
	if ctx.Err() != nil {
		return CLIRunV2Result{}, ErrBrokerUnknown
	}
	transferred = true
	return CLIRunV2Result{
		Values: reply.Values, Receipt: *reply.Receipt, ScopeDigest: digest, Epoch: reply.Epoch,
	}, nil
}

// buildCLIRunV2Request fills the public frame from the caller's private params.
// The versioned spec id and the canonical spec digest are always derived from
// the local built-in profile the name resolves to; the caller cannot set them,
// and an unknown name leaves them empty so the wire check refuses locally.
func buildCLIRunV2Request(params CLIRunV2Params, nonce string, epoch uint64) CLIRunV2Request {
	specID, specDigest := "", ""
	if spec, ok := lookupCLIRunV2Profile(params.ProfileID); ok {
		specID, specDigest = spec.ID, cliRunV2SpecDigest(spec)
	}
	return CLIRunV2Request{
		V: cliRunV2Version, Nonce: nonce, Epoch: epoch,
		VaultPath: params.VaultPath, Root: params.Root, ProfileID: params.ProfileID,
		SpecID: specID, SpecDigest: specDigest,
		Program: params.Program, Args: cloneCLIRunV2Strings(params.Args),
		Directory: params.Directory, TimeoutSeconds: params.TimeoutSeconds,
		HelperPath:   cloneCLIRunV2Strings(params.HelperPath),
		Passthrough:  cloneCLIRunV2Map(params.Passthrough),
		TokenEnvName: params.TokenEnvName, Targets: cloneCLIRunV2Targets(params.Targets),
	}
}

func validCLIRunV2WireReceipt(receipt CLIRunV2Receipt) bool {
	return validCLIRunV2Hex(receipt.Session, 16) &&
		validCLIRunV2Hex(receipt.Intent, 32) &&
		validCLIRunV2Hex(receipt.TargetDigest, 32)
}

func cliRunV2ValuesMatch(targets []CLIRunV2Target, values map[string][]byte) bool {
	if len(values) != len(targets) {
		return false
	}
	for _, target := range targets {
		value, ok := values[target.Slot]
		if !ok || len(value) > cliRunV2MaxValueBytes {
			return false
		}
	}
	return true
}
