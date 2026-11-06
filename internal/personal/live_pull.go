package personal

import (
	"bytes"
	"context"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"

	"github.com/jihuayu/locklark/internal/gateway"
	"github.com/jihuayu/locklark/internal/vault"
)

const livePullAction = "item.invoke.github-pull"

var ErrLivePullTarget = errors.New("invalid fixed GitHub pull request target")
var ErrLivePullResult = errors.New("GitHub result unavailable; intent recorded, request may have reached upstream")

// LivePullRequest is supplied and confirmed by the local human, never copied
// from a plugin proposal or recorded-response approval. Address is an independently
// chosen public IPv4 address; TLS still authenticates api.github.com.
type LivePullRequest struct {
	Repository gateway.Repository `json:"repository"`
	Number     int                `json:"number"`
	Address    string             `json:"address"`
}
type LivePullReceipt struct {
	Status       string             `json:"status"`
	Session      string             `json:"session"`
	Intent       string             `json:"intent"`
	TargetDigest string             `json:"target_digest"`
	Result       gateway.PullResult `json:"result"`
}

func (r LivePullRequest) Validate() error {
	ip, e := netip.ParseAddr(r.Address)
	if e != nil || ip.String() != r.Address || r.Number < 1 || int64(r.Number) > 2147483647 {
		return ErrLivePullTarget
	}
	if _, e = gateway.NewPullReader(r.Repository, ip); e != nil {
		return ErrLivePullTarget
	}
	return nil
}
func (r LivePullRequest) binding(secret []byte) (string, error) {
	key, e := hkdf.Key(sha256.New, secret, nil, "locklark/personal/live-pull/key/v1", 32)
	if e != nil {
		return "", invalid
	}
	defer clear(key)
	raw, e := json.Marshal(struct {
		Backend string
		Request LivePullRequest
	}{"github-https/v1", r})
	if e != nil {
		return "", invalid
	}
	defer clear(raw)
	mac := hmac.New(sha256.New, key)
	mac.Write(raw)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// LivePull sends one fixed GET only after successful authenticated intent commit
// and database close. The password field must hold the operator's GitHub token.
// The receipt reports a response observed by this process, not a durable outcome
// log or a reusable machine grant. A crash leaves intent-only/unknown evidence.
func LivePull(ctx context.Context, path, pw string, key []byte, target RevealTarget, request LivePullRequest) (LivePullReceipt, error) {
	return livePull(ctx, target, request, func(r *LivePullRequest) (result, error) {
		return command(path, pw, key, livePullAction, vault.Item{}, &Edit{ID: target.ID, Revision: target.Revision, Field: "password"}, commandOption{livePull: r})
	}, executeLivePull)
}
func livePull(ctx context.Context, target RevealTarget, request LivePullRequest, prepare func(*LivePullRequest) (result, error), execute func(context.Context, LivePullRequest, []byte) (gateway.PullResult, error)) (LivePullReceipt, error) {
	if ctx == nil || ctx.Err() != nil || !ValidRevealTarget(target.ID, target.Revision, target.Field) || target.Field != "password" || request.Validate() != nil {
		return LivePullReceipt{}, ErrLivePullTarget
	}
	r, e := prepare(&request)
	defer clear(r.value)
	if e != nil {
		return LivePullReceipt{}, e
	}
	if ctx.Err() != nil {
		return LivePullReceipt{}, ErrLivePullResult
	}
	got, e := execute(ctx, request, r.value)
	if e != nil {
		return LivePullReceipt{}, ErrLivePullResult
	}
	return LivePullReceipt{Status: "result-received", Session: r.session, Intent: r.intent, TargetDigest: r.destinationDigest, Result: got}, nil
}
func executeLivePull(ctx context.Context, r LivePullRequest, value []byte) (gateway.PullResult, error) {
	if r.Validate() != nil {
		return gateway.PullResult{}, ErrLivePullTarget
	}
	ip, _ := netip.ParseAddr(r.Address)
	reader, e := gateway.NewPullReader(r.Repository, ip)
	if e != nil {
		return gateway.PullResult{}, ErrLivePullTarget
	}
	plan, _ := json.Marshal(struct {
		V      int    `json:"v"`
		Action string `json:"action"`
		Repo   string `json:"repo"`
		Number int    `json:"number"`
	}{1, gateway.PullAction, r.Repository.ID, r.Number})
	return reader.ReadApproved(ctx, gateway.Target{Repo: r.Repository.ID, Number: r.Number}, plan, func() ([]byte, error) { return bytes.Clone(value), nil })
}

func boundValueAction(action string) bool {
	return injectAction(action) || runAction(action) || action == livePullAction || action == passkeyGetAction || (action == browserFillAction || action == browserOTPAction)
}
