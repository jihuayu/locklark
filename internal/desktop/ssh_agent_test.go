package desktop

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jihuayu/locklark/internal/personal"
	"github.com/jihuayu/locklark/internal/sshagent"
	"golang.org/x/crypto/ssh"
)

func sshSessionFixture(t *testing.T) (*personal.Session, personal.SSHKeyRow) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ssh.ll")
	key := bytes.Repeat([]byte{53}, 16)
	defer clear(key)
	if personal.Create(path, "ssh-native-fixture", key) != nil {
		t.Fatal("encrypted SSH vault fixture failed")
	}
	s, e := personal.UnlockSession(path, []byte("ssh-native-fixture"), key, time.Minute)
	if e != nil {
		t.Fatal("SSH session unlock failed")
	}
	t.Cleanup(s.Lock)
	g := personal.NewMutationGate(time.Now().Add(time.Minute))
	if s.RegisterMutation(g) != nil {
		t.Fatal("SSH mutation gate fixture failed")
	}
	row, e := s.GenerateSSHKey("Native SSH key", g)
	if e != nil {
		t.Fatal("SSH key generation failed")
	}
	return s, row
}
func sshWire(t *testing.T, row personal.SSHKeyRow, data []byte) sshagent.SignRequest {
	t.Helper()
	pub, e := canonicalSSHPublic(row.PublicKey)
	if e != nil {
		t.Fatal("SSH public metadata invalid")
	}
	return sshagent.SignRequest{RequestID: strings.Repeat("1", 32), ConnectionID: strings.Repeat("2", 32), Peer: sshagent.Peer{User: "UID fixture", PID: 42, Process: "fixture-client"}, PublicKey: pub.Marshal(), Data: data, Until: time.Now().Add(20 * time.Second)}
}

type nativeSSHResult struct {
	value []byte
	err   error
}

func TestNativeSSHRequiresOneExplicitExactApproval(t *testing.T) {
	s, row := sshSessionFixture(t)
	requests := make(chan *sshNativeRequest, 1)
	h := newSSHNativeHost(s, func(r *sshNativeRequest) { requests <- r }, nil)
	defer h.close()
	data := []byte("immutable public signing fixture")
	original := bytes.Clone(data)
	wire := sshWire(t, row, data)
	result := make(chan nativeSSHResult, 1)
	go func() { v, e := h.Sign(context.Background(), wire); result <- nativeSSHResult{v, e} }()
	var request *sshNativeRequest
	select {
	case request = <-requests:
	case <-time.After(time.Second):
		t.Fatal("native approval did not arrive")
	}
	digest := sha256.Sum256(original)
	if request.view.PayloadDigest != hex.EncodeToString(digest[:]) || request.view.Key.ID != row.ID || request.view.Key.Revision != row.Revision || request.view.DataBytes != len(original) || request.view.Flags != 0 {
		t.Fatal("native prompt was not bound to immutable core metadata")
	}
	select {
	case <-result:
		t.Fatal("signature returned before native approval")
	default:
	}
	for i := range data {
		data[i] = 0
	}
	for i := range wire.PublicKey {
		wire.PublicKey[i] = 0
	}
	request.choose(true)
	var signed nativeSSHResult
	select {
	case signed = <-result:
	case <-time.After(time.Second):
		t.Fatal("approved signature did not finish")
	}
	defer clear(signed.value)
	pub, e := canonicalSSHPublic(row.PublicKey)
	var signature ssh.Signature
	if signed.err != nil || e != nil || ssh.Unmarshal(signed.value, &signature) != nil || pub.Verify(original, &signature) != nil {
		t.Fatal("explicit approval did not sign the exact original data")
	}
}
func TestNativeSSHDenyDisconnectAndBusyNeverReuseApproval(t *testing.T) {
	s, row := sshSessionFixture(t)
	for _, kind := range []string{"deny", "disconnect", "host-stop"} {
		requests := make(chan *sshNativeRequest, 1)
		h := newSSHNativeHost(s, func(r *sshNativeRequest) { requests <- r }, nil)
		ctx, cancel := context.WithCancel(context.Background())
		wire := sshWire(t, row, []byte("public signing fixture"))
		result := make(chan nativeSSHResult, 1)
		go func() { v, e := h.Sign(ctx, wire); result <- nativeSSHResult{v, e} }()
		var r *sshNativeRequest
		select {
		case r = <-requests:
		case <-time.After(time.Second):
			t.Fatal("native pending request unavailable")
		}
		if value, e := h.Sign(context.Background(), sshWire(t, row, []byte("second request"))); e == nil || len(value) != 0 {
			clear(value)
			t.Fatal("native approval queue exceeded one pending request")
		}
		switch kind {
		case "deny":
			r.choose(false)
		case "disconnect":
			cancel()
		case "host-stop":
			h.close()
		}
		select {
		case reply := <-result:
			clear(reply.value)
			if reply.err == nil || len(reply.value) != 0 {
				t.Fatal("denied or cancelled request emitted signature")
			}
		case <-time.After(time.Second):
			t.Fatal("native cancellation waited for approval")
		}
		r.choose(true)
		cancel()
		h.close()
	}
	events, e := s.Audit()
	if e != nil {
		t.Fatal("SSH refusal audit check failed")
	}
	for _, event := range events {
		if event.Action == "item.ssh.sign" {
			t.Fatal("refused preparation recorded a signing intent")
		}
	}
}
func TestNativeSSHLockCancelsPendingAndStopsAuthority(t *testing.T) {
	s, row := sshSessionFixture(t)
	requests := make(chan *sshNativeRequest, 1)
	h := newSSHNativeHost(s, func(r *sshNativeRequest) { requests <- r }, nil)
	result := make(chan nativeSSHResult, 1)
	go func() {
		v, e := h.Sign(context.Background(), sshWire(t, row, []byte("fixture")))
		result <- nativeSSHResult{v, e}
	}()
	var r *sshNativeRequest
	select {
	case r = <-requests:
	case <-time.After(time.Second):
		t.Fatal("pending SSH request unavailable")
	}
	a := New()
	a.session = s
	a.sshHost = h
	a.sshApproval = r
	a.launch = func(fn func()) { fn() }
	a.Lock()
	select {
	case reply := <-result:
		clear(reply.value)
		if reply.err == nil {
			t.Fatal("lock did not cancel pending signature")
		}
	case <-time.After(time.Second):
		t.Fatal("lock did not release native request")
	}
	keys, e := h.Identities(context.Background(), sshagent.Peer{})
	if e != nil || len(keys) != 0 || a.sshApproval != nil || s.Unlocked() {
		t.Fatal("locked service retained metadata or authority")
	}
}
func TestPublicKeyCopyRejectsOptionsAndComments(t *testing.T) {
	_, row := sshSessionFixture(t)
	for _, value := range []string{"restrict " + row.PublicKey, strings.TrimSpace(row.PublicKey) + " injected-comment\n", row.PublicKey + row.PublicKey} {
		if _, e := canonicalSSHPublic(value); e == nil {
			t.Fatal("public copy accepted options, comment or multiple lines")
		}
	}
}

func TestNativeSSHRejectAfterApprovalStillCancelsBeforeGrant(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := &sshNativeRequest{ctx: ctx, cancel: cancel, decision: make(chan bool, 1)}
	r.choose(true)
	r.choose(false)
	if ctx.Err() == nil {
		t.Fatal("visible reject action did not revoke a not-yet-granted approval")
	}
}
