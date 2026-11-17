package remoteunlocktls

import "github.com/jihuayu/locklark/pkg/remoteunlock"

// The typed convenience methods below are thin adapters from the public
// canonical binding-context codec (pkg/remoteunlock) to the opaque ExportBinding
// and VerifyBinding methods. They do not define, duplicate or fork an
// encoding: the canonical bytes are always produced by
// remoteunlock.EncodeChannelBindingContext, and everything else (the pinned
// handshake recheck, the exporter label, the context-mandatory check and the
// constant-time comparison) is unchanged Channel behaviour.

// ExportBindingContext is the typed form of ExportBinding for the canonical
// v1 binding context. It canonical-encodes bindingCtx with
// remoteunlock.EncodeChannelBindingContext and delegates to
// ExportBinding with those bytes.
//
// An invalid bindingCtx is rejected with the codec error (wrapping
// remoteunlock.ErrInvalidContext) before the Channel is consulted, so no
// binding is derived for it. A Channel refusal (ErrUninitializedChannel,
// ErrChannelClosed, an incomplete/resumed/non-TLS-1.3/pinned-peer check) is
// returned unchanged from ExportBinding.
//
// Like every binding, the result is only meaningful for this established
// connection; a verifier must recompute it on the channel that carried the
// request (see VerifyBindingContext).
func (c *Channel) ExportBindingContext(bindingCtx remoteunlock.ChannelBindingContext) ([]byte, error) {
	encoded, err := remoteunlock.EncodeChannelBindingContext(bindingCtx)
	if err != nil {
		return nil, err
	}
	return c.ExportBinding(encoded)
}

// VerifyBindingContext is the typed form of VerifyBinding for the canonical
// v1 binding context. It canonical-encodes bindingCtx with
// remoteunlock.EncodeChannelBindingContext and delegates to
// VerifyBinding with those bytes and expected.
//
// An invalid bindingCtx is rejected with the codec error (wrapping
// remoteunlock.ErrInvalidContext) before the Channel is consulted. Otherwise
// the refusals are exactly those of VerifyBinding: ErrBindingMismatch on
// mismatch, the channel refusals of ExportBinding, and a length error for an
// expected value that is not ChannelBindingSize bytes.
//
// The context is encoded with the same public codec on both peers, so typed
// and opaque bindings for the same context are interchangeable: on one
// connection, ExportBindingContext(ctx) equals ExportBinding(encoded).
//
// Scope. These methods only bind the canonical context bytes to this
// established Channel. A successful export or verify proves nothing about the
// context's claims: it does not verify the request, device identity,
// signatures, pairing, membership or policy, does not check the request
// deadline or expiry, does not consume one-shot request state, and does not
// handle vault unlock keys (VUK) or their delivery. The Channel's own
// guarantees are limited to the TLS handshake and peer pin described in the
// package documentation.
func (c *Channel) VerifyBindingContext(bindingCtx remoteunlock.ChannelBindingContext, expected []byte) error {
	encoded, err := remoteunlock.EncodeChannelBindingContext(bindingCtx)
	if err != nil {
		return err
	}
	return c.VerifyBinding(encoded, expected)
}
