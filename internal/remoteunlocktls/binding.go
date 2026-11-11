package remoteunlocktls

import (
	"crypto/ed25519"

	"github.com/jihuayu/locklark/pkg/remoteunlock"
)

// VerifyPeerDeviceTransportBinding checks that the stable device transport
// binding received from this channel's peer names the peer certificate this
// Channel actually verified, and that the binding, cross-checked against
// bindingCtx, verifies under the caller-pinned device signing key.
//
// The checks run in exactly this order, and each one fully precedes the next:
//
//  1. c.Check(). A zero or uninitialized Channel returns
//     ErrUninitializedChannel; a closed Channel returns ErrChannelClosed; an
//     incomplete, non-TLS-1.3, resumed or unverified connection, or one whose
//     verified leaf no longer matches the handshake pin, returns the
//     corresponding Check error. Binding, context, device ID, pinned key and
//     signature are not inspected before this check passes.
//  2. Peer certificate SPKI. The SHA-256 SPKI pin of the verified peer leaf
//     (ConnectionState().VerifiedChains[0][0]) is compared with
//     binding.SPKISHA256. A mismatch returns ErrDeviceTransportBindingSPKIMismatch.
//     Context, device ID, pinned key and signature are not inspected before
//     this comparison.
//  3. remoteunlock.VerifyDeviceTransportBindingForContext(binding, bindingCtx,
//     expectedDeviceID, callerPinnedKey). Its errors are returned unchanged and
//     wrap remoteunlock.ErrInvalidBinding (or remoteunlock.ErrInvalidContext
//     for a context the canonical codec rejects). This package neither
//     duplicates nor relaxes its signature or context validation.
//
// callerPinnedKey is supplied by the caller from authenticated state, such as
// pinned vault policy for the expected device; it is never resolved from the
// binding or the channel. The rendered errors are static and never include a
// key, signature, certificate digest, recipient string or field value.
//
// Scope. A nil return proves only that (a) this already-verified TLS channel's
// peer certificate SPKI equals the SPKI digest inside a binding that the
// distinct caller-pinned key signed, and (b) that binding overlaps the
// supplied context and expected device identifier as
// VerifyDeviceTransportBindingForContext requires. It proves no enrollment,
// provenance or trust of either key, no owner/admin authorization, no pairing
// approval, no request freshness, digest or deadline correctness, no
// one-shotness, no VUK access or delivery, no request or exporter binding, and
// no complete mobile unlock. bindingCtx is not authenticated by this call.
//
// Closed Channel: Check precedes every other input, so once Close has been
// called this method returns ErrChannelClosed for any binding, context, device
// ID and key.
func (c *Channel) VerifyPeerDeviceTransportBinding(binding remoteunlock.DeviceTransportBinding, bindingCtx remoteunlock.ChannelBindingContext, expectedDeviceID string, callerPinnedKey ed25519.PublicKey) error {
	if err := c.Check(); err != nil {
		return err
	}
	leaf := c.conn.ConnectionState().VerifiedChains[0][0]
	if got := PeerSPKIPinOf(leaf); got != PeerSPKIPin(binding.SPKISHA256) {
		return ErrDeviceTransportBindingSPKIMismatch
	}
	return remoteunlock.VerifyDeviceTransportBindingForContext(binding, bindingCtx, expectedDeviceID, callerPinnedKey)
}
