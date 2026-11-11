// Package remoteunlock defines the standalone v1 canonical codecs for the
// remote-unlock TLS exporter binding context, the stable per-device transport
// binding, the owner-root authorization and the reusable owner-root admin
// remote-unlock delegation.
//
// A ChannelBindingContext is encoded to a single canonical UTF-8 JSON object
// (at most MaxContextSize bytes) that is used as the exporter context of a
// pinned TLS 1.3 channel. A DeviceTransportBinding is a separate canonical
// object (at most MaxBindingSize bytes) that identifies one member's device and
// vault across requests; it is stable and deliberately independent of any
// single request. An OwnerRootAuthorization is a third canonical object (at
// most MaxAuthorizationSize bytes) that the vault owner root signs once per
// request: it binds the context by digest, both endpoint bindings by digest
// over their complete signed bytes, and an absolute expiry. An
// OwnerRootAdminRemoteUnlockDelegation is a fourth canonical object (at most
// MaxAdminDelegationSize bytes) that the owner root signs once for one
// delegate device and one requester's stable endpoints, with an exact policy
// anchor and a validity interval, and that covers any number of requests in
// that interval. Every Encode* and Parse* pair writes and accepts its members
// manually in the fixed schema order, so every accepted input satisfies
// Encode(Parse(b)) == b.
//
// The wire format, domains, preimages, expiry semantics and limitation list
// are documented in docs/remote-unlock-wire-v1.md. The reusable admin
// delegation has its own schema, anchor and boundary; see the section there
// and VerifyOwnerRootAdminRemoteUnlockDelegation below.
//
// Scope. This package encodes and decodes context, binding, authorization and
// delegation bytes, computes the public signature preimages (SigningBytes,
// AuthorizationSigningBytes and AdminDelegationSigningBytes), and verifies a
// binding signature with a caller-pinned Ed25519 public key. VerifyOwnerRootAuthorization additionally
// checks an authorization against a caller-pinned vault-file PolicyCheckpoint:
// it requires vaultfile.VerifyPolicyCheckpoint to authenticate the carried
// current policy and content first, then matches the context's member, vault,
// key epoch, policy sequence and policy digest, resolves both context devices
// by device ID in the authenticated policy, requires the member's existing
// read qualification (a reader, writer, admin or owner role, with no role
// change) and each device's canonical age encryption key, verifies both
// device signatures with the authenticated device keys, and verifies the
// owner-root signature only with the caller-pinned root key. Expiry is strict:
// the caller-supplied nowUnixMS must be positive and earlier than both the
// authorization expiry and the request deadline (the authorization may expire
// first, never last); no system clock is read.
//
// The reusable admin delegation is a separate object, not a per-request
// authorization. It deliberately carries no request identifier, request
// digest, lock generation or request deadline: the same grant covers any
// number of requests on its scoped source and target bindings until
// expires_unix_ms, and only while the vault's current policy is still exactly
// the policy anchored by policy_seq and policy_digest. Any policy update,
// including removing, demoting or re-adding a device or principal, changes the
// policy digest and invalidates the grant; only a new owner-root-signed
// delegation for the new policy can replace it. The object names the delegate
// member and device, that device's exact policy signing key, the requester
// member, the two endpoint device identifiers, both complete binding digests,
// the pair generation, the key epoch and the policy anchor.
//
// VerifyOwnerRootAdminRemoteUnlockDelegation checks the grant against a
// caller-pinned vault-file PolicyCheckpoint and a caller-supplied clock. It
// requires vaultfile.VerifyPolicyCheckpoint to authenticate the carried
// current policy first; requires the current file header and policy to match
// the grant's vault, key epoch, policy sequence and policy digest exactly;
// requires the owner root pin and the authenticated policy root to agree and
// the owner-root signature to verify; requires the delegate device to exist in
// the authenticated current policy with delegate_member_id as its principal
// and the admin or owner role, carrying exactly the granted non-nil Ed25519
// policy signing key; and requires the requester member's existing read
// qualification plus both endpoint devices registered to it. The validity
// interval is inclusive at not_before_unix_ms and exclusive at
// expires_unix_ms, and the verifier reads no system clock.
//
// A nil return from that verifier proves only the root-signed reusable scope
// for that policy anchor and interval. It does NOT authorize a concrete
// request: this checkpoint verifies no request binding, no binding signature
// or recipient key and no per-request consent, and the later per-request
// authorization must both match the recorded binding digests and pair
// generation and verify the bindings themselves. vaultfile.AdminDelegation is
// never reinterpreted as remote-unlock authority and no vaultfile byte or
// schema changes here.
//
// The owner root is the sole issuer accepted by the owner-root authorization
// and the admin delegation. This package does not create or inspect TLS
// connections, derive or compare exporter output, match a live peer's SPKI
// (the TLS adapter's separate check), define request-digest preimage
// semantics, prove that a device holds its private keys, prove enrollment or
// real identity, provide durable one-shot or restart anti-rollback, or
// decrypt, wrap or deliver a vault unlock key (VUK). There is no reader
// authorization path and no policy mutation. The wire is synthetic in every
// test; no production identity or unlock is claimed.
//
// The package is intended for both the macOS process and the remote device, so
// it is a separate public package. It depends on the Go standard library,
// filippo.io/age for canonical age X25519 recipient parsing, and the public
// pkg/vaultfile policy-checkpoint API.
package remoteunlock
