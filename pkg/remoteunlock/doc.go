// Package remoteunlock defines the standalone v1 canonical codecs for the
// remote-unlock TLS exporter binding context, the stable per-device transport
// binding, the owner-root authorization, the reusable owner-root admin
// remote-unlock delegation, the per-request delegated-admin authorization and
// the dual-signed pairing consent.
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
// that interval. An AdminRemoteUnlockAuthorization is a fifth canonical object
// (at most MaxAdminAuthorizationSize bytes) that the delegated admin device --
// never the owner root -- signs fresh for one request: it binds the reusable
// grant by digest, the full request context by digest, both complete endpoint
// bindings by digest and one expiry. Every Encode* and Parse* pair writes and
// accepts its members manually in the fixed schema order, so every accepted
// input satisfies Encode(Parse(b)) == b. A PairConsent is a sixth, separate
// canonical object (at most MaxPairConsentSize bytes) that both endpoints of
// one pair sign with their current registered device identity keys for one
// server-issued pair challenge.
//
// The wire format, domains, preimages, expiry semantics and limitation list
// are documented in docs/remote-unlock-wire-v1.md. The reusable admin
// delegation and the per-request admin authorization have their own schemas,
// anchors and boundaries; see those sections and
// VerifyOwnerRootAdminRemoteUnlockDelegation and
// VerifyAdminRemoteUnlockAuthorization below.
//
// Scope. This package encodes and decodes context, binding, authorization and
// delegation bytes, computes the public signature preimages (SigningBytes,
// AuthorizationSigningBytes, AdminDelegationSigningBytes and
// AdminAuthorizationSigningBytes), and verifies a binding signature with a
// caller-pinned Ed25519 public key. VerifyOwnerRootAuthorization additionally
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
// request: it verifies no request binding, no binding signature or recipient
// key and no per-request consent. That is the job of the later per-request
// AdminRemoteUnlockAuthorization.
//
// VerifyAdminRemoteUnlockAuthorization composes the two objects. It verifies
// the request authorization's context and grant digests, calls
// VerifyOwnerRootAdminRemoteUnlockDelegation so the reusable grant is checked
// against the actual authenticated current policy and its
// [not_before, expires) interval, requires the request expiry to be strictly
// after the caller's now, no later than the context deadline and no later than
// the grant expiry, requires the context member, vault, both device
// identifiers, pair generation, key epoch, policy sequence and policy digest
// to equal the grant scope, re-resolves the delegate and both endpoint devices
// in the authenticated current policy, verifies both binding recipient keys
// and device signatures with each device's authenticated content signing key
// (source then target), compares each complete-binding digest with both the
// authorization member and the grant scope, and finally verifies the
// per-request signature under exactly the delegate device's current non-nil
// Ed25519 policy signing key with an admin or owner role. A content signing
// key and the owner root key are never accepted for that signature, and the
// owner root signs no per-request object. The reusable grant keeps its exact
// shape: it carries no request identifier, request digest, lock generation or
// request deadline, and one grant covers any number of requests in its scope.
//
// A nil return from VerifyAdminRemoteUnlockAuthorization still proves only
// that the request context and two signed bindings match the currently valid
// reusable scope and that the delegated admin device signed them before the
// request expiry. It is not a TLS, relay, VUK-delivery or production-identity
// check, and it is not a durable one-shot or replay defense: the same valid
// bytes verify again, before and after a restart. The caller's request
// lifecycle, not this verifier, must prevent replay and one-shot use.
// vaultfile.AdminDelegation is never reinterpreted as remote-unlock authority,
// no PC role is changed, and no vaultfile byte or schema changes here.
//
// VerifyPairConsent checks a PairConsent against the caller-pinned expected
// tenant, user, pair, pair generation, challenge identifier, exact original
// server-issued deadline and exact endpoint identifiers, and requires both
// signatures to verify under the caller-supplied current registered device
// identity keys, one pinned per endpoint (DeviceIDSignerKeys). Device a must be
// the bytewise-lower identifier so both endpoints sign exactly the same tuple.
// The caller-supplied nowUnixMS must be positive and strictly earlier than the
// consent's deadline, which must equal the original challenge deadline exactly;
// the deadline is never extended and no system clock is read.
//
// Pair-consent signatures use the current registered device identity keys that
// the caller supplies. They are NOT the vault-policy ContentSigningKey used to
// validate a DeviceTransportBinding, not the owner root and not a policy
// signing key; a content signing key never verifies a PairConsent. A
// PairConsent binds only the tenant, user, pair ID and generation, the two
// device IDs, the two 32-byte DeviceTransportBindingDigest values of the
// complete binding objects, the challenge ID and the deadline. It carries no
// vault_id, SPKI, age recipient, full binding bytes, VUK, grant,
// authorization or private key. A nil return proves only that both
// caller-pinned registered device keys signed the same metadata tuple; it does
// not establish human scan or fingerprint confirmation, current registration
// by itself (the caller must have fetched the keys from verified registration),
// vault authorization or role, a valid DeviceTransportBinding for either
// digest, TLS identity, replay safety, or any unlock. The package never reads
// a device or user registration store, and no production identity is claimed.
//
// The owner root is the sole issuer accepted by the owner-root authorization
// and the reusable admin delegation; it issues no per-request admin
// authorization. This package does not create or inspect TLS
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
