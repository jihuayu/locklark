// Package remoteunlock defines the standalone v1 canonical codecs for the
// remote-unlock TLS exporter binding context, the stable per-device transport
// binding, and the owner-root authorization.
//
// A ChannelBindingContext is encoded to a single canonical UTF-8 JSON object
// (at most MaxContextSize bytes) that is used as the exporter context of a
// pinned TLS 1.3 channel. A DeviceTransportBinding is a separate canonical
// object (at most MaxBindingSize bytes) that identifies one member's device and
// vault across requests; it is stable and deliberately independent of any
// single request. An OwnerRootAuthorization is a third canonical object (at
// most MaxAuthorizationSize bytes) that the vault owner root signs once per
// request: it binds the context by digest, both endpoint bindings by digest
// over their complete signed bytes, and an absolute expiry. Encode* and Parse*
// write and accept every member manually in the fixed schema order, so every
// accepted input satisfies Encode(Parse(b)) == b.
//
// The wire format, domains, preimages, expiry semantics and limitation list
// are documented in docs/remote-unlock-wire-v1.md.
//
// Scope. This package encodes and decodes context, binding and authorization
// bytes, computes the public signature preimages (SigningBytes and
// AuthorizationSigningBytes), and verifies a binding signature with a
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
// The owner root is the sole issuer accepted. This package does not create or
// inspect TLS connections, derive or compare exporter output, match a live
// peer's SPKI (the TLS adapter's separate check), define request-digest
// preimage semantics, prove that a device holds its private keys, prove
// enrollment or real identity, provide durable one-shot or restart
// anti-rollback, or decrypt, wrap or deliver a vault unlock key (VUK). There is
// no admin, reader or delegation authorization path and no policy mutation.
// The wire is synthetic in every test; no production identity or unlock is
// claimed.
//
// The package is intended for both the macOS process and the remote device, so
// it is a separate public package. It depends on the Go standard library,
// filippo.io/age for canonical age X25519 recipient parsing, and the public
// pkg/vaultfile policy-checkpoint API.
package remoteunlock
