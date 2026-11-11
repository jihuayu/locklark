# Remote unlock wire v1: binding context, device binding, owner-root authorization, reusable admin delegation, per-request admin authorization and lifecycle

Status: context and stable per-device binding codecs, the independent
owner-root authorization object and its checkpoint-scoped verifier, a reusable
owner-root-signed admin remote-unlock delegation with its current-policy
verifier, a per-request delegated-device admin authorization composed with that
grant, plus a process-local request lifecycle. The package `pkg/remoteunlock`
implements exactly these encodings, the binding signature check in
[Stable device transport binding v1](#stable-device-transport-binding-v1), the
owner-root authorization in
[Owner-root authorization v1](#owner-root-authorization-v1), the reusable
delegation in
[Reusable owner-root admin delegation v1](#reusable-owner-root-admin-delegation-v1),
the per-request admin authorization in
[Per-request admin remote-unlock authorization v1](#per-request-admin-remote-unlock-authorization-v1),
and the lifecycle in
[Process-local request lifecycle](#process-local-request-lifecycle).
`internal/remoteunlocktls` additionally exposes a narrow channel-side check of a
peer binding against the verified TLS peer certificate
([Peer binding over an established channel](#peer-binding-over-an-established-channel)).
The vectors below are synthetic and demonstrate the codecs only.

## Scope

This document defines the remote unlock v1 artifacts described in the status
above, and nothing else:

- the canonical TLS exporter binding context encoding and parsing, specified
  from [Encoding rules](#encoding-rules);
- the [stable device transport binding](#stable-device-transport-binding-v1)
  wire format and its state-free device-signature verification;
- the [owner-root authorization](#owner-root-authorization-v1) wire format and
  the [verification boundaries](#verification-procedure-and-boundary) of its
  checkpoint-scoped verifier — not a general authorization system;
- the [reusable owner-root admin
  delegation](#reusable-owner-root-admin-delegation-v1) wire format and the
  current-policy boundary of its verifier, which grants scope but authorizes
  no request by itself;
- the [per-request admin
  authorization](#per-request-admin-remote-unlock-authorization-v1) wire
  format, signed by the delegated admin device rather than the owner root, and
  the exact boundary of its composed verifier;
- the [process-local request lifecycle](#process-local-request-lifecycle) state
  machine; and
- the internal [peer-channel check](#peer-binding-over-an-established-channel)
  of a peer binding against the verified TLS peer certificate.

Each section defines its own limits, and those limits remain in force. This
document defines no relay protocol, no VUK delivery, no durable replay defense
and no complete mobile unlock flow.

Encoding or parsing a context proves only that the bytes are the canonical
encoding of syntactically valid claims. It does **not** prove authorization,
requester or device identity, pairing, membership, policy, request freshness,
one-shot consumption, signatures, a TLS handshake, or delivery of a vault unlock
key (VUK). The context codec does not create or inspect TLS connections and does
not verify any field. A caller that relies on these claims must verify them
through separate mechanisms, including a TLS exporter binding on the actual
connection.

## Encoding rules

The context is one UTF-8 JSON object:

- Members appear exactly once, in the order below. Every member is required and
  no other member is allowed.
- There is no whitespace between tokens, no BOM, and no trailing data.
- The object is written member by member in this fixed order. Go struct field
  order and `json.Marshal` behavior are never used to determine wire order.
- Strings use no JSON escapes. Every value permitted by this schema is written
  literally, so canonical input contains no `\` bytes inside strings.
- Integers use the canonical decimal spellings defined below.
- Both parsing and encoding are bounded by 4096 bytes.
- Parsing is all-or-nothing. A decoder must reject any input that is not
  byte-for-byte the canonical re-encoding of the values it contains. The
  implementation additionally parses to values, re-encodes them canonically,
  and requires exact equality with the input.

## Ordered schema

| # | Member | Type | Constraint |
|---|--------|------|------------|
| 1 | `format` | string | constant `locklark.remote-unlock` |
| 2 | `version` | integer | constant `1` |
| 3 | `kind` | string | constant `channel-binding-context` |
| 4 | `request_id` | string | identifier |
| 5 | `request_digest` | string | exactly 32 bytes, unpadded base64url |
| 6 | `pair_id` | string | identifier |
| 7 | `pair_generation` | unsigned integer | uint64; `0` is explicit genesis |
| 8 | `lock_generation` | unsigned integer | uint64; `0` is explicit genesis |
| 9 | `member_id` | string | identifier |
| 10 | `source_device_id` | string | identifier |
| 11 | `target_device_id` | string | identifier |
| 12 | `vault_id` | string | identifier |
| 13 | `key_epoch` | unsigned integer | uint64, strictly greater than zero |
| 14 | `policy_seq` | unsigned integer | uint64; `0` is explicit genesis |
| 15 | `policy_digest` | string | exactly 32 bytes, unpadded base64url |
| 16 | `deadline_unix_ms` | integer | int64, strictly greater than zero; Unix milliseconds |

All members are semantically opaque claims to this codec. In particular,
`request_digest` is an opaque 32-byte summary of the unlock request. The request
preimage and its encoding are **not** defined here: a caller must use a
separately defined request codec to compute and compare that digest.
`policy_digest` is likewise an opaque 32-byte policy digest whose preimage is
defined by the governing policy encoding. The codec does not interpret or
recompute either digest.

## Identifier grammar

Identifiers are opaque byte strings. The grammar is case-sensitive:

- Non-empty and at most 128 UTF-8 bytes.
- Every byte is ASCII `a`-`z`, `0`-`9`, `.`, `_`, `:` or `-`.
- Uppercase ASCII letters, non-ASCII bytes, whitespace, control bytes, and all
  other punctuation are invalid.
- No normalization, case folding, decoding, or interpretation is performed.
  Equal identifiers are byte-equal identifiers.

This is the vault-file textual identifier grammar with the 128-byte root limit
applied to every identifier in this context.

## Integer rules

`version` is the canonical JSON integer literal `1`.

Unsigned fields (`pair_generation`, `lock_generation`, `key_epoch`,
`policy_seq`) are canonical unsigned decimal uint64 values:

- `0`, or a non-zero value with no leading zero.
- No `+` or `-` sign, fraction, exponent, underscore, whitespace, or other
  decoration.
- Maximum `18446744073709551615` (`2^64 - 1`).

`deadline_unix_ms` is a canonical positive decimal int64 value:

- No `+` or `-` sign, fraction, exponent, underscore, whitespace, or leading
  zeros.
- Minimum `1`, maximum `9223372036854775807` (`2^63 - 1`).

Genesis zeroes are valid explicit values for `pair_generation`,
`lock_generation`, and `policy_seq`; they are not missing or wildcard values.
`key_epoch` must be at least 1, and `deadline_unix_ms` must be at least 1.

## Timestamp semantics

`deadline_unix_ms` is an absolute deadline expressed as Unix milliseconds:
milliseconds since 1970-01-01T00:00:00Z. The codec uses the supplied integer
exactly. It does not read the system clock, normalize time, round, clamp,
convert time zones, or otherwise change the deadline. Whether the deadline is
in the future is a caller decision made against the caller's trusted clock.

## Digest encoding

Each digest is exactly 32 bytes in memory. On the wire it is a JSON string
containing the unpadded base64url encoding of those 32 bytes:

- Alphabet: `A`-`Z`, `a`-`z`, `0`-`9`, `-`, `_`.
- Length: exactly 43 characters for 32 bytes.
- No `=` padding.
- Strict decoding is required: the standard base64 `+` and `/` alphabet,
  padding, wrong lengths, and non-zero trailing bits are all invalid.
- Decoding must be followed by encode-back equality, so only one spelling of a
  given 32-byte digest is accepted.

## Size budget

Encoded context bytes must be at most 4096 bytes. Parsers must reject input
larger than 4096 bytes before interpreting it. Encoders must also reject an
encoding over 4096 bytes.

The schema is bounded well below the budget. With every identifier at its
128-byte maximum, every uint64 at `2^64 - 1`, the deadline at `2^63 - 1`, and
both digests present:

- six identifiers: `6 * 128 = 768` bytes
- four uint64 maxima: `4 * 20 = 80` digits
- deadline: `19` digits
- two 32-byte digests: `2 * 43 = 86` characters
- fixed member names, constants, quotes, commas, colons, and braces: `306` bytes

The maximum legal encoding is therefore **1259 bytes**, leaving 2837 bytes of
headroom under the 4096-byte budget. The package tests construct exactly this
maximum-sized context, confirm the 1259-byte encoded length, and round-trip it.
An input of 4096 valid bytes plus any trailing byte is rejected.

## Synthetic canonical vector

This vector is synthetic. It is not a real pairing, request, device, member,
vault, policy, authorization, or signature. The request digest is the
deterministic bytes `0x00` through `0x1f`; the policy digest is the
deterministic bytes `0x1f` down to `0x00`.

```json
{"format":"locklark.remote-unlock","version":1,"kind":"channel-binding-context","request_id":"req-0001","request_digest":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8","pair_id":"pair-0001","pair_generation":0,"lock_generation":1,"member_id":"member-0001","source_device_id":"device-source","target_device_id":"device-target","vault_id":"vault-0001","key_epoch":7,"policy_seq":0,"policy_digest":"Hx4dHBsaGRgXFhUUExIREA8ODQwLCgkIBwYFBAMCAQA","deadline_unix_ms":1800000000000}
```

The same 473 bytes appear as a literal in the package tests. They encode a
context with explicit genesis zeroes for `pair_generation` and `policy_seq`, a
valid `key_epoch` of 7, and the supplied deadline `1800000000000` unchanged.
Encoding must produce these bytes, parsing them must reproduce the same field
values, and parsing then re-encoding must reproduce the identical bytes.

## Rejected spellings

Parsing rejects, among other things:

- missing, unknown, duplicate, or reordered members;
- a non-object top level, wrong member types, wrong constants or version;
- leading or trailing whitespace, trailing data, a second JSON value, missing
  commas or colons, and missing braces;
- invalid UTF-8, JSON escapes, and any other non-canonical string spelling;
- integer signs, leading zeros, fractions, exponents, and overflow;
- `key_epoch` zero, and a zero, negative, or overflowing deadline;
- empty, over-128-byte, uppercase, non-ASCII, or wrongly punctuated identifiers;
- digests with the wrong size, padding, the standard base64 alphabet, or
  non-canonical trailing bits;
- input larger than 4096 bytes;
- any spelling that parses to values that do not canonically re-encode to the
  identical input bytes.

Errors identify the failing member or structural rule with a static message;
they never include a field value or digest bytes.

## Stable device transport binding v1

`DeviceTransportBinding` is a second, independent canonical object. It is the
stable per-device claim that a member's device belongs to a vault and holds a
particular delivery recipient. It is signed once by a caller-pinned device
signing key and is not tied to one request. It intentionally contains no
request ID or request digest, no deadline, no key epoch, no policy sequence or
digest, and no lock generation. Those belong to a `ChannelBindingContext` and
to the owner-root authorization
([Owner-root authorization v1](#owner-root-authorization-v1)), which references
each endpoint binding by digest over its complete signed bytes.

### Binding schema

| # | Member | Type | Constraint |
|---|--------|------|------------|
| 1 | `format` | string | constant `locklark.remote-unlock` |
| 2 | `version` | integer | constant `1` |
| 3 | `kind` | string | constant `device-transport-binding` |
| 4 | `member_id` | string | identifier |
| 5 | `device_id` | string | identifier |
| 6 | `install_id` | string | identifier |
| 7 | `vault_id` | string | identifier |
| 8 | `pair_generation` | unsigned integer | uint64; `0` is explicit genesis |
| 9 | `spki_sha256` | string | exactly 32 bytes, unpadded base64url |
| 10 | `recipient_public_key` | string | canonical age X25519 recipient |
| 11 | `signature` | string | exactly 64 bytes, unpadded base64url |

Identifiers reuse the [identifier grammar](#identifier-grammar): non-empty,
at most 128 bytes, and only ASCII `a`-`z`, `0`-`9`, `.`, `_`, `:` or `-`.
Integer, digest, canonical-string, size-budget, and all-or-nothing parsing rules
are the same as for the context, except that the binding budget is 2048 bytes
(`MaxBindingSize`). The maximum legal binding, with four 128-byte identifiers,
`pair_generation` = `2^64 - 1`, a 32-byte digest, a canonical recipient and a
64-byte signature, is **941 bytes**, leaving 1107 bytes of headroom.

`spki_sha256` is the SHA-256 digest of the DER SubjectPublicKeyInfo (SPKI) of
the device certificate bound to the device's live channel. The codec neither
computes nor compares that digest; a verifier must compare it to the actual
pinned peer certificate. `recipient_public_key` is the canonical lowercase age
X25519 recipient string (`age1...`) the device claims as its delivery
recipient; the codec does not prove that the device holds the matching
identity. `pair_generation` is assigned exactly as parsed, including `0`.

### Signature domain and preimage

The Ed25519 signature is over the following bytes, with no length prefix and no
newline:

```
locklark.remote-unlock/v1/device-transport-binding\x00
```

followed immediately by the canonical JSON object containing members 1 through
10 in the order above and **without** the `signature` member. The `\x00` is one
literal NUL byte. `SigningBytes` returns exactly this preimage; the package
never stores or derives a private key and provides no production signing helper.
A caller signs the preimage with the existing protected enrolled device key and
calls `VerifyDeviceTransportBinding` with the public key it pinned from
authenticated vault policy.

### Verification boundary

- `VerifyDeviceTransportBinding(b, expectedDeviceID, pinnedKey)` requires the
  expected device identifier to equal `b.DeviceID` exactly, the pinned key to
  be exactly one Ed25519 public key, and the signature to verify. It does not
  pin the key itself.
- `VerifyDeviceTransportBindingForContext(b, c, expectedDeviceID, pinnedKey)`
  performs the check above and additionally requires the context to be
  canonical-valid, `b.MemberID`, `b.VaultID`, and `b.PairGeneration` to equal
  the context values, the context's two device endpoints to differ, and
  `b.DeviceID` to equal exactly one of them. It does not authenticate the
  context, its digests, its deadline, or the channel.
- Both functions return `ErrInvalidBinding`, and parsing returns
  `ErrInvalidBindingEncoding`; a `BindingFieldError` names the failing member
  without echoing its value.

### Synthetic binding vector

This vector is synthetic and uses the deterministic Ed25519 seed
`0x00`-`0x1f`. Its signature is real Ed25519 output over the documented
preimage, but the key belongs to no device, member, vault, pairing, certificate
or enrollment. The SPKI digest is the bytes `0x00` through `0x1f` and the
recipient is a throwaway synthetic age recipient.

```json
{"format":"locklark.remote-unlock","version":1,"kind":"device-transport-binding","member_id":"member-0001","device_id":"device-source","install_id":"install-0001","vault_id":"vault-0001","pair_generation":7,"spki_sha256":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8","recipient_public_key":"age12avp6cfclu3g432g8lhp6hyyhd5q78qjntxafudl2wnusnnprdwsqfy4ea","signature":"OhqXB70VKmxXIWcwdyZBA3vG6bt-7rc4angFC08DnXkFEF5wPEdt5JfImkRNMQEfc2PeficV4CDzBt40qbsFCg"}
```

The matching public key is the unpadded base64url string
`A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg`, and the signed JSON without
`signature` is the prefix of the vector above through
`"recipient_public_key":"age12..."`. Encoding must produce these bytes; parsing
must reproduce the fields (including `pair_generation` = 7); and the fixed
signature must verify with that key. Tests also mutate every signed member,
the signature, the pinned key and the expected device ID, and cross-check
member, device, vault and pair generation against a context.

### Explicit non-authorization limits

A valid synthetic signature, by itself, does **not** prove or grant any of the
following, and this checkpoint must not be cited as doing so:

- enrollment of the device, member, install, or vault;
- provenance or trust of the pinned key, or that it belongs to the claimed
  member/device;
- that `spki_sha256` matches the live TLS channel's peer certificate;
- owner or admin `remote_unlock` authorization;
- pairing approval or pairing state;
- request freshness, one-shot consumption, or authenticity of the context;
- access to a vault unlock key (VUK), or delivery of any key material;
- a complete mobile unlock flow.

Those properties require separate authenticated policy lookup, channel binding,
authorization, pairing, replay and VUK controls outside this package.

### Peer binding over an established channel

`internal/remoteunlocktls.Channel` adds one explicit check,
`VerifyPeerDeviceTransportBinding(binding, c, expectedDeviceID, callerPinnedKey)`.
It does not change the wire bytes above. It runs, in exactly this order:

1. `c.Check()` on the established `Channel`: a zero or uninitialized channel
   returns `ErrUninitializedChannel`, a closed one returns `ErrChannelClosed`,
   and an incomplete, non-TLS-1.3, resumed or unverified handshake, or a
   verified leaf that no longer matches the handshake pin, returns the
   corresponding `Check` error. None of the binding, context, device ID, key or
   signature is read before this passes.
2. `PeerSPKIPinOf(c.conn.ConnectionState().VerifiedChains[0][0])` — the SHA-256
   SPKI pin of the **actual verified peer leaf** — is compared with
   `binding.spki_sha256`. A mismatch returns
   `remoteunlocktls.ErrDeviceTransportBindingSPKIMismatch` before the context,
   device ID, key or signature is inspected.
3. Only then, `remoteunlock.VerifyDeviceTransportBindingForContext(binding, c,
   expectedDeviceID, callerPinnedKey)` is called, with its errors (normally
   wrapping `ErrInvalidBinding`) returned unchanged. Its member, vault, pair
   generation, endpoint and signature rules are not duplicated here.

`callerPinnedKey` is supplied independently by the caller from authenticated
state such as pinned vault policy; it is never resolved from the binding or the
channel. A nil return proves only that this already verified TLS channel's peer
certificate SPKI matches the signed `spki_sha256` and that the caller's pinned
key verifies that stable binding consistently with the context claims and the
expected device identifier. It claims none of the following: enrollment,
provenance or trust of either key, `remote_unlock` authorization, pairing
approval, request freshness, request or policy digest correctness, deadline
validity, one-shot consumption, exporter/request binding, authentication of the
context claims, VUK access or delivery, or a complete mobile unlock.

## Owner-root authorization v1

`OwnerRootAuthorization` is a third, independent canonical object. It is the
vault owner root's signature over one request: the request context, both
endpoint bindings of that request, and an absolute expiry. It supplements —
and never replaces — the context, the bindings, the TLS channel APIs, or the
vault-file policy checkpoint.

```
format, version, kind,
owner_root_key_id,
context_sha256, source_binding_sha256, target_binding_sha256,
expires_unix_ms,
signature
```

### Authorization schema

| # | Member | Type | Constraint |
|---|--------|------|------------|
| 1 | `format` | string | constant `locklark.remote-unlock` |
| 2 | `version` | integer | constant `1` |
| 3 | `kind` | string | constant `owner-authorization` |
| 4 | `owner_root_key_id` | string | identifier (non-empty, at most 128 bytes) |
| 5 | `context_sha256` | string | exactly 32 bytes, unpadded base64url |
| 6 | `source_binding_sha256` | string | exactly 32 bytes, unpadded base64url |
| 7 | `target_binding_sha256` | string | exactly 32 bytes, unpadded base64url |
| 8 | `expires_unix_ms` | integer | int64, strictly greater than zero; Unix milliseconds |
| 9 | `signature` | string | exactly 64 bytes Ed25519, unpadded base64url |

Members appear exactly once, in this order; the first eight are the signed
members. Identifier, canonical-string, integer, digest and all-or-nothing
parsing rules are those of the context. The authorization carries no request
identifier, pair, lock generation, member, device or vault identifier of its
own: those are bound through `context_sha256`, and both endpoint bindings
(each with its own device signature) through their digests.

The encoded size cap is `MaxAuthorizationSize` = 1024 bytes; input larger than
that is rejected before interpretation. With six fixed-width members, the
maximum legal encoding has a 128-byte `owner_root_key_id` and
`expires_unix_ms` = `2^63 - 1` and is **569 bytes**, well under the cap. The
canonical synthetic vector below is 450 bytes.

### Domains and preimages

Each value has its own domain label, followed immediately by one literal NUL
byte (`\x00`):

```
context_sha256        = SHA-256( "locklark.remote-unlock/v1/authorization-context\x00"
                                 || EncodeChannelBindingContext(context) )          (473-byte vector)

binding_sha256(b)     = SHA-256( "locklark.remote-unlock/v1/device-transport-binding-digest\x00"
                                 || EncodeDeviceTransportBinding(b) )               (complete bytes,
                                                                                     signature included)

signature             = Ed25519_sign( owner root key,
                        "locklark.remote-unlock/v1/owner-authorization\x00"
                        || canonical JSON of members 1..8 )
```

The binding digest covers each endpoint's **complete signed stable binding**,
signature member included, so any change to a binding, its device signature or
its recipient changes the digest. The authorization carries the digest of the
source binding in member 6 and of the target binding in member 7, in that
order; a swap is never normalized.

`pkg/remoteunlock` exports the public helpers:

- `RemoteUnlockContextDigest(c)`: `context_sha256`.
- `DeviceTransportBindingDigest(b)`: `binding_sha256(b)`.
- `AuthorizationSigningBytes(a)`: the exact signature preimage (members 1..8).
- `EncodeOwnerRootAuthorization(a)` / `ParseOwnerRootAuthorization(b)`:
  canonical encoding and strict parsing; `MarshalJSON`/`UnmarshalJSON` use them.
- `VerifyOwnerRootAuthorization(...)`: the checkpoint-scoped verifier below.

Like the binding API, the codec and signing helpers never sign and never hold,
derive or store a private key. The owner root signs the returned preimage with
its own protected Ed25519 key outside this package.

### Verification procedure and boundary

`VerifyOwnerRootAuthorization(f, checkpoint, a, c, source, target, nowUnixMS)`
returns on the first failure, in this order:

1. `nowUnixMS > 0`; the authorization, context, source binding and target
   binding are canonical-valid. **Expiry is strict**: `nowUnixMS <
   expires_unix_ms` (an authorization is expired exactly at its expiry
   instant), and `expires_unix_ms <= c.deadline_unix_ms` (an authorization may
   expire before the request does, never after). Only the caller-supplied
   `nowUnixMS` is used; there is no hidden system clock.
2. `a.context_sha256` equals `RemoteUnlockContextDigest(c)`.
3. `vaultfile.VerifyPolicyCheckpoint(f, checkpoint)` must succeed **before any
   carried policy claim is trusted**. Its error is returned wrapped with
   `ErrInvalidAuthorization`. Only then are `f.header` and the current (final)
   policy proof used.
4. `f.header.vault_id`, `key_epoch`, `policy_seq` and `policy_digest` equal the
   context exactly; `vaultfile.PolicyDigest` of the authenticated current
   policy equals both `f.header.policy_digest` and `c.policy_digest`. No
   normalization, case folding or defaulting is applied, and no carried proof
   may be newer than the context policy sequence.
5. The context's source and target devices differ, both resolve by device ID in
   the authenticated current policy, both belong to `c.member_id`, and that
   principal holds an **existing read qualification** — a reader, writer, admin
   or owner role, exactly the vault file's role semantics (any one of the four
   implies read). This is read qualification only: it grants no author role and
   never elevates or rewrites a role. Each device's canonical policy
   `age_encryption_key` must equal the matching binding's
   `recipient_public_key`.
6. Each binding verifies with `VerifyDeviceTransportBindingForContext` against
   the **exact device's authenticated `content_signing_key.public_key`** and the
   expected device ID, and the digest of the source binding then the digest of
   the target binding equal members 6 and 7.
7. `a.owner_root_key_id` equals `checkpoint.OwnerRootKeyID` (and the
   authenticated policy's root key ID), and the signature verifies **only**
   under the caller-pinned `checkpoint.OwnerRootPublicKey` — never a key carried
   in the authorization object or in the current file.

The owner root is the **sole issuer** accepted here. There is no admin,
reader, device or delegation path, no permission flag and no role change.

A nil return proves only that the owner root that owns the caller's checkpoint
issued this authorization for this request context, these two signed stable
bindings of the checkpoint-authenticated current policy, before the expiry and
the request deadline. It does **not** prove:

- the `request_digest` preimage or any request-content semantics;
- the actual TLS exporter value, handshake, or that the channel equals the
  context (that is the channel binding's own check);
- that the live peer's SPKI matches `spki_sha256` (the internal TLS adapter's
  separate check);
- that either device holds its private key or recipient identity (real device
  identity or enrollment);
- one-shot use, restart safety, or anti-rollback (no durable replay defense);
- VUK decryption, wrapping or delivery, or a complete mobile unlock.

`VerifyPolicyCheckpoint` remains the authority for the content author role and
for policy mutation, which this verifier never performs. A reader can read the
file but cannot author it: `vaultfile` rejects a current file whose author is a
reader-only device, and owner-root authorization fails closed on such a file.

### Synthetic authorization vector

All keys, identities, policies and file bytes are synthetic; the Ed25519 keys
come from the declared deterministic seed spans and every signature is real
output over the documented preimages, but none belongs to a production root,
device, member or vault.

Context: the 473-byte context vector above, whose digest is

```
context_sha256        = SFXeSJjOvMsmXh3eaNefOt_JDkO1JhrUTS6CnEabzyU
```

Bindings: the source and target vectors of
[Synthetic binding vector](#synthetic-binding-vector) (`pair_generation` 0,
signed by the synthetic source and target device keys):

```
source_binding_sha256 = H8uXANZqikFmCmZPEJo8AWtzmBn3xPH4D1wVj5rez_U
target_binding_sha256 = yHvjY7BX-EVeru1GBSe5EBd4xIlk0dHfAjK8DFYBRKM
```

Signed JSON (members 1..8), followed immediately by the domain
`locklark.remote-unlock/v1/owner-authorization\x00` and nothing else:

```json
{"format":"locklark.remote-unlock","version":1,"kind":"owner-authorization","owner_root_key_id":"owner-root-0001","context_sha256":"SFXeSJjOvMsmXh3eaNefOt_JDkO1JhrUTS6CnEabzyU","source_binding_sha256":"H8uXANZqikFmCmZPEJo8AWtzmBn3xPH4D1wVj5rez_U","target_binding_sha256":"yHvjY7BX-EVeru1GBSe5EBd4xIlk0dHfAjK8DFYBRKM","expires_unix_ms":1799999999000}
```

The synthetic owner-root public key is the unpadded base64url string
`Kay64UG8yvCyLhqU000LxzYeUm0L_hlLIl5S8kyKWbdc`; the fixed signature over the
preimage is `uo_poPoCLDqh7YE2gdpH8reRMVu7uDpHJ4sq3EMZVorh8kY04hFDfLpPrHEyDYK0tWZCPCPGogc-LwYFG0jeAw`.
The complete canonical authorization is 450 bytes:

```json
{"format":"locklark.remote-unlock","version":1,"kind":"owner-authorization","owner_root_key_id":"owner-root-0001","context_sha256":"SFXeSJjOvMsmXh3eaNefOt_JDkO1JhrUTS6CnEabzyU","source_binding_sha256":"H8uXANZqikFmCmZPEJo8AWtzmBn3xPH4D1wVj5rez_U","target_binding_sha256":"yHvjY7BX-EVeru1GBSe5EBd4xIlk0dHfAjK8DFYBRKM","expires_unix_ms":1799999999000,"signature":"uo_poPoCLDqh7YE2gdpH8reRMVu7uDpHJ4sq3EMZVorh8kY04hFDfLpPrHEyDYK0tWZCPCPGogc-LwYFG0jeAw"}
```

These bytes are pinned literally in the package tests, which also recompute
every digest and signature from the declared seeds, and verify them.

### Rejected spellings

Parsing an authorization rejects missing, unknown, duplicate and reordered
members; wrong constants, types and versions; surrounding whitespace, trailing
data and malformed structure; invalid UTF-8 and JSON escapes; integer signs,
leading zeros, fractions, exponents, a zero or overflowing `expires_unix_ms`;
identifiers that break the grammar; digests of the wrong size, padded, in the
standard base64 alphabet or with non-canonical trailing bits; signatures of the
wrong size or spelling; input over 1024 bytes; and any spelling that does not
re-encode to the identical bytes. Errors name the failing member with a static
message and never include a value, key or signature byte.

## Reusable owner-root admin delegation v1

`OwnerRootAdminRemoteUnlockDelegation` is an **independent** canonical object,
not a per-request authorization. The vault owner root signs it **once** to
delegate remote-unlock scope to one named current admin or owner device for one
named requester's stable endpoints. The same signed grant covers any number of
unlock requests until its explicit expiry, provided the vault's authenticated
**current policy is still exactly the policy it was issued against**.

It deliberately carries **no** `request_id`, `request_digest`,
`lock_generation` or request `deadline_unix_ms`. A per-request authorization
for a concrete request is the separate, later
[per-request admin authorization](#per-request-admin-remote-unlock-authorization-v1):
the delegated device signs it fresh, it references this grant by
`AdminDelegationDigest`, and it verifies the request's own context and
bindings.

```
format, version, kind,
owner_root_key_id, delegate_member_id, delegate_device_id,
delegate_policy_signing_key, vault_id, requester_member_id,
source_device_id, target_device_id,
source_binding_sha256, target_binding_sha256,
pair_generation, key_epoch, policy_seq, policy_digest,
not_before_unix_ms, expires_unix_ms,
signature
```

### Delegation schema

| # | Member | Type | Constraint |
|---|--------|------|------------|
| 1 | `format` | string | constant `locklark.remote-unlock` |
| 2 | `version` | integer | constant `1` |
| 3 | `kind` | string | constant `owner-admin-delegation` |
| 4 | `owner_root_key_id` | string | identifier |
| 5 | `delegate_member_id` | string | identifier; delegated current policy principal |
| 6 | `delegate_device_id` | string | identifier; delegated current policy device |
| 7 | `delegate_policy_signing_key` | string | exactly 32 bytes Ed25519, unpadded base64url |
| 8 | `vault_id` | string | identifier |
| 9 | `requester_member_id` | string | identifier; must hold an existing read role |
| 10 | `source_device_id` | string | identifier |
| 11 | `target_device_id` | string | identifier; must differ from member 10 |
| 12 | `source_binding_sha256` | string | exactly 32 bytes, unpadded base64url |
| 13 | `target_binding_sha256` | string | exactly 32 bytes, unpadded base64url |
| 14 | `pair_generation` | unsigned integer | uint64; `0` is explicit genesis |
| 15 | `key_epoch` | unsigned integer | uint64, strictly greater than zero |
| 16 | `policy_seq` | unsigned integer | uint64; the current-policy grant anchor |
| 17 | `policy_digest` | string | exactly 32 bytes, the exact current policy digest |
| 18 | `not_before_unix_ms` | integer | int64, strictly greater than zero |
| 19 | `expires_unix_ms` | integer | int64, strictly greater than member 18 |
| 20 | `signature` | string | exactly 64 bytes Ed25519, unpadded base64url |

Members appear exactly once, in this order; members 1..19 are signed.
Identifier, canonical-string, integer, digest and all-or-nothing parsing rules
are those of the context. `delegate_policy_signing_key` is a fixed-width
32-byte key, and members 12, 13 and 17 are 32-byte digests.

`source_binding_sha256` and `target_binding_sha256` are
`DeviceTransportBindingDigest` of the **complete signed** source and target
bindings, signature included. Each pair of endpoint identifiers must be
distinct. The grant records this scope only: the verifier in this checkpoint
does not read or verify any binding.

The encoded size cap is `MaxAdminDelegationSize` = 2048 bytes; larger input is
rejected before interpretation. With seven 128-byte identifiers, three
uint64 maxima, `not_before_unix_ms` = 1 and `expires_unix_ms` = `2^63 - 1`, the
maximum legal encoding is **1675 bytes**, well under the cap. The canonical
synthetic vector below is 810 bytes.

### Delegation domain and preimage

The owner root signs the following bytes, with no length prefix and no
newline:

```
locklark.remote-unlock/v1/admin-delegation\x00
```

followed immediately by the canonical JSON object containing members 1 through
19 in order and **without** the `signature` member. The `\x00` is one literal
NUL byte. `AdminDelegationSigningBytes` returns exactly this preimage.

The domain is distinct from the owner-root authorization domain
(`locklark.remote-unlock/v1/owner-authorization\x00`) and from the device
binding domain (`locklark.remote-unlock/v1/device-transport-binding\x00`); a
signature made for one never verifies for another.

`AdminDelegationDigest` returns `SHA-256` of the separate domain
`locklark.remote-unlock/v1/admin-delegation-digest\x00` followed by the complete
canonical encoding of the delegation, `signature` member included, so any
change to a claim or to the signature changes the digest. It is a stable
reference for a later signed request, not a signature and not an
authorization.

### Current-policy anchor and invalidation

The delegation pins the current policy by both `policy_seq` and
`policy_digest`, together with `vault_id` and `key_epoch`. The verifier
requires the authenticated current policy, and the file header, to match them
exactly. Consequently:

- **Any policy update invalidates the delegation.** Adding or removing a
  member or device, changing a role, rotating any key, changing a delegation,
  or advancing the policy sequence changes the policy digest. The old grant
  simply stops verifying, and the owner root must issue a new one.
- A later policy can never revive a removed, demoted or re-added delegate or
  requester endpoint under an earlier grant. There is no lookup of, or fallback
  to, an older proof; only the last carried, checkpoint-authenticated policy is
  read.
- The grant is reusable only within the same policy and the same validity
  interval. It is not a durable permission across policy transitions, and it
  cannot be re-anchored by a non-root party.

### Verification procedure and boundary

`VerifyOwnerRootAdminRemoteUnlockDelegation(f, checkpoint, d, nowUnixMS)`
returns on the first failure, in this order:

1. `nowUnixMS > 0`; the delegation is canonical-valid, including a positive
   `key_epoch`, a distinct source and target, and
   `not_before_unix_ms < expires_unix_ms`.
2. `d.not_before_unix_ms <= nowUnixMS < d.expires_unix_ms`. The interval is
   **inclusive at its start and exclusive at its end**, and only the
   caller-supplied `nowUnixMS` is used; there is no hidden system clock.
3. `vaultfile.VerifyPolicyCheckpoint(f, checkpoint)` must succeed **before any
   carried policy claim is trusted**; its error is returned wrapped with
   `ErrInvalidAdminDelegation`.
4. The authenticated current policy is the **exact anchor**: the file header and
   the last carried policy must match the grant's `vault_id`, `key_epoch`,
   `policy_seq` and `policy_digest`, and `vaultfile.PolicyDigest` of that policy
   must equal the grant digest. Any other policy fails.
5. `d.owner_root_key_id` equals the caller-pinned checkpoint root key ID and
   the authenticated policy root key ID and algorithm, and the checkpoint root
   public key equals the authenticated policy root public key.
6. The delegate device resolves by ID in the authenticated current policy, its
   `principal_id` equals `delegate_member_id`, that principal currently holds
   the **admin or owner** role (a reader- or writer-only principal is
   rejected), and that exact device carries a non-nil Ed25519
   `policy_signing_key` whose bytes equal `delegate_policy_signing_key`.
7. `requester_member_id` holds an existing read role (reader, writer, admin or
   owner, by the vault file's role order), and `source_device_id` and
   `target_device_id` both resolve in the authenticated policy and belong to
   that requester.
8. The owner-root signature verifies under exactly
   `checkpoint.OwnerRootPublicKey` over the delegation preimage.

No role is asserted by the caller, read from an unauthenticated or older proof,
synthesized, or mutated. `vaultfile.AdminDelegation` is **not** interpreted as
remote-unlock authority; no vaultfile byte, type or schema changes here.

A nil return proves only that the caller-pinned owner root issued this reusable
scope for this exact policy anchor and validity interval, and that the
authenticated current policy still lists the delegate, its policy key, the
requester's read role and both scoped endpoints as required. It does **not**
authorize a concrete request, and it does **not** verify a request binding. In
particular it does not prove:

- that any request's bindings match members 12 and 13, or that those bindings
  have valid device signatures or the policy recipient keys — that is the
  [per-request admin authorization](#per-request-admin-remote-unlock-authorization-v1)
  verifier's job;
- the `request_digest` preimage, request freshness, or one-shot use;
- the actual TLS exporter value, handshake, or the live peer's SPKI (the
  internal TLS adapter's separate check);
- that either device holds its private keys, or real device identity and
  enrollment;
- durable replay defense, restart safety, or policy-history continuity beyond
  the checkpoint;
- VUK decryption, wrapping or delivery, or a complete mobile unlock.

### Synthetic delegation vector

All keys, identities, policies and file bytes are synthetic; the Ed25519 keys
come from declared deterministic seed spans and every signature is real output
over the documented preimage, but none belongs to a production root, device,
member or vault. The fixture's current policy is at `policy_seq` 2, its
`policy_digest` is below, the requester is `member-0001` with the fixed
`device-source` and `device-target` bindings, and the delegate is `carol` on
`device-outsider` with the synthetic policy signing key shown.

```
policy_digest         = j5HDbfdIdI5sDh0y6NAxn7XZ6vPiGNXlZefjJ9dV4vY
delegate_policy_key   = bw8O6z-_-SXGbQPhnc5I1e3J_-5RzSaucd055W9_3aI
source_binding_sha256 = H8uXANZqikFmCmZPEJo8AWtzmBn3xPH4D1wVj5rez_U
target_binding_sha256 = yHvjY7BX-EVeru1GBSe5EBd4xIlk0dHfAjK8DFYBRKM
```

Signed JSON (members 1..19), followed immediately by the domain
`locklark.remote-unlock/v1/admin-delegation\x00` and nothing else:

```json
{"format":"locklark.remote-unlock","version":1,"kind":"owner-admin-delegation","owner_root_key_id":"owner-root-0001","delegate_member_id":"carol","delegate_device_id":"device-outsider","delegate_policy_signing_key":"bw8O6z-_-SXGbQPhnc5I1e3J_-5RzSaucd055W9_3aI","vault_id":"vault-0001","requester_member_id":"member-0001","source_device_id":"device-source","target_device_id":"device-target","source_binding_sha256":"H8uXANZqikFmCmZPEJo8AWtzmBn3xPH4D1wVj5rez_U","target_binding_sha256":"yHvjY7BX-EVeru1GBSe5EBd4xIlk0dHfAjK8DFYBRKM","pair_generation":0,"key_epoch":7,"policy_seq":2,"policy_digest":"j5HDbfdIdI5sDh0y6NAxn7XZ6vPiGNXlZefjJ9dV4vY","not_before_unix_ms":1799999900000,"expires_unix_ms":1800000001000}
```

The synthetic owner-root public key is
`Kay64UG8yvCyLhqU000LxzYeUm0L_hlLIl5S8kyKWbdc`; the complete canonical
delegation is 810 bytes:

```json
{"format":"locklark.remote-unlock","version":1,"kind":"owner-admin-delegation","owner_root_key_id":"owner-root-0001","delegate_member_id":"carol","delegate_device_id":"device-outsider","delegate_policy_signing_key":"bw8O6z-_-SXGbQPhnc5I1e3J_-5RzSaucd055W9_3aI","vault_id":"vault-0001","requester_member_id":"member-0001","source_device_id":"device-source","target_device_id":"device-target","source_binding_sha256":"H8uXANZqikFmCmZPEJo8AWtzmBn3xPH4D1wVj5rez_U","target_binding_sha256":"yHvjY7BX-EVeru1GBSe5EBd4xIlk0dHfAjK8DFYBRKM","pair_generation":0,"key_epoch":7,"policy_seq":2,"policy_digest":"j5HDbfdIdI5sDh0y6NAxn7XZ6vPiGNXlZefjJ9dV4vY","not_before_unix_ms":1799999900000,"expires_unix_ms":1800000001000,"signature":"7zsUu-9zDLf7LNOMKpGFBk1tqhqZgctUzNBQFFd6S4A8GO2-WAUpRKwXSx_ejkkxI7Snk3fmSa9Qymz1n90UDg"}
```

`AdminDelegationDigest` of that complete encoding is
`BqJKqhv9FaINZWmGD_eRraFGFosPn6ZfocLgr0mZZZU`.

These bytes are pinned literally in the package tests, which recompute the
preimage, signature and digest from the declared seeds and verify them against
a real synthetic vault file authored by an independent writer.

### Rejected delegation spellings

Parsing a delegation rejects missing, unknown, duplicate and reordered members;
any per-request member such as `request_id`, `request_digest`, `lock_generation`
or `deadline_unix_ms`; wrong constants, types and versions; surrounding
whitespace, trailing data and malformed structure; invalid UTF-8 and JSON
escapes; integer signs, leading zeros, fractions, exponents and overflow; a zero
`key_epoch`; a zero, negative or overflowing timestamp; an expiry at or before
`not_before_unix_ms`; a `delegate_policy_signing_key` of the wrong size or
spelling; identifiers that break the grammar; digests of the wrong size, padded,
in the standard base64 alphabet or with non-canonical trailing bits; a signature
of the wrong size or spelling; input over 2048 bytes; and any spelling that does
not re-encode to the identical bytes. Errors name the failing member with a
static message and never include a value, key, digest or signature byte.

## Per-request admin remote-unlock authorization v1

`AdminRemoteUnlockAuthorization` is the canonical per-request object that
composes the [reusable admin
delegation](#reusable-owner-root-admin-delegation-v1). The **delegated admin
device**, not the owner root, signs a fresh authorization for every request,
with the exact `delegate_policy_signing_key` named by the grant. The owner root
signs the reusable grant exactly once and signs no per-request object; a request
never needs a new owner-root signature or a new root contact.

The authorization binds the grant by `delegation_digest`, the **full** fresh
`ChannelBindingContext` by `context_sha256`, the complete signed source and
target bindings by their device binding digests, and one explicit
`expires_unix_ms`. It carries no request identifier, request digest, lock
generation, deadline, member, device, vault, epoch or policy member of its own:
all of those are bound through `context_sha256` and checked against the grant
scope by the verifier.

```
format, version, kind,
delegation_digest, context_sha256,
source_binding_sha256, target_binding_sha256,
expires_unix_ms,
signature
```

### Authorization schema

| # | Member | Type | Constraint |
|---|--------|------|------------|
| 1 | `format` | string | constant `locklark.remote-unlock` |
| 2 | `version` | integer | constant `1` |
| 3 | `kind` | string | constant `admin-authorization` |
| 4 | `delegation_digest` | string | exactly 32 bytes: `AdminDelegationDigest` of the reusable grant |
| 5 | `context_sha256` | string | exactly 32 bytes: `RemoteUnlockContextDigest` of the full request context |
| 6 | `source_binding_sha256` | string | exactly 32 bytes: `DeviceTransportBindingDigest` of the source binding |
| 7 | `target_binding_sha256` | string | exactly 32 bytes: `DeviceTransportBindingDigest` of the target binding |
| 8 | `expires_unix_ms` | integer | int64, strictly greater than zero; exclusive end |
| 9 | `signature` | string | exactly 64 bytes Ed25519, unpadded base64url |

Members appear exactly once, in this order; members 1..8 are signed. Identifier,
canonical-string, integer, digest and all-or-nothing parsing rules are those of
the context. Members 4 through 7 are fixed-width 32-byte digests and the
signature is fixed at 64 bytes, so the only variable-width signed member is
`expires_unix_ms`.

The encoded size cap is `MaxAdminAuthorizationSize` = 1024 bytes; larger input
is rejected before interpretation. With `expires_unix_ms` = `2^63 - 1` the
maximum legal encoding is **484 bytes**; the canonical synthetic vector below is
478 bytes.

### Authorization domain and preimage

The delegated admin device signs the following bytes, with no length prefix and
no newline:

```
locklark.remote-unlock/v1/admin-authorization\x00
```

followed immediately by the canonical JSON object containing members 1 through
8 in order and **without** the `signature` member. The `\x00` is one literal
NUL byte. `AdminAuthorizationSigningBytes` returns exactly this preimage.

The domain is distinct from every other remote-unlock domain: the owner-root
authorization domain (`locklark.remote-unlock/v1/owner-authorization\x00`), the
owner-root delegation domain (`locklark.remote-unlock/v1/admin-delegation\x00`),
the device binding domain
(`locklark.remote-unlock/v1/device-transport-binding\x00`), the context digest
domain and both digest domains. A signature made for one never verifies for
another, and the tests assert the domains are pairwise distinct.

### Composed verification procedure and boundary

`VerifyAdminRemoteUnlockAuthorization(f, checkpoint, d, a, c, source, target,
nowUnixMS)` is the only verifier of this object. It returns on the first
failure, in this order:

1. `nowUnixMS > 0`; `a` and `c` are canonical-valid and both bindings validate.
2. `nowUnixMS < a.expires_unix_ms` (an authorization is expired at exactly its
   expiry instant) and `a.expires_unix_ms <= c.deadline_unix_ms`. Only the
   caller-supplied clock is used; the verifier reads no system clock.
3. `a.context_sha256 == RemoteUnlockContextDigest(c)` and
   `a.delegation_digest == AdminDelegationDigest(d)`.
4. `VerifyOwnerRootAdminRemoteUnlockDelegation(f, checkpoint, d, nowUnixMS)`
   succeeds. This is the composition point: the reusable grant is checked
   against the actual authenticated current policy and its
   `[not_before_unix_ms, expires_unix_ms)` interval, and its owner-root
   signature is verified with the caller-pinned root. Its error is returned
   wrapped with `ErrInvalidAdminAuthorization`.
5. `a.expires_unix_ms <= d.expires_unix_ms`; the request authorization may never
   outlive the grant.
6. The context is exactly in the grant scope: `vault_id`, `member_id`,
   `source_device_id`, `target_device_id`, `pair_generation`, `key_epoch`,
   `policy_seq` and `policy_digest` all equal the grant's corresponding members.
   The requester must be the grant's requester, and neither endpoint may be
   swapped.
7. In the authenticated current policy, the delegate device resolves with
   exactly `delegate_member_id` as its principal, that principal currently holds
   the **admin or owner** role, and the device carries a non-nil Ed25519
   `policy_signing_key` byte-identical to `delegate_policy_signing_key`. Both
   scoped endpoint devices resolve to the requester and carry an Ed25519
   content signing key. No role is asserted by the caller or changed.
8. Each binding's `recipient_public_key` equals that device's authenticated
   policy age encryption key, and each binding verifies with
   `VerifyDeviceTransportBindingForContext` under that device's authenticated
   content signing key: source first, then target.
9. The complete-binding digests are computed in source-then-target order and
   each must equal both the matching authorization member and the matching
   digest recorded in the grant.
10. `a.signature` verifies under exactly the delegate device's current
    non-nil Ed25519 policy signing key over the authorization preimage. A
    content signing key, any other device key and the owner root key are never
    accepted for this signature.

A nil return proves only that the reusable grant is currently valid, and that
its delegated admin or owner device signed this exact request context and these
two signed bindings within the authorization expiry, the request deadline and
the grant interval. It does **not** prove:

- the `request_digest` preimage, request freshness, or one-shot use;
- the actual TLS exporter value, handshake, or the live peer's SPKI (the
  internal TLS adapter's separate check);
- that either device holds its private keys, or real device identity and
  enrollment, or any production identity;
- any VUK decryption, wrapping or delivery, or relay or mobile behavior;
- durable replay defense, restart safety, or policy-history continuity beyond
  the checkpoint.

This verifier is **state-free**: the same valid authorization verifies again,
before and after a restart, until it expires. It keeps no consumed-request set
and offers no durable replay or one-shot guarantee. The caller's request
lifecycle (see [Process-local request
lifecycle](#process-local-request-lifecycle)) must prevent replay and one-shot
use by issuing fresh request state and consuming it locally. The reusable grant
is unchanged and remains free of `request_id`, `request_digest`,
`lock_generation` and any request deadline; no PC role is changed and no
vaultfile byte, type or schema changes here.

### Synthetic admin authorization vector

All keys, identities, policies and file bytes are synthetic; the Ed25519 keys
come from declared deterministic seed spans and every signature is real output
over the documented preimage, but none belongs to a production root, device,
member or vault. The vector composes the fixed [synthetic delegation
vector](#synthetic-delegation-vector) and the fixed request context and
bindings, and is signed by the delegated admin device `device-outsider` with its
policy signing key (seed span `0xd0`), not by the owner root (seed span `0x20`).

```
delegation_digest     = BqJKqhv9FaINZWmGD_eRraFGFosPn6ZfocLgr0mZZZU
context_sha256        = SFXeSJjOvMsmXh3eaNefOt_JDkO1JhrUTS6CnEabzyU
source_binding_sha256 = H8uXANZqikFmCmZPEJo8AWtzmBn3xPH4D1wVj5rez_U
target_binding_sha256 = yHvjY7BX-EVeru1GBSe5EBd4xIlk0dHfAjK8DFYBRKM
```

Signed JSON (members 1..8), followed immediately by the domain
`locklark.remote-unlock/v1/admin-authorization\x00` and nothing else:

```json
{"format":"locklark.remote-unlock","version":1,"kind":"admin-authorization","delegation_digest":"BqJKqhv9FaINZWmGD_eRraFGFosPn6ZfocLgr0mZZZU","context_sha256":"SFXeSJjOvMsmXh3eaNefOt_JDkO1JhrUTS6CnEabzyU","source_binding_sha256":"H8uXANZqikFmCmZPEJo8AWtzmBn3xPH4D1wVj5rez_U","target_binding_sha256":"yHvjY7BX-EVeru1GBSe5EBd4xIlk0dHfAjK8DFYBRKM","expires_unix_ms":1799999999000}
```

The complete canonical authorization is 478 bytes:

```json
{"format":"locklark.remote-unlock","version":1,"kind":"admin-authorization","delegation_digest":"BqJKqhv9FaINZWmGD_eRraFGFosPn6ZfocLgr0mZZZU","context_sha256":"SFXeSJjOvMsmXh3eaNefOt_JDkO1JhrUTS6CnEabzyU","source_binding_sha256":"H8uXANZqikFmCmZPEJo8AWtzmBn3xPH4D1wVj5rez_U","target_binding_sha256":"yHvjY7BX-EVeru1GBSe5EBd4xIlk0dHfAjK8DFYBRKM","expires_unix_ms":1799999999000,"signature":"TfY7H33nPo2v_xpNmd8kbIFtbsuc_e4sK-a6WWQS_Oaew-7Ew-uEtIxQn-_mc3Zq9PFbLJHkqATZl-xUoYxYDA"}
```

The tests pin these bytes literally, recompute the preimage and signature from
the declared seed, verify that the signature does not verify under the owner
root key or under any other domain, and require the delegated admin key to sign
at least two different request contexts under the same byte-identical grant
within its window.

### Rejected admin authorization spellings

Parsing an authorization rejects missing, unknown, duplicate and reordered
members; any foreign member such as `request_id`, `request_digest`,
`lock_generation`, `deadline_unix_ms`, `owner_root_key_id`, `member_id`,
`device_id` or `spki_sha256`; wrong constants, types and versions; surrounding
whitespace, trailing data and malformed structure; invalid UTF-8 and JSON
escapes; integer signs, leading zeros, fractions, exponents and overflow; a
zero or negative expiry; digests of the wrong size, padded, in the standard
base64 alphabet or with non-canonical trailing bits; a signature of the wrong
size or spelling; input over 1024 bytes; and any spelling that does not
re-encode to the identical bytes. Errors name the failing member with a static
message and never include a value, key, digest or signature byte.

## Process-local request lifecycle

`pkg/remoteunlock/lifecycle.go` defines `RequestLifecycle`, an in-memory status
machine for one remote unlock request. It is a local state transition primitive
and is not part of the wire format: it adds no bytes, field, frame, or message.

Statuses are frozen as the strings `requested`, `confirmed`, `received`,
`unknown`, `cancelled` and `expired` (`StatusRequested` … `StatusExpired`).

| From | Event | To |
|------|-------|----|
| `requested` | `Confirm` while the current phase is active | `confirmed` |
| `confirmed` | `Receive` while the current phase is active; consumes the request once | `received` |
| `requested`, `confirmed` | `MarkUnknown` while the current phase is active | `unknown` |
| `requested`, `confirmed` | `Cancel` while the current phase is active | `cancelled` |
| `requested`, `confirmed` | any observation at or after the current phase deadline or the absolute deadline | `expired` |

`received`, `unknown`, `cancelled` and `expired` are terminal and never
transition again. A received request cannot be retroactively cancelled, and an
expired lifecycle cannot confirm, receive, be marked unknown or be cancelled.
Rejected transitions return a static `ErrLifecycleTransition` error.

### Timing

All timing uses caller-supplied Unix-millisecond values. The lifecycle never
reads the system clock, normalizes time, or waits.

- The default overall request TTL is `DefaultRequestTTLMS` = `120000` ms (two
  minutes). `DefaultRequestDeadlineUnixMS(nowUnixMS)` returns
  `nowUnixMS + 120000`; it rejects a non-positive `nowUnixMS` and any sum that
  overflows `int64`. The helper only computes a value; it does not clamp or
  rewrite a context.
- The maximum length of each active phase is `MaxActivePhaseMS` = `30000` ms.
- The constructor requires a positive `nowUnixMS` and a context that the
  canonical codec accepts whose `deadline_unix_ms` is strictly after
  `nowUnixMS`. The context is stored unchanged; its deadline is never clamped,
  extended, or rewritten.
- The active phase deadline is
  `min(nowUnixMS + MaxActivePhaseMS, deadline_unix_ms)` and is recalculated as
  `min(confirmUnixMS + MaxActivePhaseMS, deadline_unix_ms)` on
  `requested -> confirmed`.
- A lifecycle whose active phase is not yet terminal expires at
  `nowUnixMS >= phaseDeadline`. Because the phase deadline is already bounded
  by the absolute context deadline, this is the earlier of the two. Expiry is
  latched by `StatusAt` or by the first attempted transition at or after the
  boundary; all methods apply the same check under the mutex.
- Caller-supplied times must be non-decreasing within the same in-memory
  instance. The constructor records its `nowUnixMS` as the last accepted time,
  and every later call (`StatusAt`, `Confirm`, `Receive`, `MarkUnknown`,
  `Cancel`) rejects a non-positive time, or a time lower than the last accepted
  time, with `ErrLifecycleInvalidTime` before changing the status or a phase
  deadline. Equal timestamps are valid. A rejected call leaves the instance
  exactly as it was; an accepted call records its time as the new last accepted
  time.
- `StatusAt` with an invalid or rolled-back time returns an empty status
  together with `ErrLifecycleInvalidTime`. `StatusUnknown` is reserved for a
  genuine unknown request outcome, so an invalid clock argument is never
  reported as `unknown`.
- This rollback check is in-memory only. It is not durable replay protection
  and does not detect a whole-process snapshot rollback: an instance restored
  from an earlier snapshot, or a fresh instance after a restart, starts a new
  time sequence and does not remember earlier accepted times.

### Concurrency and state

A mutex serializes every transition, so concurrent `Receive` calls consume a
confirmed lifecycle at most once. The lifecycle holds only the binding context
claims and its status; it adds no secret payload, key buffer, or VUK bytes.

### Scope

`RequestLifecycle` is in-memory and non-restorable. It does not implement
cross-process durable replay protection and does not prove that a restart was
prevented. A fresh instance always starts in `requested` and does not recognize
any prior in-memory state; it cannot tell that an earlier instance already
received, cancelled, or expired the same request. A caller must therefore issue
fresh request state, with a fresh request identifier and digest, and rely on the
existing real TLS exporter/channel binding to reject old channel-bound packets.

The lifecycle verifies no identity, signature, pairing, membership, or policy,
does not check the request digest preimage, does not contact a relay, and does
not cancel anything remotely. `Cancel` changes only local state. The lifecycle
proves no signed identity or policy, authorizes no VUK use, and delivers, stores,
or exposes no key material. A `received` status is a local bookkeeping fact, not
evidence that a VUK was authorized or delivered.

## Loopback composition smoke (test-only)

`internal/remoteunlocktls/composition_test.go` carries one isolated positive
composition checkpoint, `TestLoopbackPositiveCompositionSmoke`, and
`internal/remoteunlocktls/rejection_test.go` carries one separate, equally
narrow rejection checkpoint described below. Both are tests, not a production
integration, and they do not change any frame, byte, member or verification
rule in this document.

The test performs a real concurrent `ClientHandshake`/`ServerHandshake` over an
owned `127.0.0.1:0` loopback TCP pair, requires TLS 1.3 without resumption and
passes `Channel.Check` on both sides. It builds a synthetic but structurally
valid sealed `vaultfile.File` whose caller-pinned current `PolicyCheckpoint`
passes `vaultfile.VerifyPolicyCheckpoint`; the policy lists the requester with
its existing reader role, an admin delegate device, and the requester's source
and target endpoint devices. All owner-root, content-signing and policy-signing
Ed25519 keys and all per-device age X25519 identities are independently
generated synthetic values, and the source and target bindings carry the actual
verified peer leaf SPKIs from the live handshake.

One canonical reusable `OwnerRootAdminRemoteUnlockDelegation` is signed by the
synthetic owner root exactly once and reused byte-identically for two fresh
request contexts that differ in `request_id`, `request_digest` and
`lock_generation`. The delegated admin device's policy signing key -- not the
owner root and not its content signing key -- signs a fresh
`AdminRemoteUnlockAuthorization` for each context. Over the established channel,
the server parses the public codecs, verifies the request exporter with
`VerifyBindingContext`, verifies the source peer binding against the channel's
verified peer SPKI with the current-policy content key through
`VerifyPeerDeviceTransportBinding`, and calls
`VerifyAdminRemoteUnlockAuthorization`; the client performs the matching target
peer binding check. Both requests pass under the one root grant without a
second root signing step.

For the first request only, the server then uses `vaultfile.SealVUKForDevice`
with the source PC's policy-bound age recipient and writes exactly that bounded
ciphertext to the channel; the source PC reads it and opens it with
`vaultfile.OpenVUKForDevice` using independent expected vault, epoch,
source-device and recipient inputs and the source identity, compares all 32 VUK
bytes, and clears the caller-owned plaintext/VUK buffers. The second request
receives no VUK. The requester's process-local lifecycle moves requested →
confirmed → received on the first request, and a second local `Receive` is
rejected with `ErrLifecycleTransition` with no VUK bytes. That lifecycle is
memory-only: the test claims no restart or durable anti-rollback behavior.

The length-prefixed request, approval and VUK frames used by this test are
private test-only helpers. They are not a product wire protocol and must not be
implemented as one; the v1 production framing contract above is unchanged.

### Narrow rejection checkpoint (test-only)

`internal/remoteunlocktls/rejection_test.go` reuses the same synthetic fixture,
test-only framing helpers, real `127.0.0.1:0` mTLS harness (`runHandshakes`,
TLS 1.3, no resumption, no session tickets), canonical public codecs and public
verification APIs, with deterministic caller-supplied protocol times and bounded
I/O deadlines. It covers exactly two rejections and nothing more:

1. **Stale exporter replayed on another TLS channel**
   (`TestLoopbackStaleExporterOnSecondChannelRejected`). One request is accepted
   on channel 1. A second fresh TLS 1.3 mTLS handshake uses the same synthetic
   CA and leaf certificates, so both endpoint SPKI pins are unchanged and the
   channel-2 source and target peer bindings still verify. On channel 2 the
   same context, source/target bindings and delegated-admin authorization still
   pass `VerifyPeerDeviceTransportBinding` and
   `VerifyAdminRemoteUnlockAuthorization`, and channel 2's own exporter
   verifies, but channel 2 derives a different exporter. Replaying channel 1's
   exporter makes the server-side channel-2 `VerifyBindingContext` fail with
   `ErrBindingMismatch` before any approval, `vaultfile.SealVUKForDevice` call
   or VUK frame. The test asserts that error, zero sealed VUKs, zero VUK frames
   and no reply bytes. It deliberately does not change certificates or any
   policy, signature or key, so the rejection is attributable to the stale
   exporter alone.
2. **Late response to a locally cancelled request**
   (`TestLoopbackCancelledRequestDoesNotConsumeLateVUK`). A distinct fresh
   context (new request identifier, request digest and lock generation) with a
   valid delegated-admin authorization travels over one real loopback TLS 1.3
   mTLS channel against the caller-pinned current file and checkpoint. The
   client creates the request's process-local `RequestLifecycle` (status
   `requested`) before it sends the request. The server verifies the real
   channel exporter, source peer binding and delegated-admin authorization,
   then pauses **before sending any response frame**. It signals that
   verified-and-paused point to the test goroutine only through a bounded,
   buffered test-only Go synchronization channel; nothing is signalled through
   the TLS channel or a protocol frame, and no approval is sent yet. While the
   server is paused, a bounded client read must observe no bytes on the TLS
   channel. After that signal the client calls `Cancel`, verifies the status is
   `cancelled`, and only then releases the server. The server then sends a
   test-only approval and one genuine age-wrapped VUK over the real TLS
   channel, and its test result proves it actually sealed and sent one VUK. The
   client reads both after cancellation but never calls
   `vaultfile.OpenVUKForDevice`: it never unpacks the late ciphertext and so
   derives no client-side plaintext VUK from that response, and it clears the
   caller-owned ciphertext buffer with a zero-buffer assertion. The server, by
   contrast, must hold the synthetic plaintext VUK to seal its response with
   `vaultfile.SealVUKForDevice` and clears its source buffer. The test does not
   claim the server never held plaintext, and it makes no bytewise comparison
   against the VUK, so it does not claim the VUK is absent from the envelope
   bytes; it only checks that the device age recipient is not carried in
   plaintext. `Confirm` and `Receive` stay rejected with
   `ErrLifecycleTransition` and the status stays `cancelled`. This API has no
   locked state, so only `Cancel` is covered.

Cancellation in case 2 is **local and in-memory only**. It does not revoke the
authorization, notify the server, stop the server from delivering the late
response, survive a restart, or provide durable anti-replay protection. The
test demonstrates that cancellation precedes the complete late response and that
no local lifecycle consumption occurs; it does not claim remote cancellation,
system-wide key revocation, or that the server withheld the late VUK.

These are two covered rejections, not a failure matrix: no wrong SPKI, key,
device, member, context, expiry, restart, stale policy or tampering case is
exercised, and they are not evidence that #127, #129 or #130 is complete. The
test-only frames remain private to the tests: one bounded request frame whose
packet ends with two 1-byte control sections (`send_vuk`, `pause_before_response`),
one bounded approval frame and one bounded VUK frame. There are no other frames;
the verification pause is signalled over Go channels only. None of this is a
product wire protocol.

## Scope boundary

This document defines two owner-root-signed objects -- the per-request
owner-root authorization and the reusable admin delegation -- and one
delegated-device-signed object, the per-request admin authorization. The two
owner-root objects are issued by the vault owner root alone. The delegation
grants reusable scope to a current admin or owner device but authorizes no
request by itself and verifies no binding; the per-request owner-root
authorization authorizes one request and its two bindings; the per-request
admin authorization is signed by the delegated admin device for one request and
its two bindings under a currently valid delegation, and never by the owner
root. None provides request-digest preimage semantics, durable replay or
restart anti-rollback, or VUK decryption, wrapping or delivery. A nil return
from a verifier means exactly what that section states and nothing more.
`VerifyOwnerRootAuthorization` and `VerifyAdminRemoteUnlockAuthorization` are
not end-to-end verifiers, and the admin verifier is not a TLS, relay, VUK
delivery or production identity integration. Neither verifier provides durable
replay protection or a one-shot guarantee: the caller's lifecycle must prevent
replay and one-shot use of a request authorization.
It does not itself compute or verify a TLS exporter or channel binding, and it
does not match a live peer SPKI. Those are separate APIs documented earlier,
and callers must compose them explicitly. The binding
[context codec](#encoding-rules) only encodes and parses context bytes;
`remoteunlocktls.Channel.ExportBindingContext` and
`remoteunlocktls.Channel.VerifyBindingContext` are what bind or verify those
canonical context bytes against the exporter on an established TLS channel.
Separately, `remoteunlocktls.Channel.VerifyPeerDeviceTransportBinding` checks
the live peer SPKI and then the [stable device transport
binding](#stable-device-transport-binding-v1) signature and context; see the
[peer-channel check](#peer-binding-over-an-established-channel).
`VerifyOwnerRootAuthorization` and `VerifyAdminRemoteUnlockAuthorization`
perform neither check, and none of them is integrated into either verifier.

This context codec alone proves no authorization, requester identity, device
identity, pairing, membership, policy, signature, request freshness or
one-shotness, and no TLS handshake. It also proves no VUK delivery. It only
proves that a byte string is the canonical encoding of syntactically valid
claims. Those claims become meaningful only when a verifier separately checks
the caller-defined request digest preimage, the policy digest preimage, the
signing and identity chain, the pairing and membership state, the deadline
against a trusted clock, and a TLS exporter binding on the actual pinned
connection.
