# Remote unlock wire v1: canonical binding context

Status: context and stable per-device binding codecs, plus a process-local
request lifecycle. The package `pkg/remoteunlock` implements exactly these
encodings, the binding signature check in
[Stable device transport binding v1](#stable-device-transport-binding-v1), and
the lifecycle in [Process-local request lifecycle](#process-local-request-lifecycle).
`internal/remoteunlocktls` additionally exposes a narrow channel-side check of a
peer binding against the verified TLS peer certificate
([Peer binding over an established channel](#peer-binding-over-an-established-channel)).
The vectors below are synthetic and demonstrate the codecs only.

## Scope

This document defines the bytes of the TLS exporter binding context for remote
unlock v1, and nothing else.

Encoding or parsing a context proves only that the bytes are the canonical
encoding of syntactically valid claims. It does **not** prove authorization,
requester or device identity, pairing, membership, policy, request freshness,
one-shot consumption, signatures, a TLS handshake, or delivery of a vault unlock
key (VUK). This codec does not create or inspect TLS connections and does not
verify any field. A caller that relies on these claims must verify them through
separate mechanisms, including a TLS exporter binding on the actual connection.

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
to later signed authorization. Later protocol layers may reference a binding by
digest, but this codec defines no digest-reference message.

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

## Scope boundary

This context codec alone proves no authorization, requester identity, device
identity, pairing, membership, policy, signature, request freshness or
one-shotness, and no TLS handshake. It also proves no VUK delivery. It only
proves that a byte string is the canonical encoding of syntactically valid
claims. Those claims become meaningful only when a verifier separately checks
the caller-defined request digest preimage, the policy digest preimage, the
signing and identity chain, the pairing and membership state, the deadline
against a trusted clock, and a TLS exporter binding on the actual pinned
connection.
