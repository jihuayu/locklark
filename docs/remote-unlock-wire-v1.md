# Remote unlock wire v1: canonical binding context

Status: codec definition plus a process-local request lifecycle. The package
`pkg/remoteunlock` implements exactly this encoding and the lifecycle in
[Process-local request lifecycle](#process-local-request-lifecycle). The vector
below is synthetic and demonstrates the codec only.

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
