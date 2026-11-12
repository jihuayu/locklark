# locklark.vault-file/v1 Wire Schema

Status: draft. Implemented in `pkg/vaultfile`: structure, canonical codec,
preimage derivation, the CEK envelope (`SealCEK`/`OpenCEK`, see [CEK sealing and
opening](#cek-sealing-and-opening)), the per-device VUK envelope
(`SealVUKForDevice`/`OpenVUKForDevice`, see [VUK device-slot
envelope](#vuk-device-slot-envelope)), and two separate verification APIs (see
[Verification APIs](#verification-apis)):

- `VerifyContentSignature`, the narrow check: `ValidateFile` plus the file's
  content signature against a caller-pinned device key. It does not
  authenticate policy proofs and does not authorize the current policy.
- `VerifyPolicyCheckpoint`, the checkpoint-scoped check: given an already
  trusted out-of-band `PolicyCheckpoint` (vault id, owner-root key id and
  public key, policy sequence and digest), which it treats as caller-owned,
  does not retain after the call and whose digest it clones internally, it
  binds the file to that vault,
  authenticates the policy continuation from the pinned digest with root-signed
  or delegated `InviteReaders` proofs (or, with no anchor carried, a first
  root-signed proof exactly at checkpoint seq+1 linked to the pinned digest),
  requires the author's role in
  the current policy to be writer, admin or owner, then verifies the content
  signature with the current policy's device key. A carried anchor proof is
  trusted through the caller's digest alone; its own signature is not
  cryptographically reverified. A continuation is root-signed by the pinned
  owner root, or is a delegated **InviteReaders** transition whose signer an
  active `InviteReaders` `AdminDelegation` in the authenticated predecessor
  policy names (see [Admin-delegated
  InviteReaders](#admin-delegated-invitereaders-transitions)).

Neither API establishes the trustworthiness or provenance of the caller's
checkpoint, root or pinned key. Of the delegated scopes, only `invite_readers`
authorizes anything, and only the narrow transition described in
[Admin-delegated
InviteReaders](#admin-delegated-invitereaders-transitions); every other
delegated scope, invite-writer addition, removal, role change and key or root
change remains unsupported.

The package also implements the two high-level full-file paths. `SealAuthenticatedFile`
authenticates the draft's policy chain against the caller's checkpoint, checks
the author key in the authenticated current policy, wraps the caller's VUK to
exactly that policy's read devices, encrypts the database under a fresh CEK and
returns the sealed bytes (see [Trusted full-file
seal](#trusted-full-file-seal)). `OpenAuthenticatedFile` parses, verifies the
caller-pinned checkpoint, resolves the caller device from the
now-authenticated current policy, then opens the VUK, CEK and KDBX payload in
that order (see [Trusted full-file open](#trusted-full-file-open)).

The package also implements the low-level KDBX payload pair
[`SealKDBXPayload`/`OpenKDBXPayload`](#kdbx-payload-sealing-and-opening), which
encrypts one unlocked KDBX 4.1 database under the per-snapshot CEK with a fixed
Argon2id profile and opens it through the bounded decoder. It binds no file and
authenticates no policy; `OpenAuthenticatedFile` calls it only after the
checkpoint and key envelopes succeed.

The package also implements two key-wrapping primitives. The per-snapshot CEK
envelope, [`SealCEK`/`OpenCEK`](#cek-sealing-and-opening), wraps a fresh random
32-byte CEK under the epoch VUK; a wrapping proves only that a CEK slot is
authentic for the VUK and the bound header. The per-device VUK envelope,
[`SealVUKForDevice`/`OpenVUKForDevice`](#vuk-device-slot-envelope), wraps a
caller-supplied 32-byte VUK to one device with standard age X25519 in the
existing `vuk_device_slots` entries (`DeviceSlot.WrappedVUK`); its caller
verified expected recipient comes from an already authenticated policy. Neither
primitive generates or rotates a VUK or key epoch. Wrapping of the invitation
and epoch keys, content history through `prev_digest`, server freshness and
overall vault trust are not implemented. `OpenAuthenticatedFile` is only the
caller-pinned authenticated open described below, not an epoch, invitation or
freshness mechanism. KDBX content serialization and opening with the CEK remain
the low-level payload APIs of
[KDBX payload sealing and opening](#kdbx-payload-sealing-and-opening), which
bind no file and authenticate no policy; `OpenAuthenticatedFile` is the
file-level orchestration around them.
This document describes the wire format and the frozen v1 preimages; it makes
no cryptographic correctness claim and grants no migration or product
permission.

## Background

Earlier drafts labelled this document revision v3, while the public wire
identifier was always required to be `locklark.vault-file/v1`. The design
revision number is a planning label only and never described the wire. Every
protocol identifier in this document, in `pkg/vaultfile` and in
`pkg/vaultfile/testdata/vaultfile-v1-vectors.json` therefore carries the `v1`
token, `version` is `1`, and the schema URI is
`https://locklark.dev/schema/locklark.vault-file/v1`.

v1 has no header signature. An earlier draft carried a `header_sig` member;
it is not a member of v1 and is rejected as `unknown_field`. The header is
covered through `content_signature`, which commits to the derived revision id
(see [File states](#file-states)).

## Wire identifiers

| Constant        | Value                                                 |
| --------------- | ----------------------------------------------------- |
| `format`        | `locklark.vault-file`                                 |
| `version`       | `1`                                                   |
| schema URI      | `https://locklark.dev/schema/locklark.vault-file/v1`  |
| MIME type       | `application/vnd.locklark.vault-file+json`            |
| `content_encoding` | `kdbx`                                             |

Domain-separation labels are the constant strings defined in
`pkg/vaultfile/domain.go`. None of them starts with `/`: every label begins
with `locklark.vault-file/v1/`, and `DomainSeparated` hashes
`domain || 0x00 || data` with no separator between the domain and the NUL.

The entries below are listed by their suffix only, for brevity. The leading `/`
in an entry is suffix shorthand and is **never** part of the label bytes: the
label for `/revision` is exactly `locklark.vault-file/v1/revision`, not
`/locklark.vault-file/v1/revision`.

Purpose domains (each prefixes exactly one preimage, followed by `0x00`):

- `/content-signature`, `/revision`, `/file-digest`
- `/policy-document-signature`, `/admin-delegation`
- `/vuk-device-wrapping` (the first bytes of a VUK device-slot plaintext),
  `/cek-wrapping` (the first bytes of a CEK wrap's AAD)

Identification usage labels (fingerprints only; they never appear in a signing,
revision or file-digest preimage):

- `/vault-id`, `/content-revision-id`, `/op-id`, `/device-id`
- `/key/device-content-signing`, `/key/device-policy-signing`,
  `/key/age-x25519`, `/policy-document`

Labels are identification and purpose separators only. This package does not
sign, generate a VUK or derive any key. It wraps and unwraps exactly two keys:
the per-snapshot CEK under the epoch VUK (`/cek-wrapping`, see [CEK sealing and
opening](#cek-sealing-and-opening)) and the per-device VUK envelope
(`/vuk-device-wrapping`, see [VUK device-slot
envelope](#vuk-device-slot-envelope)), whose plaintext begins with that label
and one `0x00`. It authenticates no policy of its own. The only
authorization it checks is
checkpoint-scoped: under a caller-supplied checkpoint, whether the author may
author the authenticated current policy. It has no trust anchor of its own. A
policy transition it accepts is either root-signed by the pinned owner root or
a delegated `InviteReaders` transition authorized by the authenticated
predecessor policy; it checks no other delegated authority. It performs
signature checks in exactly two places, both described in [Verification
APIs](#verification-apis):

- `VerifyContentSignature` checks one file content signature under the
  `/content-signature` label against a caller-pinned Ed25519 key. It does not
  authenticate policy proofs or authorize the current policy.
- `VerifyPolicyCheckpoint` checks, only relative to a caller-supplied
  `PolicyCheckpoint`, the `/policy-document-signature` proofs that continue the
  pinned digest, each either against the pinned owner-root key or, for a
  delegated `InviteReaders` transition, against the predecessor device's
  `PolicySigningKey`, and then the `/content-signature` signature against the
  current policy's device key.

## Documents

A vault file is one self-contained canonical-JSON object. Content bytes are
embedded (`kdbx_ciphertext`), never referenced by digest only. In the sync
protocol, `R` is exactly these bytes as read back from the backend.

The file members are exactly these, in this order; any other member is
unknown:

```
{
  "format":               <format>,
  "version":              <version>,
  "header":               { Header },
  "signed_policy_proofs": [ { SignedPolicy } ],
  "content_encoding":     <content_encoding>,
  "kdbx_ciphertext":      <base64url>,
  "vuk_device_slots":     [ { DeviceSlot } ],
  "cek_slot":             { "key_epoch": <int>, "wrapped_cek": <base64url> },
  "content_signature":    { Signature }
}
```

`Header`:

```
{
  "vault_id":         <id>,
  "key_epoch":        <int>,
  "content_seq":      <int>,
  "revision_id":      <lowercase hex sha256>,        // exactly RevisionID
  "prev_digest":      <base64url sha256> | null,     // null only at content_seq 0
  "op_id":            <id>,
  "policy_seq":       <int>,
  "policy_digest":    <base64url sha256>,
  "author_device_id": <device id>
}
```

`revision_id` is the derived `RevisionID` of the file (see
[Preimages](#frozen-v1-preimages)); it is never an input of any preimage.

`Signature`: `{"signer_id": <id>, "alg": "ed25519", "sig": <base64url 64 bytes>}`.
Every file `content_signature` is a non-null 64-byte signature. A `null` `sig`
is not a wire value.

`SignedPolicy`: `{"document": <base64url>, "policy": { Policy }, "signer_id",
"alg", "sig"}`. `document` is the canonical encoding of `policy`; the strict
policy parser (`ParsePolicyDocument`) re-parses it and requires byte equality
with the canonical re-encoding. A proof whose `document` is any other spelling
is a `non_canonical` error, so `ParseFile`, `SealFile` and `ValidateFile` all
reject it.

`Policy` (the authorization document):

```
{
  "format":             <format>,
  "version":            <version>,
  "vault_id":           <id>,
  "policy_seq":         <int>,
  "prev_policy_digest": <base64url sha256> | null,   // null only for the genesis policy
  "owner_root":         { "key_id", "alg", "public_key", "owners": [ {Principal} ] },
  "readers":            [ {Member} ],
  "writers":            [ {Member} ],
  "admins":             [ {Member} ],
  "owners":             [ {Member} ],
  "admin_delegations":  [ {AdminDelegation} ],
  "devices":            [ {Device} ]
}
```

- `Principal` / `Member`: `{"principal_id": <id>, "label": <label>}`.
- `AdminDelegation`: `{"delegation_id", "delegate_device_id", "granted_by",
  "scope": {"invite_readers", "invite_writers", "remove_members",
  "remove_devices", "promote_admin", "promote_owner", "replace_root"},
  "scope_note", "expires_policy_seq"}`. `promote_owner` and `replace_root`
  must be `false`.
- `Device`: `{"device_id", "principal_id", "label", "content_signing_key":
  {PublicKey}, "policy_signing_key": {PublicKey} | null, "age_encryption_key":
  <age1...>}`. `principal_id` is mandatory: every device belongs to exactly
  one principal.
- `PublicKey`: `{"alg": "ed25519", "public_key": <base64url>}`.
- `DeviceSlot`: `{"device_id", "recipient": <age1...>, "wrapped_vuk": <base64url>}`.

A policy carries no digest of itself. There is exactly one policy digest:

```
policy_digest(P) = SHA-256( "locklark.vault-file/v1/policy-document" || 0x00
                            || canonical policy document bytes )
```

It is always computed outside the `Policy` document (the `/policy-document`
usage label with the NUL separator, as in `DomainSeparated`), from the same
canonical bytes that `SignedPolicy.document` carries. Two references point at
this one value:

- `Header.policy_digest` is `policy_digest` of the policy at
  `Header.policy_seq`;
- the next policy's `prev_policy_digest` is `policy_digest` of its
  immediate predecessor.

## Set-like arrays

Nine arrays in a v1 file are semantically sets. Each has exactly one accepted
wire order; an out-of-order array is never accepted as a second representation
of the same set:

| Array                                 | Ordered by       | Array itself                                 |
| ------------------------------------- | ---------------- | -------------------------------------------- |
| file `signed_policy_proofs`           | `policy.policy_seq` | old to new (oldest first)                 |
| policy `owner_root.owners`            | `principal_id`   | `{Principal}`                                |
| policy `readers`, `writers`, `admins`, `owners` | `principal_id` | `{Member}`, each array separately |
| policy `admin_delegations`            | `delegation_id`  | `{AdminDelegation}`                          |
| policy `devices`                      | `device_id`      | `{Device}`                                   |
| file `vuk_device_slots`               | `device_id`      | `{DeviceSlot}`                               |

`signed_policy_proofs` is ordered by its numeric, non-negative
`policy.policy_seq`, oldest first. Equal `policy_seq` values are rejected, so no
two proofs carry the same sequence and the current policy is the last proof.
Every other array above is ordered by its identifier as a string.

Identifier comparison is bytewise over the raw ASCII bytes of the identifier,
case-sensitive, with no case folding, no Unicode normalization, no locale rule
and no numeric interpretation: `device-10` sorts before `device-2` because
`1` (0x31) is less than `2` (0x32), and `deleg-10` sorts before `deleg-2`.
Every ordinary identifier is already lower-case ASCII
(see [Identifiers](#identifiers)), so bytewise ASCII order is also plain
lexicographic order.

Duplicates are rejected by the same strict-order check, not by a separate
key-uniqueness rule: a repeated identifier or `policy_seq` is not strictly
greater than its predecessor. The comparison covers the whole array: element
0 has nothing to compare against, and element `i` (`i` ≥ 1) is accepted only
when its key is strictly greater than element `i-1`'s. The first element that
is not strictly greater (a decrease or an equal key) is reported as
`unsorted_collection`, with a path naming that element by its zero-based
index:

- `signed_policy_proofs[i].policy.policy_seq`;
- `owner_root.owners[i]`, `readers[i]`, `writers[i]`, `admins[i]`,
  `owners[i]`, `admin_delegations[i]`, `devices[i]`;
- `vuk_device_slots[i]`.

The order check runs before the identifier-grammar check of the same array:
an identifier that is out of order is reported as `unsorted_collection` even
if it is also malformed.

Neither the encoder nor the decoder sorts. `EncodeFile`,
`EncodePolicyDocument`, `PolicyDigest`, `SealFile`, `ValidateFile` and
`ParseFile` all reject an out-of-order array with `unsorted_collection`; input
that is signed, digested or stored must already carry the one accepted order.
Moving, inserting or swapping elements changes the canonical bytes and
therefore the canonical file, and hence its `RevisionID`; if the array is inside
a `Policy` document, it also changes the bytes of that document and hence its
`PolicyDigest`. Such a change is a new value that must be resealed, never an
in-place rewrite.

## Identifiers

An **identifier** in v1 is an opaque key for lookup and comparison, not a
display label. Display labels are separate members (`label`, `scope_note`);
they are UTF-8 text and obey `MaxLabelLength` (`scope_note` also
`MaxRoleScopeLength`) instead of the identifier grammar below. An identifier
carries no structure a peer may interpret: no numeric meaning, no ordering
meaning, and no required prefix or format beyond the grammar.

The ordinary textual identifier grammar (the `validID` rule) is:

- non-empty;
- at most the field's limit in bytes;
- every byte is one of `a`–`z`, `0`–`9`, `.`, `_`, `:`, `-`.

Uppercase ASCII, non-ASCII, whitespace and every other byte (`+`, `/`, `@`,
`#`, ...) are rejected. The set is not limited to names: it admits values such
as `device-1`, `owner-root-01` and `deleg-01`. Each member that uses the
grammar is bounded by its own limit:

| Member                                              | Limit                     |
| --------------------------------------------------- | ------------------------- |
| `vault_id`, `op_id`, `principal_id`, `delegation_id` | `MaxIDLength` (64)        |
| `device_id`, `author_device_id`, `delegate_device_id`, device-slot `device_id` | `MaxDeviceIDLength` (128) |
| `signed_policy_proofs[].signer_id`, `content_signature.signer_id` | `MaxDeviceIDLength` (128) |
| `owner_root.key_id`, delegation `granted_by`        | `MaxKeyIDLength` (64)     |

`signed_policy_proofs[].signer_id` and `content_signature.signer_id` are bounded
structurally at `MaxDeviceIDLength` (128). The codec never verifies either
signature. `VerifyContentSignature` checks `content_signature` only against a
caller-pinned key; `VerifyPolicyCheckpoint` checks the proof
`signed_policy_proofs[].signer_id` / `[].sig` only from a caller-supplied
checkpoint forward, each either root-signed by the pinned owner-root key or,
for a delegated `InviteReaders` transition, signed by the predecessor device's
`PolicySigningKey` (see [Verification APIs](#verification-apis)). No other
policy proof verification exists in this schema revision.

Several wire values that look like identifiers are deliberately **not**
ordinary identifiers:

- `revision_id` is exactly 64 characters of lowercase hex (a SHA-256 value),
  not a `validID` value and not sorted anywhere; in a sealed file it is exactly
  `RevisionID` (see [File states](#file-states)). In the builder draft it is
  `""`, which is not a wire value.
- Key fingerprint usages (`/key/device-content-signing`,
  `/key/device-policy-signing`, `/key/age-x25519`, `/vault-id`,
  `/content-revision-id`, `/op-id`, `/device-id`) are derived bytes
  (`DomainSeparated` output) and follow no textual grammar.
- age recipient strings (`age_encryption_key`, device-slot `recipient`) have
  their own encoding: they start with `age1`, must not be identity material,
  parse as an age X25519 recipient, and are bounded by `MaxPublicKeyLength`.

The genesis policy (`policy_seq` 0) has no predecessor, so its
`prev_policy_digest` is `null`. Any later policy (`policy_seq` > 0) carries
exactly one 32-byte `prev_policy_digest`. Whether a predecessor digest names an
actually known prior policy is a sync decision, not a wire rule.

Role semantics are fixed: the owner root is independent of any device, and
every key role in one policy — the owner-root signing key and, on each device,
the content signing, policy signing and age encryption keys — carries distinct
global key material. No 32 raw public-key bytes may occupy two entries, on one
device, two devices, or across root and device; an age recipient is compared
by the X25519 bytes it encodes, once `filippo.io/age` has accepted it, not by
its text. Reuse is an `invalid_value`.

A device acts only with the roles of its principal, and roles imply the ones
before them: writer implies reader, admin implies writer, owner implies admin.
A device whose principal is in none of `readers`, `writers`, `admins`,
`owners` is rejected.

## File states

A file has exactly two states (see [Builder draft versus sealed file](#builder-draft-versus-sealed-file)):

- **builder draft**: `header.revision_id` is `""` and `content_signature` is
  exactly `{"signer_id":"","alg":"","sig":null}`. A writer holds it in memory
  between building the file and signing `ContentSigningBytes`. It is not a
  wire record and is never serialized by this package.
- **sealed**: `header.revision_id` is exactly `RevisionID` of the file, and
  `content_signature` carries a 64-byte `sig` by the header's author device
  with the shape of that device's content signing key. An empty
  `header.revision_id` is a `missing_field`; a different one is an
  `invalid_value`.

`SealFile(f, sig)` produces exactly one state, the sealed file, and `sig` must
be non-nil: `SealFile(f, nil)` returns an `invalid_value` at
`content_signature` and no bytes. No other combination is accepted, including
a null `sig` with a revision id or a non-null `sig` without one.

## Builder draft versus sealed file

Only a sealed file is a valid wire record. It is the only kind of file that is
transferred to or stored by a backend, and the only kind this package
accepts or emits on the wire:

- `ValidateFile` accepts exactly one state: sealed. A null `sig` is an
  `invalid_value` at `content_signature`; an empty `revision_id` is a
  `missing_field`.
- `ParseFile` rejects a document with a null `sig` or an empty `revision_id`.
- `EncodeFile` (and `FileBytes`, its alias) rejects a draft: it never emits
  draft JSON.
- `FileDigest` hashes only a sealed file.

The builder draft exists only in memory, only so a writer can compute the
two preimages it needs before it has a signature:

- `RevisionID(draft)` and `ContentSigningBytes(draft)` accept the builder
  state. Content signing does not need a revision id, so the draft may already
  carry the signature it is about to be sealed with (`{"signer_id":"device-1",
  "alg":"ed25519","sig":<64 bytes>}`) with `header.revision_id` still `""`.
  Neither function serializes a draft as a wire file, and a null `sig` is
  never written into either preimage.
- `RevisionID` and `ContentSigningBytes` also accept a sealed file and derive
  the same preimages, so a verifier can recompute them from the wire file
  alone.

The writer never needs draft bytes: it builds the draft, calls
`ContentSigningBytes` (and optionally `RevisionID`), signs those bytes, and
calls `SealFile` with the signature. A writer that serializes its draft with
its own encoder must never treat the result as a wire record.

## Frozen v1 preimages

Three values are derived from one file. Each is
`SHA-256(domain || 0x00 || input)`; the 32-byte result is written as lowercase
hex where the schema says hex.

The inputs are the same canonical-JSON bytes as the file, produced with the
same member order and binary encodings. "Omitted" is literal: the member is
absent, not `null`, `""`, or any other placeholder. An independent
implementation must omit the member too; an omitted member and an empty
member are different bytes and different hashes.

```
RevisionID(f) = SHA-256( "locklark.vault-file/v1/revision" || 0x00
                         || canonical file
                            without header.revision_id
                            without content_signature )
```

Both members are removed entirely. `RevisionID` never reads the file's
carried `revision_id` or `content_signature`, so the builder draft and the
file sealed from it have the same revision id, and a stale revision id cannot
change it.
When `header.revision_id` is removed, the header keeps the order of its other
members: `vault_id`, `key_epoch`, `content_seq`, `prev_digest`, `op_id`,
`policy_seq`, `policy_digest`, `author_device_id`.

```
ContentSigningBytes(f) = canonical file
                         with header.revision_id = RevisionID(f)
                         without content_signature
```

`header.revision_id` is present and names the derived revision.
`content_signature` is removed entirely. The signer signs
`"locklark.vault-file/v1/content-signature" || 0x00 || ContentSigningBytes(f)`.
The preimage is the same for the builder draft and for the sealed file, so the
header is covered through the revision id without a second signature.

```
FileDigest(f) = SHA-256( "locklark.vault-file/v1/file-digest" || 0x00
                         || EncodeFile(f) )
```

The input is the complete canonical sealed file, `revision_id` and
`content_signature` included, unchanged. A builder draft has no file digest.

## Structural rules

The codec is strict:

- the input is exactly one complete object (no trailing data);
- the input bytes must be byte-for-byte the canonical encoding of the value
  they parse: `ParseFile` and `ParsePolicyDocument` re-encode the typed value
  with the canonical encoder after structural validation and reject any other
  spelling as `non_canonical` (JSON whitespace anywhere, reordered object
  members, or an equivalent string escape such as `\u0030` for `0`);
- unknown and duplicate members are rejected at every depth;
- nesting depth, array lengths, string lengths and byte lengths are limited
  before any value is copied or decoded;
- numbers are non-negative integers only (no fractions, exponents, negatives
  or leading zeros); numbers written as strings are rejected;
- binary values are base64url without padding, canonical for the value;
- `version` must equal `1` in both the file and the policy document.

`ValidateFile` first requires the sealed state (non-null shaped author
signature and the exact derived `revision_id`) and also checks the
cross-member bindings. The same checks apply to sealed files in every entry
point: every policy proof names the header vault, exactly one proof carries
the header policy sequence and its `policy_digest` (as defined above) equals
`Header.policy_digest`, the CEK slot epoch matches the header epoch, and the
author is a policy device whose principal is a writer, admin or owner.

The VUK slots are exactly the approved devices whose principal has read
access (reader, writer, admin or owner): every such device has one slot in the
set and no other device has any, so no device without a read role is wrapped
the VUK and no read-capable device is left without it. A slot must name a
policy device and carry that device's age recipient. `ValidateFile` checks
`wrapped_vuk` only for presence and the `MaxWrappedKeyLength` size; it is
neither opened nor bound to the policy or header by any structural rule
(opening is the separate caller-trusted primitive of [VUK device-slot
envelope](#vuk-device-slot-envelope)). Slots are ordered strictly ascending by
`device_id` (see [Set-like arrays](#set-like-arrays)); there is no other slot
order. Moving a slot changes the revision input and therefore the revision id,
so a file is resealed after reordering.

## Validation scope

`ValidateFile` and every parser, encoder and preimage function are structural
and shape-only. No structural path performs a cryptographic check, and the
package computes no signature.

- signature bytes are checked for presence, length, algorithm and encoding
  only; `ValidateFile` does not verify any signature. Cryptography lives only
  in the two explicit APIs of [Verification APIs](#verification-apis), in
  the CEK envelope of [CEK sealing and opening](#cek-sealing-and-opening) and
  in the VUK envelope of [VUK device-slot
  envelope](#vuk-device-slot-envelope): the
  content signature is verified by `VerifyContentSignature` (pinned key) and by
  `VerifyPolicyCheckpoint` (current policy key), and policy proof signatures
  are cryptographically verified only by `VerifyPolicyCheckpoint`, only for the
  continuation after a caller-supplied checkpoint. That API does not
  cryptographically reverify the anchor proof's signature, though
  `ValidateFile` still checks that proof's structural algorithm and signature
  shape;
- `revision_id` is checked to equal `RevisionID`; it is not a signature;
- wrapped-key bytes are checked for presence and size, never unwrapped;
  `vuk_device_slots` entries with a valid age X25519 recipient are not opened
  by any structural path;
- public keys and age recipients are parsed for shape only;
- in `ValidateFile`, the author's principal is required to be a writer, admin
  or owner of the current policy by membership in the carried, unverified
  policy. That is a structural membership check, not an authorization: which
  policy is current becomes authenticated only under `VerifyPolicyCheckpoint`'s
  caller-supplied checkpoint, and no structural path grants trust by itself.
  Whether a carried digest names a known prior value is a sync decision
  outside this codec; `VerifyPolicyCheckpoint` links `prev_policy_digest`
  forward from the checkpoint digest but does not check content history
  through `prev_digest`.

## Verification APIs

`ValidateFile` stays shape only and introduces no trust anchor: it never
verifies a signature, authenticates a policy proof or authorizes a policy.
Two separate exported APIs add cryptography on top of it, and they answer
different questions (the separate `SealCEK`/`OpenCEK` envelope of
[CEK sealing and opening](#cek-sealing-and-opening) and the
`SealVUKForDevice`/`OpenVUKForDevice` envelope of [VUK device-slot
envelope](#vuk-device-slot-envelope) are not verification APIs and authorize
nothing):

| API | Input it trusts | What it establishes |
| --- | ------------------- | ------------------- |
| `VerifyContentSignature` | caller-pinned device id and content key | the sealed file's content signature, for the author device the caller names, under that caller-pinned key |
| `VerifyPolicyCheckpoint` | caller-supplied `PolicyCheckpoint` (vault id, owner-root key id and public key, policy seq and digest) | the file and its proofs belong to that vault, the policy continuation from the pinned digest is signed by the pinned owner root or is a delegated `InviteReaders` transition authorized by the authenticated predecessor policy, the author's role in the authenticated current policy is writer/admin/owner, and the content signature verifies under the current policy's device key |

Neither API establishes or creates the trustworthiness or provenance of what
the caller supplies. `VerifyContentSignature` does not authenticate policy
proofs or authorize the current policy; `VerifyPolicyCheckpoint` takes the
checkpoint and owner root as already trusted and does not prove where they came
from. What neither establishes is stated in [Limits](#limits).

### `VerifyContentSignature`: narrower pinned key check

```
VerifyContentSignature(f *File, signerDeviceID string, publicKey ed25519.PublicKey) error
```

- It runs `ValidateFile` first and returns any structural error unchanged.
- The caller pins `signerDeviceID` and `publicKey` out of band. They must
  equal `header.author_device_id` / `content_signature.signer_id` and the
  content signing key recorded for that device in the carried policy; the key
  is never taken from the unsigned/unverified `signed_policy_proofs` as a
  trust anchor.
- It verifies, with `crypto/ed25519`, exactly
  `"locklark.vault-file/v1/content-signature" || 0x00 ||
  ContentSigningBytes(f)` against `content_signature.sig`. The preimage is
  not hashed further and not altered.
- A signer mismatch, a `publicKey` that is not 32 bytes, a key that differs
  from the carried policy key, or a signature that does not verify are all
  `signature_verify_failed`, a caller-pinned-trust failure. Each is a trust
  decision, not a structural defect; the file itself may still pass
  `ValidateFile`.

This API does **not** verify policy proof signatures
(`signed_policy_proofs[].sig`), any signature chain from the owner root or
admin delegations (including delegated `InviteReaders` transitions), policy
continuity through `prev_policy_digest`, or that the signer is authorized by an
authenticated policy. It is a narrower check
than `VerifyPolicyCheckpoint`; use that API when the current policy itself
must be authenticated.

### `VerifyPolicyCheckpoint`: checkpoint-scoped verification

```
type PolicyCheckpoint struct {
        VaultID            string
        OwnerRootKeyID     string
        OwnerRootPublicKey ed25519.PublicKey
        PolicySeq          uint64
        PolicyDigest       []byte
}

VerifyPolicyCheckpoint(f *File, checkpoint *PolicyCheckpoint) error
```

The `PolicyCheckpoint` is the caller's already-trusted policy state, derived
out of band (for example from a trusted sharing, pairing or recovery exchange).
This package neither creates nor infers one, and does not establish that it is
genuine; that trust must already exist. The checkpoint is caller-owned:
`VerifyPolicyCheckpoint` reads its fields and input bytes during the call and
does not retain the checkpoint after it returns; the verifier clones
`PolicyDigest` internally, so that clone is the only byte copy. The caller must
keep the checkpoint's fields and `OwnerRootPublicKey` / `PolicyDigest` bytes
stable while the call runs.

- It runs `ValidateFile` first and returns any structural or sealed-state
  error unchanged. It then requires a non-nil checkpoint with a valid
  `VaultID` and `OwnerRootKeyID` identifier, a 32-byte `OwnerRootPublicKey`
  and a 32-byte `PolicyDigest`; a malformed checkpoint is `invalid_value`.
- **Vault binding**: `header.vault_id` and every carried proof's
  `policy.vault_id` must equal `checkpoint.VaultID`.
- **Anchor**: the carried proof at `checkpoint.PolicySeq` whose canonical
  policy bytes hash to `checkpoint.PolicyDigest` is the anchor, and its owner
  root (`key_id`, `alg`, public key) must equal the pinned root. The anchor's
  signature is not cryptographically reverified; it is trusted through the
  pinned digest alone, and this API does not look at its `signer_id`, `alg` or
  `sig`. `ValidateFile` has still checked that proof's structural algorithm
  and signature shape. The anchor's canonical digest is still
  recomputed from its carried document bytes, which `ValidateFile` has already
  required to be canonical. Proofs before the anchor are already established
  and are ignored.
- **No carried anchor**: for a continuation the file carries no proof of, the
  carried proofs must begin exactly at `checkpoint.PolicySeq+1`, and that first
  proof must carry `prev_policy_digest` equal to `checkpoint.PolicyDigest` and
  be root-signed, with its Ed25519 signature over the policy-document preimage
  verifying under the pinned owner-root public key. No predecessor policy body
  is then authenticated, so the first continuation cannot be a delegated
  transition. A later root-signed proof may establish a predecessor policy
  whose delegation then authorizes a following delegated `InviteReaders`
  transition; the first proof can never be the delegated one. A file that
  carries `checkpoint.PolicySeq` with a different digest is rejected rather
  than treated as a continuation.
- **Continuations**: every later proof must carry exactly the previous trusted
  sequence plus one, `prev_policy_digest` equal to the previous trusted
  digest and the pinned owner root (`key_id`, `alg` and public key). Its
  `signer_id` is then either
  `checkpoint.OwnerRootKeyID` — a root-signed proof, verified with a
  `crypto/ed25519` signature over
  `"locklark.vault-file/v1/policy-document-signature" || 0x00 ||
  SignedPolicy.document` that verifies under the pinned owner-root public key
  and **not** restricted by the policy diff — or a device in the
  authenticated predecessor policy that satisfies every condition of
  [Admin-delegated InviteReaders](#admin-delegated-invitereaders-transitions),
  in which case the same preimage is verified under exactly that device's
  `PolicySigningKey`. Any other signer is `policy_checkpoint_failed` with an
  empty path. A failing proof signature, root- or device-signed, is
  `signature_verify_failed` at `signed_policy_proofs[i]`.
- A file whose current policy is behind `checkpoint.PolicySeq` is stale, and
  a carried sequence equal to `checkpoint.PolicySeq` with a different digest
  is a mismatch; vault, anchor, tip, gap, link, root and delegated-transition
  authorization failures are `policy_checkpoint_failed` with an empty path.
- **Authorize and check content**: the same current-author role requirement
  applies however the chain was signed (root or delegated). Having
  authenticated the chain to the current policy, the author's principal must
  be a writer, admin or owner of
  that current policy. A reader author, an author whose device is missing from
  the current policy, or a demoted or removed author fails before the
  sealed-state check as `invalid_value` with an empty path, because
  `current.canAuthor` and `validateStructure` run before any signature lookup.
  Structural and shape failures, including invalid policy content-key shapes,
  are returned unchanged from `ValidateFile`; after validation the
  cryptographic failures of the policy and content signatures are
  `signature_verify_failed` with the paths below. An author whose device is
  listed without an Ed25519 content signing key is therefore not reported as
  `signature_shape_invalid` here: validation rejects the invalid policy first.
  The content signature is then
  verified with the current policy's `content_signing_key` for
  `header.author_device_id`,
  exactly `"locklark.vault-file/v1/content-signature" || 0x00 ||
  ContentSigningBytes(f)`. A content signature that does not verify is
  `signature_verify_failed` with an empty path; a policy proof signature that
  does not verify is `signature_verify_failed` at
  `signed_policy_proofs[i]`.

### Admin-delegated InviteReaders transitions

The only admin-delegated policy transition `VerifyPolicyCheckpoint` accepts is
`InviteReaders`. Every other delegated transition stays unsupported. Within the
continuation loop, a proof whose `signer_id` is not
`checkpoint.OwnerRootKeyID` is accepted only when **all** of the following
hold, and is otherwise `policy_checkpoint_failed`. The authority is read only
from the predecessor policy the chain has already authenticated:

- the signer names a device in the authenticated predecessor policy whose
  principal is Admin or Owner **in that predecessor policy**;
- that device carries an Ed25519 `PolicySigningKey` (non-nil, `alg`
  `ed25519`, 32-byte key), and the proof's signature verifies under exactly
  that key, over the same
  `"locklark.vault-file/v1/policy-document-signature" || 0x00 ||
  SignedPolicy.document` preimage (a failure here is
  `signature_verify_failed` at `signed_policy_proofs[i]`);
- an active `AdminDelegation` in that same predecessor names the device
  (`delegate_device_id`) with `scope.invite_readers` `true`; a delegation is
  active when its `expires_policy_seq` is `0` (unbounded; `ValidatePolicy`
  rejects only a non-zero expiry at or before the policy's own sequence) or
  later than the predecessor's `policy_seq`;
- `inviteReadersPolicyDiff(predecessor, next)` accepts the old-to-new delta
  below.

The successor's own `admin_delegations` are never consulted for authority, the
predecessor's other scope flags and `scope_note` grant nothing, and a delegated
transition is never reinterpreted as a root-signed one. A root-signed
transition remains allowed under the pinned owner-root key and is **not**
restricted by `inviteReadersPolicyDiff`, so the root may still make other
changes it already could make.

`inviteReadersPolicyDiff` accepts only this delta, comparing arrays by
identifier rather than position:

- `format`, `version`, `vault_id` unchanged, `next.policy_seq` exactly
  `old.policy_seq+1`, `next.prev_policy_digest` equal to `policy_digest` of the
  predecessor, and the complete `owner_root` (key id, algorithm, public key
  and `owners`) unchanged; the sequence must not be exhausted at `2^64-1`;
- `readers` grows by only entirely new principals, at least one and up to
  `MaxPolicyArrayItems` (64), each carrying a new `principal_id` that is
  absent from the predecessor's `readers`, `writers`, `admins`, `owners` and
  `owner_root.owners` (and from the successor's `writers`, `admins`, `owners`
  and `owner_root.owners`); every existing reader is carried unchanged;
- `devices` gains 0 up to `MaxArrayItems` (128) entries, each owned by a newly
  added reader, for any subset of the new readers; every existing device is
  carried unchanged, so no device is removed or edited;
- `writers`, `admins` and `owners` are exactly unchanged, so no removal,
  promotion, demotion or relabel happens;
- `admin_delegations` is never added or edited: every existing delegation is
  carried unchanged, except that a delegation whose `expires_policy_seq`
  equals `next.policy_seq` may be omitted (carrying it would fail
  `ValidatePolicy`, which rejects a grant at its own expiry); a delegation
  that is not expiring at `next.policy_seq` is never removed.

Structural validity, frozen array order, key uniqueness, the unchanged
owner-root key and the rule that a later policy names exactly one 32-byte
`prev_policy_digest` (linked to its immediate predecessor) remain
`ValidatePolicy` and `ValidateFile` rules; the diff only constrains the delta.
The diff changes no wire field and no preimage.

## CEK sealing and opening

Each content snapshot has one fresh random 32-byte CEK, used as the KDBX key
credential of its `kdbx_ciphertext`. The CEK is never carried in the clear: it
travels only inside `cek_slot.wrapped_cek`, wrapped by the 32-byte VUK of
`Header.key_epoch`. Two functions implement exactly that envelope:

```
SealCEK(vuk []byte, header Header) (cek []byte, slot CEKSlot, err error)
OpenCEK(vuk []byte, header Header, slot CEKSlot) ([]byte, error)
```

- `vuk` is exactly 32 bytes (`CEKSize`). The package neither generates nor
  loads the VUK.
- `SealCEK` generates a fresh random 32-byte CEK with `crypto/rand`, wraps it
  and returns the CEK together with a slot whose `key_epoch` equals
  `header.key_epoch`. The returned `cek` is caller-owned: use it as the KDBX
  key credential, then clear it once the KDBX content has been encrypted.
  `OpenCEK` returns the unwrapped CEK, which is caller-owned in the same way
  and must be cleared after KDBX use. Neither function retains a caller
  buffer (`vuk`, `header`, a returned `cek`) after it returns; the caller
  keeps its buffers stable while a call runs.
- `header` must pass `ValidateHeader` and carry a non-zero `key_epoch`; a zero
  epoch is an `invalid_value` at `key_epoch`. A `vuk` of any other length is
  an `invalid_value` at `""`.
- A failure of `crypto/rand` inside `SealCEK` is returned as the underlying
  operational error, not as a validation code, after the generated CEK buffer
  is cleared.

The wrap is AES-256-GCM from `crypto/cipher.NewGCMWithRandomNonce` (standard
library only), keyed by the VUK. Implementation: `aead.Seal(nil, nil, CEK,
aad)`; the AEAD generates the nonce and prepends it, and the standard `Seal`
output already ends with the tag:

```
aad         = "locklark.vault-file/v1/cek-wrapping" || 0x00
              || canonicalHeaderWithoutRevisionID(header)

wrapped_cek = nonce_prefix(12) || ciphertext(32) || tag(16)
```

A valid `wrapped_cek` is exactly 60 bytes: 12-byte nonce prefix, 32-byte CEK
ciphertext, 16-byte tag (well within `MaxWrappedKeyLength`); no second tag is
appended. The `NewGCMWithRandomNonce` output is already the nonce prefix
followed by the ciphertext and tag; no other nonce scheme, cipher, KDF or
wrapper is used.

Key usage limit: with `NewGCMWithRandomNonce`, a given VUK must not be used
for more than 2^32 (2**32) encryptions; beyond that, nonce collisions and
forgery risks are no longer negligible (see the `crypto/cipher`
documentation). Each `SealCEK` call performs exactly one encryption with that
VUK. `SealCEK` is stateless and cannot track per-key usage, so the caller must
count `SealCEK` calls per VUK and rotate to a new VUK and key epoch before any
VUK reaches 2^32 encryptions.

`canonicalHeaderWithoutRevisionID` is exactly the schema order of the
canonical header with the `revision_id` member absent entirely, not empty:

```
{"vault_id":…,"key_epoch":…,"content_seq":…,"prev_digest":…,"op_id":…,
 "policy_seq":…,"policy_digest":…,"author_device_id":…}
```

It binds every header member except `revision_id`. `revision_id` is excluded
because it is derived: `RevisionID` hashes the file carrying `wrapped_cek`, so
including the derived id here would make sealing circular. The result is that
the CEK can be sealed before the revision id is derived, the same wrapping
opens under a draft header without a revision id and under the sealed header,
and a different but valid-shaped `revision_id` neither changes the
authenticated data nor the open result. The final content signature still
binds the final revision id and the complete file.

`OpenCEK` reports one generic failure code for every envelope failure:
`cek_envelope_failed`, an `*Error` with that `Code` at `cek_slot`. It covers a
slot `key_epoch` different from the header, nil/empty or wrong-length
`wrapped_cek`, a wrong VUK, and any authentication or tamper failure; a
caller cannot tell a wrong VUK from corrupted bytes. Structural failures (an
invalid header or VUK length) are returned as above instead. On any error the
returned CEK is nil and any plaintext produced before the failure is cleared;
`SealCEK` clears its generated CEK buffer when `crypto/rand` fails and
returns that error as is.

This primitive does not authorize a file and does not open a file. It does not
derive, generate or rotate the VUK (wrapping the VUK to one device is the
separate envelope of [VUK device-slot
envelope](#vuk-device-slot-envelope)), or serialize, encrypt or decrypt KDBX
content with the CEK. `OpenAuthenticatedFile` is the caller-pinned full-file
path that authenticates the file before calling this primitive. `ValidateFile`
still treats `wrapped_cek` as opaque bytes and never unwraps it.

## VUK device-slot envelope

Each approved read-capable device carries the epoch VUK in one existing
`vuk_device_slots[i].wrapped_vuk` (`DeviceSlot.WrappedVUK`). The VUK is one
per-library, per-epoch 32-byte value (`CEKSize`) chosen by the caller; it is
not derived from any password, root key or device key. Two functions implement
exactly that envelope:

```
SealVUKForDevice(vuk []byte, vaultID string, keyEpoch uint64, deviceID, recipient string) (DeviceSlot, error)
OpenVUKForDevice(slot DeviceSlot, expectedVaultID string, expectedKeyEpoch uint64, expectedDeviceID, expectedRecipient string, identity *age.X25519Identity) ([]byte, error)
```

- `vuk` is exactly 32 bytes. `vaultID` must be a `validID` value of at most
  `MaxIDLength` (64), `keyEpoch` must be positive, `deviceID` a `validID` value
  of at most `MaxDeviceIDLength` (128), and `recipient` a canonical age X25519
  recipient. All of them are caller inputs.
- `SealVUKForDevice` returns the `DeviceSlot` with `device_id` and `recipient`
  exactly as given and `wrapped_vuk` the age envelope of the plaintext below.
  It clears the envelope plaintext (VUK included) on every path. No other
  `DeviceSlot` field, wire member or vector changes.
- `OpenVUKForDevice` returns the 32-byte VUK, caller-owned; the caller clears
  it after use.

The envelope is a standard age file produced by `age.Encrypt` for exactly one
`age.X25519Recipient` and opened by `age.DecryptReaderAt` with exactly one
`age.X25519Identity`. The plaintext is a fixed, unambiguous byte layout:

```
plaintext = "locklark.vault-file/v1/vuk-device-wrapping" || 0x00
            || uint16_be(len(vault_id))   || vault_id
            || uint64_be(key_epoch)
            || uint16_be(len(device_id))  || device_id
            || vuk(32)
```

The purpose label is `DomainVUKDeviceWrapping` followed by exactly one NUL, as
in `DomainSeparated`. The two length fields are unsigned 16-bit big-endian
values; the ID limits above keep both within a `uint16`. The epoch is an
unsigned 64-bit big-endian positive value in the wire `key_epoch` domain. age
has no associated-data parameter, so the label and context travel inside the
age-authenticated plaintext and are checked after the envelope opens. No
custom crypto, key derivation, extra dependency or second recipient is used.

The context binds the vault, key epoch and device. It deliberately contains no
content sequence and no `op_id`: one device slot is reused by every content
snapshot of the same epoch, so adding them would force a rewrap per snapshot.
Changing the key epoch (and any new VUK for it) requires a new wrap for every
device.

**Trust boundary.** The expected vault id, epoch, device id and recipient
passed to `OpenVUKForDevice` are independent caller inputs; the expected
recipient must come from an already authenticated policy (for example the
current policy authenticated by `VerifyPolicyCheckpoint`). `slot.device_id` and
`slot.recipient` are never the trust source. The call requires:

- `slot.device_id == expectedDeviceID`;
- `slot.recipient == expectedRecipient`;
- `expectedRecipient == identity.Recipient().String()`;

and then, after the envelope opens, the decrypted label and context compared
in constant time against all expected values. Only then is the VUK returned.

The read is bounded and authenticated: an empty or over-`MaxWrappedKeyLength`
`wrapped_vuk` is rejected before any decryption, `age.DecryptReaderAt` receives
exactly `len(wrapped_vuk)`, the decrypted length must equal the exact expected
label, context and VUK length and exactly that many bytes are read, and any
appended trailing ciphertext fails the age final-chunk authentication.

| Argument                  | Rejected with                                    |
| ------------------------- | ------------------------------------------------ |
| `vuk` not 32 bytes        | `invalid_value` at `""`                          |
| `vault_id`, `key_epoch` or `device_id` invalid | `invalid_value` at `vault_id`, `key_epoch` or `device_id` |
| `recipient` not canonical age X25519 | `invalid_value` at `recipient`         |
| nil identity (open only)  | `invalid_value` at `identity`                    |

Every envelope or context failure of `OpenVUKForDevice` is the one code
`vuk_envelope_failed`, an `*Error` at `vuk_device_slot`: slot device or
recipient mismatch, identity recipient mismatch, a wrong caller expectation, a
malformed, empty, oversized or tampered envelope, appended bytes, a
non-matching decrypted label or context, and a wrong plaintext length. A
caller cannot tell a wrong recipient from a wrong context or tampering. On any
error the returned VUK is nil.

**Zeroization.** Both functions clear the package-owned buffers on every path,
success and failure: `SealVUKForDevice` clears its envelope plaintext (VUK
included), and `OpenVUKForDevice` clears the plaintext it reads (VUK included)
and the expected-context buffer. This is an honest limitation, not a full wipe:
`age.DecryptReaderAt` authenticates and decrypts the final chunk inside its
cached reader and retains that plaintext for the life of the reader; the public
age API exposes no method to clear it, so this package cannot clear that
internal age copy. No custom crypto or unsafe code is used to attempt it.

**Errors.** Any age error, such as a short write of the header or plaintext to
the output, is returned as is, not as a validation `*Error`. On error
`SealVUKForDevice` returns the zero `DeviceSlot` and a non-nil error. If
`age.Encrypt` unexpectedly returns a nil writer with a nil error, the function
returns an explicit operational error, never a nil error with a zero slot. age
v1.3.2 does not report a `crypto/rand` failure that way: that nil-writer guard
covers an undocumented contract violation, not a known failure mode.

**Size.** At `MaxIDLength` (64) and `MaxDeviceIDLength` (128) the plaintext is
`42 + 1 + (2 + 64 + 8 + 2 + 128) + 32 = 279` bytes, which fits one age chunk;
the envelope is well within `MaxWrappedKeyLength` (512).

This primitive does not generate, load or rotate the VUK or key epoch, does
not perform an invitation or epoch rewrap workflow, does not authenticate a
policy itself (the expected recipient is trusted only as the caller's input),
does not scope CEK epoch rotation, and does not serialize, encrypt or decrypt
KDBX content or open a full file. `OpenAuthenticatedFile` is the caller-pinned
full-file path that authenticates the current policy and then calls this
primitive. `ValidateFile` treats `wrapped_vuk` as opaque bytes.

## KDBX payload sealing and opening

Each content snapshot's KDBX content is one KDBX 4.1 database encrypted with
the snapshot's 32-byte CEK as its key credential. Two functions implement
exactly that payload, using the vendored gokeepasslib encoder and its bounded
decoder (no custom cryptography or parser):

```
SealKDBXPayload(db *kdbx.Database, cek []byte) (encoded []byte, err error)
OpenKDBXPayload(ciphertext, cek []byte) (db *kdbx.Database, err error)
```

- `cek` is exactly 32 bytes (`CEKSize`); the package neither generates nor
  loads it. Seal never modifies the caller's `cek`; Open copies it and clears
  that package-owned copy on every return.
- `pkg/vaultfile` imports only the vendored `gokeepasslib` public API for
  this: no internal package, no vendored-internal import, no unsafe or
  linkname code.

### Fixed KDBX profile

Seal sets one profile on the header before encoding, replacing any prior KDF
settings. Open accepts whatever the bounded decoder and its KDF guard accept;
it does not require this exact profile. The guard accepts a KDBX4 header whose
KDF is Argon2d or Argon2id with version `0x13`, iterations 1..10, parallelism
1..8, and memory from `parallelism*8 KiB` through 128 MiB inclusive that is a
multiple of 1024 bytes, with no SecretKey or associated data. It rejects every
other KDF, version, iteration or parallelism count, memory value, SecretKey or
associated data before any Argon2 allocation. The Seal profile below is one
point in that range, not a requirement for Open.

| Member | Value |
| ------ | ----- |
| Signature | KDBX 4.1 (`DefaultKDBX41Sig`) required on input and kept |
| KDF | Argon2id (`KdfArgon2id`) |
| KDF version `V` | `0x13` |
| Memory `M` | 16 MiB |
| Iterations `I` | 3 |
| Parallelism `P` | 2 |
| Rounds `R` | 0 |
| Secret key `K`, associated data `A` | absent |
| Salt `S` | the header's existing random 32-byte salt; an all-zero or absent salt receives a fresh `crypto/rand` 32-byte salt |
| Header cipher | the header's cipher (vendored default ChaCha20), unchanged |
| Compression | the header's flag (vendored default gzip), unchanged |

`*kdbx.Database` values are opaque buffers owned by the caller, so how the
caller obtained one and whether its header matches the file or revision it is
sealed under is outside this API. Seal does not copy `db` or its content,
backs no durable bytes up, and cannot roll back a failed encode.

### Seal: input state, locking and mutation

Seal's accepted input is an unlocked/plaintext database in the state Open
returns and the internal writer (`writeItems`) produces: `Value.Protected` set,
protected values in plaintext. It does not accept a pre-locked database.

- Seal rejects a nil database, a nil `Header`, `Signature`, `FileHeaders`,
  `Hashes`, `Content`, `Meta`, `Root` or `InnerHeader`, a signature that is
  not KDBX 4.1, a root without exactly one group, a missing inner random
  stream key, and a `cek` of any length other than 32, all as
  `kdbx_payload_invalid` before the database is modified. `Hashes` is
  required because the KDBX4 encoder dereferences it.
- Seal copies `cek` into package-owned storage, builds a key credential from
  that copy and installs it as `db.Credentials` for the duration of the call,
  calls `db.LockProtectedEntries()` exactly once on the plaintext protected
  values, and only then calls the encoder. The encoder assumes protected
  values are already locked and unlocks and relocks them under its own
  established contract. This is the same lock-before-encode flow the existing
  snapshot and export callers use.
- Any prior `db.Credentials` value (nil, password, key, Windows, or a
  credential for another key) is accepted. The exact prior pointer and its
  bytes are restored on every return, success and error alike; the
  package-owned key copy is cleared.
- The database is mutated: header KDF parameters, KDBX metadata, timestamps,
  header hashes and binary cleanup/renumbering change, and protected entries
  are left locked at the current inner-stream position (Seal's lock, then the
  encoder's unlock and relock). The mutation happens even when the output cap
  rejects the encoding. Callers must have exclusive use of `db` for the call.
  On error `db` may be partially modified and locked.
- After Seal the database is locked; callers that need it in plaintext again
  unlock it themselves.

### Open: prechecks, decode limits and timing

Prechecks run before any decoding. An input longer than
`MaxKDBXCiphertextBytes` (16 MiB + 64 KiB, the plaintext budget plus the
64 KiB envelope overhead) is `kdbx_payload_too_large`. An empty input, one
without the exact KDBX 4.1 signature, or a `cek` that is not 32 bytes is
`kdbx_payload_invalid`.

The committed bounded decoder (`Decoder.DecodeWithLimits`) then runs with
`MaxEncodedBytes = MaxKDBXCiphertextBytes` and
`MaxPlaintextBytes = MaxPlaintextBytes`:

| Stage | Bound and where it applies |
| ----- | -------------------------- |
| encoded input | read at most `MaxKDBXCiphertextBytes + 1` bytes; over it is rejected before the header is parsed |
| KDBX version | a header that is not KDBX 4 (such as KDBX 3.1) is rejected right after parsing and before any legacy AES round |
| header hash | the header SHA-256 is checked before key derivation |
| KDF guard | the credentials KDF check accepts only KDBX4 Argon2d or Argon2id, version `0x13`, iterations 1..10, parallelism 1..8 and memory from `parallelism*8 KiB` through 128 MiB inclusive and divisible by 1024 bytes, with no SecretKey or associated data; any other value is rejected before any Argon2 allocation. It does not require the fixed Seal profile |
| header HMAC | checked before content decryption |
| content blocks | bounded by the encoded budget; each block HMAC is verified |
| decrypted/gzip body | the decrypted content, or its gzip expansion, is rejected after key derivation and decryption but before XML decoding. The budget is cipher-specific. With `NoCompressionFlag` and AES, a valid 1..16-byte PKCS#7 suffix (including a full 16-byte block) is removed from the end of the decrypted content and excluded from the budget; with `NoCompressionFlag` and ChaCha20 or Twofish, every decrypted byte is kept and counted, including the 1..16 repeated-count bytes the legacy writer appends for them; the decoder removes a valid suffix only for AES. Gzip content is budgeted by its expansion only; trailing block padding is read by neither and is excluded |
| InnerHeader binaries | the aggregate binary bytes (protection flag included) are bounded by `MaxPlaintextBytes` and rejected before an over-budget binary is copied, after key derivation and decryption |

The last two budgets can only be evaluated after the validated, bounded
Argon2d/Argon2id derivation; they bound memory and CPU after it, not before
the derivation. A successful Open returns protected values unlocked (the state
Seal accepts), with `Credentials` set to an empty value. Open clears its CEK copy; temporaries
allocated inside the vendored crypto, gzip and XML code are opaque and cannot
be cleared through its public API.

### Errors, size and ownership

| Code | Meaning |
| ---- | ------- |
| `kdbx_payload_invalid` | every rejected input and every KDBX failure: a nil or malformed database, a header that is not KDBX 4.1, a CEK of the wrong length, a wrong CEK, tampered or malformed bytes, an unsupported KDF, a block or header authentication failure |
| `kdbx_payload_too_large` | input above `MaxKDBXCiphertextBytes`; a sealed plaintext body above `MaxPlaintextBytes`; a decoded or gzip-expanded body above `MaxPlaintextBytes`; aggregate InnerHeader binary bytes above `MaxPlaintextBytes`; an encoded output above `MaxKDBXCiphertextBytes` |

Both are `*Error` values created per call. The invalid code is intentionally
one code for all failures so a caller cannot distinguish a wrong key from
corrupted content; neither error embeds input data or key bytes. Seal returns
bytes only with a nil error and nil bytes on error; Open returns a database
only with a nil error and nil on error.

The decoder's expanded-body budget would otherwise let Seal produce a payload
that Open rejects. Seal therefore also bounds the encoder's plaintext body:
the encoder's opt-in `Encoder.EncodeWithLimits` measures the serialized KDBX4
plaintext (the InnerHeader followed by the XML document, after the encoder's
normalization and protected-entry ordering) and enforces `MaxPlaintextBytes`
on its writes before gzip compression and encryption. The encoded bytes are
unchanged: the legacy writer always appends 1..16 repeated-count padding
bytes before encryption, for every cipher. With `NoCompressionFlag` and AES a
body of exactly `MaxPlaintextBytes` still seals and opens, because Open removes
the PKCS#7 suffix; with `NoCompressionFlag` and ChaCha20 or Twofish the budget
also reserves those writer padding bytes, since Open retains and counts every
non-AES decrypted byte, so an encode at budget `M` admits a
body of at most `floor(M/16)*16-1` bytes and its output opens under the same
`MaxPlaintextBytes` with the padded decrypted bytes intact; `M` below 16 is
rejected. Gzip content is budgeted as before. The XML streams into that
bounded collector, so no separate full XML slice from `xml.MarshalIndent` is
built before the budget is enforced; the collector itself retains the serialized
document up to its budget. A body over it, such as
a highly compressible value that still expands the document past the budget,
is `kdbx_payload_too_large` with no output. The encoder keeps its established
write order, so by then the KDBX header and hashes have already been written to
Seal's collector; the collector is bounded and released on every error, so no
output is returned.

Seal collects output in a bounded buffer: at most `MaxKDBXCiphertextBytes` is
retained, and an encoding that would exceed it is `kdbx_payload_too_large`
with no output (collected bytes are cleared). The returned bytes are
caller-owned.

### Trust boundary

These are low-level payload APIs, not a trusted full-file open. They establish
only that the bytes are a KDBX 4.1 database sealed under the caller-supplied
CEK, that its header and content blocks authenticate under that key, and that
its blocks and bodies stay within the budgets above. They do not authenticate
a file: they do not pin vault, revision, `content_seq`, `op_id` or digest,
verify the content signature, policy proofs or a `PolicyCheckpoint`, unwrap or
authorize the VUK or CEK slot, or establish freshness. The CEK used as the KDBX
key is bound to no wire field. `SealAuthenticatedFile` is the caller-pinned
full-file seal (see [Trusted full-file seal](#trusted-full-file-seal)): it
authenticates the draft's policy chain before any wrapping, and calls
`SealKDBXPayload` with the CEK `SealCEK` generated for that snapshot.
`OpenAuthenticatedFile` is the caller-pinned full-file open: it authenticates
the file, resolves the device from the authenticated current policy, opens the
VUK and CEK slots, and only then calls `OpenKDBXPayload`.

## Trusted full-file seal

```
SealAuthenticatedFile(draft *File, db *kdbx.Database, checkpoint *PolicyCheckpoint, vuk []byte, authorPrivateKey ed25519.PrivateKey) ([]byte, error)
```

`SealAuthenticatedFile` is the package's caller-pinned authenticated file-seal
path and the sealing counterpart of [`OpenAuthenticatedFile`](#trusted-full-file-open).
It returns the canonical sealed bytes only after the exact sequence below
succeeds; every failure returns `nil, err`. `draft` is a builder `File` (protocol
`format` and `version`, the header, and the signed policy proofs), `vuk` is the
caller-owned 32-byte epoch VUK, `authorPrivateKey` is the author device's
Ed25519 private key, `db` is an unlocked KDBX 4.1 database in the state
[`SealKDBXPayload`](#kdbx-payload-sealing-and-opening) accepts, and `checkpoint`
is the caller's already-trusted `PolicyCheckpoint`.

The order is fixed and is the security boundary. Steps 1 to 4 are pure checks
with no cryptographic side effect: nothing is wrapped, no CEK is generated and
no KDF, compression or encryption runs before they pass.

1. **Basic inputs.** A nil `draft`, `checkpoint`, `db` or `vuk`, a draft
   `format` or `version` other than the protocol's, an invalid header
   (`ValidateHeader`) and a `vuk` that is not exactly 32 bytes (`CEKSize`) are
   rejected as `invalid_value` at the empty path (or at `key_epoch`).
   `draft.content_encoding` is a builder value: empty means `kdbx`, and any
   non-empty value other than `kdbx` is `invalid_value` at
   `content_encoding`.
2. **Caller pin and policy chain.** `verifyPolicyChain(draft.header,
   draft.signed_policy_proofs, checkpoint)` is the single policy-chain verifier
   shared with `VerifyPolicyCheckpoint`. Its deep-cloned authenticated current
   policy is the only roster and key source for the rest of the call. A
   missing or wrong pin (`policy_checkpoint_failed`), an invalid policy
   signature (`signature_verify_failed` at the proof), a forbidden delegated
   diff, or a malformed or unbound proof returns `nil` bytes before any device
   recipient is used. The draft's own `vuk_device_slots`, `cek_slot`,
   `kdbx_ciphertext`, `content_signature` and `revision_id` are untrusted and
   are never read as trust.
3. **Author.** The header's `author_device_id` is resolved in the
   authenticated current policy, and its principal must hold the writer,
   admin or owner role. The device's authenticated content signing key must be
   Ed25519, and `authorPrivateKey` must be exactly `ed25519.PrivateKeySize`
   bytes whose public key equals that key. A mismatch of any kind is
   `author_signing_key_mismatch` at `content_signature`, before any VUK
   wrapping or KDF. No candidate roster or key from the draft is used.
4. **Sealing state.** `key_epoch` must be positive (`invalid_value` at
   `key_epoch`);
   `ValidateHeader` already enforces that, so this step only makes the
   requirement explicit before step 5 binds the epoch into every envelope.
   The VUK length was checked in step 1.
5. **VUK slots.** On a deep local copy of the draft, `vuk_device_slots` is
   replaced by exactly one `SealVUKForDevice(vuk, checkpoint.vault_id,
   header.key_epoch, device_id, recipient)` per read-capable device of the
   authenticated current policy, in the wire's canonical strictly ascending
   `device_id` order. Each recipient is the authenticated policy's
   `Device.age_encryption_key`, never a carried `DeviceSlot.Recipient`, and each
   call generates a fresh age envelope. The caller's draft, its roster and its
   derived fields are never modified.
6. **CEK and payload.** `SealCEK(vuk, header)` generates a fresh random
   per-snapshot CEK and its `cek_slot`, and `SealKDBXPayload(db, cek)` encrypts
   the database under it. The CEK is package-owned and cleared on every
   return path; the caller's VUK and private key are never modified and never
   retained. `db` is mutated and its exact prior `Credentials` pointer and
   contents are restored as `SealKDBXPayload` documents.
7. **Signature and file.** `ContentSigningBytes` of the completed draft is
   signed with `authorPrivateKey` over `locklark.vault-file/v1/content-signature
   || 0x00 || bytes`; `SealFile` derives `revision_id` and writes the content
   signature; `ParseFile` re-parses the canonical result.
8. **Final verification.** `VerifyPolicyCheckpoint(sealed, checkpoint)` must
   accept the finished file before its bytes are returned. This final check is
   in addition to, never instead of, step 2.

**Generated values.** The seal generates one per-snapshot CEK, one age VUK
envelope per current read device, the content signature, and the derived
`revision_id`. **Zeroization and credential boundary.** The package-owned CEK
and every package-owned envelope plaintext (VUK included) are cleared on every
path; age keeps its own unexported plaintext copies that this package cannot
reach, as documented for the primitives. The VUK and author private key stay
caller-owned. The generated file retains no passphrase, key file, private key
or decrypted KDBX content; `db.Credentials` is restored on success and error.

**Trust limits.** The seal supplies no trust of its own. It seals only under a
policy chain the caller's checkpoint already anchors: the caller supplies the
VUK and the key epoch, and an already signed policy chain. It does not
generate or rotate the VUK or epoch, does not create policy changes,
invitations or device adds, does not perform an invitation or epoch rewrap,
and does not establish server freshness or content history through
`prev_digest`. A named negative returning `nil` bytes proves only which check
rejected the input. The corresponding open path is
[`OpenAuthenticatedFile`](#trusted-full-file-open).

**VUK reuse after a device removal.** The API accepts a caller-supplied VUK
and epoch and does not rotate them. When the device is removed from the
authenticated current policy, the newly sealed file omits its slot, and the
current `OpenAuthenticatedFile` call rejects that unknown device with
`invalid_value` at `device_id`; this does not revoke a VUK that device already
learned. If that same VUK is reused, the device can
still use the low-level [`OpenCEK`](#cek-sealing-and-opening) with the new
`cek_slot` to recover the new per-snapshot CEK, and then
[`OpenKDBXPayload`](#kdbx-payload-sealing-and-opening) to decrypt the new
payload. Cryptographic reader revocation requires a separate rotation to a
fresh VUK, together with a protocol epoch advance, so that new envelopes and
CEK slots are bound to a key the removed device never held. This API does not
implement that rotation: after a device removal it produces a file that binds
the current policy, not one from which the removed device's knowledge of the
VUK has been cryptographically withdrawn.

## Trusted full-file open

```
OpenAuthenticatedFile(encoded []byte, checkpoint *PolicyCheckpoint, deviceID string, identity *age.X25519Identity) (*File, *kdbx.Database, error)
```

`OpenAuthenticatedFile` is the package's caller-pinned authenticated file-open
path. It returns both the parsed sealed `*File` and the unlocked
`*kdbx.Database` only after the exact sequence below succeeds; every failure
returns `nil, nil, err`.

1. `ParseFile(encoded)` performs the bounded canonical structural validation
   and no decryption. A structural error is returned unchanged. `ValidateFile`
   requires `vuk_device_slots` to be exactly the current policy's read-capable
   device set, so a missing required slot is structurally rejected here as
   `invalid_value` at the empty path, before any checkpoint verification or
   VUK unwrapping. `ValidatePolicy` likewise requires every listed device's
   principal to hold a read-capable role, so a policy device whose principal has
   no such role is also structurally rejected here as `invalid_value` at the
   empty path and never reaches step 3.
2. `VerifyPolicyCheckpoint(f, checkpoint)` authenticates the caller-pinned
   root and policy continuation and the content signature. The policy and slot
   roster carried in the file are untrusted until this succeeds. Its error is
   returned unchanged, for example `policy_checkpoint_failed` or
   `signature_verify_failed`.
3. Only after step 2, the caller's device is resolved in the authenticated
   current policy, together with its expected age recipient
   (`Device.AgeEncryptionKey`). Neither the carried proposal roster nor
   `DeviceSlot.Recipient` is a trust source. An unknown caller device ID,
   absent from the authenticated current policy, is `invalid_value` at
   `device_id`. A device in a valid parsed policy already necessarily has
   reader-or-stronger access, because step 1 rejects any policy device whose
   principal lacks a read-capable role.
4. `OpenVUKForDevice(slot, checkpoint.VaultID, f.Header.KeyEpoch, deviceID,
   authenticatedRecipient, identity)` opens the caller device's VUK slot. The
   vault id is the caller's pinned id, the epoch is from the authenticated
   header, and the device id and recipient are from the authenticated current
   policy; the slot's own device and recipient fields must match those inputs.
   Step 1 already rejected a missing required slot and step 3 already rejected
   a caller device absent from the authenticated policy, so only a present,
   authenticated device slot reaches this call: its
   envelope/context failures are `vuk_envelope_failed` at `vuk_device_slot`.
   A nil identity or malformed caller input is an `invalid_value` from
   `OpenVUKForDevice`.
5. `OpenCEK(vuk, f.Header, f.CEKSlot)` opens the CEK with the authenticated
   header and the file's CEK slot; any envelope failure is
   `cek_envelope_failed` at `cek_slot`.
6. `OpenKDBXPayload(f.KDBXCiphertext, cek)` opens the KDBX payload; its error
   is returned unchanged.

The VUK and CEK are package-owned during the call and are cleared on every
path after use, success and failure alike. The returned `*File` is the parsed
sealed wire file; the returned `*kdbx.Database` is in the unlocked state that
`SealKDBXPayload` accepts, with no retained credentials. The caller owns both.

**Trust limits.** This path authenticates only what the caller already pinned.
It does not establish the provenance or server freshness of the checkpoint,
proof of complete content history through `prev_digest`, epoch or key
generation, key rotation, an invitation or rewrap flow, or that the KDBX
content is otherwise trustworthy. It is only a caller-pinned authenticated
file-open path, not a sealing, sync or freshness API.

## Limits

None of these APIs establishes overall vault trust beyond its caller-supplied
anchor. `VerifyContentSignature` and `VerifyPolicyCheckpoint` do not verify
content history through `prev_digest`, server freshness or ordering across
snapshots, encryption or decryption, the VUK device-slot envelope or the CEK
envelope, or the age rewrap of the invitation and epoch keys for newly invited
readers (CEK sealing/opening and VUK device wrapping are only the separate
primitives of [CEK sealing and
opening](#cek-sealing-and-opening) and [VUK device-slot
envelope](#vuk-device-slot-envelope), which authorize no file and authenticate
no policy), or the authenticity of anything the caller did not pin.
`OpenAuthenticatedFile` does perform the VUK/CEK/KDBX open, but only on the
caller-pinned authenticated path above and with the same trust limits. None of
the verification APIs cryptographically
reverify the carried anchor proof's signature; that signature is trusted only
through the caller's checkpoint digest. The chain does authenticate the
delegation fields (`owner_root`, `admin_delegations` and its `scope`) carried in
the authenticated policy documents. The only delegated authority it exercises
is `invite_readers`, and only through the narrow
`inviteReadersPolicyDiff` transition of [Admin-delegated
InviteReaders](#admin-delegated-invitereaders-transitions), which is checked in
the authenticated predecessor policy, never in the successor. Every other
delegated scope (`invite_writers`, `remove_members`, `remove_devices`,
`promote_admin`; `promote_owner` and `replace_root` are forbidden by
`ValidatePolicy`), invite-writer addition, removal or role change, and any
key or root change remains unsupported and must be root-signed. Beyond that
checkpoint-scoped current-author check and the InviteReaders diff, no
authorization is implemented. In particular:

- `VerifyContentSignature` does not authenticate policy proofs or authorize
  the current policy; it proves only that a caller-pinned key signed this
  file's content.
- `VerifyPolicyCheckpoint` proves only that the file and its proofs continue a
  checkpoint and root the caller already trusts, that each continuation is
  root-signed or an authorized delegated `InviteReaders` transition, and that
  the content was signed by a device of a writer, admin or owner of the
  authenticated current policy. It does not establish the trustworthiness or
  provenance of the checkpoint, the owner root or its key, does not perform
  the invitation or key rewrap a new reader would need, and does not accept
  any other admin-signed transition.
- `SealCEK`/`OpenCEK` establish only that a CEK slot was wrapped under, and
  opens with, a caller-supplied VUK and the bound header. They do not
  authenticate a policy, signature or revision id (`revision_id` is not
  bound), do not prove freshness or uniqueness of a VUK, do not bind a CEK to
  KDBX bytes, and do not open a file.
- `SealVUKForDevice`/`OpenVUKForDevice` establish only that a device slot
  carries a VUK authentically wrapped for the caller's expected vault, epoch,
  device and recipient under the caller's identity. They do not generate,
  rotate or prove the freshness or uniqueness of a VUK or epoch, do not
  authenticate the policy the expected recipient came from, do not authorize a
  device or a file, and do not open a file.
- `SealKDBXPayload`/`OpenKDBXPayload` establish only that the bytes are a
  KDBX 4.1 database sealed under, and opened by, the caller-supplied CEK and
  within the payload budgets. They bind no vault, revision, digest or
  signature, do not verify a policy or checkpoint, do not unwrap a CEK slot
  or VUK, and are not the full-file open path (see [KDBX payload sealing and
  opening](#kdbx-payload-sealing-and-opening)).
- `OpenAuthenticatedFile` proves only the ordered result of [Trusted full-file
  open](#trusted-full-file-open): a caller-pinned checkpoint authenticates the
  file, the authenticated current policy names the caller device and
  recipient, and those keys open the VUK, CEK and KDBX payload. It establishes
  nothing about the provenance or freshness of the checkpoint, complete content
  history through `prev_digest`, epoch/key generation or rotation, or an
  invitation or rewrap flow.
- `SealAuthenticatedFile` proves only the ordered result of [Trusted full-file
  seal](#trusted-full-file-seal): the draft's policy chain continues the
  caller's checkpoint, the author key is the authenticated current policy's
  content signing key for the header's author device, the VUK is wrapped for
  exactly that policy's read-capable devices, and the finished file verifies
  under the same checkpoint. It supplies the VUK and epoch instead of
  generating or rotating them, creates no policy change or invitation, and
  establishes nothing about the provenance or freshness of the checkpoint or
  content history through `prev_digest`.

## Budgets

| Limit                                                  | Value    |
| ------------------------------------------------------ | -------- |
| `MaxFileBytes`                                         | 32 MiB   |
| `MaxPlaintextBytes`                                    | 16 MiB   |
| `MaxKDBXCiphertextOverhead`                            | 64 KiB   |
| `MaxSignedPolicyProofBytes`                            | 256 KiB  |
| `MaxJSONDepth`                                         | 8        |
| `MaxObjectMembers`                                     | 16       |
| `MaxJSONNodes`                                         | 524288   |
| `MaxArrayItems`                                        | 128      |
| `MaxPolicyArrayItems`                                  | 64       |
| `MaxDelegations`                                       | 64       |
| `MaxDeviceSlots`                                       | 128      |
| `MaxIDLength`                                          | 64       |
| `MaxDeviceIDLength`                                    | 128      |
| `MaxKeyIDLength`                                       | 64       |
| `MaxLabelLength`                                       | 128      |
| `MaxRoleScopeLength`                                   | 256      |
| `MaxSignatureLength`                                   | 4 KiB    |
| `MaxWrappedKeyLength`                                  | 512      |
| `MaxPublicKeyLength`                                   | 1024     |

The object-member and aggregate-node checks run before the decoder requests or
decodes the next key or value token, so an input over either budget is rejected
as `too_many_members` or `too_many_nodes` without decoding the token beyond it.
Object keys do not count as nodes. Both counts reset per input: each
`ParseFile` or `ParsePolicyDocument` call starts from zero.

## Encoding vectors

`pkg/vaultfile/testdata/vaultfile-v1-vectors.json` holds one fixed synthetic
vector, `v1-canonical` (`state: sealed`). It is the only entry:
there is no serialized unsigned-draft fixture, because a draft has no wire
bytes.

Signature and wrapped-key bytes are shaped, not valid. The vector records, for
exactly these bytes: `file`, `file_sha256`, `revision_id`,
`revision_domain_input` (the unhashed `RevisionID` input),
`content_signing_input` and `content_signing_input_sha256`,
`policy_document`, `policy_document_sha256` and `file_digest`. The
in-memory builder draft built from the same content is checked by
`TestWriteVectors` to derive the same `revision_id` and the same
`content_signing_input`, and is checked to be rejected by `EncodeFile` and
`FileDigest`. Regenerate with:

```
go test ./pkg/vaultfile/... -run TestWriteVectors -update
```

`TestVectors` verifies that every vector is sealed, that re-encoding reproduces
the vector bytes and that every recorded value is reproduced.
`TestRevisionPreimageOmitsRevisionID`, `TestContentSigningPreimage`,
`TestSealedEncodingMembers`, `TestRevisionPreimageFixedVector`,
`TestSealFileSealed`, `TestSealFileNilRejected`, `TestDraftRejectedByWire` and
`TestDraftShapeRules` in `pkg/vaultfile/signing_test.go` pin the exact JSON
members of every preimage, the builder draft and the sealed file, and that
`ParseFile`, `EncodeFile`, `FileBytes`, `ValidateFile` and `FileDigest` reject
the draft, independently of the vector file.

`TestParseFileRequiresCanonicalBytes` and
`TestParsePolicyDocumentRequiresCanonicalBytes` in
`pkg/vaultfile/canonical_test.go` pin that canonical bytes round-trip and that
leading, trailing or inter-member whitespace, reordered members and an
equivalent string escape are each rejected as `non_canonical`.
`TestProofWithNonCanonicalDocumentRejected` pins that a proof carrying a
non-canonical `document` is rejected, before any policy binding is considered.

`TestVUKPlaintextLayout` and `TestVUKMaxIdentifierBoundary` in
`pkg/vaultfile/vuk_test.go` pin the exact VUK envelope plaintext and the
`MaxIDLength` / `MaxDeviceIDLength` size boundary; the remaining `TestVUK*`
tests use real generated `age.X25519Identity` values and real age ciphertext for
the round trip and each [VUK device-slot
envelope](#vuk-device-slot-envelope) negative.

## Out of scope

This schema revision includes the two verification APIs described above,
`VerifyContentSignature` (narrow, caller-pinned content key) and
`VerifyPolicyCheckpoint` (from a caller-supplied `PolicyCheckpoint` forward),
the caller-pinned full-file seal `SealAuthenticatedFile` ([Trusted full-file
seal](#trusted-full-file-seal)) and open `OpenAuthenticatedFile` ([Trusted
full-file open](#trusted-full-file-open)), two key-wrapping primitives,
`SealCEK`/`OpenCEK`
([CEK sealing and opening](#cek-sealing-and-opening)) and
`SealVUKForDevice`/`OpenVUKForDevice` ([VUK device-slot
envelope](#vuk-device-slot-envelope)), and the low-level
`SealKDBXPayload`/`OpenKDBXPayload` payload pair ([KDBX payload sealing and
opening](#kdbx-payload-sealing-and-opening)).
`ValidateFile`, parsing, encoding and preimage derivation remain shape-only.

It does not establish or create the trustworthiness or provenance of the
caller's checkpoint, owner root or pinned key, and it does not
cryptographically reverify the anchor proof's signature. The authenticated
chain does cover the delegation fields carried in the authenticated policy
documents, but the only authorization it implements is the delegated
`InviteReaders` transition of [Admin-delegated
InviteReaders](#admin-delegated-invitereaders-transitions): adding readers and
their devices under an active `invite_readers` grant in the authenticated
predecessor. Every other scope mapping (invite writers, remove members or
devices, promote admin) and every removal, role change, key or root change is
unsupported and out of scope, and a full invitation or epoch key rewrap is not
performed. Beyond the checkpoint-scoped current-author check and that one
delegated diff it implements no other policy proof, signature-chain or
authorization verification and no permission checks. It also leaves the
provenance of the caller's root outside its scope, key or digest crypto
beyond the definitions, content history through `prev_digest`, server
freshness, migration/import, VUK and epoch generation or rotation, the
invitation and epoch rewrap workflow that would produce a new VUK or epoch for
changed device sets, or product wiring. `SealAuthenticatedFile` seals under an
existing signed chain with a caller-supplied VUK and epoch, and
`OpenAuthenticatedFile` is only the ordered caller-pinned open above:
it does not claim server freshness, complete content history through
`prev_digest`, checkpoint provenance, epoch/key generation or an invitation
flow. The VUK device-slot envelope of [VUK device-slot
envelope](#vuk-device-slot-envelope) wraps only the caller-supplied VUK; it
authenticates no policy and opens no file.
