# locklark.vault-file/v1 Wire Schema

Status: draft. Implemented in `pkg/vaultfile`: structure, canonical codec,
preimage derivation, and two separate verification APIs (see [Verification
APIs](#verification-apis)):

- `VerifyContentSignature`, the narrow check: `ValidateFile` plus the file's
  content signature against a caller-pinned device key. It does not
  authenticate policy proofs and does not authorize the current policy.
- `VerifyPolicyCheckpoint`, the checkpoint-scoped check: given an already
  trusted out-of-band `PolicyCheckpoint` (vault id, owner-root key id and
  public key, policy sequence and digest), which it treats as caller-owned,
  does not retain after the call and whose digest it clones internally, it
  binds the file to that vault,
  authenticates the policy continuation from the pinned digest with
  root-signed proofs (or, with no anchor carried, a first proof exactly at
  checkpoint seq+1 linked to the pinned digest), requires the author's role in
  the current policy to be writer, admin or owner, then verifies the content
  signature with the current policy's device key. A carried anchor proof is
  trusted through the caller's digest alone; its own signature is not
  cryptographically reverified.

Neither API establishes the trustworthiness or provenance of the caller's
checkpoint, root or pinned key; admin-delegated policy transitions (no
scope-to-policy-diff validation is implemented), key wrapping,
encryption/decryption, content history through `prev_digest`, server freshness
and overall vault trust are not implemented. This document describes the wire
format and the frozen v1 preimages; it makes no cryptographic correctness
claim and grants no migration or product permission.

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
- `/vuk-device-wrapping`, `/cek-wrapping`

Identification usage labels (fingerprints only; they never appear in a signing,
revision or file-digest preimage):

- `/vault-id`, `/content-revision-id`, `/op-id`, `/device-id`
- `/key/device-content-signing`, `/key/device-policy-signing`,
  `/key/age-x25519`, `/policy-document`

Labels are identification and purpose separators only. This package does not
sign, wrap or derive any key. The only authorization it checks is
checkpoint-scoped: under a caller-supplied checkpoint, whether the author may
author the authenticated current policy. It has no trust anchor of its own and
does not check delegated authority. It performs signature checks in
exactly two places, both described in [Verification APIs](#verification-apis):

- `VerifyContentSignature` checks one file content signature under the
  `/content-signature` label against a caller-pinned Ed25519 key. It does not
  authenticate policy proofs or authorize the current policy.
- `VerifyPolicyCheckpoint` checks, only relative to a caller-supplied
  `PolicyCheckpoint`, the `/policy-document-signature` proofs that continue the
  pinned digest, each against the pinned owner-root key, and then the
  `/content-signature` signature against the current policy's device key.

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
checkpoint forward, each root-signed by the pinned owner-root key (see
[Verification APIs](#verification-apis)). No other policy proof verification
exists in this schema revision.

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
policy device and carry that device's age recipient. Slots are ordered strictly
ascending by `device_id` (see [Set-like arrays](#set-like-arrays)); there is no
other slot order. Moving a slot changes the revision input and therefore the
revision id, so a file is resealed after reordering.

## Validation scope

`ValidateFile` and every parser, encoder and preimage function are structural
and shape-only. No structural path performs a cryptographic check, and the
package computes no signature.

- signature bytes are checked for presence, length, algorithm and encoding
  only; `ValidateFile` does not verify any signature. Cryptography lives only
  in the two explicit APIs of [Verification APIs](#verification-apis): the
  content signature is verified by `VerifyContentSignature` (pinned key) and by
  `VerifyPolicyCheckpoint` (current policy key), and policy proof signatures
  are cryptographically verified only by `VerifyPolicyCheckpoint`, only for the
  continuation after a caller-supplied checkpoint. That API does not
  cryptographically reverify the anchor proof's signature, though
  `ValidateFile` still checks that proof's structural algorithm and signature
  shape;
- `revision_id` is checked to equal `RevisionID`; it is not a signature;
- wrapped-key bytes are checked for presence and size, never unwrapped;
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
different questions:

| API | Input it trusts | What it establishes |
| --- | ------------------- | ------------------- |
| `VerifyContentSignature` | caller-pinned device id and content key | the sealed file's content signature, for the author device the caller names, under that caller-pinned key |
| `VerifyPolicyCheckpoint` | caller-supplied `PolicyCheckpoint` (vault id, owner-root key id and public key, policy seq and digest) | the file and its proofs belong to that vault, the policy continuation from the pinned digest is signed by the pinned owner root, the author's role in the authenticated current policy is writer/admin/owner, and the content signature verifies under the current policy's device key |

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
admin delegations, policy continuity through `prev_policy_digest`, or that
the signer is authorized by an authenticated policy. It is a narrower check
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
  be root-signed exactly as in the next bullet. A file that carries
  `checkpoint.PolicySeq` with a different digest is rejected rather than treated
  as a continuation.
- **Continuations**: every later proof must carry exactly the previous trusted
  sequence plus one, `prev_policy_digest` equal to the previous trusted
  digest, the pinned owner root and `signer_id` equal to
  `checkpoint.OwnerRootKeyID`, and a `crypto/ed25519` signature,
  over `"locklark.vault-file/v1/policy-document-signature" || 0x00 ||
  SignedPolicy.document`, that verifies under the pinned owner-root public
  key. A failing proof signature is `signature_verify_failed` at
  `signed_policy_proofs[i]`.
- A file whose current policy is behind `checkpoint.PolicySeq` is stale, and
  a carried sequence equal to `checkpoint.PolicySeq` with a different digest
  is a mismatch; vault, anchor, tip, gap, link, root and admin-transition
  failures are `policy_checkpoint_failed`.
- **Authorize and check content**: having authenticated the chain to the
  current policy, the author's principal must be a writer, admin or owner of
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

Admin-delegated policy transitions are **not** supported. A continuation must
be signed by the pinned owner root; a proof signed by any other device is
rejected even when it carries an `AdminDelegation`, because there is no
implemented validation of an admin's `scope` against the old-to-new policy and
delegation diff. A delegated transition is never reinterpreted as a root-signed
one.

## Limits

Neither API establishes overall vault trust beyond its caller-supplied anchor.
Neither verifies content history through `prev_digest`, server freshness or
ordering across snapshots, encryption or decryption, CEK or VUK key wrapping,
or the authenticity of anything the caller did not pin. Neither cryptographically
reverifies the carried anchor proof's signature; that signature is trusted only
through the caller's checkpoint digest. The chain does authenticate the
delegation fields (`owner_root`, `admin_delegations` and its `scope`) carried in
root-signed policy documents, but neither API authorizes delegation: admin-signed
policy transitions and scope-to-policy-diff authorization are unsupported, so
a delegated transition is never accepted. Beyond that checkpoint-scoped
current-author check, no authorization is implemented. In particular:

- `VerifyContentSignature` does not authenticate policy proofs or authorize
  the current policy; it proves only that a caller-pinned key signed this
  file's content.
- `VerifyPolicyCheckpoint` proves only that the file and its proofs continue a
  checkpoint and root the caller already trusts, and that the content was
  signed by a device of a writer, admin or owner of the authenticated current
  policy. It does not establish the trustworthiness or provenance of the
  checkpoint, the owner root or its key, and it does not support admin-signed
  transitions.

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

## Out of scope

This schema revision includes only the two verification APIs described above:
`VerifyContentSignature` (narrow, caller-pinned content key) and
`VerifyPolicyCheckpoint` (from a caller-supplied `PolicyCheckpoint` forward).
`ValidateFile`, parsing, encoding and preimage derivation remain shape-only.

It does not establish or create the trustworthiness or provenance of the
caller's checkpoint, owner root or pinned key, and it does not
cryptographically reverify the anchor proof's signature. The authenticated
chain does cover the delegation fields carried in root-signed policy documents,
but the package does not authorize delegation: admin-signed policy transitions
and scope-to-policy-diff authorization are unsupported (so an `AdminDelegation`
never authorizes a transition), and beyond the checkpoint-scoped current-author
check it implements no other policy proof, signature-chain or authorization
verification and no permission checks. It also leaves key or digest crypto
beyond the definitions, content
history through `prev_digest`, server freshness, migration/import, encryption
or decryption, key wrapping or product wiring.
