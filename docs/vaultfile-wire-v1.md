# locklark.vault-file/v1 Wire Schema

Status: draft. Implemented in `pkg/vaultfile` (structure, canonical codec and
preimage derivation only). This document describes the wire format and the
frozen v1 preimages; it makes no cryptographic correctness claim and grants no
migration or product permission.

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

Labels are identification and purpose separators only. This package neither
signs, verifies, wraps nor derives any key.

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
"alg", "sig"}`. `document` is the canonical encoding of `policy`; verification
code re-parses it and requires byte equality with the canonical re-encoding.

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

The genesis policy (`policy_seq` 0) has no predecessor, so its
`prev_policy_digest` is `null`. Any later policy (`policy_seq` > 0) carries
exactly one 32-byte `prev_policy_digest`. Whether a predecessor digest names an
actually known prior policy is a sync decision, not a wire rule.

Role semantics are fixed: the owner root is independent of any device, and
the three device key roles (content signing, policy signing, age encryption)
are distinct and never interchangeable.

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
policy device and carry that device's age recipient. Slot position is not a
rule: moving a slot changes the revision input and therefore the revision id,
so a file is resealed after reordering.

## Validation scope

Validation is shape only:

- signature bytes are checked for presence, length and encoding, never
  verified; the package computes no signature and accepts none;
- `revision_id` is checked to equal `RevisionID`; it is not a signature;
- wrapped-key bytes are checked for presence and size, never unwrapped;
- public keys and age recipients are parsed for shape only;
- whether `prev_digest` or `prev_policy_digest` names a known prior value, and
  whether a signer's principal currently holds the role it claims, are sync
  and authorization decisions outside this codec.

## Budgets

| Limit                                                  | Value    |
| ------------------------------------------------------ | -------- |
| `MaxFileBytes`                                         | 32 MiB   |
| `MaxPlaintextBytes`                                    | 16 MiB   |
| `MaxKDBXCiphertextOverhead`                            | 64 KiB   |
| `MaxSignedPolicyProofBytes`                            | 256 KiB  |
| `MaxJSONDepth`                                         | 8        |
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

## Out of scope

This schema revision does not include signature verification, permission
checks, key or digest crypto beyond the definitions above, migration/import or
product wiring. Encoding and validation are shape-only and have not been
reviewed for cryptographic correctness.
