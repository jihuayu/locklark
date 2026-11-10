# locklark.vault-file/v1 Wire Schema

Status: draft. Implemented in `pkg/vaultfile` (structure and canonical codec
only). This document describes the wire format; it makes no cryptographic
correctness claim and grants no migration or product permission.

## Background

Earlier drafts labelled this document revision v3, while the public wire
identifier was always required to be `locklark.vault-file/v1`. The design
revision number is a planning label only and never described the wire. Every
protocol identifier in this document, in `pkg/vaultfile` and in
`pkg/vaultfile/testdata/vaultfile-v1-vectors.json` therefore carries the `v1`
token, `version` is `1`, and the schema URI is
`https://locklark.dev/schema/locklark.vault-file/v1`.

## Wire identifiers

| Constant        | Value                                                 |
| --------------- | ----------------------------------------------------- |
| `format`        | `locklark.vault-file`                                 |
| `version`       | `1`                                                   |
| schema URI      | `https://locklark.dev/schema/locklark.vault-file/v1`  |
| MIME type       | `application/vnd.locklark.vault-file+json`            |
| `content_encoding` | `kdbx`                                             |

Every domain-separation label is prefixed with `locklark.vault-file/v1/`:

- `/content-signature`, `/header-signature`, `/policy-document-signature`
- `/admin-delegation`, `/vuk-device-wrapping`, `/cek-wrapping`
- `/vault-id`, `/content-revision-id`, `/op-id`, `/device-id`
- `/key/device-content-signing`, `/key/device-policy-signing`,
  `/key/age-x25519`, `/policy-document`

Labels are identification and purpose separators only. This package neither
signs, verifies, wraps nor derives any key.

## Documents

A vault file is one self-contained canonical-JSON object. Content bytes are
embedded (`kdbx_ciphertext`), never referenced by digest only. In the sync
protocol, `R` is exactly these bytes as read back from the backend.

```
{
  "format":             <format>,
  "version":            <version>,
  "header":             { Header },
  "header_sig":         { Signature },
  "signed_policy_proofs": [ { SignedPolicy } ],
  "content_encoding":   <content_encoding>,
  "kdbx_ciphertext":    <base64url>,
  "vuk_device_slots":   [ { DeviceSlot } ],
  "cek_slot":           { "key_epoch": <int>, "wrapped_cek": <base64url> },
  "content_signature":  { Signature }
}
```

`Header` (the bytes `header_sig` covers):

```
{
  "vault_id":         <id>,
  "key_epoch":        <int>,
  "content_seq":      <int>,
  "revision_id":      <id>,
  "prev_digest":      <base64url sha256> | null,   // null only at content_seq 0
  "op_id":            <id>,
  "policy_seq":       <int>,
  "policy_digest":    <base64url sha256>,
  "author_device_id": <device id>
}
```

`Signature`: `{"signer_id": <id>, "alg": "ed25519", "sig": <base64url 64 bytes>}`.

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
domain label with the NUL separator, as in `DomainSeparated`), from the same
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

`ValidateFile` also checks the cross-member bindings: every policy proof names
the header vault, exactly one proof carries the header policy sequence and its
`policy_digest` (as defined above) equals `Header.policy_digest`, the content
signature names the authoring device, the header signature names a device with
a policy signing key, the CEK slot epoch matches the header epoch, and the
author's principal is a writer, admin or owner.

The VUK slots are exactly the approved devices whose principal has read
access (reader, writer, admin or owner): every such device has one slot and no
other device has any, so no device without a read role is wrapped the VUK and
no read-capable device is left without it. A slot must name a policy device
and carry that device's age recipient.

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
vector named `v1-canonical`. Its signatures and wrapped keys are shaped, not
valid. Regenerate it with:

```
go test ./pkg/vaultfile/... -run TestWriteVectors -update
```

`TestVectors` verifies that re-encoding reproduces the vector bytes and that
the recorded SHA-256 digests of the file, header and policy document still
match.

## Out of scope

This schema revision does not include signature verification, permission
checks, key or digest crypto beyond the fixed `policy_digest` definition,
migration/import or product wiring. Encoding and validation are structural
only and have not been reviewed for cryptographic correctness.
