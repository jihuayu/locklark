# Offline detached publisher attestation verification

This document describes the **offline, public-key-pinned** verifier for a
detached Ed25519 publisher attestation. It is intentionally separate from the
unsigned preparation receipt.

> **Two different checks**
>
> - `python3 -m browserrelease --product ... --output ... --verify` checks that
>   an **unsigned** ZIP and its public receipt are internally self-consistent
>   and match the fixed packaging policy. That is not a signature and does not
>   prove who produced the bytes.
> - `scripts/browser-release-verify` checks a detached Ed25519 signature over
>   the package/receipt digests, source commit, version, product, and repository,
>   using a public key supplied explicitly by the owner. Success means the
>   signature matches **that pinned key** and the actual package/receipt pair
>   passes the existing self-consistency verification.
>
> Neither check is a store-signed release, a real install/update test, or proof
> that the pinned key belongs to the release owner. **No owner public key or
> signed attestation is supplied in this repository**, so no authentic
> owner-release claim is made here.

## Scope and safety properties

The verifier only reads:

- one strict public attestation JSON file, at most 64 KiB;
- one owner-supplied public-key file;
- the fixed package and receipt names derived from `--product` and `--output`.

It never signs, never reads a private key or credential store, never uploads,
never contacts a network, never invokes a shell, and never writes or replaces
an existing file. Package/receipt paths are not supplied by the attestation or
the caller; they are derived from the fixed product allowlist. The public key
is **not** trusted from the attestation, receipt, generated manifest, or output
directory; it must be supplied out of band through `--public-key`.

## Optional dependency and fail-closed behavior

The attestation verifier uses two explicit, pinned dependencies:

```text
scripts/browserrelease/requirements.txt
cryptography==50.0.0
PyNaCl==1.6.2
```

- `cryptography` performs the Ed25519 signature equation itself. The verifier
  delegates all signature math to it and implements no curve arithmetic.
- `PyNaCl` supplies mature libsodium point validation through
  `nacl.bindings.crypto_core_ed25519_is_valid_point`. That call is the gate
  described in the next section.

The unsigned package/receipt preparation path remains dependency-free and does
not import `cryptography` or `PyNaCl`. If either dependency is absent, or if
libsodium reports a minimal build that cannot validate points, attestation
verification fails closed with the fixed refusal:

```text
FAIL: Ed25519 verification dependency is unavailable; install scripts/browserrelease/requirements.txt
```

It does not accept the attestation, does not silently skip signature
verification, and does not fall back to an unvalidated key.

## Point validation and the forged-identity key

Backend Ed25519 verification is not sufficient on its own. With
`cryptography==50.0.0` / OpenSSL, a public key whose encoded bytes are the
identity point (byte `01` followed by 31 zero bytes) combined with the
signature whose `R` is byte `58` followed by 31 bytes `66` (the basepoint
encoding) and whose `S` is byte `01` followed by 31 zero bytes (little-endian
1) verifies **any** message, without any private key. That is a real, reproduced acceptance, so a key or
signature that merely passes the backend is not trustworthy.

Before the backend is consulted, the verifier therefore requires both the
pinned public key and the signature `R` to be valid Ed25519 points, and it
requires the `S` scalar encoding to be canonical. The checks are:

- the encoding is exactly 32 bytes;
- libsodium accepts it as a point on the edwards25519 curve, in canonical
  form, on the main (prime-order) subgroup, and not of small order;
- `S`, decoded as a little-endian integer, is strictly below the subgroup
  order `L`;
- the backend then verifies the signature equation.

There is no handwritten curve arithmetic and no blacklist of particular bad
points. A zero key, the identity point, an order-2/4/8 torsion point, a
non-canonical encoding (a `y` coordinate at or above `p`, or a sign bit set on
`x = 0`), and an off-curve encoding are all refused by libsodium rather than by
a list of known values. Honest keys and honest `R` values are unaffected:
RFC 8032 vectors and freshly generated keys validate, as the tests show.

## Usage

```sh
python3 -m pip install -r scripts/browserrelease/requirements.txt

scripts/browser-release-verify \
  --product chromium \
  --output /absolute/release-parent \
  --attestation /absolute/review/attestation.json \
  --public-key /absolute/owner-pins/owner-ed25519.pub
```

Equivalent module invocation:

```sh
PYTHONPATH=scripts python3 -m browserrelease.attestation \
  --product chromium \
  --output /absolute/release-parent \
  --attestation /absolute/review/attestation.json \
  --public-key /absolute/owner-pins/owner-ed25519.pub
```

`--output` must be absolute and the package/receipt files must already exist
under their fixed names:

```text
locklark-browser-extension-<product>-unsigned.zip
locklark-browser-extension-<product>-unsigned.receipt.json
```

A successful run prints `PASS: attestation signature matches the explicitly
supplied pinned public key` and a JSON summary. A refusal prints `FAIL:` with a
fixed public-safe message and exits non-zero.

## Public key file

The owner public-key file contains exactly 64 lowercase hexadecimal characters
(32 raw Ed25519 public-key bytes), with one optional trailing LF. It is read as
a regular file without following symlinks and within a small size limit.

A well-formed hex string is not enough: the decoded bytes must be a canonical
prime-subgroup non-small-order Ed25519 point. A key that is not, including the
zero key, the identity point, a torsion point, a non-canonical encoding, or an
off-curve encoding, is refused with the fixed message
`FAIL: owner public key is not usable` before any signature is examined. Key
format errors keep their own fixed message.

The verifier does not discover a key from a repository, profile, environment
variable, network, store account, or the artifact itself. The owner must pin
and transmit the key through a channel the verifier trusts independently.

## Attestation schema v1

The public attestation is a flat JSON object with exactly these members:

```json
{
  "schema": "locklark-browser-release-attestation/v1",
  "repo": "jihuayu/locklark",
  "product": "chromium",
  "version": "0.1.0",
  "source_commit": "<40 lowercase hex characters>",
  "artifact_sha256": "<64 lowercase hex characters>",
  "receipt_sha256": "<64 lowercase hex characters>",
  "signature": "<128 lowercase hex characters>"
}
```

Accepted products are `chromium`, `firefox`, and `safari`. The version follows
the existing central-version rules: one to four dot-separated decimal
components, no leading zeros, each component at most 65535.

The verifier refuses:

- a document over 64 KiB, empty, non-UTF-8, BOM-prefixed, non-JSON, or not a
  JSON object;
- missing, unknown, duplicate, or case-aliased field names (for example
  `Product` where `product` is required);
- a non-string field value;
- an unrecognized schema, repository, or product;
- an invalid version, non-40-hex commit, non-lowercase SHA256 digest, or
  non-lowercase 64-byte signature encoding;
- a symlinked or non-regular attestation or public-key file;
- a symlinked, missing, non-regular, or oversize package/receipt file;
- an output path that is not a real directory.

## Canonical signed bytes

The signature is over exactly the following ASCII bytes, including the final
newline. The first line is the domain separator. The `signature` field itself
is not signed.

```text
locklark-browser-release-attestation/v1
repo=jihuayu/locklark
product=chromium
version=0.1.0
source_commit=<40 lowercase hex>
artifact_sha256=<64 lowercase hex>
receipt_sha256=<64 lowercase hex>
```

The JSON formatting, key order, whitespace, and duplicate-free representation
do not affect the signed bytes; only the validated field values do.

## What a successful verification binds

The verifier:

1. validates the strict schema and all field values;
2. requires the pinned public key and the signature `R` to be canonical
   prime-subgroup non-small-order points and the `S` scalar to be canonical
   (libsodium point validation, see above);
3. verifies the detached Ed25519 signature using the explicitly supplied
   pinned public key;
4. re-runs the existing unsigned package/receipt verifier on the fixed paths,
   including the ZIP entry allowlist, entry digests, manifest policy, receipt
   schema, and receipt-to-ZIP binding;
5. requires the attestation `artifact_sha256` and `receipt_sha256` to match the
   actual ZIP and receipt bytes;
6. requires the attestation `version` and `source_commit` to match the receipt;
7. requires the attestation product to match both the requested product and the
   fixed package/receipt names.

It refuses tampered package bytes, changed receipt bytes or receipt semantics,
a changed signature, a different key, a mismatched product, an invented source
commit or version, and unknown/malformed schema fields. It also refuses a
forged-identity or otherwise unusable pinned key and a signature whose `R` or
`S` encoding is not canonical, even when the backend signature equation would
accept them.

The output is read only. There is no overwrite path, no temporary file, and no
publication step in this verifier.

## Limits of the claim

A successful run proves only:

- the detached signature verifies under the **explicitly supplied** public key;
- that key is the one the caller chose to pin;
- the actual package and receipt pass the existing unsigned self-consistency
  checks and match the signed digests, version, product, and source commit.

It does **not** prove:

- that the public key genuinely belongs to the Locklark release owner;
- that a release owner approved this particular artifact;
- Chrome Web Store, Microsoft Edge Addons, or Firefox AMO signing, review,
  publication, or listing acceptance;
- that a store-signed package installs or updates correctly;
- native-host registration, end-to-end messaging, hardware-key/passkey,
  accessibility, or OS permission behavior.

No owner public key or signed attestation was supplied with this worktree.
Therefore this repository makes **no authentic owner-release claim**. Issue #53
remains open for owner/store/signing/real-install/update evidence.

## Tests

The attestation tests generate throwaway Ed25519 keys in memory using
`cryptography` and sign independently with `Ed25519PrivateKey`; no real key,
credential, or owner identity is used. They do not use the verifier as their
signer. Coverage includes:

- the exact forged-identity reproduction (public key `01` + 31 zero bytes,
  `R` = basepoint encoding, `S` = little-endian 1) at the wrapper and through a
  full synthetic package/receipt/attestation run, including the CLI, which must
  never print `pinned-key-signature-match`;
- a check that the pinned backend alone does accept that forged signature, so
  the libsodium gate is demonstrably what refuses it;
- small-order (order 2, 4, 8, identity, zero), non-canonical (near `p`,
  sign-bit-on-`x=0`), and off-curve public-key fixtures, each refused on the
  public-key path and as a signature `R`;
- non-canonical `S` scalars (`S = L`, `S = L + 1`, all `ff`, zero);
- RFC 8032 section 7.1 test vectors 1, 2, and 3, plus a freshly generated
  standard signer that verifies end to end and fails on a different message;
- missing `cryptography` and missing `PyNaCl` fail-closed behavior;
- successful verification for all three products, tampered
  package/receipt/signature, unknown signer, mismatched
  product/source/version/digests, unknown/duplicate/case-alias/missing fields,
  invalid hashes/versions/products, oversize and symlinked/non-regular inputs,
  and read-only CLI behavior.

```sh
PYTHONPATH=scripts python3 -m unittest discover \
  -s scripts/browserrelease/tests -t scripts
```

The attestation component contributes 37 tests, and the full browserrelease
suite (including the existing dependency-free packager tests) ran 113 tests
with no failures when this component was verified. Other independently
developed components may change the total. Installing the optional
`cryptography` and `PyNaCl` dependencies is required only for attestation
verification; the packager tests pass without them.
