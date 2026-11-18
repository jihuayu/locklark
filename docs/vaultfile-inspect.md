# Read-only vaultfile inspection

`locklark vaultfile inspect --file PATH --checkpoint FILE` is a metadata-only
entry. It parses one sealed vault file with `pkg/vaultfile.ParseFile` and then
calls `VerifyPolicyCheckpoint` with the explicit checkpoint supplied on the
command line. It does not use a profile, account, session, provider, network,
or unlock path, and it does not open the KDBX payload.

The checkpoint is caller-owned JSON:

```json
{"v":1,"vault_id":"...","owner_root_key_id":"...","owner_root_public_key":"...","policy_seq":5,"policy_digest":"..."}
```

`owner_root_public_key` and `policy_digest` are canonical 32-byte RawURL
base64. The parser rejects duplicate, wrong-case, unknown, missing, null, and
wrong-typed fields; IDs are validated by the existing vaultfile verifier, not
by a second rule set. Trailing JSON whitespace is allowed; non-whitespace
trailing bytes are not.

Success reports `policy: verified` and `payload: not_decrypted`. This is not a
claim that the KDBX payload AEAD, content history, server freshness, or a
workspace/provider is verified. Failure is a fixed JSON enum with a non-zero
exit status and does not echo the input.

The vault file is opened read-only with a bounded reader. On Unix the final
component is opened with `O_NOFOLLOW`/`O_NOCTTY`/`O_NONBLOCK` and the actual
handle is fstat-checked as a regular file; FIFOs and character devices are
rejected without acquiring a controlling terminal. Legitimate intermediate
directory symlinks (for example `/tmp` or `/var` on macOS) are allowed. On
Windows the final reparse point and non-disk handles are rejected; Windows is
compile-checked only.
