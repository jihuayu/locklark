# Typed personal CLI surfaces (issue #63)

Status: in progress. This document describes the typed creation entry point
(`personal add-item`) and the rich v2 1PUX import opt-in. It is updated as the
implementation lands.

## `personal add-item`

```
locklark personal add-item --file VAULT --input ITEM.json
```

Sensitive values are read only from an explicit local JSON file; they are never
accepted on the command line. The input path is opened without following a
final symlink and must be a regular file owned by the effective user with no
group/other permission bits. On Windows the handle must be a disk file owned by
the current user with a DACL limited to that user, LocalSystem or Builtin
Administrators.

### Accepted document

The document is one strict JSON object, valid UTF-8, at most 1 MiB. Duplicate
keys (checked ASCII-case-insensitively), unknown keys and trailing values are refused.
Object keys must use ASCII; Unicode values remain lossless. Unpaired surrogate
escapes are refused before decoding.
Refusals always return the same fixed error and never echo the document, a key,
a path or a decoded value.

The accepted projection covers the native item categories:

- `category` (default `login`) from the supported vault categories;
- `title` (required), `username`, `password`, `notes`, `otp`, `favorite`;
- `url`, `urls`, `tags`;
- `sections` with custom fields, using the native field types except `file`;
- `credit_card` for `credit_card` items and `identity` for `identity` items;
- `attachments` naming explicit private files (see below);
- `ssh_private_key_file` for `ssh_key` items (see below).

`ssh_key` never carries a raw seed, private key, public key, passkey, import
source or attachment through JSON, and it refuses `username`, `password`, `otp`,
`notes` and the legacy `url` member because the native ssh_key layout has no
slot for them; accepting them would silently drop user data.

`document` items are accepted only when they request at least one attachment;
their payload is carried by the v2 attachments instead of the legacy
`filename`/`attachment` pair, so `username`, `password`, `otp`, `notes` and the
legacy `url` member are refused. Other supported categories may also have
attachments.

### Attachment files

Each attachment is an explicit private-file request, never an inline body:

```json
{"attachments":[
  {"file":"/home/ada/scan.pdf","file_name":"scan.pdf","mime_type":"application/pdf"},
  {"file":"/home/ada/evidence.bin","file_name":"evidence.bin"}
]}
```

- `file` must be an absolute path to an existing regular file. It is read once
  and is not stored in the item; the path is refused if it contains control
  characters.
- `file_name` must be a safe basename: no path separators, no `.`/`..`, no
  control characters and at most 255 bytes.
- `mime_type` is optional, at most 256 bytes and free of control characters.
- At most 16 files are accepted. Each file is at most 2 MiB (the native
  per-attachment limit) and the aggregate is at most 4 MiB, conservatively
  charging the raw JSON document and native attachment metadata as well.
- Binary bodies are allowed, including NUL bytes and non-UTF-8 bytes; a
  zero-length file is valid.
- Files use the same owner-only descriptor rules as the JSON input: no final
  symlink, no FIFO, regular file only, owned by the effective user with no
  group/other permission bits. Windows applies the same owner/DACL rule to the
  opened handle. Every check and read uses the same descriptor or handle.

All attachment files are read and frozen before the SAVE prompt and before the
single mutation, so replacing a path afterwards cannot change the stored bytes.
A missing, unreadable, unsafe, per-file-oversize or aggregate-oversize file
returns the fixed refusal before any prompt and leaves the vault unchanged. On
any error or cancellation every already-read body is cleared best-effort.
Native `Session.AddItem` validation remains the final authority.

Raw attachment content/base64/body, attachment IDs, sizes, digests, provenance,
passkeys, import sources and history are not accepted members.

### SSH private key file

An `ssh_key` document names exactly one explicit private key file:

```json
{"category":"ssh_key","title":"Deploy key","ssh_private_key_file":"/home/ada/.ssh/id_ed25519"}
```

- `ssh_private_key_file` is required for `ssh_key` and refused for every other
  category. It must be an absolute path to an existing regular file with no
  control characters.
- The file is read with the same bounded owner-only descriptor/handle rules as
  the JSON input and attachments: no final symlink, no FIFO, owner-only
  permissions, at most 32 KiB. The bytes are not stored in the item.
- Only an unencrypted Ed25519 private key is accepted. The 64-byte key must be
  internally consistent with the seed half; the 32-byte seed and the SSH wire
  public key derived from it are stored in the native encrypted item.
- RSA, ECDSA, malformed files and an encrypted key are refused with a fixed
  error. Passphrase input (argv, prompt or environment) is not part of this
  command. File bytes and parsed key buffers are cleared best-effort.
- The file is resolved before both factors, the SAVE prompt and the mutation, so
  an unsafe or unsupported key never reaches consent. No error, prompt or
  receipt contains the path, a key byte or a fingerprint.

### Consent and receipt

After both the master password and Secret Key are entered, the command displays
only the validated category and counts (sections, custom fields, URLs, tags and
attachments with their total bytes). It never displays the title, a field value,
an attachment name, an attachment path, an SSH path or an SSH fingerprint. The
operator must type `SAVE`; any other answer cancels with a fixed error and leaves
the vault unchanged.

The write is one authenticated `Session.AddItem` under an expiring
`MutationGate`; there is no direct-persistence or ungated shortcut. The JSON
receipt contains only:

```json
{"status":"created","id":"...","revision":"..."}
```

The private input buffer is cleared on exit and decoded native byte slices are
cleared best-effort. Go strings are immutable, so the command does not claim to
zero their backing arrays.

### Tests

Unit tests use a real two-factor vault and a fake console for the SAVE answer.
They verify successful identity creation with a concealed section, reopening the
encrypted vault and reading item detail plus references, and refusal without
mutation for a wrong SAVE or bad factors. Attachment tests create a real
two-file document with binary/NUL content, reopen the encrypted vault, and use
`GetAttachment` to compare exact bytes and SHA-256; they also verify
all-or-nothing refusal for a missing file, per-file oversize, aggregate oversize
and wrong SAVE. SSH tests generate a real Ed25519 OpenSSH key file, verify the
copied seed/public pair, reopen the encrypted vault and read the persisted public
key and fingerprint, and refuse an encrypted, ECDSA, malformed, group-readable
or symlinked key before the consent prompt without mutating the vault. Reader tests cover binary content, the 2 MiB file bound,
permissions, symlink and FIFO refusal; Windows fixture helpers create an
owner-only DACL. The receipt and prompt contain no item value, attachment name
or path. CLI tests cover argument validation and the interactive-terminal
boundary. These tests do not simulate a real TTY. The F6_08 end-to-end case now drives
typed ssh_key creation from a generated owner-private Ed25519 file over a real
PTY and proves the seed/public pair through a metadata-only probe; its actual
PTY execution and acceptance remain with the primary reviewer. Windows tests are cross-compiled only unless run on Windows.

## Explicit rich 1PUX profile

Use `personal plan-import-1pux --file VAULT --source ARCHIVE --model v2`,
then `personal import-1pux --file VAULT --source ARCHIVE --digest PLAN_DIGEST --model v2`.
The v2 profile is explicit for both steps; a v2 plan is not interchangeable with
the default basic-login profile. Both steps keep the existing full-factor and
PLAN/SAVE consent boundaries. Unsupported input is refused as a whole and
existing items are not overwritten. Imported source records remain encrypted
and may retain old values after later edits.

Omitting `--model v2` preserves the existing basic-login import behavior.
Typed creation accepts explicit private attachment and Ed25519 private-key
files but still refuses raw attachment bodies, inline key material and other raw
credential records through JSON.


2026-11-09（香港）独立验收：八项 F6 真实终端用例全部通过，包含显式私有 SSH 文件创建、现有原生 SSH 签名接口的公钥验签、错误 SAVE、非法/公开权限文件的原子拒绝。全部 typed 解析/创建 Go 测试通过（8.639 秒）。原始密钥、文件路径和条目内容未进入创建回执；签名证明仅向 E2E 返回布尔值。整合套件此前 215 项的 183 PASS/32 PENDING/0 FAIL 为原始全量回执；本次另行补齐 T1_F6_08，未冒称已重跑全部 215 项。
