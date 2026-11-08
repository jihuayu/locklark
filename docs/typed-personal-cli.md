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

The accepted projection covers the native item categories that do not need raw
key material:

- `category` (default `login`) from the supported vault categories;
- `title` (required), `username`, `password`, `notes`, `otp`, `favorite`;
- `url`, `urls`, `tags`;
- `sections` with custom fields, using the native field types except `file`;
- `credit_card` for `credit_card` items and `identity` for `identity` items;
- `attachments` naming explicit private files (see below).

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
passkeys, import sources and history are not accepted members. SSH keys remain
unsupported because they would require raw private key material; the remaining
raw SSH input path is separate work.

### Consent and receipt

After both the master password and Secret Key are entered, the command displays
only the validated category and counts (sections, custom fields, URLs, tags and
attachments with their total bytes). It never displays the title, a field value,
an attachment name or an attachment path. The operator must type `SAVE`; any
other answer cancels with a fixed error and leaves the vault unchanged.

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
and wrong SAVE. Reader tests cover binary content, the 2 MiB file bound,
permissions, symlink and FIFO refusal; Windows fixture helpers create an
owner-only DACL. The receipt and prompt contain no item value, attachment name
or path. CLI tests cover argument validation and the interactive-terminal
boundary. These tests do not simulate a real TTY; end-to-end TTY coverage is a
separate exercise. Windows tests are cross-compiled only unless run on Windows.

## Explicit rich 1PUX profile

Use `personal plan-import-1pux --file VAULT --source ARCHIVE --model v2`,
then `personal import-1pux --file VAULT --source ARCHIVE --digest PLAN_DIGEST --model v2`.
The v2 profile is explicit for both steps; a v2 plan is not interchangeable with
the default basic-login profile. Both steps keep the existing full-factor and
PLAN/SAVE consent boundaries. Unsupported input is refused as a whole and
existing items are not overwritten. Imported source records remain encrypted
and may retain old values after later edits.

Omitting `--model v2` preserves the existing basic-login import behavior.
Typed creation accepts explicit private attachment files but still refuses raw
attachment bodies, private key records and other raw credential material through
JSON; raw SSH input remains separate pending work.
