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
Refusals always return the same fixed error and never echo the document, a key
or a decoded value.

The accepted projection covers the native item categories that do not need raw
key or attachment material:

- `category` (default `login`) from the supported vault categories;
- `title` (required), `username`, `password`, `notes`, `otp`, `favorite`;
- `url`, `urls`, `tags`;
- `sections` with custom fields, using the native field types except `file`;
- `credit_card` for `credit_card` items and `identity` for `identity` items.

SSH keys, documents and raw attachment/passkey/provenance/history material are
not part of this command. SSH seed/public-key members, attachments, passkeys,
`import_source`, `history`, native IDs, state, timestamps and similar members
are refused as unknown keys.

### Consent and receipt

After both the master password and Secret Key are entered, the command displays
only the validated category and counts (sections, custom fields, URLs, tags).
It never displays the title or any field value. The operator must type `SAVE`;
any other answer cancels with a fixed error and leaves the vault unchanged.

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
encrypted vault and reading item detail plus references, refusal without
mutation for a wrong SAVE or bad factors, and that the receipt contains no item
value. CLI tests cover argument validation and the interactive-terminal
boundary. These tests do not simulate a real TTY; end-to-end TTY coverage is a
separate exercise.

## Explicit rich 1PUX profile

Use `personal plan-import-1pux --file VAULT --source ARCHIVE --model v2`,
then `personal import-1pux --file VAULT --source ARCHIVE --digest PLAN_DIGEST --model v2`.
The v2 profile is explicit for both steps; a v2 plan is not interchangeable with
the default basic-login profile. Both steps keep the existing full-factor and
PLAN/SAVE consent boundaries. Unsupported input is refused as a whole and
existing items are not overwritten. Imported source records remain encrypted
and may retain old values after later edits.

Omitting `--model v2` preserves the existing basic-login import behavior.
Typed creation still does not accept attachment bodies or private credential
records through JSON; attachment file input is separate pending work.
