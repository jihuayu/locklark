# Executing the approved program bytes (run bundle / `cli run`)

`locklark cli run` records a SHA-256 of the tool executable and hands that digest
to the credential runner (`personal.RunBundleRequest.ProgramSHA256`). The runner
must execute *those* bytes: the approval happened against one image, so a rename,
an in-place overwrite or a replaced file between approval and `CreateProcess` /
`execve` must not run something else.

This note records what each platform can actually prove today, what is tested,
and what is still missing. It is deliberately explicit about the parts that are
*not* covered.

## Contract

* `ProgramSHA256 == ""` means the caller explicitly approved no digest. Every
  platform then performs an ordinary local direct exec of the original path: no
  image copy, no handle/ACL pin and no lock are held. The caller's `argv0`,
  script `$0`/path, arguments, working directory, environment and standard
  streams are preserved exactly, and the run is a single direct child. That is
  the documented unpinned scope, not an exact-byte guarantee.
* `ProgramSHA256 != ""` means the caller approved exactly these bytes. A platform
  that cannot bind execution to those bytes must refuse with
  `personal.ErrRunProgramPinUnsupported`; it must never fall back to a
  verify-then-exec-by-name path.
* `personal.ErrRunProgramPinUnsupported` is preserved through `runBundle`, so the
  CLI reports "the pin is unsupported here" rather than "the child failed".
* The CLI pins by default (it computes the digest unless `--pin-sha256 false` is
  given explicitly). On platforms without a pin, `--pin-sha256 false` is the
  explicit, documented way to say "run the current file, I accept that the
  approval is not bound to bytes"; it selects the all-platform unpinned direct
  exec above.

## Platform matrix

| Platform | Status | Mechanism |
| --- | --- | --- |
| Linux | Implemented, tested on a real kernel | copy into a `memfd` sealed with `F_SEAL_WRITE\|F_SEAL_GROW\|F_SEAL_SHRINK\|F_SEAL_SEAL`, re-hash the copy, execute `/proc/self/fd/3` |
| Windows | Implemented, cross-compiled and type-checked here; runtime coverage on a real Windows host is **not** part of this change | deny-write/deny-delete handle on the image **and** on every ancestor directory, held for the whole `cmd.Run`; handle identity, resolved path and digest verified before start |
| macOS | **Refused** (`ErrRunProgramPinUnsupported`) | no public API has been proven to close the gap; see "Darwin" below |
| BSDs, Solaris, Plan 9, wasm | **Refused** (`ErrRunProgramPinUnsupported`) | no implemented pin |

With an empty digest every platform in this table, including the refused ones,
takes the same explicit unpinned path: one ordinary local direct exec of the
original program path, with full caller semantics and no exact-byte claim.

## Linux

When a digest is supplied, `internal/personal/run_exec_pin_linux.go` snapshots
the image once into an anonymous `memfd`, verifies the copy against that digest,
seals it against write/grow/shrink/seal-add, and starts the child on
`/proc/self/fd/3` (the pinned descriptor passed as `ExtraFiles[0]`). `argv0`
stays the caller's program path. The caller-visible path is meaningless after
the copy, so a later rename, truncate or in-place write cannot change what runs.

A pinned shebang script is now explicitly refused
(`personal.ErrRunProgramScriptPinUnsupported`) before any snapshot exists:
executing the sealed copy through `/proc/self/fd` would make the kernel use the
descriptor path as the script's `$0`, silently changing relative-asset and
package-resolution semantics. Invoking a native ELF interpreter explicitly with
the script as an argument is allowed, but only the interpreter image is pinned;
the script argument, its assets and everything it loads are not pinned and may
change after approval. With an empty digest Linux takes the explicit unpinned
direct-exec path above.

Real tests (`run_exec_pin_linux_test.go`) execute real binaries:

* atomic replacement of the path after the pin, child still runs the original
  bytes with the original `argv0`,
* in-place truncate-and-rewrite after the pin, same result,
* post-approval replacement and digest mismatch refused before any child exists,
* a pinned shebang script refused before the child-start seam while an explicit
  ELF interpreter plus script argument runs with the script's own `$0`; the
  script argument and its dependencies stay outside the pin.

## Windows

Windows has **no public "start a process from this handle" API** (no `fexecve`
equivalent, and `CreateProcess` takes a name, not a handle), so the child is
still started by path. The pin therefore makes that name unfalsifiable for the
child's whole lifetime instead of replacing the bytes:

1. `CreateFileW(program, GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING)` — the
   share mode allows only further readers. No `FILE_SHARE_WRITE`, no
   `FILE_SHARE_DELETE`. Every later open that asks for write access (truncate,
   in-place overwrite, append, attribute write) or for DELETE access (rename,
   delete, replace) fails with a sharing violation until the handle is closed.
   Sharing is enforced per file object, so this holds for other processes and
   for a second handle in the same process.
2. Handle identity: the opened object must be a regular file, not a directory,
   not a reparse point, with `0 < size <= 1 GiB`.
3. Path binding: `GetFinalPathNameByHandle` must resolve to exactly the
   requested path (case-insensitive, `\\?\` stripped). A symlink, junction,
   mount point, short (8.3) name or swapped link that reaches a different image
   is refused instead of executed.
4. Access rule: the image's owner must be the current user, SYSTEM,
   Administrators or TrustedInstaller, and no other principal may hold write,
   append, DELETE, `WRITE_DAC`, `WRITE_OWNER`, `FILE_WRITE_EA` or
   `FILE_WRITE_ATTRIBUTES` on it (the same descriptor policy the private run
   root already uses).
5. Ancestry: every ancestor directory is checked with the same owner/ACL policy,
   must not be a reparse point, and is then **held open** with
   `GENERIC_READ | FILE_SHARE_READ` for the child's lifetime. Renaming, deleting
   or replacing a directory needs DELETE access on that directory, so no
   component of the path can be swapped while the child runs — this is the
   answer to "a parent rename retargets the path" and it is tested, not assumed.
6. Digest: the bytes are read through the *guard handle* (not re-opened by name)
   and compared with `ProgramSHA256`. A second look at the same handle after the
   read must show the same identity, attributes, length and write time, so an
   image that moved during hashing is refused.
7. Ordering: the guards are taken before the hash, and `closeProgram` runs after
   `cmd.Run` returns, i.e. after the child exited.

An empty `ProgramSHA256` does not use this pin. It is the explicit unpinned
scope shared with every platform: `newRunBundleCommand` requires an absolute
path that `os.Lstat` reports as an existing regular, non-empty `.exe`, then
returns `exec.CommandContext(ctx, program, args...)` with a no-op cleanup. No
image handle, ACL check or rewrite, ancestry handle or lock is taken, so a
writer or rename is not blocked. A non-empty digest always takes the pin above
and is refused if any step cannot be proven.

`argv0`, the working directory, the environment, the three standard streams and
the deadline context are the caller's: the command is
`exec.CommandContext(ctx, program, args...)` with no shell, no PowerShell, no
interpreter, no output capture. Go passes this path as `lpApplicationName`, so
`CreateProcess` performs no PATH or extension search.

### Windows tests

`internal/personal/run_exec_pin_windows_test.go` (build tag `windows`) copies the
test executable into its own temporary directory as an ordinary PE/CLI helper —
not a shell or script wrapper — and drives the real `executeRunBundle` path:

* `TestExecuteRunBundleWindowsPinsImageAndAncestry`: inside the pre-start window
  (guard held, no child yet) rename / truncate / delete of the image and rename
  of its parent directory all fail, **and** a separate attacker process launched
  at that moment also cannot truncate, rename or delete the image; the child then
  starts from the approved bytes, reports its own `argv0` and reads the caller's
  stdin; after the run the same rename succeeds, proving the earlier failures
  came from the guard and that it was released.
* `TestExecuteRunBundleWindowsRefusesStaleProgramImage` and
  `TestExecuteRunBundleWindowsExactDigestRefusesAnotherImage`: a different real
  image at the approved path is refused with no child output, both when it is
  merely stale relative to the approved digest and when the digest belongs to
  another image; the same image runs when it is the approved one.
* `TestExecuteRunBundleWindowsDirectStreamsAndSingleChild`: stdin/stdout/stderr
  are the caller's files, `argv0` is the approved path, and the child's parent
  PID is the test process — one direct child, no wrapper.
* `TestExecuteRunBundleWindowsHonoursContext`: a cancelled context starts
  nothing, and the run deadline kills a sleeping child.
* `TestNewRunBundleCommandWindowsEmptyDigestIsExplicitlyUnpinned`: an empty
  digest runs the original path with the caller's arguments and streams; while
  the command is pending an open-for-write and a rename both succeed, proving no
  write/delete guard is held, and `closeProgram` is a no-op.
* `TestNewRunBundleCommandWindowsEmptyDigestRequiresOrdinaryExe`: the unpinned
  path still refuses a relative path, directory, empty image, missing file and
  non-`.exe` name.
* `TestPinRunBundleProgramWindowsRefusesUnsafePrograms`: directory, empty image,
  missing file, non-`.exe` name and a wrong digest are all refused, and the guard
  handles are released exactly once.

Run them on a Windows host (this repository's Linux container only cross-compiles
them, which proves they build and type-check, **not** that they pass):

```powershell
go test ./internal/personal/ -run 'Windows|PinRunBundleProgramWindows' -count=1 -v
```

### Windows residual limits

These are the honest edges; none of them is claimed as closed:

* **A writer that was already open before the pin.** Share modes govern new
  opens. A process that opened the image for write *before* the guard handle
  existed keeps its handle. The second handle look after hashing refuses an
  image whose length, attributes or write time moved during the read, but a
  same-length rewrite that races the hash and lands before
  `CreateProcess` is not excluded by the public API. The pin closes the
  approval-to-exec window for every *new* writer, which is the realistic attack,
  and the CLI's own `VerifyProgram` already refused a changed image earlier.
* **Same-user trust.** The current user is trusted, exactly as on Linux: a
  same-user process can debug or inject into `locklark` or the child. The pin
  protects against other principals, against accidental replacement by tools, and
  against path races — not against the user.
* **Administrators / `SeRestorePrivilege` / kernel components** can act outside
  normal sharing and ACL rules, as root can on Linux.
* **Scope refusals.** UNC program paths, reparse-point images or ancestors,
  ancestors owned by an untrusted principal, ancestors that an untrusted
  principal may write/delete/rewrite, and short (8.3) names are refused rather
  than pinned. A tool installed in a world-writable directory is therefore
  refused; that matches the existing binding rule that the immediate parent must
  not be group/other writable.
* **Held ancestor handles.** While the child runs, its own program directory
  cannot be renamed or deleted (that is the point). A tool that wants to replace
  itself in place during the run fails; on Linux the same self-update simply has
  no effect on the running image.

## Darwin

Research result: with public API only, no way to execute an already-open file as
the approved image has been **proven**, so `run_exec_pin_other.go` keeps the
explicit `ErrRunProgramPinUnsupported` refusal for pinned requests.

Evidence gathered here (from public API surface, no macOS machine available):

* macOS libc does not provide `fexecve`; it is a POSIX *optional* interface and
  Darwin does not implement it.
* Go has no equivalent: `syscall` has no `Fexecve` on darwin, and
  `golang.org/x/sys/unix` exposes no `fexecve` wrapper for darwin (only BSD
  syscall-number constants mention it).
* Executing `/dev/fd/N` is not a supported Mach-O exec path — the kernel loads
  Mach-O images by path (the `execve` path argument), and there is no documented
  contract that a `devfs` file descriptor works.
* A private `0700` copy or an advisory `flock` does **not** give immutability
  against another process of the same user, so neither can honestly be called a
  pin. No public API here has been proven to bind execution to immutable bytes,
  and a copy-and-replace scheme would add its own trust and signing problems
  without closing that gap.

Remaining gap and next actual test (needs a real Mac; the owner's device
acceptance passes are the place for it):

1. On a real Mac, confirm against the SDK headers (`unistd.h`, `sys/fcntl.h`)
   that no `fexecve`/`fexecveat` declaration exists, and test at runtime whether
   `execve("/dev/fd/N", ...)` of a Mach-O ever succeeds.
2. If a supported primitive exists, the Darwin implementation can seal a copy the
   same way Linux does (copy + hash + immutable snapshot + exec the copy) and
   must then be covered by the same set of real tests: replace path after pin,
   truncate in place, digest mismatch, stale other file, direct streams/`argv0`,
   one child.
3. Until that evidence exists, Darwin stays a deliberate fail-closed refusal; do
   not ship a best-effort "verify then exec by name" that would silently weaken
   the approval.

## References

* `internal/personal/run_bundle.go` — request validation, digest binding, error
  propagation, `executeRunBundle`.
* `internal/personal/run_exec_pin_linux.go` / `_linux_test.go` — sealed memfd pin.
* `internal/personal/run_exec_pin_windows.go` / `_windows_test.go` — handle pin.
* `internal/personal/run_exec_pin_other.go` — explicit refusal for every other
  platform.
* `docs/cli-wrappers.md` — user-facing CLI contract.
