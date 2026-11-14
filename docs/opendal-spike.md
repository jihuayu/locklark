# OpenDAL Go spike (#107)

Re-runnable, synthetic-data-only spike of the official Apache OpenDAL **Go**
binding. It is a research harness under `tools/opendal-spike/` (an independent
Go module) and is **not** wired into the product, the root `go.mod`, or CI.
No S3/OneDrive product integration is implemented here, no cloud credentials
are read, and the programs never talk to a real remote service.

Pinned official sources:

- https://opendal.apache.org/docs/bindings/go/
- https://opendal.apache.org/docs/bindings/go/production/
- https://opendal.apache.org/services/s3/go/
- https://opendal.apache.org/services/onedrive/go/

## 1. Published versions and pins

Queried with `go list -m -versions` / `go mod download -json` against
`proxy.golang.org` on 2026-11-10 (host clock). Latest published release line is
**v0.1.16** for both the binding and the companion service modules.

| Module | Pinned version | `h1:` (go.sum) | License | Source / tag |
| --- | --- | --- | --- | --- |
| `github.com/apache/opendal/bindings/go` | `v0.1.16` | `h1:W80lrbhmXrcCwvEcrydYhjMFUTyOPue9wgfrD4lhBKE=` | Apache-2.0 | `apache/opendal` @ `1e0fc73190afb7e221c7badda7ef43fe40592940`, tag `bindings/go/v0.1.16` |
| `github.com/apache/opendal-go-services/memory` | `v0.1.16` | `h1:4OcQNo9RMi+Q7HD1sVv8vJHLLPFWRu1Nm0kqbOP+b4w=` | Apache-2.0 | `apache/opendal-go-services` @ `ac5d229bbb9ce580f07bf60c6f7ea7e770c239a9`, tag `memory/v0.1.16` |
| `github.com/apache/opendal-go-services/s3` | `v0.1.16` | `h1:uhK+59UPW9zXWqEPkA1lYvJWkH78qut8Gc4Ju2aRRY8=` | Apache-2.0 | same commit, tag `s3/v0.1.16` |
| `github.com/apache/opendal-go-services/onedrive` | **not published** | — | — | `GET https://proxy.golang.org/.../onedrive/@v/list` → HTTP 404; `go mod download github.com/apache/opendal-go-services/onedrive@latest` → `no matching versions for query "latest"` |

Indirect Go dependencies are pinned by `go.sum`: `ebitengine/purego v0.8.4`,
`jupiterrider/ffi v0.5.0`, `klauspost/compress v1.17.9`, `golang.org/x/sys v0.24.0`
(all Apache-2.0/BSD-style upstream licenses; the binding itself is Apache-2.0,
see `LICENSE`/`NOTICE` shipped in each module).

### Native (`libopendal_c`) artifacts

The Go binding is a pure-Go FFI wrapper; the actual OpenDAL core is a native
shared library **embedded (zstd-compressed) inside each companion module**. The
published `memory`, `s3` and `fs` modules at `v0.1.16` contain only:

```
embed_linux_amd64.go   //go:build linux && amd64
embed_linux_arm64.go   //go:build linux && arm64
libopendal_c.linux.amd64.so.zst
libopendal_c.linux.arm64.so.zst
```

There is **no darwin, windows, or other platform native library** in any
published companion release checked (`memory`/`s3` at v0.1.8, v0.1.11, v0.1.13,
v0.1.16). The library carries no version string of its own; it is pinned by the
companion module version + the hashes below.

| Artifact | SHA-256 |
| --- | --- |
| `libopendal_c.linux.amd64.so.zst` (memory v0.1.16) | `0197a9dffb3db6c60e0c27326d208cc393996fe39270b20f7dc9e7adcf71cf3f` |
| `libopendal_c.linux.arm64.so.zst` (memory v0.1.16) | `3471b69bf6d2c1d31591f23381064984bee230479d5713574785e82d6837db4c` |
| decompressed `libopendal_c*.so`, linux/amd64 | `69d0c483bbbaac6ecc807a5ec80519fd1e5163d7a4643242cae78ebfa30032da` (8,336,584 B) |
| decompressed `libopendal_c*.so`, linux/arm64 | `2d759a7bd2819da4ba9605d36e5ddc002ca115505cf386c974d97672a46c0895` (7,432,568 B) |

Runtime requirement observed: the native library needs **glibc ≥ 2.38**
(`GLIBC_2.38 not found` on Debian bookworm / glibc 2.36) and is **not
musl-compatible** (alpine fails in `jupiterrider/ffi` init with a missing
symbol). Both tested working on `golang:1.24-trixie` (glibc 2.41).

## 2. Task 1 — memory write/read/list/close (real, synthetic)

Program: `tools/opendal-spike/cmd/memory`. It loads the official embedded
native library, creates a `memory` operator, writes three synthetic objects,
reads them back byte-for-byte, `Stat`s one, does a non-recursive `List`, checks
a missing key returns typed `CodeNotFound`, closes the operator, and enforces a
hard 30 s wall-clock budget.

Reproduce:

```bash
cd tools/opendal-spike
./run-memory.sh linux/arm64   # or linux/amd64
```

Reproduce (image pinned by digest; second arg records emulation honestly):

```bash
cd tools/opendal-spike
./run-memory.sh linux/arm64 native     # host is darwin/arm64 -> no emulation
./run-memory.sh linux/amd64 emulated   # foreign arch on this arm64 Mac
```

Luna re-run 2026-11-10, macOS 27.0.1 / Apple M2 Max (`uname -m` = `arm64`),
OrbStack Docker, image
`golang:1.24-trixie@sha256:5835f052b784aa39f2fe9070def3568605c8bc3fcd810f10402066348b61e716`
(Debian trixie, glibc 2.41). linux/arm64 ran with **no emulation**; linux/amd64
ran **under platform emulation** (x86-64 binary on arm64 via Docker/OrbStack).

```
$ ./run-memory.sh linux/arm64 native
platform=linux/arm64 mode=native image=golang:1.24-trixie@sha256:5835f052...b61e716 modcache=opendal-spike-gomodcache-trixie
[..] go=go1.24.13 os=linux arch=arm64
[..] binding=github.com/apache/opendal/bindings/go v0.1.16 companion=github.com/apache/opendal-go-services/memory v0.1.16
[..] native lib path=/tmp/libopendal_c3126911279.so
[..] info scheme=memory root="/" read=true write=true list=true
[..] PASS Write / PASS Read / PASS Stat: len=32
[..] PASS List(non-recursive): got=[spike/hello.txt spike/nested/] err=<nil>
[..] PASS Read-missing=CodeNotFound: err=3 NotFound (permanent) ... memory doesn't have this path
[..] RESULT: PASS
[..] PASS Close
exit=0
```

```
$ ./run-memory.sh linux/amd64 emulated
platform=linux/amd64 mode=emulated image=golang:1.24-trixie@sha256:5835f052...b61e716 modcache=opendal-spike-gomodcache-trixie
[..] go=go1.24.13 os=linux arch=amd64
[..] native lib path=/tmp/libopendal_c2730837149.so
[..] RESULT: PASS
[..] PASS Close
exit=0
```

Both runs wrote three synthetic objects, read them back byte-for-byte, `Stat`ed
one, listed one level, checked a missing key returns typed `CodeNotFound`, and
closed the operator. The module cache volume keeps the already-fetched pinned
modules so re-runs do not download.

Binding API notes found while writing it (v0.1.16):

- `Operator.Close()` returns nothing; `Lister` has `Error()` (not `Err()`).
- Recursive listing is **not** available in this binding version (`List(path)`
  takes no options; the doc comment says recursion is unsupported), so the list
  check is single-level.
- Capabilities are `Info().GetFullCapability()` / `GetNativeCapability()`.
- `OperatorInfo.GetName()` returned unreadable values in an earlier probe round
  (§3); the spike does not rely on it. `GetScheme()`/`GetRoot()` are stable.

## 3. Earlier boundary-probe round (author) — failure, timeout, capability, error and cancellation boundaries

Program: `tools/opendal-spike/cmd/probe`; runner: `tools/opendal-spike/run-probes.sh`.
Every case runs in its own process (`timeout 25s`, `slow-uncancellable` 5s)
because several cases intentionally panic or never return. Synthetic memory
data only.

The table below records **the author's earlier observation** (linux/arm64,
`golang:1.24-trixie` before the digest pin). In the latest Luna round these
crash cases were **not** re-run; Luna independently re-ran only `cmd/memory` on
linux/arm64 and linux/amd64 (§2).

| Case (author, earlier round) | Exit | Observation |
| --- | --- | --- |
| `load-missing` | 0 | `NewOperator` → `/tmp/.../libopendal_c.so: cannot open shared object file: No such file or directory`; plain `error`, **not** `*opendal.Error` |
| `load-corrupt` | 0 | → `/tmp/corrupt-libopendal.so: file too short`; plain error |
| `load-tmpdir` | 0 | `opendal/services/memory: cannot create temp file: open /nonexistent-spike-tmp/...: no such file or directory` (only the first call shows it — see `LoadOnce` note) |
| `timeout-invalid` | 0 | `WithTimeout(0,0)` → `timeout must be positive` at construction |
| `info-name` | 0 | `GetName()` returned 14-byte hex-looking strings like `0xffff38…`/`0x7fff98…` on 50/50 calls; root cause not established |
| `capabilities` | 0 | full: stat/read/write/list/delete/create_dir/list_recursive=true, copy/rename/presign=false; native: same except create_dir=false; `Rename`/`PresignRead` → `CodeUnsupported (1)` |
| `error-matrix` | 0 | read/stat missing → `CodeNotFound (3)`; read `dir/` → `CodeIsADirectory (5)`; delete missing → `nil`; rename missing → `CodeUnsupported (1)` (capability check runs before the path check); list missing dir → 0 entries, `nil` error |
| `timeout-io` | 0 | `WithTimeout(1s, 1ns)`: 13 B and 8 MiB write/read all succeeded in 0.1–6 ms with `err=nil`; no timeout expiry observed |
| `close-then-use` | **2** | `op.Close()` then `op.Read()` → `SIGSEGV: segmentation violation` in the FFI call |
| `close-during-list` | **2** | `op.Close()` while another goroutine lists 2000 keys → `SIGSEGV` |
| `slow-uncancellable` | **124** | loop writing 1 MiB objects; only the external `timeout 5s` stopped it |

### Interpretation

- **Native load failures are returned, not fatal**, but they are plain Go errors
  from `dlopen`/temp-file creation, so callers must not assume
  `errors.As(err, *opendal.Error)`.
- **`LoadOnce` error handling** (companion `service.go` v0.1.16): the error is a
  local variable inside the `sync.Once` closure, so it is **not cached**. Once
  the `Once` body has executed, later `LoadOnce()` calls skip the body and
  return `nil` — even if the first load failed and the scheme's `path` is empty.
  Consequence: a failed load must be treated as terminal for the process; a
  retry of `LoadOnce` or `NewOperator` succeeds at the Go level, and the empty
  path then fails inside the binding with an opaque `dlopen` error.
- **Timeout scope: not empirically observed to expire on this round's memory
  workload.** `WithTimeout(timeout, ioTimeout)` is a real operator layer passed
  into `NewOperator`. With the in-memory backend, 13 B and 8 MiB writes/reads
  finished well below a 1 ns IO budget, so the path produced `err=nil` and
  proves nothing about expiry. `slow-uncancellable` only shows that a Go caller
  cannot interrupt a long-running loop through this Go API surface in-process
  within 5 s; it is one workload, not a proof that no blocking call can ever be
  bounded or interrupted. Timeout behaviour on slow remote backends remains
  **unverified** until tested without credentials/native-crash paths.
- **Capability flags tracked the observed outcomes for copy/rename/presign**
  (all false, all `CodeUnsupported`). Full vs native capabilities disagree only
  on `create_dir`; the mechanism was not investigated. Check capabilities before
  optional calls, and still handle `CodeUnsupported` because unsupported
  operations report `Unsupported` even when the target path is also missing.
- **Close is destructive and not concurrency-safe.** Using an operator after
  `Close`, or closing while an operation is in flight, segfaults the whole
  process (Go reports SIGSEGV, exit 2). Ownership must be single-goroutine:
  quiesce all operations before `Close`, never share an operator across
  independent lifetimes.
- **`OperatorInfo.GetName()`** returned unreadable hex-looking values in the
  earlier probe round. Root cause was not established; do not depend on it.
  Use `GetScheme()`/`GetRoot()` instead.

## 4. Platform / packaging matrix

Host for every row below: macOS 27.0.1 / Apple M2 Max (`arm64`), OrbStack
Docker. “Container” means a Linux container on this Mac, never a Linux host.

| Platform | Official native lib in `memory` v0.1.16 | What was done (latest Luna round) | Status |
| --- | --- | --- | --- |
| linux/arm64 | yes, embedded | `./run-memory.sh linux/arm64 native` executed | **run, PASS** (container, no emulation) |
| linux/amd64 | yes, embedded | `./run-memory.sh linux/amd64 emulated` executed | **run, PASS** (container, emulated) |
| darwin/arm64 | no | `go build`; guard run: prints `... this build is darwin/arm64 (unsupported)`, exits 3 | unsupported — cannot run |
| darwin/amd64 | no | `GOOS=darwin GOARCH=amd64 go vet ./...` | cross-build only, never executed |
| windows/amd64 | no | `GOOS=windows GOARCH=amd64 go vet ./...` | cross-build only, never executed |
| windows/arm64 | no | `go build ./...` (earlier round) | cross-build only, never executed |
| linux/arm64 or amd64 bare metal | yes | not tested | untested |
| Debian bookworm / glibc 2.36 | yes, but glibc-linked | earlier container run | load fails: `GLIBC_2.38 not found` |
| Alpine / musl | yes, but glibc-linked | earlier container run | `jupiterrider/ffi` init fails |
| iOS / Android (desktop/mobile packaging from #107) | **no** companion artifact | inspected published module contents | **unsupported today** — no cgo/purego mobile target, no native lib |

Guard output after the `runtime.GOOS/GOARCH` fix:

```
$ go build -o /tmp/spike-host ./cmd/memory && /tmp/spike-host; echo exit=$?
opendal-spike/memory: official opendal-go-services/memory supports only linux/amd64 and linux/arm64; this build is darwin/arm64 (unsupported)
exit=3
```

Container vs. real machine: linux rows ran the official `.so` in a Linux
container on macOS; they are **not** bare-metal evidence. Cross-build success
is never reported as a run.

## 5. Static Go API surface for #107 conditional writes (source review only)

Static review of `github.com/apache/opendal/bindings/go@v0.1.16` sources, not
executed. “Exposed” means the Go API compiles and the value can be passed; it
does **not** mean any service honours it. Verify per service before claiming
any multi-writer support.

| Conditional-write / versioning primitive | Exposed in Go API v0.1.16? | Notes |
| --- | --- | --- |
| Read if match / if none match / if modified / if unmodified | no | `Read(path)` takes no options; no `ReadWith*` helpers |
| Read with version | no | — |
| Stat if match / if none match / if modified / if unmodified | no | `Stat(path, ...)` takes no `StatWith*` options |
| Stat with version | no | — |
| Write if match / if none match (create-only) | no | `Write(path, data)` has no precondition argument |
| Writer / multipart chunk upload with precondition | no | `NewWriter`/`Writer` do not accept ETag conditions |
| Copy / rename with precondition | no | `Copy`, `Rename` take only paths; memory reports both as unsupported |
| Delete with version / precondition | no | `Delete(path)` |
| Presign with precondition | no | `PresignRead/Write/Delete/Stat(path, expiry)` only |
| Capability fields for conditional ops | **yes** (raw booleans) | `Capability` exposes `StatWithIfmatch`, `StatWithIfNoneMatch`, `ReadWithIfmatch`, `ReadWithIfMatchNone`, `WriteWithIfMatch`, etc. and `Metadata.Version/ETag`; but there is no Go operator call to use them |
| Version metadata on stat | no | `Metadata` in v0.1.16 holds only length / is-file / is-dir / last-modified; no ETag or version |

AV-001 resolution (2026-11-10): version-test expectations were revised down —
there is no exposed conditional write to test, so only the LWW service test
applies. The real risk is clear: if a product path treats a plain `Write` as
CAS because the backend happens to be consistent (memory is trivially “exact”
because it is single-process and synchronously overwrites), that is a false
safety claim. **A plain memory write is not CAS** and must not be cited as
evidence of multi-writer safety.

## 6. S3 / OneDrive / OIDC configuration — left blank for the user

No cloud credentials were read and no real S3 or OneDrive endpoint was
contacted. **Not validated against any real account.** Fill in locally; never
commit.

```text
# S3 (unverified)
OPENDAL_S3_BUCKET=
OPENDAL_S3_ENDPOINT=
OPENDAL_S3_REGION=
OPENDAL_S3_ACCESS_KEY_ID=
OPENDAL_S3_SECRET_ACCESS_KEY=
OPENDAL_S3_SESSION_TOKEN=

# OneDrive (unverified; no published Go companion module)
ONEDRIVE_CLIENT_ID=
ONEDRIVE_TENANT_ID=
ONEDRIVE_REFRESH_TOKEN=
ONEDRIVE_DRIVE_ID=
ONEDRIVE_ROOT=

# OIDC (unverified)
OIDC_ISSUER_URL=
OIDC_CLIENT_ID=
OIDC_CLIENT_SECRET=
```

## 7. Unfinished / not proven

- Timeout **expiry** was not observed on the memory backend this round; only
  layer construction, validation (`WithTimeout(0,0)` rejected) and the
  existence of the layer in `NewOperator` are known. Slow-backend timeouts and
  in-flight interruption are unverified.
- S3 and OneDrive: never run or connected. `github.com/apache/opendal-go-services/onedrive`
  is not published, so it cannot be compiled against at all. No product
  S3/OneDrive/OIDC implementation exists in this spike, and nothing was tested
  with a real account.
- Conditional write / CAS: not exposed by the Go API (see §5); nothing in this
  spike validates #107's “single success under concurrent same-token writers”.
- darwin/windows/iOS/Android: cross-build only or unsupported; never executed.
- Bare-metal Linux not tested.
- Earlier crash probes (`close-then-use`, `close-during-list`,
  `slow-uncancellable`, etc.) are author observations only and were not
  re-run in the latest round.
- glibc requirement bounded only as “fails on 2.36, works on 2.41”.
- No changes to the root `go.mod`, other repositories, or CI.
