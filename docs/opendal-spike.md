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

Actual command result (2026-11-10, macOS 27.0.1 / Apple M2 Max, OrbStack Docker
running the official **linux/arm64** native library in `golang:1.24-trixie`):

```
[..] go=go1.24.13 os=linux arch=arm64
[..] binding=github.com/apache/opendal/bindings/go v0.1.16 companion=github.com/apache/opendal-go-services/memory v0.1.16
[..] native lib path=/tmp/libopendal_c3015367854.so
[..] info scheme=memory root="/" read=true write=true list=true
[..] PASS Write: 3 synthetic objects
[..] PASS Read: byte-for-byte match
[..] PASS Stat: len=32
[..] PASS List(non-recursive): got=[spike/hello.txt spike/nested/] err=<nil>
[..] PASS Read-missing=CodeNotFound: err=3 NotFound (permanent) at read, context: { service: memory, path: spike/does-not-exist, range: 0- } => memory doesn't have this path
[..] RESULT: PASS
[..] PASS Close
```

The same program passes unchanged on `--platform linux/amd64`:
`RESULT: PASS`, `PASS Close`.

Binding API notes found while writing it (v0.1.16):

- `Operator.Close()` returns nothing; `Lister` has `Error()` (not `Err()`).
- Recursive listing is **not** available in this binding version (`List(path)`
  takes no options; the doc comment says recursion is unsupported), so the list
  check is single-level.
- Capabilities are `Info().GetFullCapability()` / `GetNativeCapability()`.
- `OperatorInfo.GetName()` is broken in v0.1.16: it returns a formatted pointer
  string (e.g. `0xffff38…`) instead of the backend name, because the FFI wrapper
  reads the returned pointer as a C string. Scheme/root are stable; the spike
  does not rely on `GetName()`.

## 3. Task 2 — failure, timeout, capability, error and cancellation boundaries

Program: `tools/opendal-spike/cmd/probe`; runner: `tools/opendal-spike/run-probes.sh`.
Every case runs in its own process (`timeout 25s`, `slow-uncancellable` 5s)
because several cases intentionally panic or never return. Synthetic memory
data only.

Actual result summary (linux/arm64, `golang:1.24-trixie`, 2026-11-10):

| Case | Exit | Observation |
| --- | --- | --- |
| `load-missing` | 0 | `NewOperator` → `/tmp/.../libopendal_c.so: cannot open shared object file: No such file or directory`; plain `error`, **not** `*opendal.Error` |
| `load-corrupt` | 0 | → `/tmp/corrupt-libopendal.so: file too short`; plain error |
| `load-tmpdir` | 0 | `opendal/services/memory: cannot create temp file: open /nonexistent-spike-tmp/...: no such file or directory` |
| `timeout-invalid` | 0 | `WithTimeout(0,0)` → `timeout must be positive` at construction |
| `info-name` | 0 | `GetName()` returned a 14-byte string like `0xffff38…` 50/50 times — a formatted pointer, **not** the backend name |
| `capabilities` | 0 | full: stat/read/write/list/delete/create_dir/list_recursive=true, copy/rename/presign=false; native: create_dir=false; `Rename`/`PresignRead` → `CodeUnsupported (1)` |
| `error-matrix` | 0 | read/stat missing → `CodeNotFound (3)`; read `dir/` → `CodeIsADirectory (5)`; delete missing → `nil`; rename missing → `CodeUnsupported (1)` (capability gate wins over path check); list missing dir → 0 entries, `nil` error |
| `timeout-io` | 0 | `WithTimeout(1s, 1ns)`: 13 B and 8 MiB write/read all succeeded in 0.1–6 ms with `err=nil`; no timeout expiry observed |
| `close-then-use` | **2** | `op.Close()` then `op.Read()` → `SIGSEGV: segmentation violation` in the FFI call |
| `close-during-list` | **2** | `op.Close()` while another goroutine lists 2000 keys → `SIGSEGV` |
| `slow-uncancellable` | **124** | loop writing 1 MiB objects; only the external `timeout 5s` stopped it |

### Interpretation

- **Native load failures are returned, not fatal**, but they are plain Go errors
  from `dlopen`/temp-file creation, so callers must not assume
  `errors.As(err, *opendal.Error)`. Companion `LoadOnce` caches the first error
  in a `sync.Once`, so a failed load cannot be retried in-process.
- **Timeout is configuration, not a cancellation primitive.** The layer is
  accepted and validated, but with the in-memory backend every operation
  finished far below even a 1 ns IO budget, so expiry was never observed.
  The binding has **no per-call `context.Context`** (verified against
  `reader.go`, `opendal.go` and the production guide): a blocked/long operation
  cannot be cancelled in-process. The only proven bound is killing the process
  (`slow-uncancellable` exit 124). Treat timeout expiry as unverified until a
  slow but credential-free backend is introduced.
- **Capability is honest for copy/rename/presign**, but full vs native disagree
  on `create_dir` (compat layer emulates it). Check capabilities before optional
  calls, and still handle `CodeUnsupported` because rename-on-missing surfaces
  `Unsupported` before `NotFound`.
- **Close is destructive and not concurrency-safe.** Using an operator after
  `Close`, or closing while an operation is in flight, segfaults the whole
  process (Go reports SIGSEGV, exit 2). Ownership must be single-goroutine:
  quiesce all operations before `Close`, never share an operator across
  independent lifetimes.
- **`OperatorInfo.GetName()` is unusable in v0.1.16** (returns a hex pointer
  string). Use `GetScheme()`/`GetRoot()` instead.

## 4. Platform matrix (host = macOS arm64, no official darwin native library)

| Target | Official native lib? | What was actually done | Result |
| --- | --- | --- | --- |
| linux/arm64 (container on this Mac) | yes, embedded in module | built + **executed** `cmd/memory` and the full `cmd/probe` suite | memory PASS; probes as in §3 |
| linux/amd64 (container on this Mac) | yes, embedded in module | cross-built for amd64 and **executed** under emulation | memory PASS; same probe outcomes |
| darwin/arm64 (host) | **no** | `go build` OK; executing `cmd/memory` prints the unsupported guard and exits 3 | not runnable — native lib not published |
| darwin/amd64 | **no** | `GOOS=darwin GOARCH=amd64 go build ./...` OK | cross-build only, never executed |
| windows/amd64 | **no** | `GOOS=windows GOARCH=amd64 go build ./...` OK | cross-build only, never executed |
| windows/arm64 | **no** | `GOOS=windows GOARCH=arm64 go build ./...` OK | cross-build only, never executed |
| linux/amd64 or arm64, bare metal | yes | not tested in this session | untested |
| Debian bookworm (glibc 2.36) | yes, but too-old glibc | built + executed in container | `GLIBC_2.38 not found` at load |
| alpine/musl | yes, but glibc-linked | built + executed in container | `jupiterrider/ffi` init fails (no musl artifact) |
| onedrive companion | **module not published** | proxy 404 / `no matching versions` | unsupported as a Go companion; no fake implemented |
| s3 companion | yes (module `v0.1.16`) | version/hash pinned only | never executed or connected (no credentials, no network allowed) |

Container execution is **not** a real-machine claim: linux/* rows mean the
official native `.so` ran inside a Linux container on this Mac, not on a Linux
host. `darwin`/`windows` build success must never be reported as a working
native run.

Actual cross-build commands and results:

```
$ for t in darwin/arm64 darwin/amd64 windows/amd64 windows/arm64 linux/amd64 linux/arm64; do
    GOOS=${t%/*} GOARCH=${t#*/} go build -o /dev/null ./...
  done
darwin/arm64 build=ok
darwin/amd64 build=ok
windows/amd64 build=ok
windows/arm64 build=ok
linux/amd64 build=ok
linux/arm64 build=ok

$ go build -o /tmp/spike-host ./cmd/memory && /tmp/spike-host; echo exit=$?
opendal-spike/memory: official opendal-go-services/memory supports only linux/amd64 and linux/arm64; this build is / (unsupported)
exit=3
```

## 5. Unfinished / not proven

- Timeout **expiry** was never observed (memory backend too fast); only
  configuration, validation, and external process-kill bounding were proven.
- No in-process cancellation exists to test; `Close` is unsafe during in-flight
  work and is not a cancellation mechanism.
- s3/onedrive were **not** run at all: no cloud credentials are read, no real
  S3/OneDrive endpoint is contacted, and no product integration is implemented.
  The onedrive Go companion module has no published version, so it cannot even
  be compiled against today.
- darwin/windows binaries were cross-built but never executed (no official
  native library for those platforms).
- Bare-metal Linux (non-container) was not tested.
- No stress test of concurrent reads/writes on a live operator (only
  close-during-list); no exhaustive enumeration of every error code.
- glibc requirement is bounded only as “fails on 2.36, works on 2.41”; not
  bisected.
- No changes to the root `go.mod`, other repositories, or CI.
