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
`proxy.golang.org` on 2026-09-24 (host clock). Latest published release line is
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

Actual command result (2026-09-24, macOS 27.0.1 / Apple M2 Max, OrbStack Docker
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
- `OperatorInfo.GetName()` returned non-reproducible garbage/dangling data
  (`len` varied 10→14 across runs) because `Info()` frees the underlying
  `opendal_operator_info` right after copying; the spike therefore does not call
  `GetName()`. Scheme/root are stable.

## 3. Platform matrix (host = macOS arm64, no official darwin native library)

| Target | Official native lib? | What was actually done | Result |
| --- | --- | --- | --- |
| linux/arm64 (container on this Mac) | yes, embedded in module | built + **executed** real write/read/list/close | PASS |
| linux/amd64 (container on this Mac) | yes, embedded in module | cross-built for amd64, **executed** under emulation | PASS |
| darwin/arm64 (host) | **no** | `GOOS=darwin go build` succeeds (guard `cmd/memory/status_unsupported.go`), executing prints unsupported and exits 3 | not runnable — native lib not published |
| darwin/amd64 | **no** | `go vet` cross-compile only | cross-build only, never executed |
| windows/amd64 | **no** | `go vet` cross-compile only | cross-build only, never executed |
| linux/arm64 natively (bare metal, no container) | yes | not tested in this session | untested |
| linux/amd64 natively (bare metal, no container) | yes | not tested in this session | untested |

Container execution is **not** a real-machine claim: linux/* rows mean the
official native `.so` ran inside a Linux container on this Mac, not on a Linux
host. `darwin`/`windows` cross-build success must never be reported as a
working native run.
