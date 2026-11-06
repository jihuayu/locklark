# Native mobile core contract

Go import: `github.com/jihuayu/locklark/mobile/core`; package name: `mobilecore`.
Gomobile Java package: `mobilecore`; Objective-C module is `Mobilecore` with
`gomobile bind -prefix Mobilecore`. Generated language signatures are authoritative.

Only native app code may call this package. Never expose it to JavaScript, IPC,
an agent, or a remote renderer. Calls that access a vault or OS store run on a
worker. Mutable secret input buffers are consumed and cleared by Go; native
copies must also be cleared by the app.

```go
Open(path string) (*Vault, error) // absolute app-private database path
GenerateSecretKey() ([]byte, error) // new random 16-byte account Secret Key
FormatSecretKey(key []byte) string
ParseSecretKey(text string) ([]byte, error)

(*Vault).Create(password, secretKey []byte) error // creates locked vault
(*Vault).Unlock(password, secretKey []byte) error // both factors; idle 300s
(*Vault).IsUnlocked() bool
(*Vault).RequestLock() // immediate invalidation/cancellation, no disk wait
(*Vault).Lock()        // invalidate, then complete cleanup
(*Vault).Close()       // permanently close wrapper and clear session
(*Vault).List(state string) (*Rows, error)
(*Vault).Search(query, state string) (*Rows, error) // title-only
(*Vault).CreateLogin(title, url string, username, password []byte) (*Receipt, error)
(*Vault).GenerateLogin(title, url string, username []byte, length int) (*Receipt, error)
(*Vault).EditField(id, revision, field string, value []byte) (*Receipt, error)
(*Vault).RegeneratePassword(id, revision string, length int) (*Receipt, error)
(*Vault).RevealField(id, revision, field string) (*SecretValue, error)
(*Vault).RevealOTP(id, revision string) (*SecretValue, error)
(*Vault).EnableSystemUnlock(store SystemUnlockStore) error
(*Vault).UnlockWithSystem(store SystemUnlockStore) error
(*Vault).DisableSystemUnlock(store SystemUnlockStore) error

(*Rows).Count() int
(*Rows).At(index int) (*Row, error)
// Row exported metadata fields: ID, Revision, Title, State.
// Receipt exported metadata fields: ID, Revision, Length, EntropyBits.
(*SecretValue).Take() ([]byte, error) // explicit, one-use disclosure
(*SecretValue).UntilUnixMilli() int64 // display deadline; read AFTER Take
(*SecretValue).FromUnixMilli() int64 // reject display if wall clock moves below it
(*SecretValue).Clear()

type SystemUnlockStore interface {
    Store(id string, value []byte) error
    Load(id string) ([]byte, error)
    Delete(id string) error
}
```

Field edits accept existing fields `title`, `url`, `username`, `password`, `otp`,
`notes`. Reads accept `username`, `password`, `notes`; OTP seed has no read API.
Search/list/receipts contain no username, password, notes, seed, or OTP code.
Revision checks are mandatory. Edit UI begins blank; disclosure is a separate
explicit action. Native UI must match its own captured generation before calling
Take, clear secret buffers and visible text on selection/background/lock, and
honor UntilUnixMilli (at most 15 seconds after delivery; OTP clips to its actual
window). Take rechecks vault generation and OTP validity/target revision. It may
perform authenticated disk work; do not block the UI waiting for its result.
RevealField itself creates a metadata-only handle. Take obtains the value in a
fresh exact-revision authenticated transaction and records its one disclosure
intent. That authenticated transaction is the read observation: a later edit by
another independent process cannot retract a delivery that has already begun.
After all blocking work, a short wrapper grant shares the RequestLock mutex.
Lock before this grant refuses bytes; a grant before lock begins delivery and
the native UI must discard its result if its captured generation is stale.

The app must call RequestLock immediately when inactive, before a queued worker
can finish. A late unlock or OS callback cannot reopen the vault. Cancellation
that wins before the mutation commit gate rolls back the write. If persistence
wins but its final result cannot be confirmed, the error says the outcome is
unknown; inspect the vault before retrying. Creating a database may complete
while cancellation occurs and then reports an unknown result, leaving it locked.

SystemUnlockStore is the trusted native Keychain/Keystore adapter. It protects
the existing audited, path/slot-bound identity capsule with authenticated local
OS access, never stores password/Secret Key, and never falls back to plaintext.
The capsule expires 24 hours after the original complete two-factor unlock.
The callback runs outside wrapper locks and must fail when native authentication
is cancelled. Native storage excludes database, capsule, account Secret Key,
and device keys from cloud backup; local encryption keys cannot migrate devices.

The wrapper is exclusively a personal offline vault. It has no network upload
method or team-key access. This increment reuses the established native audit
schema: session/disclosure/quick-unlock actions retain existing `desktop.*` and
`item.desktop.*` names. These events are not evidence of a desktop transport;
mobile provenance is not yet a distinct signed event field. Product claims must
state this limitation until the audit schema has an explicit surface field.
