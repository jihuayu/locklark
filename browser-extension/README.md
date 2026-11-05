# Locklark browser login fill

This slice connects an extension to a **separate MyGo native process**. Unlocking
the ordinary desktop application does not unlock this process. Next.js management
pages have no access to this channel, factors, pairing, or field values.

Build with Node 24 and the Go version in `go.mod`:

```sh
node browser-extension/build.js chromium
node browser-extension/build.js firefox
go build -o /absolute/path/locklark-browser-chromium ./cmd/locklark-browser-chromium
go build -o /absolute/path/locklark-browser-firefox ./cmd/locklark-browser-firefox
go build -o /absolute/path/locklark-browser-register ./cmd/locklark-browser-register
```

Load `browser-extension/dist/chromium` as an unpacked Chrome/Edge extension. Its
public manifest key fixes the development ID to
`geldnhjapnackobgknocomedmjgphnpe`; it is not a release signature. The Firefox
package fixes its addon ID to `browser@locklark.local`. Firefox can be loaded as a
temporary addon for development; release packaging/signing is separate.

Register the matching binary; this writes a manifest to the selected browser's
per-user directory and refuses overwrite unless `--replace` is explicit:

```sh
/absolute/path/locklark-browser-register --browser chrome --host /absolute/path/locklark-browser-chromium
/absolute/path/locklark-browser-register --browser edge --host /absolute/path/locklark-browser-chromium
/absolute/path/locklark-browser-register --browser firefox --host /absolute/path/locklark-browser-firefox
```

`--output /absolute/directory/org.locklark.browser.json` selects an isolated
profile directory. Chromium profiles use `<user-data-dir>/NativeMessagingHosts`.
Default Linux directories are `~/.config/google-chrome/NativeMessagingHosts`,
`~/.config/microsoft-edge/NativeMessagingHosts`, and
`~/.mozilla/native-messaging-hosts`. macOS uses
`~/Library/Application Support/Google/Chrome/NativeMessagingHosts`,
`~/Library/Application Support/Microsoft Edge/NativeMessagingHosts`, and
`~/Library/Application Support/Mozilla/NativeMessagingHosts`.

On Windows, use absolute `.exe` paths and add `--register-user` to the relevant
registration command. This writes the absolute manifest path to the default
value of the corresponding `HKCU\Software\Google\Chrome\NativeMessagingHosts\org.locklark.browser`,
`HKCU\Software\Microsoft\Edge\NativeMessagingHosts\org.locklark.browser`, or
`HKCU\Software\Mozilla\NativeMessagingHosts\org.locklark.browser` key using Go's
registry API. No elevation or shell is used. The default manifest is under
`%APPDATA%\Locklark\NativeMessagingHosts\<browser>`. Existing registry entries
also require explicit `--replace`. Windows registration/native messaging and
macOS native messaging remain untested here.

Registration checks the executable, manifest, and their ancestor ownership and
write permissions. It rejects final symlinks/reparse points and publication or
binary parent directories writable by unrelated users. On Windows, higher
existing ancestors may grant only new-child creation rights, while every
existing child must deny unrelated deletion, replacement, and ACL/owner changes.
Unix permits root-owned sticky temporary roots
containing protected user directories. New manifests use a restricted temporary
file and atomic publication/replacement; Windows creates protected DACLs before
writing and also checks the HKCU registration key and its ancestors. Unsupported
or insufficiently protected layouts fail closed.

Visit a supported HTTPS page and open the extension action (Chrome/Edge:
Ctrl+Shift+Y, or Command+Shift+Y on macOS; Firefox: toolbar), then connect. In the native window select the vault,
unlock, and confirm the fixed extension connection. Read the current website's
login candidates in the popup, choose a login, and approve its exact origin,
item, and revision in the native window. The extension fills only one visible,
enabled, writable username/password pair in one form and never calls submit.
It refuses ambiguous forms, cross-origin actions, frames, IP/IDN/local hosts,
and unsupported document identity APIs. Firefox requires version 153 or newer:
its `documentId` and `documentIds` APIs were exercised in real Firefox 157,
including rejection of an old document ID after navigation. Missing document
identity fails closed. Real Linux Chromium and Firefox extension/native/MyGo
fill flows have also passed; see the validation record for exact runs. Other
platforms and system biometric hardware still require their own acceptance.

Firefox opens this action from its toolbar. It has no default shortcut because
Firefox reserves common browser shortcuts; users can choose one in Firefox's
extension shortcut settings. Chrome/Edge keep the shortcut above.

The extension has only `activeTab`, `scripting`, and `nativeMessaging`. There is
no persistent host permission, page-message bridge, value persistence, or
localhost secret proxy. Origin, active tab, and document identity are obtained
from browser APIs and rechecked before matching, selecting, and injecting.
The final injection explicitly targets the original document ID. An old response
is never redirected to a newly navigated document.

Connections have a fixed 15-minute lifetime, pairing requests expire after one
minute, native fill requests after 30 seconds, and prepared field pairs after
five seconds. Browser traffic does not renew the native session's idle timer.
Lock, disconnect, cancellation, and expiry revoke pending requests; unlocking
again requires new pairing. A cancellation cannot recall bytes already being
written or fields already injected. Pipe failures remain delivery unknown; audit
records contain committed intent and a purpose-separated binding digest, never
the values or a claim that the website received them.

Native launch allowlists constrain normal browser invocation. An application
running as the same OS user can forge process arguments or control that user's
software; native messaging does not isolate that attacker. The host trusts the
fixed extension's browser API assertions and cannot independently attest a tab.

Checks:

```sh
node --test browser-extension/test/*.test.js
go test -race ./internal/browserhost
go test ./internal/personal ./internal/desktop
LOCKLARK_TEST_PLAYWRIGHT=/absolute/path/to/playwright node scripts/browser_extension_dom.cjs
```

Node tests use a simulated browser API only for worker races and policy checks.
The DOM script runs the actual static fill function in Chromium, including form
and iframe refusals. These do not replace real extension/native/MyGo UI approval
acceptance, independent review, or platform-specific hardware tests.

After receiving a field response, browser API verification and injection waits
have finite deadlines and abort on lock/navigation. The worker clears its
response references in `finally`. An injection already dispatched to the browser
cannot be recalled; a timeout leaves its result unknown and is never retried.
Each dispatched function carries a 1500ms absolute expiry and checks it at entry
and immediately before both writes, so a queued late-starting script refuses.


Real Linux native acceptance uses the repository scripts
`scripts/browser_native_acceptance.mjs` and
`scripts/browser_firefox_native_acceptance.mjs` inside a private DBus session and
an isolated Xvfb display. The scripts perform actual unlock, pairing and approval
through AT-SPI control labels and XTest input, without product approval hooks.
Linux native hosts restore the system accessibility bridge by dropping the
browser-internal `NO_AT_BRIDGE` flag inherited from Chromium or Firefox.

Firefox acceptance additionally needs Mozilla geckodriver 0.36.0 and
`libnss3-tools`; it trusts only its temporary test CA in a fresh Firefox profile.
Its native registration helper refuses an existing user manifest, and cleanup
removes only the exact unmodified file created for that run. Private diagnostics
capture the matched host window or the test popup, never the whole desktop.
See [the validation record](../docs/browser-native-validation.md) and the script
headers for dependencies and environment variables.
