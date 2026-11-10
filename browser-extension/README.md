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
Ctrl+Shift+Y, or Command+Shift+Y on macOS). Connect, unlock the native vault,
and choose **连接并启用快捷填充** to authorize explicit account selection,
saving/updating and TOTP filling for this connection. **确认连接此扩展** retains
per-operation native approval. Locking or disconnecting revokes either mode.

Focus a login field to select a saved account in the page, or use the popup.
The extension recognizes visible semantic username/current-password fields,
including individual username/password steps. It refuses ambiguous targets,
new-password forms, cross-origin actions, frames, IP/IDN/local hosts and missing
document identity. Two-step pages currently require selection on each step.

**选择账号后自动登录** is enabled by default. Each login also has an opt-out.
Automatic submission requires a complete username/current-password pair, a POST
form and exactly one visible same-origin submitter. Form actions are rechecked
after input/change handlers. Signup/reset/destructive buttons are excluded.
Other forms are filled without submission. This is not proof of successful login;
check the website's result. OTP is never automatically submitted.

Chromium requires version 120 or newer. Firefox retains its version 153 minimum;
its earlier manual fill/save/OTP implementation was tested in real Firefox 157.
The new inline/Passkey experience is prioritized and tested on Chromium; Edge,
Firefox and other OS versions require their own acceptance.

Firefox opens this action from its toolbar. It has no default shortcut because
Firefox reserves common browser shortcuts; users can choose one in Firefox's
extension shortcut settings. Chrome/Edge keep the shortcut above.

To save credentials already entered on a supported page, choose **保存当前登录**
(Save current login). In the native window verify the exact website, choose the
new title, and approve (or use the explicitly authorized quick session). To update a saved login, first read the website's
candidates, choose **更新此登录** (Update this login), and confirm the displayed
item in the native window. Update replaces only the username/password pair;
title, URL, OTP and other item metadata remain unchanged. New entries store the
canonical HTTPS origin as their website.

Save captures the field pair at the explicit click, not after native approval.
Changing the page's values while approval is pending does not replace that
snapshot. After approval the extension performs a short final check of the
original active browser window, tab, document and origin before requesting the
single vault transaction. It does not automatically watch submissions or save values. Password form submission is governed by the separate auto-login setting. The popup receives no captured values.

**已批准** means approved and still checking; only **已保存** means saved with a
confirmed receipt. **结果未确认** means the result is unknown: inspect the item
in the desktop vault before deciding what to do, and do not blindly repeat the
save. A cancellation that reaches the host before persistence wins prevents the
write; a later navigation, lock, or broken connection cannot retract a
transaction that already won. Browser state and database commit are not one
atomic operation. See [save validation](../docs/browser-save-validation.md) for
the exact verification status and limitations.

**Paste protection** is on by default and can be turned off in the extension
options. Pasting into a current-password field on a page whose last candidate
lookup explicitly reported no saved login shows a confirmation panel first;
cancelling blocks the paste. Pasting text shaped like a Locklark Secret Key
(`LL1-`, `LLR2-`, or the 110-character recovery material) is always confirmed,
even on a linked page. An unknown site state (locked vault, disconnected host,
or an expired observation) never blocks a paste, and signup/confirm-password
fields are excluded so generated passwords can still be pasted. The pasted text
stays in the content script for the single decision and is never sent to the
worker or stored. See
[the 1Password beta parity note](../docs/browser-1password-beta-parity.md) for
the reference behaviour, decision table and limits.

To fill a saved TOTP, configure the login's `otp` field in the native vault,
read the current website's candidates, and choose **填充验证码** (Fill one-time
code). Approve that exact website and item in MyGo, or select it in an authorized quick session. The extension rechecks the
original document before requesting the code. It supports one visible, writable
top-level `input[autocomplete=one-time-code]` in a same-origin form, with a
6- or 8-digit code. Split fields, multiple targets, frames and cross-origin form
actions or submitters are refused. It never calls submit or automatically obtains
the next period's code. Seeds and codes do not appear in the popup, extension
storage or Next.js management pages.

**取消本次验证码** cancels the pending OTP operation. Confirmed cancellation is
shown only when the host confirms cancellation and local injection has not
started. **验证码填充结果未确认** means to inspect the page before deciding what
to do; disconnecting or reconnecting does not erase this uncertainty. A fresh
explicit request is allowed and follows the current pairing mode. There is no
automatic retry. An injection already submitted to the browser cannot be
recalled by cancelling its pending promise.

OTP has a separate intent action and single-use challenge, acknowledgement and
output grant. The final document probe starts a 1500ms budget; page and worker
monotonic clocks are checked within their own contexts, with wall-clock checks
providing additional refusal. Receiving a reply cannot renew that budget or the
original TOTP period. Only the dedicated writer path may serialize a granted
code. Production native pipe writes have a fatal watchdog, including ordinary
metadata replies, so a blocked inherited stdout cannot hold the connection
indefinitely. See [OTP design](../docs/browser-otp-design.md) and
[OTP validation](../docs/browser-otp-validation.md) for the exact evidence and
remaining platform checks.

The extension requests `activeTab`, `scripting`, `nativeMessaging`, `storage`
and persistent `https://*/*` access. HTTPS permission enables the in-page UI and
document-start WebAuthn integration; the browser displays this access at install.
Storage contains only preferences and per-item automatic-login overrides, never
passwords, vault factors, private keys, or TOTP values. There is no localhost proxy.
The worker authenticates content-script senders using extension ID, frame, active
tab, document ID and browser-provided URL. Page-provided origin fields have no
authority. Password injection targets the original document, and password values
never pass through the MAIN-world message bridge.

Passkey create/get calls offer Locklark or the browser's other authenticators.
The native window shows the authoritative origin/RP ID and offers a new login,
an eligible existing login, or a matching saved Passkey. It never silently
replaces an existing Passkey. Requests requiring user verification need fresh
master-password and Secret Key verification in the native window. The unlocked
session or an OS Secret Service lookup alone does not set the WebAuthn UV flag.

Each login can hold up to 16 ES256 discoverable credentials in a protected KDBX
field, and every credential carries its own opaque content revision alongside the
login revision.
Private keys stay in the encrypted vault; creation and assertion intent use
signed, encrypted audit records. Backup/restore retains the credential. Standard
responses include RP/challenge binding, `none` attestation, COSE public keys,
UP/UV/BE flags and a zero multi-device signature counter. Requests validate
public and private public-suffix boundaries, respect top-level Permissions Policy,
and support `AbortSignal`. Native confirmation remains required for Passkeys in
quick mode. Unsupported algorithms/extensions use the original browser flow.
Separate popup settings disable offers to save/use Passkeys.

Conditional account buttons, popup credential views and removals bind the full
public selector: login ID, parent revision, credential ID and the exact
per-credential revision. A missing, stale or unknown selector is refused with no
first-credential fallback, sibling credentials under one login stay distinct
options, and the projection never carries a user handle, private key or raw
record. The popup lists and removes each credential independently; removing the
last one keeps the login and its other fields.

Known Passkey gaps include PRF/largeBlob, related origins, iframe credentials and
biometric verification in this new flow.
This is an initial implementation, not complete 1Password feature parity. The
[coverage and validation record](../docs/browser-parity-validation.md) tracks the
remaining work and the distinction between implemented and tested platforms.

Connections have a fixed 15-minute lifetime, pairing requests expire after one
minute, native fill requests after 30 seconds, and prepared field pairs after
five seconds. Metadata polling does not renew idle time; explicit approved operations do. Passkey requests expire within two minutes or the shorter supplied timeout.
Lock, disconnect, cancellation, and expiry revoke pending requests; unlocking
again requires new pairing. A cancellation cannot recall bytes already being
written or fields already injected. Pipe failures remain delivery unknown; audit
records contain committed intent and a purpose-separated binding digest, never
the values or a claim that the website received them.

Repeated message IDs are silently ignored without another terminal reply or
side effect, even when reused with another message type. They still count toward
the connection's 128-message budget. This prevents old cancellation or commit
messages from disrupting a new operation.

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
# Requires real DBus/X11, native host, and Playwright; no approval bypasses:
LOCKLARK_TEST_BROWSER_PARITY=1 node scripts/browser_native_acceptance.mjs
```

Node tests use a simulated browser API only for worker races and policy checks.
The DOM script runs the actual static fill/capture and OTP functions in Chromium and
Firefox, including form/iframe refusals and Unicode bounds. These do not replace real extension/native/MyGo UI approval
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
OTP stages disable diagnostic screenshots and scan controller output, native
logs and persistent diagnostics for synthetic factors and window-specific codes;
the separate OTP privacy wrapper also exercises a real driver argument failure.
See [the validation record](../docs/browser-native-validation.md) and the script
headers for dependencies and environment variables.
