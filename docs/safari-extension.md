# Safari extension package (foundation)

This tree is the **build and transport foundation** for a macOS Safari web
extension. It is not a claim that Safari has been run, that an app is signed,
or that signed Safari installation and runtime flows have passed. The compiled
`locklark-browser-safari` helper implements the fixed Darwin-only
`--safari-browser` mode; other OSes and arbitrary launch arguments refuse it.

Apple's transport reference:
<https://developer.apple.com/documentation/safariservices/messaging-between-the-app-and-javascript-in-a-safari-web-extension>

The relevant asymmetry is:

- `runtime.sendNativeMessage` invokes the extension's native handler
  (`NSExtensionRequestHandling.beginRequest`) and returns the handler response.
- Safari's `connectNative` does not expose the Chromium-style installed stdio
  native host / duplex `Port` process. Do not assume a Chrome native messaging
  process exists on Safari.
- Therefore the Safari build inserts `safari-native-port.js` as a
  **background-only** shim before `background.js`. It adapts
  `runtime.sendNativeMessage` into the Port surface (`postMessage`,
  `disconnect`, `onMessage`, `onDisconnect`) that `background.js` already uses.

## Fixed identities

| Item | Fixed value |
| --- | --- |
| Containing macOS app bundle ID | `org.locklark.browser.safari` |
| Safari web extension bundle ID | `org.locklark.browser.safari.Extension` |
| App group | `group.org.locklark.browser.safari` |
| Native host name used by the shim | `org.locklark.browser` |
| Embedded helper | `locklark-browser-safari` |

The Team ID comes from the signed build and Info.plist. Blank values,
placeholders (`REPLACE`, `CHANGEME`, `YOUR_`, `PLACEHOLDER`, `EXAMPLE`,
`TEAMID`, `UNSIGNED`, unresolved `$(...)`) and identity mismatches fail closed
at runtime. `ConfiguredIdentity` also requires the exact fixed IDs above, and
the extension bundle ID must equal the app bundle ID plus `.Extension`.

## Transport shape

```
background.js
  -> safari-native-port.js (explicit connector, safari-web-extension:// only)
       -> runtime.sendNativeMessage("org.locklark.browser", envelope)
            -> SafariWebExtensionHandler.beginRequest
                 -> app-group UNIX socket native/relay.sock
                      -> containing app RelayServer
                           -> fixed embedded locklark-browser-safari
                              (Foundation.Process + 4-byte LE framed stdio)
```

The envelope is strictly one of:

- `{"v":1,"op":"open","token":"<32 lowercase hex>"}`
- `{"v":1,"op":"send","token":"…","frame":{…}}`
- `{"v":1,"op":"poll","token":"…"}`
- `{"v":1,"op":"close","token":"…"}`

Replies are only `{v,token,ok,frames}` or `{v,token,ok:false}`; failures carry
no error text, frames or approval. Frames are limited to 256 KiB, 64 frames
per reply/poll, one outstanding poll, 64 queued host frames, 2 MiB queued
bytes, 8 app sessions and a 30-minute session TTL. Every native call failure,
timeout, bad token, oversized/mistyped/unknown reply or ambiguous result closes
the Port with a fixed safe reason. Mutating frames are never retried.

The shim exports an explicit connector and never patches `runtime.connectNative`
or replaces `globalThis.chrome`/`browser`. The background selects it only for a
Safari extension runtime and the fixed native host. It is never listed in
`content_scripts` or the `MAIN` world.

## Security boundaries

- The Safari extension handler reads `SFExtensionMessageKey` and, when
  available, `SFExtensionProfileKey`; it validates the envelope before
  forwarding and never logs raw requests or errors. Apple's example on the
  page linked above passes `SFExtensionProfileKey` as a `UUID`, not a string,
  so the value is decoded by `TrustedSafariProfile.identifier`: `nil` stays
  `nil` (key absent, or macOS 13 where the key does not exist), a `UUID`
  becomes its lowercase canonical `uuidString`, and any other present type
  (`String`, `NSNull`, a number) cancels the request with the fixed
  `RelayError.unavailable` before the relay runs. A wrong type is never
  downgraded to `nil`, so a profiled session cannot be reached as an
  unprofiled one. The profile is still never taken from JavaScript, and the
  exact Optional profile check in `SessionProfileTable` is unchanged.
- Two envelope parsers exist. The browser/JS parser accepts only
  `v`/`op`/`token`(/`frame`) and **refuses any `profile` field**, so page
  content can never choose or spoof a profile. The trusted parser for the
  app-group hop is used only after the `SecCode`/Team/bundle/UID peer check and
  accepts the bounded, NUL-free `profile` on *every* operation.
- The profile a session is bound to comes only from the native handler context
  (`SFExtensionProfileKey`) and is forwarded on open, send, poll and close. The
  containing app requires *exact* Optional equality between the stored and
  incoming profile for every operation: `nil` only reaches a `nil`-bound session
  (Safari without profiles), a non-nil profile never reaches a `nil` session or
  a different profile, and a mismatched `close` is refused without removing the
  session. The token remains a random 128-bit bearer value; the profile binds
  the session, it does not replace the token.
- Every write follows one SIGPIPE policy, with no process-wide SIGPIPE ignore.
  Sockets get `SO_NOSIGPIPE` at creation and accept (a failure is refused), and
  each write blocks SIGPIPE for the calling thread only, restores the caller's
  exact original pthread signal mask on every return path, never consumes a
  SIGPIPE that was already pending, and consumes only the thread-directed
  SIGPIPE its own failed write raised (checked with `sigpending`/`sigwait`
  before the mask is restored). A closed-peer socket write or a write to an
  exited helper's stdin returns the fixed `RelayError.unavailable` instead of
  terminating the app or extension process, and a partially written frame is
  never retried.
- The app-group container path is resolved only through
  `FileManager.containerURL(forSecurityApplicationGroupIdentifier:)`. No
  JavaScript-supplied path, executable, argv or environment is accepted.
- The containing app, only after a normal user launch, starts the fixed
  embedded `locklark-browser-safari` binary with fixed arguments. The
  Application Extension never launches processes.
- Before accepting app-group IPC, the app pins the peer UID **and** validates
  `SecCode` against a fixed requirement containing the same Team ID and the
  exact extension bundle identifier. UID alone is never trusted.
- If the helper is missing, exits, violates framing, or produces a bad frame,
  the relay reports `unavailable`/failure and closes. It never fabricates a
  protocol reply or approval.

## Build

Signed build (required for an installable Safari extension):

```sh
LOCKLARK_TEAM_ID=ABCDE12345 \
LOCKLARK_APP_GROUP_ID=group.org.locklark.browser.safari \
LOCKLARK_SAFARI_HELPER=/absolute/path/locklark-browser-safari \
safari/scripts/build_safari.sh
```

The helper basename must be exactly `locklark-browser-safari`, must be
executable, and in a signed build must already be signed by the same Team ID.
The script generates the Xcode project with the checked-in
`safari/project.yml` (XcodeGen), runs `node browser-extension/build.js safari`,
verifies the package, and builds `Locklark.app` with the extension embedded.

Unsigned compile-only mode for CI:

```sh
LOCKLARK_UNSIGNED_CI=1 \
LOCKLARK_SAFARI_HELPER=/absolute/path/locklark-browser-safari \
safari/scripts/build_safari.sh
```

This sets `CODE_SIGNING_ALLOWED=NO`/`CODE_SIGNING_REQUIRED=NO`. It is **not**
an installed or signed Safari extension and does not prove Safari loads it.
If the helper is absent, CI may additionally set
`LOCKLARK_ALLOW_MISSING_HELPER=1`; the app then reports `unavailable` at
runtime instead of faking a helper. Signature checks are never disabled to force
a passing signed build.

## Tests and current status

Static/package tests run on this Linux worker:

```sh
node --test browser-extension/test/safari_native_port.test.js
python3 scripts/test_safari_package.py
python3 scripts/test_safari_package.py --verify-dist
```

Swift foundation tests are checked in under `safari/Tests` and are run by:

```sh
safari/scripts/test_safari_swift.sh
```

That script also builds and runs the standalone native probe
`safari/TestProbe/Sources/main.swift` (`LocklarkSafariSIGPipeProbe`), which sets
SIGPIPE to `SIG_DFL` **in its own process** (never in the XCTest host) and
requires that a closed-peer `socketpair` write and a closed-pipe write both
return the fixed failure, that the process survives, and that the caller thread
mask (including a SIGPIPE that was already pending) is preserved.

The macOS GitHub job for source `27445a1` actually compiled the Swift package
and passed 43 XCTest cases. It subsequently failed before the Xcode app build
because the package script had not generated the Chromium comparison baseline;
that build order is corrected in the current source. The job ran `swift test`
directly, so its 43 passes do not establish execution of the standalone SIGPIPE
probe. CI now invokes the complete script above, including that probe.

Linux package tests and source review do not establish Xcode app compilation,
Apple signing, installation or Safari runtime behavior. Record the final commit
and actual macOS job result before crediting each of those checks.

## Integration still required

- Complete a successful Xcode containing-app and extension build using the
  actual Go helper. Unsigned compilation does not establish installation.
- Signing/notarization with matching app, extension and app-group entitlements,
  and the Team ID used in `PeerVerifier`.
- Real Safari installation and password/OTP/Passkey, lock, cancel, navigation,
  reconnect and update acceptance under the signed identity.

## Build order and baseline verification

`browser-extension/build.js` treats Safari as an explicit opt-in mode: with no
argument it produces only the `chromium` and `firefox` packages, whose manifest
bytes are frozen by hashes in `scripts/test_safari_package.py`.

`safari/scripts/build_safari.sh` therefore builds the default baseline first and then
the Safari package:

```
node browser-extension/build.js          # tracked Chromium + Firefox baseline
node browser-extension/build.js safari   # opt-in Safari package
python3 scripts/test_safari_package.py --verify-dist
```

A Safari-only build on a clean tree is still rejected by the verifier, because
it holds the Safari manifest to the Chromium baseline's `content_scripts`,
`action`, `options_ui`, `commands`, `name` and `version`; the failure now says
the baseline is missing instead of raising a bare file error. Rebuilding Safari
never changes the Chromium/Firefox bytes, and `--verify-dist` remains a strict
comparison rather than a relaxed or skipped check.
