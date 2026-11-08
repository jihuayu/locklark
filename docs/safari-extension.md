# Safari extension package (foundation)

This tree is the **build and transport foundation** for a macOS Safari web
extension. It is not a claim that Safari has been run, that an app is signed,
or that the native host supports Safari mode. The embedded helper needs the
containing app/desktop owner to add a compiled `SafariBrowser` mode using the
fixed extension identity described below.

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
  -> safari-native-port.js (install only in safari-web-extension://)
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

The shim does not replace `globalThis.chrome`/`browser`, does not install on
Chromium/Firefox-shaped runtimes and is never listed in `content_scripts` or
the `MAIN` world.

## Security boundaries

- The Safari extension handler reads `SFExtensionMessageKey` and, when
  available, `SFExtensionProfileKey`; it validates the envelope before
  forwarding and never logs raw requests or errors.
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

On this worker no Swift toolchain, Xcode, `xcodegen`, code-signing identity,
Safari browser or real Safari installation is available. The Swift sources
have therefore **not** been compiled or executed here; the macOS CI step is the
next action. Exact Apple API availability/signature requirements still need
confirmation by that compile and by a signed run.

## Integration still required

- A compiled `locklark-browser-safari` helper that speaks the existing 4-byte
  little-endian framed native protocol and a Safari/SafariBrowser mode using
  the fixed extension identity. This worker does not add or modify the Go
  host, so none of the Safari path is claimed operational yet.
- Signing/notarization with matching app, extension and app-group
  entitlements, and the Team ID used in `PeerVerifier`.
- Real Safari packaging/installation/acceptance (only possible after the
  above).
