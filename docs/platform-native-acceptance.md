# Platform native acceptance foundation (#50 / #51 / #57)

Status: **foundation only**. Everything below is implemented and unit-tested on
Linux with pure Python fakes. No Windows or macOS run has been performed yet —
there is no hardware/CI proof and this document does not claim one. The
platform CI proof and the real opt-in runs come later from the primary owner.

## What was added

| File | Role |
| --- | --- |
| `scripts/native_acceptance_contract.py` | Shared stdlib-only request contract, fixed error codes, observation/focus/authorisation orchestration |
| `scripts/browser_native_windows.py` | Windows adapter: ctypes Win32 + UI Automation (comtypes, lazy) + `SendInput` |
| `scripts/browser_native_macos.py` | macOS adapter: ApplicationServices AX (PyObjC, lazy) + `CGEventPost` |
| `scripts/native_acceptance_driver.py` | Platform dispatcher; Linux is replayed byte-for-byte into the existing X11 driver |
| `scripts/test_native_acceptance_contract.py` | 31 pure contract tests |
| `scripts/test_native_acceptance_platforms.py` | 30 adapter/dispatcher seam tests (fakes and spies) |

The X11 driver (`scripts/browser_native_x11.py`) and the `.mjs` callers were
**not** edited; switching the callers to the dispatcher is a later integration
step. The existing OS unlock user-verification adapters
(`internal/osunlock/passkey_windows.go`, `internal/osunlock/passkey_darwin.go`,
`internal/osunlock/passkey_darwin.m`) are untouched and are not re-implemented
here.

## Architecture: external ordinary input

The drivers are ordinary external input agents, like a human with a mouse:

1. Read public window metadata (title, PID, executable path, visibility,
   on-screen state, geometry).
2. Read **only** the five public widget fields `role`, `name`, `enabled`,
   `visible`, `bounds` from the platform accessibility tree. Value, text,
   clipboard and invoke/perform interfaces are neither read nor called.
3. Re-observe the window, the control rectangle and the exact foreground
   window (never just its process)
   immediately before input.
4. Emit **exactly one** physical input batch through the OS input queue
   (`SendInput` / `CGEventPost`) and record only what the OS actually proved:
   `accepted` (the whole Windows batch was queued) or `posted` (macOS created
   and posted the event objects). Neither claims the application acted.

There is no product hook, no approval injection, no UIA `ValuePattern`,
`TextPattern` or `InvokePattern`, no `SetText`, no AX action/`AXPress`, no
clipboard access and no retry of an authorisation click. A failed or ambiguous
observation refuses *before* any input.

`test_platform_sources_avoid_forbidden_automation_apis` enforces these bans by
scanning the adapter sources, and the Windows/macOS unit tests assert that no
forbidden accessibility member is ever touched.

## Shared contract (`native_acceptance_contract.py`)

* One JSON document on stdin, one JSON result on stdout.
* Accepted keys: `title`, `title_prefix`, `executable`, `actions`, `inspect`,
  `wait_absent`, `preserve_focus`. Exactly one of `title`/`title_prefix`.
* Accepted action keys: `click_label`, `wait_label`, `click`, `text`, `key`.
* Bounds: request ≤ 64 KiB, ≤ 64 actions, titles ≤ 512 chars, executable ≤ 4096,
  ASCII text ≤ 256 chars, ≤ 4 chord parts, pointer offsets ±100000, plus hard
  observation limits (512 windows, 4096 controls, 240 observations).
* Labels may only come from `X11_CONTROL_LABELS`, imported from the existing
  X11 module's literal tuple; importing it opens no display and loads no X11
  library (verified in a subprocess test that spies on `ctypes.CDLL`).
* Every refusal carries one fixed code from `ERROR_MESSAGES`; the emitted line
  is `Native acceptance input failed [code=<code> action=<action> index=<n>
  platform=<platform>]`. Request values, control values and raw exception text
  can never appear in stdout, stderr or argv.
* Result JSON: `window` (hex id), `pid`, `x`, `y`, `width`, `height`, `clicks`
  (label, centre, `before.focus_matches_target`, `evidence` = `accepted` or
  `posted`, `ack.move/down/up`), and, for `inspect`,
  `controls[label] = {present, enabled, showing}`. No request title, prefix or
  control text is ever echoed in success output.

Adapter protocol (implemented by both platform adapters):
`platform`, `supports_activation`, `check_capability()`, `list_windows()`,
`read_window(id)`, `read_controls(window)`, `focus_state(window)`,
`activate(window)`, `click(x, y)`, `type_text(text)`, `press_chord(parts)`,
plus the mandatory truthful `input_evidence` literal (`accepted` or `posted`)
and `exact_focus`. An adapter without a valid literal, or one that reports
`exact_focus` but only a PID, refuses before input. Optional `screen_bounds()`
and `hit_test(window, x, y)` let a platform prove the click point is on screen
and resolves to the selected window.

## Windows

* Window discovery: `EnumWindows`, `GetWindowThreadProcessId`, `IsWindowVisible`,
  `GetWindowRect`/`GetClientRect`/`ClientToScreen`, `GetWindowTextW`,
  `GetForegroundWindow`. Enumeration is exactly bounded: more than 512
  top-level windows refuses with `window-overrun` (never a truncated "unique"
  answer, even if the target was in the first 512 handles).
* Process identity: read-only `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` +
  `QueryFullProcessImageNameW`, plus a same-user check via `OpenProcessToken` /
  `GetTokenInformation(TokenUser)` / `EqualSid`. No writable handle is opened.
* UI Automation: `comtypes.client.GetModule("UIAutomationCore.dll")` and
  `CreateObject` for `IUIAutomation`, lazily imported; descendants are walked
  with a 4096-node cap, reading only `CurrentName`, `CurrentControlType`,
  `CurrentIsEnabled`, `CurrentIsOffscreen`, `CurrentBoundingRectangle`.
* Focus: the foreground `HWND` (not merely its PID) must equal the selected
  top-level window immediately before input, so a second window of the same
  process is refused. If focus is elsewhere, exactly one `SetForegroundWindow`
  attempt is made (never when `preserve_focus` is requested) and the exact
  HWND is re-verified; failure refuses with `focus-lost`.
* Input: one `SendInput` batch per action — absolute virtual-desktop move +
  left down + left up, a full key chord (modifiers first, released last), or a
  single `KEYEVENTF_UNICODE` batch (two events per ASCII character, layout and
  modifiers never assumed). Absolute coordinates are normalised over the
  observed virtual-screen origin and extent; a point outside the virtual
  screen or the selected window refuses with `control-offscreen`.
* Hit testing: `WindowFromPoint` + `GetAncestor(GA_ROOT)` must resolve the
  click point to the selected top-level HWND, and the point must lie inside
  its client rectangle.
* Acknowledgement: a zero or partial `SendInput` return count refuses with
  `input-failed` and is never retried.
* Secure desktop: `OpenInputDesktop`/`GetUserObjectInformationW` reporting a
  non-`Default` desktop, or a window owned by `logonui.exe`, `consent.exe`,
  `credentialuibroker.exe` (or a credential-dialog window class), refuses with
  `secure-desktop`. UAC consent and Windows Hello can never be approved by this
  driver — the human must act.

Known API limits: `SetForegroundWindow` is subject to Windows foreground-lock
rules, so a browser that is not already frontmost may be refused rather than
activated; `SendInput` acknowledgements prove delivery to the input queue, not
that the application acted; the token/SID trust check refuses when the process
cannot be opened read-only.

## macOS

* Capability: `AXIsProcessTrusted()` is **queried only**. A `False` result is the
  fixed `capability-unavailable` refusal. No TCC prompt, no grant, no
  `AXIsProcessTrustedWithOptions` (a strict fake in the tests raises if it is
  ever touched).
* Windows: `CGWindowListCopyWindowInfo` (on-screen, layer 0) for id/PID/bounds,
  AX window titles; process path and ownership via `proc_pidpath` +
  `proc_pidinfo(PROC_PIDTBSDINFO)`. The executable file owner is never used as
  a process-identity guess: an unknown process UID leaves the window untrusted
  and every request against it refuses.
* Window binding: the AX window must match the selected `CGWindow` by exact
  title and exact frame; zero candidates refuses `a11y-query`, several refuse
  `window-ambiguous`. The first AX window sharing a title is never used, and
  `AXStaticText` is not treated as an editable/clickable control.
* Widgets: bounded AX walk (4096 nodes, depth 12) reading `AXRole`,
  `AXTitle`/`AXDescription`, `AXEnabled`, `AXHidden`, `AXPosition`/`AXSize`.
  `AXEnabled`/`AXHidden` must be real booleans; a missing or unknown value
  refuses `a11y-unavailable`, and geometry that is unavailable or not positive
  refuses `control-geometry`. `kAXValueAttribute`/`AXSelectedText` are never
  read.
* Focus: `NSWorkspace.frontmostApplication().processIdentifier()` must equal the
  target PID, and `AXFocusedWindow`/`AXMainWindow` (when exposed) must bind to
  the exact selected window before input; otherwise input is refused. With
  `preserve_focus` the driver never activates anything — if the target is not
  frontmost it refuses with `preserve-focus-lost` instead of silently stealing
  focus.
* Point check: the click point must lie inside the bound window and
  `AXUIElementCopyElementAtPosition` must resolve to an element inside that
  same window.
* Input: `CGEventCreateMouseEvent` + `CGEventPost(kCGHIDEventTap)` for one
  move/down/up batch; keyboard chords via `CGEventCreateKeyboardEvent` with
  `CGEventSetFlags`; ASCII text via `CGEventKeyboardSetUnicodeString`. Success
  records `evidence: posted`, which proves posting only, not product effect.

Known API limits: `CGWindowName` is only populated when the process already has
Screen Recording permission, so titles come from AX (Screen Recording is not
requested); the exact PyObjC return shape of `AXValueGetValue` is handled
defensively and geometry failures fail closed as `control-geometry`; if
`proc_pidinfo` is unavailable or returns a partial `proc_bsdinfo`, the window
stays untrusted (there is no `stat`-based owner fallback);
`activateWithOptions_` is deprecated on recent macOS releases;
`CGEventKeyboardSetUnicodeString` availability is verified only on a real run.

## Dispatcher

`scripts/native_acceptance_driver.py` selects `windows` (`os.name == "nt"`),
`macos` (`sys.platform == "darwin"`) or `linux`. Linux stdin bytes are replayed
into `scripts/browser_native_x11.py` as a subprocess and its exit status is
returned unchanged, so existing X11 behaviour is identical. The only accepted
argument is the literal `--platform linux|windows|macos`; anything else exits 2
with a fixed code and never echoes the argument. Request content is never placed
in argv.

## Platform dependency install

```sh
# Linux (existing driver): standard library + libX11/libXtst, nothing new.
# Windows: real UI Automation via comtypes.
py -3 -m pip install --disable-pip-version-check comtypes
# macOS: real ApplicationServices/Quartz/AppKit bindings.
python3 -m pip install --disable-pip-version-check \
  pyobjc-framework-Quartz pyobjc-framework-Cocoa
```

None of these are imported at module import time, so importing the adapters and
running the unit tests needs no platform library.

## Opt-in real run procedure

```sh
# Linux (unchanged driver)
python3 scripts/native_acceptance_driver.py --platform linux < request.json
# Windows (from an interactive desktop session, same user as the browser)
py -3 scripts/native_acceptance_driver.py --platform windows < request.json
# macOS (after Accessibility trust is granted by the human)
python3 scripts/native_acceptance_driver.py --platform macos < request.json
```

`request.json` is the same document the `.mjs` callers already build, e.g.
`{"title":"Locklark · 浏览器原生确认","executable":"C:\\Program Files\\...\\browser.exe",
"actions":[{"click_label":"批准本次填充"}]}`.

Real runs are opt-in, one action per invocation, on a dedicated test desktop and
with the acceptance vault only. Nothing in this foundation runs them
automatically and no CI job is added.

## OS consent requirements

* macOS: Accessibility must be enabled by the human in System Settings →
  Privacy & Security → Accessibility for the *terminal/host process* that spawns
  the driver. The driver only reports `capability-unavailable` when it is not
  trusted; it never prompts.
* Windows: no elevation is required for the driver, but a secure-desktop switch,
  UAC consent prompt or Windows Hello prompt belongs to the human — those
  surfaces are refused with `secure-desktop`.
* Both platforms: the driver must run in the same interactive session and same
  user as the browser under test; otherwise process trust or focus verification
  fails closed.

## Human acceptance for #50 / #51 / #57

The driver returns only a physical-input acknowledgement. Deny paths
(`拒绝本次填充`, `拒绝连接`) and stale completions (an approval window that is no
longer the foreground, or a completion that arrives after the action deadline)
must still be accepted **by a human** watching the real UI: a click
acknowledgement is not evidence that the product denied, refreshed or completed
anything. Do not record these issues as validated from driver output alone.

## Verification performed here

* `python3 -m unittest scripts/test_native_acceptance_contract.py
  scripts/test_native_acceptance_platforms.py` → 61 tests, OK.
* `python3 -m unittest discover -s scripts -p 'test_native_acceptance*.py'` → OK.
* `python3 -m py_compile` on all six modules → OK.

## Remaining limitations

* No Windows/macOS execution: `WindowsAdapter()`/`MacAdapter()` construction,
  the real UIA walk, real AX geometry, `SendInput`/`CGEventPost` delivery and
  foreground rules are unverified on hardware.
* `scripts/browser_native_x11.py` and every `.mjs` caller are unchanged; the
  dispatcher is not yet wired into them.
* No platform CI job, no signed artefacts, no screen capture and no fallback
  when a platform refuses accessibility permission other than the fixed error.
