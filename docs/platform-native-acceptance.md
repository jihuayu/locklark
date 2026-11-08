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
| `scripts/test_native_acceptance_contract.py` | 47 pure contract tests |
| `scripts/test_native_acceptance_platforms.py` | 96 adapter/dispatcher seam tests (fakes and spies) |

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
  platform=<platform>]`. `control-hit` is the click-target identity refusal
  (below). Request values, control values and raw exception text
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
`exact_focus` but only a PID, refuses before input. Optional `screen_bounds()`,
`hit_test(window, x, y)` and `point_visible(window, x, y)` let a platform prove
the click point is on screen, resolves to the selected window and lies on a
visible display; a hook that answers anything other than `True` fails closed.

`hit_test_control(window, label, rect, x, y)` is the strict target-identity
hook and is **required** for every `click_label` action. Once the ordinary
point checks pass, the contract re-resolves the selected label inside the
CURRENT bound window with the same role/name rules, requires the freshly
observed rectangle to equal the authorising `rect` exactly, and then requires
the element actually under the point to be that selected control or one of its
descendants. Only the literal `True` authorises the single click; a missing
hook, any other return value, an unknown label, a changed rectangle, a
cycle/overrun or a failed accessibility query refuses with `control-hit`
(or the more specific `control-ambiguous` / `control-missing` / `a11y-query`)
and no input is emitted. Offset `click` actions keep the existing window-root
`hit_test` only, because they deliberately name no selected control.

## Windows

* Window discovery: `EnumWindows`, `GetWindowThreadProcessId`, `IsWindowVisible`,
  `GetWindowRect`/`GetClientRect`/`ClientToScreen`, `GetWindowTextW`,
  `GetForegroundWindow`. Enumeration is exactly bounded: more than 512
  top-level windows refuses with `window-overrun` (never a truncated "unique"
  answer, even if the target was in the first 512 handles). If `EnumWindows`
  itself returns FALSE without that own overflow stop, the handle list is a
  partial view: the whole query refuses with `window-query` and no partial list
  is ever returned.
* Process identity: read-only `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` +
  `QueryFullProcessImageNameW`, plus a same-user check via `OpenProcessToken` /
  `GetTokenInformation(TokenUser)` / `EqualSid`. No writable handle is opened.
  The current-process pseudo handle comes from `kernel32.GetCurrentProcess`
  (declared on kernel32 only — `user32` does not export it); a strict fake DLL
  in the tests fails if `user32` is ever asked for that symbol.
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
* Window hit testing: `WindowFromPoint` + `GetAncestor(GA_ROOT)` must resolve
  the click point to the selected top-level HWND, and the point must lie inside
  its client rectangle. A same-root sibling widget, a transparent overlay or a
  window stacked above the target passes this check, so it is only the outer
  bound.
* Control hit identity (`click_label` only): the selected label is parsed again
  from the current bound HWND (`FindAll` descendants, same 4096-node cap) and
  must still be unique with a rectangle exactly equal to the authorising one.
  `IUIAutomation.ElementFromPoint` then returns the element actually under the
  point, and a `RawViewWalker.GetParentElement` walk bounded to
  `MAX_HIT_ELEMENTS` (64 elements, at most 63 parent steps) must reach that
  exact element; every comparison is `IUIAutomation.CompareElements`, never a
  name, control type or rectangle comparison. A sibling, an overlay, a moved or
  duplicated control, a cycle, a walk overrun or a failed COM query refuses
  (`control-hit` / `control-ambiguous` / `control-missing` / `a11y-query`)
  before any input.
* COM call shapes: `ElementFromPoint` is passed the comtypes-generated
  `tagPOINT` from `UIAutomationCore.dll`, and the structure is checked to be
  exactly two 32-bit signed `x`/`y` members before the call; a module without
  that generated type refuses `a11y-unavailable` instead of guessing a POINT
  layout. `CompareElements` returns `BOOL *`, which comtypes surfaces as the
  integer 1 for TRUE (it is not a `VARIANT_BOOL` and is never converted to a
  Python bool here), so the reader accepts only the literal `True` or the
  integer 1 as a match and treats 0, 2, -1 or any other value as no match.
* Acknowledgement: a zero `SendInput` return count refuses with
  `input-failed`. A short non-zero count means a *prefix* may already be in the
  input queue: the batch is never resent and no repair key/button release is
  injected, so the fixed `input-unknown` refusal is raised and the driver
  stops. Which prefix the OS actually delivered is not observable from this
  process.
* Secure desktop: `OpenInputDesktop`/`GetUserObjectInformationW` reporting a
  non-`Default` desktop, or a window owned by `logonui.exe`, `consent.exe`,
  `credentialuibroker.exe` (or a credential-dialog window class), refuses with
  `secure-desktop`. If either call fails, the desktop identity is **unknown**:
  that is the fixed `capability-unavailable` refusal (input never proceeds on a
  desktop this process cannot name) — never a silent `False`/"not secure". UAC consent and Windows Hello can never be approved by this
  driver — the human must act.

Known API limits: `SetForegroundWindow` is subject to Windows foreground-lock
rules, so a browser that is not already frontmost may be refused rather than
activated; `SendInput` acknowledgements prove delivery to the input queue, not
that the application acted; the token/SID trust check refuses when the process
cannot be opened read-only.

## macOS

* Frameworks: every AX call and constant (`AXIsProcessTrusted`,
  `AXUIElementCreateApplication`, `AXUIElementCopyAttributeValue`,
  `AXUIElementCopyElementAtPosition`, `AXValueGetValue`, `kAXWindowsAttribute`,
  `kAXValueCGPointType`/`kAXValueCGSizeType`) belongs to
  ApplicationServices/HIServices (`self.ax`) and is imported separately
  (`import ApplicationServices`), lazily. Only CoreGraphics window, display and
  event work (`CGWindowListCopyWindowInfo`, `CGGetActiveDisplayList`,
  `CGDisplayBounds`, `CGEventCreate*`, `CGEventPost`) uses `self.quartz`. There
  is no runtime fallback from one framework to the other: a missing
  ApplicationServices import fails closed instead of being answered by
  CoreGraphics. The single exception is a caller-injected combined fake object
  in the tests, which is reused for both roles explicitly.
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
  target PID and `AXFocusedWindow` must bind to the exact selected window
  before input; a missing or differently bound focused window refuses even when
  `AXMainWindow` matches. `AXMainWindow` is only an additional consistency
  check when the OS exposes it, never a fallback. With
  `preserve_focus` the driver never activates anything — if the target is not
  frontmost it refuses with `preserve-focus-lost` instead of silently stealing
  focus.
* Point check: the click point must lie inside the bound window,
  `AXUIElementCopyElementAtPosition` must resolve to an element inside that
  same window, and `point_visible()` must prove the point is inside one active
  display via `CGGetActiveDisplayList` + `CGDisplayBounds`. Membership is
  tested display by display, so a gap between two display rectangles is not
  screen. Neither call prompts for Screen Recording. An error, an empty list, a
  count that is bool/non-integer/out of range or longer than the returned list,
  non-finite or non-positive geometry, or any other query failure fails closed
  with `control-offscreen`.
* Control hit identity (`click_label` only): the selected label is re-resolved
  in the CURRENT bound AX window with the same role/name rules, and its fresh
  `AXPosition`/`AXSize` frame must equal the authorising rectangle exactly.
  The native element returned by `AXUIElementCopyElementAtPosition` is then
  walked up with `AXParent` for at most `MAX_HIT_PARENTS` (64) steps, and each
  step is compared with `CFEqual` against the ACTUAL selected `AXUIElement` -
  never by title, role or frame, and never by Python object identity. The first
  `AXWindow` on the chain ends the walk without success, so a window ancestor is
  never accepted as a substitute for the control. `CFEqual` is taken from an
  injected object or imported lazily from CoreFoundation; if it is unavailable
  the driver refuses (`a11y-unavailable`) instead of guessing equality. A
  sibling or overlay element above the control, a moved or duplicated control,
  a repeated element (cycle), an exhausted 64-step walk or a failed AX query
  refuses (`control-hit` / `control-ambiguous` / `control-missing` /
  `a11y-query`) before any input.
* Input: `CGEventCreateMouseEvent` + `CGEventPost(kCGHIDEventTap)` for one
  move/down/up batch; keyboard chords via `CGEventCreateKeyboardEvent` with
  `CGEventSetFlags`; ASCII text via `CGEventKeyboardSetUnicodeString`. Every
  mouse, chord and text event (including its unicode string and flags) is
  created and validated **before** the first `CGEventPost`, so a failed
  creation posts nothing and can never leave an orphan key-down behind.
  `CGEventPost` returns void: success records `evidence: posted`, which proves
  posting only — never acceptance and never product effect. If a post raises
  after an earlier event of the same batch was delivered, the batch is never
  rebuilt or re-posted; the fixed `input-unknown` refusal reports delivery as
  unprovable.

Known API limits: `CGWindowName` is only populated when the process already has
Screen Recording permission, so titles come from AX (Screen Recording is not
requested); the exact PyObjC return shape of `AXValueGetValue` is handled
defensively and geometry failures fail closed as `control-geometry`; if
`proc_pidinfo` is unavailable or returns a partial `proc_bsdinfo`, the window
stays untrusted (there is no `stat`-based owner fallback);
`activateWithOptions_` is deprecated on recent macOS releases;
`CGEventKeyboardSetUnicodeString` availability is verified only on a real run.
A partially delivered batch (Windows short `SendInput` prefix, macOS partially
posted `CGEventPost` batch) is reported as `input-unknown`; residual OS
delivery cannot be inspected or undone from here, so a Linux mock cannot prove
it. Hit identity against a sibling overlay window that sits above the target
window is still open (pending the next phase) and is not claimed closed.

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
# macOS: real ApplicationServices (AX/HIServices), Quartz (CoreGraphics) and
# Cocoa (AppKit) bindings. ApplicationServices is a separate framework import,
# not a Quartz re-export.
python3 -m pip install --disable-pip-version-check \
  pyobjc-framework-ApplicationServices pyobjc-framework-Quartz pyobjc-framework-Cocoa
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
  scripts/test_native_acceptance_platforms.py` → 143 tests (47 contract + 96
  platform seam), OK.
* `python3 -m unittest discover -s scripts -p 'test_native_acceptance*.py'` →
  143 tests, OK.
* `python3 -m py_compile` on all six modules → OK.

## Remaining limitations

* A partially delivered input batch is reported as `input-unknown`; the tests
  prove only that nothing is retried and nothing is resent, never which events
  the OS actually delivered.
* Control hit identity is now enforced by `hit_test_control` and covered by pure
  mock tests (selected control and legitimate child accepted; same-root
  sibling, transparent overlay, duplicate label, changed rectangle, cycle,
  parent-limit overrun and failed/unknown queries refused before any input).
  That is a mock-only proof: `ElementFromPoint`/`RawViewWalker`/`CompareElements`
  on Windows and `AXUIElementCopyElementAtPosition`/`AXParent`/`CFEqual` on
  macOS have **not** been executed against a real desktop, a real overlay window
  or real DPI/scaling, so no OS behaviour is claimed for them.
* `ElementFromPoint` interprets screen coordinates according to the calling
  process's DPI awareness; if the driver and the acceptance browser ever run
  with different per-monitor awareness the identity check refuses rather than
  clicking, which is a fail-closed limitation, not a proven equivalence.
* No Windows/macOS execution: `WindowsAdapter()`/`MacAdapter()` construction,
  the real UIA walk, real AX geometry, `SendInput`/`CGEventPost` delivery and
  foreground rules are unverified on hardware.
* `scripts/browser_native_x11.py` and every `.mjs` caller are unchanged; the
  dispatcher is not yet wired into them.
* No platform CI job, no signed artefacts, no screen capture and no fallback
  when a platform refuses accessibility permission other than the fixed error.
