# 浏览器扩展无障碍外部验收驱动

更新：2026-11-09。范围是真实 Locklark Chromium 扩展的**实际工具栏 action 弹窗**与真实 `options.html` 页面。驱动只做只读 axe/DOM 探针与 Tab 遍历；不连接原生宿主、不创建金库、不注入解锁/批准/认证/状态消息、不关闭 CSP、不点击产品操作、不截图。

## 运行方式（仅主代理执行，需要可见 GUI）

worker 不启动浏览器/Xvfb。主代理在仓库根目录执行一次可见 GUI 运行（真实 Edge + 物理快捷键），建议超时 5 分钟：

```sh
timeout 300 env \
  LOCKLARK_TEST_AXE_SOURCE=/workspace/toolchains/a11y/node_modules/axe-core/axe.min.js \
  node scripts/browser_accessibility_acceptance.mjs \
    --out browser-accessibility-receipt.json
```

- 默认 Edge：`/workspace/toolchains/edge/opt/microsoft/msedge/msedge`；默认 Playwright：`/workspace/locklark/web/node_modules/playwright`。可用 `LOCKLARK_TEST_EDGE` / `LOCKLARK_TEST_PLAYWRIGHT` 覆盖。
- axe 必须是绝对路径、存在的 `axe.min.js`，页面内验证版本为 `4.10.3`（已确认本机 pinned axe 为 4.10.3）。
- `--out` 必填且必须尚不存在；驱动使用独占创建，不覆盖旧回执。退出码：`PASS=0`、`FAIL=1`、`UNAVAILABLE=3`、参数/驱动枚举错误=2。
- 需要 `DISPLAY` 与 `python3`（复用 `scripts/browser_native_x11.py` 的 XTest 输入）。驱动本身不开 headless。
- **必须有真实窗口管理器（WM）**：驱动在构建后、启动 Edge/发送快捷键之前，只读检查 EWMH `_NET_SUPPORTING_WM_CHECK`（根窗口属性必须存在，且被指向的检查窗口必须自引用同一属性）。`DISPLAY` 缺失、无 WM、`xprop` 缺失/超时或属性不可读都只产生固定 `window-manager-unavailable` 的 `UNAVAILABLE` 回执（`audits=0`），不会启动 Edge，也不会退化成随机的 `cdp-closed` 失败。驱动不会自动启动、安装、替换或配置 WM，也不会修改用户桌面/会话偏好。WM 正常存在时后续审计路径不变。

### 自有 Xvfb + 私有 D-Bus 示例（不触碰用户桌面）

只有当主代理需要隔离的可见 X11 会话时，才在自有 Xvfb 中启动 WM；下面的命令不修改用户桌面，并在退出时清理自己启动的进程：

```sh
set -euo pipefail
DISPLAY_NUM=:99
Xvfb "$DISPLAY_NUM" -screen 0 1280x1024x24 -nolisten tcp &
XVFB_PID=$!
cleanup() {
  kill "$XVFB_PID" 2>/dev/null || true
  wait "$XVFB_PID" 2>/dev/null || true
}
trap cleanup EXIT
export DISPLAY="$DISPLAY_NUM"
dbus-run-session -- bash -c '
  set -euo pipefail
  if command -v startxfwm4 >/dev/null 2>&1; then
    startxfwm4 &
  else
    xfwm4 --compositor=off &
  fi
  WM_PID=$!
  trap "kill $WM_PID 2>/dev/null || true" EXIT
  for _ in $(seq 1 100); do
    xprop -root _NET_SUPPORTING_WM_CHECK 2>/dev/null | grep -q "window id" && break
    sleep 0.1
  done
  node scripts/browser_accessibility_acceptance.mjs --out "$1"
' _ browser-accessibility-receipt.json
```

说明：`dbus-run-session` 只给本次 Xvfb 会话一个私有 D-Bus；两个 `trap` 分别清理 WM 与 Xvfb。驱动自己的 WM 预检仍是最终判据，示例中的等待只是为了减少初次启动的抖动。若发行版的 `startxfwm4` 包装器会 fork，请按该包装器的 PID 语义清理，或使用前台的 `xfwm4`。

## 实际弹窗路径（不是普通标签页）

1. 运行 `browser-extension/build.js chromium`，核对固定扩展 ID `geldnhjapnackobgknocomedmjgphnpe`，然后以**普通 Edge 进程**和私有临时 profile 启动，参数含 `--remote-debugging-port=0`、`--load-extension`。
2. 只打开一个本地、无凭据的 fixture 页面（`127.0.0.1` 随机端口，仅标题与说明），用于窗口标题匹配和键盘焦点；不涉及认证、金库或原生宿主。
3. 从 profile 的 `DevToolsActivePort` 读取端口，经 `/json/list` 记录已有 target；随后通过 XTest 驱动发送**物理 `Ctrl+Shift+Y`**，让 Edge 自己打开 action 弹窗。
4. 只把「URL 精确为 `chrome-extension://<固定 ID>/popup.html`、WebSocket 地址为本机回环、且未在打开前快照中出现」的**新** target 作为候选；CDP `type` 仅为 `page` 或 `other` 的候选元数据，**不能单独证明**它是 action 弹窗（Edge 实际可能报 `page`）。候选不唯一以 `popup-target-ambiguous` 失败，无候选/旧 target 以 `popup-not-opened` 失败，无本机回环候选以 `popup-target-not-action` 失败。
5. action 弹窗不是 Playwright `Page`，因此由 `browser_accessibility_cdp_adapter.mjs` 提供最小 CDP 适配面：`evaluate(fn,arg)`、`context().newCDPSession()`、受控 `keyboard.press("Tab")`（可信 `Input.dispatchKeyEvent`）、`setViewportSize`（Emulation）、`emulateMedia`（Emulation）、`wait/poll` 与 `close`。
6. attach 之后、任何 axe/DOM 审计之前，先用只读平台上下文守卫证明它是真实 action 弹窗：`chrome.extension.getViews({type:"popup"})` 必须包含当前 `window`，`chrome.tabs.getCurrent` 回调必须返回 `undefined`（无 tab），且实际 document 可见、`location.href` 精确固定。普通标签页即使手工绘制了锁定 DOM 也在此失败（`popup-context-not-action`）；平台 API 缺失/抛错/超时无法证明时以 `popup-context-unavailable` 失败。守卫不发送 runtime/state/auth/approval 消息，也不调用 `chrome.action.openPopup`。
7. 守卫通过后继续等待原生后台态 `popupReady`：`readyState === "complete"`、`#locked-view` 实际可见且 `#status` 有文本。该状态只能由真正无 `sender.tab` 的弹窗 sender 路径取到（`core.validSender` 拒绝带 tab 的发送者）。超时以 `popup-ready-timeout` 硬失败，不会跳过；随后仍须 `lockedPopup` 复核，否则 `popup-not-locked`。
8. 在 action 弹窗上完成全部 popup 审计后，显式关闭并等待 target 消失（`popup-close-timeout`），**之后**才用 Playwright `connectOverCDP` 打开真实 `options.html` 标签页审计。

实际 PASS 回执共 9 条审计：popup 3 条（原生 `390×600` action 尺寸 × default/forced-colors/reduced-motion，**不做视口仿真**）+ options 6 条（`1280×800` 与 `640×800` × 三种媒体模拟）。因此 popup 是 3、options 是 6、总计 9；只有 options 页面做响应式 viewport 仿真。

## 检查内容

1. 只读注入固定版本 axe-core，运行 WCAG 2 A/AA 与 2.1 A/AA 标签规则，仅输出规则 ID、impact 和节点计数。
2. 桌面 `1280×800` 与窄视口 `640×800` 下检查水平溢出。
3. `forced-colors: active` 与 `prefers-reduced-motion: reduce` 浏览器媒体模拟。
4. Tab 遍历只统计真实可聚焦控件：`checkVisibility`（含 CSS/content visibility）、隐藏祖先、`inert`、关闭的 `<details>`（其子项不是 Tab 目标，`summary` 除外）、`:disabled`、零尺寸与负 `tabindex` 均排除。只输出总数/到达数/步数与状态。
5. 回执不含 HTML、文本、字段值、选择器、URL、本机路径、截图或节点 payload。

## 源码与回执诚实性

- `browser-extension` 产品源码有未提交改动时拒绝出 PASS：写 `FAIL`/`source-dirty` 并返回非零，不把 git HEAD 当证据。
- 构建完成后记录 `source_sha256`（实际被审计的 `dist/chromium` 字节）与 `head`，便于区分 HEAD 与实际产物。
- 所有失败只输出固定错误枚举（如 `source-dirty`、`window-manager-unavailable`、`native-shortcut-failed`、`popup-context-not-action`、`popup-context-unavailable`、`popup-ready-timeout`、`devtools-port-timeout`、`unknown-argument`），不打印原始异常、参数或本机路径。
- 本轮已有实际 PASS 回执：源 `2778d7cbc076f01bae167f361dc7510c001b7476`，`source_sha256=2290aec47be8b8e5580c327a0cdef49041305ce99e502916dc01ad97fdcb2c70`，工具回执 `state=PASS`、9 条审计、violations/incomplete/failed=0。其公开副本保存在 `docs/validation/browser-accessibility-linux-edge.json`，只含既有公开 schema，不含本机路径、字段值或控件 payload。

## 状态与非声明

- `PASS`：所有审计无 axe violations、无水平溢出、Tab 到达全部可见可聚焦控件，且 popup 为实际锁定态。
- `FAIL`：存在 violations、水平溢出、Tab 未到达控件、popup 非锁定态、源码不干净或驱动执行失败。
- `UNAVAILABLE`：固定版本 axe 缺失/版本不符，或没有真实窗口管理器/`DISPLAY`/`xprop` 预检失败（`window-manager-unavailable`）；均不会写成 `PASS`，且 `audits=0`。

限制（回执 `not_claimed` 同样记录）：没有真实 NVDA/VoiceOver/JAWS、没有真实 OS 高对比度/动画设置、没有真实 200% 浏览器缩放、没有 reference/读屏参照对照；弹窗的视口与媒体是 CDP 模拟，不等于 OS 缩放/高对比度/读屏输出。本轮不修改产品 HTML/CSS/JS。issue #57 中的参照对照与真实读屏验证仍未完成，本轮 9 PASS 不关闭该 issue。

纯检查：

```sh
node --check scripts/browser_accessibility_acceptance.mjs
node --check scripts/browser_accessibility_window_manager.mjs
node --test scripts/test_browser_accessibility_acceptance.mjs
```
