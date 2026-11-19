# 浏览器原生配对与登录填充验收

基线 main `dcc52d04cd8bcf5e17e8d9e2aedd98c92056bacb`，分支 `codex/browser-native-fill`。用户指定：主代理设计架构、功能并验收；Sol（xhigh）完成具体实现；Luna（max）独立 review。[架构与验收约定](browser-native-design.md) 区分实际原生 UI、扩展来源断言和同 OS 用户信任边界。

## 实现范围

Chromium 扩展由实际用户 action/快捷键开启，固定扩展 ID，通过 Native Messaging 启动独立 MyGo 窗口。窗口持有自己的个人金库会话，使用既有完整因素及系统解锁接口；原生批准连接后才能读取当前网站候选，每次用户名/密码填充仍须原生批准。Next.js 管理页不接收金库字段。连接、来源/标签页/文档/条目/修订、短期一次请求以及认证事务的审计意图共同限制交付。

Chrome/Edge 使用 Chromium 宿主；Firefox 有独立启动身份、注册及扩展构建。真实 Firefox 157 临时扩展实验已验证 `executeScript` 返回标准 UUID `documentId`，按 `documentIds` 注入成功，同源导航后旧 ID 被浏览器拒绝（`Invalid documentId`），证据见 `/tmp/locklark-validation/firefox-document-binding/report.json`。该 API 自 Firefox 153 起提供，缺失身份的负测只是模拟不支持的 API，不代表新版 Firefox 不支持。主代理已独立实跑 Firefox 157 的完整 native 填充/UI 链路，见下方记录；仓库脚本亦已独立通过，精确 head CI 继续验收，不引入较弱的来源匹配回退。Chromium 和 Firefox 的测试结果不能替代 Edge、Safari 或手机验收。签名发布、自动更新和商店分发仍待完成。

## 失败先行及回归

日志保存在执行环境 `/tmp/locklark-validation/`：`browser-red-session.log`、`browser-red-host.log`、`browser-red-connection.log` 分别记录缺失会话 API、协议模块和连接到期行为的失败。`browser-red-worker-late.log` 复现锁库提示被迟到回调覆盖及旧请求清除新候选；实现加入代次/请求身份约束后，扩展测试通过。

已完成个人金库精确来源、修订/状态、一次消费、提交回滚/关闭失败、到期/锁定、旧历史复验；宿主帧长度、重复 JSON 字段、固定启动身份、配对/确认前无值、请求重放、慢管道/断管和原生锁定竞态；扩展来源规范、精确 popup sender、导航后旧响应及缺失文档身份拒绝。`browser-race-final.log` 的 host/desktop/personal 定向竞态通过；`browser-go-all.log` 记录启用真实 Bun 和 PyKeePass 的全量 Go 测试通过。后续独立审阅修复仍需相应回归，不能把早期测试当作最终 head 的结论。

## 主代理独立实际链路

在 Linux Xorg dummy 显示服务器上运行真实 MyGo 进程、Chrome for Testing 156 和已安装开发扩展。`scripts/browser_native_acceptance.mjs` 生成独立合成金库及受控 HTTPS 页面，只信任此次临时证书的 SPKI；通过实际 `Ctrl+Shift+Y` 用户 action 获得 `activeTab`，浏览器读取真实 host manifest 并启动宿主。

`scripts/browser_native_x11.py` 通过系统 AT-SPI 的控件标签、可见/可用状态及实际几何定位，再使用 XTest 操作窗口（不读取字段 Value/Text）：输入完整合成解锁因素、确认连接、批准或拒绝填充、锁库。实际 popup 以本机测试 CDP 连接并发送鼠标输入，不伪造扩展消息或宿主响应。产品中没有跳过解锁/配对/批准的测试入口。

首次完整验收发现锁库提示被异步失败覆盖，保留失败日志并修复；随后 `browser-native-e2e.log` 已通过：批准前字段为空、批准后两字段与合成值一致、未自动提交、原生拒绝后无值、文档导航后旧请求不填新页面、锁库停止匹配/交付且提示锁定、浏览器控制台不含合成秘密。合成证据目录 `/tmp/locklark-browser-acceptance-vTSzqm`，原生确认截图 `native-confirm.png`；合成因素目录不上传、不提交。真实 DOM 测试还覆盖隐藏/disabled/readonly/歧义字段、跨来源表单 action/base 与 iframe 拒绝，见 `browser-dom.log`。

复跑命令（路径按本机调整）：

```sh
DISPLAY=:94 \
LOCKLARK_TEST_PLAYWRIGHT=/workspace/locklark/web/node_modules/playwright \
LOCKLARK_GO=/tmp/locklark-tools/go/bin/go \
LOCKLARK_BROWSER_HOST=/tmp/locklark-tools/locklark-browser-chromium \
dbus-run-session -- node scripts/browser_native_acceptance.mjs
```

## 共享桌面金库的剪贴板租约外部验收

`scripts/browser_native_acceptance.mjs` 新增显式外部验收模式（不是产品测试开关）：同时设置 `LOCKLARK_TEST_SHARED_CLIPBOARD=1` 与绝对路径 `LOCKLARK_DESKTOP_HOST` 时，脚本在生成私有合成 fixture、注册真实 native host manifest 并启动固定身份扩展之后、进入原有独立宿主配对流程之前，直接转入 `scripts/browser_shared_clipboard_acceptance.mjs`。未设置该变量时原独立宿主验收路径完全不变。

该模式首先在私有验收目录下创建 0700 的 `shared-environment/home` 与 `shared-environment/tmp`，并把 `HOME`、`TMPDIR`、`XDG_CONFIG_HOME`/`XDG_CACHE_HOME`/`XDG_DATA_HOME` 与显式 `LOCKLARK_BROWSER_SOCKET=<state>/shared-environment/tmp/b.sock` 组成独立环境：它同时传给 Playwright 的浏览器进程和真实 `locklark-desktop` 普通进程（无参数启动），因此浏览器启动的 native host 子进程与桌面 App 使用同一个私有 broker 端点，不会连接或影响真实用户的桌面 App/设置。启动前断言私有 HOME/配置/临时目录为空且该端点尚不存在（因此产品使用默认 30 秒清理设置、只打开本脚本生成的受控 fixture 金库），启动后断言端点已是 socket。Go fixture/注册步骤仍使用原环境，因为其输出路径都是显式私有路径。

宿主随后按其正常 native-messaging 通道转发到该桌面 broker，`native-clipboard-lease-v1` 能力由实际 App 的 `NewClipboard` 工厂发布；popup 的连接不依赖任何“快捷配对”勾选。桌面解锁只通过 `scripts/browser_native_x11.py` 的真实 AT-SPI 控件、就绪状态与 XTest 物理输入完成，桌面窗口使用标题 `Locklark · 本地金库` 与桌面可执行文件，独立宿主窗口标题 `Locklark · 浏览器原生确认` 与之区分为不同 UI 宿主。

配对仍先在真实弹窗上点击 `#connect`，并用 XTest 物理点击固定标签 `拒绝连接` 完成拒绝前置检查：随后重新打开的新 popup 必须仍可连接、不可刷新（`pair_refused_unpaired`），因此拒绝路径是真实的，不是仅检查提示。成功连接只在桌面配对提示上物理等待并点击唯一固定标签 `连接并启用快捷填充`（`pair_quick_consent_bound` / `quick_consent_accepted`），该原生提示文本明确授权本连接 15 分钟内的 V2 详情（`item-get`）与字段复制/显示等快捷操作，配对 UI 也说明快捷模式避免反复切换焦点窗口；不使用普通逐次同意（`确认连接（每次敏感操作需批准）`），不从状态文本推断或自动批准同意。标签均为源码固定的字面量，不从动态 UI 文本读取。

在此显式快捷同意下，点击实际合成登录行打开合成详情，并在同一个 action popup 中点击隐藏密码行的 `[data-field-id="password"] [data-action="copy-field"]`，不等待被快捷同意明确替代的 `item-get` / `item-copy-field` 原生审批。真实 Chromium X11 曾实证：普通同意虽可成功绑定连接，但物理 `item-get` 批准会关闭失去焦点的瞬时 action popup，新 popup 不再保留内存中的详情视图并最终超时；这正是本旅程改用快捷同意的原因。详情断言（行标题、详情标题、隐藏且可显示的密码字段、唯一的复制控件）与“已复制”+“已启用自动清理”的 toast 断言保持不变，登录行与复制各只点击一次（`detail_popup_retained`、`popup_copy_in_quick_detail`）。脚本等待真实 DOM 复制确认，并以该确认完成时刻作为 30 秒 TTL 的锚点（不早于确认），再用 `scripts/desktop_native_probe.py` 通过私有 JSON stdin 比对操作系统剪贴板；期望值只出现在私有管道中，argv、环境变量、DOM 与日志都不含该值。关闭 popup 后再次独立读取，值必须仍可粘贴。

后续断言：外部独立 foreign X11 owner 由 `scripts/desktop_clipboard_owner.py` 提供（marker 也仅经私有管道），在原始 30 秒 TTL 加余量后断言 owner 与 marker 未被改写、应用未请求其它载荷、未写入空值；一次新的真实复制后通过桌面 UI 锁定，断言应用拥有的值被清除，之后出现的 foreign owner 不再被清除。迟到 prepare 场景只在点击复制前对本脚本自己启动的 App PID 发送 `SIGSTOP`，在 popup 仍等待响应时关闭 popup，始终在 `finally` 中 `SIGCONT` 并等待响应/取消，断言剪贴板保持 foreign marker、隐藏后没有发生复制。暂停只是外部进程编排，不是认证钩子；脚本不停止任何 foreign 或用户进程。

失败诊断：驱动的 `catch` 在 `finally` 结束 App 之前调用 `desktopInspect`，只输出固定 `failed_stage`、公开窗口 XID 和白名单控件名的 `present`/`enabled`/`showing` 布尔值，不输出任何解锁因素、控件值、正文、命令或异常文本；随后才结束 App 与 foreign owner。

原生复制判别：除真实 DOM “已复制”与 `desktop_native_probe.py` 私有 stdin 的秘密值比对之外，脚本要求 popup 可见提示为原生自动清理措辞（“已启用自动清理”），并拒绝 legacy 手动措辞（“浏览器无法保证自动清除”）；`prepared.cleanup_ttl_seconds` 只可能来自实际 App 工厂发布的原生租约，因此仅凭“复制成功文本”或同值不构成通过。

隐私边界：不授予浏览器 `clipboardRead`/`clipboardWrite` 权限，不注入产品消息、不覆盖 CDP/JS 剪贴板、不设置任何隐藏状态；不读取原始因素、密钥、金库数据或剪贴板值。输出仅有固定阶段名、布尔回执和既有私有 fixture/控制器扫描。

2026-11-09（香港）实测：主代理在隔离的 Linux D-Bus/Xvfb 中运行真实 Edge 和 Firefox，共享桌面金库的上述完整旅程均通过。Edge 验证源码为 `fcf2c79fa4abfc690c7624f1f4e12d553798f8b9`，Firefox 为 `9f18a7cde3daf0dc68d9308cab398d08d0a96517`；后续重放到 main `1598380` 未改变产品逻辑。回执分别为 `clipboard-real-edge-run-result.json`、`clipboard-real-firefox-run-result.json`（独立验收工作区，仅保留公开阶段与退出状态，不纳入产品包）。

两者都覆盖完整因素真实 UI 解锁、隐藏密码的原生复制、popup 关闭后可粘贴、30 秒到期后 foreign owner 保留且零载荷请求、锁库只清除自有内容，以及迟到 prepare 在 popup 隐藏后取消。受控探针经真正的 POSIX FIFO 传递，未放宽原有 stdin/stdout 管道检查。Firefox 使用实际 action popup 和键盘事件，并由其 native host 转发到相同桌面 App。

尚未在独立 Chrome 安装、真实 Windows/macOS 上重跑这条完整浏览器共享旅程；已有平台原生剪贴板 smoke 不替代它。#59 因这些剩余平台证据保持开放。可复跑示例（使用各环境实际工具路径）：

```sh
DISPLAY=:94 \
LOCKLARK_TEST_PLAYWRIGHT=/workspace/locklark/web/node_modules/playwright \
LOCKLARK_GO=/tmp/locklark-tools/go/bin/go \
LOCKLARK_BROWSER_HOST=/tmp/locklark-tools/locklark-browser-chromium \
LOCKLARK_DESKTOP_HOST=/tmp/locklark-tools/locklark-desktop \
LOCKLARK_TEST_SHARED_CLIPBOARD=1 \
dbus-run-session -- node scripts/browser_native_acceptance.mjs
```

## 独立宿主能力协商回归

2026-11-09：PR #72 首轮 CI 与主代理本地真实 Edge 均在 2 MiB 附件上传处失败。原因是独立宿主的配对回执错误调用仅对共享桌面有效的能力列表，丢失了 `attachments-v1` 等原有能力，页面据此禁用上传。修复为配对/解锁回执发布原有基线，仅在实际原生管理器存在时附加剪贴板能力；独立 status 的历史语义保持不变。

DeepSeek 补齐独立/共享、管理器存在/缺失及锁定状态的六组回归。主代理独立 race 检查通过（17.369 秒），相关宿主 race 批次通过（100.517 秒），Luna 确认能力边界。修复后的真实 Edge 完整普通旅程通过，包含 2 MiB 上传、下载 SHA-256 比对、删除，以及原生填充/保存/更新/OTP/Passkey。共享桌面 Edge/Firefox 的前述完整租约证据保留；本段不冒充 Windows/macOS 或最终远端提交的 CI 结果。

## 独立 review 与待验收

Luna 的架构预审及最终实现复审已完成，未发现剩余阻塞项。安装路径/权限与原子发布、无关标签导航、配对前锁定通知、取消授权顺序、候选 JSON 编码预算、外置提交按钮、值后浏览器 API 无界等待与迟到状态覆盖均已修复并有回归。独立运行宿主测试、14 项扩展测试及 Windows 测试交叉编译通过；最后新增一项过期参数测试并格式化后，Sol 的 15 项 Node 测试及真实 DOM 再次通过。主代理在最终二进制上重新运行完整真实 GUI，`browser-native-e2e-final.log` 通过，合成证据目录 `/tmp/locklark-browser-acceptance-bSULDZ`。精确 PR head 远端 CI 尚待完成。已开始写管道/注入的字段无法撤回，失败或回执丢失只表示交付未知；不自动重试或声称网站接收成功。

Windows Hello/TPM、macOS Touch ID 与 Linux Secret Service 的真实系统验证仍保留桌面硬件验收项；本次完整因素 UI 流程不是生物识别硬件验证。保存/更新、TOTP/Passkey、完整类别迁移、团队邀请/远端同步、Safari及移动系统填充继续推进，不由本切片关闭。

## 首轮 CI 失败与真实环境修复

PR #26 初始 head `63a5a2b` 的 run `42066506800`：Ubuntu Go/macOS 桌面通过，Windows Go/Web 失败，不能视为全绿。Windows 唯一已观察失败是 `TestStartupIdentity` 使用 Unix `/tmp` 路径作为跨平台正例，已改为平台临时绝对路径并保留严格启动身份检查；Windows 实跑仍以新 head CI 为准。

Web 的管理页 Chromium/Firefox、扩展单测和真实 DOM 已通过；原生 GUI 在配对阶段失败。Sol 在与 CI 相同的 WenQuanYi 中文字体和 Xvfb 环境复现：字体改变控件高度，固定坐标没有正确输入/解锁。改用实际 AT-SPI 控件定位和就绪状态，保留一次真实用户输入，不反复重试授权。又实证两个 Linux 浏览器均向 native host 继承 `NO_AT_BRIDGE=1`，使实际 MyGo 窗口不可被系统辅助技术发现。合法宿主启动后、GTK 初始化前仅移除此标记，恢复系统默认桥接；不改其他系统设置和解锁/批准条件。Chromium 与 Firefox 均有环境回归，Firefox 扩展修复前失败记录为 `browser-ci-firefox-a11y-red.log`。

主代理在原失败字体配置独立复跑 `browser-xvfb-wqy-parent.log` 全绿，覆盖成功、拒绝、导航、锁库、批准前无值和不自动提交；私有合成目录 `locklark-browser-acceptance-LRceOc`。复跑在上方命令增加 `FONTCONFIG_FILE=/tmp/locklark-ci-fonts/wqy.conf XDG_CONFIG_HOME=/tmp/locklark-ci-gtk-wqy`，使用已运行的隔离 Xvfb `:94`。本机 AT-SPI 需要 `at-spi2-core`、`libatspi2.0-0` 和私有 DBus 会话。

## Firefox 独立完整链路

Sol 的外部实验和主代理独立复跑均已通过真实 Firefox 157、临时扩展、native messaging 和 MyGo 的完整解锁/连接/批准填充，包括原生拒绝、同源新文档拒绝、锁库、批准前无值、不自动提交及控制台秘密扫描。主代理日志 `firefox-native-parent.log`，私有合成目录 `locklark-firefox-native-R0s0Am`。测试只向临时 NSS 库导入受控 HTTPS CA，`acceptInsecureCerts=false`；使用浏览器真实 document IDs，无身份回退。

Firefox 通过实际工具栏 action 触发 `activeTab`。默认 Ctrl+Shift+Y 与 Firefox Library 冲突，其他候选快捷键未证明可靠，故 Firefox 构建不预设快捷键，用户可在浏览器扩展快捷键管理中配置；Chromium 的既有快捷键不变。新的仓库脚本 `scripts/browser_firefox_native_acceptance.mjs` 已由主代理独立复跑通过，CI 使用私有 DBus/Xvfb；本机成功不冒充远端 CI 已通过。


## 最终增量审阅及诊断隐私

Luna/max 对 Linux 两宿主无障碍环境恢复、Windows 启动测试路径、Firefox 快捷键以及新 GUI 驱动/验收脚本作了独立增量复核，结论无阻塞。独立通过 15 项 Node 测试、环境 Go 回归、manifest 身份/权限检查及脚本语法/差异检查；没有将这些检查当作完整 GUI 实跑。

复核提出的诊断问题已修复：X11 与 AT-SPI 同时绑定预期宿主可执行文件/PID和唯一窗口；只捕获该窗口或测试 popup，不截整个桌面。诊断目录由脚本在私有状态目录内创建，不接受外部复用目录。失败只输出固定阶段/错误类，避免把含合成因素的远端异常原文打印出来。Sol 的 Chrome 实际批准后强制故障、Firefox 实际配对后向异常放入合成因素的故障测试，均确认非零退出、stdout/stderr及诊断 JSON 无因素/字段回显；Firefox 同时确认自建 manifest 清理。分别见 `browser-ci-private-diagnostic-check.log`、`firefox-repo-privacy-after-pair.log`。这些工具故障不会改变产品授权条件。

主代理对最终 Chromium 控件/进程定位与私密截图版再次独立验收通过：`browser-xvfb-final-parent.log`，私有诊断目录 `locklark-browser-acceptance-d36xtN/diagnostics-103CUb`。定向 Go desktop/browserhost 与 15 项 Node 回归亦由主代理独立通过（`browser-parent-incremental-go.log`、`browser-parent-incremental-node.log`）。Firefox 最终仓库脚本亦由主代理独立复跑通过：`firefox-repo-final-parent.log`，私有目录 `locklark-firefox-native-lVt62A`。精确新 head CI 结果随后记录。


Firefox 最终复跑命令（使用已经运行的隔离显示，路径按本机调整）：

```sh
DISPLAY=:95 \
LOCKLARK_FIREFOX=/home/agent/.cache/ms-playwright/firefox-1555/firefox/firefox \
LOCKLARK_GECKODRIVER=/tmp/locklark-validation/firefox-document-binding/geckodriver \
LOCKLARK_GO=/tmp/locklark-tools/go/bin/go \
LOCKLARK_BROWSER_HOST=/tmp/locklark-tools/locklark-browser-firefox \
LOCKLARK_BROWSER_REGISTER=/tmp/locklark-tools/locklark-browser-register \
dbus-run-session -- node scripts/browser_firefox_native_acceptance.mjs
```

临时 manifest 已确认清理，现有用户 manifest 若存在则脚本拒绝覆盖。实际 Firefox 无障碍标记失败时的直接工具输出曾记录该标记；该轮本地日志后被正常轮覆盖，故不将已覆盖日志列为保留证据。Go 环境先红后绿日志和最终真实 GUI 日志分别保留。


## 合并结果

[PR #26](https://github.com/jihuayu/locklark/pull/26) 最终 head `6c649d992f913c36a75a16f30e1320c4b008d085` 在 [run 42073803355](https://github.com/jihuayu/locklark/actions/runs/42073803355) 的 Ubuntu Go、Windows Go/终端验收、macOS 桌面、Web 四项全部通过。Web 日志分别确认真实 Chromium 和 Firefox 原生完整链路通过，保留原有 Next.js 两浏览器和 DOM 测试。经 Luna/max 复审与主代理验收后 squash 合入 main `0f38177eb1059121d04e94fb96d264126688573f`。下一切片是显式保存/更新，见 [架构约定](browser-save-design.md)。
