# 1Password beta 浏览器扩展对照与粘贴保护同步

日期：2026-11-10。本文件记录用 REA 对 1Password beta Chromium 扩展（8.12.46.26）做的静态对照，以及据此在 Locklark 浏览器扩展中补齐的粘贴保护。它是**增量对照记录**，不替换 65 项冻结的[浏览器 1:1 清单](browser-parity-checklist.md)，也不声称完成完整参考对照。所有结论区分“静态观测”“推断”和“未验证”。

## 参考对象与身份

| 项 | 值 |
| --- | --- |
| 渠道/商店 | Chrome Web Store beta 列表 `khgocmkkpikpnmmkgmdnfckapcdkgfaf` |
| 扩展版本 | 8.12.46.26（buildnum `81246026`，builddate `2026-11-03T23:05:32.454Z`，channel `beta`） |
| CRX | CRX3，18,371,474 字节，SHA-256 `94cb3513f3b8ab50eea900b1a163a43f6bc2779a85e1b361fc335a69fb438d4a` |
| 解包目录摘要（REA subject） | SHA-256 `ea6055af8f4839e35b0e6ac037c2b164b8d8f3f44f5bc25f0bcb1eb8a5ab0781` |
| `manifest.json` | SHA-256 `9f83fde11ace2988b43b5e8316a5512397b1cbb1822361597fcb8cb4f8f5a21d` |
| `inline/injected.js` | SHA-256 `7cf23524c056d19abc83413832275ddda5852ab940814e671b8c4369b5a3b9da` |
| `background/background.js` | SHA-256 `3c6d8387a28b4b485d96e8fdd9a9029433c89c98433e6f4a3ae45cb8b59145a9` |
| 对照的 stable | 8.12.44.33，CRX SHA-256 `1cdc5bfbe2d13f38bbceeeb6fb41ff08477939c42567bf7cbcd0016ac00b09cb` |
| 另取 nightly（仅作边界参考） | 8.12.48.17，CRX SHA-256 `9aa25a705c6e5c664f65a06757d99eb913fe9cd5272bf4325f65c584e410ad6e` |

参考包只用于行为分析；没有把 1Password 的代码、素材或文案复制进 Locklark，也没有把参考包放进仓库。解包树放在工作区的 `.tmp/1p-artifacts/`（未跟踪）。

## 方法

### REA 静态重建

```sh
npx -y rea-agents@6.8.0 analyze-javascript-application <beta 解包目录> \
  --detail summary --evidence_output <evidence.json> \
  --source-path inline/injected.js \
  --max-semantic-nodes-per-file 20000 --max-heap-mb 3072
```

- provider：`rea-javascript-application` v1（REA 6.8.0），operation `analyze_javascript_application`。
- Evidence：`ev_c87bf6c8da4d659f9dfc57535d74a333b81f69b15f86eb8ab65fffc37a02efbe`，保留方式 `complete-record`。
- 选中源码：`inline/injected.js`（470,936 字节）；解析 1 个 JS 文件、118,969 个 AST 节点、20,388 个语义节点、10,570 条关系、52 项 findings。
- 全树分析（1,047 个文件）在 1 GiB 与 4 GiB V8 老生代堆上分别因 `chunks/chunk-MHRU6UBF.js`、`popup/index.js` 超限失败；改为按源文件选择后成功。**因此语义图只覆盖被选中的源文件**，其他 414 个 inventoried 文件的内部关系仍未分析。

REA 声明的局限（原文要点）：选定源分析使 414 个 inventoried 文件不在分析范围内；图覆盖不完整，缺失事实不能读作不存在；JS/HTML 仅作为惰性文本解析，未执行 bundle 引导代码；静态导入、入口、worker、端点与存储关系不证明运行时执行；动态或混淆表达式可能未解析。

### 补充证据

- 按字节偏移直接读取解包文本，确认 REA 语义节点的源码区间与字面量（REA 不输出被选中文件以外的源码片段）。
- 从 `assets/js/messages.i18n-*.js` 提取英文 UI 目录做 beta/stable 对比。这是 UI 字符串目录，不是行为证明。
- 对两棵解包树做文件级 SHA-256 与归一化文件名的差分。

## 观测一：beta 相对 stable 没有发现新的浏览器填充行为

| 观测 | 结果 |
| --- | --- |
| 文件集合 | beta 1,006 个文件，stable 1,005 个；归一化后无 beta 独有或 stable 独有的路径 |
| 内容不同的文件 | 38 个（manifest、background、injected、popup/app、若干 wasm 与 i18n） |
| 英文 UI 字符串 | beta 1,086，stable 1,078；新增 8 条、删除 0 条、修改 1 条（弯引号） |
| 新增字符串内容 | 引导页四句卖点、“Get started”、组织预装说明、“Show keyboard shortcut hints in universal sign-in” |

推断（不是运行时观测）：两个构建相隔约一天，beta 的差异集中在首次使用引导与组织预装，没有新增自动填充、保存、Passkey 或设置项行为。因此“同步 beta”在本轮等价于“同步 8.12.4x 的浏览器行为集”，下文清单按该行为集对照。该推断不能排除运行时开关、服务端功能位或未在 UI 目录出现的差异。

### beta 功能位

`inline/injected.js` 内 61 个 `b5x-*` 功能位的静态默认值全部为关闭（`!1`），由账号能力与远端放量决定；静态包不能证明某个 beta 用户实际看到哪些实验。与浏览器界面直接相关的有 `b5x-unified-panel`、`b5x-single-pane-popup`、`b5x-universal-sign-on`（及 11 个同族子开关）、`b5x-phishing-prevention-v2`、`b5x-closed-shadow-root-support`、`b5x-editable-autosave`、`b5x-hidden-pages-list`、`b5x-passkey-user-verification`。本轮只纳入有稳定默认行为、不依赖账号能力的粘贴保护；实验性界面重做不跟随。

## 观测二：参考扩展的浏览器侧行为清单

下表只记录有静态锚点的行为；“锚点”是可复核的源位置（行:列，来自 470 KB 单行/少行 bundle，列号是字符位置）。

| 参考行为 | 静态锚点 |
| --- | --- |
| 内容脚本分层：`inline/inject-content-scripts.js`（隔离世界）+ `inline/injected.js`（页面世界桥）+ `injected/webauthn*.js` + 站点集成 `b5.js`/`kolide.js`/`autofill.js` | `manifest.json` content_scripts |
| 内联菜单动作集合：填充条目、填充教程条目、填充生成密码、保存条目、隐私卡/邮箱别名/SSH 对话框 | `inline/injected.js:3`（菜单 action 枚举） |
| 自动保存分类：login、creditCard、identity、shellPlugins（API 凭据） | `inline/injected.js:37:5160` |
| 生成器类型：characters、pin、smart、words、rsa、ed25519 | `inline/injected.js:3`（generator 枚举） |
| Passkey 错误集合：timeout、bad-rp-id、duplicate、user-cancelled、fallback-requested 等 | `inline/injected.js:3` |
| 通用登录（universal sign-on）步骤：click-sign-in-with-button、click-generic-button、done、refresh、resolve-pending-fill | `inline/injected.js:3` |
| Watchtower 分类：reused、weak、unsecured、2FA、passkey、expiring 等 | `inline/injected.js:3:101984` |
| **钓鱼粘贴警告**：密码框粘贴时，若当前站点未关联任何条目则确认；取消则阻止粘贴 | `inline/injected.js:40:58237`；REA 节点 `jsrg_node_68573b501974c3a8f6b3cfde1be36b3e81074e3481f65bc8e857105c8649647f`（函数 `VN`，第 40 行 58019–58934 列） |
| **Secret Key 粘贴保护**：识别账号凭据形态，确认后才放行并回填 | `inline/injected.js:37:3856`；REA 节点 `jsrg_node_d624898081d16f9e9e5f5add642a7465dc4e219d2e54b5118df423b3e192279b`（函数 `BR`，第 37 行 3693–4190 列）；文案 `authorize-paste-secret-key` 在 5:58 |
| HTTP 页面填充警告 `authorize-fill-protocol` | `inline/injected.js:3:243621` |
| “添加网站并填充”与“仅填充一次”动作 | `inline/injected.js:3:116379` |
| 后台侧触发条件：条目缓存的裸域集合不包含当前标签页裸域时，推送 `show-phishing-warning` | `background/background.js`（`phishing-detection-handler.ts` 字符串附近） |

参考实现的行为要点（由上述锚点读出）：

1. 站点是否“已关联”按**裸域**匹配条目 URL 判断，而不是精确来源；页面内只保存一个布尔状态，粘帖时同步决策。
2. 未关联时，密码框粘贴使用阻塞式 `window.confirm`；点“取消”执行 `preventDefault` + `stopImmediatePropagation`，点“确定”清除该标签页的警告状态并放行浏览器原生粘贴。
3. Secret Key 形态的粘贴保护独立于站点链接状态，在确认后由脚本执行 `insertText` 回填。
4. 两个确认都只发生在页面世界的内容脚本里，不向后台发送剪贴板内容。

## 观测三：与 Locklark 现有实现的对照

| 参考行为 | Locklark 现状 | 结论 |
| --- | --- | --- |
| 内联菜单（关闭 Shadow DOM、焦点触发、键盘导航） | `content.js` `panel()`/`button()`；`focusin`；方向键/Esc | 已实现，实现方式不同（参考用页面世界 + 菜单页） |
| 候选按来源过滤、原生逐次批准 | `core.js` `sameContext`、`background.js` `inline-match`/`inline-fill` | 已实现，信任模型更严格 |
| 保存/更新、提交后横幅、新/更新分类、此站不保存 | `content.js` `stageFrom`/`showPendingSaveBanner`，`background.js` `stagedSaves` | 已实现 |
| 生成器（random/memorable/pin）与历史 | `core.js` `generatePasswordObject`，`background.js` 生成历史 | 已实现；参考另有 smart/SSH 类型，未同步 |
| Passkey 创建/断言/条件式/管理 | `webauthn.js`、`background.js` passkey 路由 | 已实现 |
| 身份/银行卡填充、结算 iframe 选择 | `content.js` `showAutofillSuggestions`、checkout picker | 已实现 |
| 右键“在此网站隐藏” | `background.js` `locklark-toggle-site-inline` | 已实现（等价于参考 Hide on this page） |
| 站点级禁用、永不保存、选项页、快捷键、徽章 | `options.*`、`background.js` commands/badge | 已实现 |
| Watchtower 本地体检 + 可选 HIBP | `background.js` watchtower 路由 | 已实现 |
| HTTP 页面填充警告 | Locklark 只注册 `https://*/*`，非 HTTPS 不运行 | 平台不适用 |
| 富图标下载、Masked Email、Privacy/Brex 虚拟卡、SSH 密钥、开发者平台 API 凭据自动保存、企业 Kolide/Trelica/Apono、agentic autofill / local MCP | 无对应产品能力或与本地优先模型冲突 | 未实现，见下文 |
| **钓鱼粘贴警告** | 本轮补齐 | 新增 |
| **Secret Key 粘贴保护** | 本轮补齐 | 新增 |

## 本轮实现：粘贴保护

### 行为规范

内容脚本在捕获阶段监听 `paste`（`content.js` `installPasteProtection`）。决策由纯函数 `core.pasteWarning` 完成：

| 输入 | 结果 |
| --- | --- |
| 设置关闭（`pasteProtection === false`） | 不处理 |
| 目标不是可编辑的 `input`/`textarea`，或 disabled/readOnly | 不处理 |
| 粘贴文本匹配 `LL1-`（26 位 Base32）、`LLR2-`（52 位）或 110 位恢复材料 | 警告 `secret-key`（与站点是否已关联无关） |
| 文本不匹配 Secret Key，目标是当前密码框，且本页最近一次 `inline-match` 明确报告 `siteLinked === false` | 警告 `phishing` |
| 站点状态未知（未连接、锁定、有未完成的原生请求、观测过期或从未发生） | 不拦截 |
| 目标是注册/确认新密码框 | 不按钓鱼处理（允许生成密码粘贴） |
| 合成事件（`isTrusted !== true`） | 不处理 |

命中时执行 `preventDefault` + `stopImmediatePropagation`，显示关闭 Shadow DOM 面板（标题“粘贴保护”），提供“取消粘贴”和“仍要粘贴”。选择“仍要粘贴”后才把文本写入目标字段并派发 `input`/`change`；选择“取消粘贴”时字段保持原值。

### 数据流与边界

- 剪贴板文本只存在于内容脚本地闭包中，用于一次决策；**不发送给后台、不写入存储、不写日志**，与参考实现一致。
- 后台只新增一个布尔元数据 `siteLinked`（`background.js` 的 `inline-match` 回复）：`true` 表示本次回复实际执行了 login 类别匹配且 `rows` 非空；`false` 表示执行了匹配但没有条目；`null` 表示未连接/有未完成请求/分类不是 login。不包含条目标题、ID 或任何字段值。
- 该布尔值在内容脚本内按来源缓存 5 分钟；保存成功后置为已关联。页面导航后自然失效。
- 设置项 `pasteProtection` 默认开启，位于选项页“自动填充与登录”分节，文案说明两项保护。

### 与参考实现的差异（经确认的设计选择）

1. **不复制 `window.confirm`**：使用扩展自己的关闭 Shadow DOM 面板，保持与现有内联 UI、键盘可达性和主题一致。代价是必须在用户确认后手动插入文本，而不是依赖浏览器原生默认动作。
2. **“未关联”以精确来源的 login 匹配为准**，不是参考的裸域集合；这与 Locklark“精确来源 + 原生批准”的既有模型一致，也避免把同裸域的不同端口/子域当作已关联。
3. **未知状态不告警**：参考由后台在标签页状态变化时把“未关联”布尔值推给页面；Locklark 只在内容脚本请求候选时获得状态，因此首次快速粘贴可能漏报。选择漏报而不是误报。
4. **跳过注册/确认新密码框**：这类字段经常接收生成密码，参考未明确区分；Locklark 明确排除，避免阻断生成器流程。
5. **没有遥测**：参考在警告时上报 `phishing_detection` 事件；Locklark 不上报。

### 测试

| 层 | 文件 | 覆盖 |
| --- | --- | --- |
| 纯策略 | `browser-extension/test/core.test.js` | Secret Key 形态（大小写、长度、尾随文本、110 位材料）、决策矩阵、默认开启与布尔归一化 |
| 内容脚本 | `browser-extension/test/paste_protection.test.js` | 未关联拦截与确认后写入、已关联放行、未知状态放行、锁定/断连放行、Secret Key 在已关联站点仍拦截、设置关闭、注册字段放行、合成事件与非可编辑目标忽略、取消后不残留且后台从未收到文本 |
| 后台 | `browser-extension/test/background.test.js` | `inline-match` 的 `siteLinked` 为 true（有登录）、null（identity 分类）、null（断开后） |

本批实际执行：`node --test test/*.test.js`，417 项全部通过（含上述新增 13 项）。这是 Node DOM 测试，**不是**真实浏览器、真实站点或固定参考版本的运行时对照。

### 限制

- 未在真实 Chromium/Edge/Firefox 中加载运行；没有真实站点、真实剪贴板或真实原生连接验证。
- 只覆盖内容脚本能够运行的顶层 HTTPS 文档与同源 iframe；跨源 iframe 不在 UI 范围。
- 页面世界若在捕获阶段更早注册了 `paste` 处理器，仍可能先看到事件；Locklark 只能阻止其后的处理器。
- 手动插入绕过页面的 `paste` 处理器，可能影响依赖 `paste` 事件做格式处理的前端框架；`setRangeText`/原生 setter 与 `input`/`change` 事件是当前兼容手段。
- 关闭 Shadow DOM 内部的输入目标不可见，不触发保护。
- 未知站点状态与首次快速粘贴会漏报；这是有意的失败方向。
- 面板因锚点失效（滚动出视口、目标被移除）或按 Esc 关闭时，本次粘贴已经被取消且不会自动重放；需要用户重新粘贴。
- 手动回填失败时只显示“无法自动完成粘贴”的提示，该失败路径没有自动化测试。
- 参考用裸域、Locklark 用精确来源，两者对“已关联”的判断可能不同；本文件不声称行为等价。

## 同轮追加：两步验证二维码捕获

参考的 `autosave-qr-code-detected` 行为在本轮同期实现为浏览器侧捕获：`BarcodeDetector` 本地解码、文档绑定的 worker 捕获、用户确认后以仅含 `otp` 的 `item-save` 写入已有登录。没有新增浏览器权限或原生协议消息；Chromium 系以外不可用。设计、边界与测试见[二维码捕获验收](browser-otp-qr-capture-validation.md)。它同样不计入 65 项冻结合同。

## 未同步的参考行为

| 行为 | 未同步原因 |
| --- | --- |
| “Sign in with” 第三方身份识别与保存 | 需要供应商按钮识别、跨步骤状态机与新的条目类型；与本地库模型不匹配 |
| 生成器 smart/SSH 类型 | Locklark 库类别只有 login/identity/card，SSH 条目无存储与使用路径 |
| 富图标下载 | 会引入外部请求与域名泄露；与本地优先、无持续联网的模型冲突 |
| Masked Email、Privacy/Brex 虚拟卡 | 依赖第三方账号与服务端集成 |
| 开发者平台 API 凭据自动保存 | 依赖站点专用规则集与“shellPlugins”类别 |
| 企业集成（Kolide/Trelica/Apono/特权访问） | 依赖企业服务端策略与设备信任链 |
| agentic autofill、local MCP server | 参考中的账号级 AI 能力；Locklark 的 MCP/网关边界另在仓库其他文档定义 |
| 系统通知、默认密码管理器引导、睡眠/空闲锁定 | 需要新权限或浏览器无对应 API；Locklark 的锁定由原生会话负责 |
| 通用登录合并提示 | 现有内联菜单已是统一入口；参考的 USO 是账号级产品流程 |

## 复跑

```sh
cd browser-extension
node --test test/core.test.js
node --test test/paste_protection.test.js
node --test test/background.test.js
node --test test/*.test.js
```

REA 复跑需要参考包（未跟踪）。`.tmp/rea/1p-injected.evidence.json`（约 48 MB）是上表的 Evidence 来源；它不在仓库内，不能作为可公开分发的证据副本。需要复核时按上面的命令重新生成，并比对本文件记录的 SHA-256 与 Evidence ID。
