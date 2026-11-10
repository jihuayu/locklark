# 浏览器插件当前功能与 1:1 对照清单

更新：2026-11-09。本批已合并起点 main 9cbc34c（[PR #48](https://github.com/jihuayu/locklark/pull/48)），含 PR #44–48。条件式/共存已合并，见[验收](conditional-passkey-validation.md)；下一批 Signal APIs、逐次系统 UV、公共站点组件和未签名发布准备见[综合验收](browser-completion-validation.md)。未取得固定参考版本逐项对照结果。 本轮 UI、元数据刷新性能与安全修补从 main 38c8324 接续，见[专项验收](ui-performance-security-validation.md)；原未关闭范围已拆到 #50–#59，#39 仍开放。

旧清单基于 `8e61dc1` 和当时未合并的 PR #40；其中“39 项未实现”“没有 v2 协议/共享会话”等结论已过时。完整参考分析、65 项稳定 ID、行为约定和当时的结果保存在[历史快照](history/browser-parity-m3-baseline-2026-11-06.md)，不再作为当前缺口统计。机器可读的 65 行映射见[证据映射](browser-parity-evidence.json)，由 `scripts/check_browser_parity_evidence.py` 校验；除 B13.3 的既有经确认差异外，参考状态仍为未对照。

## 状态与证据

“实现存在”“Locklark 实际跑通”“与参考产品对照完成”是不同结论。保留设计规定的五种状态：`未实现`、`已实现未对照`、`已实测`、`平台不适用`、`经用户确认的差异`。本表的状态指参考行为对照；以下真实 Locklark 测试通过，不自动关闭全部参考版本对照。

- 参考行为基线仍为历史记录的 1Password `8.12.44.33`；当前没有新的参考截图/安装版逐任务对照。只按行为清单开发，不复制其代码、品牌或素材。
- PR #44 的最终开发 head `faf4732` 六项 CI 通过后 squash 合入上述 main；附件、显式清空、172 项扩展测试、206 项 E2E 以及真实 Chromium/Edge/Firefox 范围见[插件收尾验收](plugin-completion-validation.md)。以下 PR #43 的 run 保留为上一阶段证据。
- [检查 run](https://github.com/jihuayu/locklark/actions/runs/42315487787)、[移动 run](https://github.com/jihuayu/locklark/actions/runs/42315487747)。iOS 只覆盖保护能力不足时的拒绝路径；PR #69/#70 保持正向保护失败为红色的门槛检查也不等于完整真机成功。
- 对应实现与测试：`content.js`、`core.js`、`background.js`、`popup.js`、`options.js`、`test/m3_fill_v2.test.js`、`test/host_v2_contract.test.js`，以及 `internal/browserhost` / `internal/personal`。具体实际命令与边界见 [M6 集成验收](m6-integration-validation.md)。

## 当前逐项清单

| 稳定 ID | 行为 | 对照状态 | 当前实现与仍需完成 |
| --- | --- | --- | --- |
| B1.1 | Closed-shadow inline menu on focus | 已实现未对照 | 当前代码已有对应实现；单测/DOM/原生验收见下方证据，尚无固定参考版本逐项对照结果。 |
| B1.2 | Keyboard navigation | 已实现未对照 | 当前代码已有对应实现；单测/DOM/原生验收见下方证据，尚无固定参考版本逐项对照结果。 |
| B1.3 | Reposition on scroll/resize; hide when anchor hides | 已实现未对照 | 当前代码已有对应实现；单测/DOM/原生验收见下方证据，尚无固定参考版本逐项对照结果。 |
| B1.4 | Ignore attribute and per-site suppression | 已实现未对照 | 当前代码已有对应实现；单测/DOM/原生验收见下方证据，尚无固定参考版本逐项对照结果。 |
| B1.5 | Origin/domain/port candidate filtering and sender verification | 已实现未对照 | 当前代码已有对应实现；单测/DOM/原生验收见下方证据，尚无固定参考版本逐项对照结果。 |
| B2.1 | Global and per-login auto-submit toggle | 已实现未对照 | 当前代码已有对应实现；单测/DOM/原生验收见下方证据，尚无固定参考版本逐项对照结果。 |
| B2.2 | Guarded POST `requestSubmit` | 已实现未对照 | 当前代码已有对应实现；单测/DOM/原生验收见下方证据，尚无固定参考版本逐项对照结果。 |
| B7.1 | Username-only or password-only screen fill | 已实现未对照 | 当前代码已有对应实现；单测/DOM/原生验收见下方证据，尚无固定参考版本逐项对照结果。 |
| B7.2 | Continuous multi-step fill session | 已实现未对照 | 当前代码已有对应实现；单测/DOM/原生验收见下方证据，尚无固定参考版本逐项对照结果。 |
| B7.3 | Multi-step auto-advance | 已实现未对照 | 当前代码已有对应实现；单测/DOM/原生验收见下方证据，尚无固定参考版本逐项对照结果。 |
| B12a.1 | Single-field TOTP fill | 已实现未对照 | 当前代码已有对应实现；单测/DOM/原生验收见下方证据，尚无固定参考版本逐项对照结果。 |
| B12a.2 | Split OTP digit inputs | 已实现未对照 | 当前代码已有对应实现；单测/DOM/原生验收见下方证据，尚无固定参考版本逐项对照结果。 |
| B12b.1 | Same-origin and same-site iframe fill | 已实现未对照 | 同源 iframe 已有实现/测试；same-site 跨源范围仍须单独确认，不能扩大已测范围。 |
| B12b.2 | Cross-origin iframe blocking and warning | 已实现未对照 | 当前代码已有对应实现；单测/DOM/原生验收见下方证据，尚无固定参考版本逐项对照结果。 |
| B12b.3 | Open shadow-DOM traversal | 已实现未对照 | 当前代码已有对应实现；单测/DOM/原生验收见下方证据，尚无固定参考版本逐项对照结果。 |
| B5.1 | Detect form submission | 已实现未对照 | 当前代码已有对应实现；单测/DOM/原生验收见下方证据，尚无固定参考版本逐项对照结果。 |
| B5.2 | Stage pending save across navigation and show a post-submit banner | 已实现未对照 | 当前代码已有对应实现；单测/DOM/原生验收见下方证据，尚无固定参考版本逐项对照结果。 |
| B5.3 | Classify new vs update vs unchanged | 已实现未对照 | 当前代码已有对应实现；单测/DOM/原生验收见下方证据，尚无固定参考版本逐项对照结果。 |
| B5.4 | Capture multi-password signup/change forms | 已实现未对照 | 当前代码已有对应实现；单测/DOM/原生验收见下方证据，尚无固定参考版本逐项对照结果。 |
| B5.5 | Never save for this site | 已实现未对照 | 当前代码已有对应实现；单测/DOM/原生验收见下方证据，尚无固定参考版本逐项对照结果。 |
| B6.1 | Inline generator trigger on signup/change-password fields | 已实现未对照 | 当前代码已有对应实现；单测/DOM/原生验收见下方证据，尚无固定参考版本逐项对照结果。 |
| B6.2 | Generator modes and controls | 已实现未对照 | 当前代码已有对应实现；单测/DOM/原生验收见下方证据，尚无固定参考版本逐项对照结果。 |
| B6.3 | Fill new-password and confirm-password together | 已实现未对照 | 当前代码已有对应实现；单测/DOM/原生验收见下方证据，尚无固定参考版本逐项对照结果。 |
| B6.4 | Generated-password history and staged recovery | 已实现未对照 | 当前代码已有对应实现；单测/DOM/原生验收见下方证据，尚无固定参考版本逐项对照结果。 |
| B9.1 | Popup vault search bar | 已实现未对照 | 当前代码已有对应实现；单测/DOM/原生验收见下方证据，尚无固定参考版本逐项对照结果。 |
| B9.2 | Suggested / All Items / Favorites / Categories tabs | 已实现未对照 | 当前代码已有对应实现；单测/DOM/原生验收见下方证据，尚无固定参考版本逐项对照结果。 |
| B9.3 | Item detail view | 已实现未对照 | 持久化详情/编辑及按次取值已通过真实 Chromium；附件与显式清空在本轮补齐并另记结果。剪贴板所有权 PR #72 的真实 Edge/Firefox 检查仍待完成，不能把 Chromium 结果外推。 |
| B9.4 | Create and edit items in the popup | 已实现未对照 | 持久化详情/编辑及按次取值已通过真实 Chromium；附件与显式清空在本轮补齐并另记结果。 |
| B9.5 | Popup header lock | 已实现未对照 | 当前代码已有对应实现；单测/DOM/原生验收见下方证据，尚无固定参考版本逐项对照结果。 |
| B10.1 | Open popup shortcut | 已实现未对照 | 当前代码已有对应实现；单测/DOM/原生验收见下方证据，尚无固定参考版本逐项对照结果。 |
| B10.2 | Autofill and lock shortcuts | 已实现未对照 | 当前代码已有对应实现；单测/DOM/原生验收见下方证据，尚无固定参考版本逐项对照结果。 |
| B10.3 | Right-click context menu | 已实现未对照 | 当前代码已有对应实现；单测/DOM/原生验收见下方证据，尚无固定参考版本逐项对照结果。 |
| B11.1 | Toolbar badge | 已实现未对照 | 当前代码已有对应实现；单测/DOM/原生验收见下方证据，尚无固定参考版本逐项对照结果。 |
| B11.2 | Per-site controls | 已实现未对照 | 当前代码已有对应实现；单测/DOM/原生验收见下方证据，尚无固定参考版本逐项对照结果。 |
| B11.3 | Dedicated options page | 已实现未对照 | 当前代码已有对应实现；单测/DOM/原生验收见下方证据，尚无固定参考版本逐项对照结果。 |
| B15.1 | Weak password detection | 已实现未对照 | 本地体检/可选 HIBP 与插件面板已有；结果来源时点、真实站点和参考行为仍待逐项核对。 |
| B15.2 | Reused password detection | 已实现未对照 | 本地体检/可选 HIBP 与插件面板已有；结果来源时点、真实站点和参考行为仍待逐项核对。 |
| B15.3 | Unsecured HTTP warning | 已实现未对照 | 本地体检/可选 HIBP 与插件面板已有；结果来源时点、真实站点和参考行为仍待逐项核对。 |
| B15.4 | Breached password via HIBP k-anonymity | 已实现未对照 | 本地体检/可选 HIBP 与插件面板已有；结果来源时点、真实站点和参考行为仍待逐项核对。 |
| B15.5 | Missing 2FA/passkey and expiring items | 已实现未对照 | 本地体检/可选 HIBP 与插件面板已有；结果来源时点、真实站点和参考行为仍待逐项核对。 |
| B15.6 | Current-site Watchtower banner and dashboard | 已实现未对照 | 本地体检/可选 HIBP 与插件面板已有；结果来源时点、真实站点和参考行为仍待逐项核对。 |
| B8.1 | Identity item category and field storage | 已实现未对照 | typed 金库模型、协议与 DOM 测试已有；真实网站、浏览器及参考产品对照仍须扩展。 |
| B8.2 | Identity field detection and multi-field fill | 已实现未对照 | typed 金库模型、协议与 DOM 测试已有；真实网站、浏览器及参考产品对照仍须扩展。 |
| B8.3 | Credit Card item category and field storage | 已实现未对照 | typed 金库模型、协议与 DOM 测试已有；真实网站、浏览器及参考产品对照仍须扩展。 |
| B8.4 | Credit Card field detection and `<select>` fill | 已实现未对照 | typed 金库模型、协议与 DOM 测试已有；真实网站、浏览器及参考产品对照仍须扩展。 |
| B3.1 | MAIN-world WebAuthn create/get interception | 已实现未对照 | 当前代码已有对应实现；单测/DOM/原生验收见下方证据，尚无固定参考版本逐项对照结果。 |
| B3.2 | Isolated-world passkey modal and settings | 已实现未对照 | 当前代码已有对应实现；单测/DOM/原生验收见下方证据，尚无固定参考版本逐项对照结果。 |
| B3.3 | ES256 discoverable credential creation and assertion | 已实现未对照 | 当前代码已有对应实现；单测/DOM/原生验收见下方证据，尚无固定参考版本逐项对照结果。 |
| B3.4 | RP ID validation against the Public Suffix List | 已实现未对照 | 当前代码已有对应实现；单测/DOM/原生验收见下方证据，尚无固定参考版本逐项对照结果。 |
| B3.5 | `excludeCredentials`/`allowCredentials` and overwrite prevention | 已实现未对照 | 当前代码已有对应实现；单测/DOM/原生验收见下方证据，尚无固定参考版本逐项对照结果。 |
| B3.6 | Browser fallback and cancellation | 已实现未对照 | 当前代码已有对应实现；单测/DOM/原生验收见下方证据，尚无固定参考版本逐项对照结果。 |
| B13.1 | Conditional UI | 已实现未对照 | 本批新增 metadata-only 账户列表、能力接口、开放 Shadow DOM 焦点、无提前批准和期限/取消/断连清理；Chromium/Edge/Firefox 实际组合旅程通过。参考版本对照仍待完成，见条件式验收。 |
| B13.2 | Passkey management and separate removal | 已实现未对照 | 弹窗服务端筛选、RP/账号元数据、明确确认/取消和独立删除；既有双账号旅程记录不覆盖 PR #71 的同父项多凭据范围。PR #71 的实现与测试已完成，真实 Edge/Firefox 检查待 CI，不能先记为通过。每条登录一个凭据，多账号分条目管理；同条目多凭据迁移未做，远端检查见本轮验收。 |
| B13.3 | Advanced WebAuthn extensions, algorithms, related origins, signal APIs | 经用户确认的差异 | 沿用历史清单记录的 P2 差异：高级算法/扩展走原生认证器回退；本批补 RS256/EdDSA-only、enterprise attestation 和超长算法列表的回退回归，Edge 其他软件验证器实际签名共存通过。本批已实现已有原生 Signal APIs 的 owner 确认流程，相关来源/非本域 RP 委托浏览器；Chrome/Edge 真实 Signal 验收通过。高级能力回退不是本地实现全部扩展，见综合验收；原历史决定见 §6.3。 |
| B14.1 | Truthful user verification | 已实现未对照 | 当前代码已有对应实现；单测/DOM/原生验收见下方证据，尚无固定参考版本逐项对照结果。 |
| B14.2 | Windows Hello / Touch ID biometric prompt | 已实现未对照 | 本批接入每次新鲜系统保护 capsule 的 Passkey 验证，等待后重新核验请求；fake adapter 与 race 通过，真实 Hello/Touch ID 提示、拒绝及硬件失效仍待验收。 |
| B4.1 | Shared unlock state with desktop | 已实现未对照 | 共享会话/单独宿主路径已有；锁库撤销测试通过，跨平台完整交互仍待对照。 |
| B4.2 | Bidirectional lock propagation | 已实现未对照 | 共享会话/单独宿主路径已有；锁库撤销测试通过，跨平台完整交互仍待对照。 |
| B4.3 | Biometric/system unlock delegation | 已实现未对照 | 本批接入每次新鲜系统保护 capsule 的 Passkey 验证，等待后重新核验请求；fake adapter 与 race 通过，真实 Hello/Touch ID 提示、拒绝及硬件失效仍待验收。 |
| B4.4 | Standalone fallback when desktop is not running | 已实现未对照 | 共享会话/单独宿主路径已有；锁库撤销测试通过，跨平台完整交互仍待对照。 |
| B16.1 | Chromium/Edge MV3 manifest and native registration | 已实现未对照 | Chromium 及独立 Edge 157 的真实原生流程、附件/清空、填充/保存/更新/OTP、快捷配对/自动登录/Passkey 均实跑通过；发布安装仍待验证。 |
| B16.2 | Firefox MV3 manifest and native acceptance | 已实现未对照 | Firefox 填充/保存/更新/OTP 及新增 Passkey 创建/断言/签名验证/取消/回退分别实跑通过，范围及最终 CI 见本轮验收。 |
| B16.3 | macOS Safari Web Extension | 已实现未对照 | Safari Web Extension 清单、`safari-native-port.js` 传输与 Swift 宿主已存在；真实 macOS job `128804121932` 通过 77 项 Swift 测试、系统探针及 Xcode app/extension **未签名**构建。尚无签名安装、实际 Safari 加载/生命周期或固定参考对照，不能以构建通过关闭。 |
| B17.1 | Commands (`_execute_action`, autofill, lock) | 已实现未对照 | 当前代码已有对应实现；单测/DOM/原生验收见下方证据，尚无固定参考版本逐项对照结果。 |
| B17.2 | Connection status, pairing UX, onboarding | 已实现未对照 | 共享会话/单独宿主路径已有；锁库撤销测试通过，跨平台完整交互仍待对照。 |

## 本批新增行为（不计入 65 项冻结合同）

2026-11-10 以 REA 静态对照 1Password beta 8.12.46.26 后，补入两项粘贴期保护。它们**不在**上表 65 项稳定 ID 中：该合同锚定 8.12.44.33，扩表需要单独决定并同步 `scripts/check_browser_parity_evidence.py` 的 tripwire；在决定前只用本节记录，不改变 `browser-parity-evidence.json` 的 65 行。

- **未关联站点粘贴密码前的钓鱼警告**：当前密码框粘贴时，若本页最近一次候选匹配明确报告“无已保存登录”，先显示关闭 Shadow DOM 的确认面板；取消则阻止本次粘贴。站点状态未知（未连接、锁定、有未完成原生请求、观测过期）不拦截。参考行为、决策表与差异见 [1Password beta 对照](browser-1password-beta-parity.md)。状态：已实现未对照，只有 Node DOM 测试。
- **Locklark Secret Key 粘贴保护**：粘贴 `LL1-`、`LLR2-` 或 110 位恢复材料形态的文本时，无论站点是否已关联都先确认；与参考的 `authorize-paste-secret-key` 对应。状态：已实现未对照，只有 Node DOM 测试。
- **两步验证二维码捕获并保存**：`BarcodeDetector` 可用时本地解码页面上的 `otpauth://totp` 二维码，显示 issuer/account，用户确认后把 OTP 配置写入当前来源的已有登录；种子不回传页面、不自动保存、不新增权限。与参考的 `autosave-qr-code-detected` 对应。状态：已实现未对照，只有 Node DOM 与 Go 单测，未在真实浏览器运行；Chromium 系以外不可用。见[二维码捕获验收](browser-otp-qr-capture-validation.md)。

- **金库外围能力**：弹窗“已归档”筛选与归档/取消归档、把当前网站追加到条目后填充、显式打开内联菜单时聚焦首项、仅当前站点的 favicon、选项页诊断报告导出、Open & Fill 优先已保存的登录页路径。见[缺口盘点](browser-native-gap-inventory.md)。
- **空闲自动锁定与系统通知**：新增 `idle` 与 `notifications` 权限；空闲锁定默认关闭、通知默认关闭，通知只含标题或固定锁定文案。权限理由见[发布准备](browser-release-preparation.md)。
- **密码历史与身份提供商标识**：新增原生能力 `history-v1`，浏览器只读元数据并按索引恢复（旧密码不外发）；身份提供商只做展示识别，不接入 OAuth。见[历史与提供商验证](browser-history-and-provider-validation.md)。
- **交互完整度**：金库与页面内面板的键盘导航、详情返回焦点、`/` 聚焦搜索、回收站两步确认、保存横幅聚焦与 `Esc`/`Enter`、加载与空状态、减少动画。见[交互对齐记录](browser-interaction-parity.md)。

以上行为除空闲锁定与系统通知默认关闭外均默认开启，可在选项页关闭；剪贴板文本与二维码种子都不写入扩展存储。

## 本轮补齐与仍开放的产品范围

附件上传/下载/删除、未读取备注及隐藏自定义字段的显式清空，在 [插件收尾验收](plugin-completion-validation.md) 记录实际结果。未运行的流程不能仅凭代码或新按钮记为通过。

仍开放：Safari；各浏览器的 Windows/macOS 原生组合；同一登录条目的多凭据管理；真实系统生物识别；更多站点和输入框兼容性；签名、商店分发与自动更新。条件式账号列表已实现并完成三浏览器受控验收；公共站点精简 fixture 与未签名准备已有证据，不能代替实际站点账户或签名分发验收。已实现范围的完整参考对照仍需逐项关闭。真实 NVDA/VoiceOver/JAWS、操作系统缩放/高对比度、固定参考安装及外部 owner 验收仍开放（#57）；自动化驱动已加入 `scripts/browser_accessibility_acceptance.mjs`，但主代理尚未运行，不得据此声称通过。

新结果应更新本表相应行及精确提交/平台证据；旧版本计数、E2E 的能力探针通过和 CI 绿色均不能代替完整产品任务验收。
