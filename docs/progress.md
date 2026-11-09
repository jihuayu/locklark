> 2026-11-09（北京时间）更新：主线 `42a2a7c` 已合并 PR #71 多通行密钥和 #72 剪贴板；#56、#63、#66 已关闭。迁移 #74、证据映射/无障碍 #75、结算 #76、CLI broker/lease #77 尚未合并。组合分支 438 项 Node 检查及真实 Linux CLI、共享 Edge 剪贴板和结算拒绝旅程通过；组合 Go race 与最终平台 CI 继续验证。iOS 正向文件保护失败仍由 #69 跟踪；真机、商店签名、固定参照与独立审计未宣称完成。历史完整 E2E 的 215 项计数不是本轮重跑；新增证据及未完成条件见[遗留 issues 台账](all-issues-implementation-ledger.md)。

# Locklark 开发进度

2026-11-08（香港）：DeepSeek 已修复浏览器复制后的无条件清空定时器，避免覆盖后来复制的内容，并改为准确的手动清理提示；主代理独立复跑 304 项扩展测试通过。见[剪贴板归属验收](browser-clipboard-ownership-validation.md)。#59 的原生租约接入和实际 OS 验收仍在推进，其他 #50–#58 不因本补丁自动完成。

本轮优化起点：main 38c8324（PR #49），日期 2026-11-07（香港）。已实现首屏搜索/可展开工具/深色对比度/键盘筛选、弹窗迟到秘密回复及锁定抢占保护、一次认证三份桌面元数据快照（保留三条原审计）、x/net 安全更新与持续扫描。301 Node、两浏览器各 32 组 DOM/组件及快照 race 通过；E2E 213 项为 177 通过、36 pending、0 失败，完整原生和最终 CI 回执见本批 PR。详见[UI、性能与安全验收](ui-performance-security-validation.md)。

遗留范围现已拆成 [#50–#59](https://github.com/jihuayu/locklark/issues?q=is%3Aissue+is%3Aopen)，#39 继续作为总清单。DeepSeek 初始 HTTP 403，后续已实际恢复并完成 CSS/驱动/生命周期实现及定向静态检查；Luna max 复核，主代理设计并独立验收，恢复证据及凭据迁移/轮换遗留见 #58。以下前轮“仅 #39 开放”的数字为历史，不再是当前 issue 总数。

## 前轮交接记录


本批已合并起点：main 9cbc34c（[PR #48](https://github.com/jihuayu/locklark/pull/48)，2026-11-07 09:16:47 UTC），精确 head b2905ff 的六项 CI 全部成功，合并树与验证树一致。PR #46 已关闭 #24/#32/#33/#34/#36/#38，PR #47 关闭 #35；当前仅 #39 浏览器体验 epic 开放。旧段落为历史，不代表当前未合并 PR。

2026-11-07 浏览器继续完成：条件式账户建议和其他提供者回退已经 PR #48 合并；本批补齐 native owner 确认的 Signal APIs、逐次新鲜系统 UV 入口、相关来源请求回退、可重复未签名发布包和公共站点精简兼容 fixture。主代理设计/独立验收，外部 DeepSeek workers 实现/并行复核。扩展 293 项通过，统一 E2E 212 项（176 通过、36 pending、0 失败），探针和组件单独统计；实际 Chromium/Edge/Firefox 完整原生交互及三浏览器公共站点组件通过；本批 [PR #49](https://github.com/jihuayu/locklark/pull/49) 的最终精确 head CI 与合并回执见该 PR。详见[本批综合验收](browser-completion-validation.md)及[条件式验收](conditional-passkey-validation.md)。真实 Hello/Touch ID、Windows/macOS 全链路、跨设备和签名商店分发仍未完成，不能关闭整个 #39。

2026-11-07 全部 issues 接续：起始 8 项未关闭。#32/#33/#34/#36/#38 的主修复已在 PR #43 合并，正独立复核并补齐原始竞态回归；#35 历史验证性能与 #39 条件式 Passkey 在隔离工作区并行实现，#24 收录通知补 README 回链。逐项证据、关闭门槛和外部验收范围见 [issues 完成记录](issue-completion-validation.md)。

2026-11-07 继续推进 Passkey 管理：弹窗筛选、RP/账号元数据、独立删除及并发撤销已实现；主代理独立 Chromium、Edge、Firefox 双账号旅程通过，删除后保留登录/密码/备注，另一账号重连后仍能签名。DeepSeek workers 完成实现并并行调研 CLI，主代理补审计动作回放并独立验收。完整测试与当前 PR/远端门槛见 [Passkey 管理验收](passkey-management-validation.md)；CLI broker 客户端/租约仍未闭环。

2026-11-07 插件收尾（[PR #44](https://github.com/jihuayu/locklark/pull/44)）：附件上传/下载 SHA-256 校验/删除、备注及隐藏自定义字段显式清空、异步操作竞态修复已完成本地验收。扩展 172 项测试通过；更新后 E2E 为 206 项：170 通过、36 pending、0 失败，分开报告能力探测与组件契约。独立 Edge 与 Firefox Passkey 实测范围、剩余 CLI broker/旧文档兼容和远端回执见[本轮验收](plugin-completion-validation.md)。

## 历史阶段记录

2026-11-07：从 main `eccd326` 接续唯一未合并的 [PR #43](https://github.com/jihuayu/locklark/pull/43)，完成集成缺陷修复并推进桌面、扩展与 CLI：共享持久化 v2 模型、原子浏览器编辑、真实 DTO 适配、OTP 序列化、锁库通知、受控 CLI 帮助路径与 DeepSeek profile。按本轮用户指令由主代理设计架构、DeepSeek 外部 worker 并行调研/实现。实际测试、独立复核范围、远端合并门槛与仍待 1:1 对照项见 [M6 集成验收](m6-integration-validation.md)；以下段落保留历史记录，不能覆盖此处较新的 PR 状态。

团队同步与移动端从 main `9d8d574` 接续，架构与验收约定见[团队与移动设计](team-mobile-design.md)。主代理设计和独立验收，Sol xhigh 子代理分别实现真实 HTTPS 团队同步、共享 Go 移动门面、Android Kotlin、iOS Swift及外部验收，Luna max审阅。PR #37 当前仍为草稿：真实团队 TLS 与服务命令独立验收已通过；第七轮 Android 原生流程、独立外部界面、真实数据库签名审计及 KDBX 互通全部通过，新增系统认证验收发现 ATD 不提供安全锁屏，已切换完整 Google APIs 镜像继续；iOS 在官方 URL 接口实测后仍返回较弱保护，保持拒绝并准备真机验收。精确进展及失败证据见[团队与移动验收](team-mobile-validation.md)，不能把协议核心或构建成功当作完整手机/团队产品通过。

登录备注 [PR #31](https://github.com/jihuayu/locklark/pull/31) 已在精确 head `9b11713` 的四项 CI（run `42146467829`）、Luna max产品/工具/测试复核及主代理独立 GUI/升级/对账验收后，正常 squash 合入 `9d8d574`。主代理核对完整远端日志中的八项真实 GUI/故障门槛；首轮 OTP 测试时钟失败已由仅测试修正关闭。

MyGo 快捷搜索 [PR #30](https://github.com/jihuayu/locklark/pull/30) 已经 Sol xhigh 实现、Luna max 复审、主代理固定构建独立 GUI 与精确 head `e12cc9ab` 的四项 CI（run `42138473111`）合入 main `87fcd7c`。下一项为[登录备注](login-notes-design.md)：迁入、加密保存、原生明确查看/编辑和独立 KDBX 对账；Sol实现、Luna max产品及工具复审、主代理固定v1独立旧桌面回归与完整备注GUI、真实旧CLI升级及独立PyKeePass对账已通过；全Go/race/vet/交叉编译通过，主代理与Sol的最终故障隐私也已通过，[PR #31](https://github.com/jihuayu/locklark/pull/31) 首轮macOS/Web成功，Ubuntu旧OTP版本检查测试撞到真实到期；已由Sol仅修正测试时钟，重复/race及Luna复核通过。产品不变，更新提交的精确head CI和正常合并门槛仍待核验。

浏览器逐次原生批准OTP [PR #29](https://github.com/jihuayu/locklark/pull/29) 已由Sol xhigh实现，Luna max复审、主代理固定构建的两浏览器完整GUI与故障隐私验收通过；精确head `ced61e5` 的四项CI（run `42133038819`）全部通过，合入 main `20e27aa`。继续从此主线实现[MyGo快捷搜索](desktop-quick-search-design.md)，同样保留Sol实现、Luna review及主代理设计/验收分工；固定v2已通过主代理完整日常回归与真实全局快捷搜索验收，精确head远端CI和合并门槛待完成。

桌面日常生成/TOTP与系统剪贴板所有权 [PR #28](https://github.com/jihuayu/locklark/pull/28) 已经Sol xhigh实现、Luna/max复审、主代理独立完整GUI与精确head `85b400ff` 的四项CI（run `42120014509`）合入 main `4f37d8c`。Windows部分写入失败通过先发布nonce再发布文本修复，Windows/macOS原生smoke均实际通过。继续从此主线实现浏览器逐次原生批准的验证码填充，见[浏览器OTP架构](browser-otp-design.md)与[验收](browser-otp-validation.md)；同样按主代理设计/验收、Sol xhigh实现、Luna max review分工；浏览器OTP已完成固定构建的两引擎真实GUI及本地回归，Luna无阻塞，PR与精确head CI合并门槛仍待完成。

浏览器保存/更新 [PR #27](https://github.com/jihuayu/locklark/pull/27) 已经 Luna/max、主代理独立两浏览器完整验收及精确head `8d63fd6` 的四项CI（run `42089993817`）合入 main `c9d4a5d`。继续从该主线实施MyGo原生强密码生成和TOTP日常操作，见[桌面架构](desktop-daily-design.md)与[桌面验收](desktop-daily-validation.md)，仍由Sol xhigh实现、主代理设计验收、Luna max审阅。 桌面生成/OTP核心及竞态测试已通过；真实GUI发现锁定同步读取foreign剪贴板会阻塞，已改为系统ownership lease。最终v4已通过主代理独立完整GUI、故障隐私扫描、53项工具测试及Luna/max复审；锁定foreign-owner场景647ms发布界面、零读取请求。[PR #28](https://github.com/jihuayu/locklark/pull/28) 首轮CI已通过macOS原生剪贴板，Windows部分写入清理出现真实失败，已完成凭证先于文本发布的窄修并经Luna复核；新head须四项CI全部通过再合并。

浏览器原生配对与登录填充 [PR #26](https://github.com/jihuayu/locklark/pull/26) 已经 Luna/max、主代理独立 Chromium/Firefox 完整 GUI 验收及精确 head `6c649d9` 的四项 CI（run `42073803355`）合入 main `0f38177`。当前从该主线开始显式保存新登录/更新已有登录，按 [保存架构约定](browser-save-design.md) 继续由 Sol xhigh 实现、主代理设计验收、Luna max review。

显式保存/更新实现已完成 Luna/max 最终增量 review、全仓 Go/定向 race、35项扩展测试及主代理独立 Chromium/Firefox v4 完整 GUI 验收。独立验收发现并修复 popup 刷新旧候选操作窗口与外部 AT-SPI 瞬态查询失败，证据见 [保存与更新验收](browser-save-validation.md)。当前准备精确 head PR/CI，尚未据此标记合入；下一候选为 MyGo 日常生成密码和原生TOTP。

Next.js 本机只读管理 PR #25 已经 Luna/max 复审和精确 head `f67f34e` 四平台/浏览器 CI（run 42060380427）通过，squash 到 main `dcc52d0`。后续浏览器切片已同步此基线；按用户要求由主代理负责架构/验收，Sol xhigh 实现，Luna max 审阅。真实 Chromium 扩展 → MyGo 解锁/配对/批准 → HTTPS 登录填充及拒绝/导航/锁库流程已实跑；独立审阅修复与最终 CI 继续推进，见 [浏览器验收](browser-native-validation.md)。真实 Firefox 157 完整填充链路也已由主代理独立复跑；首轮 CI 发现的 Windows 测试路径与中文字体坐标问题已定位并修复，新增无障碍恢复与稳定的真实控件验收继续复审。保存/更新、Safari/移动、完整迁移和团队同步仍未完成。

原生 MyGo 桌面与系统快捷解锁 [PR #23](https://github.com/jihuayu/locklark/pull/23) 经 Luna/max 最终复审及 Ubuntu/Windows/macOS CI（run 42044135997，head `bb59657`）合入 main `de7ba5a`。系统 Hello/Touch ID/Secret Service 真机行为继续单列。当前接 Next.js 本机只读团队管理和固定 Go 元数据接口，见 [Web 验收](nextjs-management-validation.md)；完整迁移、扩展、团队/同步和手机范围仍持续推进。

个人开发者环境注入 [PR #22](https://github.com/jihuayu/locklark/pull/22) 已合入 `5b0ce38`，精确 head `40aba12` 的 Ubuntu/Windows CI（run 42009389353）通过。

第八批标题搜索 [PR #21](https://github.com/jihuayu/locklark/pull/21) 已经 Luna/max 与 Ubuntu/Windows CI 合入 main `b9edaa8`（run 42004280736，head `5dd722c`）。第九批接个人开发者 `run-env`：固定条目/修订/字段、人工确认、意图先提交、最小子环境和无子进程文本回流，见[环境注入验收](personal-run-env-validation.md)。这是向本地可信程序披露，不能代替 invoke 机器授权或第三方沙箱；SSH 与 op 对照仍待完成。

第七批签名插件目录 [PR #20](https://github.com/jihuayu/locklark/pull/20) 已经 Luna/max、全量 Go/竞态和 Ubuntu/Windows CI 合入 main `1dfc8b0`（run 42001953615，head `6e5b315`）。第八批接个人 CLI 隐藏查询的标题搜索：Unicode 匹配、状态范围、同名保留、事务审计与无原始查询绑定，见[标题搜索验收](personal-title-search-validation.md)。桌面、浏览器/手机、远端同步及其他产品缺口仍按七条范围保留。

第六批个人 GitHub 实时查询 PR #19 已经 Luna/max 与 Ubuntu/Windows CI 合入 main `8659bb9`（run 41994363160，head `0fcf57d`）。继续第六条产品线的离线签名插件目录：独立公钥配置、包摘要确认、安装/升级/永久撤销、checkpoint 与原子事件，见[签名插件目录验收](signed-plugin-catalog-validation.md)。这批只管理静态签名数据，第三方执行仍关闭，操作系统沙箱和管理 UI 尚未完成。

七条推进第五批 PR #18 已经 Luna/max 与 Ubuntu/Windows CI 合入 main `c8c38e4`（run 41991910945，head `33f56f0`）。第六批接个人 CLI 人工确认的真实 GitHub HTTPS 适配器入口，见[实时查询验收](personal-live-pull-validation.md)。真实网络代码已接入，测试仍区分个人事务/受控 TLS/终端拒绝；真实账号成功调用、远程审批与机器授权未完成，不能由本入口代替。

七条推进第四批 PR #17 已经 Luna/max、全量 Go/竞态与 Ubuntu/Windows CI 合入 main `a4adaac`（run 41990092318，head `5450615`）。第五批实施团队 writer 数据写权限：独立策略 Scope、强制设备证明、事务内前态授权、历史重读复核和精确父 CAS；见[写权限验收](team-writer-acl-validation.md)。这是本地目录 API，完整团队产品和其他七条范围仍未完成。

七条推进第三批 PR #16 已经 Luna/max、Linux/Windows CI（含原生 DACL 与 ConPTY）合入 main `19f6e5a`。第四批接团队设备双钥持有证明，见 [设备证明验收](team-device-possession-validation.md)；仍是目录协议/持久化核心，完整邀请、权限和远端同步继续保留。

七条推进第二批 PR #15 已经 Luna/max 与双平台 CI 合入 `a078a75`。第三批接受控单字段 JSON 配置注入：精确修订、目的绑定、审计先提交、私密文件创建和不覆盖发布，见 [注入验收](personal-json-injection-validation.md)。这不是完整 run/inject/SSH 或全部七条完成。

七条推进第一批 PR #14 已经 Luna/max 及双平台 CI 合入 main `e925eec`：基本登录导入/对账、源计划私密绑定、来源记录保留。第二批接本地密码体检，见 [体检验收](personal-health-validation.md)。桌面/浏览器/手机/完整迁移等范围仍保留在七条清单中。

用户要求完成七条产品线，持续范围见 [七条交付](seven-track-delivery.md)。从 main `d932f51` 接续第一批认证 1PUX 登录导入：摘要绑定计划、同事务整批写入/逐项审计、加密来源记录及独立导出对账；详细范围见 [导入验收](personal-import-validation.md)。完整迁移及其他六条仍按清单逐项推进，不能将本批窄 profile 计为全部完成。

从 main `65b3f3d` 接续个人回收站/恢复：保留原活动或归档状态、版本冲突与固定拒绝审计、阻止回收站值披露/编辑/生成、备份及 KDBX 状态保留，见 [回收站验收](personal-trash-validation.md)。Luna/max 最终复核、完整 Go 与定向 race 已通过；最终 head、双平台 CI 与合并状态见 [PR #13](https://github.com/jihuayu/locklark/pull/13)。永久清空、保留期和安全擦除仍未实现。

2026-11-05（香港时区）四线交接：独立密码 KDBX 迁出 [PR #9](https://github.com/jihuayu/locklark/pull/9)、归档日常操作 [PR #10](https://github.com/jihuayu/locklark/pull/10)、HTTPS 来源候选与共享向量 [PR #11](https://github.com/jihuayu/locklark/pull/11)、签名团队目录/撤销/冻结核心 [PR #12](https://github.com/jihuayu/locklark/pull/12)。四批均有 Luna/max 独立复核、针对性失败/成功测试与双平台 CI 证据；最终 head/合并状态以对应 PR 为准。后两项是平台/团队基础核心，真实浏览器与手机接入、设备持有证明/权限执行及网络同步仍待完成。

四线第 3 批 PR #11 已合并 main `c8bf4fd`，Luna/max 与双平台 CI 通过。第 4 批签名团队目录/可信本地排序、持久原子版本提交、撤销墓碑与冻结见 [团队核心验收](team-directory-validation.md)。本轮四条线均有代码/验收推进；平台应用和完整团队网络产品仍未完成。

四线第 2 批 PR #10 已合并 main `33ede66`，Luna/max 与双平台 CI 通过。第 3 批网站 URL 与来源匹配核心、CLI 和平台共享向量见 [来源匹配验收](login-origin-matching-validation.md)；真实浏览器/移动系统集成仍保留。

四线第 1 批已合并 PR #9 / main `1c58330`：独立密码 KDBX 迁出、Luna/max、Ubuntu/Windows CI 全通过。第 2 批归档/恢复状态、默认列表/引用过滤及 CAS 审计见 [归档验收](personal-archive-validation.md)。来源匹配和团队目录随后推进。

总规格与验收矩阵见 [design.md](design.md)。下表按依赖列出持续目标；只有实际跑过的范围才写为已验证。「待做」包括本机仍可开发的部分；只有需要外部条件的那条验收延后。

全部开发范围与每切片完成门槛见 [development-goal.md](development-goal.md)。已配置按小时接续的持续推进任务；只有实际完成的功能及验收证据才能更新完成状态。

2026-11-05 接续：PR #1 已合入 main `8c97e8537e1b5659a696339a02ff83122b6745b5`，下文早期“main 只有 README / PR #1 未合并”为历史记录。本轮在 `codex/personal-disclosure` 实现个人 CLI 受控单字段披露：交互确认、稳定 ID/修订、加密签名意图先提交、终端显示和无秘密 stdout 回执。并发编辑、事务失败、输出失败及包含披露意图的恢复均有回归；状态与 Luna/max 独立复核见 [personal-disclosure-validation.md](personal-disclosure-validation.md)。完整产品、外部密码评审和原生平台验收仍保留。

继续接续：PR #2 经 Luna/max 复核、修复和 Ubuntu/Windows CI 后已合入 `011814d`。本轮新增生成密码并创建/按修订替换个人登录的 CLI 事务入口；生成策略进入签名审计，原值仅加密保存，另用受控披露查看。范围、故障注入、旧版升级及检查证据见 [personal-generation-validation.md](personal-generation-validation.md)；生成不是上游网站改密。后续继续接通个人 TOTP 产品入口。

PR #3 已完成 Luna/max 复核和 Ubuntu/Windows CI，合入 `c37e833`。随即接续 `codex/personal-totp`，实现个人 TOTP 配置保存/清除、先记意图再计算的受控取码、窗口过期/回拨拒绝及配置生命周期清除；独立 Python HMAC 校验实际终端码。范围与验收见 [personal-totp-validation.md](personal-totp-validation.md)，仍不提供 Agent 种子或验证码访问。

PR #4 经 Luna/max 复核和 Ubuntu/Windows CI 合入 `55b3ae7`。继续从该基线开发 `codex/personal-references`：认证引用目录、按引用披露用户名/密码及生成验证码，在同一事务内解析、绑定、核对修订并提交意图；同名、类型串用和旧引用拒绝。验收与当前状态见 [personal-references-validation.md](personal-references-validation.md)。

PR #5 已完成 Luna/max 复核（修复 Unicode 格式字符造成的终端显示欺骗）、全仓与定向 race，以及最终 Ubuntu/Windows CI，合入 `85a3d6f`。继续开发 `codex/onepux-login-fields`，扩展 1PUX 登录字段的字面清点、重复/未知 designation、独立 type/fieldType 属性和共享容量预算；不输出源值、不授予迁移许可。证据与下一项见 [onepux-login-fields-validation.md](onepux-login-fields-validation.md)。

PR #6 已经 Luna/max 复核及 Ubuntu/Windows CI，合入 `83ba767`。现从该主线推进 `codex/onepux-password-history`：值/时间形状、精确整数时间比较、条目内字面重复及共享容量清点；保留所有顺序/重复与未映射状态。证据见 [onepux-password-history-validation.md](onepux-password-history-validation.md)。下一步优先把预检接到认证、审计的个人 CLI，避免基础模块长期没有可用入口。

PR #7 经 Luna/max 复核与 Ubuntu/Windows CI 合入 `cff9aaf`。随后接续个人 CLI 的认证 1PUX 预检：解锁并验证历史后才读取源文件，输出前提交成功报告摘要或固定拒绝类别；同时补齐共享命令的数据库关闭失败处理。范围和实跑证据见 [personal-onepux-inspection-validation.md](personal-onepux-inspection-validation.md)。

四线推进（用户要求 1/2/3/4 都推进）：PR #8 已合入 `5c40f8a`，先接通个人加密 KDBX 迁出和独立互操作；随后依次推进归档、严格网站来源匹配、持久签名团队设备目录。每批仍单独复核、CI 和 PR 合并，不把核心模块或编译成功写成原生多端验收。迁出证据见 [personal-kdbx-export-validation.md](personal-kdbx-export-validation.md)。

| 工作 | 已验证 | 下一项可开发、可验收的增量 |
| --- | --- | --- |
| 持库核心与兼容 | 双密钥、独立设备收钥、吊销后离线解密失败；Argon2id/旧 Argon2d 互操作；内置 1PUX 的原生登录/文档/附件与可逆迁出；TOTP 与密码生成核心验收；1PUX v3 只读清点及显式文件路径的匹配/缺失、共享与大小差异核对，来源审计回归通过 | 独立复核、区段/字段类型与重复标识预检、其他附件布局及完整条目/历史映射，以及真实迁移前的恢复演练 |
| 审计 | 按 session 查拒绝，写盘前筛查凭据；独立审计签名、前序摘要、可复制的签名检查点；删改与见证回滚负测 | 独立审计加密/恢复、持久日志事务、多签发端与跨设备见证，接入真实请求生命周期 |
| 成员、同步与恢复 | 同账号及多设备的文件级撤销；未实现团队目录或备份服务 | 签名成员目录和可信新鲜度；独立离线恢复材料，灾后新设备身份与新代次 |
| 远程授权 | 本地加密待办、独立会话公钥登记/签名、事务内撤销；已核实合成目标的签名决定、短有效期、事务性审计、请求替换及并发负测；合成元数据单次执行、崩溃未知和密文回执恢复 | 远程安全配对、独立决策流检查点、真实适配器和执行设备隔离；AI 只能否决 |
| 个人离线 CLI | 交互式建空库、独立保存 Secret Key、添加登录、跨进程双因子重开、列表只含 ID、标题和条目版本；按 ID 编辑标题、用户名和密码，同版本竞争只成功一次；事务内单独加密签名审计，拒绝单独截尾或替换快照；个人备份/恢复及独立历史检查点的 Linux 合成验收见本页交接 | 受控披露、生成保存、TOTP 和认证引用已接入；下一步系统解锁与独立日志见证 |
| 字段引用基础 | 纯 Go 元数据核心支持三/四分量、名称/ID、大小写及区段；个人 v1 与内置合成导入分别保留其字段身份和修订来源；已解析目标可精确校验为原生槽位/类型，拒绝旧修订、跨布局、区段错配和文档取值；未知 profile、重复键、槽位重绑、缺失修订和部分结果拒绝；OTP 配置与生成码类型分开，竞态与模糊测试通过 | 独立复核、固定 op v2 行为对照与通用导入；个人 v1 的可信事务、人工披露及 OTP 已接入；其他布局未接入 |
| 桌面、浏览器和移动 | 只有 CLI 演练 | MyGo 原生托盘、系统解锁、搜索和审批；浏览器、iOS/Android 客户端和真机验收 |
| 网关与 Web | 限仓库的 MCP stdio 工具与 Bun 提案；持久去重、带时间的状态、原会话的签名录制回执；重启重复领取不再次执行，插件换版后旧登记只读 | 跨机安全配对、真实仓库级上游委托、签名安装、第三方 OS 沙箱和 Next.js 管理界面 |
| 机器授权 | 已定 invoke 与 deliver 独立部署 | 分别签发/吊销、固定上游及交付对象，串用凭据的负测 |

MCP stdio 这一批已在 Windows 和 WSL Linux 用真实子进程验收。提交范围 `4932c8d..a0d8ab1` 的独立代码复核尚未完成；本地测试不能替代这项检查。

回执领取已通过 Windows 和 WSL 的跨进程验收；Windows 双版本实验确认旧模块只可查状态和领取已签发的结果。独立复核 `db59690..f03956a` 发现本地接收身份遗失时重试可能生成无效替代身份；`e473c4f` 修复，分别保留票据或回执的负测通过，独立复核确认关闭。升级恢复要求已有原投递标识。

KDBX 互操作已在 Windows 和 WSL Linux 使用 PyKeePass 4.2.0 验收。上一版 CLI `3218ef7` 写出的第 2 代快照由新 CLI 打开：保留设备 B 成功，被撤销的 A 失败。独立复核指出本地模块替换会破坏按版本安装 CLI，以及受保护 Notes 标记未被断言；`9d2ca2d` 修复，两项均通过独立复核。按提交安装使用本地 Git/模块代理验证，没有发布版本标签。该验收仅覆盖载荷容器，尚未完成原生条目映射。

原生条目批次在 Windows 和 WSL 用 PyKeePass 按 UUID 修改同名登录、TOTP 和附件；外部修改必须重新签名。新 CLI 迁出旧布局和新布局第 1、3 代的 1PUX 字节完全相同。独立复核发现到期等行为设置和附件内存保护位可能在重封时丢失；`fa34545` 对前者明确拒绝，后者保留并独立读回，两项均已复核关闭。其他类别、历史和真实导入未验收。

个人库 CLI 已在 Windows ConPTY 和 WSL PTY 使用新进程通过 `scripts/personal_acceptance.py`，测试数据由验收现场生成。缺少或替换任一因子会被拒；查询不重写金库；损坏事件、单独删除末条日志或替换旧快照后拒绝继续写。个人库测试及竞态检查通过。独立复核所报的终端回显窗口和目录发布持久性已在 `c5d4f52` 修复并复核关闭。Linux 使用目录同步，Windows 请求不覆盖目标的写穿移动；未实测硬件断电。尚无换机恢复、外部审计见证、系统钥匙串或个人库团队同步。

个人条目编辑已通过 Windows ConPTY 与 WSL PTY 的双进程竞争：两个编辑者读同一版本并同时提交，只有一个成功，另一个得到冲突。Go 竞态测试解密核对实际赢家的密码、另一同名条目不变、冲突事件关联赢家版本。上一版 `d294bb4` 创建的个人库可直接升级；写入新事件后旧客户端明确拒绝。独立复核指出的列表文档与赢家验收两项已在 `79e92e2` 修正并复核关闭。

当前交付为离线个人库预览与合成网关演练。正式使用仍需要独立安全评审、干净机器恢复、移动真机与逐平台 1Password 行为对照。

Cloud 恢复安全修复已提交为 `43c6732`，在 PR #1 的原 `codex/first-preview` 分支接续；main 核对为 `3901bc8d8c91c8da039fa02d83e1521746c3c5aa`。恢复验证及目标预检先于新 Secret Key，发布仍原子拒绝覆盖；LLR2 独立离线材料固定整份签名备份检查点，旧 LLR1/版本 1 明确拒绝。Linux 真实 PTY 的错误恢复码、损坏备份、已有目标、旧格式及迟到目标负测通过，完整重签历史负测通过，容量与历史段数错误已区分。实跑检查、失败测试及复核/CI 门槛详见 [recovery-validation.md](recovery-validation.md)。尚未合并，不能把本地结果计为 GitHub 通过；后续从更新 main 实现受控人工单字段披露。

恢复来源复查在 `7054bf5` 上复现 FIFO 与 FIFO 符号链接打开时阻塞，`888944e` 改为 Unix 非阻塞打开并在读前核验句柄，非普通文件明确拒绝。Linux 单测、全量 Go、个人库竞态、真实 PTY、MCP/Bun 及 Windows/macOS 交叉编译通过；正常备份文件符号链接的恢复审计正例通过。原生 Windows/macOS 特殊文件行为及独立复核仍未完成，PR #1 合并门槛继续保留。main 仍为 `3901bc8d8c91c8da039fa02d83e1521746c3c5aa`；本轮命令、失败证据和后续工作见 [recovery-file-source-validation.md](recovery-file-source-validation.md)。

字段引用核心 `0dece6d` 从最新实际 head `78ed9e5` 接续，作为外部阻塞期间不依赖存储和未合并 main 的基础增量。模块不含字段值、不认证元数据、不授予权限，也未开放人工或 Agent 原值读取。全量 Go、核心竞态、789326 次模糊执行、个人 PTY、MCP/Bun 回归及 Windows/macOS 测试包交叉编译通过；固定 op 版本、原生运行、独立复核和真实事务审计接入仍未完成。main 仍为 `3901bc8d8c91c8da039fa02d83e1521746c3c5aa`，工作分支仍是 PR #1 的 `codex/first-preview`。失败测试、实跑命令和代码 head 的具体远端检查见 [reference-validation.md](reference-validation.md)。

个人原生字段投影实际发布为 `a1b95a6`（本地已测试实现 `eaf6331`，文件树完全相同）。登录投影不复制字段原值，文档身份参与同名拒绝；真实加密库的改名/恢复投影分别对上原/新签名账本修订。全量 Go、个人/引用竞态、338048 次投影模糊输入、PTY、Bun/MCP 及 Windows/macOS 测试包交叉编译通过；生产原子事务、原生平台、独立复核和固定 op 对照仍未完成。发布时 CLI 新出现 401，已通过 GitHub 连接器带预期 head 快进原分支并同步本地提交记录。main 保持 `3901bc8d8c91c8da039fa02d83e1521746c3c5aa`，PR #1 仍未合并；远端结果、发布方式和下一项见 [personal-reference-metadata-validation.md](personal-reference-metadata-validation.md)。

合成导入引用投影 `12612b113d92fba24a813530175a20acff702b37` 从实际 head `3a0184b` 接续并推送原分支；本轮终端 Git/gh 访问已恢复。投影仅接受内置原生演练布局，保留源 `ops/otp-demo`，不沿用个人字段映射，不复制原值；真实加密快照改名/轮换后身份不变、快照签名版本改变，并核对审计与独立检查点。全量 Go、定向竞态、911 次模糊输入、个人 PTY、Bun/MCP、静态检查及 Windows/macOS 测试包交叉编译通过。main 仍是 `3901bc8d8c91c8da039fa02d83e1521746c3c5aa`，工作分支为 PR #1 的 `codex/first-preview`；新增切片与此前待复核范围均未完成独立复核，未 squash。远端精确链接、失败先行证据、未验证平台和下一项见 [fixture-reference-metadata-validation.md](fixture-reference-metadata-validation.md)。

字段槽位/类型绑定 `0970d63ae95fc5e8673da7bcd6c0ef5116b1d953` 从实际 head `c0a494f` 接续并推送原分支。两个 profile 的绑定均复用完整投影验证；之后只接受精确 ID、区段和修订，输出固定槽位及文本/密码/OTP 配置类型，不读取原值或授权。个人改名/恢复与合成快照轮换的旧目标拒绝，当前绑定对应已验签审计来源。全量 Go、定向 race、677430 次目标模糊执行、个人 PTY、MCP/Bun、静态检查，以及两个包的 Windows/macOS 测试包交叉编译通过。main 保持 `3901bc8d8c91c8da039fa02d83e1521746c3c5aa`，工作分支为 `codex/first-preview`，PR #1 仍未合并；独立复核与远端门槛未关闭。失败先行、准确检查链接、平台缺口与下一项见 [reference-binding-validation.md](reference-binding-validation.md)。

TOTP 核心 `295e8c35601941ca02c13e4afd8c203ebbb5f0a7` 从实际 head `8d5d81d` 接续并推送原分支。公开 RFC 6238 的 18 个向量、RFC 4226 的 10 个计数向量、半开时间窗口、参数拒绝、普通输出脱敏与并发测试通过；708401 次模糊执行无失败。使用独立合成强种子，经真实加密快照读回、源字段绑定及独立审计检查点验证后计算，与 RFC 输出一致，审计/序列化不含种子或码值。原内置短种子演练不改写，新核心明确拒绝；尚无产品取码或披露审计入口。全量 Go、定向 race、PTY、MCP/Bun、静态检查与 Windows/macOS 测试包交叉编译通过。main 保持 `3901bc8d8c91c8da039fa02d83e1521746c3c5aa`，工作分支为 `codex/first-preview`，PR #1 未合并；独立复核与逐平台运行未完成。准确范围、失败测试、远端检查和下一项见 [totp-validation.md](totp-validation.md)。

密码生成核心 `9d3bcb2d2c47f1e5899aa28e464ad6afc7797caa` 从实际 head `0d1cfc6` 接续并推送原分支。系统 CSPRNG、标准库无偏拒绝采样、精确整数熵校验、随机源失败零结果和敏感输出脱敏均通过；786630 次模糊执行无失败。真实合成个人库保存生成密码后可重开，签名 `item.add` 审计通过，数据库及普通报告未出现原值；该事件只证明新增条目，不冒充生成/披露事实。全量 Go、定向 race、PTY、MCP/Bun、静态检查及 Windows/macOS 测试包交叉编译通过；尚无产品生成入口、独立复核、原生平台及真实 op 对照。main 保持 `3901bc8d8c91c8da039fa02d83e1521746c3c5aa`，工作分支为 `codex/first-preview`，PR #1 未合并；具体检查、失败证据、平台边界与下一项见 [password-generation-validation.md](password-generation-validation.md)。

1PUX 只读清点 `3dc0f9fdabb9822a401af3f4d36bcba24c9df473` 从实际 head `4e0a721` 接续并推送原分支。在内存中校验 ZIP/CRC/严格 JSON，按账号/库作用域核对 ID 并输出受限计数和固定原因码；所有条目始终标记未映射，不将清点成功称为可迁移。自查新增负测修复了目录预算检查过晚、尾随数据、跨磁盘记录、目录后缀掩盖符号链接及末尾记录选择差异。全量 Go、定向 race、ZIP 256165 次/JSON 200688 次模糊执行、PTY、MCP/Bun、静态检查和 Windows/macOS 测试包交叉编译通过。真实加密演练来源的独立审计检查点核验与报告秘密扫描通过；没有新增通用迁移或产品预检审计入口。main 保持 `3901bc8d8c91c8da039fa02d83e1521746c3c5aa`，工作分支为 `codex/first-preview`，PR #1 未合并；独立复核、附件关联、原生平台及真实导出对照仍待完成，详见 [onepux-preflight-validation.md](onepux-preflight-validation.md)。

显式文件关联 `b2347ac8c0d637f653c271944232e433ce2f60f9` 从实际 head `1c191e7` 接续并推送原分支。只按 item.file.path 的归档相对路径与经 CRC/实际长度校验的文件精确匹配，不用 documentId/fileName 猜路径；报告匹配/缺失/重复引用、唯一已关联文件、未被当前显式引用覆盖的文件、缺少路径条目与大小差异。保留整体未映射状态，不据此删除文件；旧演练缺少显式路径仍未验证。全量 Go、定向 race、ZIP 650560 次/JSON 115570 次模糊执行、PTY、MCP/Bun、静态检查及 Windows/macOS 测试包交叉编译通过；来源审计/检查点与无私有值回显回归通过。main 保持 `3901bc8d8c91c8da039fa02d83e1521746c3c5aa`，工作分支为 `codex/first-preview`，PR #1 未合并；独立复核、其他附件布局、原生运行及真实导出对照未完成，详见 [onepux-file-references-validation.md](onepux-file-references-validation.md)。

区段/字段结构清点 `63cb54fde5c72834baef0fd0fafe0360f9232d61` 已接续原分支：重复名称/字段 ID 按源作用域计数，不合并；值按 JSON 形状统计，语义与迁移仍未验证。合成失败测试、包内测试、定向 race、229677 次 fuzz、来源审计/报告隐私回归与 Windows/macOS 测试包交叉编译通过；独立复核和远端门槛未满足，main 仍为 `3901bc8`。实跑命令、限制与后续 loginFields 清点见 [onepux-sections-validation.md](onepux-sections-validation.md)。

Windows CI 恢复实际运行后，`38b308d` 的 Ubuntu 成功，Windows 在个人 backup 的 ConPTY JSON 读取失败；不再沿用付款/额度阻塞结论。已用合成传输失败测试复现并在 `45f2e79` 修复子进程退出后的输出排空，`020622f` 将回归加入双平台 CI。Windows 原生运行又发现传输不发 EOF，`dd68eef` 改为完整响应加输出静默并保留截止时间；延迟输出、延迟秘密回显、不发 EOF 三项本地测试通过；原生结果与独立复核单独记录，main 未变，详见 [conpty-drain-validation.md](conpty-drain-validation.md)。

ConPTY 修正版 `dd68eefdb0dc744436403299b382b3ebfbeb1fa5` 的 [run 41943464262](https://github.com/jihuayu/locklark/actions/runs/41943464262) Ubuntu/Windows 均成功，个人终端恢复、审计及 MCP 验收通过，关闭本批真实 CI 失败。该结果不是全平台产品验收；PR #1 独立复核仍待完成，未合并 main。

PR #1 的 `f0c58e3` 已完成三个经用户授权的 Luna/max 独立代码复核：恢复与个人审计、MCP/Gateway执行回执、引用/生成/1PUX/ConPTY 基础模块，均未确认阻塞当前预览合并的可复现缺陷。审查者实跑定向单测、关键路径 race、PTY/MCP；完整 preview race 仍未完成。具体范围及命令见 [pr1-independent-review.md](pr1-independent-review.md)，本记录更新上述范围的历史“待独立复核”状态；不关闭外部密码评审、整库/决策库独立回滚见证、真实平台及全部设计验收。main 仍为 `3901bc8`，合并前须核对本交接提交的双平台检查。用户已持续授权 Luna/max 子代理复核及满足门槛后的正常 squash 合并，无需重复确认。
