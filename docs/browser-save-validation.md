# 浏览器保存与更新验收

最终 [PR #27](https://github.com/jihuayu/locklark/pull/27) 已合入 main `c9d4a5d284ddc15aa58953896e9b5773873bb1e6`。精确head `8d63fd6bce7068e8a7ae8968eb48425613026345` 的 [CI 42089993817](https://github.com/jihuayu/locklark/actions/runs/42089993817) Ubuntu、Windows、macOS、Web四项全通过；Web包含两浏览器真实native保存链路。下文“待CI/待合并”为该批各阶段历史状态，已由本段关闭。

基线 main `0f38177eb1059121d04e94fb96d264126688573f`，分支 `codex/browser-save-update`。此前浏览器配对/填充 PR #26 精确 head `6c649d9` 的四项 CI 与独立验收已通过并合入。本批沿用用户指定分工：主代理架构/功能设计与独立验收，Sol xhigh 实现，Luna max 独立 review。

[架构及验收约定](browser-save-design.md) 已经 Luna/max 预审，最终实现及修复也完成独立增量 review。主代理最终 Chromium/Firefox 完整 GUI 验收通过；精确提交的远端 CI 和合并状态以 PR 为准。本切片不代表全部产品完成。

## 失败先行

`/tmp/locklark-validation/browser-save-red-core.log` 记录新核心保存 API 缺失而导致契约测试编译失败；新增核心后第一轮对应测试通过（`browser-save-green-core.log`），后续协议、并发、错误与整体验收尚待完成。

`browser-save-red-firefox-control.log` 记录真实 Firefox 临时扩展打开 popup 后缺少保存入口而失败，阶段为 `save-new control`。该失败证明旧产品没有功能入口，不代表浏览器保存协议或安全负测已经验证。合成目录 `locklark-firefox-native-Et433l` 保持私有，因素不提交。

## 验收门槛

个人事务与审计回放、gate和锁库/取消竞态、严格输入与nonce、后台状态机、真实Chrome/Firefox保存/更新和无变更负测、主代理独立验收、Luna最终review及精确head CI按架构矩阵分别记录如下。硬件系统解锁、Safari/手机、TOTP/Passkey、完整迁移、团队远端同步等仍另列，不因本批推进而宣称完成。


## 增量 review 与第一轮回归

Luna/max 在个人核心增量审阅中发现：已落盘拒绝审计遇到DB close失败仍被报告为明确拒绝；pre-gate错误与释放可能留下可复用gate；可变payload的清理契约不明确。先行失败记录 `browser-save-red-core-review.log`，修复后 `browser-save-green-core-review.log` 及Luna独立 `TestBrowserSave` 通过。现在保存入口接管并清理两个可变缓冲，释放取消pending gate、注册和Touch核对期限，已持久化的拒绝close失败归unknown。不可变string和浏览器内部复制不能据此宣称物理擦除。整树review与race结论仍待最终记录。

主代理架构抽查还要求修复宿主deadline与worker双终态回复、原生Reject检查与CAS间的竞态，以及无匹配context时save-new漏掉窗口切换取消。具体实现与回归继续由Sol负责；不因指出问题就声称已验收。

第一轮扩展状态机18项Node测试通过（`browser-save-node.log`）。真实Chromium与Firefox DOM测试分别通过（`browser-save-dom-chromium-v1.log`、`browser-save-dom-firefox-v1.log`）：静态采集不写字段、不触发输入或提交事件，中文/非BMP字符、UTF-8字节边界、孤surrogate、空用户名/空密码和过期行为明确；隐藏/禁用/只读/歧义、跨源action/base/外部关联提交按钮和iframe均拒绝。它们不是完整native保存链路的替代证据。


## v1 完整真实链路

Sol 使用版本化原生二进制 `/tmp/locklark-tools/browser-save-v1/` 和该轮冻结的扩展dist，分别通过真实Firefox与Chromium的完整流程（`browser-save-firefox-v1-gui.log`、`browser-save-chromium-v1-gui.log`）。私有合成目录分别为 `locklark-firefox-native-IeVgng`、`locklark-browser-acceptance-Tgs4x8`。保留原填充四场景，新增真实保存后按新ID回填、同ID更新后回填新值，中文/非BMP字段精确一致；待批准期间修改页面字段不改变已经捕获的值。新建与更新各自的原生拒绝、导航、锁库均保持snapshot、条目修订和保存事件数不变。原库观察通过只读bbolt一致快照进行，读取/审计仅在私有副本上执行。

验收结束关闭驱动后，controller输出、浏览器console、持久化驱动日志与诊断JSON/摘要均扫描全部合成canary，无值回显。工具输入合成因素与受控页面值始终留在私有fixture中，不上传或提交。v1不是最终树验收：扩展unknown提示在超时/手动断开及链式失效后的保留仍需v2补丁、独立复跑及最终CI。

`browser-save-host-race.log` 记录宿主定向race通过（47.443秒），覆盖一请求单终态、原生晚拒绝归unknown及无View轮询的到期清理。`browser-save-core-complete.log` 记录追加的逐字段保留、拒绝snapshot/修订不变、备份恢复与ArchivedAudit重读、取消赢时拒绝审计也不写等回归通过。更广的回归与最终审阅仍需随后记录。

## v2 回归与独立 GUI 发现

`browser-save-go-all.log` 全仓 Go 测试通过，包含真实 Bun 与 PyKeePass 互操作；个人核心定向 race（`browser-save-core-race.log`，172.606秒）、宿主最终定向 race（`browser-save-host-race-v2-final.log`，123.600秒）和 vet 通过。扩展 unknown 状态在导航、锁定、断开、超时与协议错误链中的保留有先行失败证据 `browser-save-red-node-clear.log`，最终 Node 状态机 30/30 通过（`browser-save-node-v2-final.log`）。这些结果覆盖对应 v2 代码，不能预先充作后续补丁的结果。

Luna 最后两项发现也有先行失败：有效空标题登录被错误当作没有候选（`browser-save-empty-title-red.log`）；并发原生批准可能重复发挑战（`browser-save-native-double-approve-red.log`）。分别以独立 found 状态和第二次状态核验修复；空标题保留原值，仅显示“（无标题）”，并发批准只有一次确定标题和挑战。Luna 对 v2 最终树复核未留下阻塞发现。

冻结 `/tmp/locklark-tools/browser-save-v2/` 后，Sol 的真实 Firefox 完整链路通过（`browser-save-firefox-v2-gui.log`，私有目录 `locklark-firefox-native-0Cz6f6`）。主代理独立 Chromium/WenQuanYi/Xvfb 验收增加了真实 popup 候选按钮跨轮询焦点保持检查，该项通过，但全链路在 `save-update:reject` 失败（`browser-save-chromium-v2-parent.log`，私有目录 `locklark-browser-acceptance-NbFBd4`）。该失败没有忽略或计为通过。

随后源代码核查确认 popup 在候选刷新 RPC 未返回时仍允许点击旧候选：`busy` 尚未同步反映到真实按钮，存在刷新与更新并发的实际产品操作窗口。正在补充确定性失败测试、同步禁用及响应顺序修复，再做增量独立审阅和两浏览器最终完整验收。此时尚未创建本批 PR，精确 head CI 和合并仍待完成。

主代理以真实 Chromium DOM 加载原版 popup.js、仅延迟测试 runtime 响应，确定性复现了“刷新必须立即禁用”断言失败（`browser-save-popup-parent-red.log`）；这独立于完整 GUI 的时序，证明产品需要修复。v2 Firefox 的实际驱动故障注入在受控页面已收到 Unicode 合成登录参数之后触发，预期退出失败；controller、geckodriver 持久日志及 JSON 摘要扫描无合成值或因素（`browser-save-firefox-v2-driver-failure.log`，私有目录 `locklark-firefox-native-h6hYaX`）。因素从未作为网页参数传入。

## v3 popup 修复

Sol 增加加载真实 popup.js 的确定性 deferred-runtime 测试，先得到同步禁用、迟到轮询覆盖、旧动作多发请求三项失败（`browser-save-popup-v3-red.log`），再修复。UI 在发送业务 RPC 前同步应用 busy，保持到最终 state 回来；disconnect 可以中断，旧动作响应/失败/收尾均失效。递增响应序号阻止反序轮询覆盖新状态，原生 pending 仍通过周期 state 更新；候选不变时继续保留 DOM 节点与键盘焦点。

主代理在真实 Chromium 和 Firefox DOM 独立复跑同一外部脚本，验证同步禁用、已排队旧点击拒绝、同代次轮询反序、焦点保持及仅发送最新修订，均通过（`browser-save-popup-parent-green.log`）。完整扩展 → 原生 → 加密库链路和最终增量 review 仍需 v3 冻结后记录；DOM 测试不替代该验收。

## 取消分类的自足性复核

主代理抽查发现 `saveMessage(cancel-save)` 本地分支仍先读 CommitWon 再调用 Cancel 且未使用其返回值。正常串行 wire 的 `registerRequest` 已先对匹配目标执行 CAS，因而不能把这一静态发现直接说成已证实的生产 wire 竞态；但局部处理器不应依赖隐含前置仲裁来正确分类结果。要求改为先尝试 Cancel，再根据终态决定 cancelled/unknown，与原生 RejectSave 一致，并由 Luna 核对其他取消入口。该增量采用新版本化 artifact，保留 v3 不覆盖；最终 GUI 验收在新 artifact 完成。

该自足性加固及局部两个 gate winner 的回归已完成；没有把局部静态发现虚构成端到端失败先行。`browser-save-cancel-v4-race.log` 定向 race 通过（46.428秒），Luna 对该分支、注册取消、原生拒绝、期限和失效入口复核通过；也独立确认正常读循环的前置 CAS。Popup 最终 Node 35/35 与 Luna 增量 review 通过。

## v4 最终固定产物验收

`browser-save-v4-artifacts.sha256` 固定 `/tmp/locklark-tools/browser-save-v4/` 三个原生 binary 及扩展源/两种 dist。验收脚本将 enabled 条件改为明确 `=== false`，缺失控件不能误判成可用；刷新后按认证库观察得到的最新 ID/修订寻找真实 row，三个不变断言（snapshot、条目/修订、保存事件）均保留，增加固定细阶段定位。

主代理独立 Chromium/WenQuanYi/Xvfb 完整通过（`browser-save-chromium-v4-parent.log`，私有目录 `locklark-browser-acceptance-00sKvk`）：实际 popup 跨轮询焦点保持、原填充四场景、新建/更新后真实回填与点击时快照、两种保存的拒绝/导航/锁库均通过；日志/持久诊断无合成秘密。安全元数据原生截图已人工检查。Firefox 最终重跑及故障诊断继续记录，不以先前版本通过代替本版本。

Firefox 的 v4 首轮在解锁/配对阶段出现驱动失败（`browser-save-firefox-v4-gui.log`，私有目录 `locklark-firefox-native-0aNRbq`）。补充只输出白名单原因和固定动作编号的诊断后，主代理在另一显示环境独立复现（`browser-save-firefox-v4-parent.log`，`locklark-firefox-native-bnj5qq`）：失败明确为 `native-pair` 的 `a11y-query`，随后的只读检查已找到唯一可用配对控件。原脚本的 ready 循环虽有10秒截止，却在瞬态 AT-SPI 查询错误时直接退出；修复限定为同一截止内重读该查询，不重试点击、不放宽唯一性/可用性和任何库状态断言。修复及最终复跑继续记录。`initialBridgeDisabled` 只反映进程初始环境，不能误称 native 未执行运行时清除；控件已通过 AT-SPI 可见。

工具修复先得到一次瞬态与持续查询失败两项 red（`browser-save-a11y-query-red.log`），再通过4项回归（`browser-save-a11y-query-green.log`），主代理也独立复跑通过。专用异常仅在原 AT-SPI GError 查询路径产生；歧义、结构限额等错误不重试，XTest 输入动作不重放，CI已接入这些纯Python测试。Luna 最终工具增量 review 无阻塞；Firefox 完整复跑已经越过此前配对失败点，最终结果随后记录。

Chromium v4 的实际 `page-arguments` 驱动故障验收通过：预期失败，38个持久化artifact扫描无合成值/因素（`browser-save-chromium-v4-driver-failure.log`，私有目录 `locklark-browser-acceptance-NJTNAI`）。测试wrapper最初误用v2文件名，已保留原字节并纠正本轮文件名；没有覆盖此前Firefox v2证据，后续wrapper显式版本且拒绝覆写。

主代理最终 Firefox/WenQuanYi/Xvfb 完整通过（`browser-save-firefox-v4-parent-final.log`，私有目录 `locklark-firefox-native-B0irEy`，退出0）：原填充正负流程、新建/更新后真实回填、点击时字段快照、两种操作各自拒绝/导航/锁库后的三个不变断言均通过；controller、驱动持久日志、console和JSON诊断扫描无合成值。用户native manifest已按身份检查清理，产物哈希再次核对一致。本结果关闭上述原生配对阶段的工具失败，未通过无限重试或重复批准动作掩盖。

最终源码还包含一个 Luna 非阻塞工具维护项：AT-SPI snapshot 首段若已经 ref 一个窗口后另一查询失败，异常路径可进一步清理该引用；每次外部输入进程有界且终止会释放资源，不影响批准/否决和库不变验收。已安排下一原生桌面工具切片处理，不称为产品安全阻塞。

最后的 Firefox v4 实际驱动故障验收也通过（`browser-save-firefox-v4-driver-failure.log`，`locklark-firefox-native-X7eJYS`）：受控页面收到参数后固定阶段预期退出1，controller、geckodriver日志和JSON摘要3个artifact扫描无合成值/因素，主代理独立重跑扫描通过。manifest再次确认清理，未覆盖v2日志。最终本地门槛和Luna review已满足；精确head的四项远端CI仍须通过，才能正常squash合并。
