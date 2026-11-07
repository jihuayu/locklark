# Passkey Signal APIs 验收

日期：2026-11-07；基于已合并 main 9cbc34c（PR #48）的 #39 增量。主代理设计并独立执行，外部 DeepSeek workers 实现和静态复核；协议和原子性见[设计](passkey-signals-design.md)。

## 实际组件回归

- 扩展全量 293/293 通过、0 失败或跳过。涵盖原生方法是否存在、原 this/参数/Promise 身份、同步异常与拒绝、调用后同步快照、防止后续参数修改、严格字段/大小、同窗口/来源/可见性、真实 sender、epoch 与槽位保护。日志 browser-completion-node-frozen.log。
- 主代理独立 personal Signal race 通过（101.046 秒），包括真实有效的 50/51 条边界、只读快照与历史不变、全部行 CAS、伪造 accepted 保留项不得删除、重开/完整历史回放、名称修改后独立软件签名、无关字段保留。此记录在接入 PR #47/#48 前执行；整合后由统一 E2E 再跑相关 personal 契约。
- 整合后的 browserhost Signal race 通过（46.567 秒），含连接互斥锁被其他只读操作占用时立即取消、旧 ID 不取消新建议、数据库阻塞时取消先赢不提交、锁库、迟到提交只在 native 报 UNKNOWN、精确 ACK 且无第二个页面结果。日志 passkey-signal-final-native-race.log。
- 最终统一 E2E 的 T2_F2_10 实际执行 Go/Node 契约，要求非零匹配及足够数量；13 项 background 契约使用 signal: 前缀。第一轮适配器因名字筛选只选中 1/13 而失败，已修正并重跑整套；失败 browser-completion-f2-final.* 保留，最终以 browser-completion-e2e-final.* 为准。
- 外部独立复核仅计静态证据，不称独立密码学审计。它的“标准字段应为 ArrayBuffer”与“快照晚于 Promise 完成”推断已核对标准和动态回归并撤回：标准信号 ID 为 Base64URLString；实现先调用原方法，再同步快照，fulfilled 后才发送。

## 真实浏览器与原生确认

主代理脚本 scripts/browser_passkey_signal_acceptance.mjs 只用标准网页 API、普通扩展界面及物理 native 点击，不增加产品测试接口、不在运行时改库或注入批准结果。完整 Chromium 与独立 Edge 均通过；日志 browser-completion-chromium-full.log、browser-completion-edge-full.log。

1. 原生创建同一 user ID 的两条新凭据；网页信号原 Promise 先正常返回 void，原生 owner 随后才审阅。
2. CurrentUserDetails 先取消且不变，再确认同时修改两条公开名称；原登录字段仍保留，第二把原私钥继续完成 RP 签名验证。
3. AllAcceptedCredentials 保留列出的第二凭据，只移除第一条的 Passkey；UnknownCredential 对不存在 ID 仍返回原 void，不改变库；再经确认移除第二凭据。
4. 两条登录记录仍在，原来另一个用户的凭据仍能签名。页面没有本地是否存在、修改数量或提交结果。
5. 两账号实际 GUI 曾发现 Cancel 被挤出可视区域；已改为有界可滚动列表，Confirm/Cancel 保持列表外同一行。旧失败 passkey-signal-chromium-1/2.log 保留，修正后第三轮及最终两浏览器完整组合均通过。

最终完整运行配置独立 @simplewebauthn/server 14.0.3（单独目录、ignore-scripts 安装），并核对 origin/challenge/RP/账户/UP/UV/签名。日志中的成功标志由断言产生，不把截图或点击本身计为签名成功。Firefox 缺失的原 Signal 方法保持缺失，不伪造支持；Firefox 完整回归不作为 Signal 支持证明。

日志目录为 /workspace/issue-completion-tasks。合成 vault、身份因素和浏览器私有资料不作为发布附件。真实硬件 UV、跨设备同步及商店分发仍见[综合验收](browser-completion-validation.md)。
