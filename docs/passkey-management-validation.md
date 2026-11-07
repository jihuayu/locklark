# Passkey 管理验收

日期：2026-11-07。起点为已合并 [PR #44](https://github.com/jihuayu/locklark/pull/44) 的 `main` `e2561be1f8070f9539433412bc7ac635b965bd5f`；分支 `codex/passkey-management`。协议、事务和并发边界见[设计](passkey-management-design.md)。主代理设计并独立验收，实际外部 DeepSeek workers 实现 Go/扩展并并行调研 CLI；只读复核另行运行。

## 实现范围

- 弹窗 Passkey 筛选和 RP/账号/显示名；宿主在 500 项截断前筛选，元数据来自已验证记录，只包含四个公开字段。
- 独立删除需要明确确认，取消不发送删除；删除绑定条目、修订和 credential ID，保留登录、密码、备注、OTP、网址、附件、分区及归档状态。
- 删除与签名审计、加密快照同事务，重开可正常验证历史并读取新修订。错误 selector、旧修订、废纸篓、锁库和取消均拒绝。
- 保留 Session 单待提交槽位；待审批操作会阻止删除。旧事务释放槽位后，跨共享连接排队的 Passkey 响应受 Session 撤销序号保护；已经开始写出的响应无法撤回。
- 旧宿主明确提示升级。超时/断线或提交后结果未知时提示刷新核实，并禁用旧修订的再次删除；迟到操作不能覆盖新详情、锁库或导航后的界面。

## 真实浏览器证据

三种浏览器均实际操作扩展控件和原生因子确认，在受控 HTTPS 网站调用 `navigator.credentials`；没有通过特权测试消息执行管理变更。公开数据的只读观察器用于核对持久化结果。签名以 Node 加密库验证；最终 CI 另外使用既有 `@simplewebauthn/server` 验证器。

| 浏览器 | 实际运行 |
| --- | --- |
| Chromium | `/workspace/passkey-management-chromium-1.log`，退出 0。双账号、元数据、编辑密码/备注、取消后原凭据签名、删除后登录和字段保留、旧凭据不可用、另一账号签名、重连后的列表和签名均通过。 |
| Firefox | `/workspace/passkey-management-firefox-2.log`，退出 0。相同管理旅程通过，包含既有创建/断言/取消/浏览器回退；为 Passkey-only 验收，不冒充本次重跑了完整填充/保存/OTP。 |
| Edge | `/workspace/passkey-management-edge-1.log`，退出 0。独立 Edge 157 上同一管理旅程通过，包含快捷配对、自动登录及 Passkey 基础流程。 |

Firefox 首轮 `/workspace/passkey-management-firefox-1.log` 在编辑步骤失败：测试驱动把键盘焦点切回主窗口，关闭了扩展弹窗。驱动改为先检查弹窗实际聚焦输入框，再保持该焦点发送真实 XTest 键盘事件；没有直接修改输入值或放宽产品批准。第二轮完整管理旅程通过。管理/揭示秘密阶段禁止截图，控制器和持久诊断仍执行合成秘密扫描。

## 组件与 E2E

定向 `go test -race ./internal/personal ./internal/browserhost -run 'Test(RemovePasskey|PasskeyPendingApproval|PasskeyEpoch)' -count=1` 独立通过：personal 33.255 秒、browserhost 12.848 秒。worker 全量 Go 三包通过：passkey 0.004 秒、personal 235.986 秒、browserhost 55.941 秒（日志 `/tmp/passkey-full.log`）。主代理全仓编译探针与 `go vet ./...` 通过；编译探针不冒充全仓测试。原生控制器 82 项通过；E2E 检测回归 46 项通过，包含仅一端支持管理时不能误判完整能力。

主代理重新构建后执行全量 E2E：208 项、172 通过、36 pending、0 失败，136.263 秒，报告 `/workspace/passkey-management-e2e-final.json`。其中 functional 149 项（130 通过/19 pending）、capability_probe 45 项（28/17）、component_contract 14 项全部通过。未把既有 pending 改成无条件成功。最后缓存竞态修复后，主代理独立运行全部扩展测试：186 通过、0 失败、0 跳过，日志 `/workspace/passkey-node-independent-cache-final.log`。

两轮静态 DeepSeek 复核分别检查扩展状态与 Go 删除事务。扩展复核指出未知删除结果可重复操作旧修订，已修复并覆盖回归；其关于安全 DTO 应包含 wire `v/type` 的建议不适用，后台已验证 wire，弹窗接收的是三个公开结果字段。Go 复核未证明所审查事务路径存在阻塞缺陷；其部分并发担忧在核对 `Handle` 持锁及 writer grant 后撤回。复核未覆盖全部代码，也未自行跑测试。

主代理另外发现后台搜索响应乱序可污染共享列表缓存：旧的全部条目搜索晚于 Passkey 搜索返回时，后续状态刷新会读到旧列表。已增加搜索代次及会话/能力绑定；锁库和成功变更使旧搜索失效。回归实际重排原生回复，并检查删除或锁库后的迟到结果不能恢复旧凭据元数据。每次搜索仍由宿主过滤，不用客户端筛掉截断页来掩盖问题。

E2E 新增两个稳定 ID：`T1_F2_07` 实跑元数据/严格协议/截断前筛选的 Go 与 Node 契约；`T2_F2_07` 实跑字段保留、事务忙拒绝、排队响应撤销、确认取消和未知结果。均标为 `component_contract`，不把组件测试写成完整浏览器旅程。既有 206 个 ID 保留，真正缺失的 CLI 客户端/跨功能流程仍 pending。

最终合并仍须当前精确 head 的六项 CI 成功；上述本地证据不能代替远端检查。

## 仍未完成

每条登录仍仅保存一个 Passkey；同网站多个账号通过不同登录条目管理。本批未做同一登录多个 credential 的模型迁移、完整 conditional 账号列表、Safari、真实系统生物识别、全部平台浏览器组合、参考产品逐任务对照或商店发布。删除本地凭据不会自动撤销网站登记的凭据。

CLI 调研确认桌面 broker 服务端和低层请求函数存在，但正式 `cli run` 尚未调用它。当前 broker 响应直接返回字段值，缺少执行档案、程序/参数/工作目录、请求 nonce 与租约期限等完整绑定；不能仅接通返回值就宣称安全闭环。下一批应先设计并实现绑定执行意图的客户端/租约，再验证锁库撤销、人工批准和超时回退。F17 的 14 项 pending 继续保留。
