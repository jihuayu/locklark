# Passkey 管理：列表、元数据与独立删除

起点：main `e2561be`（PR #44）。目标：补齐 B13.2 的跨条目多账号管理与单独删除，保持每条登录一个 Passkey 的既有存储模型；不改密钥格式，不引入每条登录多个凭据的迁移。

## 数据与协议

- 列表与 `item-get` 的 `has_passkey` 保持兼容；新增只读 `passkey` 元数据：`credential_id`、`rp_id`、`user_name`、`display_name`。它们必须由已验证的持久化 record 投影，绝不返回私钥、record JSON 或 user handle。
- `search/list/vault-search/vault-list` 增加可选布尔 `passkeys_only`，在服务端截断到 500 项之前过滤；搜索该模式下的 RP ID、凭据账号名/显示名，同时保留原 title/username 匹配。其他协议操作不得接受此字段。
- 新能力 `passkey-management-v1`。新请求 `passkey-remove`：`v,id,type,capability,item_id,revision,credential_id`，无 origin/网页参数、无私钥。credential ID 是 record 中 canonical base64url 的公开 ID，必须精确匹配。
- 成功回应 `passkey-removed`：`v,id,type,item_id,revision,credential_id`；已赢得提交而结果未知时回应 `unknown`，不得声称没有删除。拒绝为现有 `error/refused`。
- Passkey 管理请求只来自扩展自身页面，仍须当前配对能力。旧宿主不发送新字段/命令，界面明确提示升级。

## 事务、撤销与保留

删除复用 Session、MutationGate、认证快照、修订校验、密封与链接审计；增加 `item.passkey.remove` 审计动作。拒绝未知 ID/错误修订/错误 credential ID/已移到废纸篓条目/无凭据。仅将当前 item.Passkey 置空；登录、密码、备注、OTP、网址、附件、分类和分区保留。允许管理已归档但未删除的条目，原状态不变。

增加 Session 级原子 Passkey 撤销序号：只有删除目标与修订验证成功且 mutation gate 赢得提交决定后、写入持久化快照前递增。即使随后存储失败也保守撤销旧请求。pendingPasskey 在开始时捕获序号，live 检查（含响应 WriteGranted）须匹配；因此跨共享连接、仍在排队的签名/注册响应会被撤销。已经开始交付的响应不能撤回，界面不作此承诺。不增加无限增长的撤销表。

保留既有 Session 单待提交槽位：其他待审批或提交操作占据槽位时，删除可以被拒绝，须先完成或取消原操作；不抢占或放宽其授权。旧 Passkey 事务结束释放槽位后，其尚未授权交付的结果仍受上述撤销序号保护。新审计动作同时进入签名验证与历史修订回放，确保删除后的新 revision 可立即读取和重开验证。

## 界面与验收

弹窗新增 Passkey 筛选、RP/账号元数据及独立删除。删除需要明确确认，可取消；操作绑定当前 item ID、revision、credential ID 及界面代次，锁库/切换条目/编辑/关闭会撤销本地等待，迟到结果不能修改新界面。已发出提交但断线须提示结果未确认并刷新核实。删除完成刷新列表与详情，保留登录本身。

验证：真实库创建同 RP 的两个不同账户凭据；列表可区分；取消不改数据；删除一个后登录条目和非 Passkey 内容保留，该 credential 不再可用，另一个仍能完成签名验证；重连/重开持久化一致。定向 Go/JS 回归覆盖陈旧修订、错误 selector、锁库/取消/提交竞争、跨连接撤销、元数据无私钥、网页来源拒绝和迟到界面响应。最终仍以实际运行范围和精确 head 的六项 CI 为准。
