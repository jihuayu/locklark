# 个人条目归档

基线 main `1c583303c9d374a3c4409f894dac4a707ee0841b`（加密迁出 PR #9 已经 Luna/max 与双平台 CI 后合并）。本批 `codex/personal-archive` 实现登录条目归档/取消归档和默认发现过滤。

- `personal archive-login|unarchive-login --file PATH --id ID --revision REV`：交互双因素和 SAVE 确认，稳定 ID + 当前修订检查。状态变化、加密快照和签名审计在同一事务提交；旧修订冲突、重复状态分别记为 conflict / already-archived / already-active，不改变条目修订。
- `personal list --file PATH [--state active|archived|all]` 默认 active，返回状态、标题、ID、修订，不返回字段值。`references` 只推荐 active；引用解析仍保留归档条目的身份用于重复标题歧义检查。归档不是权限撤销；显式 ID/引用加最新修订仍可受控读取或编辑。
- 原生 KDBX 可选字段 `Locklark.State=archived`，active 以字段缺省表示。拒绝其他枚举、空的显式字段或不正确保护位。备份 JSON 的 State 使用 omitempty，保持旧备份的序列化签名；包含新状态的备份不能由旧实现静默降级。
- 备份/恢复保留状态并重新建立修订；便携 KDBX 迁出保留自定义状态。但第三方密码管理器未必把此自定义字段当作其自己的归档功能。

失败先行：`/tmp/locklark-validation/archive-red.log` 记录缺少生命周期 API。定向测试覆盖 CAS 并发单赢家、状态/修订、重复与冲突审计、引用歧义、明确读取、恢复、事务回滚以及已签事件 schema；PyKeePass 独立检查迁出的状态。完整 Go、定向 race、vet/模块检查及最终双平台 CI 记录在 PR。

`python3 scripts/archive_acceptance.py /tmp/locklark-tools/locklark /tmp/locklark-tools/locklark-before-lifecycle` 已实跑：真实 PTY 确认/取消、状态列表、引用建议、冲突、恢复、审计；旧 CLI 由 main `5c40f8a` 构建，明确拒绝归档库读取及其备份恢复，不发新 Secret Key。CI 在 Linux PTY 和 Windows ConPTY 执行当前实现终端流程；旧二进制负测仅本地 Linux 实跑。

不包含删除/回收站、收藏/标签、完整类别和跨库移动；这些仍保留在总体目标中。

Luna/max 核心审阅无阻塞问题，反馈的顶层帮助与确认目标缺失已补齐：确认前显示归档/取消归档动作、稳定 ID 和修订，说明不删除条目。本地完整 Go、race、vet/模块及真实终端验收通过；最终独立复核和双平台检查链接见 PR #10。
