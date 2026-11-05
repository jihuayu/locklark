# 个人登录回收站与恢复

基线 main `65b3f3d0decb3fc503be194c657af83bbce0e9f5`，分支 `codex/personal-trash`。本批补齐日常可恢复删除，保留永久删除、自动清空/保留期和安全擦除为未实现项。

`personal trash-login|restore-login --file PATH --id ID --revision REV` 要求终端双因素、显示动作/目标/修订以及 SAVE 确认。移入后仍保留加密条目和稳定 ID；恢复回到移入之前的 active/archived 状态，每次成功操作产生新修订。两项并发请求持同一修订只有一项成功；冲突和重复操作提交固定审计结果，不改条目/修订。审计 action 为 `item.trash` / `item.untrash`，与灾后恢复的 `item.restore` 分开。

`list --state trashed` 显示回收站，`--state all` 包含全部状态；只有 trashed 行含 `restore_state=active|archived`。默认列表、引用建议和网站匹配排除回收站。引用解析仍保留全部身份，因此同名回收站项不会使原本有歧义的引用突然指向另一项。

在认证和完整历史验证之后，先核 ID/当前修订，再核回收站状态。trashed 条目的字段编辑、归档/取消归档、密码重新生成、用户名/密码披露、OTP 生成及引用披露均记录固定 `trashed` 拒绝；恢复前不释放字段、不解析保存的 OTP、不调用密码生成器。语法有效的目标上，无效字段值和生成长度不会掩盖版本冲突或回收站拒绝。字段值/再生成策略校验因此移到事务内，仍在实际写值/生成熵之前执行；活动条目的无效值失败回滚。命令结构、字段名、ID/修订语法和整数写法仍在解锁前验证。

原生 Item 新增 `State=trashed`，`PreviousState` 只允许为空（原 active）或 archived，且非空只能配合 trashed。KDBX 以 `Locklark.State` / 可选 `Locklark.PreviousState=archived` 保留；拒绝空的显式 PreviousState、未知枚举、错误保护位或非法状态组合。JSON 新字段使用 omitempty，旧备份的序列化签名不变。

备份和显式授权的便携 KDBX 导出包含回收站项，保留原状态与数据；导出确认提示明确告知包含归档/回收站，其他密码管理器未必将自定义字段当作回收站。灾后恢复保留回收站状态但建立新修订，之后可恢复条目到原 active/archived 状态。回收站不构成密码撤销，也不能抹除先前复制的数据、历史备份或已导出副本；无自动清空、永久清除或抹盘保证。

失败先行日志 `/tmp/locklark-validation/trash-red.log`：缺少回收站 API/状态字段。Luna/max 预审发现事务前值校验会掩盖冲突/trashed 拒绝，已调整并补 `TestTrashAndRevisionPrecedeInvalidValues`。因此两项既有测试的注入/期望随接口边界更新：OTP 的内部 edit 不再绕过语义校验，legacy 无效 seed 通过私有原生 item.add 注入并明确断言 `totp.ErrInvalid`；CLI 的再生成范围检查推迟，非规范整数仍提前拒绝。

测试覆盖两种原状态、重复操作、全部敏感操作拒绝且零输出、无效输入优先级、无熵调用、审计结果白名单和字段泄露扫描、并发单赢家、提交回滚、引用歧义、备份恢复，以及原生字段和 PyKeePass 独立迁出核对。`scripts/trash_acceptance.py` 已在 Linux PTY 跑通；CI 在 Linux PTY/Windows ConPTY 执行。以 main `65b3f3d` 构建的旧 CLI 在 Linux 验证：旧备份→新版恢复成功，新回收站库/备份→旧版明确拒绝。未实测硬件掉电或 Windows 旧版二进制对照。

实跑检查：定向及完整 Go 测试、定向 race、vet/模块校验、PTY + PyKeePass、旧版正反向兼容；最终 Luna/max 复核、具体 head 与双平台 CI 证据记录在本批 PR。
