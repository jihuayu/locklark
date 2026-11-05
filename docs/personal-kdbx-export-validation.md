# 个人加密 KDBX 迁出

从 main `5c40f8a8c0a535ef5567cbd40189d931982cc4d5` 开 `codex/personal-kdbx-export`。这是四线推进中迁移的第一批：提供可由独立密码管理工具打开的加密退出路径，不能把它称为通用 1PUX 导入完成。

`personal export-kdbx --file owner.ll --out NEW.kdbx` 要求交互双因素、两次输入独立导出密码和 SAVE 确认。密码下限为 12 个 Unicode 字符、上限 1024 字节，拒绝全空白和无效 UTF-8；长度要求不证明密码熵。KDBX 4.1 使用 Argon2id，64 MiB、3 次迭代。当前原生标题、ID、类型、用户名、密码、OTP 和文档附件完整写入；无内部元数据条目、账户钥匙、设备钥匙、审计、恢复材料或 Agent 授权。

生成密文与 `vault.export.kdbx` / `intent` 在认证事务中执行；提交和数据库关闭后才创建同目录临时文件、写入、同步、关闭并原子发布。使用既有 Unix hard link / Windows no-replace write-through move，不覆盖目标。Unix 临时文件模式 0600；Windows 继承目标目录 ACL，不声称 0600 等价于 Windows 用户隔离。应选择自己控制的目录。

发布失败保留意图，统一错误不包含路径/密码。目录同步失败可能已存在完整目标文件，因此错误明确“输出可能存在”；不能把意图当已交付。临时文件正常退出时清理，进程被强制终止可能遗留加密临时文件。原库不变，导出不替代包含账户审计的独立恢复备份；明文字符串副本不保证可靠擦除。

失败先行日志 `/tmp/locklark-validation/export-red.log`：缺少 ExportKDBX/导出 API。合成测试覆盖错误因素、回滚零结果、已存在目标不覆盖、发布失败意图保留、备份恢复保留意图；独立 PyKeePass 验证精确 KDF 参数、密码-only 解锁及错误密码拒绝、Unicode/重复标题、空字段、OTP、原始附件及保护标记。真实 PTY/ConPTY 验证确认/取消、加密导出、独立重开和无值回执。全仓 Go、定向 race、vet/模块和最终双平台 CI、Luna/max 复核结果记录在 PR。
