# 认证的 1PUX 登录导入

本文记录最初 `login-v1` 批次。后续 `login-notes-v2` 新增登录纯文本备注并更新计划绑定域，保留原来源身份；当前范围与升级证据见[登录备注验收](login-notes-validation.md)。下述 v1 拒绝备注属于当时的历史行为。

桌面“导入与导出”已接入同一认证、计划、摘要和原子提交链路，并默认使用 `FullProfileV2` 完整类别（可关闭回到登录及备注 profile）。1Password 8 `.1pux` 可直接选择；1Password 7 `.opvault`/`.1pif` 不支持。完整类别的实际字段/附件/历史边界仍以本文件和对应测试为准，不能从“桌面有入口”推断为无损迁移。

当前容量上限已从早期 8 MiB/256 条提高到归档 64 MiB、展开 128 MiB、单次导入 1024 条、vault 载荷 16 MiB；新增 300 条完整类别导入测试，以及 36 MiB 归档（超过旧 32 MiB 上限）的映射测试。提高上限仍是有界拒绝，不是无限制或无损承诺。

基线 main `d932f51`，分支 `codex/onepux-login-import`。本批是七条持续目标中的第一个导入闭环，尚不覆盖完整类别/字段/附件/历史迁移。

先运行 `personal plan-import-1pux --file owner.ll --source source.1pux`，双因素和 PLAN 确认后获得 `report.source_digest`。再运行 `personal import-1pux --file owner.ll --source source.1pux --digest PLAN_DIGEST`，双因素和 SAVE 确认后原子写入。计划只写审计、不写条目。导入重新读取有界普通文件，在认证、历史和快照验证之后核对绑定源文件逐字节内容的 HMAC-SHA256 计划标记；摘要不同就拒绝，不能使用旧计划导入新文件。计划密钥从本库审计加密密钥经独立用途 HKDF 派生；不公开明文归档的无密钥摘要，标记不可跨库/恢复后串用。摘要只绑定来源字节，不认证 1Password 来源，也不证明本地整库没有被回滚。

`login-v1` 只接受单账户/单库、类别 001、active/archived、非空标题、明确 username/password designation 及 T/P 类型、字符串值（空密码保留）、一个符合当前 HTTPS profile 的网址。重复 designation、未知或不支持字段、非空备注/区段/历史/标签/收藏、文档与附件、不同网址和跨库扁平化整批拒绝。既有 Inspect 始终是未映射清点，不会凭清点成功授予导入。

每项 ID 对账户 UUID、库 UUID 和条目 UUID 的长度无歧义 JSON 序列加域分隔 SHA256 后取 128 bit；同源重放与既有 ID 冲突均拒绝，重复标题保留。合并后的条目数与载荷使用原生同一限额，先全部校验再 seal 一次。每项 `item.import` 建立修订并绑定报告摘要，最终 `migration.import.1pux` 作为批次回执，全部和密文在一个事务提交。源读取/解析/冲突拒绝只有固定类别；报告只含 profile、源摘要、计数，审计不记录源路径、名称或字段值。

原始 export.attributes、账户/库属性和条目对象规范化 JSON 写入可选 `ImportSource`，经 KDBX protected 字段 `Locklark.ImportSource` 存储并由备份和加密导出保留。它是不可执行的来源记录，编辑当前密码不会改写来源中的旧密码。导入和导出确认都明确提示这个行为；不能将来源记录误称为已经实现可浏览的密码历史。无该字段时 JSON omitempty 保持旧备份签名；旧客户端遇到新字段或新审计动作会明确拒绝。

失败先行日志 `/tmp/locklark-validation/import-red.log` 记录缺少映射 API。测试覆盖作用域身份、重复标题/归档/空值、源记录读回、混合不支持项整批拒绝、错因素/坏历史不读来源、计划不改库、来源变化、提交回滚、并发重复拒绝、备份恢复和审计不泄露值。`scripts/import_acceptance.py` 用 Linux PTY/Windows ConPTY 驱动 CLI，并用 PyKeePass 独立核对当前字段与来源 JSON。具体命令、最终 head、Luna/max 复核和双平台 CI 见本批 PR。

Luna/max 审阅复现了标题中的 C1/Cf 字符可伪造终端显示，失败记录 `import-title-red.log`；导入标题现拒绝控制/格式字符，密码值不受此显示规则限制。最终复核与远端检查记录在 PR。
