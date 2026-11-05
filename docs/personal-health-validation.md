# 本地密码体检

从 main `e925eec`（PR #14 登录导入）接续，分支 `codex/personal-health`。`personal health --file owner.ll` 在隐藏双因素和 SCAN 确认后，只分析当前 active 登录。不读取来源记录中的旧密码，也不把归档、回收站和文档纳入当前密码重复统计。

`local-heuristics-v1` 固定规则：empty 为空值；short 少于 12 个 Unicode code point；low-variety 少于 4 种不同 code point；common-example 是代码内明确列出的 12 个示例密码（不区分大小写）；reused 是活动登录的非空密码精确相等；totp-not-stored 仅表示本库没有保存 TOTP 值。大小写不同、Unicode 规范化不同的密码不会合并。规则不是熵估计，不检查网站/泄露数据库，不判断网站是否启用其他双因素；没有发现不表示安全。

报告只输出 profile、scope、检查/跳过计数、条目 ID、当前修订和固定问题码；不输出标题、用户名、密码、OTP、密码摘要或相等分组标识。内存中的比较结果不缓存、不上传。报告摘要绑定完整报告，`vault.health.local` 审计与解锁、历史校验和分析同事务，提交及关闭成功后才释放回执。失败/回滚无报告；扫描不改条目和修订。旧客户端遇到新审计动作会拒绝，需要使用新版。

失败先行 `/tmp/locklark-validation/health-red.log`：缺少体检 API/报告。覆盖空值、短值、重复和低字符种类、活动状态范围、来源旧值排除、精确相等、固定报告无值/摘要、错误因素、事务回滚和审计绑定。`scripts/health_acceptance.py` 在真实终端核对同意/取消、报告与事件 SHA256、修订不变和秘密未输出；CI 在 Linux PTY 与 Windows ConPTY 执行。审阅与最终精确 head 的检查见本批 PR。
