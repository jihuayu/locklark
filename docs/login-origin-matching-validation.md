# HTTPS 来源候选匹配

基线 main `33ede6611dd3d3259065b8dfbfa76272d0c84620`（PR #10 归档完成）。本批 `codex/login-origin-matching` 提供可供未来浏览器/移动适配器复用的 Go 来源核心和真实个人 CLI 入口，不把它称为已实现浏览器插件或手机系统填充。

`personal edit-login --file PATH --id ID --revision REV --field url` 隐藏输入一个网站 HTTPS URL（空值清除）。沿用修订检查、加密快照和签名审计事务。KDBX 原生 URL 字段内存保护，JSON 缺省 URL 保持旧备份签名兼容；恢复与便携导出保留 URL。当前单网址，不把它视为完整多网址迁移。

`personal match-logins --file PATH --origin https://example.com --frame-origin https://example.com` 必须交互解锁，核验同事务快照和审计历史后返回 active 登录的 ID、标题、状态、修订；不返回 URL、用户名或密码，不授予披露/填充权限。两来源须一致，子域名、相似域名及不同非默认端口不匹配。固定 `item.match` 审计事件只含 succeeded/cross-origin，不含网站、候选 ID、标题或字段值；回滚不释放候选。

`internal/origin` 的 v1 保守 profile：仅小写 scheme `https://`，整条 URL 必须使用 ASCII 写法（非 ASCII 路径可先百分号编码），DNS host 大小写归一；拒绝 IDN/punycode、IP 字面量及非标准 IPv4 数字写法、单标签、localhost/local/internal/home.arpa 后缀、尾点、userinfo、空白/控制符、反斜线、query 和 fragment。允许 1..65535 的规范十进制端口，443 归一，拒绝空端口/前导零/0/越界。保存 URL 可含路径；输入来源只允许缺省路径或字面 `/`，匹配忽略保存路径。无 DNS 或网络查询，因此不能据此保证任意 DNS 名不解析到私网。

版本化共享向量 `internal/origin/testdata/origin-v1.json` 可供 Swift/Kotlin/扩展适配器对照。这一 CLI 的 origin 字符串只是调用者声明，无法认证页面来源；未来适配器必须从浏览器/系统可信 API 获取顶层和 frame origin，并独立做解锁、连接生命周期和用户授权验证。真正 Chrome/Edge/Firefox/Safari 集成、iOS/Android 真机系统填充与 Passkey 均未验收。

失败先行记录 `/tmp/locklark-validation/origin-red.log`。单测覆盖域名/端口/编码边界、错误因素、同源、跨源、归档排除、无秘密审计、事务回滚以及备份恢复；PyKeePass 验证独立导出 URL。`scripts/matching_acceptance.py` 通过 PTY/ConPTY 验证隐藏编辑与匹配/拒绝/归档流程。完整 Go、定向 race、vet/模块、Luna/max 与最终双平台 CI 结果见 PR。

Luna/max 静态审阅未见阻塞；反馈已补齐：CLI 明确完整 URL 的 ASCII 输入范围，匹配时说明来源来自调用者且只查询候选，清除 URL 后不可匹配有专门回归测试。最终复核与双平台 CI 见 PR #11。
