# 个人登录标题搜索

从 main `1dfc8b020b941d2eaa38aa74bdf1645124ab46af`（签名插件目录 PR #20）接续，分支 `codex/personal-title-search`。命令 `personal search --file owner.ll [--state active|archived|trashed|all]` 默认 active；密码、Secret Key 和搜索词均通过真实终端隐藏输入，不接受 `--query` 或位置参数搜索词。

`title-nfc-fold-substring-v1` 只匹配当前原生 login 的 Title：先 NFC，再 locale-independent case folding，再 NFC，做子串匹配。Go 1.26.8、x/text v0.43.0 的 cases/norm 和标准库分类表均使用 Unicode 15.0.0；测试锁定表版本，未来升级导致语义变化须更新 profile。支持中文、组合字符等价形式及 Straße/STRASSE，不进行模糊、拼音、去重音或全字段搜索。原始查询限 1–256 UTF-8 字节，拒绝无效 UTF-8、全空白、Cc/Cf；非空查询的首尾空格保留并参与匹配。同名条目保留各自 ID/修订，按 ID 排序。

解锁仍会解密整个个人库，但搜索算法不检查用户名、密码、OTP、网址或导入来源旧值。回执仅含 profile/scope、session、审计事件摘要、query_digest 及匹配的标题/ID/修订/状态；匹配标题自然可能包含搜索词，不应将结果输出理解成隐去标题。Cc/Cf 在原始 JSON 中显示为可见转义，JSON 消费者仍能恢复原始标题。

查询没有独立回显字段，不写入错误和审计。query_digest 是以 AuditEncryption 经独立 HKDF label 派生密钥计算的 HMAC，绑定 profile、原始查询字节和 state；相同库的相同查询/范围可关联，不暴露无钥字典可枚举的普通摘要。大小写或空格不同的原始查询即使命中相同也有不同绑定。查询在进程内存短暂存在，不声称 Go 字符串可安全擦除。

解锁、完整历史校验、搜索和 `item.search` 元数据事件在同一事务完成；零命中也入账，事件 Link 保存上述 HMAC。提交和关库成功后才构造回执；失败无结果。搜索不重封快照、不改变条目修订，不授权字段披露。备份恢复能重放搜索事件。旧客户端不认识该动作时会拒绝读取，需使用新版。

失败先行记录 `/tmp/locklark-validation/title-search-red.log`：缺少 Search API/回执。单测覆盖 Unicode、状态、重复标题、字段排除、控制字符、HMAC 跨库/范围隔离、错误因素、修订保持、事务回滚、关库失败及备份恢复；`scripts/search_acceptance.py` 使用实际 CLI/PTY，覆盖隐藏输入、终端控制字符、归档范围、错误因素、查询不单独输出、五次成功审计。CI 同一脚本运行 Linux PTY 与 Windows ConPTY。

Luna/max 已独立复核实现，未发现阻塞问题，并独立执行定向 Go 测试、vet、构建和 PTY 验收；Unicode 表版本建议已补入规则和测试。主任务全量 Go 通过（personal 202.987s、preview 136.555s），定向 race 通过（personal 200.469s、CLI 1.099s），vet、diff 检查及真实 PTY 通过；日志保存在 `/tmp/locklark-validation/title-search-{all,race}.log`，新增 Unicode 版本约束测试单独通过。最终精确 head 和双平台结果以本批 PR 检查为准。本切片只交付人工 CLI 标题搜索；桌面快捷搜索、系统解锁、复制清理及自动锁仍待开发，七条产品线仍未全部完成。
