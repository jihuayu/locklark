# 1PUX 登录字段结构清点

从 PR #5 合并后的 main `85a3d6f6f53f40bf8ad93b86114b005324a2e609` 接续，分支 `codex/onepux-login-fields`。只扩展内存只读 `onepux.Inspect`；不读取用户文件路径、不解压落盘、不迁移或赋予取值权限。具体实现 head、Luna/max 结论和最终双平台 CI 链接记录在 PR 正文。

## 字面清点，不推断字段语义

`login_field_inventory` 按源出现次数统计字段，不按名称合并。name/id 各有独立去重空间；重复为同条目内首次之后的次数，跨条目不计重复，缺失和精确空串分别进入未命名/未标识总数。无大小写折叠、TrimSpace 或 Unicode 规范化。

designation 分为缺失、精确空串、精确 `username`、精确 `password` 和其他非空字符串；非空 designation 的重复按同条目计，未知值也保留重复。未知和重复不是迁移许可，也不据此选择“正确”用户名/密码。原值、名称、ID、未知 designation 和类型字符串均不出现在报告或错误中。

2026-11-05 核对的[公开格式说明](https://support.1password.com/1pux-format/)正文使用 `type`、示例使用 `fieldType`，并称所列 HTML 类型并非穷尽。两种属性分别计存在数，同时存在数和原始字符串不同数另计，不互相覆盖或规范化，不把未列举类型判为无效；即使两属性相同也未证明语义等价。缺少两者另计。报告以 `login-type-attributes-both` 标记同时存在，`login-type-attributes-differ` 只说明字面差异。

value 按缺失、null、object、array、string、number、boolean 计数；大整数保持 json.Number，不取浮点值，不下探嵌套敏感对象。缺失值记 `login-value-missing`；现存非 string 值记 `login-value-not-string`，两者不混同，但清点仍接受并保持未映射。非空 loginFields 始终保留 `login-fields-unmapped` 与 `login-field-semantics-unverified`；所有条目计入 UnmappedItems，MappingVerified 始终 false。

## 拒绝与容量

loginFields 缺失或空数组有效；显式 null、非数组和非对象元素拒绝。若提供 name/id/designation/type/fieldType，必须是字符串；null 等畸形与未知合法字符串分开。所有错误只返回固定错误与全零报告，前面的有效条目不能成为部分结果。

全归档的区段数、区段字段数与登录字段数共用 4096 上限；恰好上限有效，多一个返回 ErrLimit，两种跨条目遍历顺序均受约束。账号/库/条目的既有上限独立保留，ZIP/展开大小/严格 JSON/深度与节点限制不变。

## 证据

先写 `TestLoginFields*` 并运行，旧实现实际失败：缺少报告、接受畸形 designation 元数据和超限 loginFields（`/tmp/locklark-validation/login-fields-red.log`）。随后覆盖所有值形状、重复作用域、未知/空/缺失 designation、大小写/空白、type 与 fieldType 同/异/缺失、未知类型、畸形对象在有效条目之后、预算精确边界与超限、报告秘密扫描。模糊测试保持有效 ZIP/外层层级，以变异直达 loginFields，并检查分类计数守恒和零部分结果。

真实加密合成预览从验签审计与独立检查点核验的来源读回归档，断言已有 `fieldType: P` 登录字段没有被归一化为 `type`，预检/审计报告不含源值。这个来源验证不是新增预检操作的持久审计入口。

本轮运行全仓 Go（含 Bun/PyKeePass）、onepux/preview 定向 race、20 秒定向 fuzz、vet/模块校验、macOS arm64 测试包交叉编译，以及 Luna/max 独立复核与最终 Ubuntu/Windows CI；最终结果在 PR 中记录。公开格式和合成数据不替代真实 1Password 导出对照。完整历史/字段语义映射、其他附件布局、通用导入和产品预检审计入口仍未实现。下一项可继续 passwordHistory 的时间/值结构清点，保留原始顺序与重复，不将清点当成可逆迁移证明。
