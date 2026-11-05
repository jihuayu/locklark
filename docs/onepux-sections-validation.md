# 1PUX 区段与字段结构清点

本切片只扩展内存只读 `onepux.Inspect`，不接通通用导入、人工披露或 MCP 取值。`MappingVerified` 仍始终为 false。JSON 形状不是字段语义类型，也不证明能够无损迁移。

## 交接基线

- main：`3901bc8d8c91c8da039fa02d83e1521746c3c5aa`。
- 分支：`codex/first-preview`；接续 `46ca0f5881406d02385d25c8d7d771b40d5a05d7`；实现 head：`63cb54fde5c72834baef0fd0fafe0360f9232d61`。本交接文档随后作为同分支提交，具体文档 head 见 git 历史和 PR。
- PR：[#1](https://github.com/jihuayu/locklark/pull/1)，仍未合并。fetch 后未发现并发提交，未修改 main。
- 独立复核仍待完成；本轮自查不是独立复核。既有恢复、MCP 与后续基础切片的未完成复核没有被关闭。

## 行为与限制

按条目作用域统计重复区段 name，按各区段统计重复字段 id；相同名称或 ID 不合并，不做大小写或 Unicode 规范化。重复次数是首次出现以后的次数，缺失和空字符串另计未标识数。字段 ID 在源格式中不保证唯一；重复区段名则作为需核对的源异常保留，不能作为目标身份。

字段值分别计缺失、null、object、array、string、number 和 boolean；不回显原值、标识或标题，不将数字转换为浮点或字符串。未知值对象内部语义仍未验证，报告固定 `field-value-semantics-unverified`；原有 `sections-unmapped` 和全体未映射标记继续保留。loginFields、历史及嵌套类型的语义校验仍待实现。

区段缺少 fields 时标记 `section-fields-missing`；显式 null、非数组字段列表、非对象字段，以及存在但不是字符串的 name/id/title 返回固定 ErrInvalid 和零报告。整个归档的区段与字段合计最多 4096，超限返回 ErrLimit，与格式错误分开；原 ZIP、展开大小和严格 JSON 限额继续生效。清点成功不能作为接受异常源结构的导入许可。

依据：[1Password 1PUX 格式说明](https://support.1password.com/1pux-format/)，本轮沿用此前下载的公开格式说明；没有使用真实用户导出或真实 1Password 进行对照。

## 实跑验证

先写合成测试，再运行 `go test ./internal/onepux -run TestSectionInventory -count=1`，实际失败：缺少区段清点报告、畸形 fields 返回成功、超过新容量限制未拒绝。原始输出保存在临时路径 `/tmp/locklark-validation/sections/red.log`；临时日志不是持久 CI 证据。

实现后验证：

- 配置 `LOCKLARK_TEST_BUN=/tmp/locklark-tools/bun-linux-x64/bun`、`LOCKLARK_TEST_PYKEEPASS=/tmp/locklark-tools/python/bin/python` 后，`/tmp/locklark-tools/go/bin/go test -count=1 ./...` 全仓通过（日志 `go-all.log`）。

- 包内完整测试通过；覆盖跨条目/跨区段作用域、重复 ID、缺失与 null 区分、大整数 JSON 值、大小写区分、所有值形状、报告秘密扫描、畸形拒绝和超限零报告。
- `go test -race -count=1 ./internal/onepux ./internal/preview -run 'TestSectionInventory|TestInventory|TestOnepux'` 通过。真实加密合成库的来源审计与独立检查点回归通过，报告不包含源秘密；该来源证明不等于新增清点操作的持久审计入口。
- `go test ./internal/onepux -run '^$' -fuzz '^FuzzSectionInventory$' -fuzztime=20s -parallel=2` 通过，229677 次执行；重建有效 ZIP，使变异能够到达区段结构，检查分类计数守恒与容量约束。
- `go vet ./...`、`git diff --check` 通过；Windows amd64、macOS arm64 的 onepux 测试包交叉编译通过，仅编译。

本次未重跑独立 PTY/MCP/Bun 脚本；此前记录仍只代表当时版本。Windows/macOS 原生运行、移动真机、硬件、真实 1Password 对照、独立密码评审均未在本轮完成。

## 合并条件与下一项

本轮读取 PR 最新已完成检查时，head `46ca0f5` 的 [Ubuntu 检查](https://github.com/jihuayu/locklark/actions/runs/41937705459/job/126950272644) 仍为付款/额度原因未启动，Windows 取消。实现 `63cb54f` 的 [Windows 检查](https://github.com/jihuayu/locklark/actions/runs/41941414108/job/126962879802) 亦因相同付款/额度原因未启动，Ubuntu 取消，已读取该检查 annotation 确认。没有把本地通过记作远端通过，也没有绕过用户要求的检查与独立复核门槛。

下一项可继续实现 loginFields 的 designation/字段形状清点，保留重复/未知语义，不把清点当作迁移授权。PR 条件满足并 squash 合入 main 后，再从更新后的 main 开分支接通个人 CLI 受控单字段披露。完整语义映射和产品审计入口仍保留为未完成验收。
