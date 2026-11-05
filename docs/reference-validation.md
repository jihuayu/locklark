# 字段引用解析核心：验收与交接

## 接手与本切片

重新 fetch 核对：`origin/main` 为 `3901bc8d8c91c8da039fa02d83e1521746c3c5aa`；[PR #1](https://github.com/jihuayu/locklark/pull/1) 开放、未合并，真实 head、远端 `codex/first-preview` 和 `refs/pull/1/head` 均为 `78ed9e584930ba2fcf6b3179d575c7e0b2827200`。接手工作树干净，未见其他开发测试进程。没有覆盖后续提交或改动 main。

本切片实现不依赖存储或未合并主分支的纯 Go 引用基础：`internal/reference`。代码提交为 `0dece6d432c787ca126c4575417d0424ec48fdd9`，已快进推送到 PR #1 原分支。它不依赖 `personal`、`preview`、KDBX、解锁因素或任何服务；不是人工 raw read、Gateway 授权或已经接通的 CLI 功能。原恢复修复与审核门槛继续保留。

## 可验收行为

`Parse` 接受 `op://vault/item/field` 和 `op://vault/item/section/field`。本子集使用 ASCII 字母、数字、普通空格、`-`、`_`、`.`；大小写不敏感，普通空格与点按字面保留，不做路径清理或 URL 解码。`?` 查询属性明确返回 unsupported；百分号转义、其他 scheme、片段、空分量、控制字符及不支持的字符拒绝。具有中文、斜杠等不支持字符的元数据名称保留，但引用须使用稳定 ID；没有静默转写或 Unicode 相似字符折叠。

`Resolve` 只读取调用者提供的不可变元数据快照：名称或 ID 可定位 vault、item、section、field。每层均须唯一；同名、大小写碰撞、跨区段同名字段，以及一个对象名称碰上另一个对象 ID，均报歧义，不选第一项，也不利用后续分量偷偷跳过歧义。明确指定区段时不会查到其他区段的字段。改名后稳定 ID 继续定位，返回元数据中的当前条目修订号。

元数据校验拒绝重复 ID（按各自作用域，不区分大小写）、条目内跨区段复用字段 ID、空白/缺失/含控制字符的修订号、无效文本和超限。当前上限：引用 4096 字节、单分量/ID/修订号 256 字节、名称 1024 字节、元数据总计 4096 个对象和 1 MiB 文本。大目录明确拒绝，不能截取前页后当作唯一命中。

成功 `Target` 只含 vault/item/可选 section/field 的 ID 与条目修订号；失败全部返回空 Target，错误正文为固定分类，不回显未核实引用或名称。元数据类型没有字段值槽，模块不读取、输出或执行凭据。

### 审计与授权边界

“唯一解析”只证明在给定元数据内命中一个目标，不证明该元数据经过签名、仍新鲜，或调用者有权使用字段。调用者须在持库事务/快照边界内提供完整且可信的元数据，再核验版本、设备、会话、用途、授权及撤销，提交审计意图后才能取值。不得将 Target 当成授权票据，或把插件提交的元数据当作系统核实。

本模块没有 I/O、日志或取钥，不产生一次用钥事实。验收覆盖可供未来审计绑定的 ID/修订号投影：JSON 不含选择器、标签或原引用；拒绝不返回部分 ID。真实存储事务审计的接入仍未实现，不能用该投影测试替代。现有个人恢复与 MCP 生命周期的签名审计本轮继续回归通过；MCP 工具列表和固定演练引用没有扩大。

## 先失败的证据

先写 API 类型、空实现与合成测试，执行 `go test -count=1 ./internal/reference`，实际失败：有效引用被报 invalid、有效目标被报 not found、同名歧义误报 not found、目录校验与输出投影正例失败。然后实现解析与查找，以上测试通过。这是新增核心能力的 TDD，不把空实现失败描述为既有产品漏洞。

失败日志为本次临时环境 `/tmp/locklark-validation/reference/red.log`，临时环境不保证长期保留。合成测试未接触真实金库、真实账号或生产凭据。

## 实际检查

工具链为 Go 1.26.8、Bun 1.4.4、PyKeePass 4.2.0，执行环境为 Cloud Linux。`go` 为 `/tmp/locklark-tools/go/bin/go`。

| 检查 | 命令与结果 |
| --- | --- |
| 核心单测与竞态 | `go test -race -count=1 ./internal/reference` 通过；复查补充空白/控制字符修订号拒绝后重新通过（1.025 秒） |
| 模糊测试 | `go test ./internal/reference -run '^$' -fuzz=FuzzParse -fuzztime=15s -parallel=2` 通过，789326 次执行；覆盖失败不返回部分目标、成功身份始终来自给定目录、解析重建语义一致 |
| 模块/静态 | `go mod verify`、`go vet ./...`、补充修订号校验后的 `go vet ./internal/reference`、`git diff --check` 通过 |
| Go 全量 | 设置 `LOCKLARK_TEST_BUN=/tmp/locklark-tools/bun-linux-x64/bun` 和 `LOCKLARK_TEST_PYKEEPASS=/tmp/locklark-tools/python/bin/python`，`go test -count=1 ./...` 通过，含独立 KDBX 实现和真实 Bun 子进程；随后只补充本包修订号校验并重跑本包竞态/静态检查 |
| Bun | `bun test ./plugins/github-pull-reader`：2 pass、0 fail |
| 个人终端 | 构建本轮 CLI 后 `python3 scripts/personal_acceptance.py /tmp/locklark-validation/reference/locklark` 通过，含原恢复所有负例及 FIFO 拒绝 |
| MCP 子进程 | Bun 位于命令 PATH 时，`python3 scripts/mcp_acceptance.py /tmp/locklark-validation/reference/locklark` 通过 |
| Windows 编译 | `GOOS=windows GOARCH=amd64 go test -c -o /tmp/locklark-validation/reference/reference-windows.test.exe ./internal/reference` 通过，仅编译未运行 |
| macOS 编译 | `GOOS=darwin GOARCH=arm64 go test -c -o /tmp/locklark-validation/reference/reference-macos.test ./internal/reference` 通过，仅编译未运行 |

## op 行为对照状态

本轮读取了[官方 Secret reference syntax](https://www.1password.dev/cli/secret-reference-syntax.md)，参考其路径、ID、大小写与支持字符说明；读取文档的 SHA-256 为 `d3be13f7fd47f49642ac670cd8f9e15b0dd427143cccb65649da2dab6bec2c79`。公开文档不是固定 op 版本的实际运行证据。当前环境没有 `op`，也未使用真实账号登录。

| 项目 | 本实现 | 原版对照状态 |
| --- | --- | --- |
| 三/四分量、名称/ID、大小写 | 已用合成目录实测核心 API | 已实现未对照；op v2 基准尚未固定 |
| 同名和 ID/名称碰撞 | 明确拒绝，绝不猜第一项 | 已实现未对照 |
| 空格、点、百分号与编码 | 本子集规则明确；无 URL 解码 | 已实现未对照，不能宣称转义兼容 |
| 中文等名称 | 元数据保留，引用需 ID | 直接中文名称引用未实现 |
| 查询属性、OTP、附件值 | 明确不支持，无取值能力 | 未实现，不计兼容 |
| 人工 CLI read/run/inject、退出码与 stdout | 未接入本模块 | 未实现，不计兼容 |

## 远端检查、复核与下一项

代码提交 `0dece6d` 的 [run 41871642842](https://github.com/jihuayu/locklark/actions/runs/41871642842) 未启动测试。实际读取了 Ubuntu check `126720015974` 和 Windows check `126720015461` 的 annotation，仍为账户付款/额度限制；本地通过不等于远端通过。此为原阻塞，未单独重复通知。文档提交后的最新 head 检查以 [PR checks](https://github.com/jihuayu/locklark/pull/1/checks) 为准。

本切片独立代码复核未完成；既有恢复切片及 `4932c8d..a0d8ab1` 的复核欠项保留。自己的复查和模糊测试不算独立复核。本轮未运行原生 Windows/macOS、移动真机、硬件实验、真实 op/1Password 对照或外部密码评审。预览包全量竞态检查原超时限制仍未关闭。

下一项：复核本核心，并固定 op v2 版本建立真实合成账号行为对照；可独立开发名称/ID 到原生条目字段元数据的投影向量。人工字段披露仍须先满足既有 PR 的检查/复核并合并，再从最新 main 开 `codex/` 分支，接入可信来源、修订号核验、人工身份与事务审计。PR #1 保持开放，未 squash、未直接推送或强推 main；全部开发目标尚未完成，不停用持续推进任务。
