# 个人原生字段元数据投影：验收与交接

## 接手和发布

本轮重新 fetch 后，`origin/main` 为 `3901bc8d8c91c8da039fa02d83e1521746c3c5aa`，工作分支是 `codex/first-preview`；[PR #1](https://github.com/jihuayu/locklark/pull/1) 开放、未合并。实际 PR head、远端分支和本地接手提交均为 `901588fc8a3cad1ae8204ba3b4b4fa290f03c1f4`，工作树干净，未见其他开发测试进程。未从只有 README 的 main 重做代码，也未覆盖后续提交。

新增实现本地提交为 `eaf63315e82fcfed26d235c4e6f61df445e14171`；通过 GitHub 连接器发布的实际实现提交为 `a1b95a61e501767a2982b493c291edea24e43eb8`。二者 Git 文件树均为 `6f5733748a80a392c3cffdf3c7a1ed5afd4abdc3`，与本次测试内容完全相同。PR 原分支采用预期父提交 `901588f`、`force=false` 的快进更新；main 未修改。

终端在发布前出现新的认证问题：Git fetch 报无法取得 Username，`gh api` 返回 `Bad credentials (HTTP 401)`；Cloud 环境仍 connected，网络策略 enforced。连接器可正常读取 PR 和创建 Git 数据，故通过标准 Git Data 接口创建匹配的树、提交，再带预期 head 更新原分支。已核验远端提交的原始对象哈希并导入本地；本地 `codex/first-preview` 与实际实现提交同步，原本地提交保留在 `codex/projection-local-eaf6331`。未更改凭据或绕过分支规则。终端凭据仍待正常恢复，连接器可用不代表 CLI 已恢复。

## 范围与行为

`personal.ProjectReferenceMetadata` 仅接受精确的 `locklark/personal/items/v1` 标签，从现有原生条目投影引用目录；源字段原值不进入输出。调用者必须从同一可信事务取得快照和审计修订映射；标签与合法格式的摘要都不证明真实性。调用者还须提供受信的 vault ID/名称；本函数不为已有库自动分配或持久化逻辑 vault ID。

- 登录保留源条目 ID、标题和修订号，固定逻辑字段 ID 为 `username`、`password`、`otp`。它们不随字段值是否为空改变，也不依赖位置或字段值摘要。空用户名即使没有独立 KDBX XML 槽，仍是本逻辑 profile 的已知字段。
- 文档保留条目身份与标题以参与名称歧义检查，但没有普通登录字段或附件取值入口。不会因文档没有密码就跳过同名文档、猜中某个登录。
- 原生条目 ID 须为本 profile 的 32 位小写十六进制 ID；修订映射须与全部条目一一对应，修订号为 64 位规范摘要。缺失、多余、重复 ID、未知类别、无效文本和超限均拒绝，失败返回 nil 目录，不回显输入。
- 未知、未来或导入区段布局明确返回 unsupported profile；不能把 1PUX 的 `ops/otp-demo` 等源字段身份自动替换成本 profile 的 `otp`。本切片没有完成通用 1PUX/自定义区段投影。

投影读取身份、类别、标题与提供的修订映射；用户名、密码、OTP、文件名、附件字节和保护标记既不影响字段身份，也不复制到目录。目录仍包含私有标题，不能写入普通日志或直接交给未经授权的 Agent。`reference.Validate` 只复用目录结构、容量和唯一性校验，不认证快照或授权访问。

## 失败先行和审计验收

先写类型、空实现和合成测试，执行 `go test -count=1 ./internal/personal -run 'TestProjectReferenceMetadata|TestProjection'`，实际失败：有效投影报 invalid、值独立性/同名文档正例失败、未知 profile 未按 unsupported 分类、真实个人库首次投影失败。然后实现并跑通。这是新增能力的失败测试，不把空实现描述为已有生产漏洞。日志位于本次临时环境 `/tmp/locklark-validation/projection/red.log`，临时环境不保证长期保存。

回归用现有 CLI 核心创建真实加密合成个人库，读取经验签/解密的原生条目和签名审计修订。改名后条目/字段 ID 不变，投影修订号精确对应 `item.edit.title` 的签名事件摘要。独立备份恢复后保留条目/字段 ID，但使用新账本 `item.restore` 的修订号，没有复制旧修订号。审计正文与投影序列化均扫描合成字段标记，原值未泄漏。

本测试无并发写者，调用现有 List 与读回帮助函数分别核验来源；生产接入必须将快照和修订读取放在同一持库事务，尚未完成。投影函数本身无 I/O、不使用凭据、不产生披露事实，不能把投影成功写成已执行或已披露。人工 CLI、MCP/机器授权和生产事务审计入口没有扩大。

## 实际检查

环境为 Cloud Linux，Go 1.26.8、Bun 1.4.4、PyKeePass 4.2.0。下表的 go 为 `/tmp/locklark-tools/go/bin/go`。

| 检查 | 命令与结果 |
| --- | --- |
| 新投影单测 | `go test -count=1 ./internal/reference ./internal/personal -run 'TestProjectReferenceMetadata|TestProjection|TestResolve|TestParse'` 通过，含加密个人库改名/恢复与签名修订对账 |
| 全量 Go | 设置 `LOCKLARK_TEST_BUN=/tmp/locklark-tools/bun-linux-x64/bun` 与 `LOCKLARK_TEST_PYKEEPASS=/tmp/locklark-tools/python/bin/python` 后，`go test -count=1 ./...` 通过，含独立 KDBX 读写与真实 Bun 子进程 |
| 竞态 | `go test -race -count=1 -timeout=10m ./internal/personal ./internal/reference` 通过，分别 170.884 秒和 1.116 秒 |
| 模糊测试 | `go test ./internal/personal -run '^$' -fuzz=FuzzProjectReferenceMetadata -fuzztime=15s -parallel=2` 通过，共 338048 次执行；检验失败无部分目录、身份保留、改变字段值不改变投影 |
| 模块与静态 | `go mod verify`、`go vet ./...`、`git diff --check` 通过 |
| 个人真实 PTY | 构建 `/tmp/locklark-validation/projection/locklark` 后，`python3 scripts/personal_acceptance.py /tmp/locklark-validation/projection/locklark` 通过，含原恢复负例与 FIFO 拒绝 |
| Bun 与 MCP | `bun test ./plugins/github-pull-reader` 2 pass/0 fail；Bun 在命令 PATH 中运行 `python3 scripts/mcp_acceptance.py /tmp/locklark-validation/projection/locklark` 通过 |
| Windows 编译 | `GOOS=windows GOARCH=amd64 go test -c -o /tmp/locklark-validation/projection/personal-windows.test.exe ./internal/personal` 通过，仅编译 |
| macOS 编译 | `GOOS=darwin GOARCH=arm64 go test -c -o /tmp/locklark-validation/projection/personal-macos.test ./internal/personal` 通过，仅编译 |

未运行原生 Windows/macOS、移动真机、硬件断电或真实 op/1Password 对照；没有外部密码评审。预览包全量竞态检查先前超时的限制继续保留，不计为通过。

## 远端、独立复核与下一项

实现提交 `a1b95a6` 的 [run 41882130434](https://github.com/jihuayu/locklark/actions/runs/41882130434) 标记 failure；连接器读到 Ubuntu job `126757021993` 和 Windows job `126757021235` 均 failure、steps/logs 均为空，没有远端测试通过证据。本轮因 CLI 401 无法重读注释；连接器对实际 annotations URL 返回不支持的 URL（400），所以没有重新确认本轮失败的具体原因。此前已核实的付款/额度阻塞记录仍保留，不能仅据历史原因推断新 run。最终文档 head 的实际检查见 [PR checks](https://github.com/jihuayu/locklark/pull/1/checks)。

本切片、原恢复切片以及 `4932c8d..a0d8ab1` 的独立代码复核均未完成；自己的复查、模糊测试和互操作不能替代。PR #1 保留，未 squash，未直接推送/强推 main。全部目标尚未完成，持续任务保持进行。

下一项可独立工作：为导入布局保留源区段/字段 ID 的投影与对照向量，明确其独立 profile，避免沿用个人固定字段映射。生产事务、人工身份与披露审计仍待既有 PR 满足检查/复核并合并后，从更新 main 开分支接入；普通 Agent 仍无原值读取能力。
