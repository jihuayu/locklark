# 合成导入源字段投影：验收与交接

## 接手与发布

本轮成功 fetch `origin/main`、PR #1 原分支与 `refs/pull/1/head`。main 为 `3901bc8d8c91c8da039fa02d83e1521746c3c5aa`；PR 开放、未合并，三个预览 head 都为 `3a0184bad879043528c8c5a3d6a857eb436cf8f0`，工作树干净，未见其他开发测试进程。已读取 design、progress、development-goal，未依赖 Ryugi。累计差异是已有第一版代码，未从只有 README 的 main 重做。

工作分支仍为 `codex/first-preview`，新增实现 head 为 `12612b113d92fba24a813530175a20acff702b37`，已普通快进推送到 [PR #1](https://github.com/jihuayu/locklark/pull/1)。提交前重读远端，原 head 未变。本轮终端 Git/gh 访问恢复；未更改凭据、强推或修改 main。文档提交的最终 head 由本文件所在提交及 PR head 确定，精确远端检查见 [PR checks](https://github.com/jihuayu/locklark/pull/1/checks)。

## 范围与安全边界

`preview.ProjectFixtureReferenceMetadata` 只接受现有内置合成原生布局：一个固定源 vault、一个登录、一个文档及六个既有槽位。它与个人 `items/v1` profile 分开，不是通用 1PUX 导入器。未知版本、缺失布局、不认识的属性或类别、归档状态和非既定身份明确拒绝；既有快照读写格式与迁出功能没有改版或自动降级。

- 源 vault/item ID 保留；登录根字段沿用源 `name=password`，区段 ID 用源 `name=ops`，字段 ID 用源 `id=otp-demo`，显示名来自源标签。既定合成源没有另一个根字段 UUID，不生成假的 UUID。`op://synthetic-vault/login-sample/ops/otp-demo` 可定位，不把它改为个人 `otp`，也不凭空增加 `username`。
- 当前标题来自原生条目，文档仍保留身份并参与名称歧义检查；没有普通字段或附件取值入口。源和原生条目次序均不作为绑定依据。
- 所有条目的版本为 `snapshot-signature-v1:` 加调用者提供的规范快照签名。它绑定整份快照，任一快照变更会使两条目的版本一起变化，不能冒充源 1Password 的逐条修订号。函数不验签、不证明新鲜度；调用者必须在可信读取中一起认证布局、条目和签名。
- 校验源布局只重建中性空值，既不读取也不插入原生密码、OTP、用户名、文件名或附件。目录含私有标题和标签，不得进入普通日志或未经授权的 Agent 输出。额外未知字段拒绝，避免意外扩大元数据。
- JSON 拒绝重复键、大小写别名重复键、非 ASCII 属性名、非法 UTF-8、尾随根值和未知属性。元数据最多 4 MiB，中性源最多 1 MiB，深度最多 32，节点最多 4096；超限返回独立 `reference.ErrLimit`，其他失败返回固定错误、nil 目录，不回显输入。重新拆槽并逐一比对，拒绝槽位交换、重复与缺失。

本函数无 I/O、不授予权限、不产生字段披露或执行事实。此次未扩大 CLI/MCP 工具、授权清单或原值入口。生产事务认证与披露意图审计仍未接入，不能把投影成功记为已披露。

## 失败先行与审计

先写新增 API 空实现和合成测试，实际执行 `go test -count=1 ./internal/preview -run '^TestFixtureReference'` 失败：有效源投影、值/次序独立性、同名文档、真实快照审计正例失败；未知版本和容量未正确分类。之后实现并跑通。这是新能力的失败先行，不能称为空实现揭示了已有生产漏洞。日志在临时目录 `/tmp/locklark-validation/import-reference/red.log`，临时文件不保证长期保存。

负例覆盖槽位交换/重复/缺失、字段 ID 替换、重复源 UUID 键、额外私有字段、归档、缺失/重复原生条目、类别串用、无效签名格式、控制字符标题、未知元数据键、大小写重复版本、尾随 JSON 和容量。错误无部分目录、无源标记回显。改变私有值不影响投影，文档同名仍拒绝。

审计正例使用 `preview.Create` 创建真实加密演练，分别通过既有 `readPayload` 验证、解密第 2、3 代快照；改名/OTP 轮换后引用源 ID 不变，版本精确对应各自已验签的快照。`VerifyAudit` 对两代独立 witness 检查点核对全部事件已见证。纯函数单测提供的格式合法假签名只测试映射，不提供真实性证明。此次审计验收验证来源关联，没有新增取值审计事件。

## 实跑检查

Cloud Linux，Go 1.26.8、Bun 1.4.4、PyKeePass 4.2.0。下表 go 为 `/tmp/locklark-tools/go/bin/go`，输出目录为 `/tmp/locklark-validation/import-reference`。

| 检查 | 实际命令与结果 |
| --- | --- |
| 新切片 | `go test -count=1 ./internal/preview -run '^TestFixtureReference'` 通过 |
| 全仓 Go | 设置 `LOCKLARK_TEST_BUN=/tmp/locklark-tools/bun-linux-x64/bun`、`LOCKLARK_TEST_PYKEEPASS=/tmp/locklark-tools/python/bin/python` 后，`go test -count=1 ./...` 通过，含独立 KDBX 互操作与 Bun 子进程；preview 87.703 秒 |
| 定向 race | `go test -race -count=1 -timeout=5m ./internal/preview -run '^TestFixtureReference'` 通过，21.651 秒；只覆盖新切片 |
| 模糊测试 | `go test ./internal/preview -run '^$' -fuzz=FuzzFixtureReferenceMetadata -fuzztime=15s -parallel=2` 通过，911 次执行，3 个新增 interesting 输入，未发现崩溃或身份漂移 |
| 静态与依赖 | `go mod verify`、`go vet ./...`、`git diff --check` 通过 |
| 真实终端 | 构建 `locklark` 后，`python3 scripts/personal_acceptance.py /tmp/locklark-validation/import-reference/locklark` 通过：错误恢复材料、损坏备份、已有目标均无新钥/恢复库；FIFO、旧格式、迟到目标及建库/重开回归通过 |
| 插件/MCP | `bun test ./plugins/github-pull-reader` 2 pass/0 fail；Bun 加入 PATH 后 `python3 scripts/mcp_acceptance.py /tmp/locklark-validation/import-reference/locklark` 通过 |
| Windows 编译 | `GOOS=windows GOARCH=amd64 go test -c -o /tmp/locklark-validation/import-reference/preview-windows.test.exe ./internal/preview` 通过，仅编译 |
| macOS 编译 | `GOOS=darwin GOARCH=arm64 go test -c -o /tmp/locklark-validation/import-reference/preview-macos.test ./internal/preview` 通过，仅编译 |

原生 Windows/macOS、移动真机、硬件断电、真实 1Password/op 对照和外部密码评审未验收。此前 preview 全包 race 超时仍未解决为完整通过；本轮定向 race 不替代它。

## 合并门槛与下一项

实现提交的 [run 41891994871](https://github.com/jihuayu/locklark/actions/runs/41891994871) 失败；[Ubuntu job 126791527200](https://github.com/jihuayu/locklark/actions/runs/41891994871/job/126791527200) 和 [Windows job 126791527657](https://github.com/jihuayu/locklark/actions/runs/41891994871/job/126791527657) 均无测试步骤。通过本轮恢复的 gh 读取两个 check 的 annotations，均明确写明 `The job was not started because recent account payments have failed or your spending limit needs to be increased.` 这是当前 run 的实际原因，无远端测试通过证据。未绕过规则合并。

本轮已自行检查类型/索引边界、槽位绑定、输入上限与秘密流向，未发现新增问题；这不是独立复核。本切片、先前恢复/投影切片及 `4932c8d..a0d8ab1` 的独立代码复核仍待完成。PR 保留，未 squash；全部设计及逐平台验收远未完成，持续目标保持进行。

下一项可独立开发：引用目标到既定原生字段槽/类型的绑定校验与向量，拒绝跨 profile、文档和过期快照目标；保持元数据级，不读值或授权。生产人工披露仍需已有 PR 满足复核/检查并合并，再从更新 main 建分支接入可信事务与披露意图审计。
