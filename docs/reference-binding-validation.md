# 原生字段槽位与类型绑定：验收与交接

## 接手与提交

本轮 fetch 最新 main、原分支和 PR head，均成功。main 为 `3901bc8d8c91c8da039fa02d83e1521746c3c5aa`，工作分支 `codex/first-preview`，实际接手 head 为 `c0a494f4092a5634f4bc9782017dd49479e6883a`；远端分支、PR ref、本地一致，工作树干净，未见其他开发测试进程。已重读 design、progress 和 development-goal，无新增仓库指令，不依赖 Ryugi。

[PR #1](https://github.com/jihuayu/locklark/pull/1) 仍开放、未合并；接续已有实现，未从只有 README 的 main 重做。实现提交为 `0970d63ae95fc5e8673da7bcd6c0ef5116b1d953`，已普通快进推送原分支；提交前重新 fetch，未出现并发新 head。main 未修改。文档 head 由本文件所在提交和 PR 实际 head 确定，最终检查见 [PR checks](https://github.com/jihuayu/locklark/pull/1/checks)。

## 新能力与边界

`reference.CheckTarget` 验证整个元数据目录后，按精确 vault/item/section/field ID 检查目标，随后比较精确修订号。它不再按名称查找，不做大小写折叠，也不省略区段重试；名称解析必须先经 `Resolve` 得到目录中的规范 ID。合法字段的旧修订返回 `ErrStale`；未知字段、错误区段或名称冒充 ID 返回 `ErrNotFound`；目录错误/容量错误沿用原类型，错误不回显输入。

两个布局各自的绑定函数先调用自己的完整投影校验，再检查目标，最后只允许封闭的槽位/类型映射。输出 `Binding` 包含 profile、规范目标、原生槽位和类型，没有字段值。任意失败均返回零值 Binding。

| 已验证布局 | 源字段身份 | 原生槽位 | 类型 |
| --- | --- | --- | --- |
| 个人 `locklark/personal/items/v1` | 根 `username` | Username | text |
| 个人 v1 | 根 `password` | Password | password |
| 个人 v1 | 根 `otp` | OTP | otp-configuration |
| 内置合成原生演练 v1 | 根 `password` | Password | password |
| 内置合成原生演练 v1 | `ops/otp-demo` | OTP | otp-configuration |

演练描述符 profile 为 `locklark/synthetic/native-fixture/v1`，仅标识现有固定布局，不改变已有存储格式。不会把 `otp-demo` 改为个人 `otp`。文档没有普通字段映射，也没有附件回退。OTP 类型表示存储的种子/配置，不表示已生成一次性码；类型来自固定布局声明，不校验私有字段值是否为有效配置，空值也保持字段身份。text 不是公开数据或免授权标记。

这些纯函数不验签、不建立来源/新鲜度、不提供权限。Binding 是可构造的普通元数据，不能把来自 Agent/IPC 的该结构当成授权证明；实际使用仍须在同一可信事务中重新认证布局、条目、版本、主体和操作权限，并先持久记录审计意图。调用方须提供同一快照的不可变输入，不能并发修改。此次无新增 CLI/MCP 原值入口、字段读取或执行路径，没有把生产事务与披露审计标为完成。

## 失败先行与审计验收

先写 API 空实现和合成测试，运行 `go test -count=1 ./internal/reference ./internal/personal ./internal/preview -run 'TestCheckTarget|TestBind|TestProjectionTracksRealPersonalAuditRevision|TestFixtureReferenceBindsVerifiedSnapshotAndAudit'` 实际失败：规范目标、三种个人槽位、两种源字段槽位、未知 profile/缺失修订分类及真实加密来源绑定均不满足。之后实现并转绿。这是新增能力的失败测试，不声称空实现是已有生产漏洞。临时日志为 `/tmp/locklark-validation/binding/red.log`，临时目录不保证长期保留。

负例覆盖显示名和大小写变体冒充规范 ID、区段错配、文档、跨布局目标、旧修订、未知布局、缺失修订、重复字段目录和容量超限。绑定序列化扫描合成用户名、密码、OTP、文件名、附件标记均未出现；改变或清空字段值不影响绑定。模糊测试验证只有精确字段及版本能成功，其余按未知/旧版本拒绝。

审计正例扩展已有真实加密回归，不另造签名来源：个人库改名后绑定当前 `item.edit.title` 的事件摘要，恢复后绑定新账本 `item.restore` 摘要，两次均拒绝上一目标。演练第 2/3 代快照先验签/解密，再绑定源字段与快照签名；改名/OTP 轮换后旧快照目标拒绝，现有 VerifyAudit 核对独立 witness 检查点与全部事件。测试无并发写者；个人回归的 List/读回仍是分开的验证调用，不能据此宣称生产同一事务已实现。绑定本身无 I/O 或披露事实，没有生成“已用钥”的虚假审计事件。

## 实跑检查

Cloud Linux，Go 1.26.8、Bun 1.4.4、PyKeePass 4.2.0；下表 go 为 `/tmp/locklark-tools/go/bin/go`，测试产物目录为 `/tmp/locklark-validation/binding`。

| 检查 | 实际命令与结果 |
| --- | --- |
| 切片单测 | 上述失败先行命令实现后通过，含真实加密改名/恢复与快照审计回归 |
| 全仓 Go | 设置 `LOCKLARK_TEST_BUN=/tmp/locklark-tools/bun-linux-x64/bun`、`LOCKLARK_TEST_PYKEEPASS=/tmp/locklark-tools/python/bin/python`，`go test -count=1 ./...` 通过；preview 84.492 秒，含独立 KDBX 互操作和 Bun 子进程 |
| 定向 race | `go test -race -count=1 -timeout=5m ./internal/reference ./internal/personal ./internal/preview -run 'TestCheckTarget|TestBind|TestProjectionTracksRealPersonalAuditRevision|TestFixtureReferenceBindsVerifiedSnapshotAndAudit'` 通过，分别 1.046、28.497、20.070 秒；仅本轮相关测试 |
| 模糊测试 | `go test ./internal/reference -run '^$' -fuzz=FuzzCheckTarget -fuzztime=15s -parallel=2` 通过，677430 次执行，3 个新增 interesting 输入 |
| 静态/模块 | `go mod verify`、`go vet ./...`、`git diff --check` 通过。vet 首次发现新测试两处跨包结构体未命名字段，已改为命名字段并重新通过 |
| 个人 PTY | 构建 `locklark` 后，`python3 scripts/personal_acceptance.py /tmp/locklark-validation/binding/locklark` 通过：错误恢复材料、损坏备份、已有目标不发钥/不留库；FIFO/旧格式/迟到目标、建库和跨进程重开回归通过 |
| Bun/MCP | `bun test ./plugins/github-pull-reader` 2 pass/0 fail；Bun 加入 PATH 后，`python3 scripts/mcp_acceptance.py /tmp/locklark-validation/binding/locklark` 通过 |
| Windows 编译 | 分别对 `./internal/personal`、`./internal/preview` 运行 `GOOS=windows GOARCH=amd64 go test -c -o ...`，两份测试包均通过，仅编译 |
| macOS 编译 | 分别对上述两包运行 `GOOS=darwin GOARCH=arm64 go test -c -o ...`，两份测试包均通过，仅编译 |

未验收原生 Windows/macOS、移动真机、硬件断电、真实 1Password/op 对照、独立密码评审。此前 preview 全包 race 超时未被本轮定向检查替代，仍不能写为完整通过。

## 远端门槛、复核与下一项

实现 [run 41900091647](https://github.com/jihuayu/locklark/actions/runs/41900091647) 中，[Windows job 126819864165](https://github.com/jihuayu/locklark/actions/runs/41900091647/job/126819864165) failure；[Ubuntu job 126819864341](https://github.com/jihuayu/locklark/actions/runs/41900091647/job/126819864341) cancelled。两个 job 没有测试 steps；本轮读取 annotations，Windows 明确报告近期付款失败或需提高 spending limit，Ubuntu 因矩阵 Windows 失败被取消。无远端测试通过证据，保留 PR，不绕过规则合并。

本轮自查了完整目录验证、规范 ID 匹配、区段隔离、版本比较与秘密流向，未发现新增问题；自查不是独立复核。读取 PR reviews/review comments 均为空，没有可关闭待复核项的新意见。本切片、先前恢复/投影切片和 `4932c8d..a0d8ab1` 等既有待复核范围继续保留。main 未动，未 squash，全部设计与逐平台验收仍未完成，持续目标保持进行。

下一项可独立开发：纯 Go OTP 配置校验与 RFC 6238 向量，区分存储配置和生成码/有效期，拒绝不支持参数且错误不回显种子。生产人工字段披露仍待已有 PR 的检查/独立复核完成并合并，再从最新 main 接入可信事务、身份与审计。
