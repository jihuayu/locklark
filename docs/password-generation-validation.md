# 密码生成核心：验收与交接

## 接手与发布

本轮 fetch 最新 main、原分支和 PR ref 后，main 为 `3901bc8d8c91c8da039fa02d83e1521746c3c5aa`，工作分支为 `codex/first-preview`，接手 head 为 `0d1cfc650dadc2b2ada723066b0480708309887a`。本地/远端/PR head 一致，工作树干净，未见其他开发测试进程。已重读 design、progress、development-goal 并核对远端差异；无新增 AGENTS 指令，不依赖 Ryugi。

[PR #1](https://github.com/jihuayu/locklark/pull/1) 仍开放、未合并。实现提交 `9d3bcb2d2c47f1e5899aa28e464ad6afc7797caa` 已普通快进推送原分支，提交前重新 fetch 未发现并发新 head。未覆盖后续提交、从空 main 重做、强推或修改 main。最终文档 head 由本文件所在提交与 PR 实际 head 确定，最终远端状态见 [PR checks](https://github.com/jihuayu/locklark/pull/1/checks)。

## 新能力与范围

`internal/password.Generate` 从标准库系统 CSPRNG 读取随机性，用 `crypto/rand.Int` 的拒绝采样逐位选择字符，不用随机字节直接对字符数取模。无新增依赖；已检查当前 Go 1.26.8 的 rand.Int 源码，向其传入的 reader 确实用于采样。生产 API 不提供自定义 reader、种子或降级随机源；私有 reader 钩子仅用于合成向量与故障注入。

- 默认策略为 24 位、62 个大小写字母/数字，允许这些字符但不强制每类至少出现一个。自定义字符集须由 2–94 个不同的可打印 ASCII 字节组成，不含空格或控制字符；区分大小写，不去重、不规范化或替换输入。
- 长度最多 256，并须达到至少 128 位组合熵。Validate 用精确整数 `alphabetSize^length` 的 BitLen 计算向下取整的 log2，避免浮点边界上调。Profile 只含长度、字符数和熵下界，不含密码或其摘要；该值以独立均匀 CSPRNG 抽样为前提，不是对单个输出的随机性检测。
- 策略先验证再读取随机源；格式、容量与低熵分别为 ErrInvalid、ErrLimit、ErrEntropy。随机源可返回错误、耗尽或拒绝采样总字节预算耗尽时，返回固定 ErrRandom 与零 Secret，不回显提供者错误，不交付部分前缀或切换备用源。
- 总采样预算为 `length*64` 字节。它限制连续被拒绝索引的读取量，不声称能中断阻塞的操作系统随机源；本轮故障注入不等于硬件故障验收。
- Secret 的普通 fmt、JSON、slog 文本/JSON 均脱敏，反序列化拒绝；只有显式 Value() 暴露敏感字符串。Profile 返回副本。内存中的同进程恶意代码不在此保护范围，也不承诺 Go 字符串副本被可靠清零。

| 合成策略 | 实际保守熵 | 结果 |
| --- | --- | --- |
| 默认 24 位、62 字符 | 142 bit | 接受 |
| 128 位、2 字符 | 128 bit | 接受 |
| 127 位、2 字符 | 127 bit | ErrEntropy，无输出 |
| 81 位、3 字符 | 128 bit | 接受 |
| 80 位、3 字符 | 126 bit | ErrEntropy，无输出 |
| 20 位、全部 94 个可打印字符 | 131 bit | 接受 |

本子集未实现类别配额、单词口令、Unicode、网站专属规则、剪贴板或产品生成界面，不能称为完整 1Password/op 生成器兼容。没有新增 CLI/MCP/桌面/Agent 明文输出入口或修改存储格式。未来可信宿主仍须认证主体和用途，在披露前持久记审计意图；本函数不提供这些权限或审计事实。

## 失败先行与审计验收

先写 API 空实现与合成测试，运行 `go test -count=1 ./internal/password ./internal/personal -run 'TestDefaultPolicy|TestExactEntropy|TestRejectionSampling|TestRandomFailures|TestSecretRedacts|TestConcurrentSystem|TestGeneratedPassword'` 实际失败：默认/熵约束、拒绝采样向量、脱敏、并发与加密重开正例未满足。实现后转绿。这是新增能力的失败测试，不把空实现描述为已有生产漏洞；临时日志 `/tmp/locklark-validation/password/red.log` 不保证跨环境保留。

采样向量枚举 0–255 的全部字节，分别验证三字符和 62 字符策略的等频接受序列，证明拒绝的索引没有被取模映射回来。这不是统计随机性测试。负例覆盖重复字符、空/单字符集、控制字符、Unicode、超限、低熵、nil/EOF/中途错误与始终拒绝的 reader；无效策略通过会 panic 的 reader 证明未读取随机性。32 个 goroutine 并发运行真实系统 CSPRNG 路径。

审计回归只创建新的合成个人库：真实生成值经既有 AddLogin 事务保存，按返回的稳定条目 ID 解密重开核对；数据库字节中没有明文值，已验签审计中有该 ID 的 `item.add/succeeded`，序列化审计/Secret/Profile 不含生成值或用户名。既有 item.add 事件只证明新增条目，不冒充专门的生成或原值披露事件；本轮没有实现产品生成/披露审计。

## 实跑检查

Cloud Linux，Go 1.26.8、Bun 1.4.4、PyKeePass 4.2.0。下表 go 为 `/tmp/locklark-tools/go/bin/go`；测试产物目录为 `/tmp/locklark-validation/password`。

| 检查 | 实际命令与结果 |
| --- | --- |
| 切片测试 | 上述失败先行命令实现后通过，含真实系统随机源、精确熵边界、拒绝向量及加密保存/签名审计 |
| 全仓 Go | 设置 `LOCKLARK_TEST_BUN=/tmp/locklark-tools/bun-linux-x64/bun`、`LOCKLARK_TEST_PYKEEPASS=/tmp/locklark-tools/python/bin/python`，`go test -count=1 ./...` 通过，含 KDBX 独立实现互操作与 Bun 子进程；preview 82.725 秒 |
| 定向 race | `go test -race -count=1 -timeout=5m ./internal/password ./internal/personal -run 'TestDefaultPolicy\|TestExactEntropy\|TestRejectionSampling\|TestRandomFailures\|TestSecretRedacts\|TestConcurrentSystem\|TestGeneratedPassword'` 通过，分别 1.062 秒、8.539 秒，仅本轮相关测试 |
| 模糊测试 | `go test ./internal/password -run '^$' -fuzz=FuzzGeneratePolicies -fuzztime=20s -parallel=2` 通过，786630 次执行，检查策略拒绝、零部分结果、字符/长度边界、确定性和敏感 JSON |
| 静态/模块 | `go mod verify`、`go vet ./...`、`git diff --check` 通过 |
| 个人真实 PTY | 构建 locklark 后，`python3 scripts/personal_acceptance.py /tmp/locklark-validation/password/locklark` 通过；错误恢复材料、损坏备份、已有目标不发钥/不留库，FIFO/旧格式/迟到目标及建库/重开回归通过 |
| Bun/MCP | `bun test ./plugins/github-pull-reader` 2 pass/0 fail；Bun 加入 PATH 后，`python3 scripts/mcp_acceptance.py /tmp/locklark-validation/password/locklark` 通过 |
| Windows 编译 | 对 `./internal/password`、`./internal/personal` 分别运行 `GOOS=windows GOARCH=amd64 go test -c -o ...`，通过；仅编译 |
| macOS 编译 | 对上述两包分别运行 `GOOS=darwin GOARCH=arm64 go test -c -o ...`，通过；仅编译 |

本轮未运行原生 Windows/macOS、移动真机、硬件随机源故障/断电、真实 1Password/op 对照或外部密码评审。此前 preview 全包 race 超时的缺口仍保留，本轮定向检查不替代它。

## 远端、复核与下一项

实现 [run 41918992994](https://github.com/jihuayu/locklark/actions/runs/41918992994) 的 [Ubuntu job 126886160658](https://github.com/jihuayu/locklark/actions/runs/41918992994/job/126886160658) 和 [Windows job 126886160254](https://github.com/jihuayu/locklark/actions/runs/41918992994/job/126886160254) 均 failure、零 steps。本轮读取两个 check annotations，均明确报告近期付款失败或需提高 spending limit，job 未启动。没有远端测试通过证据，保留 PR，不绕过规则合并。

已自行复查整数熵/范围、标准库采样、错误与部分值流向、格式化及加密/审计回归，未发现新增问题；自查不是独立复核。PR reviews/review comments 无新意见；新切片、此前恢复/引用/TOTP 和 `4932c8d..a0d8ab1` 等已标待复核范围均继续保留。main 未动，未 squash，全部设计与逐平台验收尚未完成，持续目标保持进行。

下一项可独立开发：通用 1PUX 只读预检，限制归档路径/大小/重复项，报告类别数量和不可映射语义，不改写源或回显私有值。产品生成与人工取值仍待既有 PR 检查/独立复核满足并合并后，从最新 main 接入可信事务、身份和披露意图审计。
