# TOTP 配置与计算核心：验收与交接

## 接手与提交

已 fetch 最新 `origin/main`、原分支和 PR head；main 为 `3901bc8d8c91c8da039fa02d83e1521746c3c5aa`，工作分支为 `codex/first-preview`，接手 head 为 `8d5d81d64ce0db7a46ce607a8dcf157862bb80d5`。本地/远端分支/PR ref 一致，工作树干净，未见其他开发测试进程。已重读 design、progress、development-goal，无新增 AGENTS 指令，不依赖 Ryugi。

[PR #1](https://github.com/jihuayu/locklark/pull/1) 开放、未合并；实现提交 `295e8c35601941ca02c13e4afd8c203ebbb5f0a7` 已普通快进推送原分支。提交前重新 fetch，未出现并发新 head。未覆盖后续提交、从空 main 重做、强推或修改 main。文档最终 head 由本文件所在提交与 PR head 确定，远端最终检查见 [PR checks](https://github.com/jihuayu/locklark/pull/1/checks)。

## 支持范围

`internal/totp` 是无 I/O 的 Go 计算模块，使用标准库 HMAC/SHA 实现 RFC 6238 的计数与动态截断，无新增依赖。`Parse` 返回不公开种子的不可变配置；`At` 必须传入 UTC Unix 秒，返回敏感 Code 与半开有效区间 `[From, Until)`，不暗读系统时钟。例如 30 秒步长在第 59 秒的区间是 `[30, 60)`。模块不证明时间可信、来源真实性、新鲜度或使用权限。

| 内容 | 本轮明确支持的子集 |
| --- | --- |
| 输入 | ASCII 大小写 Base32，规范填充或无填充；或 `otpauth://totp/<label>?secret=...` |
| 种子 | 解码后 16–64 字节；拒绝非规范尾位、错误填充、空格、非 ASCII 和短种子，不修补或猜测 |
| 算法 | SHA1、SHA256、SHA512；默认 SHA1，算法名 ASCII 大小写不敏感 |
| 码与步长 | 6 或 8 位十进制，默认 6 位；1–3600 秒步长，默认 30 秒；T0 固定为 Unix epoch |
| URI | 只允许 secret、algorithm、digits、period、issuer；属性名区分大小写，重复或编码别名重复拒绝；label/issuer 限长、无控制字符，若同时声明 issuer 必须一致，解析后不保留显示标签 |
| 时间 | 拒绝负时间和无法用 int64 表达完整有效区间的时间；失败返回零 Code |
| 容量 | 输入最多 4096 字节、编码种子最多 104 字节；容量错误独立返回 ErrLimit |

HOTP、Steam、二维码、非零 T0、7 位码、更长步长/密钥及未知参数均未支持；不忽略未知语义。数字参数必须为规范正十进制，不接受 `030`、正号或空值。错误只返回固定 ErrInvalid/ErrUnsupported/ErrLimit/ErrTime，不携带种子、URL 或标签。URI 解析不发起网络请求。

原内置演练中的 `MZXW6` 等短种子仍按既有格式原样保存和迁出；新核心明确拒绝计算，不静默放宽长度，也不改写旧数据。该限制须由未来导入预检向用户报告，不能将本子集称为完整 op/1Password OTP 兼容。

Config 和 Code 的普通 fmt、JSON 以及标准 slog 输出均脱敏，JSON 反序列化明确拒绝。Code 只有显式 `Value()` 返回敏感数字；这不是权限检查。参数与时间窗口可单独读取，参数返回副本。脱敏不能保护进程内的恶意代码、内存检查或调用者主动打印 Value；也不承诺 Go 管理内存中的种子副本被可靠清零。

未新增 CLI、MCP、桌面或 Agent 取码入口。生产持库端仍须在同一可信事务认证字段绑定、修订与主体，在计算/披露前持久提交审计意图；本模块不提供或替代这些门槛，也不产生“已披露”的事实。

## 失败先行与来源/审计验收

先写 API 空实现与合成测试，运行 `go test -count=1 ./internal/totp`，实际失败：RFC 向量、默认参数、规范输入、错误分类、脱敏和并发正例均未满足。随后实现并转绿；这是新增能力的失败先行，不声称空实现是已有生产漏洞。临时日志 `/tmp/locklark-validation/totp/red.log` 不保证跨环境保留。

已读取 RFC Editor 原文核对 [RFC 6238 Appendix B](https://www.rfc-editor.org/rfc/rfc6238#appendix-B) 的全部 18 个输出，按其参考程序使用 SHA1/256/512 对应的 20/32/64 字节公开密钥；同时核对 [RFC 4226 Appendix D](https://www.rfc-editor.org/rfc/rfc4226#appendix-D) 的 10 个计数向量。覆盖前导零、2038 年后及第 20000000000 秒；每个 RFC 4226 计数在区间起点/末秒均测试，下一秒切换。另测 1/60/3600 秒步长、负时间、int64 上界、空配置及 32 个 goroutine 并发只读。

拒绝测试覆盖编码错误、重复/编码别名参数、未知算法/参数、非规范数字、片段、空参数、URI 认证信息/端口、非法标签和 issuer 冲突。普通 fmt 的多种 verb、指针与值、JSON、slog 文本/JSON 均扫描公开合成种子及生成码；错误无原值回显，失败无部分配置或码。

来源回归仅为测试创建独立合成强种子，不修改内置场景：以既有原生布局封装真实加密快照、固定独立审计公钥和离线检查点。读回先验签/解密，再通过现有投影、源字段绑定及 VerifyAudit 验证检查点，按绑定 item ID 取测试配置，计算结果与 RFC 一致。审计/报告/绑定和默认序列化不含种子或码。检查点对应 `fixture.import` 来源事件，不能把它记作生产取码或披露事实；此次没有实现生产披露审计。

## 实跑检查

环境 Cloud Linux，Go 1.26.8、Bun 1.4.4、PyKeePass 4.2.0；下表 go 为 `/tmp/locklark-tools/go/bin/go`，产物目录为 `/tmp/locklark-validation/totp`。

| 检查 | 实际命令与结果 |
| --- | --- |
| 核心和来源 | `go test -count=1 ./internal/totp ./internal/preview -run 'TestRFC\|TestParseCanonical\|TestParseRejects\|TestSensitive\|TestConfigurationConcurrent\|TestTOTPAuthenticated'` 通过；来源测试改为在计算前核验 witness 后，定向单测再次通过 |
| 全仓 Go | 设置 `LOCKLARK_TEST_BUN=/tmp/locklark-tools/bun-linux-x64/bun`、`LOCKLARK_TEST_PYKEEPASS=/tmp/locklark-tools/python/bin/python` 后，`go test -count=1 ./...` 通过，含 KDBX 独立实现互操作与 Bun 子进程；preview 81.489 秒 |
| 定向 race | `go test -race -count=1 -timeout=5m ./internal/totp ./internal/preview -run 'TestRFC\|TestParseCanonical\|TestParseRejects\|TestSensitive\|TestConfigurationConcurrent\|TestTOTPAuthenticated'` 通过；core 1.173 秒、preview 6.815 秒。来源测试顺序调整后单独 race 再通过，4.693 秒 |
| 模糊测试 | `go test ./internal/totp -run '^$' -fuzz=FuzzParseAndGenerate -fuzztime=20s -parallel=2` 通过，708401 次执行；检查固定错误、无部分结果、支持范围、确定性、窗口与敏感序列化 |
| 静态/模块 | `go mod verify`、`go vet ./...`、`git diff --check` 通过；最后来源测试调整后 vet 再通过 |
| 个人真实 PTY | 构建 locklark 后，`python3 scripts/personal_acceptance.py /tmp/locklark-validation/totp/locklark` 通过；错误恢复材料、损坏备份、已有目标不发钥/不留库，FIFO/旧格式/迟到目标及建库/重开回归通过 |
| Bun/MCP | `bun test ./plugins/github-pull-reader` 2 pass/0 fail；Bun 加入 PATH 后，`python3 scripts/mcp_acceptance.py /tmp/locklark-validation/totp/locklark` 通过 |
| Windows 编译 | 对 `./internal/totp`、`./internal/preview` 分别执行 `GOOS=windows GOARCH=amd64 go test -c -o ...`，通过；仅编译 |
| macOS 编译 | 对上述两包分别执行 `GOOS=darwin GOARCH=arm64 go test -c -o ...`，通过；仅编译 |

本轮未运行原生 Windows/macOS、移动真机、硬件断电、真实 1Password/op 对照或外部密码评审。此前 preview 全包 race 超时的缺口仍保留，本轮定向 race 不替代它。RFC 向量不能替代独立代码/密码复核。

## 远端、复核与下一项

实现提交的 [run 41910241147](https://github.com/jihuayu/locklark/actions/runs/41910241147) 中，[Ubuntu job 126855565969](https://github.com/jihuayu/locklark/actions/runs/41910241147/job/126855565969) 和 [Windows job 126855565484](https://github.com/jihuayu/locklark/actions/runs/41910241147/job/126855565484) 均 failure、零 steps。本轮重新读取两个 check annotations，均明确为近期付款失败或需提高 spending limit，job 未启动。没有远端测试通过证据，保留 PR，不绕过保护合并。

已自行复查解析边界、HMAC/截断/整数运算、敏感格式化和来源测试，未发现新增生产问题；自查不是独立复核。本轮读取 PR reviews/review comments 为空，没有关闭既有待复核范围的新意见。本切片、先前恢复/引用切片和 `4932c8d..a0d8ab1` 等已标待复核范围仍未完成独立复核。main 未动，未 squash，全部设计和逐平台验收仍未完成，持续目标保持进行。

下一项可独立开发：基于 crypto/rand 的密码生成核心，明确字符集、长度和熵约束，采用无模偏差采样，随机源失败无部分结果、普通输出脱敏。人工取值/取码仍待 PR 检查及独立复核满足并合并后，从最新 main 接入可信事务、身份与披露意图审计。
