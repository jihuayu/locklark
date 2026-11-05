# 个人 CLI 受控字段披露

## 基线与范围

从已合并 PR #1 的远端 main `8c97e8537e1b5659a696339a02ff83122b6745b5` 接续，分支 `codex/personal-disclosure`。本轮开始时工作区只有初始提交，已通过 fast-forward 保留完整主线实现，没有重建预览。

新增 `personal reveal-login --file PATH --id ID --revision REV --field username|password`。必须从真实交互终端输入因素并明确确认；字段只显示于已检查为终端的 stderr。stdout 仅有无秘密回执。提示标明 ID、版本、字段及终端历史留存风险；用户输入 `SHOW` 才开始认证事务。

同一 bbolt Update 事务完成因素认证、快照签名、完整审计验证、原生登录及稳定 ID/版本定位。先提交签名且独立加密的 `item.reveal.FIELD` 意图，再关闭数据库并输出 JSON 转义值。意图含真实条目基准修订、自动生成的本机会话及 UTC，不保存原值或调用者的未知身份。`intent` 不推进条目修订。未知 ID 与旧版本分别记 `not-found`、`conflict`；不能解锁或损坏审计时不记可信事件。

短写或 writer 错误返回固定错误，不传播可能携带秘密的 writer 文案，不发成功回执。部分输出无法撤回；持久事件始终为 `intent`，不声称已交付。崩溃发生在提交与显示之间时亦保留这种未知状态。

## 失败先行与验证

先加入两个核心测试，运行 `go test ./internal/personal -run TestReveal -count=1`，编译因缺失 `RevealTarget` / `RevealLogin` 等接口失败；原始日志 `/tmp/locklark-validation/reveal-red.log`（临时运行证据）。初次实现后，含 ESC 的测试样例被既有 KDBX XML 字符校验拒绝，改用实际允许的制表符、引号和换行验证编码，未放宽库格式校验。

新增回归涵盖：

- 输出回调从另一事务读到已经提交的签名意图，回执的会话/摘要与事件一致；显示正确字段且不改变条目修订。
- 错误因素、未知 ID、过期修订、未支持字段、损坏审计全部零输出。
- 在完整事务回调后注入错误并回滚：审计无残留、字段无输出。这是事务失败模拟，不是实际磁盘满/断电验收。
- 输出报错和短写不返回成功回执；writer 提供的秘密错误文案不传播。
- 并发编辑/读取要么显示原指定修订，要么报冲突，不能显示新版本冒充旧版；包含披露意图的备份可恢复，恢复后旧修订拒绝、新修订可取值。
- 真实 PTY 的确认、取消/中断、因素失败、目标失败、密码/用户名选择、普通 stdout 隔离及审计秘密扫描。Windows ConPTY 同一验收已接入 CI；是否实际通过以对应远端运行结果为准。

## 实跑检查与独立复核

实现提交 `adf810c76678e676c809bc0696731a0eaba643b2`，PR [#2](https://github.com/jihuayu/locklark/pull/2)。以下本地命令均通过：

- Go 1.26.8，设置 `LOCKLARK_TEST_BUN=/tmp/locklark-tools/bun-linux-x64/bun`、`LOCKLARK_TEST_PYKEEPASS=/tmp/locklark-tools/python/bin/python` 后执行 `go test -count=1 ./...`（包括独立 PyKeePass 互操作与 Bun 插件）。
- `go test -race -count=1 ./internal/personal ./cmd/locklark`，两个包分别 401.416s / 141.661s。
- `go vet ./...`、`go mod verify`、`git diff --check`；`bun test ./plugins/github-pull-reader`；`python3 -m unittest discover -s scripts -p test_personal_windows.py`。
- 构建实际二进制后运行 `scripts/personal_acceptance.py`、`scripts/mcp_acceptance.py` 和 `scripts/disclosure_acceptance.py`，均通过。
- `GOOS=windows GOARCH=amd64 go build ./cmd/locklark` 与 `GOOS=darwin GOARCH=arm64 go build ./cmd/locklark`（仅交叉编译）。

用户指定的 `gpt-6-luna` / `max` 独立审查了存储事务、事件验证、恢复兼容、CLI 终端边界和新增测试，独立实跑 personal/CLI 全包测试（71.531s / 13.451s）、构建、披露 PTY 和 diff 检查通过。未发现事务/认证主路径阻塞缺陷；提出 Unicode 格式控制字符显示风险、顶层 help 遗漏，以及恢复历史需要明确断言披露意图。

三项均已补齐。Unicode 回归先运行失败，原因 `Unicode control reached terminal unescaped`，日志 `/tmp/locklark-validation/unicode-red.log`；随后新增 Cc/Cf 转义，补充 C1、双向文本、零宽和非 BMP 标签字符的实际加密库读取测试，要求 JSON 解码无损、终端不含原始控制字符且保留普通中文/emoji。恢复回归明确验证指定 ID/修订的 intent 恰好保留一次。

远端运行 [41949948920](https://github.com/jihuayu/locklark/actions/runs/41949948920) 对应首个实现提交，Ubuntu/Windows 均成功，包括真实 Windows ConPTY 披露验收。最终修正提交的 SHA、复核结论和远端检查链接记录在 [PR #2](https://github.com/jihuayu/locklark/pull/2) 正文与 Checks；合并时须核对该 PR 最终 head，不用先前 head 的成功代替最终检查。Windows ConPTY 合并两条输出流；独立 stdout 零原值检查由 Linux PTY 场景覆盖。

## 保留边界

仅本人交互 CLI 的两个原生字段，不实现通用引用、OTP、`op read/run/inject`、MCP/Agent 原值权限或系统生物认证。终端检查不能阻止拥有同用户权限的进程创建伪终端；Go 字符串和第三方解码内存不保证彻底擦除。整库与本地审计一起回滚仍需外部见证。外部密码评审、真实 1Password 对照、macOS 原生及干净机器/硬件断电验收未由本轮本地测试替代。

新增审计动作会让旧读取器明确拒绝；不得宣称向旧 CLI 降级兼容。现有备份格式没有改变，新版仍接受此前合法历史。

下一项可从最新已验收主线接通受控生成密码并保存，或将引用解析绑定到同一认证事务。远程原值披露须继续遵循单独的 deliver 授权与平台隔离设计。
