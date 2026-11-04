# 恢复来源特殊文件拒绝：验收与交接

## 接手与范围

本轮重新 fetch 后，`origin/main` 为 `3901bc8d8c91c8da039fa02d83e1521746c3c5aa`；[PR #1](https://github.com/jihuayu/locklark/pull/1) 开放、未合并，真实 head、远端分支和 `refs/pull/1/head` 均为 `7054bf5ef2c1137aa390d06e273c5d68d64f575d`。本地工作树干净，无其他开发测试进程，未发现后续提交。继续 `codex/first-preview`，没有修改 main。

在已有恢复安全切片内补齐不可信文件类型的拒绝路径；没有越过合并门槛启动依赖新 main 的功能。实现提交：`888944e3ffbe75f4b2798cb0df98bcb9b3fa8edf`。完整目标仍见 [development-goal.md](development-goal.md)，先前检查点、旧格式及发钥顺序的验收仍见 [recovery-validation.md](recovery-validation.md)。

## 失败先行与修复

旧实现调用 `os.Open` 后才检查类型。无人写入的 FIFO（包括指向 FIFO 的符号链接）会在打开阶段等待，无法到达拒绝分支。

先增加并实际运行 `go test -count=1 ./internal/personal -run '^TestRestoreRejectsIdleFIFO$'`：`direct` 和 `symlink` 均在两秒期限内未返回，失败为 `untrusted FIFO blocked restore before file type validation`。测试打开一个临时对端，等旧实现退出后才结束，避免遗留阻塞 goroutine 和句柄。失败日志为本次临时环境 `/tmp/locklark-validation/fifo/red.log`；不保存终端秘密。

Unix 现在以 `O_NONBLOCK|O_NOCTTY` 打开来源，解码器在读数据前核验实际文件句柄为普通文件。文件名的预检查不能替代句柄检查，也不能单独防住路径替换。非 Unix 路径先检查文件类型，再打开并由解码器复核句柄；Windows 特殊文件和路径替换行为仍需原生验证，不能将其标为等价的非阻塞保障。

非普通文件报告独立的 `backup source must be a regular file`，仍然先于新 Secret Key 提示与目标预检。正常文件的符号链接继续接受原内容检查点验证。容量、恢复因素、历史签名与来源检查点逻辑没有降级。

## 本轮实际运行

工具链：Go 1.26.8、Bun 1.4.4、PyKeePass 4.2.0，执行环境为 Cloud Linux。下表的 `go` 为 `/tmp/locklark-tools/go/bin/go`。

| 检查 | 实际结果 |
| --- | --- |
| 新增 FIFO 单测 | `go test -count=1 ./internal/personal -run '^TestRestoreRejectsIdleFIFO$'` 修复后通过（0.002 秒）；补查竞态模式通过 |
| 模块/静态 | `go mod verify`、`go vet ./...`、`git diff --check` 通过 |
| Go 全量 | 设置 `LOCKLARK_TEST_BUN=/tmp/locklark-tools/bun-linux-x64/bun` 与 `LOCKLARK_TEST_PYKEEPASS=/tmp/locklark-tools/python/bin/python` 后，`go test -count=1 ./...` 通过；包含 Bun 真进程及独立 KDBX 读写 |
| 个人库竞态 | `go test -race -count=1 -timeout=10m ./internal/personal` 通过（139.086 秒） |
| 真实终端 | 构建 `/tmp/locklark-validation/fifo/locklark` 后，`python3 scripts/personal_acceptance.py /tmp/locklark-validation/fifo/locklark` 通过 |
| Bun | `bun test ./plugins/github-pull-reader`：2 pass、0 fail |
| MCP 子进程 | 将 Bun 放入该命令 PATH 后，`python3 scripts/mcp_acceptance.py /tmp/locklark-validation/fifo/locklark` 通过 |
| Windows 编译 | `GOOS=windows GOARCH=amd64 go build -o /tmp/locklark-validation/fifo/locklark.exe ./cmd/locklark` 通过，仅交叉编译 |
| macOS 编译 | `GOOS=darwin GOARCH=arm64 go build -o /tmp/locklark-validation/fifo/locklark-macos ./cmd/locklark` 通过，仅交叉编译 |

PTY 使用合成因素与真实终端，对无人写入 FIFO、FIFO 符号链接、目录及 `/dev/null` 确认非零退出、无新钥、无成功 JSON、无恢复库和残留目标临时文件。旧的错误因素、损坏备份、旧格式、已有与迟到目标、成功恢复及归档历史回归继续通过。

新增普通文件符号链接正例实际完成恢复，再读取签名审计，核对 `vault.restore` 与本次 `audit.list`。不可信文件类型在认证备份之前拒绝，不能为了记录拒绝而创建恢复库或信任未经验证的来源账本；已认证的恢复继续在创建事务中写审计。本轮没有将自己的检查或互操作测试标为独立代码复核。

## 合并门槛与未验证范围

独立代码复核尚未完成；先前恢复切片及 `4932c8d..a0d8ab1` 的独立复核欠项继续保留，不重复询问审查方式。GitHub 连接器查询本轮未返回，已用 `gh` 核对实际 PR 和检查状态。

接手 head `7054bf5` 的 [run 41852815563](https://github.com/jihuayu/locklark/actions/runs/41852815563) 仍未启动，已重读 check `126653360462` 的 annotation，仍为账户付款/额度限制。此既有阻塞不当作新进展通知；推送后另核对新 head，不把本地检查计作远端通过，也不尝试合并或绕过保护。

本轮未运行 Windows ConPTY/命名管道、macOS 终端、iOS/Android 真机、物理新机或硬件断电；未做真实 1Password 对照或外部密码评审。预览包全量竞态检查先前超时的限制仍见 recovery-validation，本轮未重跑，不能写为已通过。

下一项：完成已有恢复切片的独立复核及 Windows 原生文件来源验收；合并门槛满足后才 squash PR #1，再从更新后的 main 开 `codex/` 分支做受控人工单字段披露。仍无 Agent 原值读取接口。
