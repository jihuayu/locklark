# 个人恢复安全修复验收与交接

## 接手状态

接手并再次 fetch 核对：`origin/main` 为 `3901bc8d8c91c8da039fa02d83e1521746c3c5aa`；[PR #1](https://github.com/jihuayu/locklark/pull/1) 开放、未合并，base 为 main，真实 head 为 `codex/first-preview` / `2705a84ff34a0c66e50eed84a86702f6792cf18e`，与 `refs/pull/1/head` 相同。原 PR 有 40 个提交、125 个变更文件；main 仅有初始 README。继续原分支，没有从空 main 重做，没有覆盖后续提交。

恢复修复代码提交：`43c6732`。完整持续目标见 [development-goal.md](development-goal.md)。以下只记录本次 Cloud Linux 实跑结果，历史 Windows/WSL 结果仍在 progress 原记录中，不替代本次 Windows 验收。

## 先失败的证据

- 用 `2705a84` 构建旧二进制，再运行新增的 PTY 错误恢复码负例，失败为 `RuntimeError: failed restore issued a new Secret Key`。驱动从真实终端读取新钥模式即失败并结束进程，不打印终端中的测试秘密。
- `TestRecoveryRejectsResignedHistory` 在修复前失败：`accepted an attacker-replaced and re-signed entire history with the original offline material`。攻击测试使用全部解密因子，替换所有历史事件及公钥、重签事件与清单并重新加密。
- `TestRecoveryLimitsAreNotCredentialErrors` 在修复前失败：历史超限返回 `invalid personal vault, unlock factors or journal`。

这些失败实际发生于实现前；测试随后随 LLR2 API 调整。原始本次运行日志在执行环境 `/tmp/locklark-validation/restore-order-red.log` 和 `recovery-trust-red.log`，临时环境可能不长期保留。此文保留失败结论与复跑入口，不保存凭据、完整终端画面或备份样本。

## 最终行为及负例

`PrepareRestore` 完成旧因素、独立检查点、AEAD、清单和历史签名、条目格式验证，预检目标及父目录，然后 CLI 才生成/提示新 Secret Key。已验证的载荷留在内存，不在用户确认后重读可被替换的来源。发布仍使用已有同目录无覆盖操作。

`PrepareBackup` 在源库审计事务中准备 `backup.prepare` 事件与签名载荷，将版本 2 备份完整写入并同步临时文件后，才生成供单独保存的 `LLR2-<秘密>-<SHA-256 检查点>`。用户确认材料后发布备份。检查点固定整份文件的原始字节，因而固定其中的源公钥、全历史和条目；不是从备份自己的公钥重新建立信任，也不代表最新状态。文件重排或重新格式化同样拒绝。

真实 PTY 脚本已确认：错误恢复码、损坏备份、已有目标均无新钥、无成功 JSON、无恢复库或残留临时文件。旧 LLR1 材料与版本 1 备份明确报告 legacy；并发进程在新钥确认前创建目标时，原目标字节保留。正例包含把原库移走后恢复、重开、条目 ID 保留和归档历史读回。

Go 测试补查：原检查点拒绝攻击者重签的完整替代历史；替代包配上攻击者自行生成的检查点可通过验证，证明负例确实可解密且签名有效。另测预检后来源被替换时仍发布原已验证载荷、迟到目标拒绝覆盖、缺检查点拒绝、LLR1/版本 1 不降级、历史 33 段超限、备份文件/明文容量超限及其独立错误类型。既有恢复测试继续验证错误因素、两次恢复、新身份与新代次、原设备打不开新版、原历史签名逐字保留。新库 `vault.restore` 与 `item.restore` 仍在创建事务中写入，恢复材料与条目值不进审计。

## 本次实际检查

工具链为 Go 1.26.8、Bun 1.4.4、PyKeePass 4.2.0；全部在 Cloud Linux 执行。命令中的测试工具绝对路径为本次临时安装位置。

| 检查 | 命令与结果 |
| --- | --- |
| 模块 | `/tmp/locklark-tools/go/bin/go mod verify` 通过 |
| 静态检查 | `/tmp/locklark-tools/go/bin/go vet ./...` 通过 |
| Go 全量 | `LOCKLARK_TEST_BUN=/tmp/locklark-tools/bun-linux-x64/bun LOCKLARK_TEST_PYKEEPASS=/tmp/locklark-tools/python/bin/python /tmp/locklark-tools/go/bin/go test -count=1 ./...` 通过，包括真实 Bun 子进程和独立 KDBX reader/writer |
| Bun | `/tmp/locklark-tools/bun-linux-x64/bun test ./plugins/github-pull-reader`：2 pass、0 fail |
| 个人库终端 | 构建后 `python3 scripts/personal_acceptance.py /tmp/locklark-validation/current` 通过；包括上述新负例与并发发布 |
| MCP 进程 | `PATH=/tmp/locklark-tools/bun-linux-x64:$PATH python3 scripts/mcp_acceptance.py /tmp/locklark-validation/current` 通过；恢复/幂等/签名回执不重复执行 |
| Windows 编译 | `GOOS=windows GOARCH=amd64 /tmp/locklark-tools/go/bin/go build -o /tmp/locklark-validation/locklark.exe ./cmd/locklark` 通过，仅交叉编译 |
| 补充独立实现 | 设置上述 `LOCKLARK_TEST_PYKEEPASS` 后运行 `go test -v -count=1 ./internal/vault -run TestKDBXIndependentPeer`，实际 PASS；一次未设变量的补查为 SKIP，未将其算作通过 |
| 补丁检查 | `git diff --check` 通过 |

竞态检查 `go test -race -count=1 ./internal/personal ./internal/preview` 中个人库通过（157.664 秒）；扩大到未修改的预览包时触发默认整包 10 分钟超时，不能标为全包竞态通过。超时栈在 `TestSignedPullApprovalToSingleRecordedReply` 的 PBKDF2 计算中，未报告数据竞争。随后实际运行 `go test -race -count=1 -timeout=5m ./internal/preview -run '^TestSignedPullApprovalToSingleRecordedReply$'` 通过（44.164 秒）；这不能替代预览全包竞态验收，不修改或降低密码派生参数来加快测试。全量非竞态测试已通过（预览包 104.337 秒）。

## 合并门槛与下一项

尚未完成本切片的独立代码复核；已询问采用单独审查 agent 或由用户安排外部审查，等待选择。自己的复查、负测和 PyKeePass 互操作都不等于独立代码/密码评审。已有 `4932c8d..a0d8ab1` 复核欠项也继续保留。

接手时 GitHub [run 41847695945](https://github.com/jihuayu/locklark/actions/runs/41847695945) 未启动测试，check annotation 原文为：`The job was not started because recent account payments have failed or your spending limit needs to be increased. Please check the 'Billing & plans' section in your settings`。main 保护规则 API 返回 403（`Resource not accessible by integration`），rulesets 返回空列表；不能据此认定 main 不受保护。推送后须核对新 head 的实际检查；有阻塞就保留 PR，不尝试绕过、管理员合并或直接推 main。

修复和目标文档已快进推送至 `dd1df67fa54ad2f61baac658169b226339a2cd50`。本次新 [run 41851825922](https://github.com/jihuayu/locklark/actions/runs/41851825922) 仍未启动测试；已读取 check `126649857083` 的 annotation，原因为同一付款/额度限制。PR 保持开放；main 未修改。

Cloud 本次未运行 Windows ConPTY/macOS、iOS/Android 真机、物理新机/硬件断电、真实 1Password 对照、真实 GitHub 上游委托，也没有外部密码评审。这些保持未验证。

满足独立复核及远端检查后才 squash 合并 PR #1。重新 fetch main，从更新后的 main 建 `codex/` 分支实现受控人工单字段披露，验收见 development-goal；不让普通 MCP Agent 获得原值读取能力。
