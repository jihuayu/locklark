# 审计历史性能验收

日期：2026-11-07；起点 `main` `41e31f7`（PR #45）。实现分支 `codex/audit-history-performance`，对应 [#35](https://github.com/jihuayu/locklark/issues/35)。主代理设计算法和独立验收，外部 DeepSeek worker 实现并跑首轮测试，另一个只读 worker 独立审查验证路径。算法及未改变的威胁模型见[设计](audit-history-performance-design.md)。

## 安全与等价性

真实 bbolt 测试覆盖缓存预热后修改中间事件而保持 tip/count/last 不变、删改/重排/截断/增加/嵌套事件、错误 tip/快照、恢复归档篡改、另一 Session 的合法尾部及修订更新、未提交回滚、返回 map 可变性、锁库/重开/迟到发布、缓存不保留秘密、完整审计和备份恢复结果。预热读取仍遍历全部历史密文。

- worker 全 personal 包：240.126 秒；相关 cache/篡改/恢复 race：159.548 秒；browserhost/desktop 整包：46.473/32.467 秒；personal vet 通过。
- 主代理独立 `go test -race ./internal/personal -run 'TestAuditCache(MiddleAndShapeTampering|RestoredChainTampering|AnotherSessionTailUpdatesRevisions|RollbackDoesNotPoison|LockDropsAndLatePopulationRefused)' -count=1`：通过，101.324 秒，日志 `/workspace/issue-completion-tasks/audit-security-independent.log`。
- 只读复核未证明所检查缓存路径存在验证绕过、错误修订、恢复链遗漏、回滚污染或锁库后可用性问题。其关于 `ReadAuthenticatedItems` 克隆 SSH/Passkey backing bytes 的建议未采纳：现有元数据消费者使用 presence 标志，实际密钥操作及 Passkey 元数据在专门认证事务内读取；本批明确注释该边界，不额外复制私钥材料。复核未执行测试，也不代表完整密码评审。

## 可复现基准

以一个真实设置事务生成 100、1,000、10,000 条签名/加密事件；只有三个 live items。恢复组实际经过两轮 Backup/Restore。冷组在每次操作前清除会话验证缓存，运行同一二进制的完整验证路径；不是旧发布版本的测量。暖组仍哈希所有历史和归档密文，并验证新增尾部。不存在硬编码延迟阈值。

```sh
go test ./internal/personal -run '^$' -bench '^BenchmarkAuditCache' -benchmem -benchtime=3x -count=1
```

worker 全矩阵见 `/tmp/audit-cache-bench.log`：一万事件下只读 662.837→22.541 ms，审计追加列表 668.759→23.775 ms，两段恢复历史 1511.976→42.244 ms。

主代理在实现冻结后独立运行一万事件组（同机同时有其他开发任务，绝对数值受负载影响）：

| 操作 | 强制完整验证 | 已验证前缀 | 冷/暖分配次数 |
| --- | ---: | ---: | ---: |
| `ReadAuthenticatedItems(false)` | 953.180 ms | 28.926 ms | 203,112 / 22,602 |
| `Session.List("active")`，每次仍追加审计 | 669.580 ms | 22.396 ms | 203,254 / 22,791 |
| 两段恢复历史的读取 | 1343.774 ms | 26.081 ms | 353,735 / 22,609 |

完整 ns/op、B/op、allocs/op 输出保存于 `/workspace/issue-completion-tasks/audit-benchmark-independent.log`。已有固定快照解密分配仍约 17 MB/op；没有把总分配或总耗时说成与历史无关。

## 集成门槛

Linux CI 运行相同的全矩阵基准，其他平台继续正常功能测试。最终必须当前精确 head 的六项检查成功，再正常合并关闭 #35。基准改善不代替篡改、恢复、并发和原有浏览器/桌面/CLI 验收。

## CI 中发现的独立测试缺陷

首个 PR head `30d7768` 的 Linux/Windows 检查失败于 PR #46 新增的 `TestFillQueuedInvalidCancelCannotRevoke`：把随机 capability 首位替换为 `f`，有 1/16 概率仍等于真实 capability。认证逻辑正确地接受了真实 token；这是测试构造错误，不能靠重跑算通过。修复在处理请求前将 fixture 首位固定为 `f`，再分别翻转第 0、15、31 位的低 hex bit，显式断言每个无效 token 与真实 token 不同，保留 epoch、排队批准及结果断言，未修改生产认证。

主代理独立重复该测试 32 次通过（15.143 秒），全部 queued-fill 测试 `-race` 通过（18.887 秒）；日志为 `/workspace/issue-completion-tasks/invalid-token-independent-32.log` 和 `invalid-token-independent-race.log`。最终合并仍要求修复后的同一个 head 六项 CI 全绿，旧 head 已失败/取消的检查不计入。

修复上述 token fixture 后，head `8af2689` 的 Windows 全包运行在 `TestBrowserOTPReadonlyRevalidationRejectsSecondSessionRevision` 失败（用时 3.30 秒）；Linux、macOS 通过。该语义测试把 control 期限设为 1 秒，却先执行准备、另一 Session 的实际编辑和读盘。授权入口先检查 control.Pending，过期会返回 ErrBrowserOTP，早于应检查的 ErrConflict 路径。外部 worker 用临时诊断强制跨过期限，复现 ErrBrowserOTP（不是缓存绕过），随后删除诊断文件。原 Windows 日志未打印具体 error，新的失败诊断会保留真实错误类别。

仅此测试改为有界 1 分钟 control 并 cleanup，调用授权前显式要求 Pending；仍严格要求 ErrConflict 和前后持久状态逐字节一致。生产 OTP 的 1.5 秒披露预算、cap bounds、时钟和专门的过期测试均未改变。worker 定向重复 16 次通过（其中多次超过旧 1 秒期限），7 类持久化/绑定/取消测试通过；主代理独立将此测试及另一 Session 审计尾部测试 `-race -count=3` 跑通（62.706 秒）。见 `/workspace/issue-completion-tasks/audit-otp-revision-independent-race.log`。再次要求最终新 head 的完整六检查；未将旧 head 的部分绿色结果拼接为最终证据。
