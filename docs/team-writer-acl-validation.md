# 团队数据写入权限

从 main `a4adaac`（PR #17 已经 Luna/max 与 Ubuntu/Windows CI 合并）接续。`NewConfigWithWriterACL(Pins)` 建立独立策略 Scope，强制双钥入网证明，并允许当前 writer 成员的设备提交数据更新。`NewConfig` 与 `NewConfigWithPossession` 的授权规则保持原样；两者不能读取或降级此 Scope。没有旧目录迁移工具，不应通过新建目录丢弃历史墓碑来假装升级。

## 接口与授权

owner 仍使用 `Build` / `Freeze`，独占初建、成员及角色变更、撤销、冻结。`BuildUpdate(config, deviceSigningKey, parentReceipt, completeItems)` 从父回执推导完整 roster 和 age recipients，不接收调用方另传的成员列表。生成新的随机加密材料；设备签名绑定完整 proposal，包括 Scope、精确父检查点、代次、成员列表和密文摘要，snapshot 也由同一设备签名。writer 提案 `Owner` 为空、`AuthorDevice` 为设备 ID；两类作者互斥。新增字段采用 omitempty，旧 owner 提案的签名字节保持兼容。

签名自洽不等于有权写入。`Commit` 在同一 bbolt 事务中先重放全链并比较当前 head，再以已验证前态检查作者当时属于 writer、目录 active、完整 roster 不变、无入网证明且未冻结。`Read` 重放每条历史时也执行该检查，然后验证当前 snapshot；不能靠 reader 自行把提案里的 Role 改为 writer 取得授权。旧父、降级或撤销之前的提案不能继续提交；同父并发只有一个成功。

`Read` 返回的 `View.SnapshotSigner` 在整链和当前快照验证成功后赋值，owner 头是 pinned publisher，writer 头是获授权的设备公钥。消费者应将该值与 `View.Snapshot`、回执代次交给 `vault.OpenItems`；不能继续固定传 publisher。frozen 和失败结果没有 signer。writer 不需要 owner/publisher 私钥；reader 仍可离线解密全部已获得的密文。ACL 约束此目录的接受与历史验证，不能阻止已有明文的成员泄漏，也不能公开证明 age 信封仅包含规定收件人。

## 验证与边界

失败先行：`/tmp/locklark-validation/writer-red.log` 缺少 ACL API 与 signer 字段。真实 Ed25519/age/KDBX/bbolt 测试覆盖 writer 发布及全部成员解密、reader 绕过 builder 后以正确密钥签署完整快照仍被事务拒绝、降级后旧父及自提权拒绝、成员/角色/密钥篡改、作者双填/双空、writer 冻结与初建拒绝、旧策略拒绝新授权、事务回滚、并发 CAS、只持公开 pins 的新进程重读，以及带有效新 snapshot 和 sequencer 签名的历史自提权拒绝。冻结和失败读回不提供 signer。

命令：`go test ./internal/directory -count=1`、`go test -race ./internal/directory -count=1`、带 PyKeePass/Bun 的 `go test -count=1 ./...`、`go vet ./...`、`git diff --check`。本地结果、Luna/max 独立复核及最终精确 head 的双平台 CI 以本批 PR 证据为准；设计预审不计作实现复核。

本批是本地目录 API 的权限执行，无团队产品 UI、网络服务、远端新鲜度见证、离线冲突合并、per-item 权限或机器委托级联撤销。publisher/owner/sequencer 根轮换与灾后恢复仍待开发；writer 不能改变这些固定根。失败写入不返回成功回执，磁盘关闭失败仍保留结果可能已提交的语义；硬件断电未代验。
