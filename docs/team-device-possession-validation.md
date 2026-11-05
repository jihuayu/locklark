# 团队设备双钥持有证明

基线 main `19f6e5a`（PR #16 JSON 注入），分支 `codex/team-device-possession`。这是 `internal/directory` 的 Go API 增量，还不是团队 UI、手机配对、角色权限执行或网络同步服务。

新目录使用 `NewConfigWithPossession(pins)`。强制持有证明策略以独立域散列进入 scope，同样的公钥 pins 通过旧 `NewConfig` 得到不同 scope，不能读取或写入新目录；旧 API 继续表示旧的 owner 断言协议。此处没有已有目录的原地升级/撤销历史迁移工具，不能用新建目录冒充既有目录升级。

1. 可信 owner 用 `IssueChallenge` 给出 Enrollment（精确 parent checkpoint、member ID、device ID、age 与 Ed25519 公钥）。32 字节随机 nonce 只加密给该 age recipient；owner 签名覆盖 enrollment、nonce 摘要和密文。
2. 设备调用 `AnswerChallenge`，必须提供独立确认的 expected Enrollment，而不是照抄不可信挑战。验证 owner 签名和双方 scope/身份后，检查所持 age 与 Ed25519 私钥分别对应两把公钥，解密 nonce、验证摘要，再签整个挑战和响应。
3. `Build(..., admissions...)` 将证明纳入 owner 签名。持久 `Create/Commit` 在同一目录事务内要求每个新设备恰有一份对应证明，拒绝重复/多余/错 parent 的证明；已有设备不需要每次更新都在线回应。历史 `Read` 同样重做新增设备证明检查，不只信任写入入口。

证明公开的是一次性随机 nonce 和公钥元数据，不包含设备私钥或库值。它依赖可信 owner 诚实产生不可预测挑战，不能抵御 owner 与设备串谋，也不能证明私钥只存在于一台物理机器或两把钥匙不可复制。它不授予成员角色或发布权限；已有 owner/publisher/sequencer 约束仍然生效。

挑战绑定当前 parent；目录更新后未消费证明失效。同一 parent 下的并发提交只有一个成功。没有墙钟 TTL，也不把证明称为完整邀请/审批租期。身份和公钥撤销墓碑照常校验，即便旧设备提供新的正确证明也不能复活已退役身份。全文件/远端最新性仍需独立可信检查点；这项证明不解决恶意中继扣留新版本。

失败先行日志 `/tmp/locklark-validation/possession-red.log`。测试覆盖单钥不足、签名/密文/nonce 篡改、成员/设备/parent 重绑定、无证明的 genesis/新增设备拒绝、策略 scope 防降级、深拷贝、撤销墓碑、失败事务零回执、并发单赢家，以及重签历史剥离证明仍拒绝。独立子进程仅凭公开 pins、checkpoint 和数据库路径重开验证，不接收任何私钥。故障注入断言遵守既有固定 `ErrStorage` 契约，不透出 updater 内部错误。

Luna/max 已独立审阅当前实现，运行定向/整包 directory 测试、vet 与 diff 检查，无阻塞项。最终 head、全仓/race 与双平台 CI 证据记录在本批 PR。
