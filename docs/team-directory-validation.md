# 签名团队目录与可信本地排序核心

基线 main `c8bf4fdc72fab276ac5841ca778dd53b427046bc`（PR #11 已经 Luna/max 与双平台 CI 后合并）。本批 `internal/directory` 是供后续服务/客户端接入的持久化 Go 核心；没有团队 CLI、邀请界面、HTTP 排序服务或云同步，不把单机测试称为完整多人产品。

## 信任和协议

`NewConfig(Pins)` 接收独立可信来源提供的 team/vault ID、1..8 个 owner 验签公钥、独立 sequencer 公钥、独立 snapshot publisher 公钥。采用任意一位 owner 即可授权的 1-of-N 策略，不是多人门限。配置内部深拷贝，规范编码公钥、排序去重、角色密钥互异；版本化域、owner 数量和逐字段长度前缀生成 Scope。目录/中继不能自行提供或改写信任根。

`Build(config, ownerPrivate, publisherPrivate, parent, members, completeItems)` 从完整规范 roster 内部推导设备 age 收件人，调用现有 `vault.SealItems` 生成全新随机密钥的下一代密文，再由 owner 签 proposal。绑定 Scope、精确 parent version/hash、epoch=parent+1、active/frozen 模式、完整成员/设备公钥、完整 snapshot 摘要和 owner 身份。Proposal、receipt、head digest 和 snapshot digest 使用各自的 v1 域。协议结构体有固定 JSON 字段顺序；存储读取要求规范重编码逐字节一致，拒绝未知/重复字段和非规范编码。

roster 只包含稳定 ID、reader/writer 角色和设备公开收钥/签名钥匙，无姓名或条目值。成员/设备按 ID 严格排序，全局 ID/公钥唯一，最多 64 成员、总计 64 设备。每个 active 成员必须有设备。设备不能改挂成员或在原 ID 下换钥；换钥需新设备 ID。完整历史保留永久墓碑：被移出的成员/设备 ID、设备收钥及签名公钥不能复用，避免用新 ID 恢复旧钥。owner/publisher/sequencer 是独立外部角色，不由成员设备自助授予。

age 信封没有可公开核验的收件人清单：排序端只能验证 publisher 签名、epoch、owner 签署的 roster 和精确密文摘要，不能仅由这些证明加密者实际使用了哪些收件人。受信客户端必须使用 `Build` 的 roster 派生封装路径；已经掌握明文的恶意 owner/publisher 泄漏数据不在该证明之内。实际撤销验收通过用旧设备尝试解密新密文实现。

## 存储与状态

`Create` 在同目录临时数据库完成事务和关闭后，以 Unix no-replace hard link + 目录 fsync / Windows no-replace write-through move 发布新文件。`Commit` 在一个 bbolt 默认同步事务中验整链、精确比较父检查点，持久化新签名 receipt 与对应当前密文。两位 owner 对同父提交，只有一个成功；另一个重新读取可信状态再提。失败/回滚/关闭失败均返回零回执，结果可能已经提交时可用旧检查点重新读取确认。现有目标不覆盖；极端掉电、文件系统持久化保证仍需硬件验收。Unix 文件 0600，Windows 继承目录 ACL，调用方须提供自己控制的目录。

`Freeze(config, ownerPrivate, parent)` 退休**整个** roster（包括最后一个设备），签下一代 frozen 记录；同一事务删除当前 snapshot，并明确读出 frozen 模式。旧父提案不能再发布。frozen 必须严格空 roster/空 snapshot/空 digest；禁止 frozen genesis 和 frozen→frozen。恢复 active 必须新成员/设备 ID、新设备钥匙、下一代实际密文，并由 owner 提供独立保留或重建的完整条目；目录不恢复已丢失数据，不从旧 snapshot 隐式复用旧钥。固定 publisher 钥匙不可用时保持冻结，本批不轮换根钥匙。旧设备持有的历史密文、已复制数据和 bbolt 释放页不承诺擦除。

`Read(path, config, independentlyRetainedCheckpoint)` 重新验证完整 owner/sequencer 链、当前 snapshot，以及检查点确为祖先；同版本不同 hash、落后于检查点和跨 Scope 均拒绝。Genesis 检查点只用于可信首次建立/未拿到首次回执的检查，没有回滚保护。检查点是下限，签名不是远端新鲜度证明；调用方必须保管独立检查点并直接访问可信本地排序库。不能把中继提供的旧签名文件认定为最新，排序端失陷或分叉需要后续外部见证/新鲜度协议。

容量明确有界：最多 1024 版本、每条记录 128 KiB、当前 snapshot JSON 12 MiB、打开的数据库文件 256 MiB；到达容量拒绝继续提交，不静默裁剪墓碑或旧链。目录存公开成员元数据和签名密文，不写私钥、个人库数据或条目明文；它不是通用加密活动审计系统。

## 验收与未完成项

失败先行 `/tmp/locklark-validation/directory-red.log`：缺少目录 API。Go 测试使用真实 bbolt、Ed25519、age 和 KDBX：重开、两位 owner 同父并发单赢家、重放、错 Scope、篡改、角色分离、设备移出/整成员移出、旧收钥/签名钥匙/ID 复用、设备改挂、快照替换、提交回滚、关闭失败后重读、独立检查点拒绝磁盘回滚、整库冻结和由独立数据重建。被移除成员的两台设备均打不开新代，剩余设备能读；冻结后旧父提案失败，旧设备不能读新身份的新代，但仍能读先前持有的历史版本。

实跑命令：`go test ./internal/directory -count=1`、`go test -race ./internal/directory -count=1`、完整 `go test -count=1 ./...`、`go vet ./...`、`go mod verify`。最终 Luna/max 复核与 Ubuntu/Windows CI 结果见 PR。

仍待：owner/publisher 轮换、真实邀请/指纹核对、设备本机保钥与签名操作、两人两个人库一团队库一机器联调、依赖资格的会话/机器委托级联撤销、可信远端新鲜度和中继分叉处理、离线草稿/同步冲突、团队恢复保管、网络服务和 UI。不能据此宣称完整团队同步/撤权产品已完成。
