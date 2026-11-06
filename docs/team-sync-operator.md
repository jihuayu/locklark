# 团队同步服务：构建与运维

当前入口是 `locklark-team-sync` HTTPS 排序服务与 `internal/teamsync` Go 客户端库。该库受 Go `internal` 导入边界限制，仅供仓库内应用集成；尚未发布外部可导入的稳定 SDK。普通用户的团队创建、邀请、配对、草稿和冲突处理界面尚未提供；Android/iOS 应用当前操作个人离线库，未接入团队同步。不存在 `locklark team-sync read` 命令。个人库 `owner.ll` 也不能直接当作团队目录上传。

## 启动前准备

需要 Go 1.27.3、真实控制终端、可信团队目录数据库，以及主机名匹配的 TLS 证书。服务只接受 WriterACL + 双钥持有证明策略；旧策略目录不能靠修改配置静默升级。团队初始化、设备证明和 owner 成员变更仍通过现有 `internal/directory` 的 `NewConfigWithWriterACL`、`IssueChallenge` / `AnswerChallenge`、`Build` / `Create` / `Commit` 等 API 集成，不是服务命令中的建库向导。

从独立可信管理端取得：

- 团队/库 ID、owner 公钥列表、sequencer 公钥、publisher 公钥，即 `directory.Pins`。不要从待验证的服务响应中取得这些信任根。
- 最小可信 `directory.Checkpoint`，包含 `scope`、`version`、`hash`。已有团队应使用独立保留并核对的回执检查点；不要为绕过错误退回 Genesis。只有明确的新团队引导才使用该配置的 `cfg.Genesis()`，它没有此前历史的回滚保护。
- 已签名的团队目录库和当前密文，以及 TLS 证书/私钥。服务不接收条目明文或 owner、publisher、设备私钥。

sequencer 的 **32 字节 Ed25519 seed** 由操作员另行安全保管；启动时输入它的 64 位小写十六进制形式。当前命令只支持隐藏控制终端输入，未提供无人值守系统密钥存储入口；不接受参数、环境变量、stdin 管道或普通 seed 文件。TLS PEM 私钥是另一个常规服务端秘密文件，不是 sequencer seed 的替代入口。

## 可信配置

下面是格式有效的**公开合成公钥示例**，没有保留对应私钥，也不包含可用团队数据库。不能用于真实部署；替换为自己的可信 pins、匹配的检查点及绝对路径。

```json
{
  "pins": {
    "Team": "00112233445566778899aabbccddeeff",
    "Vault": "8899aabbccddeeff0011223344556677",
    "Owners": ["cddc462cca9bf44a68301c5721a4c4b694e1b0a8919c7eebb25658f35e0458fd"],
    "Sequencer": "ec26ebcc8e80cb713003f939be4fb734db16af92da2b8061f0b147a4a41b1123",
    "Publisher": "c0dd09127ce9baafcd4f892012f9d2c88c179d78b979da01fc8bbbb997c04dd0"
  },
  "minimum": {
    "scope": "5bc86f92cca9eceb8e09fbd94b6c61bccc2f656cdd6b4d5baf55b201b45aa5c2",
    "version": 0,
    "hash": ""
  },
  "directory": "/srv/locklark/team.db",
  "anchor": "/srv/locklark/server.anchor",
  "listen": "127.0.0.1:8443",
  "certificate": "/srv/locklark/tls/server.crt",
  "tls_key": "/srv/locklark/tls/server.key"
}
```

`pins` 内字段大小写沿用 `directory.Pins`。`minimum.scope` 是完整 pins 和策略计算出的 scope，不能任填或只复制团队 ID。配置允许排版，但拒绝未知/重复字段和尾随 JSON。

用专用 OS 用户运行。Unix 下配置、TLS 私钥和检查点文件应为 `0600`，父目录应由该用户或 root 控制且不可被其他用户写入；证书可为 `0644`。Windows 检查实际所有者和 DACL，不能用 chmod 外观代替权限；新检查点由程序建立受限 DACL。拒绝最终文件符号链接。检查点必须是独立文件，不能与团队目录库或任何客户端检查点共用。

## 构建、初始化与运行

在仓库根目录构建：

```sh
go build -o locklark-team-sync ./cmd/locklark-team-sync
```

完成自己的配置和已签名团队目录准备后，仅首次明确初始化服务端检查点：

```sh
./locklark-team-sync init-anchor --config /srv/locklark/server.json
./locklark-team-sync serve --config /srv/locklark/server.json
```

`init-anchor` 只把配置中的独立 `minimum` 写入新的私有检查点，不创建团队库，不覆盖现有检查点。`serve` 要求检查点已经存在；隐藏输入 sequencer seed 并核对公钥后才监听。成功输出 `Team sync HTTPS server ready.`。无控制终端时拒绝启动；不要用 `echo seed | ...`、命令行或环境变量绕过。

服务直接使用 TLS 1.3，客户端验证可信证书根及固定 URL 的主机名；客户端不跟随重定向、不使用环境代理。不要用 `curl -k`、关闭主机名验证或改成 HTTP 来排错。此接口要求签名请求，普通 curl 请求也不能代替客户端库。启动错误只给固定类别，不打印配置正文、密钥或内部错误。

## 客户端集成与结果处理

以下是真实 Go API，运行于工作线程；密钥由调用者的可信本机流程提供，不能送到服务端。应用需要自行提供配对/批准和本机密钥保护界面。

```go
teamsync.CreateFileAnchorStore(path, trustedMinimum) // 仅首次显式创建
teamsync.OpenFileAnchorStore(path)                 // 重开，不自动重建
teamsync.NewDeviceClient(config, endpoint, device, deviceSigner, anchors)
teamsync.NewOwnerClient(config, endpoint, ownerSigner, anchors)

client.Fetch(ctx)             // (teamsync.VerifiedState, error)
client.Publish(ctx, p, s)     // (directory.Receipt, error)
client.Reconcile(ctx, p)      // (teamsync.Reconciliation, error)
client.Close()
```

`endpoint` 是 `teamsync.Endpoint{URL: "https://team.example:8443", Roots: trustedRoots}`；`Roots` 为 nil 时使用系统可信根，自签部署须独立配置可信根。`config` 来自独立 pins 的 `directory.NewConfigWithWriterACL`。每个客户端保留自己的私有检查点文件；验证完整历史、当前密文及请求 nonce 后，持久检查点 CAS 成功才返回已同步状态。`VerifiedState.View()` / `History()` 返回独立的元数据和密文副本，不含条目明文。

设备 reader 可读整个快照；writer 仅能以自己的设备签名发布数据更新。owner 是独立客户端身份，负责现有 owner 提案、冻结及恢复，不提供设备冒充 owner 的回退。`directory.BuildUpdate` 从已验证父回执构造 writer 候选；最终服务端仍按当前父版本 CAS，不把一次读取当作写入租约。

发布失败后不要自动重签、重发或覆盖。`ErrConflict` 要重新读取并明确核对；`ErrUnknown` 要保留原提案，用新的显式 `Reconcile(ctx, originalProposal)` 对账：

| 结果 | 含义 |
| --- | --- |
| `PublishCommitted` | 已验证完整历史包含原提案。 |
| `PublishConflicted` | 同一代已有不同提案，原提案不能提交。 |
| `PublishUnknown` | head 仍为原 parent，原请求可能尚在提交；不能据此重试。 |

网络响应最多 32 MiB、发布请求最多 16 MiB、读请求最多 8 KiB；超限拒绝而非截断历史。读取有不超过 15 秒的单调时间预算，部分网络阶段更短。成功只证明排序端在该次请求中观察到的状态，收到后仍可能立即出现新修改或撤销；离线缓存不能标记为最新。

## 停止、重启与恢复

正常运行时用 Ctrl-C 或 SIGTERM 请求停止。等待隐藏输入时，Ctrl-C、Escape、Ctrl-D、SIGTERM/SIGHUP 会取消并恢复终端；失败不继续启动。强制杀进程或断电不能保证执行清理，也不能证明在途发布没有提交。

重启使用原配置、目录和**原服务端检查点**，再次隐藏输入 seed。服务发现目录落后于检查点会拒绝；目录已提交但检查点尚未推进时，只能在完整验证后推进并恢复读取。不要删除检查点或重跑初始化来消除回滚错误。检查点丢失时，从独立可信备份/可信已验证设备核对恢复下界，不能只信任当前服务数据库。

服务端检查点和客户端检查点应各自保留、单独备份核对。服务目录与其检查点一起回滚、可信排序端作恶/分叉或同宿主失陷，仍需外部见证；nonce 不提供全局透明日志。撤销也不能收回设备此前已获得的密文或明文，已有成员可能泄漏数据。同一 OS 用户下的恶意进程不属于这里可隔离的边界。

## 合成数据验收

这些命令创建临时合成团队并注入故障，**不是生产建库、邀请或配对工具**：

```sh
go test ./internal/directory ./internal/teamsync ./cmd/locklark-team-sync -count=1
go build -o /tmp/locklark-team-sync-fixture ./scripts/team_sync_fixture
python3 scripts/team_sync_acceptance.py --fixture-bin /tmp/locklark-team-sync-fixture
```

验收临时材料有意包含合成因素，保持私有，不上传原始日志或材料。当前实际结果、失败轮和平台边界见[团队与移动端验收](team-mobile-validation.md)，协议见[架构约定](team-mobile-design.md)。
