# Locklark

**Keep the keys. Grant the action.** 面向个人和小团队的本地密码管理器。目标是替换 1Password 8 的日常体验，并让 Agent 申请具体操作、说明原因、关联会话。

当前交付是 **M0 合成数据 CLI 预览**。可以验证设备吊销、加密收件箱和按会话查询记录。它不能保存你的真实密码、批准真实请求或代替 1Password。完整产品与威胁模型见[设计稿](docs/design.md)。

## 五分钟复跑

需要 Go 1.26.8；可用仓库的 `mise.toml` 选择工具链。Windows PowerShell 下，在仓库根目录运行：

```powershell
go test ./...
./scripts/acceptance.ps1
```

脚本在系统临时目录创建全新的合成资料，分别启动 CLI 验证：A 能读旧库；复制给 A 的新版打不开；B 能打开新版；演练的拒绝记录可以按会话找回；另一进程可以读到主人离线时提交的待办。脚本打印目录位置，便于自行复核。

也可以手动操作，先选择一个**尚不存在**的目录；同名目录绝不覆盖。写入失败留下的残缺目录不能视为成品，重试请用新目录。以下命令不联网：

```powershell
go build -o locklark.exe ./cmd/locklark
.\locklark.exe demo --out demo-out --session build-42 --reason "核对演练条目"
.\locklark.exe inspect --bundle demo-out/share/epoch-1 --device demo-out/clients/A --epoch 1
.\locklark.exe inspect --bundle demo-out/share/epoch-2 --device demo-out/clients/A --epoch 2
.\locklark.exe inspect --bundle demo-out/share/epoch-2 --device demo-out/clients/B --epoch 2
.\locklark.exe audit --bundle demo-out/share/epoch-2 --device demo-out/clients/B --epoch 2 --session build-42
```

第二次 `inspect`（A 尝试开第 2 代）应失败并返回非零状态码。B 将得到 `{"epoch":2,"items":2,"attachments":1}`。旧版仍然能读；如旧凭据已经泄露，须到真实上游轮换。代次来自独立可信状态，演练由调用者通过 `--epoch` 明确提供；还没有分布式防回滚或防分叉协议。

## 在第 3 代核对修改和迁出

`demo` 会用 B 重开第 2 代，按库、条目、区段和字段 ID 修改演练登录的标题及 TOTP，再只向 B 发布第 3 代。使用相同标题的文档和二进制附件应保持原样。要在本机检查结果，可以显式写出**明文合成样本**：

```powershell
.\locklark.exe fixture-export --bundle demo-out/share/epoch-3 --device demo-out/clients/B --epoch 3 --out edited-sample.1pux
```

目标必须是新文件并支持硬链接。命令仅允许本版内置的原样或已编辑归档；不会导出一般金库，也不会向标准输出打印字段值。第 2 代仍能迁出原样归档；A 不能导出第 2、3 代。编辑过程写入签名快照的 `locklark-bootstrap` 会话；导出本身不提供不可抵赖的披露审计。

## 错过通知也能找回请求

请求会在写入前检查 session 和原因，拒收可识别的认证头、密钥赋值、私钥头、OTP URI 和部分供应商令牌。旧审计中匹配的原因在查询时显示为 `[redacted]`；不改写历史快照。孤立的任意密码无法可靠识别，请只写用途，勿粘贴真实凭据。后续工作和当前验收范围见[开发进度](docs/progress.md)。

以下两条命令可以相隔数小时。提交方只需要待办目录和独立交付的公开收件密钥；不用给它任何客户端目录。唯一可用的 `op://` 引用指向合成条目。原因使用演练文本；CLI 参数可能留在 shell 历史中。

```powershell
.\locklark.exe request --inbox demo-out/inbox --recipient demo-out/agent/approval.pub --session deploy-17 --reason "检查演练发布" --ref "op://synthetic-vault/login-sample/ops/otp-demo"
.\locklark.exe inbox --inbox demo-out/inbox --device demo-out/clients/B --session deploy-17
```

第一条返回随机请求 ID 和 `pending`。第二条解密并按 session 查回 ID、引用和原因，不解析或返回字段值。它用独立的收件密钥；每页最多检查 128 封密文，损坏的计入 `unreadable`。响应有 `next` 时，带上 `--after <next>` 继续；新投递从第一页重新查。这是本地文件投递，要求文件系统支持硬链接（Windows NTFS / Linux 本地文件系统）；还没有远程中继或推送。公开收件密钥须由可信客户端单独交付，不能相信待办目录自报的公钥。

`inbox` 中的请求来自未经认证的提交方，session、原因和时间都是自报；拥有收件公钥就能投递，控制目录者也能删信。`audit` 读取的则是建库演练时保存在签名快照中的事件，包括一次固定的拒绝。两者都不能证明某人批准过使用密钥。新版演练的事件另有审计签名；批准与一次性兑现仍未实现。

## 核对审计与历史回滚

新版 `demo` 使用与快照签发者不同的 Ed25519 审计密钥；每个事件签名绑定事件正文、序号及上一条签名的 SHA-256 摘要。事件和签名都在加密快照内。客户端独立保存 `audit.pub`；审计流按签名密钥区分。旧版演练没有审计签名，仍可普通查询，但不能通过检查点验证。

从可信设备把 `witness/epoch-3.json` 复制到另一个可信位置（下例为 `backup/`），随后可离线运行：

```powershell
.\locklark.exe audit-verify --bundle demo-out/share/epoch-3 --device demo-out/clients/B --epoch 3 --checkpoint backup/epoch-3.json
.\locklark.exe audit --bundle demo-out/share/epoch-3 --device demo-out/clients/B --epoch 3 --session build-42 --checkpoint backup/epoch-3.json
```

第 3 代对第 3 代检查点返回 `{"events":4,"witnessed":4}`。对第 2 代检查点则是 4 条、见证 3 条；用第 3 代检查点验证第 2 代会拒绝。带 `--checkpoint` 的 `audit` 返回整条流的计数和本 session 的 `rows`；每条的 `witnessed` 表示是否属于该检查点见证过的前缀。普通查询保留原列表格式。修改单条事件或拿另一演练的检查点也会失败。若快照和检查点一起回退，则仅凭二者无法发现回退；`witness/` 在同一实验目录，不等于已有异地备份。本批只实现单签发设备、内存产生的审计私钥；独立审计加密/恢复、持久写入、跨设备见证与故障处理待开发。

## 已验证的边界

| 场景 | 当前行为 |
| --- | --- |
| 服务器只拿到 `share/` | 仅三个代次的 KDBX、age 信封及签名清单；没有 Secret Key、设备私钥或可解库的账户副本。这里没有运行同步服务。 |
| 同账号的设备 A 被移除 | A、B 共用账户双因子，各有独立设备私钥。每代随机产生 256 位文件密钥并重写整个 KDBX。离线测试直接拿旧设备私钥解新信封，又拿旧库钥调 KDBX 解码器，均失败；B 能解开。 |
| 账户双密钥 | 主密码与本机随机 128 位 Secret Key 参与派生，借鉴 1Password 2SKD：NFKD 规范化、650,000 轮 PBKDF2-HMAC-SHA256、独立 HKDF 分支、异或组合。Locklark 使用自己的标签与账号标识，无 1Password 协议互操作声明。Go 结果与[独立 Python 向量](internal/account/vector.py)一致；任一因子错误不能解开设备密钥槽。 |
| 合成 1PUX | 内置两个重名条目、Unicode 区段、TOTP 和一个二进制附件。原归档整个装入 KDBX 的受保护字段，再打开后逐字节相同。第 3 代按稳定 ID 改名并轮换合成 TOTP。迁出后逐字段核对 JSON，其他文件逐字节相同；这仍不是通用 1PUX 导入或原生 KDBX 字段映射。 |

**信任边界：** 整个 `demo-out` 是生成器的实验台，包含两台客户端，不能交给服务器或 Agent。模拟服务器只复制 `share/`；模拟被吊销者只给 `clients/A/` 和目标快照。演练用固定公开口令，把随机 Secret Key 存在客户端文件中，未接操作系统钥匙串。没有权限隔离的同用户进程可直接读取 B 的材料；不能以这个演练替代系统隔离。签名锚来自受信的客户端，签发私钥在生成时使用，不随演练资料分发。

KDBX 4.1 候选库当前写入 **Argon2d**，与设计要求的 Argon2id 有差距；KDBX 输入为随机文件密钥，账户口令走独立的双密钥派生。引入真实资料之前，须补齐文件格式互操作、独立密码评审、操作系统密钥存储与在干净机器上的恢复验收。

接下来的 M0：将逐字段编辑和迁出对账扩展到更多条目类型、成员/多设备换代与故障恢复、MyGo 常驻桌面原型。Next.js 团队 Web、iOS/Android、受隔离的 Bun MCP Gateway、AI 否决，以及独立部署的 invoke / deliver 两种 server token 均已在[设计稿](docs/design.md)中界定，尚未交付。
