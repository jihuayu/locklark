# Locklark

**Keep the keys. Grant the action.** 面向个人和小团队的本地密码管理器。目标是替换 1Password 8 的日常体验，并让 Agent 申请具体操作、说明原因、关联会话。

当前交付包括 **个人离线库 CLI 预览** 和独立的 **M0 合成网关演练**。个人库可以实际创建和保存登录记录，尚未完成独立密码评审、系统密钥存储和灾后恢复验收。请先用测试数据，不要停用已有密码管理器。设计与威胁模型见[设计稿](docs/design.md)。

字段引用的元数据核心已实现有限的 `op://vault/item/[section/]field` 解析、名称/ID 唯一定位和修订号绑定；同名拒绝，未知属性不静默忽略。该核心尚未接入真实 CLI 取值、存储事务或授权，也未与固定 op 版本实际对照，不代表已兼容 `op read/run/inject`。当前子集与验收见[字段引用记录](docs/reference-validation.md)。

个人 v1 原生条目现有元数据投影函数，固定登录字段身份并绑定提供的审计修订号；改名后 ID 保留，恢复后使用新账本修订。其他导入布局明确拒绝，文件附件取值仍未实现。该函数不认证输入或授权取值，生产同一事务接入尚待完成；证据与边界见[个人投影验收](docs/personal-reference-metadata-validation.md)。

内置合成 1PUX 演练另有独立投影，保留源 `ops/otp-demo` 区段与字段身份，版本绑定调用者提供的整份快照签名。它只支持已有演练布局，不是通用 1PUX 导入，也不授予取值权限；范围与真实加密快照/审计验收见[合成导入投影](docs/fixture-reference-metadata-validation.md)。

## 离线创建个人库

在自己的交互终端运行下面四条命令。选择已存在的本地父目录。Unix 文件系统须支持硬链接及目录同步；Windows 使用不覆盖目标的写穿移动；建库拒绝覆盖已有文件。不需要服务器或团队账号。

```powershell
go build -o locklark.exe ./cmd/locklark
.\locklark.exe personal init --file owner.ll
.\locklark.exe personal add-login --file owner.ll
.\locklark.exe personal list --file owner.ll
.\locklark.exe personal audit --file owner.ll
```

建库时输入并确认主密码。终端显示一次随机的 `LL1-…` Secret Key；离线另存并重新输入后才会建库。它不会写入库文件、参数或 JSON 输出。关闭进程后仍需主密码和这把 Secret Key；单独拥有库文件或任一因子不能打开登录内容。两项都不能代替库文件或已登记设备的加密槽。忘记任一账户因子不能重设；提前生成独立备份后才可以离线恢复到新设备。

`add-login` 在关闭回显的终端中收集标题、用户名和密码，返回稳定条目 ID；`list` 只列 ID、标题和条目版本。每次成功操作记录人类会话、动作、条目 ID（如适用）、结果和 UTC 时间；不记录标题、用户名或密码。未解锁的失败不能写入已认证的账本。事件单独加密、逐条签名，添加登录和审计写入同一事务。查询会写审计事件，但不改 KDBX 密文。当前每次操作都校验完整本地日志；整份文件被回滚仍需外部见证才能发现。个人文件包含设备专属加密槽，**不要当作可上传给同步服务器的格式**；此入口尚未接入团队、设备撤销或 Gateway。

要修改登录，先运行 `personal list`，取目标条目的 `id` 和 `revision`。例如，在 PowerShell 中将它们放入 `$itemID` 和 `$revision` 后执行：

```powershell
.\locklark.exe personal edit-login --file owner.ll --id $itemID --revision $revision --field password
```

可编辑 `title`、`username` 或 `password`；新值只在不回显的终端提示中输入。用户名可以清空。每次成功编辑返回同一个 ID 和新版本；版本来自该条目最后一次成功操作的签名事件，不是密码摘要。遇到版本冲突时不写条目，应重新列出并核对后再编辑。其他条目的修改以及审计查询不改变此条目的版本。成功、冲突和找不到目标都会写审计；只记录被编辑的字段名及已核验的 ID 和基准版本，不保存调用者提交的未知 ID、版本串或字段值。

新版可在原个人库上直接编辑。写入首条编辑操作审计后，`d294bb4` 的旧 CLI 会拒绝不认识的事件，不能用旧版继续打开该库。升级验收：`python scripts/personal_acceptance.py <新版程序> <旧版程序>`。

个人库的跨进程验收可用 `python scripts/personal_acceptance.py <本机编译的 locklark>` 复跑。脚本只用临时目录和随机测试凭据；Windows 测试环境另需 `pywinpty==3.1.2`，产品本身无需 Python。

## 个人库离线备份与恢复

```powershell
.\locklark.exe personal backup --file owner.ll --out owner.llb
.\locklark.exe personal restore --file owner.llb --out recovered.ll
.\locklark.exe personal archived-audit --file recovered.ll
```

备份时，把终端显示的完整 `LLR2-<恢复秘密>-<可信检查点>` 恢复材料与备份文件分开保存。两部分各为 52 个 Base32 字符，共 110 个字符，不可截掉后一部分。检查点是备份文件原始字节的 SHA-256，固定这份备份内的源审计公钥、全部签名历史、条目和解密参数；恢复时不从备份或服务器重新获取信任依据。每份备份各有一份材料。恢复需要原主密码、原 Secret Key 和该材料，不需要旧设备或服务器。即使有人取得全部解密因子，重新签名和封装的替代历史也无法匹配原先单独保存的检查点。检查点不证明备份是当前最新版本；拿到过的旧数据也无法收回。

恢复先完整验证备份及旧因素、检查条目格式，并预检目标及其父目录，之后才显示新的 Secret Key。最终发布仍原子拒绝覆盖，包括保存新钥期间被其他进程占用的路径。新库保留条目 ID 和原值，沿用主密码，生成新的 Secret Key、设备密钥、审计密钥和快照代次；原设备私钥、会话和可执行授权不会被复制。

恢复来源必须是普通文件。Unix 在读取前以非阻塞方式打开并核验实际句柄，拒绝无人写入的 FIFO、指向 FIFO 的符号链接、目录和设备文件，不等待它们提供内容，也不发新钥。指向正常备份文件的符号链接仍可使用，检查点校验的是文件内容。Windows 特殊文件及命名管道行为仍待原生运行验证，交叉编译不代表已验证。

旧版 `LLR1` 恢复材料及版本 1 备份没有独立历史来源依据，新版明确拒绝，不提供静默兼容或忽略检查点选项。仍有可信原库时，用新版重新备份并独立保存新材料；只剩旧备份时须保留原件并另做来源核验，不能借旧版还原后自动认定历史可信。升级不会改写已有个人库或历史签名。备份文件必须按字节保留，重新格式化 JSON 也会使检查点不符。

`audit` 查看新设备的账本；`archived-audit` 查看备份时已有的历史事件、原签名和验签公钥。再次备份会携带这些历史。原库的 `backup.prepare` 表示已准备好密文，不证明备份文件最终写完或已异地保存；以命令成功退出并在独立目录试恢复为准。旧设备仍能访问自身曾持有的旧库。当前只验证单人库、独立新目录，没有跨设备外部见证；预览限制为 32 段历史、备份明文上限 16 MiB、文件上限 32 MiB。超出容量或历史段数会分别报告限制，不再混同凭据无效。新事件不被旧 CLI 识别。

## 五分钟复跑

需要 Go 1.26.8；可用仓库的 `mise.toml` 选择工具链。在 Windows 上用 PowerShell 7 从仓库根目录运行：

```powershell
go test ./...
pwsh -NoProfile -File ./scripts/acceptance.ps1  # PowerShell 7 或更高版本
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

拥有收件公钥就能投递匿名请求，但仅凭它不能让请求获批；只有登记过的会话签名有效时，`sender_status` 才会显示 `verified`。签名证明持有该会话的私钥，不能证明它声称的用途属实。控制目录者仍能删除来信。`audit` 读取的则是建库演练时保存在签名快照中的事件，包括一次固定的拒绝。两者都不能证明某人批准过使用密钥。新版演练的事件另有审计签名；下节的本机决定和单次执行意图另有事务账本。

## 登记 Agent 会话

Agent 在自己的私有目录生成一次性会话密钥，把显示的公钥交给主人通过独立渠道核对。主人只登记公钥。以下是两边手工演练的命令；真实隔离需要不同 OS 用户或独立远端 runner，不能把持库客户端目录交给 Agent：

```powershell
# Agent：记下输出中的 public，私钥只保存在 Agent 自己的目录。
.\locklark.exe session-keygen --out runner.sessionkey
# 主人：把 PUBLIC_HEX 替换为独立核对过的完整公钥。
.\locklark.exe session-enroll --device demo-out/clients/B --session deploy-17 --public PUBLIC_HEX --reason "核对发布任务的 runner"
# Agent：使用通过可信途径拿到的收件公钥文件，签名后投递。
.\locklark.exe request --inbox demo-out/inbox --recipient demo-out/agent/approval.pub --session deploy-17 --session-key runner.sessionkey --reason "检查演练发布" --ref "op://synthetic-vault/login-sample/ops/otp-demo"
```

每次登记最长 24 小时，限定本机收件身份和固定合成动作。session 名称和公钥都不能在此设备重新登记，续期用新名称和新密钥。主人可运行 `session-revoke --device demo-out/clients/B --session deploy-17 --reason "任务结束"`；`session-history --device demo-out/clients/B --session deploy-17` 可查签名登记及撤销记录。动作、字段、代次、理由、时间和请求 ID 均绑定签名。未签名来信仍可查看和拒绝；撤销和批准共用事务，撤销之后不能发出新的批准。登记记录和一份单独签名的当前头在同一事务提交，单独删掉撤销记录会使查询和批准失败；能同时恢复旧登记链与匹配旧头的人仍可抹去撤销，不必回滚决定账本。独立介质上的最新见证尚未接入批准。Agent 私钥文件受所在目录及 OS 权限保护，尚未对接系统钥匙串。

## 对离线请求作出决定

主人先用 `inbox` 核对原因、session、固定动作 `fixture.inspect-metadata` 和字段引用，从该行复制 `id` 与 `review` 摘要。然后可以在独立进程中记录一次决定：

```powershell
.\locklark.exe decide --device demo-out/clients/B --inbox demo-out/inbox --bundle demo-out/share/epoch-3 --id <请求ID> --review <核对过的摘要> --choice approve --reason "已核对演练目标"
.\locklark.exe decisions --device demo-out/clients/B --session deploy-17
```

拒绝用 `--choice deny`，无需打开金库。批准只适用于已核实的第 3 代内置合成目标；匿名、未登记、已撤销或目标未核实的来信只能拒绝。请求自报时间不能在未来或早于 24 小时前，批准有效期最多 2 分钟，且不能超过会话或请求的到期时间。`decisions` 是历史记录，过期不会改写历史；`inbox` 显示当前状态。仅下节固定元数据动作有执行接口，无原值交付。

B 的本地事务库把签名决定与单独审计流的事件一起加密提交；查询会校验两种签名和前序摘要。并发相反决定只提交一个；原来信仍可读、批准目标仍可核验且会话仍有效时，相同决定和理由的重试返回原记录。会话撤销或失效后，即便是相同的批准请求也会失败；已签决定只作为历史用 `decisions` 查询。同一 ID 换了请求内容会显示冲突，删掉中继来信也不能删除本机决定。新功能需要新生成的演练客户端；旧演练仍能查看原待办。这个本机账本与快照里的演练审计是两条独立的流；此版还不能发现整个本机事务库被回滚，有效期依据本机时钟，尚无抗时钟回拨的独立时间基准，不能用于生产授权。

## 一次性兑现（合成字段元数据）

用新生成的演练客户端和新签发的批准。Agent 使用 `request` 回执里的 `id`、`review`，无需读取主人目录。以下文件可在 Agent 与持库端之间离线转交。Agent 必须通过可信配置取得收件公钥 `approval.pub` 和结果签名公钥 `host-sign.pub`。

```powershell
# Agent：创建新的私有目录；只把 invocation.age 转交给 B。
.\locklark.exe invoke-prepare --session-key runner.sessionkey --recipient demo-out/agent/approval.pub --host-sign-key demo-out/agent/host-sign.pub --session deploy-17 --id ID --review DIGEST --attempt private-attempt

# 持库端 B：核对会话、批准和已签的密文快照，先入账，再解锁并执行。
.\locklark.exe invoke-run --device demo-out/clients/B --bundle demo-out/share/epoch-3 --ticket private-attempt/invocation.age --out reply.age
.\locklark.exe executions --device demo-out/clients/B --session deploy-17

# Agent：用本次尝试独有的私钥解回执并验签。attempt.private 不得随票据分发。
.\locklark.exe invoke-result --attempt private-attempt --reply reply.age
```

返回值仅含目标代次、字段 ID 和类型（例如 `{"epoch":3,"field":"otp-demo","kind":"totp"}`）。不会返回 OTP、URI、附件或其他条目的信息。请求票据由登记会话签署，绑定设备、批准摘要、随机 nonce 和结果收件公钥。并发提交同一份批准只有一个执行者；换新票据不能重复使用批准。

意图和占用在一个事务内提交。若进程中断且没有结局记录，`executions` 显示 `unknown`，不自动重试；有明确的动作错误才记为 `failed`。若结果已记录为 `succeeded`、但文件传输失败，持库端可用原票据执行 `invoke-receipt --device ... --ticket ... --out new-reply.age` 取回同一份密文，不再执行；领取要求会话仍有效。结果只能由原尝试接收，已交付的数据不能通过撤销收回。

主人可在执行前单独撤销一项批准：`approval-revoke --device demo-out/clients/B --id ID --review DIGEST --reason "任务取消"`。这不会关闭整个会话，理由留在签名账本中。撤销和占用共用同一个写事务，已开始的动作不能撤回。

早期演练缺少执行账本头或批准时的快照指纹，可以查历史但不能直接兑现，须新建演练。单次执行仅对同一份持续保存的本机账本成立；同时还原旧账本与匹配的头，或把设备私钥和未消费账本复制到两个独立目录，可能重复执行。尚未提供跨设备防重放、可信时钟或远程执行服务。上游 API 副作用、插件注入和机器 token 不属于这个动作。

## 网关：GitHub PR 读取适配器

内置 Bun 插件只读仓库 ID 和 PR 编号，产生 `github.pulls.get` 操作提案。Go 宿主把提案与调用方提供的已批准目标逐项比较，一致后才读凭据；它只向固定 GitHub HTTPS 域名和拥有者配置的 IPv4 地址发送 GET。返回值限 PR 编号、状态、合并时间，并核对上游返回的仓库 ID。上游接口见 [GitHub REST 文档](https://docs.github.com/en/rest/pulls/pulls#get-a-pull-request)。

用以下命令在 PowerShell 7 复跑（Go 1.26.8、Bun 1.4.4）。测试启动独立 Bun 进程，并用本机合成 HTTPS 服务测证书拒绝、凭据注入与结果过滤；不需要 GitHub 令牌。

```powershell
$env:LOCKLARK_TEST_BUN = (Get-Command bun -CommandType Application | Select-Object -First 1).Source
bun test ./plugins/github-pull-reader
go test -count=1 ./internal/gateway
```

签名审批现在支持**本地录制响应**。主人用 `pull-enroll` 登记会话、仓库稳定 ID 和 owner/name；Agent 用 `pull-request` 提交 Bun 提案、PR 编号和理由。待办显示插件身份、版本、内置模块 SHA-256、固定字段和执行方式 `recorded-response/v1`。主人只对所见请求摘要批准；一张票据只能消费一次。模块摘要标识这个二进制认可的提案代码，不证明 Agent 一定运行过该代码；宿主独立验证参数。

建库时，快照签发器把合成字段、代次、快照指纹和归档摘要签名，并将证明单独加密给 B 的审批身份。审批只验证这份证明、密文快照和会话登记，不开密码槽；实际取值在执行意图提交之后。旧演练没有目标证明，若要签发 PR 批准须重新生成演练。插件升级会使旧版本授权不能发起新执行；已成功的回执仍可由原票据在会话有效时取回。

例如，先为 `example/tools`（演练 ID `123`）登记一个新 session，然后申请查看 PR #7：

```powershell
.\locklark.exe pull-enroll --device demo-out/clients/B --session pr-run --public PUBLIC_HEX --reason "核对 PR" --repo example/tools --repo-id 123
'{"repo":"123","number":7}' | bun run ./plugins/github-pull-reader/index.ts | Set-Content proposal.json -Encoding utf8NoBOM
.\locklark.exe pull-request --inbox demo-out/inbox --recipient demo-out/agent/approval.pub --session-key runner.sessionkey --session pr-run --reason "核对合并状态" --repo example/tools --repo-id 123 --pr 7 --proposal proposal.json
```

后续沿用 `inbox → decide → invoke-prepare`。持库端运行 `invoke-run` 时加 `--recorded-response PATH` 选择本地合成 JSON；离线演练只接受该文件，绝不向 GitHub 发请求。结果明确标为录制数据，`executions --session pr-run` 保留实际消费的目标。旧元数据授权与 PR 授权不可互换。完整的双端命令由 `scripts/acceptance.ps1` 复跑。

在线适配器没有向 Agent 暴露真实凭据调用入口。GitHub 的 GET 路径按 owner/name 定位，响应后才能核对稳定 ID；若旧名被复用，不能仅靠响应校验限制请求发向哪个仓库。上线前须让上游凭据本身也只对指定仓库有效。MCP 已可发现内置录制工具；签名安装和第三方插件 OS 沙箱尚未接入。

## 用 MCP 提交申请并在重启后查状态

持库端为已登记的录制 PR 会话签发五分钟的 stdio 配置。它只公布仓库、会话身份、内置模块摘要和到期时间。把签名配置、安全核对过的两个公钥交给可信启动器；`runner.sessionkey` 只在启动器侧，Agent 通过 MCP 工具传参数。启动器私有状态不能与中继目录重叠。以下路径表示不同角色实际可访问的文件，不等同于已经建立 OS 隔离。

```powershell
# 持库端：已有 pull-enroll 登记，使用专用的配置文件；courier 常驻时可续发配置，但不能延长会话登记。
.\locklark.exe bridge-profile --device demo-out/clients/B --session pr-run --out bridge.profile
.\locklark.exe status-serve --device demo-out/clients/B --inbox demo-out/inbox --exchange status-exchange --session pr-run --profile bridge.profile

# 启动器：预先创建独立的 private-state、status-exchange 两个目录。MCP 客户端用以下命令及参数启动 stdio 服务。
.\locklark.exe mcp-stdio --profile bridge.profile --session-key runner.sessionkey --recipient demo-out/agent/approval.pub --host-sign-key demo-out/agent/host-sign.pub --inbox demo-out/inbox --exchange status-exchange --private private-state --bun ABSOLUTE_BUN_PATH
```

- `github_pulls_get` 接受 `repo`（登记的数字 ID 字符串）、`number`、`reason` 和 `request_key`（每次新申请生成 32 位小写十六进制随机值）。同键同参数的并发调用或重连重试返回同一个 ID 和摘要。私有发件箱保留原始密文以便补投；同一键更换目标或理由会失败。 重试返回的是原投递回执，当前状态另用只读查询确认。若私有发件箱丢失而中继仍保留原密文，重试会报告冲突；同一会话和请求键不会因此生成第二个请求 ID。
- `locklark_resume` 接受 `request_id` 和 `review`。首次产生新的只读挑战，返回 `awaiting-holder` 和 `poll_id`；将该 `poll_id` 传回来即可读取持库端签名的状态与观测时间。再次省略 `poll_id` 请求更新的观察。持库端离线、查询无法验证或会话已被撤销时，不能将等待误当作同意。已收到的旧观察不能证明此刻仍获批准。
- `locklark_collect` 接受原投递回执里的 `request_id` 和 `review`。仅当结果文件还未出现时返回 `awaiting-receipt`；签名无效、会话不匹配或本地接收身份丢失都会报错。领取成功时返回 `succeeded` 和明确标注来源的录制结果。重复领取不会重新申请、批准或执行。插件升级后，旧登记只能凭已保存的 `request_id` 和 `review` 查询或领取；若首次提交回复丢失并且期间插件退役，目前不能只凭 `request_key` 找回这两个标识。
- 常驻端只答复状态并转交已经入账的回执密文。持库端决定批准后，须另外显式执行，例如 `invoke-run --device CLIENT_B --bundle EPOCH_3 --ticket status-exchange/ID.invoke.age --recorded-response RECORDING.json --out NEW_FILE`。常驻端再次核验活跃会话才会从账本补投同一份密文。已交付的结果无法撤回。
- 首次提交或重试会持久保存随机的回执接收身份；私有目录内的 `.replykey` 用会话种子派生的专用密钥加密。保留该文件和会话私钥；丢失原接收身份不会让新的身份获得已完成的回执。旧版桥提交的请求须在执行前用同一请求键重试以准备接收身份。
- stdio 的短期配置到期后须重连，在线持库端为仍有效的登记自动续发。插件换版时，旧登记只列出状态与领取工具，不能发起新的操作。离线中继可能重放未到期配置，持库端仍逐次核验会话。没有远端自动配对、第三方插件沙箱或实时 GitHub 凭据。

进程级验收：`python scripts/mcp_acceptance.py PATH_TO_LOCKLARK`（需要 Bun 1.4.4）；Windows 综合验收已包含这一步。实现基于[官方 Go SDK](https://github.com/modelcontextprotocol/go-sdk)，使用 [MCP stdio 协议](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)。

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
| 合成 1PUX | 登录和文档各自是原生 KDBX 条目，源 ID 决定稳定 UUID，同名也可区分。密码和 `otp` 只在对应受保护字段里；文档字节只在原生附件里。迁出从条目和保留的 JSON 片段重建归档。第 3 代按稳定 ID 修改标题和 TOTP，重新核对字段和附件；仅支持内置样例。 |

**信任边界：** 整个 `demo-out` 是生成器的实验台，包含两台客户端，不能交给服务器或 Agent。模拟服务器只复制 `share/`；模拟被吊销者只给 `clients/A/` 和目标快照。演练用固定公开口令，把随机 Secret Key 存在客户端文件中，未接操作系统钥匙串。没有权限隔离的同用户进程可直接读取 B 的材料；不能以这个演练替代系统隔离。签名锚来自受信的客户端，快照签发私钥只在生成时使用，不随演练资料分发。B 客户端保留加密的决定及本机审计签名槽，以便后续登记会话和签署决定。

新签名快照写 **KDBX 4.1 / Argon2id**（16 MiB、3 次、2 路）；旧预览的 Argon2d 快照仍可读。输入是每代独立的随机文件密钥，账户口令继续走独立的双密钥派生。用 [PyKeePass](https://github.com/libkeepass/pykeepass) 实测了独立读取、修改受保护的合成载荷、另存及 Go 回读。外部修改使原快照签名失效；只有测试签发者重新签名后才可采用。该结果不证明所有 1Password 条目、附件或桌面客户端互操作。

Windows 可用一次性 Python 环境复跑，Linux 则使用虚拟环境中的 `bin/python`。产品程序无需 Python：

```powershell
$peerEnv = Join-Path ([IO.Path]::GetTempPath()) ("locklark-peer-" + [guid]::NewGuid())
python -m venv $peerEnv
$env:LOCKLARK_TEST_PYKEEPASS = Join-Path $peerEnv 'Scripts/python.exe'
& $env:LOCKLARK_TEST_PYKEEPASS -m pip install 'pykeepass==4.2.0'
go test -count=1 ./internal/vault -run 'TestKDBXIndependentPeer|TestIndependentNativeEditor|TestOfflineRevocation'
```

引入真实资料之前，仍须独立密码评审、操作系统密钥存储、原生字段映射和干净机器恢复验收。

新版 CLI 可读旧版单载荷快照；旧版 CLI 不能读取新原生条目布局。PyKeePass 可按 UUID 修改登录、密码、TOTP 和附件；采用外部改动仍须可信签名。普通 CLI 只允许迁出明确支持的合成内容，未提供任意明文导出或真实库导入。 当前布局只承载上述条目数据，重写时重新生成访问等时间戳；条目到期、覆盖 URL、自动输入规则、组备注等未支持的设置会被拒绝。文档附件的 KDBX 内存保护位连同字节一起保留；不据此宣称进程内存已被操作系统锁定。

升级验收可以用 `python scripts/native_upgrade.py <旧版可执行文件> <新版可执行文件>` 复跑。旧版基准为 `c620f50`。脚本临时生成两套合成金库，比较第 1、3 代的迁出字节，检查被撤销设备与旧读取器被拒。

接下来的 M0：将逐字段编辑和迁出对账扩展到更多条目类型、成员/多设备换代与故障恢复、MyGo 常驻桌面原型。Next.js 团队 Web、iOS/Android、受隔离的 Bun MCP Gateway、AI 否决，以及独立部署的 invoke / deliver 两种 server token 均已在[设计稿](docs/design.md)中界定，尚未交付。
