# Locklark

**Keep the keys. Grant the action.** 面向个人和小团队的本地密码管理器。目标是替换 1Password 8 的日常体验，并让 Agent 申请具体操作、说明原因、关联会话。

当前交付包括 **个人库 CLI 预览** 和独立的 **M0 合成网关演练**。个人库日常操作可离线运行，另有每次人工确认的 GitHub HTTPS 查询入口。个人库可以实际创建和保存登录记录，系统密钥保护已有平台实现，独立密码评审、逐平台硬件与干净机器灾后恢复验收尚未完成。请先用测试数据，不要停用已有密码管理器。设计与威胁模型见[设计稿](docs/design.md)。

字段引用的元数据核心已实现有限的 `op://vault/item/[section/]field` 解析、名称/ID 唯一定位和修订号绑定；同名拒绝，未知属性不静默忽略。个人 v1 登录布局已接入认证事务、人工字段披露和取码，其他布局仍只有元数据核心；尚未与固定 op 版本实际对照，不代表已兼容 `op read/run/inject`。当前子集与验收见[字段引用记录](docs/reference-validation.md)。

个人 v1 原生条目现有元数据投影函数，固定登录字段身份并绑定提供的审计修订号；改名后 ID 保留，恢复后使用新账本修订。其他导入布局明确拒绝，文件附件取值仍未实现。投影函数本身不认证输入或授权取值；个人 CLI 现由同一认证事务调用，证据与边界见[个人投影验收](docs/personal-reference-metadata-validation.md)。

内置合成 1PUX 演练另有独立投影，保留源 `ops/otp-demo` 区段与字段身份，版本绑定调用者提供的整份快照签名。它只支持已有演练布局，不是通用 1PUX 导入，也不授予取值权限；范围与真实加密快照/审计验收见[合成导入投影](docs/fixture-reference-metadata-validation.md)。

两个已有布局的引用现可校验为明确的原生槽位和字段类型，拒绝旧修订、区段错配、名称冒充 ID 和跨布局目标；OTP 类型指存储配置，不是生成码。绑定结果只含元数据，不自行验输入真实性或授予权限；个人 CLI 另在认证事务内使用绑定结果，见[字段绑定验收](docs/reference-binding-validation.md)。

Go TOTP 核心已通过 RFC 6238/4226 向量，支持有限的 Base32/otpauth 配置、SHA1/256/512、6/8 位码和显式时间窗口。个人 CLI 已接入配置保存与先记意图的受控取码；短种子、不支持参数和非法时间明确拒绝，现有短种子演练数据不改写。不代表已兼容 op 的 OTP 行为；核心见[TOTP 验收](docs/totp-validation.md)，产品入口见[个人 TOTP 验收](docs/personal-totp-validation.md)。

密码生成核心使用系统 CSPRNG 与标准库拒绝采样，默认 24 位字母数字；策略要求至少 128 位组合熵，拒绝字符集重复、弱策略及超限。个人 CLI 和 MyGo 桌面已接入生成并保存/替换的事务流程，普通输出不包含生成值。核心证据见[密码生成验收](docs/password-generation-validation.md)，产品入口见[生成保存验收](docs/personal-generation-validation.md)。

独立 1PUX v3 清点预检模块在内存中检查归档边界、CRC 和严格 JSON，输出受限计数，不输出标题、路径或字段值，也不落盘解压。显式 `file.path` 可精确核对匹配/缺失、重复引用和声明大小差异；没有当前子集显式引用的文件不能称为孤儿或据此删除。另有区段和登录字段结构清点，保留重复、缺失、未知 designation 和 JSON 值形状；`type`/`fieldType` 分开计数，不猜测语义，见[登录字段清点](docs/onepux-login-fields-validation.md)。密码历史另按原顺序清点值/时间形状、精确整数相邻关系和字面重复，不排序、不去重，见[历史清点](docs/onepux-password-history-validation.md)。个人 CLI 已开放认证、审计的只读预检；全部条目映射仍未验证，未开放通用写入入口；见[清点验收](docs/onepux-preflight-validation.md)与[显式文件关联验收](docs/onepux-file-references-validation.md)。

## 加密迁出

`personal export-kdbx --file owner.ll --out NEW.kdbx` 经双因素和 `SAVE` 确认后，把当前原生条目（包括归档和回收站）导出为独立密码加密的 KDBX 4.1 文件；其他工具未必识别归档/回收站状态。导入条目的原始来源记录也会导出，其中可能保留修改前的旧值。导出密码在隐藏终端输入两次，至少 12 字符；已存在目标不会被覆盖。可使用 KeePass 兼容工具打开，不包含账户钥匙、审计或恢复材料。互操作和故障边界见[加密迁出验收](docs/personal-kdbx-export-validation.md)。

## 迁移前检查 1PUX

```powershell
.\locklark.exe personal inspect-1pux --file owner.ll --source export.1pux
```

在交互终端输入个人库双因素，并输入 `SCAN` 确认。命令只读检查不超过 8 MiB 的普通归档文件；输出条目/附件/登录字段/密码历史计数及固定待核对原因，不输出源标题或字段值，也不会导入数据。检查结果先记入个人库审计，提交后才输出报告和摘要回执。源 1PUX 仍是明文，命令不负责清除原文件；报告成功不表示可无损迁移。事务、恢复和平台边界见[个人预检验收](docs/personal-onepux-inspection-validation.md)。

## 按字段引用操作

离线插件包可用 `plugin inspect/install/list/audit/revoke` 管理，安装要求独立核对的发布者公钥、可信 pins 文件、已检查包的 digest 和当前目录 checkpoint。升级必须数值版本递增，撤销 ID 在该目录永久禁用；所有状态仍为 `execution: disabled`。安装不运行脚本、不下载依赖、不授予工具能力，见[签名插件目录与命令](docs/signed-plugin-catalog-validation.md)。

`personal github-pull --file owner.ll --id ID --revision REV --repository-id NUMERIC_ID --owner OWNER --repository NAME --number PR --api-ip PUBLIC_IPV4` 经隐藏双因素和 `CALL` 确认，把选定 password 字段作为 GitHub token 交给固定 HTTPS 查询器；审计意图提交后才发请求，只返回经校验的 PR 状态，不返回 token。目标地址需独立确认，TLS 始终验证 api.github.com。本入口联网，但不改变其他个人命令的离线行为；不是远程移动审批或机器授权，真实账号调用仍待验收，见[实时查询边界](docs/personal-live-pull-validation.md)。

`personal inject-json --file owner.ll --id ID --revision REV --field username|password --name TOKEN --out NEW.json` 经双因素和 WRITE 确认，将一个指定字段写成新 JSON 配置文件，正确转义值，不覆盖已有目标。输出为明文，创建时采用当前账户的受限权限；stdout 只有审计回执。此入口不执行任意模板或子进程，也不向 MCP 增加原值工具。详见[JSON 注入验收](docs/personal-json-injection-validation.md)。

`personal run-env --file owner.ll --id ID --revision REV --field password --name TOKEN --cwd ABS_DIR --timeout 30 -- ABS_PROGRAM [ARG...]` 经双因素输入和 RUN 确认后，把单个字段交给可信本地程序的环境变量。审计意图提交后才启动，清空继承环境（Windows 仅额外设置系统目录），标准流接空设备，只返回退出码。它不是沙箱；程序能使用、保存或转交该值。见[环境注入验收](docs/personal-run-env-validation.md)。

`personal search --file owner.ll [--state active|archived|trashed|all]` 在隐藏双因素后隐藏输入查询，按 Unicode 等价形式和大小写折叠搜索当前登录标题，返回稳定 ID/修订，默认仅活动项。搜索词不作为命令参数或单独输出字段，审计只保存库内 HMAC 绑定；标题控制字符可见转义。见[标题搜索](docs/personal-title-search-validation.md)。

`personal health --file owner.ll` 经双因素和 SCAN 确认后提供本地密码体检，仅输出活动登录的 ID/修订与固定问题码；检查空值、短值、低字符种类、示例常见值、重复使用和未保存 TOTP。不联网查询泄露库，不把未发现问题称为安全，也不推断网站的双因素状态。范围、规则与验收见[本地体检](docs/personal-health-validation.md)。

支持范围明确的基本登录导入：先运行 `personal plan-import-1pux --file owner.ll --source source.1pux`，使用返回的 `report.source_digest` 运行 `personal import-1pux --file owner.ll --source source.1pux --digest PLAN_DIGEST`。两步都需要隐藏双因素和确认；源文件变化、同源重复、容量超限或未支持字段整批拒绝。当前 `login-notes-v2` 接受单账户/单库、用户名/密码、单 HTTPS URL、纯文本备注（最多 64 KiB）和活动/归档状态；旧 `login-v1` 计划需重新生成并确认，已导入同源条目仍会拒绝重复。原始来源记录加密保留，编辑后可能仍含旧值。完整字段/类别/附件/历史迁移未完成，详见[登录导入验收](docs/personal-import-validation.md)和[七条交付范围](docs/seven-track-delivery.md)。

`personal references --file owner.ll` 经双因素解锁后列出库 ID、固定别名 `Personal`、条目 ID/标题/修订及 username/password/otp 引用，不输出字段值。使用当前列表中的引用和修订：

```powershell
.\locklark.exe personal reveal-ref --file owner.ll --ref "op://VAULT_ID/ITEM_ID/password" --revision REVISION
.\locklark.exe personal otp-ref --file owner.ll --ref "op://VAULT_ID/ITEM_ID/otp" --revision REVISION
```

两者均需交互终端、双因素和 `SHOW` 确认，先提交稳定条目/修订的披露意图，再向终端显示 JSON 字符串值或验证码；stdout 只有回执。`reveal-ref` 只接受用户名/密码，`otp-ref` 只生成码，不显示种子。名称/ID 不区分大小写且必须唯一；同名和名称冒充 ID 都拒绝。语法仅支持 ASCII 名称/ID（含空格、点、连字符和下划线），不解释查询参数或百分号编码；中文标题请用 ID。当前个人布局没有区段字段。

引用不是权限，也不表示 OTP 已配置。恢复后库 ID 和修订更新，须重新取得引用。超长或含控制/Unicode 格式字符的标题会导致整个引用目录拒绝，可使用 `list` 与直接 ID 入口修正。此入口不增加 MCP 原值能力，未实现 run/inject、通用导入或完整 op 兼容；详细验证见[个人引用验收](docs/personal-references-validation.md)。

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

可编辑 `title`、`username`、`password`、`otp`、`url` 或 `notes`；新值只在不回显的终端提示中输入。终端 `notes` 是单行替换，多行备注请在原生桌面编辑。用户名可以清空；TOTP 配置另有确认，见下文。每次成功编辑返回同一个 ID 和新版本；版本来自该条目最后一次成功操作的签名事件，不是密码摘要。遇到版本冲突时不写条目，应重新列出并核对后再编辑。其他条目的修改以及审计查询不改变此条目的版本。成功、冲突和找不到目标都会写审计；只记录被编辑的字段名及已核验的 ID 和基准版本，不保存调用者提交的未知 ID、版本串或字段值。

新版可在原个人库上直接编辑。写入首条编辑操作审计后，`d294bb4` 的旧 CLI 会拒绝不认识的事件，不能用旧版继续打开该库。升级验收：`python scripts/personal_acceptance.py <新版程序> <旧版程序>`。

个人库的跨进程验收可用 `python scripts/personal_acceptance.py <本机编译的 locklark>` 复跑。脚本只用临时目录和随机测试凭据；Windows 测试环境另需 `pywinpty==3.1.2`，产品本身无需 Python。

## 在终端显示单个字段

先用 `personal list` 核对条目 ID 和修订，再执行：

```powershell
.\locklark.exe personal reveal-login --file owner.ll --id $itemID --revision $revision --field password
```

目前仅支持 `username` 和 `password`。输入主密码、Secret Key，并在列出 ID、修订和字段的提示下输入 `SHOW` 后，程序在同一写事务内认证快照与完整审计、校验目标版本，并提交加密签名的 `item.reveal.FIELD` / `intent` 事件。提交成功后才在交互终端 stderr 显示一个 JSON 字符串；换行、制表符、引号及 Unicode 控制/格式字符（包括方向控制字符）经过转义，普通中文和 emoji 保留。stdout 仅返回不含字段值的 `status`、本次 `session` 和签名意图摘要 `intent`，可以单独保存回执。

取消、错误因素、未知 ID 或旧修订不会显示字段。已解锁的未知 ID 和版本冲突记录拒绝结果，不记录未经核验的 ID 或调用者版本。披露不修改条目修订；输出失败保留意图并报告交付未知，成功写入终端也不证明人已看到。终端历史或录屏可能保存显示值。stdin 与 stderr 必须是终端，普通管道调用拒绝；此检查不是针对同用户进程或伪终端自动化的 OS 隔离。

写入首条披露事件后，较旧的 CLI 会拒绝不认识的审计事件；请保留升级版程序。新版仍可读取此前库与备份，也能备份/恢复包含披露意图的历史。该入口未接入 `op://`、OTP、MCP 或远程 Agent 取值。验收：`python scripts/disclosure_acceptance.py <本机编译的 locklark>`；证据与边界见[受控披露验收](docs/personal-disclosure-validation.md)。

## 生成密码并直接保存

```powershell
.\locklark.exe personal generate-login --file owner.ll
.\locklark.exe personal regenerate-password --file owner.ll --id $itemID --revision $revision --length 32
```

`generate-login` 隐藏输入解锁因素、标题和用户名；输入 `SAVE` 确认后，生成随机密码并加密保存新登录。默认 24 位字母数字（组合熵下界 142 位），可用 `--length` 指定 22–256 位；不接受弱长度或自定义字符集。`regenerate-password` 另要求从 `list` 得到的条目 ID/修订及明确确认，成功后只替换此条目的本地密码，返回新修订。**它不会修改网站或服务端密码**；需要保留旧值时先备份，再协调网站改密。

生成器只在同一事务已经认证解锁因素、快照、审计及目标修订之后运行。生成保存与 `item.generate` / `item.regenerate.password` 签名加密审计一起提交，审计包含公开长度/字符集大小/组合熵下界；随机失败不修改库，旧修订竞争只能有一次成功。stdout 仅有 ID、修订和策略，终端不直接显示生成值；用 `reveal-login` 另行确认查看。回执丢失时先重新 `list` 和 `audit` 核对，不要把重试当成幂等创建。

写入新生成事件后旧 CLI 会拒绝不认识的历史；新版仍可打开升级前的库，也支持生成历史的备份/恢复。验收：`python scripts/generation_acceptance.py <新版程序> [升级前程序]`。

## 保存 TOTP 并查看验证码

```powershell
.\locklark.exe personal edit-login --file owner.ll --id $itemID --revision $revision --field otp
# 将返回的新修订保存到 $revision，再取码：
.\locklark.exe personal otp --file owner.ll --id $itemID --revision $revision
```

编辑时隐藏输入 Base32 种子或 `otpauth://totp/…` 配置，并输入 `SAVE` 确认；精确空输入表示清除本地配置。它不会改变网站的双因素设置。支持 16–64 字节种子、SHA1/256/512、6/8 位码、1–3600 秒周期；不接受空白变体、短种子、HOTP 或未知参数，也不会根据输入 URI 发起网络请求。

`otp` 必须重新输入解锁因素并以 `SHOW` 确认。认证事务核验条目/修订和配置，提交签名加密的 `item.reveal.otp-code` 意图后才计算验证码；终端 stderr 显示 JSON 字符串，stdout 只返回 `status: written-to-terminal`、会话、意图摘要及 Unix 秒半开有效区间 `valid_from` / `valid_until`。未配置、未知 ID 和旧修订会拒绝；普通 `reveal-login` 仍不能读取 OTP 种子或码。

时间来自本机，须保持时钟准确；操作期间回拨或写入前已经过期时不输出码，需要本人明确重试。终端写入阻塞可能让显示到达时已经过期，成功写入也不能证明用户看到或网站接受；审计一直保留为 `intent`。输出错误不返回成功回执，部分写入无法撤回。新增动作写入后旧版 CLI 会拒绝此历史；包含配置编辑和取码意图的备份可由新版恢复。验收：`python scripts/otp_acceptance.py <新版程序> [升级前程序]`。

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

需要 Go 1.27.3；可用仓库的 `mise.toml` 选择工具链。在 Windows 上用 PowerShell 7 从仓库根目录运行：

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

用以下命令在 PowerShell 7 复跑（Go 1.27.3、Bun 1.4.4）。测试启动独立 Bun 进程，并用本机合成 HTTPS 服务测证书拒绝、凭据注入与结果过滤；不需要 GitHub 令牌。

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

当前开发版已提供 MyGo 原生个人金库和 Next.js 本机只读团队管理。更多条目类型的迁移对账、完整团队邀请/同步、iOS/Android、受隔离的 Bun MCP Gateway、AI 否决，以及独立部署的 invoke / deliver 两种 server token 继续按[设计稿](docs/design.md)推进。

个人 CLI 支持 `archive-login` / `unarchive-login`（`--file`、`--id`、`--revision`，终端 SAVE 确认）。`list --state active|archived|all` 默认只列 active；归档条目仍可显式读取、取消归档及备份恢复。归档不会撤销字段权限，详见 [归档验收](docs/personal-archive-validation.md)。

用 `edit-login --field url` 保存一个 HTTPS 网站，用 `match-logins --file PATH --origin HTTPS_ORIGIN --frame-origin HTTPS_ORIGIN` 查找同源 active 登录候选（仅元数据）。当前只接受保守 ASCII URL / DNS HTTPS profile。CLI 接口本身不证明浏览器来源；真实扩展通过下述原生确认流程填充，详见 [来源匹配验收与向量](docs/login-origin-matching-validation.md)。

团队方向已有 `internal/directory` 持久化核心：固定 owner/排序端/发布者信任根、签名 roster、精确父版本提交、撤销身份墓碑、检查点核验和整库冻结。真实 age/KDBX 测试覆盖撤销设备无法解开新代。目录变更当前为 Go API，已有下述只读管理 UI，尚无完整团队变更界面/网络同步；[协议、验收与限制](docs/team-directory-validation.md)。

新目录可用 `NewConfigWithPossession` 启用 scope 固定的强制设备双钥证明：owner 签名的 age 随机挑战、设备 Ed25519 响应、精确成员/设备/parent 绑定，并在持久提交和历史重读时强制检查新增设备证明。旧配置不能静默降级新目录；不证明物理设备唯一性，不替代邀请 UI、权限执行或同步。详见[设备证明验收](docs/team-device-possession-validation.md)。

新目录另可用 `NewConfigWithWriterACL` 同时强制入网证明与数据写权限：`BuildUpdate` 允许当前 writer 设备发布新密文，reader 不可发布，成员/角色/冻结仍只由 owner 授权。事务提交和历史重读都依据之前的可信状态执行权限检查；`Read` 返回验证后的 `SnapshotSigner` 供解密使用。写入仍是本地 Go API，只读管理界面不授予写入权限，网络同步尚未交付，见[团队写权限验收](docs/team-writer-acl-validation.md)。

个人 CLI 新增 `trash-login` / `restore-login`（`--file`、`--id`、`--revision`，SAVE 确认），以及 `list --state trashed`。回收站条目需先恢复才能读取或编辑，恢复时保留原活动/归档状态。备份和加密迁出仍包含回收站；不自动清空或永久擦除。详见 [回收站验收](docs/personal-trash-validation.md)。


### 原生桌面（开发版）

使用 Go 1.27.3 运行 `go run ./cmd/locklark-desktop`。界面由 MyGo 原生 UI 渲染，支持创建/解锁个人金库、标题搜索、逐字段显示/复制、编辑、归档/回收站、审计、体检和现有基本登录导入/加密导出。首次使用主密码与 Secret Key；解锁后在安全设置主动启用系统快捷解锁。Windows 使用 Passport KSP 的 Hello 私钥操作；macOS 构建需开启 CGO，使用本设备钥匙串及用户验证；Linux 使用 Secret Service。系统服务不可用时回到完整解锁，没有明文文件替代存储。

可用窗口或托盘中的“快捷搜索”，也可用 `Ctrl+Shift+L`（macOS 为 `⌘⇧L`）唤起。输入标题后按 Enter 查询活动登录，用 Tab 和 Enter 选定条目，再明确显示或复制字段。Escape 关闭搜索并保留原编辑草稿；锁定时只显示解锁界面，忙操作期间只唤起窗口。系统可能需要允许全局快捷键，窗口按钮始终可用。使用与验证范围见 [快捷搜索验收](docs/desktop-quick-search-validation.md)。

日常新建从搜索栏的“新建登录”进入，可填写网站并手工保存，或选择“生成强密码并保存”。默认生成24位字母数字密码，可设22–256位；保存后再按需显示或复制。已有活动/归档登录可选择“重新生成本地密码”，核对网站和条目后确认；这只更新本地金库，不会修改网站账号的密码。若提示有操作结果未确认，先核实金库内容，勿重复生成。

在条目的 `otp` 字段保存网站提供的TOTP密钥或 `otpauth://` 配置后，可按次“显示验证码”或“复制验证码”。显示最长15秒，复制最长30秒，且都受本期验证码的有效时间限制；到期后需明确重新获取。切换条目/页面或锁库会清理显示，并按系统所有权凭证清理本程序的剪贴板内容。Windows与Linux/X11会核对当前所有权，保留后来复制的内容；macOS的系统接口无法原子比较并清除，同时发生的新复制仍存在竞态。原生Wayland当前明确拒绝复制，可使用按次显示；系统剪贴板历史不受清理保证。实现和实际验证范围见 [日常桌面验收](docs/desktop-daily-validation.md)。

登录详情可按次“显示备注”“复制备注”或“编辑备注”。多行编辑器会先记录读取意图再填入原文，保存绑定当前条目的修订号；取消不改内容，锁库或切换目标会清除草稿。备注按纯文本加密保存，最长 64 KiB；浏览器填充和 Next.js 管理不会收到正文。1PUX 备注迁入及 KDBX 迁出保留换行和空格；导入来源记录仍可能保留编辑前的旧备注。范围与验证见[登录备注验收](docs/login-notes-validation.md)。

系统快捷解锁默认 24 小时后要求完整解锁；这是本地系统时间策略，不能抵抗系统时钟回拨。开启快捷解锁会将金库身份材料交给对应 OS 的保护机制；不保存主密码或 Secret Key。Linux 系统钥匙串可能不逐次弹验证，且同一系统用户的其他程序可能有读取权限。屏幕锁定/睡眠通知能否到达取决于平台会话服务。Windows Hello/TPM、macOS Touch ID 的设备行为尚需真机验收，当前不能作为生产替换承诺。详见 [桌面验收](docs/desktop-validation.md)。

### 浏览器登录（开发版）

使用流程参考 1Password：在桌面金库保存登录及对应 HTTPS 网站，安装扩展和原生宿主后，从网站的扩展工具栏入口连接。Chromium 可用 `Ctrl+Shift+Y`（macOS 为 `Command+Shift+Y`）。

1. 在原生窗口选择金库，使用主密码与 Secret Key 或已启用的系统快捷解锁，然后确认连接扩展。
2. 在扩展弹窗读取当前网站的登录候选并选择条目。
3. 在原生窗口核对精确网站、条目和版本，批准本次填充；扩展填入用户名和密码，由你自行提交表单。

此宿主使用独立原生会话。页面跳转、锁库或断线会使旧请求失效；重新连接需要再次确认。构建、Chrome/Edge/Firefox 注册路径及平台限制见 [扩展安装与使用](browser-extension/README.md)，真实填充链路和负测见 [浏览器验收](docs/browser-native-validation.md)。

要保存网页上已输入的登录，在扩展中选择“保存当前登录”，再在原生窗口核对网站并设置标题后批准。要替换已有登录的用户名和密码，先读取候选，选择该条目的“更新此登录”，再在原生窗口确认；标题、网站、OTP 和其他条目数据保持原样。保存的是点击时捕获的字段，不会自动检测提交或自动提交网页。原生批准后还会核对原浏览器文档；若显示“结果未确认”，请在桌面金库核实后再决定，不要盲目重复保存。具体实现/验收状态见 [保存与更新验收](docs/browser-save-validation.md)。

在登录条目中配置TOTP后，可在网站的扩展候选中选择“填充验证码”，再在MyGo窗口批准本次操作。支持6位或8位验证码，页面须有唯一可见、可写的标准验证码输入框，并属于同源表单；分格、多框和iframe暂不支持。扩展复核当前页面后才请求本次码，不主动提交表单，不自动换取下一期。种子和码不会显示在扩展弹窗或Next.js管理页。取消后若显示“结果未确认”，先核实页面，再决定是否重新发起；新操作仍需原生批准。实现及当前实际验收状态见 [浏览器验证码验收](docs/browser-otp-validation.md)。Passkey仍在后续范围中。

### Next.js 团队管理（本机开发版）

Web 界面使用 Next.js，只查看已验证的团队成员、设备和目录状态。Go 服务的 `--config` 必须是可信的 `{ "pins": ..., "anchor": ..., "policy": "writer-acl-v1" }` 配置；公钥与 checkpoint 必须来自可信原生端，不能直接信任从中继下载的文件。

已有真实团队目录时，在本机运行：

```sh
go run ./cmd/locklark-management --directory /absolute/team.db --config /absolute/trusted/config.json --connection /absolute/private/connection.json
```

在第二个终端中（Node 24、Go 1.27.3）：

```sh
cd web
npm ci
npm run build
LOCKLARK_MANAGEMENT_CONNECTION=/absolute/private/connection.json npm start
```

PowerShell 使用 `$env:LOCKLARK_MANAGEMENT_CONNECTION = 'C:\private\connection.json'`，再运行 `npm start`。启动器会调用 Go helper 检查连接文件与父目录权限；可通过 `LOCKLARK_MANAGEMENT_EXECUTABLE` 指定预编译 helper 的绝对路径。打开启动器打印的本机地址，输入同一窗口显示的一次性连接码。退出或连接码已用/过期后，重新启动 Web 界面可取得新码。不要将连接文件提交仓库或开放服务端口。

尚无团队目录时，可用 `go run ./web/tests/fixture -out /absolute/private/demo-team` 创建明确的合成只读演示，再将上面的目录和配置路径指向其 `team.db` / `config.json`；演示生成器不保留管理私钥，不能用于实际团队。浏览器填充、团队变更与远端同步仍在后续交付范围，详见[Web 验收](docs/nextjs-management-validation.md)。
