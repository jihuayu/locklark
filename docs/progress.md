# Locklark 开发进度

总规格与验收矩阵见 [design.md](design.md)。下表按依赖列出持续目标；只有实际跑过的范围才写为已验证。「待做」包括本机仍可开发的部分；只有需要外部条件的那条验收延后。

全部开发范围与每切片完成门槛见 [development-goal.md](development-goal.md)。已配置按小时接续的持续推进任务；只有实际完成的功能及验收证据才能更新完成状态。

2026-11-05 接续：PR #1 已合入 main `8c97e8537e1b5659a696339a02ff83122b6745b5`，下文早期“main 只有 README / PR #1 未合并”为历史记录。本轮在 `codex/personal-disclosure` 实现个人 CLI 受控单字段披露：交互确认、稳定 ID/修订、加密签名意图先提交、终端显示和无秘密 stdout 回执。并发编辑、事务失败、输出失败及包含披露意图的恢复均有回归；状态与 Luna/max 独立复核见 [personal-disclosure-validation.md](personal-disclosure-validation.md)。完整产品、外部密码评审和原生平台验收仍保留。

继续接续：PR #2 经 Luna/max 复核、修复和 Ubuntu/Windows CI 后已合入 `011814d`。本轮新增生成密码并创建/按修订替换个人登录的 CLI 事务入口；生成策略进入签名审计，原值仅加密保存，另用受控披露查看。范围、故障注入、旧版升级及检查证据见 [personal-generation-validation.md](personal-generation-validation.md)；生成不是上游网站改密。后续继续接通个人 TOTP 产品入口。

PR #3 已完成 Luna/max 复核和 Ubuntu/Windows CI，合入 `c37e833`。随即接续 `codex/personal-totp`，实现个人 TOTP 配置保存/清除、先记意图再计算的受控取码、窗口过期/回拨拒绝及配置生命周期清除；独立 Python HMAC 校验实际终端码。范围与验收见 [personal-totp-validation.md](personal-totp-validation.md)，仍不提供 Agent 种子或验证码访问。

PR #4 经 Luna/max 复核和 Ubuntu/Windows CI 合入 `55b3ae7`。继续从该基线开发 `codex/personal-references`：认证引用目录、按引用披露用户名/密码及生成验证码，在同一事务内解析、绑定、核对修订并提交意图；同名、类型串用和旧引用拒绝。验收与当前状态见 [personal-references-validation.md](personal-references-validation.md)。

PR #5 已完成 Luna/max 复核（修复 Unicode 格式字符造成的终端显示欺骗）、全仓与定向 race，以及最终 Ubuntu/Windows CI，合入 `85a3d6f`。继续开发 `codex/onepux-login-fields`，扩展 1PUX 登录字段的字面清点、重复/未知 designation、独立 type/fieldType 属性和共享容量预算；不输出源值、不授予迁移许可。证据与下一项见 [onepux-login-fields-validation.md](onepux-login-fields-validation.md)。

| 工作 | 已验证 | 下一项可开发、可验收的增量 |
| --- | --- | --- |
| 持库核心与兼容 | 双密钥、独立设备收钥、吊销后离线解密失败；Argon2id/旧 Argon2d 互操作；内置 1PUX 的原生登录/文档/附件与可逆迁出；TOTP 与密码生成核心验收；1PUX v3 只读清点及显式文件路径的匹配/缺失、共享与大小差异核对，来源审计回归通过 | 独立复核、区段/字段类型与重复标识预检、其他附件布局及完整条目/历史映射，以及真实迁移前的恢复演练 |
| 审计 | 按 session 查拒绝，写盘前筛查凭据；独立审计签名、前序摘要、可复制的签名检查点；删改与见证回滚负测 | 独立审计加密/恢复、持久日志事务、多签发端与跨设备见证，接入真实请求生命周期 |
| 成员、同步与恢复 | 同账号及多设备的文件级撤销；未实现团队目录或备份服务 | 签名成员目录和可信新鲜度；独立离线恢复材料，灾后新设备身份与新代次 |
| 远程授权 | 本地加密待办、独立会话公钥登记/签名、事务内撤销；已核实合成目标的签名决定、短有效期、事务性审计、请求替换及并发负测；合成元数据单次执行、崩溃未知和密文回执恢复 | 远程安全配对、独立决策流检查点、真实适配器和执行设备隔离；AI 只能否决 |
| 个人离线 CLI | 交互式建空库、独立保存 Secret Key、添加登录、跨进程双因子重开、列表只含 ID、标题和条目版本；按 ID 编辑标题、用户名和密码，同版本竞争只成功一次；事务内单独加密签名审计，拒绝单独截尾或替换快照；个人备份/恢复及独立历史检查点的 Linux 合成验收见本页交接 | 受控披露、生成保存、TOTP 和认证引用已接入；下一步系统解锁与独立日志见证 |
| 字段引用基础 | 纯 Go 元数据核心支持三/四分量、名称/ID、大小写及区段；个人 v1 与内置合成导入分别保留其字段身份和修订来源；已解析目标可精确校验为原生槽位/类型，拒绝旧修订、跨布局、区段错配和文档取值；未知 profile、重复键、槽位重绑、缺失修订和部分结果拒绝；OTP 配置与生成码类型分开，竞态与模糊测试通过 | 独立复核、固定 op v2 行为对照与通用导入；个人 v1 的可信事务、人工披露及 OTP 已接入；其他布局未接入 |
| 桌面、浏览器和移动 | 只有 CLI 演练 | MyGo 原生托盘、系统解锁、搜索和审批；浏览器、iOS/Android 客户端和真机验收 |
| 网关与 Web | 限仓库的 MCP stdio 工具与 Bun 提案；持久去重、带时间的状态、原会话的签名录制回执；重启重复领取不再次执行，插件换版后旧登记只读 | 跨机安全配对、真实仓库级上游委托、签名安装、第三方 OS 沙箱和 Next.js 管理界面 |
| 机器授权 | 已定 invoke 与 deliver 独立部署 | 分别签发/吊销、固定上游及交付对象，串用凭据的负测 |

MCP stdio 这一批已在 Windows 和 WSL Linux 用真实子进程验收。提交范围 `4932c8d..a0d8ab1` 的独立代码复核尚未完成；本地测试不能替代这项检查。

回执领取已通过 Windows 和 WSL 的跨进程验收；Windows 双版本实验确认旧模块只可查状态和领取已签发的结果。独立复核 `db59690..f03956a` 发现本地接收身份遗失时重试可能生成无效替代身份；`e473c4f` 修复，分别保留票据或回执的负测通过，独立复核确认关闭。升级恢复要求已有原投递标识。

KDBX 互操作已在 Windows 和 WSL Linux 使用 PyKeePass 4.2.0 验收。上一版 CLI `3218ef7` 写出的第 2 代快照由新 CLI 打开：保留设备 B 成功，被撤销的 A 失败。独立复核指出本地模块替换会破坏按版本安装 CLI，以及受保护 Notes 标记未被断言；`9d2ca2d` 修复，两项均通过独立复核。按提交安装使用本地 Git/模块代理验证，没有发布版本标签。该验收仅覆盖载荷容器，尚未完成原生条目映射。

原生条目批次在 Windows 和 WSL 用 PyKeePass 按 UUID 修改同名登录、TOTP 和附件；外部修改必须重新签名。新 CLI 迁出旧布局和新布局第 1、3 代的 1PUX 字节完全相同。独立复核发现到期等行为设置和附件内存保护位可能在重封时丢失；`fa34545` 对前者明确拒绝，后者保留并独立读回，两项均已复核关闭。其他类别、历史和真实导入未验收。

个人库 CLI 已在 Windows ConPTY 和 WSL PTY 使用新进程通过 `scripts/personal_acceptance.py`，测试数据由验收现场生成。缺少或替换任一因子会被拒；查询不重写金库；损坏事件、单独删除末条日志或替换旧快照后拒绝继续写。个人库测试及竞态检查通过。独立复核所报的终端回显窗口和目录发布持久性已在 `c5d4f52` 修复并复核关闭。Linux 使用目录同步，Windows 请求不覆盖目标的写穿移动；未实测硬件断电。尚无换机恢复、外部审计见证、系统钥匙串或个人库团队同步。

个人条目编辑已通过 Windows ConPTY 与 WSL PTY 的双进程竞争：两个编辑者读同一版本并同时提交，只有一个成功，另一个得到冲突。Go 竞态测试解密核对实际赢家的密码、另一同名条目不变、冲突事件关联赢家版本。上一版 `d294bb4` 创建的个人库可直接升级；写入新事件后旧客户端明确拒绝。独立复核指出的列表文档与赢家验收两项已在 `79e92e2` 修正并复核关闭。

当前交付为离线个人库预览与合成网关演练。正式使用仍需要独立安全评审、干净机器恢复、移动真机与逐平台 1Password 行为对照。

Cloud 恢复安全修复已提交为 `43c6732`，在 PR #1 的原 `codex/first-preview` 分支接续；main 核对为 `3901bc8d8c91c8da039fa02d83e1521746c3c5aa`。恢复验证及目标预检先于新 Secret Key，发布仍原子拒绝覆盖；LLR2 独立离线材料固定整份签名备份检查点，旧 LLR1/版本 1 明确拒绝。Linux 真实 PTY 的错误恢复码、损坏备份、已有目标、旧格式及迟到目标负测通过，完整重签历史负测通过，容量与历史段数错误已区分。实跑检查、失败测试及复核/CI 门槛详见 [recovery-validation.md](recovery-validation.md)。尚未合并，不能把本地结果计为 GitHub 通过；后续从更新 main 实现受控人工单字段披露。

恢复来源复查在 `7054bf5` 上复现 FIFO 与 FIFO 符号链接打开时阻塞，`888944e` 改为 Unix 非阻塞打开并在读前核验句柄，非普通文件明确拒绝。Linux 单测、全量 Go、个人库竞态、真实 PTY、MCP/Bun 及 Windows/macOS 交叉编译通过；正常备份文件符号链接的恢复审计正例通过。原生 Windows/macOS 特殊文件行为及独立复核仍未完成，PR #1 合并门槛继续保留。main 仍为 `3901bc8d8c91c8da039fa02d83e1521746c3c5aa`；本轮命令、失败证据和后续工作见 [recovery-file-source-validation.md](recovery-file-source-validation.md)。

字段引用核心 `0dece6d` 从最新实际 head `78ed9e5` 接续，作为外部阻塞期间不依赖存储和未合并 main 的基础增量。模块不含字段值、不认证元数据、不授予权限，也未开放人工或 Agent 原值读取。全量 Go、核心竞态、789326 次模糊执行、个人 PTY、MCP/Bun 回归及 Windows/macOS 测试包交叉编译通过；固定 op 版本、原生运行、独立复核和真实事务审计接入仍未完成。main 仍为 `3901bc8d8c91c8da039fa02d83e1521746c3c5aa`，工作分支仍是 PR #1 的 `codex/first-preview`。失败测试、实跑命令和代码 head 的具体远端检查见 [reference-validation.md](reference-validation.md)。

个人原生字段投影实际发布为 `a1b95a6`（本地已测试实现 `eaf6331`，文件树完全相同）。登录投影不复制字段原值，文档身份参与同名拒绝；真实加密库的改名/恢复投影分别对上原/新签名账本修订。全量 Go、个人/引用竞态、338048 次投影模糊输入、PTY、Bun/MCP 及 Windows/macOS 测试包交叉编译通过；生产原子事务、原生平台、独立复核和固定 op 对照仍未完成。发布时 CLI 新出现 401，已通过 GitHub 连接器带预期 head 快进原分支并同步本地提交记录。main 保持 `3901bc8d8c91c8da039fa02d83e1521746c3c5aa`，PR #1 仍未合并；远端结果、发布方式和下一项见 [personal-reference-metadata-validation.md](personal-reference-metadata-validation.md)。

合成导入引用投影 `12612b113d92fba24a813530175a20acff702b37` 从实际 head `3a0184b` 接续并推送原分支；本轮终端 Git/gh 访问已恢复。投影仅接受内置原生演练布局，保留源 `ops/otp-demo`，不沿用个人字段映射，不复制原值；真实加密快照改名/轮换后身份不变、快照签名版本改变，并核对审计与独立检查点。全量 Go、定向竞态、911 次模糊输入、个人 PTY、Bun/MCP、静态检查及 Windows/macOS 测试包交叉编译通过。main 仍是 `3901bc8d8c91c8da039fa02d83e1521746c3c5aa`，工作分支为 PR #1 的 `codex/first-preview`；新增切片与此前待复核范围均未完成独立复核，未 squash。远端精确链接、失败先行证据、未验证平台和下一项见 [fixture-reference-metadata-validation.md](fixture-reference-metadata-validation.md)。

字段槽位/类型绑定 `0970d63ae95fc5e8673da7bcd6c0ef5116b1d953` 从实际 head `c0a494f` 接续并推送原分支。两个 profile 的绑定均复用完整投影验证；之后只接受精确 ID、区段和修订，输出固定槽位及文本/密码/OTP 配置类型，不读取原值或授权。个人改名/恢复与合成快照轮换的旧目标拒绝，当前绑定对应已验签审计来源。全量 Go、定向 race、677430 次目标模糊执行、个人 PTY、MCP/Bun、静态检查，以及两个包的 Windows/macOS 测试包交叉编译通过。main 保持 `3901bc8d8c91c8da039fa02d83e1521746c3c5aa`，工作分支为 `codex/first-preview`，PR #1 仍未合并；独立复核与远端门槛未关闭。失败先行、准确检查链接、平台缺口与下一项见 [reference-binding-validation.md](reference-binding-validation.md)。

TOTP 核心 `295e8c35601941ca02c13e4afd8c203ebbb5f0a7` 从实际 head `8d5d81d` 接续并推送原分支。公开 RFC 6238 的 18 个向量、RFC 4226 的 10 个计数向量、半开时间窗口、参数拒绝、普通输出脱敏与并发测试通过；708401 次模糊执行无失败。使用独立合成强种子，经真实加密快照读回、源字段绑定及独立审计检查点验证后计算，与 RFC 输出一致，审计/序列化不含种子或码值。原内置短种子演练不改写，新核心明确拒绝；尚无产品取码或披露审计入口。全量 Go、定向 race、PTY、MCP/Bun、静态检查与 Windows/macOS 测试包交叉编译通过。main 保持 `3901bc8d8c91c8da039fa02d83e1521746c3c5aa`，工作分支为 `codex/first-preview`，PR #1 未合并；独立复核与逐平台运行未完成。准确范围、失败测试、远端检查和下一项见 [totp-validation.md](totp-validation.md)。

密码生成核心 `9d3bcb2d2c47f1e5899aa28e464ad6afc7797caa` 从实际 head `0d1cfc6` 接续并推送原分支。系统 CSPRNG、标准库无偏拒绝采样、精确整数熵校验、随机源失败零结果和敏感输出脱敏均通过；786630 次模糊执行无失败。真实合成个人库保存生成密码后可重开，签名 `item.add` 审计通过，数据库及普通报告未出现原值；该事件只证明新增条目，不冒充生成/披露事实。全量 Go、定向 race、PTY、MCP/Bun、静态检查及 Windows/macOS 测试包交叉编译通过；尚无产品生成入口、独立复核、原生平台及真实 op 对照。main 保持 `3901bc8d8c91c8da039fa02d83e1521746c3c5aa`，工作分支为 `codex/first-preview`，PR #1 未合并；具体检查、失败证据、平台边界与下一项见 [password-generation-validation.md](password-generation-validation.md)。

1PUX 只读清点 `3dc0f9fdabb9822a401af3f4d36bcba24c9df473` 从实际 head `4e0a721` 接续并推送原分支。在内存中校验 ZIP/CRC/严格 JSON，按账号/库作用域核对 ID 并输出受限计数和固定原因码；所有条目始终标记未映射，不将清点成功称为可迁移。自查新增负测修复了目录预算检查过晚、尾随数据、跨磁盘记录、目录后缀掩盖符号链接及末尾记录选择差异。全量 Go、定向 race、ZIP 256165 次/JSON 200688 次模糊执行、PTY、MCP/Bun、静态检查和 Windows/macOS 测试包交叉编译通过。真实加密演练来源的独立审计检查点核验与报告秘密扫描通过；没有新增通用迁移或产品预检审计入口。main 保持 `3901bc8d8c91c8da039fa02d83e1521746c3c5aa`，工作分支为 `codex/first-preview`，PR #1 未合并；独立复核、附件关联、原生平台及真实导出对照仍待完成，详见 [onepux-preflight-validation.md](onepux-preflight-validation.md)。

显式文件关联 `b2347ac8c0d637f653c271944232e433ce2f60f9` 从实际 head `1c191e7` 接续并推送原分支。只按 item.file.path 的归档相对路径与经 CRC/实际长度校验的文件精确匹配，不用 documentId/fileName 猜路径；报告匹配/缺失/重复引用、唯一已关联文件、未被当前显式引用覆盖的文件、缺少路径条目与大小差异。保留整体未映射状态，不据此删除文件；旧演练缺少显式路径仍未验证。全量 Go、定向 race、ZIP 650560 次/JSON 115570 次模糊执行、PTY、MCP/Bun、静态检查及 Windows/macOS 测试包交叉编译通过；来源审计/检查点与无私有值回显回归通过。main 保持 `3901bc8d8c91c8da039fa02d83e1521746c3c5aa`，工作分支为 `codex/first-preview`，PR #1 未合并；独立复核、其他附件布局、原生运行及真实导出对照未完成，详见 [onepux-file-references-validation.md](onepux-file-references-validation.md)。

区段/字段结构清点 `63cb54fde5c72834baef0fd0fafe0360f9232d61` 已接续原分支：重复名称/字段 ID 按源作用域计数，不合并；值按 JSON 形状统计，语义与迁移仍未验证。合成失败测试、包内测试、定向 race、229677 次 fuzz、来源审计/报告隐私回归与 Windows/macOS 测试包交叉编译通过；独立复核和远端门槛未满足，main 仍为 `3901bc8`。实跑命令、限制与后续 loginFields 清点见 [onepux-sections-validation.md](onepux-sections-validation.md)。

Windows CI 恢复实际运行后，`38b308d` 的 Ubuntu 成功，Windows 在个人 backup 的 ConPTY JSON 读取失败；不再沿用付款/额度阻塞结论。已用合成传输失败测试复现并在 `45f2e79` 修复子进程退出后的输出排空，`020622f` 将回归加入双平台 CI。Windows 原生运行又发现传输不发 EOF，`dd68eef` 改为完整响应加输出静默并保留截止时间；延迟输出、延迟秘密回显、不发 EOF 三项本地测试通过；原生结果与独立复核单独记录，main 未变，详见 [conpty-drain-validation.md](conpty-drain-validation.md)。

ConPTY 修正版 `dd68eefdb0dc744436403299b382b3ebfbeb1fa5` 的 [run 41943464262](https://github.com/jihuayu/locklark/actions/runs/41943464262) Ubuntu/Windows 均成功，个人终端恢复、审计及 MCP 验收通过，关闭本批真实 CI 失败。该结果不是全平台产品验收；PR #1 独立复核仍待完成，未合并 main。

PR #1 的 `f0c58e3` 已完成三个经用户授权的 Luna/max 独立代码复核：恢复与个人审计、MCP/Gateway执行回执、引用/生成/1PUX/ConPTY 基础模块，均未确认阻塞当前预览合并的可复现缺陷。审查者实跑定向单测、关键路径 race、PTY/MCP；完整 preview race 仍未完成。具体范围及命令见 [pr1-independent-review.md](pr1-independent-review.md)，本记录更新上述范围的历史“待独立复核”状态；不关闭外部密码评审、整库/决策库独立回滚见证、真实平台及全部设计验收。main 仍为 `3901bc8`，合并前须核对本交接提交的双平台检查。用户已持续授权 Luna/max 子代理复核及满足门槛后的正常 squash 合并，无需重复确认。
