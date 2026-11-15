# T4_06：terminal lease 与真实改密闭环设计

状态：**设计检查点，未实现 lease，T4_06 仍未验收通过**。本文固定基线
`80ec7b821030d1643f61393abd5edf3f77a8e0d9`，只定义安全边界、状态机和逐步验收。
文中的 grant/use/refresh 是拟议的产品操作，不是现有 CLI 命令。

首平台选 **Darwin**，首 target 仅为现有 **`netrc` profile + 受保护的
`/usr/bin/curl` + 固定的真实 HTTPS 认证目标**，沿用已有 one-shot broker 和 native
review 的安全边界。本范围不支持可替换的第三方 program。Linux GUI CI
可以承担其已有浏览器/桌面验证，但当前 Linux CLI broker client 未启用，peer TTY
authority 也不可用；GUI 能运行或 `cli-broker-v1` 被列出，都不构成 terminal lease
支持。Darwin 本机 AX blocker 尚未解除，本文没有运行 GUI，也不声称已有完整 positive。

交接验收记录中的 **CI 377 PASS 仅覆盖 R0→R1 后 fresh one-shot 的链路**，不能提升为
lease invalidation/refresh 或 browser rotation 的验收。本文未重跑或重新获取该 CI
记录；以下源码结论在上述基线上核对。真实检测、网站、浏览器、保存、terminal 和
lease 必须贯穿同一个 target，不能拼接组件成功数。

## 已存在的边界与缺口

| 已读证据 | 该证据能说明什么 | 仍不能说明什么 |
| --- | --- | --- |
| [`tests/e2e/tier4_scenarios.py:276–338`](../tests/e2e/tier4_scenarios.py#L276-L338) | T4_06 执行 opt-in/拒绝合同和本地 CONNECT/TLS HIBP mock 子步骤，然后保留显式 `UNVERIFIED` | 未执行浏览器改密、旧 lease 拒绝或 refresh；能力探测为真也不能 PASS |
| [`tests/e2e/support.py:2184–2202`](../tests/e2e/support.py#L2184-L2202)、[`internal/browserhost/types_v2.go:9–29`](../internal/browserhost/types_v2.go#L9-L29) | F17 helper 检查源码是否存在桌面与 CLI 路径；能力列表包含 `cli-broker-v1` | 源码字符串或能力名不是运行时平台支持、进程信任或 lease 生命周期证明 |
| [`cmd/locklark/cli_broker.go:19–43`](../cmd/locklark/cli_broker.go#L19-L43)、[`cmd/locklark/cli.go:1210–1227`](../cmd/locklark/cli.go#L1210-L1227) | 生产 dispatcher 仅在 Darwin 尝试 broker；每次建立 one-shot 请求 | Linux broker client 为 false；没有可复用 terminal lease |
| [`cmd/locklark/cli_broker.go:73–153`](../cmd/locklark/cli_broker.go#L73-L153) | 将已提交的 request/targets、private root 和新 nonce 变成精确 scope，核对 canonical request | caller 的 ProgramSHA256、TTY 声明不能自行成为可信代码/真实执行证明 |
| [`internal/browserhost/broker_peer_darwin.go:16–60`](../internal/browserhost/broker_peer_darwin.go#L16-L60) | 读取 socket 本地凭据、peer PID 和系统报告的路径，路径失败可退到进程名 | `Peer` 没有进程世代或签名/image trust；PID、路径、进程名不足以授权可复用 lease |
| [`internal/browserhost/broker_tty.go:105–111`](../internal/browserhost/broker_tty.go#L105-L111)、[`internal/browserhost/broker_tty.go:177–252`](../internal/browserhost/broker_tty.go#L177-L252)、[`internal/browserhost/broker_tty_darwin.go:18–22`](../internal/browserhost/broker_tty_darwin.go#L18-L22)、[`internal/browserhost/broker_tty_linux.go:57–63`](../internal/browserhost/broker_tty_linux.go#L57-L63) | Darwin broker 核对 peer 的 kernel controlling TTY；Linux peer attestation 明确关闭；声明的 TTY peer ID 被拒绝 | 一个终端设备号并不自动证明跨 CLI 进程的稳定 session authority |
| [`internal/browserhost/broker.go:405–467`](../internal/browserhost/broker.go#L405-L467)、[`internal/browserhost/broker.go:521–617`](../internal/browserhost/broker.go#L521-L617) | nonce 先消耗，再核对 TTY；连接取消和绝对审批时限可阻止 secret reply；TTY 失败在实际 serve 路径归为固定拒绝 | 不是 lease grant/use/refresh 协议；不能把内部 unavailable 注释当作 fallback 授权 |
| [`internal/browserhost/broker_replay.go:12–38`](../internal/browserhost/broker_replay.go#L12-L38)、[`internal/browserhost/broker_replay.go:120–171`](../internal/browserhost/broker_replay.go#L120-L171) | 当前 replay cache 在 broker 进程内，以 authenticated peer label 与 nonce 的 digest 去重，拒绝不回收 | 不是持久 lease store，也没有进程世代绑定；cache TTL 不是拟议 lease TTL |
| [`internal/desktop/ipc_broker.go:209–346`](../internal/desktop/ipc_broker.go#L209-L346)、[`internal/desktop/ipc_broker.go:349–429`](../internal/desktop/ipc_broker.go#L349-L429) | 现有 native review 绑定不可变 scope/targets、当前 vault/session/epoch，审批后仍重查并通过 audited preparation 返回值 | 现有 native review 不可因新增 lease 被默认放开；桌面 preparation 不启动 child |
| [`internal/personal/run_bundle.go:177–218`](../internal/personal/run_bundle.go#L177-L218)、[`internal/personal/run_bundle.go:395–446`](../internal/personal/run_bundle.go#L395-L446) | 在 authenticated transaction 中逐个核对 exact revision，任何 stale target 都清除已提取值；准备值与 intent receipt 配对 | 新 revision 不能静默替换进旧授权；preparation receipt 不是执行证明 |
| [`internal/personal/run_bundle.go:636–687`](../internal/personal/run_bundle.go#L636-L687)、[`internal/clibinding/binding.go:220–254`](../internal/clibinding/binding.go#L220-L254) | optional program pin 在文件写入/启动前重查，但仍按路径执行 | 源码明确不承诺 atomic exec-byte/TOCTOU 保证；path hash 不证明运行的 image |
| [`internal/cliprofile/profiles.go:207–223`](../internal/cliprofile/profiles.go#L207-L223) | `netrc` 使用 username/password/url slots、private `home/.netrc` 与 `NETRC`，允许的 executable 名称为 `curl` | profile 并未证明解析结果是受保护的 `/usr/bin/curl`，也未验证实际网站认证 |
| [`internal/browserhost/save.go:307–324`](../internal/browserhost/save.go#L307-L324)、[`internal/desktop/browser.go:354–387`](../internal/desktop/browser.go#L354-L387) | native update review 展示 HTTPS origin、same item ID 与 exact revision，并要求批准更新 | 保存不验证网站账号正确性；仍必须以网站实际认证验证新旧值 |
| [`internal/terminalpeer/doc.go:1–39`](../internal/terminalpeer/doc.go#L1-L39)、[`internal/terminalpeer/snapshot.go:99–108`](../internal/terminalpeer/snapshot.go#L99-L108)、[`internal/terminalpeer/snapshot.go:158–166`](../internal/terminalpeer/snapshot.go#L158-L166) | 观察 socket 当前 accessor，比较 token、generation/start、TTY 和 token-bound path 的有限读窗口 | 不能证明 original connector，不能证明代码真实性，不能创建、续期、复用或验证 lease |
| [`docs/release-trust.md:1–8`](release-trust.md#L1-L8) | release validator 是 source-only preparatory checkpoint | 不是已部署的 runtime CLI code trust root，也不证明外部 signing/release 事实 |

## 必须先成立的 authority

授权由桌面 broker 持有。client 请求、caller 自报 TTY/路径/hash、环境变量、binding
文件和 `terminalpeer.Observation` 都是需要核验的输入，不能单独产生 authority。

每次 grant、use、refresh 至少重查：当前连接的实际 kernel peer、CLI 进程世代、实际
controlling TTY/session 与稳定 session-owner anchor 的真实关联、可信 CLI image、
vault/session epoch，以及 exact scope。
检查到变化、无法证明或未知情况即拒绝，在披露 secret、生成 credential 文件和启动
目标 child 前停止。有限的双读只能拒绝观察到的变化，不能被描述成无竞态证明。

**进程和代码信任是首个实现阻断项。** 当前 `authenticatedPeer` 的 PID/path 不够；
不能直接将 `terminalpeer` 的 current-accessor snapshot 接到 grant 分支上。需要先决定
并验证消息发送者与实际进程世代的关联、descriptor 继承/传递及 exec 变化的处理。
如果所选 kernel IPC/认证机制不能证明所需边界，继续拒绝该模式，而不是退为路径匹配。

**可信代码 pin 的来源是独立阻断项。** 必须由 client 无法自选或改写的信任根确定允许
的 CLI image 与版本；需要明确 Darwin kernel-backed code identity/签名验证、可信分发
及 pin 更新/撤销来源。签名“有效”也不能代替“签发者和该 release 被本产品信任”。
当前 source-only release validator、本地重新签名、caller 提交的 hash 或可写文件均不
满足此要求；具体机制见决策表，未定前不授予 lease。

**protected target execution 也是披露前阻断项。** 首版只允许 `netrc` 的受保护
`/usr/bin/curl`，`ProgramSHA256` 对这条路径必须非空；当前源码仍将它视为 optional，
本设计没有宣称约束已经落地。必须实际验证该系统 image 的代码身份、路径保护及其
持续成立的运行环境前提，不能假定任意 Darwin 机器或任意绝对路径均受保护。若系统
保护被禁用、状态无法读取或无法绑定到实际启动的 image，拒绝，不退为 hash 后 exec。
broker 必须证明准许的 program/profile 与实际接收凭据并启动的 child 一致，并拒绝
审批后替换、同路径新 image 及 exec 窗口变化。当前 hash 重查后按路径 `exec` 仍有
明确限制。
不能先把 secret 交给未完成信任验证的 CLI，再以 child 自报成功补足证明。有关
`6fbcb824` 的 execution 研究不在本设计中启用、移植或提升为已完成保证。

## scope 与 token 内容

lease 是 broker 持有的、**不含 secret 的授权记录**；对外 handle 不能自行扩权。
它至少绑定以下不可变元组，具体 wire 名称和存储机制尚未确定：

| 绑定项 | 权威来源和校验要求 |
| --- | --- |
| OS principal、稳定 kernel TTY/session-owner anchor、允许的 CLI code requirement | broker 独立建立主体及其真实终端关联；不能使用 caller TTY 字符串、设备号或环境变量作为 authority |
| 每次操作的实际 CLI audit-token process generation 与动态代码认证 | 属于 per-use envelope，不要求等于首次临时 CLI PID；对新的实际调用者独立认证，区分退出重用和 exec/image 变化 |
| profile ID 与 spec identity/version | broker 自己解析受信 built-in spec；拒绝 caller 注入 spec 或 profile 切换 |
| 受保护 `/usr/bin/curl` 的 code identity/必填 ProgramSHA256、argv、cwd、helper path、passthrough、timeout、credential destination policy | native review 与 actual execution 使用同一 canonical scope；限定 netrc、固定 HTTPS 目标、禁第三方 helper/用户配置/转向其他目的地；具体策略须定案 |
| vault identity、当前 unlocked session identity 与 epoch | broker 当前状态；路径只是定位信息，不能单独代替 vault identity |
| exact target item IDs、每项 revision、field/slot | grant 固定 R0；use 在 authenticated transaction 重查当前 revision，任一变化全部拒绝 |
| 授予时刻与 absolute expiry、lease generation/handle | broker clock 与 store；活动、失败、refresh-pending 不延长原 deadline；重启使旧 handle 失效 |
| 每次操作的 single-use nonce 与操作种类 | broker 在产生授权副作用前原子消耗；拒绝、取消、过期、断连和未送达也不恢复 |

lease 是可多次 use 的 **scope approval**；每次 use 的 exact request、实际 CLI 世代、
nonce、private run root 和 receipt 是独立 envelope。现有 one-shot scope 固定
`TempRoot`，而新的 CLI invocation 会创建新的 root；不能通过忽略此字段复用。必须
明确 native grant 审批的受限 root/destination policy，并在每次 use 验证真实私有
root 的身份、权限与 canonical request/intent 绑定。具体机制未完成前，复用不启用。

token、lease store 和审计不携带 password、prepared values、完整 HIBP hash/suffix、
Secret Key、私钥或网站 session credential。若 canonical scope 需要比较可能敏感的
argument/passthrough 值，使用 broker 私有比较材料/承诺的机制须单独定案，不能将值
序列化进可流转 lease。prepared values 只在通过 use 的现有受审计通道短暂出现，并按
实际能力清除；不作 Go immutable string 可强制擦除的承诺。

现有 **60 秒 approval lifetime** 与 **2 分钟 nonce cache TTL** 分别是既有 one-shot
审批和 replay cache 常量，不是 lease 的已选 TTL。lease TTL、时钟失败处理和重启
epoch 的具体编码均须先定案；要求是绝对时限、无 sliding renewal、失败关闭。

## 稳定 session 主体与每次 CLI 进程绑定

lease 的稳定主体选择 **kernel TTY/session-owner anchor**，不绑定首次临时 CLI PID。
同一真实 shell/TTY 中新启动的公开 CLI 必须可在原 absolute TTL 内多次使用同一 scope
approval；但每次都重新认证实际 CLI audit-token 世代及动态 code requirement，不能
只检查 same TTY 或旧 handle。anchor 的 kernel 来源、生命周期及其与当前 CLI 的
真实关联尚未实现；Name/Dev/Unit 相等不够，缺失 proof 时禁止启用复用。

`issuerPID == callerPID` 不能区分 PID 重用，附加 start/generation 后也仍会拒绝普通
shell 下一次新启动的 CLI。它不能实现上述 per-TTY 产品语义。一个存活的可信
issuer/controller 可用于首个 kernel proof 的中间组件验证；**不能替代公开 CLI
跨新进程的真实最小 T4_06 闭环**，也不能用它缩小最终验收范围。

新进程不是旧 issuer；继承文件、复制 token、同 TTY 路径或同一 user 均不能构成转移
授权。`LOCAL_PEERTOKEN` 会随 socket 最近 accessor 改变，不能当作初始连接者或稳定
terminal session 的凭据。必须分别证明稳定 session 主体与本次实际 caller 的关联。

每次 use 的 nonce 一次性消耗，lease 在成功 use 后仍保留原 expiry 和 scope。T4_06
用 **仍在 TTL 内的 R0 lease + 新的未消耗 nonce** 验证 revision 拒绝，不能用已消耗
nonce 的 replay 拒绝代替。旧 lease 一旦 invalidated，任何新 nonce 都不能复活它。

## 状态机与边界

下表描述拟议授权状态；use transaction 的一次性消耗另行记录。所有终态都保留旧
handle 不可复活的语义。失败原因可以在私有审计中区分；公开响应使用固定非敏感结果。

| 当前状态 | 事件/检查 | 新状态与必须产生的结果 |
| --- | --- | --- |
| 无 grant | 显式 grant；身份、代码、TTY/session、vault/epoch、scope 校验完整 | `grant-pending`，只展示 native review；尚无 secret、credential 文件或目标 child |
| `grant-pending` | owner 对同一 immutable snapshot 原生确认；再次核验全部绑定与当前 revision | `granted`，发出新 secret-free handle，固定 expiry 与 exact revisions |
| `grant-pending` | 拒绝、取消、断连或审批超时 | `cancelled` / `expired`，消耗本次 nonce，无授权、无 fallback |
| `granted` / `refreshed` | 显式 use；有效 nonce 被原子消耗；全部绑定仍匹配 | `use-pending`；串行/原子保留该 use，禁止并发重复披露 |
| `use-pending` | 在同一授权边界内重查 revision/epoch、记录 intent、核验接收者和 protected execution | 本次 use 为 `used`，一次实际 child；receipt 只能证明其实际已覆盖的阶段 |
| 本次 use 已 `used` | 原 lease 绑定仍有效且未到期 | lease 回到 `granted` / `refreshed`，scope/expiry 不变；本次 nonce 永远不能复用；下一次 CLI 必须独立认证 |
| `granted` / `refreshed` / `use-pending` | target R0→R1、撤销、删除/回收站、profile/spec/程序/scope/anchor/TTY/session 改变，或本次已认证 caller 在操作中发生世代/image 变化 | `invalidated`，旧 handle 永久失效；披露前发现时 zero child、zero credential 文件、zero target TLS；合法新 invocation 仍须独立认证 |
| 任意未终止授权 | absolute deadline 到达 | `expired`，包括已打开的 review；不能因鼠标/终端活动延长 |
| `invalidated` / `expired` 或 owner 主动替换旧 grant | owner 显式 refresh | `refresh-pending`；主动替换时先原子撤销旧 handle，其余旧 handle 保持无效；重新读取当前 R1 和完整 scope，重新完整 native review |
| `refresh-pending` | 新 review 确认，并再次核验当前 revision/代码/本次进程/anchor/TTY/session/vault/epoch | `refreshed`，全新 handle/generation/nonce/absolute expiry，明确绑定 R1；旧 handle 仍拒绝；仅显式新授权可有新时限 |
| `refresh-pending` | 取消、断连、过期、再次变化或审计失败 | `cancelled` / `expired` / `invalidated`，没有可用新 grant，旧 token 不复活 |
| 任意 pending/granted 状态 | lock、session epoch 变化、broker shutdown、显式 revoke | `locked` / `revoked`，撤销全部关联 grant，取消 review 和未披露 use；unlock 不恢复旧 handle |

refresh 不是给旧 token 更新 revision，不是 `cli bind`/re-sign，也不是自动重试。
old token 的 R0 不匹配当前 R1 时，即使 TTL 尚充足，也必须拒绝；不得静默读取 R1
后执行。refresh 的新 review 必须重新展示当前 R1、目标和完整执行范围。若确认期间
再次变为 R2，应拒绝本次确认，等待 owner 再次显式发起操作。

use 的允许点必须与 revision/epoch 校验、nonce 消耗及 audited preparation 形成明确
线性化边界，拒绝 revision 校验后再披露的竞态。具体实现见 D5。已披露给可信 child 的
凭据不能被 lock 擦回，网站已经接受的请求也不能撤回；报告须区分披露前拒绝与运行中
取消，并保留既有 child cancellation 的实际保证，不扩大为终止任意后代的承诺。

## 逐步真实验收：同一 target 的最短闭环

以下是未来实现的 release acceptance 合同，**本次文档变更未执行**。测试账号、网站
和 HIBP 路由必须是事先同意使用的测试目标；不借用真实个人凭据。自动化使用产品真实
入口和原生确认，不能调用 test approver hook 代替 owner review。

1. **建立单一 target 链。** 在受控 HTTPS 网站创建测试账号，以产品正常入口将该账号
   保存为 vault 中同一 item 的 R0。记录内部关联关系：网站 origin/account、item ID、
   R0、netrc/curl、kernel terminal session-owner anchor 与每次 CLI caller。公开证据只输出脱敏关联
   标签。网站接受旧值；准备好的 TLS/child 观察面须能区分本次 use 和浏览器请求。
2. **真正同意并检测该 target。** 经真实 consent 运行 shipped
   `personal health --hibp true` 路径，固定 HIBP destination、HTTPS 和 range lookup
   合同保持不变。受控 CONNECT/TLS HIBP range server 可隔离测试网络，但必须仅为这
   个 target 返回匹配结果，证明结果落在同一 item/R0 上；这证明真实客户端的受控
   fixture 路径，不冒充公网 HIBP 生产服务可达性。拒绝 consent 也须另验无查询、无
   intent。不能仅运行 source capability helper 或脱离该账号的 breach 计数。
3. **在真实 terminal grant R0。** 在已完成 kernel/code trust 的 Darwin native surface
   中，由 owner 对同一 target/R0、完整 scope 进行原生确认。经公开 CLI 的多个新进程
   在同一真实 kernel TTY/session-owner 下 use 同一 lease，每次独立认证实际 CLI
   世代/code requirement、消耗新 nonce，实际 `/usr/bin/curl` 通过 netrc 认证该网站。
   确认成功 use 不滑动 expiry。保留该 R0 lease 和新的未消耗 nonce，记录其尚有
   绝对有效期；组件内同一进程循环不能替代此验证。
4. **真实浏览器改密。** 从同一检测目标进入其真实 HTTPS 改密表单，用浏览器产品的
   generator 生成新值，经真实 fill、表单 submit 和网站校验完成修改；浏览器应收到
   实际成功响应。继而在 Locklark 的真实 native save review 明确更新同一 item，
   完成 **R0→R1**。确认 item ID 未变、新 revision 非 R0、保存值与网站实际新值
   一致。不能用 CLI edit/generate、后台直接写 vault、native message 人工注入或
   测试服务器直接改密码替代这一步。
5. **旧 grant 在尚未过期时拒绝。** 从新的公开 CLI invocation，在相同 kernel
   TTY/session-owner anchor、通过本次独立代码/世代认证、相同可信代码
   和执行 scope 下，使用 R0 handle 与全新未消耗 use nonce。内部证据确认有效期尚
   在、身份/scope 均匹配而当前 revision 为 R1；拒绝原因必须是 stale revision，
   进入 `invalidated`。此 use 必须 **zero target child、zero credential 文件、
   zero target TLS 请求**，不返回 prepared values，不改成 local-factor fallback，
   不自动 refresh。排除 expiry、replay、零 revision/无效 revision 等替代负例。
6. **显式 refresh，重新完整确认。** owner 主动发起 refresh；broker 独立重读当前
   同一 item 的 R1、可信代码与全部 scope，显示新的 native review。取消一次应不
   产生可用新 handle；继续时需要新的显式 refresh 和确认。确认成功才产生 R1 的
   新 handle。旧 R0 token 在 refresh 前、pending 中、成功后都保持拒绝。
7. **真实执行与网站认证。** 经新 handle，从新的公开 CLI invocation 的 use 走实际
   protected `/usr/bin/curl` execution，child 通过 netrc 的正常 credential 路径获取
   **R1/new value**，向步骤 1 的
   同一 HTTPS 网站认证成功。另以隔离且已授权的测试验证网站拒绝旧值。两次验证须
   观测网站实际认证结果，不能由 child 打印“R1”或本地比较摘要替代。公开结果只给
   new accepted / old rejected、child 与 target TLS 的关联计数及脱敏状态。
8. **审计、lock 与 cleanup。** 核对同一链的 consent/query、browser native save 的
   R0→R1、grant、stale refusal、refresh-pending/refreshed、use intent/执行结果、
   revoke/lock 的状态证据。清理该次 private run root、credential 文件、生成/保存
   draft、临时路由/CA 与测试网站账号，确认旧 handle 无法再用。privacy 扫描覆盖
   stdout/stderr、审计/测试 artifact、网站访问日志、网络请求与截图；仅输出扫描
   结果。不得输出实际 PID/UID、nonce、TTY identity、端口、key、测试 secret 或 raw log。

步骤 2–7 必须是一个连续的、可关联且真实执行的 target 链。fresh one-shot R1 成功、
单独的 browser save、独立 HIBP fixture、组件计数或重新 binding 的成功，可以作为
局部证据，均不能代替该闭环。任何前置条件未满足，保留明确 `UNVERIFIED`/失败和具体
阻断项，不新增 retry、提高 cap、skip 或硬编码 capability 来制造 PASS。

## 必须覆盖的负例与状态证据

每个负例使用合法、仍有时间的初始 grant 和独立 nonce，除非该例本身测试 nonce/TTL。
以受控 kernel/native/child/HTTPS 观察面和脱敏审计共同判断，不依赖返回文案一项。

| 场景 | 必须看到的授权状态和结果 |
| --- | --- |
| 同 nonce 并发/顺序 replay、大小写变体、先取消或未送达再重放 | nonce 至多消耗一次；无第二次披露/child；取消不释放 nonce |
| R0→R1、target 删除/回收站、任一多 target revision 改变 | `invalidated`；披露前全体拒绝，无部分值、credential 文件、child 或 target TLS |
| cross TTY、无 controlling TTY、session 更换、同设备名重建 | 原 grant 拒绝；caller 自报相同 TTY 不被接受 |
| profile/spec/program、argv/cwd/helper/passthrough/destination 改变 | `invalidated`；不能转授权到另一执行范围 |
| anchor 退出/新世代/PID 重用、CLI 同路径新 image/exec、凭据变化 | 旧主体或未认证 caller 的 use 拒绝；合法新 CLI 世代必须逐次独立认证，不能凭 PID 数字、path/hash 或 copied token 获得 authority |
| socket descriptor 继承、传递或 accessor 更换 | 所选机制不能证明原授权接收者时拒绝；terminalpeer 观察成功不放行 |
| 审批期间 CLI image 或 target executable 被替换、校验到 exec 之间变化 | 披露前拒绝；必须证明 protected execution 机制实际约束到所启动 image |
| expiry 前/边界/之后、review 中超时、持续终端活动、时钟失败 | `expired` 或固定拒绝；绝对 deadline 不变，活动不续期 |
| lock/idle lock/revoke、vault/session/epoch 切换、broker 重启 | `locked` / `revoked`；取消 pending；unlock/重启后旧 handle 不恢复 |
| grant/refresh 的取消、UI 关闭、断连、超时、拒绝、审计写入失败 | 无新 grant；旧 token 保持无效；没有 fallback 或 late success |
| refresh review 期间 R1→R2，或旧 refresh 决定晚到 | 拒绝旧 review；不能授权 R2，也不能覆盖新的 pending request |
| refresh 成功后重放旧 R0 handle 或旧 review | 旧 token 永远拒绝；只有新 handle 的新 use nonce 可进入 R1 执行 |

## 待定决策：未解决时阻断对应实现

| 决策 | 必须给出的具体答案与验收边界 |
| --- | --- |
| D1：kernel peer/process authority | 选择消息实际发送者与 process generation 的可信关联；明确 exec/exit/PID reuse、descriptor 传递和竞争窗口的处理；不能用 terminalpeer snapshot 直接补位 |
| D2：code trust root | 允许的 Darwin CLI image/code requirement、可信签发/版本 pin 的来源、部署与更新/撤销路径；怎样与实际 peer image 绑定；缺外部事实则保持阻断 |
| D3：terminal session 与 invocation 机制 | 主体已选稳定 kernel TTY/session-owner anchor；具体 kernel anchor、生命周期、当前新 CLI 与其真实关联 proof 及每次 invocation 的 audit-token/code 认证机制仍须定案；同活 controller 不替代最终目标 |
| D4：lease store 与有效期 | 多次 use 已定；absolute TTL 具体值、anchor 死亡与重启失效、clock failure、nonce 原子消耗/保留期、并发 use；不能从既有 cache 常量推定答案 |
| D5：披露/执行线性化 | revision/epoch 重查与 secret 披露的顺序/原子边界；受保护 `/usr/bin/curl` 的系统路径保护前提如何真实验证并绑定 actual image；rotation/lock 并发时的允许点与拒绝证据 |
| D6：协议、审计与验收 surface | grant/use/refresh 的版本和固定结果、secret-free scope 承诺、每次 private root 的可信验证与精确 intent 绑定、native review 展示/撤销传播、脱敏 schema；固定 HTTPS 表单/netrc 认证和 curl 禁用户配置/重定向/额外目的地的参数策略 |

## 最小分阶段检查点

每个完成的小任务先形成可独立 review 的 Conventional Commit，再开始下一项。真实
最小正向先跑通，再扩大矩阵；实现中按实际边界继续拆分，不能把下表各阶段攒成大提交。

1. **本检查点：设计与验收合同。** 只提交本文；核对 source line 引用和 `git diff
   --check`。不新增低影响文档测试，不运行产品、GUI、build、设备或 credential 网络。
2. **首个实现：kernel process/code trust。** 先定 D1/D2/D3 的具体 proof，实现并
   真实验证 Darwin PTY/session-owner 与当前 CLI 的关联、动态代码认证，以及
   changed-process/image、exec、FD inheritance/transfer/accessor 的拒绝。该组件
   检查点不发 lease，不算 lease/T4 完成，不跳过 native gate。protected execution 若需另
   一小任务，应单独提交和验收；该阻断解除之前不能开始 secret-bearing lease use。
3. **安全 grant/use。** 定 D4/D5/D6，用单一 netrc target、真实 terminal、真实 native
   review，验证 secret-free grant、同 TTY 多个新公开 CLI invocation 的多次 use、
   单次 nonce、absolute TTL 和受保护 curl actual child/HTTPS
   use，再补 replay、scope/TTY/lock/revoke/并发边界。状态变更与审计失败均关闭。
4. **invalidation/refresh 的 lease 子旅程。** 在同一 target 上通过真实产品修改产生
   R0→R1，旧 still-unexpired lease 携 fresh/unconsumed nonce 因 revision 拒绝；显式 refresh 重新
   完整 native review 后，actual child 使用 R1。先证明此链，不把 fresh one-shot
   或 re-bind 视为 lease 完成；随后补取消、refresh 中再变更和旧 token replay。这个
   检查点没有步骤 5 的 browser/HIBP 证据时，仍不算 T4_06 完成。
5. **T4_06 browser journey。** 加入同 target 的真实 consented HIBP、HTTPS 改密表单、
   browser generator/fill/submit 和 native save R0→R1，再执行本文完整 1–8；保留
   `UNVERIFIED` 直到真实证据齐全。Darwin AX blocker 未解除则该平台 positive 继续
   阻断，不能用 Linux GUI CI 代替 terminal lease。最小真实闭环通过并提交后，才扩
   Chromium/Firefox 与更广负例/平台矩阵。

不改变签名、真实设备 iOS 验收或任何已有 release gate；不增加 retry/cap/skip。
本阶段不改代码、CI 或运行环境，不启用 execution 研究分支，不触碰既有 WIP。
Private SaaS 的既有合并/私有仓库/Actions 禁用状态不由本设计变更；外部 S3、OneDrive、
OIDC 配置继续留空。后续每个检查点只报告实测范围，未解决决策和平台 blocker 单独保留。
