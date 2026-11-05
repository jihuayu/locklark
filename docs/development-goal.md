# Locklark 持续开发目标

目标：完成 [design.md](design.md) 的全部产品、安全协议和验收范围。`main` 是长期基线；[progress.md](progress.md) 记录实际证据。本目标不把预览、合成演练或编译成功认定为已能替换 1Password。用户已要求先不依赖 Ryugi。

用户已持续授权使用 `gpt-6-luna`、`max` 推理强度的独立审查子代理；已授权的复核、修复、测试、推送和满足门槛后的 squash 合并无需逐步确认。代码复核不替代 GitHub 要求的人工批准或外部密码认证。

## 每个切片的完成条件

1. 从远端实际 main/PR/head 接续，先核对工作树与并发提交；保留已有实现，不覆盖后来工作。
2. 选一个依赖已满足、可独立验收的功能；使用合成数据先写并运行失败测试，保存失败原因。
3. 实现并修复，覆盖成功、拒绝、篡改和适用的并发/崩溃路径；审计与数据变更或执行意图必须满足设计的事务要求，检查秘密不会出现在日志、普通 Agent 输出或中继。
4. 运行相应单测、终端/子进程/互操作验收及仓库检查，做独立复核并关闭发现。自己的复查不能标为独立复核。
5. 提交到 `codex/` 分支并更新 PR。所有要求满足后通过 PR squash 合入 main，再从更新后的 main 开下一批。禁止直接推送或强推 main，禁止绕过保护或把本地结果充作远端检查。
6. 文档交接记录 main SHA、工作 head、PR、实跑命令、失败测试证据、复核范围、未验证项和下一项。外部条件阻塞须保留原验收项；不静默缩小目标。

PR #1 的恢复安全修复及预览已合入 main `8c97e8537e1b5659a696339a02ff83122b6745b5`；必须从该主线接续，不从初始 README 重做第一版。受控单字段披露切片见 [personal-disclosure-validation.md](personal-disclosure-validation.md)。

## 全部开发范围与验收门槛

以下均为持续目标，完成证据以 progress 和各切片记录为准；没有证据不能打勾。

| 范围 | 应完成内容 | 必须保留的验收 |
| --- | --- | --- |
| M0 基准与兼容矩阵 | 固定 1Password 8.x、op v2、OS 和浏览器版本；行为、输出、差异与平台不适用清单 | 同一合成数据逐任务对照；无损未证明不锁定底座 |
| 密钥与本地核心 | Go 2SKD、设备独立收钥、用途分离、参数与版本防降级、加密审计 | 公开向量及独立密码评审；设计规定的三次服务器失陷/灾难恢复演练 |
| 原生条目与迁移 | 完整类别、区段、自定义字段、重复标题、关联、多网址、附件、TOTP、生成器、历史、归档、最近删除及恢复 | 1PUX/KDBX 导入预检、编辑重开、可逆迁出与独立实现互操作；不支持的语义明确拒绝 |
| 个人 CLI | 人工字段引用、读取/披露、注入、运行、导出和日常离线操作 | 按稳定 ID 与版本定位，披露意图先入账；真实终端隐藏因素、错误因素和中断负测；op 行为契约 |
| MyGo 桌面 | 原生解锁、托盘、快捷搜索、复制及清理、锁屏/睡眠/空闲锁、活动与审批 | Windows Hello、macOS Touch ID、Linux 本机机制分别实测；秘密不经远程 JS |
| Next.js Web | 团队非秘密管理、状态界面、窄授权 IPC；适用时随签名桌面包静态分发 | 服务端下发脚本不能解锁金库或签署成员/吊销决定；窗口权限串用负测 |
| 浏览器与开发者签名 | Chrome/Edge/Firefox、Safari 单列；填充、更新、TOTP、Passkey、SSH Agent、Git SSH 签名 | 相似域名与跨来源 iframe、锁库旧连接；受控站点注册/登录；Unix socket 与 Windows OpenSSH 管道分别测 |
| 本地体检与联网能力 | 弱/重复密码、泄露数据来源及隐私；联网/同步/分享/Travel Mode 分列 | 离线能力离线验收，联网能力明确数据时点，不能混写已兼容 |
| 备份与灾后恢复 | 独立离线材料、可信历史来源、新设备身份与新代次、恢复演练 | 原因素验证后发新钥、原子拒绝覆盖、整链替换拒绝、旧格式明确处理；干净机器恢复与物理条件单列 |
| 团队、设备与同步 | 独立个人/团队库；签名成员目录、可信排序/新鲜度、邀请、成员及设备撤销、同步草稿与冲突 | 两人两个人库一团队库一机器；被撤销设备拿新密文仍打不开；并发目录更改、中继分叉、离线改密和影子设备负测 |
| 远程操作与审批 | Agent 明确动作、目标、原因和 session；安全配对、持久待办、移动决定、短期一次性批准 | 漏通知仍可决定、签名/目标/版本校验、撤销/并发/重放/崩溃未知与回执恢复；默认无原值 |
| iOS 与 Android | 完整离线库、平台系统填充、Passkey、系统钥匙保护和审批专用模式 | Swift/Kotlin 平台集成与 Go 协议向量；两部真机、系统结束/断网/通知关闭及交换或逐站回退 |
| Bun 插件与 MCP Gateway | 签名安装/升级/撤销、锁定依赖、能力清单、工具集、客户端配置接入及回退 | 独立 Bun 进程与有界 IPC；恶意插件的网络、文件、环境、shell、FFI 逃逸；不支持隔离的平台禁第三方插件 |
| 真实受限适配器 | 从录制 PR 演练接入真实仓库范围的上游委托与固定动作 | TLS、重定向、响应身份、越权目标、回显槽值与调用审计；不能将离线录制称为真实上游通过 |
| invoke 机器授权 | 独立签发、固定上游和动作、状态/撤销、轮换与独立执行部署 | 只交付结果；断网、过期、撤销、重放、串用 deliver 凭据以及执行环境失陷的边界 |
| deliver 机器授权 | 独立披露批准、固定字段/受众/接收身份、明确交付状态、独立发布部署 | 生产双人审批或本人再认证；断线不能写为确认交付；串用 invoke 凭据拒绝，原值不进入普通 Agent 路径 |
| AI 裁决 | 仅接受脱敏结构化摘要；只能收紧、否决或转人工 | 模型无取钥、审批或改策略工具；无授予和敏感动作不得因模型意见放行 |
| 全功能审计 | 人工/桌面/浏览器/签名/恢复/设备/策略/导出及请求全生命周期，独立加密和外部检查点 | 意图落盘前不执行；磁盘满、掉电、重复、回执丢失、时钟回拨、回滚/篡改与秘密扫描；证据不足显示未知 |
| M3 替换与发布 | 逐平台签名发布/更新、防降级、双轨试用、退出和真实迁移指引 | 全任务对照及差异关闭，独立评审、干净机恢复、Windows 与移动真机/硬件验收后由本人决定切换 |

## 下一项候选

Windows ConPTY 验收失败已在 `dd68eef` 的双平台 CI 关闭；三个 Luna/max 独立代码复核已完成，见 [pr1-independent-review.md](pr1-independent-review.md)，PR #1 已合并。Actions 已恢复实际运行，不应继续复述旧付款阻塞。PR 标题与正文统一英文；面向用户进度使用中文。

外部合并条件阻塞期间，已开发纯 Go 字段引用元数据核心、两种既有布局投影/绑定、TOTP、密码生成、1PUX v3 只读清点及显式文件关联核对。验收与限制见 [reference-validation.md](reference-validation.md)、[personal-reference-metadata-validation.md](personal-reference-metadata-validation.md)、[fixture-reference-metadata-validation.md](fixture-reference-metadata-validation.md)、[reference-binding-validation.md](reference-binding-validation.md)、[totp-validation.md](totp-validation.md)、[password-generation-validation.md](password-generation-validation.md)、[onepux-preflight-validation.md](onepux-preflight-validation.md) 和 [onepux-file-references-validation.md](onepux-file-references-validation.md)。区段作用域、重复标识与 JSON 值形状清点已实现，见 [onepux-sections-validation.md](onepux-sections-validation.md)，字段语义仍未验证。loginFields 的 designation/字段形状清点见后续 [onepux-login-fields-validation.md](onepux-login-fields-validation.md)，保留未知与重复语义，不授予迁移许可。其他附件布局、完整条目映射和通用写入仍待开发。这些基础工作本身不授予迁移或取值权限；产品入口与事务接入以各后续切片的实际证据为准，不关闭其他验收项。

受控单字段披露、生成保存、TOTP 分别已在 PR #2、#3、#4 经 Luna/max 复核及双平台 CI 后合并。个人字段引用切片已在 PR #5 合入 main `85a3d6f`，保持同事务身份/快照/账本验证、精确修订与先记意图；验收见 [personal-references-validation.md](personal-references-validation.md)。该切片不授予 MCP 或 invoke 原值读取能力。loginFields 清点已在 PR #6 合入 `83ba767`。passwordHistory 清点已在 PR #7 合入 `cff9aaf`，保留顺序和重复，见 [onepux-password-history-validation.md](onepux-password-history-validation.md)。当前从该主线接通经过认证、提交审计后输出报告的个人 CLI 预检入口，见 [personal-onepux-inspection-validation.md](personal-onepux-inspection-validation.md)；随后完成类别/字段/历史/附件映射、可逆迁出及独立互操作。预检不能授予迁移许可。

若 Actions 的账户付款/额度阻塞未解除，保留 PR 并记录精确检查链接；可完善未阻塞的验收材料，但不越过合并门槛启动依赖最新 main 的下一功能。Windows 运行、移动真机、硬件断电、真实 1Password 对照和外部密码评审始终单列，云端测试不能代验。

四线最新交接见 progress：PR #9–#12 分别实现个人加密迁出、归档、HTTPS 来源候选/共享向量、签名团队目录与冻结核心，均保留完整产品未完成项。后续从实际 main 接续：通用迁移的类别/字段/历史/附件映射与对账，日常回收站/恢复，真实浏览器与移动系统适配，团队设备持有证明与权限执行/远端新鲜度。已实现的候选接口和本地目录核心不能替代这些验收。
