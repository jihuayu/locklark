# M6 集成修复与后续复刻验收

日期：2026-11-07（香港时间）。接续 main `eccd32650eac6e2bf9fa7f44f4a555a8cf2d57e7` 与 [PR #43](https://github.com/jihuayu/locklark/pull/43) 原 head `8141d5ed276928b72e2f8b97b79f2779381a7fb4`。本记录区分实现、实际运行与仍待对照的范围，不把 E2E 的 pending feature 当成通过。

## 架构与实现

- 桌面与浏览器共同使用持久化 `vault.Item` v2。移除进程全局 metadata overlay；浏览器创建和编辑均通过完整校验、原修订校验及一次 `AddItem`/`EditItem` 事务提交。收藏也写入金库并推进修订。卡片、身份、自定义字段不会只停留在宿主内存；同一模型供桌面及浏览器读取。
- 扩展在明确的 DTO 适配层转换弹窗字段与 Go wire schema：类别别名、网址结构、分区、卡片与身份字段均显式映射。按次显示/复制使用真实 `action` 请求键和 `value` 响应键，共用 JSON fixture 同时经 Go 生产解码器/编码器与 Node 检查。原生详情不自动带回密码、备注或 OTP 种子；弹窗原值只保留在短期显示状态。
- OTP 探测传递明确的 null 占位符，兼容 scripting 参数的 JSON 序列化。保留批准、来源、文档、修订、nonce、原时间窗口与不自动提交的限制。
- 自动登录在注入前登记本次凭据、文档和 epoch，失败回退；避免同步提交早于登记导致误弹“保存登录”。Passkey 面板期间隐藏待保存 banner，防止同名按钮竞争。
- MyGo 三栏界面增加分区/自定义字段、标签、多网址及卡片/身份编辑。标准模板直接绑定 typed draft，保存时同步模板副本；自定义分区不受覆盖。保险库切换重新加载，异步列表绑定查询代次，拒绝过期结果；隐藏字段先遮蔽再判断是否为空。
- 桌面锁库立即撤销会话、取消 CLI 待批准项并广播插件锁定。IPC 只读取受锁保护的会话快照；批准发布时再次校验会话与代次，防止旧请求在锁库后发布。
- CLI 现有 16 个 profile。帮助/版本路径也使用可信临时父目录、独立 HOME/config/temp 和明确 PATH，不继承父环境密钥。新增 `deepseek` profile，经明确绑定的 Python 程序向前台 harness 注入 `DEEPSEEK_API_KEY`；拒绝 `configure`、`spawn`、`--background`。解释器 pin 不等于固定 harness 脚本内容，脚本也必须可信。用法见 [CLI 包装器](cli-wrappers.md)。

## DeepSeek worker 分工

按用户要求安装 `jihuayu/skills` 的独立 `deepseek-subagent`，来源提交 `9a63f2539c6fde1e85978c8e0ea166de73af0cab`，安装器与运行状态不加入 Locklark 仓库。harness 的 14 项测试通过；请求模型为 `auto/deepseek-v4.1-flash`，服务返回 `group/auto-deepseek-v4-1-flash`。

主代理制定数据、事务、协议和会话边界；外部 worker 并行完成浏览器/CLI/桌面调研、实现与定向测试。达到轮次上限的任务在检查实际文件后续接；一次大范围复核遇到连接重置，不能计为成功。重新以冻结的 broker/CLI diff 进行独立复核，未发现已证明的阻塞；其指出的旧会话批准发布窗口另补会话/代次校验及锁库负测。worker 报告不替代下列主代理独立运行。

## 本地实际证据

日志位于本次执行工作区 `/workspace`，未提交含运行状态的私有材料。

| 验证 | 结果及边界 |
| --- | --- |
| Go 全仓 `go test ./... -count=1 -timeout=10m` | browserhost、desktop、CLI 及其余包通过；personal 唯一失败为先前 overlay 测试仍预期可存 HTTP metadata。改为持久化校验后的测试，再完整运行 personal：通过（240.181 秒）。不是跳过失败用例。 |
| 最终编译、`go vet ./...`、`go mod verify` | 通过；Go 1.27.3。 |
| 持久化与协议回归 | 浏览器创建→桌面读取→重开、卡片与隐蔽字段保留、收藏修订、旧修订拒绝、非法 OTP/备注不部分提交，以及共享 wire fixture 通过。 |
| 桌面定向竞态 | broker 解锁/锁定/CLI 请求与查询变更测试通过；新增锁库取消待批准及旧会话不能重新发布批准测试。 |
| DeepSeek key 真实子进程 | 合成 key 从真实加密库经 `RunBundle` 注入子进程；父环境 key 不覆盖库值、其他 token 不继承、签名审计无原值、临时目录清理，均通过。没有迁移用户现有真实密钥或冒充对真实上游的调用。 |
| CLI 外部验收 | F16：10 项通过、6 项功能 pending、0 失败；顶层/各子命令帮助及 shell 诊断通过。16 profile、DeepSeek 明确程序/前台限制、绑定和 pin、shell function、免因素帮助路径、拒绝、输出与绑定秘密扫描通过；5 项验收控制器测试通过。 |
| 扩展 Node | 151/151 通过；含 null 参数、真实 Go DTO、显式取值、原值不进入快照、填充过程中提交的保存竞态、真实 textarea 只读属性、保存后的 busy 交接和未读取备注保留。 |
| Web | 8 项单测、typecheck、production build 与 Chromium/Firefox 的真实目录→Go broker→Next.js 只读流程均通过。 |
| 真实弹窗编辑 | Chromium 实际点击新建、输入、保存至 Go 原生库、遮蔽/按次显示、仅改标题后密码与备注保留通过；已纳入 Web CI。外部脚本 `LOCKLARK_TEST_POPUP_VAULT=1` 启用，产物扫描不记录原值。 |
| 原生 Chromium / Firefox | 两引擎完整填充、保存、更新与 OTP 流程通过；Chromium 另通过 Passkey 创建、断言、独立签名验证与取消。使用冻结可执行文件，避免验收期间重建正在运行的程序。 |
| MyGo 原生日常 GUI | 创建/生成、精确再生成、系统剪贴板所有权及外部 owner、独立 HMAC 的 TOTP/原窗口到期、锁库和完整私有产物/控制器扫描通过。 |

## 合并与平台门槛

中间 head `7469cfe` 的六项 GitHub 检查全部通过；最终补丁另推新 head，须等待该提交的全部检查与合并回执。禁止绕过分支规则、将旧 head 的绿色检查挪用到新提交，或把交叉编译称为平台原生验收。

1:1 仍需固定 1Password/浏览器/OS 版本并逐屏、逐任务对照。本批没有新的 1Password 参考图或真实导出来源，因此仅记录已实现的功能和已跑的流程。Safari、移动真机、系统生物识别、签名发布、附件在扩展中的完整操作、未读取备注/隐蔽自定义字段显式清空等继续保留；扩展无附件 transport 的 document mutation 明确拒绝。独立密码评审、干净机器恢复和原有产品范围不由本批自动关闭。
