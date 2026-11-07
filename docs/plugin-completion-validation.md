# 插件功能收尾与进度对账

日期：2026-11-07。起点 `main` `4abecb8e869a255920f0104ce69977d87150feef`；工作分支 `codex/plugin-completion`，[PR #44](https://github.com/jihuayu/locklark/pull/44)。本记录区分本地独立验收、组件契约、真实浏览器流程及最终远端 CI；合并回执以 [PR #44 的 Checks](https://github.com/jihuayu/locklark/pull/44/checks) 和 timeline 为准，旧 PR 的绿色检查不代替本次 head。

## 本批范围

- 对齐 E2E 能力探测与真实 CLI 输出，区分缺失、实现损坏、仅探针通过和完整任务验收；不靠删除断言或无条件放行消除 pending。
- 更新已过时的 PR/合并状态、浏览器功能清单和 M6 回执。历史分析移入独立快照，保留稳定行为 ID，不沿用旧基线计数。
- 插件附件元数据、分块上传/下载/删除，复用已有金库附件事务与 2 MiB 单文件上限；native messaging 单帧仍上限 256 KiB。
- 编辑时明确区分“未读取/保留”“替换”“清空”“删除字段”。备注与隐藏自定义字段不会因空编辑器误删，也能由用户明确清空。

## 架构与边界

附件请求仅由扩展自身页面发出，使用当前配对能力。上传暂存最多一个、上限 2 MiB、120 秒失效，绑定连接、会话、条目 ID 与原修订；顺序与 SHA-256 全部匹配后，通过一次既有 `AddAttachment` 事务提交。取消、失效和锁库清理暂存。下载逐块重新核对修订、先审计再返回字节，插件重组并校验完整 SHA-256 后才保存；不会在网页、普通状态快照、缓存或日志中暴露附件正文。删除使用精确修订和既有 mutation gate。

编辑请求的 `clear_fields` 显式指定目标；未提供的隐藏值保留。提供分区结构时，以稳定 section/field ID 区分保留值、替换值及移除字段；未知、冲突或旧修订请求应整体拒绝，不部分落库。

由主代理制定上述数据、事务和传输边界；DeepSeek 外部 workers 并行实现 E2E 修正、Go 宿主协议及扩展界面。worker 自报结果不替代独立运行。

## 验收结果

| 验证 | 已实际取得的结果 |
| --- | --- |
| 冻结旧 main 的全量 E2E | 206 项：123 通过、73 pending、10 失败，报告 `/workspace/plugin-completion-baseline-e2e.json`。失败包含旧检测假设/缺少导入等；本轮最终结果另列，不能挪用旧数字。 |
| 更新后全量 E2E | 主代理重新构建后实跑：206 项，170 通过、36 pending、0 失败，76.349 秒；检测回归由 31 项扩展为 43 项，主代理独立运行全部通过（31.536 秒）。报告 `/workspace/plugin-e2e-final.json`，保留全部 206 个稳定 ID。 |
| 扩展单测 | 主代理冻结实现独立运行 `node --test browser-extension/test/*.test.js`：172 项通过、0 失败、0 跳过。 |
| Go 宿主整包 / personal 整包 | worker 实跑通过：browserhost 40.215 秒，personal 219.826 秒；包含原有测试。 |
| 主代理独立竞态检查 | `go test -race ./internal/browserhost ./internal/personal -run 'TestAttachment|TestExplicitClear|TestV2SectionsFromInputKeepsSecretClassification' -count=1` 通过，分别 33.518 秒 / 1.032 秒。 |
| 主代理全仓编译 / vet | `go test ./... -run '^$'` 与 `go vet ./...` 通过；编译探针不计作完整测试。 |
| 真实 Chromium 插件收尾 | `/workspace/plugin-popup-native-5.log`：新建并编辑真实库；隐藏字段不预读；显式清空备注/一个隐藏字段后另一隐藏字段保持；删除字段、2 MiB 附件上传/下载 SHA-256/删除并重开确认，全部通过。同期自动登录、Passkey 注册/断言/签名核验/取消通过。 |
| 独立 Edge | 官方 Edge Linux x64 `157.0.4341.42` 安装包经官方 SHA-256 校验；`/workspace/plugin-edge-native-1.log`：快捷配对、自动登录、Passkey 创建/断言、独立依赖方签名验证及取消通过。随后 `/workspace/plugin-edge-native-full-2.log` 完整通过：弹窗字段清空/附件、填充、保存、更新、OTP 的独立 HMAC 与负测、快捷配对/自动登录、Passkey 创建/断言/签名核验/取消。首次完整运行遇到辅助功能总线失联，第二次单独运行通过，不将失败记为成功。 |
| Firefox | `/workspace/plugin-firefox-native-2.log` 完整填充/保存/更新/OTP 通过；独立新增 Passkey-only 运行 `/workspace/plugin-firefox-passkey-6.log` 的创建、断言、取消、浏览器回退通过，原生因子审批及依赖方签名核验均实际执行。7 项控制器/验证器测试通过。随后 `/workspace/plugin-firefox-full-final.log` 的合并流程也完整通过；最终 CI 已启用该流程及额外 `@simplewebauthn/server` 核验。 |
| 独立复核 | DeepSeek 只读复核附件操作、分区值保留及生产入口范围校验。最初提出的负数 size/length 风险在核对 `registerRequest -> Request.valid` 后撤回：入口已在分派前拒绝；未报告该范围内已证明的外部阻塞。另复核异步附件生命周期，发现并复查修复了取消后迟到 chunk 复活上传记录、删除后的迟到提示覆盖新界面两项竞态；172 项测试包含对应回归。该静态复核不代替实际测试或完整密码评审。 |

真实验收发现并修复了仅靠简化 DOM/wire fixture 无法覆盖的问题：备注清空控件读取了已过滤的字段；宿主未返回隐藏自定义字段是否有值；分区字段同时以平铺和分区形式渲染导致重复；下载结束后按钮没有重新启用；旧操作 finalizer 可能修改新代次状态。还修复了旧上传误取消新上传、取消后 chunk 复活记录、孤立上传永久占用槽位、清空隐藏字段时被重新分类为明文的问题；对应控件、事务和生命周期回归保留。

## E2E 数字的含义

| coverage_kind | 总数 | 通过 | pending | 失败 |
| --- | ---: | ---: | ---: | ---: |
| functional | 149 | 130 | 19 | 0 |
| capability_probe | 45 | 28 | 17 | 0 |
| component_contract | 12 | 12 | 0 | 0 |

`functional` 包含 CLI/原生消息等入口测试，不等于每项都是完整浏览器旅程。12 项组件契约实际执行既有 Node/Go 测试；45 项能力探测只说明组成能力，不宣称完整用户任务。测试名称匹配为零、已实现组件失败均判 FAIL，不能转成 pending。36 项 pending 的实际范围：CLI 创建/导入命令面 13、CLI broker 客户端/租约 14、跨功能旅程 6（包括跨源卡片 iframe）、iframe/卡片用户激活 2、CLI HIBP/在线旅程 1。以 JSON 中每项原因优先，不能将这 36 项直接读成 36 个插件未实现功能。

首轮远端 head `a80802b` 为 169 通过、36 pending、1 失败：T2_F7_05 没有收到拒绝响应。修正测试请求发出后立即关闭 stdin 的行为：有效请求明确等待完整回复，畸形/截断帧仍保留 EOF 检测；所有等待有截止时间，桌面及宿主探针清理自建进程组，避免包装进程退出后遗留子进程。新增回归覆盖迟到回复与 EOF 竞争、提前退出的包装进程、忽略 SIGTERM 的子进程、无权进程组保护。原拒绝断言保留，不把失败改为 pending。修正后主代理独立重跑 T2_F7_05 通过；worker 重跑全部 206 项仍为 170 通过、36 pending、0 失败（113.893 秒，复用冻结二进制，报告 `/workspace/plugin-completion-e2e-probes.json`）；最终远端结果以本 PR Checks 为准，不能沿用首轮其他平台的绿色结果。第二轮远端 `200658d` 同项仍然超时，因此 stdin 生命周期问题不能被视为已经证明的 CI 根因。进一步使 Linux GUI 探针自行创建 D-Bus/Xvfb 会话，并在 CI 清除前序步骤继承的 DISPLAY/Wayland/D-Bus 环境；保留显式提供且可用的用户会话。等待回复的截止时间和拒绝断言不放宽，缺少所需工具记 validation-blocked 失败，超时只输出退出码、字节数、帧类型和截断 stderr 等诊断。本地随后复现为 stdout 161 字节、0 个有效帧：服务控制台输出与 native stdout 混用，单纯补 D-Bus 不足以修复。通过固定 argv 和独立 fd 9 保留宿主协议管道，将启动器/辅助服务输出导向 stderr；fd 3 被真实 xvfb-run 占用并关闭，不能用于保留协议管道。未修改严格帧解析器；回归要求带公开服务横幅的启动器产生的 stdout 精确等于一个协议帧，横幅只在 stderr。主代理在自建 D-Bus/Xvfb 环境独立重跑 T2_F7_05 通过（12.166 秒），43 项检测回归全部通过（31.536 秒）。最终确认属于本 PR 最新 head 的 CI。Web CI 同时保存 JSON 报告 artifact（14 天）。

复现：`python3 -m unittest discover -s tests/scripts -p 'test_e2e*.py'`、`python3 scripts/e2e_runner.py --feature all --json-out /tmp/locklark-e2e-report.json`；使用有效 Go、Node、Xvfb 工具链。本轮同样进入 Web CI。

## CLI 外部验收与后台遥测

`0e13665` 的 Web、Windows、macOS、Android、iOS 均通过，Linux 首次在 `gh-pipes` 失败；原提交重跑通过该阶段，但随后在 `stale` 失败。固定诊断码使主代理随后在本地捕获到 `request-temporary-directory-not-clean`：旧修订请求正确退出 1、观察到全部 3 个提示、没有输出和 TLS 请求，残留却来自前一次 `gh` 的 `home/.local/state/gh/device-id`。

官方 `gh 2.103.3` 的[遥测实现](https://github.com/cli/cli/blob/v2.103.3/internal/telemetry/telemetry.go)会启动 detached `send-telemetry` 子进程，并持久化 device ID；后台进程能在直接命令结束、清理后重建旧临时目录。这解释了检测失败可能落在后续不同阶段。正式 RunCLI 已明确只等待/终止直接子进程，不能撤销可信程序的后代，本批保留该约定。

修正仅在受控 `scripts/run_cli_fixture` 的 GH 模式附加官方支持的 `GH_TELEMETRY=false`，与原有禁用更新通知的测试配置一起隔离可选后台活动；先前的正式环境白名单、已选 token、TLS 1.3、真实 stdin/stdout/stderr、旧修订/拒绝/无子进程、严格临时目录清空和隐私断言均保留。生产环境和清理实现没有因此放宽。

固定失败码及受限元数据不包含因子、token、参数、正文或异常文本；14 项控制器/隐私测试通过。修正后 worker 用新建 fixture 和官方 `gh 2.103.3` 完整运行四次（前两次固定 CPU 0）：每次退出 0、11 个阶段通过、临时目录和 device-id 残留均为 0。主代理独立重建 fixture 并再次完整通过，日志 `/workspace/plugin-cli-telemetry-independent.log`。修正前只读复核未证明控制器的正常拒绝路径存在竞态，四轮先前未复现的压力运行也未被当作根因证据。

最终远端确认见 [PR #44](https://github.com/jihuayu/locklark/pull/44)；未取得同一最终 head 的六项成功结果前不合并。

## 已实现与真实剩余范围的区分

- 16 个 CLI profile 与直接金库解锁执行存在；桌面 broker 服务端虽有实现，`cli run` 的客户端接入尚未闭环，不能标 F17 完成。
- 原生界面已有身份/银行卡、多步登录和分格 OTP；缺少旧 E2E 所假定的 CLI 命令，不代表这些原生/插件功能整体不存在。组件契约、能力探针和真实浏览器流程分别报告。
- 本批附件通道覆盖已有 v2 稳定 ID 附件；旧 v1 内嵌文档正文没有稳定附件 ID，尚未通过此通道显示/下载/删除。插件新建 document 仍拒绝，避免生成无文件的文档；该兼容范围不能因新增附件按钮自动关闭。

## 不由本批自动关闭

完整参考版本逐项对照、Safari、Windows/macOS 的浏览器组合、真实硬件生物识别、完整 conditional 账号列表、Passkey 独立删除/多凭据管理、签名与商店发布；以及上文明确保留的 CLI 客户端和旧 v1 文档兼容范围。Edge 与 Firefox 的已实测范围见验收表，不据此宣称全平台完成。
