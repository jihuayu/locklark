# 登录备注验收

基线为 PR #30 合入后的 main `87fcd7c4f26ba19277ca0fdc3c6341098e82a3da`，工作分支 `codex/native-login-notes`。架构与功能由主代理定义，Sol xhigh 实现，Luna max 独立审阅；具体权限、格式和流程见[设计](login-notes-design.md)。本记录中的未完成项不计为通过。

## 失败先行与升级基线

`login-notes-behavior-red.log` 中两个实际运行的测试分别因多行备注迁入被拒、原生 notes/edit 准备被拒而失败，非编译失败。首次基础实现后两组通过（onepux 0.006s、personal 1.236s），不代表完整产品验收。

主代理从实际 main 构建旧 CLI `/tmp/locklark-tools/login-notes-baseline/locklark`，SHA256 `7dab0b3ce66786f048d48f4e9cfa23ead3ba192d1a004c80badf718b41b3789b`。通过真实终端准备一个保留旧计划的空库和一个已完成 v1 导入的库，正文及因素仅保存在受限私有材料中，日志 `login-notes-parent-upgrade-prepare.log` 只有固定结果。早期固定 core-v1 CLI（SHA256 `9e4241fd1e2c22f6c6ac47e83a97bb7adfba7d4152ade8b48c12eb04f7e20456`）已在新建旧版夹具上独立通过这些边界，以及真实 CLI 多行/Unicode/TAB/CRLF/尾空格迁入、PyKeePass Notes 字节与保护位核对、单行编辑后原始来源字节语义不变，日志 `login-notes-parent-upgrade-core-v1-round2.log`。首轮父工具错误地预期重复来源能先生成计划再在导入时拒绝，产品实际在计划时已拒绝；仅修正 oracle 后重建夹具通过，首轮 `login-notes-parent-upgrade-core-v1.log` 保留，不记为产品缺陷。固定完整 v1 后又重新从旧 CLI 创建新夹具并完整重跑，通过 `login-notes-parent-upgrade-v1.log`；主代理另对完整重定向 stdout/stderr 扫描因素、正文/随机标记及 JSON/URL/Base64 变体，零命中。

Luna 架构预审提示统一取值分支原先对非 password 默认取 Username；实现须明确处理 notes，并保持公共 reveal/inject/run/browser 验证器范围。复用 NativeField 的前提是严格的原生目的与字段校验；编辑填入的 intent 不推进条目修订，保存成功才推进。

独立 Sol 边界测试 `notes_boundary_test.go` 覆盖真实已认证备注/来源存在的正对照、仅备注或来源含查询词时标题搜索无结果、元数据与体检/审计无正文、共享 reveal/inject/run/reference 拒绝、浏览器 fill/OTP 输出域及其他编辑保留 Notes/ImportSource。race 9个结果通过且零竞态，重复三次27个结果通过，私有日志 canary 零命中；日志 `login-notes-boundary-{race,repeat}.log`。初次编译受并发首稿未落地影响，不计为行为 red；这些包内结果不冒充实际浏览器/Next/MCP 链路。

## 固定产品候选 v1

`/tmp/locklark-tools/login-notes-v1/` 包含 CLI、desktop 和两浏览器宿主。主代理独立核对全部148项产品源码清单，manifest SHA256 `35bdfb4ce36d990c3bb42910764e5b753b1b5e42c4fbb0c6327d1e989d3d30c5`。desktop SHA256 `fc4ff4b4b2fc06bad1687e860771d21f73470eb0621452300b9eebb8cd17d687`；CLI 与上述 core-v1 相同。Chromium `f315e7e6c3a9e992bef7690dc978a626cb69014379fa0deec2c52c05c103c924`，Firefox `0741f556e9a6a2bb5cd3ff613cdcd395150cb168789df389f09598046da28dc1`。

Luna 已独立审阅此冻结产品，运行 vault/onepux `Test.*Notes`、personal `Test(NativeNotes|LoginNotes|NotesBoundary)` 和 desktop `TestNotes`，均通过且无剩余产品阻塞。审阅不替代主代理 GUI 或硬件验收。主代理另要求并修复系统剪贴板清理重入时的页面/会话/目标与操作代次检查；保存和读取均不得跨过已失效的 UI 上下文。

## 主代理旧桌面完整回归

固定 v1 在主代理94显示、真实窗口管理器及私有 D-Bus 会话下运行 `scripts/desktop_native_acceptance.py`，exit0，日志 `login-notes-v1-parent-daily.log`、私有 state `7zcg_j9c`。原子新建/生成、精确替换、系统剪贴板 provider/后续所有者、独立 HMAC 的 TOTP 显示/复制/到期及锁定全部通过。五项共享工具在整轮前后 hash 一致，内层 artifact/controller scan 通过；主代理另扫描完整重定向 stdout/stderr 的因素变体及覆盖整轮的 OTP 时间窗口，通过。外层扫描不声称重建全部已替换的随机密码，后者由内层动态 canary 集覆盖。

## 备注 GUI 工具定位

Sol95 的 v1/draft1、draft2 完整流程在复制核对未通过，日志 `login-notes-v1-native-draft{1,2}.log` 保留。draft2 固定阶段 `explicit-notes-copy-raw`：GTK读取结果非空，原始 CRLF 比较为 false、仅将 CRLF 转 LF 的对照为 true。父代理与 Sol 分别核对 GTK3 源码：`gtk_clipboard_request_text` 优先请求 text/plain;charset=utf-8，该路径在收发时按文本格式规范化换行；UTF8_STRING 路径则直接传原字节。此时尚不能据此判产品丢字节，也不把失败记为成功；须通过独立 raw X11 请求验证原 UTF-8，另记录接收方文本格式的换行行为。Sol随后用独立 GTK owner 作正对照：raw UTF8_STRING 原始 CRLF=true、规范化 LF=false；GTK convenience reader 反之，日志 `login-notes-clipboard-reader-control.log`。产品 v1/draft3 又实际通过 raw 原始字节、未修改编辑器→保存→独立 KDBX、改写与快捷面板返回和旧修订冲突；该轮的清空工具误用了空剪贴板粘贴（不会删除所选文本），故改为真正 Ctrl+A/BackSpace，未改产品。

draft4 通过实际清空/省略 Notes 字段、恢复备注和锁定处理，但在进程重开后的旧无障碍读取器失败，日志 `login-notes-v1-native-draft4.log`、state `w90p1imu`。定向实验 `login-notes-v1-reopen-probe-diagnostic.log` 确认同一 observer 对第二 PID 再初始化 AT-SPI 被工具按非零状态拒绝；固定函数/行号诊断不含值。新应用完全退出/重开后，仅更换专属显示 observer，保留独立剪贴板 owner；相同两次完整解锁的正对照均通过，日志 `login-notes-v1-reopen-probe-fresh.log`。不把这些失败写成整轮成功，也不改产品来配合工具。

工具 draft5 冻结15项，manifest `/tmp/locklark-validation/login-notes-tools-draft5.sha256`，SHA256 `fe81a2f1fbdd0a2486cbe992ffe6a821968efafdd11d10ac61454b15e94f478a`，父代理已独立逐项匹配。增加对实际产品原始 UTF8_STRING 与 GTK 接收端转换的双检查、明确 BaseRevision 审计比对、唯一导出路径、foreign clipboard 锁定保留与 owned clipboard 清除。69项工具测试通过，旧桌面/快捷搜索/两浏览器门槛保留，CI新增 notes 正常/故障隐私及固定版本 PyKeePass，并扩展 macOS Notes 测试筛选。最终 Notes GUI 与故障隐私的精确冻结版证据随后记录。

## 产品完整检查

Sol 完成一次 `GOTOOLCHAIN=go1.27.3 LOCKLARK_TEST_BUN=/tmp/locklark-tools/bun-linux-x64/bun LOCKLARK_TEST_PYKEEPASS=/tmp/locklark-tools/python/bin/python go test -count=1 ./... -timeout=15m`，exit0，日志 `login-notes-go-all.log`；personal 326.680s、preview 148.367s、desktop 56.582s、CLI 14.709s。Notes core/边界/UI 的定向 race exit0（personal 248.964s、desktop 125.854s），日志 `login-notes-native-race.log`。vet 与 Windows amd64 / Darwin arm64 desktop 测试包交叉编译通过；后者不冒充平台原生运行。另补真实两会话同时保存同一修订，恰一成功一冲突，认证读回精确赢家且其他字段/来源不变；含 Notes 的备份恢复及历史验证通过，日志 `login-notes-concurrency-recovery.log`。148项产品 manifest 仍匹配冻结 v1。

## 主代理最终 Notes GUI 与工具冻结

主代理在94显示独立执行固定产品 v1、normal 工具 draft5 全流程，明确 exit0；日志 `login-notes-v1-parent-draft5.log`，私有 state `lm1y1ozc`。正常 CLI 迁入后选中不披露；show/copy/edit 分别有精确 ID/修订的意图；原始 UTF8_STRING 与 GTK 接收端格式对照通过；Enter 不保存、取消不修改；不改编辑器再保存保持 CRLF/Unicode/空格；多行改写经快捷面板 Escape 保留；独立 CLI 先提交后旧编辑器保存冲突；清空省略 KDBX Notes 字段；锁定丢草稿、保留 foreign owner、清除本程序 owned copy；真实退出重开需重新解锁并明确读取。三类 KDBX 导出由 PyKeePass 核对字节/保护位/来源记录和条目身份。内层所有产物/controller scan 通过，父代理另对包含 D-Bus 输出的完整重定向 stdout/stderr 扫描因素/正文/片段及 JSON、URL、Base64 变体，通过。

故障 wrapper draft5 曾误预期 `probe-operation`，而原生 probe 的 reason 已是该值、基类再加 `probe-` 前缀，实际为 `probe-probe-operation`；真实内层按预定故障 exit1，外层错误分类被拒，原日志 `login-notes-v1-draft5-privacy.log` 保留。draft6 只修 wrapper 固定预期并加退出码/阶段正负对照；与 draft5 精确只有 wrapper 和对应 unit 文件两个 hash 变化，normal 的13项相关工具/CI完全未变，故不把无关 wrapper 变更当作重跑正常链路的理由。父代理独立核对15项最终 manifest，SHA256 `4f7cc0180180e915f17bbabd118ec37e43f540933f9f6397e1934126022032a5`；Luna也独立逐项核对、运行70项工具测试/py_compile/diff检查，最终产品和工具复核均无阻塞，Luna没有冒充执行 GUI。

## 最终故障隐私

Sol95 与主代理94 分别在固定 v1/draft6 运行 `scripts/login_notes_privacy_acceptance.py`，均 exit0。主代理日志 `login-notes-v1-parent-draft6-fault.log`，wrapper私有目录 `tzr4j2fr`；Sol日志 `login-notes-v1-draft6-privacy.log`、wrapper `l4ben4nw`。内层真实明确显示 Notes 后故意提交携带全部私有 canary 的未知 probe 操作，必须固定阶段/原因 exit1；完整 controller stdout/stderr、native/probe 日志及 diagnostics JSON 扫描通过，无截图。主代理额外检查 wrapper 和最外层 D-Bus 重定向输出含 Base64 变体，零命中。最终两个 manifest 再核无变化。

## PR 与首轮远端检查

[PR #31](https://github.com/jihuayu/locklark/pull/31) 初始 head `3b50eca15213300768bd02d17332d972185ca620`，[CI 42144714585](https://github.com/jihuayu/locklark/actions/runs/42144714585) 的 macOS 与 Web 成功。父代理下载完整 Web 日志，逐一核对旧桌面日常、快捷搜索、Notes 正常/故障隐私、Chromium/Firefox 完整填充保存 OTP 及两项 OTP 故障门槛均实际 PASS，不能据此把整轮标绿。

Ubuntu 全 Go 中旧 `TestDailyOTPRequiresDurableRevalidationAndSingleDelivery` 在 daily_test.go:82 预期 ErrConflict 却收到 ErrDesktopDelivery，日志 `login-notes-pr31-ubuntu-failed.log`；Windows 被矩阵 fail-fast 取消，非独立 Windows 产品失败（此前原生剪贴板 smoke 已通过）。该测试在真实 TOTP 窗口末端准备 holder，再进行另一会话的解锁和修改；到期 timer 可以先清值并删登记，合法的到期拒绝先于旧修订检查。Sol 的修正仅涉及 `daily_test.go`：版本/重放语义测试使用已有受控 OTP 时钟并独占本次 holder timer，必须实际走到精确 ErrConflict；同类跨会话测试同步强化，独立真实到期/回拨测试保留，新增到期先于只读检查的零调用/零交付/清零对照。产品 v1 源码和二进制不变；主代理重新核对148项产品源文件和15项最终工具manifest均一致。

Sol使用 `GOTOOLCHAIN=go1.27.3 /tmp/locklark-tools/go/bin/go test ./internal/personal -run '^TestDailyOTP(RequiresDurableRevalidationAndSingleDelivery|SecondSessionChangesAreRejected|ExpiryPrecedesStaleRevalidation)$'`，定向重复 `-count=3 -timeout=180s`（53.026s）和定向 `-race -count=1 -timeout=240s`（79.895s）通过，日志 `login-notes-otp-ci-timing-repeat.log` / `login-notes-otp-ci-timing-race.log`。Luna max 对精确测试增量审阅无阻塞，独立运行 `go test ./internal/personal -run 'TestDailyOTPRequiresDurableRevalidationAndSingleDelivery|TestDailyOTPExpiryPrecedesStaleRevalidation|TestDailyOTPSecondSessionChangesAreRejected|TestDailyOTPFinalClockSampleRejectsRollbackAndExpiredWindow' -count=5` 通过（58.372s），以及 `go test -race ./internal/personal -run '^TestDailyOTPRequiresDurableRevalidationAndSingleDelivery$' -count=1` 通过（16.047s）。Luna另一次更宽的重复race被主动停止，不计通过。主代理独立阅读断言、错误优先级和timer所有权后接受这份仅测试的修正；新head完整CI仍须核验。

## 当前门槛

本地实现、独立复核、主代理完整验收与故障隐私已通过；PR #31 首轮真实 CI 失败已定位并完成测试修正；更新提交的精确 head CI 与正常 PR 合并仍待核验。本切片不关闭完整类别/自定义字段/历史/附件迁移、平台真机或整体替换验收。

## 最终远端与合并

最终 head `9b11713ee3a215117be78ed1f54b167fec10c80f` 的 [CI 42146467829](https://github.com/jihuayu/locklark/actions/runs/42146467829) Ubuntu、Windows、macOS、Web 四项全部成功。主代理下载完整日志核对 Windows/Ubuntu 真实终端与独立 Notes KDBX 对账、macOS 原生剪贴板，以及 Web 中旧桌面日常、快捷搜索、备注正常/故障隐私、Chromium/Firefox 完整流程与两项 OTP 故障门槛各实际成功一次。PR #31 于北京时间2026-11-06 10:01:20经正常 squash 合入 `9d8d57475f3fb904fc9fe4bedc0c1e6b4ce07535`，无保护绕过；main 已快进同步。本段关闭前述最终 CI/合并待办，不关闭其余产品范围。
