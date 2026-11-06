# 浏览器验证码填充验收

基线 main `4f37d8ccd9499b6a3e292709e7d567747a8ada7a`，分支 `codex/browser-native-otp`。桌面 [PR #28](https://github.com/jihuayu/locklark/pull/28) 已经 Luna/max、主代理独立完整GUI及精确head `85b400ff328525572fdc98d9855b011613b9b2bd` 的四项 [CI 42120014509](https://github.com/jihuayu/locklark/actions/runs/42120014509) 合入；其中Windows/macOS原生剪贴板smoke均实际执行并通过。

本批已按 [架构约定](browser-otp-design.md) 实现浏览器逐次原生批准的OTP填充；固定构建的最终本地验收已通过，待PR精确head远端检查。主代理设计与独立验收；Sol xhigh分别承担Go核心/宿主与扩展/外部工具；Luna max独立review。需要保留失败先行、修复、固定构建、两浏览器真实GUI、全部值扫描及精确head CI证据。

## 已保留的失败证据

私有日志保存在 `/tmp/locklark-validation`，仅固定分类进入交接，不复制夹具秘密或原始诊断。

- `browser-otp-protocol-red.log`：当前协议拒绝新增完整OTP请求，属于行为失败。
- `browser-otp-core-red.log`：独立目标/control及Prepare→Authorize→Grant接口尚不存在，属于编译失败；不将它称为已执行安全断言。
- `browser-otp-extension-core-red.log`、`browser-otp-extension-protocol-red.log`、`browser-otp-dom-chromium-red.log`：扩展DTO、静态页面OTP处理及Chromium页面行为的缺失证据；不等同真实原生批准链路验收。
- `browser-otp-cancel-output-race-red.log`：已调用页面注入、promise尚未完成时取消，旧草稿错误显示确定停止。修复需要区分发送、ACK及注入阶段；主机明确取消且本地尚未开始注入，才能显示确定取消。ACK后的断线/超时/锁定若没有确定拒绝，保留“结果未确认”。新一次显式操作仍须重新原生批准，旧回调不得覆盖其状态。
- `browser-otp-reconnect-unknown-red.log`：仅重新连接就清掉旧操作的未确认结果；修复保留至显式新OTP操作，不增加额外审批。
- `browser-otp-ack-local-timeout-red.log`：ACK后的页面本地等待先于RPC计时器超时，旧catch提前删除pending状态并误报确定拒绝；修复区分可信主机拒绝与其他ACK后失败。

这些日志保留各阶段失败，不代表最终实现仍存在相应缺陷。最终固定构建的检查见下文；精确head远端CI仍待创建PR后执行。

## 主代理早期独立复跑

当前扩展草稿的 `node --test test/*.test.js` 45项全部通过，日志 `browser-otp-parent-node-draft.log`。随后使用 `LOCKLARK_TEST_PLAYWRIGHT=/workspace/locklark/web/node_modules/playwright` 分别设置 `LOCKLARK_TEST_BROWSER=chromium`、`firefox`，运行 `node scripts/browser_extension_dom.cjs`，两次均exit 0；日志为 `browser-otp-parent-dom-{chromium,firefox}-draft2.log`。它们包含原填充/保存与新增OTP静态函数的页面检查，尚未连接真实原生OTP宿主。

此前同名不带draft2的DOM尝试因当前worktree没有默认Playwright模块，在加载阶段失败；使用已有主worktree的依赖后复跑，未把环境失败算作产品失败或成功。上述草稿后仍有并发修复，不能替代最终固定源码验收。

取消、重连与ACK本地超时修复后，主代理再次独立执行全部49项Node测试及55项Python原生验收工具测试，均exit 0；日志 `browser-otp-parent-node-unknown-fixed.log`、`browser-otp-parent-tools-draft.log`。宿主复核另发现旧请求持Connection锁等待writer槽、OTP持writer槽等待Connection锁的环，Luna独立确认。该问题已通过Grant无法立即取得Connection锁时无值拒绝并释放writer槽修复；真实旧save拒绝路径的并发红绿证据见下文。

## candidate1 集成诊断（不是最终验收）

首个固定构建在 `/tmp/locklark-tools/browser-otp-candidate1`：Chromium SHA256 `7c465389c89cabcb1850d98c46aa0ead2a2233b6f43632fd0b5a46291bb48e2f`；Firefox `c7b13628577ea42dac1389ae4e721532c435a0fbb5f0049873a96ed1e5aa4c54`；注册器 `bac3b0037141d355866f84c4e232dfc94b23187062f0067742ca296b5e4aec62`。主代理已独立核对这三个摘要。后续仍在修协议/取消竞态，不能以candidate1代替最终源码。

Sol CI的Firefox正常链路exit 0（`browser-otp-firefox-candidate1.log`），包含旧fill/save、6/8位独立HMAC、审计及OTP拒绝/导航/锁定/表单/旧修订/未配置/短窗口检查。draft2工具的Chrome和Firefox实际参数故障验收均通过：子进程在预期OTP故障阶段exit 1，外层隐私门槛exit 0，完整controller码/因素扫描通过，OTP失败截图为零。日志为 `browser-otp-{chromium,firefox}-candidate1-draft2-fault.log`。这是实现代理的集成证据，主代理最终独立验收仍待完成。

主代理首轮Chrome在fixture阶段失败（`browser-otp-candidate1-parent-chromium.log`）：显示94的锁文件对应Xvfb僵尸进程，socket拒绝连接，独立Playwright启动也确认无X服务。核实后仅移除失效socket/锁文件并重建，`xdpyinfo`成功；没有进入产品操作。

恢复显示后，draft2工具快照22项摘要全部匹配，但完整Chrome在旧 `save-update:navigate:fresh-candidate` 阶段失败（`browser-otp-candidate1-parent-chromium-draft2.log`，私有state `bjk7c2`）。popup截图确认等待原生保存批准，原生控件却无保存待办；尚未进入OTP。后续独立实验及只读就绪等待见下文；原失败的唯一根因未被证明，不把猜测写成根因。

此外，`browser-otp-save-slot-{red,green}.log` 保留真实旧save拒绝与OTP writer槽的ABBA修复；`browser-otp-parent-go-draft.log` 是主代理定向Go复跑通过（personal 17.705s、browserhost 2.320s）。`browser-otp-lifecycle-cancel-retire-red.log` 则证明C已在入口赢得取消、慢worker先自然retire时，后续C错误被归为refused；该竞态已由短锁记录真正的取消胜者、CancelBefore区分迟到取消与自然期限修复，Luna独立复验通过；最终head回归仍待收齐。

Chrome独立无金库实验没有证明旧target长期存活：20次零等待打开均为新target，但12次发现时尚不可见；另一次只读等待实验20次均在29ms内转为可见/聚焦，无追加按键。证据 `browser-otp-popup-lifecycle-real-{batch,settle}.log`。draft3工具仅改Chrome adapter：关闭旧CDP、等旧target退场、一次Escape和一次打开动作、等本次唯一target完整加载且可见/聚焦，点击前再次复核。Luna增量review无阻塞。Sol CI在此快照完整Chrome exit 0（`browser-otp-chromium-candidate1-draft3-normal.log`，state `OQWkof`），包括原失败场景与全部OTP检查；这不回溯证明 `bjk7c2` 的唯一根因。

主代理对两个自身失败运行的完整重定向输出（含DBus/子进程输出）另用独立Python派生期间全部6/8位码及因素变体扫描，均通过。实现中的取消来源与期限已改为短锁仲裁：早到C的胜出状态能跨慢worker/期限保留；已过期限但timer未执行的C仅撤权，不能改写自然过期来源。Luna独立复跑生命周期/重复ID及旧save隔离通过，并重复验证late-C/early-C/slow-worker边界；最终固定源码回归仍需收齐。

## 必须关闭的门槛

独立OTP用途HMAC与意图提交、完整持久复验、提前绑定取消control、输出grant与锁仲裁、O/A/C单次终态、challenge/nonce和消息ID重放、活动目标/精确来源与修订、原窗口与双时钟、串行writer及真正阻塞stdout的exit74验收。协议错误、日志和格式化不得含码或种子；旧fill/save不能接受OTP字段或取消其状态。

扩展只支持唯一顶层标准OTP输入，静态探测与填写共用来源策略；window/tab/documentId、form/action/submitter、可见与可写状态、期限在赋值前核验。预算从ack前探测开始，不在收到码时重开；无需及不得等下一期。拒绝、导航、旧页面、iframe、多框、隐藏或跨源表单等负测须独立证明无值。

真实Chrome/Firefox原生批准链路由主代理独立执行，Python HMAC在私有进程核码并重开审计，日志只输出固定分类/布尔。故障扫描包含native、browser/extension、controller和诊断，以及所有相关OTP窗口token。物理Hello/TouchID、Safari/移动与Passkey仍单列，不因本批通过而关闭。

## candidate3 与扩展 draft4 的固定实现

Go产品候选3保存在 `/tmp/locklark-tools/browser-otp-candidate3`，`browser-otp-candidate3-products.sha256` 固定146个产品源码/模块文件及3个二进制；主代理独立核对149项全部匹配。Chromium宿主 SHA256 `dcea6f514ca4fec3eb1bee6bb9b74c86ee2eb04d4f97f919d8c6e37e7a1dbbcc`，Firefox宿主 `bb7f5e3c283d5291482befb1a1877b5c2ac9bba631c9561026d837b9ac31e91d`，注册器 `6ede0e9e03b0ebd625993bb9aebddab7c35faacb2a13b5330ca8eb3f201f5ecb`。工具和扩展另由 `browser-otp-tools-draft4.sha256` 固定22项，两个dist由同一源码重建；不把Go摘要当作扩展摘要。

从candidate1到最终Go候选关闭了用途/目标/control身份校验和独立核心cap到期清码问题。主代理复跑用途/control测试先失败（`browser-otp-parent-purpose-control-red.log`）；修复绑定browser用途、精确目标、原Session及原holder。独立长control测试另证明短cap过期后缓冲仍留存（`browser-otp-cap-expiry-red.log`），最终在发布缓冲前缩短同一个control至实际cap期限并复核Pending，不能通过新建gate绕过撤权。Luna独立复验相关核心测试通过（12.900s）。同包测试人工篡改私有control时原无值登记可延至短timer清理，此有限元数据保留不被描述成立即清除。

迟到C的UI归属另有真实background VM先行失败 `browser-otp-late-c-new-save-official-red.log`：新save-new已开始，旧取消回复却覆盖它的进度。draft4仅改background及对应测试，保留历史OTP unknown记录，同时以原取消标记/epoch/token和无新pending/context约束状态写入。Luna独立执行全部52项扩展测试通过，新增矩阵覆盖save-new/fill及cancelled/unknown/refused和丢失回复；增量review无阻塞。

## 最终本地自动化检查

- 全仓Go `go test ./... -count=1`（真实Bun和PyKeePass可用）通过：personal 289.095s、browserhost 53.144s、desktop 12.109s；日志 `browser-otp-go-all.log`。全仓vet通过，日志 `browser-otp-vet-all.log`。
- Windows amd64 personal/browserhost/desktop测试交叉编译、Darwin arm64 CGO关闭的personal/browserhost测试交叉编译及对应核心/宿主vet通过，见 `browser-otp-cross-{windows,darwin}.log`；这些不等于物理系统解锁验收。
- 核心定向race通过（81.367s，`browser-otp-core-race-final.log`）：慢只读I/O中的Cancel/RequestLock、grant前锁定、并发单次、Busy+Discard、独立cap到期和共享holder上限。Writer定向race通过（1.128s，`browser-otp-writer-race-final.log`），含真实继承blocking stdout、不读端、stderr固定marker及子进程自身exit74。
- 生命周期最终17个顶层测试通过（含子例33项，`browser-otp-lifecycle-final.log`）。原16项重复5轮通过；整组race曾在180秒期限内停于夹具Argon2计算，不能写为单次完整race通过。已完成前14项及剩余两项分开race，新增原生Reject另重复5轮race通过；未报告DATA RACE。Luna独立生命周期/重放与旧save隔离复跑通过（42.628s），late/early-C与慢worker重复5轮通过（23.055s）。
- 扩展最终52/52通过（`browser-otp-extension-node-draft4.log`）；Python工具57/57及两引擎DOM均通过（`browser-otp-python-tools-final.log`、`browser-otp-dom-{chromium,firefox}-final.log`）。Next.js 8/8测试、typecheck、build及Chromium/Firefox各1项E2E通过（`browser-otp-web-*-final.log`），本批未修改Web源码。

主代理已在candidate3与draft3完成Firefox和Chromium全部旧fill/save及OTP真实GUI正常链路，日志 `browser-otp-candidate3-parent-{firefox,chromium}.log`；该结果属于最后UI修复之前的证据。draft4的最终正常与故障验收另外记录，不能把旧快照结果写成新快照通过。

## 主代理最终 GUI 验收（candidate3 / draft4）

Firefox完整正常链路exit 0，日志 `browser-otp-candidate3-parent-firefox-draft4.log`，私有state `9z6Pu1`。既有fill/save/update、点击时值、拒绝/导航/锁定不变性，以及OTP的6/8位独立Python HMAC、意图审计、取消、旧修订/来源/表单/iframe及原窗口耗尽均通过；无自动提交。退出后全局native manifest确认已清理。主代理另外扫描完整重定向输出（含DBus/子进程），所有因素及运行期间相关6/8位码均无匹配；draft3 Chromium完整重定向输出也另扫通过。

主代理独立扩展最终Node复跑52/52通过，日志 `browser-otp-parent-node-draft4.log`。Sol CI在相同candidate3/draft4执行Chromium真实driver参数故障：`browser-otp-chromium-candidate3-draft4-fault.log`，wrapper state `zwyd1bkc`；HMAC后预期子exit1、外层exit0，全controller扫描通过，OTP故障PNG为零。Firefox同快照故障也exit0（`browser-otp-firefox-candidate3-draft4-fault.log`，wrapper `8sw5pmig`），同样完成真实HMAC后携码参数故障、全controller扫描和零PNG检查；退出后manifest已清理。

Chromium最终完整正常链路exit 0，日志 `browser-otp-candidate3-parent-chromium-draft4.log`，私有state `QYOIAS`；覆盖与Firefox相同的既有fill/save/update及全部OTP正负场景。主代理另外对完整重定向输出独立派生所有相关时间窗口6/8位码及因素变体扫描，通过。产品和工具manifest再次全部匹配，31个变更Go文件gofmt检查无差异。精确head远端CI在PR创建后核验，不用本地成功替代。

主代理独立Chromium最终故障复跑exit 0（`browser-otp-candidate3-parent-chromium-draft4-fault.log`，wrapper `9k4ns38l`）：真实原生批准并经独立HMAC核码之后，携码driver参数故障按预期使子进程exit 1；外层完整controller因素/相关窗口码扫描通过，OTP失败截图为零。Luna对Go候选3及扩展draft4均无阻塞结论；本地验收门槛关闭。

## 合并结果

[PR #29](https://github.com/jihuayu/locklark/pull/29) 的最终head `ced61e5391c19d761e3ded615d5afd4074b20906` 在 [run 42133038819](https://github.com/jihuayu/locklark/actions/runs/42133038819) 的Linux、Windows、macOS和Web四项检查全部通过。主代理另外核对CI完整日志中Chromium/Firefox正常链路及两种OTP参数故障均实际执行并通过。2026-11-06 00:04:59 UTC正常squash合入 main `20e27aa48b6ac855e027cc7abde64fc3c56591f7`。以上更新前文历史等待状态；物理系统解锁、Safari/手机/Passkey等持续范围未由本批关闭。下一批为[桌面快捷搜索](desktop-quick-search-design.md)。
