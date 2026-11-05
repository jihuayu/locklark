# MyGo 日常密码生成与 TOTP 验收

[PR #28](https://github.com/jihuayu/locklark/pull/28) 已于2026-11-05正常squash合入 main `4f37d8ccd9499b6a3e292709e7d567747a8ada7a`。最终精确head `85b400ff328525572fdc98d9855b011613b9b2bd` 的 [CI 42120014509](https://github.com/jihuayu/locklark/actions/runs/42120014509) 四项全部成功，Windows/macOS原生剪贴板smoke、Ubuntu CLI/Go及Web/两浏览器真实GUI均通过。主代理独立核对run/head/四job后按正常流程合并。以下保留此前红测及各轮历史记录，不把早期“等待CI”视作当前状态。

基线 main `c9d4a5d284ddc15aa58953896e9b5773873bb1e6`，分支 `codex/desktop-daily-tools`。用户指定主代理架构与验收、Sol xhigh 实现、Luna max review；[架构约定](desktop-daily-design.md) 已根据Luna预审冻结。本批本地实现、失败先行、独立复核和最终GUI均已完成；精确head远端CI与合并仍待完成。以下保留各轮失败和修正，不能将候选或旧轮证据替代最终结果。

前批浏览器保存/更新 [PR #27](https://github.com/jihuayu/locklark/pull/27) 精确head `8d63fd6bce7068e8a7ae8968eb48425613026345` 的四项 [CI 42089993817](https://github.com/jihuayu/locklark/actions/runs/42089993817) 全部通过并已合入该基线。

本批必须完成核心原子生成/收据与取消仲裁、原生OTP意图/持久复验/单次交付、双时钟和剪贴板所有权、真实原生GUI、值扫描、独立review及精确head CI。系统硬件解锁、全部类别/附件迁移、移动/远端同步等不因本批单测或Linux GUI通过而关闭。

## 失败先行与预审

`/tmp/locklark-validation/desktop-daily-core-red.log` 记录新MutationGate、原生生成和OTP窄API不存在导致契约测试编译失败。此为核心接口缺失证据，不等于事务或GUI负测已经完成。Luna/max 已核对正式架构与预审一致，无架构阻塞；后续实现还需逐阶段独立review。

前批非阻塞工具维护项的窗口ref异常释放已有纯工具先红后绿（`desktop-daily-windowref-red.log`、`desktop-daily-windowref-green.log`，8项工具测试通过）；不因此宣称原生产品功能完成。第一轮旧桌面GUI探测误等待disabled保存按钮，属于验收工具错误，明确不计为产品缺入口red；修正观察后再记录有效证据。

修正外部观察后，真实旧版MyGo GUI缺入口red已完成（`desktop-daily-gui-red-final.log`，预期退出1）：旧手工保存/密码显示控件存在，可选网站、生成保存、重新生成、验证码显示/复制均不存在。基线binary在 `/tmp/locklark-tools/desktop-daily-baseline/`，SHA256 `456904d110cedb63ed889c4125d755995450fcfa36c5b4fbb92b36e5493baa5d`。该证据只证明新功能入口缺失；生成/OTP安全语义及新实现真实链路仍需后续验收。

## 第一阶段核心

`desktop-daily-core-first.log` 首轮核心测试通过（3.352秒）：原子生成网站/精确修订、取消与过时目标、OTP在准备后被另一Session修改时拒绝、prepared/delivery单次消费。原生只读复验已使用与写事务共享的完整认证逻辑，并以ReadOnly方式打开现有库，保留原文件检查。UI、广泛故障和竞态测试尚未完成；Luna正在进行核心增量review。

主代理抽查发现DeliverOTP末段两次时钟采样之间可能回拨或跨窗口，而第二次采样未再次核验；已要求先行失败测试并修复最后采样检查，不能把首轮green当最终验收。

外部真实reader实验还证实MyGo的Text.Label会替换辅助技术读取的静态文本：旧密码显示节点存在，但私下精确比较为false；依赖源码静态文本接口也返回Label。架构因此改为正常可访问Group命名加真实Text子节点，仅用户显式显示期间存在；不会通过新增产品测试接口绕开授权。该修复及真实读屏/显示值一致性待后续新binary验收。

`desktop-daily-clock-red.log` 已确定性复现最终采样回拨及窗口过期仍交付的两项失败；修复后核心及旧浏览器/生成定向回归通过（`desktop-daily-core-green.log`，42.265秒）。MyGo新控件先红（`desktop-daily-ui-red.log`，缺少网站入口），首版UI测试随后通过，但尚非最终GUI验收。

Luna核心增量确认两个阻塞点：最后校验与callback之间RequestLock可能已经返回却仍交付；callback panic时显式Unlock未运行，外层clear会重新锁同一cap mutex。已冻结交付grant与RequestLock短锁仲裁、panic解锁后清理的约束，要求分别先红后绿。新UI与工具首版继续等待这些核心修复及复审，不提前打包作完成声明。

这两项已有确定性red（`desktop-daily-delivery-red.log`：锁赢仍交付、panic清理死锁）及修复后的green（`desktop-daily-delivery-green.log`，personal 6.674秒/desktop 1.617秒）。原生UI首版专用operation token覆盖晚dispatch/锁库，unknown历史提示不被后来成功动作清除；仍在补关闭错误、RNG故障、多字段跨会话修改、恢复及真实GUI等证据。

## v1 固定程序首轮

`/tmp/locklark-tools/desktop-daily-v1/locklark-desktop` 的SHA256为 `95aaa0012759392d1a08409774f9de5bb88c197ac651486c4bab683fe7d3a32b`，不覆盖该产物。`desktop-daily-v1-gui.log` 记录真实手工/生成新建、授权显示/复制精确值、同ID重新生成和其他字段保留、取消/过时修订/归档/回收站，以及独立Python HMAC、显示/原码窗口到期、改选/切页/观察修订/锁定清理等均已越过。但最后 `otp-later-clipboard-owner-preserved` 控件等待超时，整套不计为通过，私有状态 `locklark-desktop-acceptance-8wkpzd39` 保留。该轮扫描仅覆盖native.log和failureJSON两个文件，不冒称controller输出也扫描过。

独立v1定向诊断在 `select-otp` 等待显示密码时失败（`desktop-daily-v1-owner-targeted.log`，`locklark-desktop-acceptance-649a_cuu`）；后续只读诊断显示对应控件唯一且enabled/showing，两个授权显示组为空。尚不足以归因产品或工具/时序；后续增加固定动作、异常类别与耗时，不重试点击或延长产品lease。工具已经统一安全输出并把controller文本写入私有controller.log，和动态生成值/OTP token一并扫描，避免为了扫描持久化原值。

增量review继续发现并修复：Prepare末次wall观察需保存，普通字段disclose的切页ABA/隐藏晚回调需核曝光代次；OTP复制之后的普通密码复制必须失效旧OTP timer/bounds/owner，防止旧任务误清新值。后者要求定向先红后绿及真实GUI追加场景；最终v2仍待这些修复闭环、冻结与独立验收。

## 最终代码复核与竞态

后续确定性失败测试还覆盖复验磁盘读取期间的验证码清理：验证码不能提前移出Session注册的可取消对象，必须在短锁下原子交换prepared/delivery对象；认证失败同时发生Close错误时，仍须先执行锁定。临时对象先清值后移出注册表，指针和值格式化均固定脱敏，callback panic不会阻断清理。对应证据为 `desktop-daily-authorize-lock-red.log`、`desktop-daily-read-finalizer-red.log` 及修复后的定向回归。

`desktop-daily-core-race-final.log`（66.417秒）和 `desktop-daily-ui-race.log`（39.944秒）覆盖原生事务/旧浏览器门控、交付与锁竞争、迟到UI、切页ABA、隐藏和剪贴板所有权。Luna/max最新独立复核没有剩余阻塞，其独立命令 `go test ./internal/personal ./internal/desktop -run 'TestDailyOTP|TestDailyOldOTPTimerCannotClearLaterOrdinaryCopy|TestDailyNativeReadInvalidAndCloseFailureStillLocks|TestDailyOrdinaryDisclosure' -count=1` 通过（personal 17.227秒、desktop 3.023秒），并确认 `git diff --check` 通过。此结论是代码复核，最终固定binary的完整GUI和远端CI仍单列验收。

全量 `go test -count=1 ./...` 已以退出码0完成，实际设置 `LOCKLARK_TEST_BUN=/tmp/locklark-tools/bun-linux-x64/bun`、`LOCKLARK_TEST_PYKEEPASS=/tmp/locklark-tools/python/bin/python`，使用Go 1.27.3；日志 `desktop-daily-go-all.log`（personal 290.213秒、preview 140.730秒、desktop 9.407秒、browserhost 18.171秒）。全量 `go vet ./...` 退出0，`desktop-daily-vet.log` 无诊断。

最终v2程序固定在 `/tmp/locklark-tools/desktop-daily-v2/locklark-desktop`，SHA256 `cd24f877f1824bf51fe136accf4ac204e6bcf48f6677a9191b3cce11eb492759`；`desktop-daily-v2-artifacts.sha256` 同时记录产品源码和测试，主代理独立逐项校验通过。v1保持不覆盖；v2完整GUI与故障诊断隐私扫描分别进行。

## v2 外部验收诊断

主代理首轮 `desktop-daily-v2-parent.log` 在过时重新生成的审计断言失败，私有状态 `locklark-desktop-acceptance-tr0xjrw8` 保留。原因是后来补充的工具断言把冲突事件 `base_revision` 错认成旧请求修订；签名历史契约始终要求当前已认证修订。私有oracle仅返回固定布尔，确认conflict、精确itemID、当前base revision、独立编辑确实存在、审计安全和观察未写活库。脚本改为核对 `independent` 当前修订，快照/全部条目不变的断言保持。Luna独立确认修正符合 `appendLinked` 与 `journal.history` 的现有契约，17项工具测试及编译/diff检查通过。该轮失败属于验收工具，不能冒称产品事务缺陷，也不算完整GUI通过；v1越过此阶段不能回溯当作这项新断言的验证。

真实 `probe-input` 故障验收 `desktop-daily-v2-probe-failure.log` 已按预期退出1（`private-probe-failure`）：先真实生成新密码，再将私有值送入探针错误路径，固定枚举错误返回。私有状态 `locklark-desktop-acceptance-49n__tem` 中controller/native/诊断共3文件及重定向controller输出均经动态密码、因素、种子与独立OTP token扫描，无原值泄漏。产品v2未改动，最终正常GUI正在独立重跑。

第二轮 `desktop-daily-v2-parent-final.log` 已通过修正后的冲突审计、归档/回收站，在OTP显示的外部读取中收到固定 `probe-a11y-query`，整套仍不计通过，状态 `locklark-desktop-acceptance-shrm4fv2` 保留。独立显示探针之前对 `AccessibilityQueryUnavailable` 单次失败，而共享控件driver已处理这种查询错误。现探针仅对这一类型错误在原请求内允许0.5秒单调预算启动只读重取，并处理非阻塞事件队列；其他结构/授权错误直接失败，到期空值/不匹配不能重取成新码。没有重复点击或生成，没有延长产品lease；单次底层查询耗时仍受外部15秒请求时限约束，0.5秒不冒称底层调用的硬超时。安全响应只新增尝试次数。`desktop-daily-probe-query-red.log` 记录工具先行失败，green日志21项工具测试通过；最终完整GUI继续以同一v2程序执行。

Luna/max已独立复核该探针修正，核对有限预算、仅指定异常重取、授权静态文本范围、引用释放以及到期值仍拒绝；独立执行probe和共享X11 driver的17项测试通过，无剩余工具阻塞。CI的macOS筛选已包含 `TestDaily`，Linux/Windows全量测试与既有两浏览器GUI链路保留。

第三轮 `desktop-daily-v2-parent-probe-fixed.log` 已通过独立HMAC显示与到期清理，但在 `otp-copy-original-window-expiry` 未完成，状态 `locklark-desktop-acceptance-4470j4zo` 保留。复制点击成功，固定诊断中原生按钮enabled，显示探针最大尝试次数1；随后私有探针响应不可用，故障诊断也无法再取得display。整套失败、完整日志扫描通过，尚不能据此确定为产品或探针剪贴板路径的问题。后续需补精确超时分类并定位，不能把无响应认作剪贴板为空，也不能跳过剩余场景。

## 剪贴板重入修复

后续代码排查发现另一个可确定复现的产品边界：MyGo Linux `Clipboard.ReadText` 使用同步 `gtk_clipboard_wait_for_text`，GTK嵌套事件循环可重入View。旧 `clearClipboard` 在读取结束之后才清除过期ownership元数据；因此View可再次发起读取，或旧清理在读取期间有新复制后继续误清新值。`desktop-daily-clipboard-reentry-red.log` 的两个真实UI seam测试分别复现递归读取和误清新复制。此证据证明该边界存在，尚不能单凭它断言第三轮真实GUI失败的根因。v2产物继续保留；修复与增量review后另建v3。

第三轮状态的私有审计观察确认一次OTP copy intent，目标及当前base revision正确，后续无条目mutation，审计不含原值。两次只读观察的快照相同；由于没有此阶段之前的独立hash基线，不把这一结果称作完整阶段前后快照不变，也不把intent视为交付成功。

独立合成GTK owner实验 `desktop-clipboard-sync-owner-red.log` 使owner延迟16秒；旧同步探针在15,267ms仍未返回，后续同worker请求也无响应。改为有界异步 `gtk_clipboard_request_text` 后，`desktop-clipboard-async-owner-green.log` 记录约1,005ms返回固定超时失败、同worker随后可用、迟到回调不能满足后续请求。回调指针保持整个worker生命周期，opaque递增token不引用临时Python对象；过期token不读取原文，超时不能当作empty。这个实验独立证明探针边界修正，不借此推断第三轮根因。

后续产品失败测试分别证明：普通字段/OTP复制在OS读取内发生锁库、改选、同目标新复制后，旧回调仍继续写入（`desktop-daily-copy-context-reentry-red.log`，6分支）；读取实际耗尽4秒原OTP窗口后仍写入（`desktop-daily-copy-expiry-reentry-red.log`）；锁库把OS读取排在会话/UI撤销之前（`desktop-daily-lock-before-clipboard-red.log`）。修复限定desktop：清理先摘metadata，复制返回后复核UI/曝光/精确目标/ownership代次和OTP原bounds，锁库先撤销再OS清理。personal核心保持v2源码不变。

Luna增量复核还发现“每次clear都递增序号”会让嵌套Lock阻止外层清理旧值，导致旧秘密留在剪贴板且丢失清理metadata。强化旧值必须清空的断言后有4分支red（`desktop-daily-nested-clear-owner-red.log`）。架构将序号限定为新复制取得ownership时递增，纯Lock/clear允许已经开始的旧hash清理完成；只有新复制才阻止旧清理，旧回调写入仍由UI/曝光代次阻止。Luna已独立挑战并认可这一方案，最终实现回归及GUI仍须通过。

最终探针工具32项测试、Python编译和diff检查通过（`desktop-native-tools-final.log`）；Luna独立复核并运行32项通过，确认超时/EOF/坏JSON/断管会禁用失步transport、固定业务错误仍允许健康worker提供诊断，所有输出仅固定分类、计数和布尔。

## v3 冻结版本

Luna已对重入、锁库顺序和ownership代次的最终产品实现复核，无剩余阻塞；其独立定向桌面测试通过（12.781秒）。最终 `go test ./internal/desktop -count=1` 通过（15.097秒，`desktop-daily-v3-desktop-all.log`），定向UI race通过（62.355秒，`desktop-daily-v3-desktop-race.log`），desktop vet退出0（`desktop-daily-v3-desktop-vet.log`）。9个personal源码/测试文件与v2清单逐一SHA相同，因此保留上文全量Go/全vet与核心race的证据，新增行为另由本次desktop回归和随后精确head CI覆盖。

`/tmp/locklark-tools/desktop-daily-v3/locklark-desktop` SHA256为 `edee1658a03cfaad0c6473b2ca40f605f8a89519089736a9c49a89b6029037a6`；主代理独立验证 `desktop-daily-v3-artifacts.sha256` 的程序及全部源码/测试匹配。v1/v2保持不覆盖。主代理使用隔离display `:94`、私有DBus、真实AT-SPI/XTest输入执行完整GUI，工具代理在独立 `:95` 以同一v3执行最终故障隐私验收。

v3故障隐私验收通过（`desktop-daily-v3-probe-failure.log`，状态 `locklark-desktop-acceptance-nzgk91ut`）：实际生成后预期exit1，wrapper核对host SHA并扫描重定向stdout/DBus及state内3个日志/诊断文件，无因素、种子、生成值和独立OTP token泄漏。正常整套首轮 `desktop-daily-v3-parent.log` 仍在OTP显示/到期场景失败为 `probe-unexpected`（状态 `locklark-desktop-acceptance-2jbnl3hw`），不得计通过；日志扫描通过，原生日志无panic/fatal/segfault。现补固定异常分类和无值结构诊断后定向定位，不在未确认原因时放宽树预算或归因CPU。

安全诊断增量只公开固定异常类别、本工具白名单函数别名/行号、数值depth/visited/remaining/children，并在probe与controller两侧过滤；不输出异常args、文本、locals或源路径。已知tree/child/window guard分别分类，原12层/512节点/256子节点限制不变；先红日志 `desktop-probe-guard-reason-red.log`，37项工具测试通过 `desktop-probe-guard-diagnostic-green.log`。定向真实OTP显示/HMAC/到期通过（`desktop-daily-v3-otp-targeted.log`，状态 `b29maoqg`）。持有真实已移除OTP组proxy的只读实验显示child_count=-1且GError=true（`desktop-daily-v3-defunct-count.log`，状态 `e9kwuxsn`），属于已有typed-query路径，不证明“负count无错误”假说。两项均有私有扫描；尚未复现首轮unexpected，不将定向通过当根因修复。

主代理第二轮v3整套 `desktop-daily-v3-parent-diagnostic.log` 已越过OTP显示/原窗口到期、OTP复制被普通密码替换、切换条目/页面、观察修订、锁定清理和到期保留外部owner；最后 `otp-later-clipboard-owner-preserved` 点击锁定后等待解锁界面10.127秒超时，整套仍失败（状态 `locklark-desktop-acceptance-lp3hw8o0`）。扫描通过，诊断中旧OTP组仍显示，锁定按钮仍enabled。这些只是最后可见的可访问树，不能仅凭它区分点击未到达与锁定已执行但OS读取阻塞，后续需单次输入与私有栈符号诊断。没有重复点击或把部分通过当完整验收。

随后执行环境重启，源码和v3 SHA均保留。旧display进程与socket需核实状态后恢复；已完成测试证据保留，重启中断的实验另记环境原因，不能当产品失败。主代理隔离display `:94` 已重新建立，继续同一v3的诊断。

## v3 实际锁定阻塞与 v4 修复门槛

重启后的定向复现保留在 `desktop-daily-v3-lock-combined-restored.log`（状态 `h6ecq4ty`）及 `desktop-daily-v3-lock-split-restored.log`（`0f_fecvc`）。两轮均只点击一次锁定，输入发送与目标窗口正确，10秒内未发布解锁界面；私有SIGQUIT栈仅提取固定符号布尔，确认同goroutine进入 `App.Lock → clearClipboard → linux.clipboard.ReadText`。分离AT-SPI显示探针与剪贴板owner后仍复现，不能归因组合测试进程。扫描通过，原始栈不进入公开输出。

`desktop-daily-v3-lock-owner-verified.log`（`5fol9wlk`）在锁定前先由独立reader读Marker时通过。这只能证明额外预读改变了时序，不能关闭产品阻塞。工具新增独立owner检查后的42项测试通过；完整GUI仍未通过。

已冻结v4原生ownership lease设计并授权Sol实现，Luna审查平台生命周期与竞态。外部red必须先通过XGetSelectionOwner确认foreign owner，随后不预读、不重复点击；owner拒绝响应时，锁定仍须及时发布，清理阶段请求计数为0且owner不变，最后才启用响应独立读取Marker。v3产物及失败证据保留；v4的单测、真实GUI、故障日志扫描、独立review和精确head CI均尚待完成。

`desktop-daily-v4-clipboard-red.log` 已先行复现两项确定性产品失败：`TestClipboardCleanupNeverRequestsForeignContent` 在Lock请求了剪贴板内容；`TestClipboardCleanupPreservesSameValueFromNewOwner` 证明内容hash不能区分同值的新foreign owner。两项退出1，Sol随后开始native lease实现。此为单测red，真实不响应owner的外部red仍单列。

平台预审曾担心GTK共享owner window的旧SelectionClear误清新provider。主代理取得GTK 3.24.38完整源码后，Luna独立确认 `gtkclipboard.c → gtkselection.c → gdkselection-x11.c → gdkdisplay-x11.c`：每次新set无条件记录NextRequest，旧SelectionClear在派发到GTK前被窗口/serial过滤。因此该项不是已证实的产品缺陷；撤销额外filter/barrier方案，保留真实快速重写测试。源码观察不代替最终运行证据。对应上游为 [GDK SelectionClear过滤](https://github.com/GNOME/gtk/blob/3.24.38/gdk/x11/gdkselection-x11.c) 与 [X11事件分发](https://github.com/GNOME/gtk/blob/3.24.38/gdk/x11/gdkdisplay-x11.c)。

真实不响应foreign owner的强red已完成：`desktop-daily-v3-unresponsive-owner-red.log`，私有状态 `n0ofik4c`。XGetSelectionOwner确认精确foreign XID；设owner后无预读，仅一次Lock，XTest/focus检查通过。3秒内未出现锁定界面（3005ms），清理阶段1次SelectionRequest为payload请求，foreign owner保持不变，按 `foreign-clipboard-request` 失败。controller/native/probe/诊断完整扫描通过。该场景已接正常完整GUI与CI路径；独立scenario只用于外部验收选段，不是产品权限开关。

主代理独立运行v4候选1定向foreign-owner场景通过（`desktop-daily-v4-candidate1-parent-foreign.log`，状态 `m79ogw_y`）：锁定界面535ms发布，全部SelectionRequest为0、owner保持、无预读，随后独立Marker比对及完整日志扫描通过。固定binary SHA256 `25ae1e61c15976cfff03a43eae1f7f40ce8d5026d24ad1d6556e136427411f29`。这轮使用旧0.2秒观察窗口，不计为已覆盖1秒重试；脚本末尾通用PASS文案亦不能当完整流程通过，已要求按scenario修正。Luna随后发现的GObject地址复用/旧lease ABA需另修，候选1不覆盖该修复。

Luna发现旧GTK lease仅凭GObject数值地址和owner XID可能接受释放后复用的地址。`desktop-daily-v4-gtk-aba-red.log` 确定性失败，修复要求 `gtk.sources[p.owner] == p` 的provider对象身份核验。随后 `desktop-daily-v4-desktop-all.log` 中nativeclipboard/desktop测试通过（0.014/7.720秒），但后续平台错误路径增量及最终构建还需复跑。候选1仍固定保留，不追溯含此修复。

工具46项测试通过（`desktop-native-tools-v4-single-action.log`）。当前主脚本SHA256 `47a80e2601c324fd027403ac815af25fc48e63e3bddf81d6898bb3889f4aec31`；foreign owner持续拒绝1.25秒，并在respond线性点检查累计请求仍为0才允许独立reader开始。一次点击的AST与成功/超时调用次数断言是契约保护，不记录为已修双击缺陷（review中的重复行源于两段读取区间重叠，已独立核对并撤回）。

## v4 候选完整GUI（非最终构建）

主代理在独立显示94运行 `desktop-daily-v4-candidate1-parent-full.log`，退出0，状态 `zk6vt60w`，首次完整GUI通过。脚本为上述 `47a80e...aec31`；覆盖原子手工/生成、精确重新生成、取消/冲突/归档/回收站、大段Unicode原生复制/独立读与自有清理、TOTP独立HMAC及原窗口显示/复制到期、后续密码复制、改选/切页/修订/锁定清理。160KiB Unicode provider的独立95定向也通过（`desktop-daily-v4-candidate1-provider.log`，`z7qvhleb`）。

完整流程的三项foreign owner观察（同值新owner切页、OTP到期、锁定）均无预读，持续拒绝1250ms，全部SelectionRequest及allow线性点累计请求为0，owner保持；允许后由独立reader核对值。锁定界面617ms发布。controller/native/probe/诊断以及动态生成值、ProviderCanary/完整大值和独立OTP窗口token扫描通过。此候选不含后续GTK地址复用、accepted-write错误路径和旧复制期限等增量；最终v4必须重新固定及全套验收，当前还未创建PR/运行远端CI。

## v4 最终固定构建

`/tmp/locklark-tools/desktop-daily-v4/locklark-desktop` 构建退出0，SHA256 `0c098b9249ddfb3e8d86ff0dba538c674c02cdbb3554510a0a9f0d035f529228`；源码清单 `desktop-daily-v4-artifacts.sha256` 包含binary及91项源码/go.mod/go.sum，主代理逐项校验通过，工具9项清单亦通过。personal核心相对v3未改；purego v0.11.1仅改为直接依赖，无版本变动。最终GUI与故障验收正在该固定构建上执行，候选1不能替代。

最终产品测试 `desktop-daily-v4-desktop-all.log` 通过（nativeclipboard 0.046秒、desktop 8.233秒）；竞态 `desktop-daily-v4-desktop-race-final.log` 通过（1.137/61.766秒）。Linux `desktop-daily-v4-desktop-vet.log`、Windows amd64 `desktop-daily-v4-windows-vet.log`、macOS arm64 `desktop-daily-v4-darwin-vet.log` 均退出0。跨平台静态检查和测试包交叉编译不等于原生运行；Windows/macOS的 `TestNativeClipboardSmoke` 已在CI显式启用，包含独立owner进程，Windows另核busy、nonce格式序号变化和部分写入。

`desktop-daily-v4-partial-expiry-red.log` 先行证明复制期间原期限到期、旧metadata尚在且新lease清理暂不可用时，会丢失新清理资格；最终实现仅在原代次仍有效时摘除旧metadata，再保留新lease清理，真正重入的新复制不受影响。Windows部分写入无nonce且同owner序号变化时保留Unavailable；元数据无法证明内容已替换，不虚报Superseded。

Luna/max最终产品增量复核无阻塞，独立Linux定向测试通过（nativeclipboard 0.032秒、desktop 6.069秒）；Windows amd64/macOS arm64测试包交叉编译成功，仍不计原生运行。最终v4故障隐私验收 `desktop-daily-v4-probe-failure.log` 通过（状态 `tyb1c17s`）：真实生成新密码后probe-input按预期退出1，wrapper核固定phase/reason后退出0；重定向controller/DBus输出及state内3日志/诊断文件均扫描通过，包含ProviderCanary及完整大值。

最终v4首轮完整GUI `desktop-daily-v4-parent-final.log` 在启动解锁阶段失败（状态 `gyyb3uwe`）：`native-x-target`、65ms、failed index为None且无最后click记录，未进入输入动作；事后控件仍为解锁页，native.log73字节无panic/fatal/segfault，完整扫描通过。窗口存在与可接受focus之间可能有启动竞态，但原诊断未保存X错误码，暂不把这一推断定为根因；已要求外部unmapped窗口red/固定数值诊断及原发现预算内的只读可见性观察。产品v4保持冻结，最终完整GUI门槛仍未关闭。

启动工具的独立X11实验 `desktop-native-viewability-red.log` 复现同类错误：精确匹配但尚未mapped的窗口被聚焦，helper退出1并记录BadMatch错误码8，窗口随后正常映射。`desktop-native-viewability-green.log` 及singleclick-green验证修复后只读等待同一XID达到IsViewable，再一次聚焦/输入；发现和可见性等待共用原5秒绝对预算，查询返回后复核期限，属性失败/超时/实际focus或input错误仍拒绝。初始GUI失败没有错误码，不能把独立实验的8追溯当作该轮原始记录。

修正经Luna增量复核无阻塞，其独立18项helper测试通过；主代理独立53项全部native工具测试通过（`desktop-v4-tools-parent-readiness.log`）。新工具清单 `desktop-daily-v4-readiness-tools.sha256` 保留另名，主脚本SHA256 `f455738cad72e71d2e60ebfa830829ebc327cf98915c2eb7a26881ea0d20aa40`；旧清单及失败日志不覆盖。主代理已重新核对全部产品/工具hash并启动最终完整GUI，产品v4保持上述固定构建。

## 最终本地验收通过，等待PR精确head CI

主代理最终完整 `desktop-daily-v4-parent-readiness-final.log` 退出0，状态 `qymbm41y`，使用固定v4 SHA256 `0c098b...29228` 和readiness工具清单。完整生成/精确重新生成/状态/Unicode provider/TOTP显示与原窗口复制/改选/切页/修订/锁库场景均通过；三项foreign owner观察全部无预读、1250ms内及allow线性点累计请求0、owner保持，独立读取核对正确。最后锁定界面647ms发布；授权显示reader最大尝试数2，仍在既定只读查询预算内，没有重复点击或重新生成码。全日志及动态canary/token扫描通过。

同一最终构建和readiness工具的故障隐私验收 `desktop-daily-v4-readiness-probe-failure.log` 再次通过，状态 `70keuamt`：真实生成后预期脚本退出1、wrapper退出0，完整重定向输出及3个状态日志/诊断文件扫描通过。旧故障及候选证据保留。53项工具测试、最终产品测试/race/vet及Luna复审均完成，准备PR；Windows/macOS原生剪贴板smoke及四项精确head CI仍待远端执行，硬件解锁仍单列。

## PR #28 首轮真实平台CI

[PR #28](https://github.com/jihuayu/locklark/pull/28) 首个精确head `cdd7e599a99a3713c45eb1ce2ee36e40f12712c2` 的 [run 42118122749](https://github.com/jihuayu/locklark/actions/runs/42118122749) 已执行。macOS job成功，包含显式启用的原生剪贴板smoke。Windows job `127563078621` 在 `TestNativeClipboardSmoke` 的固定 `partial native write cleanup failed` 断言失败（smoke_windows_test.go原第98行）：之前ErrWrite、lease非nil及实际Unicode内容读回均通过，说明文本已交OS但清理未确认。Ubuntu矩阵因fail-fast取消，不计为通过；Web最终成功，包含Linux原生桌面、管理两浏览器E2E、Chrome/Firefox DOM及两浏览器原生fill/save全部步骤。

该Windows路径在文本已写入而nonce失败后依赖Close前采样的sequence；现有日志不能区分写Close、后续读取或合成格式是否推进了序号，不把推断写成已观测根因。架构改为同Open锁内nonce先于文本；凭证失败则不发布秘密，所有secret-bearing lease均可用nonce验证。Sol实施窄修、Luna增量复审，之后新head必须四项CI全部通过，不能用Linux GUI或macOS成功替代Windows失败。原始CI日志仅私下保存，普通输出只引用固定测试/阶段。

Windows后续窄修只改 `clipboard_windows.go` 和 `smoke_windows_test.go`：nonce在同一Open锁内先发布，失败时文本Set调用为0；文本失败确认回滚后才返回nil，回滚未确认保留nonce lease；真实文本成功后Close结果未确认仍可凭nonce清理。旧sequence/无nonce授权分支已删除。原生smoke保留固定 `partial native write cleanup failed` 断言，新增真实nonce失败、文本失败/回滚、回滚故障、post-text未知结果检查，不能以删除失败场景换取通过。

Luna/max增量复核无阻塞，独立Linux nativeclipboard测试及Windows amd64测试包交叉编译通过；Sol Windows amd64交叉编译与vet通过。本地无Windows运行时，原生green仍等待新head CI。Linux/macOS产品与已验收v4行为不变；本次不将跨编译充当Windows成功，也不因首轮Web/macOS成功忽略新head的四项完整门槛。
