# 团队同步与原生移动端验收

基线 main `9d8d57475f3fb904fc9fe4bedc0c1e6b4ce07535`，工作分支 `codex/team-mobile-sync`。主代理负责[架构](team-mobile-design.md)及独立验收，Sol xhigh 分工实现与工具，Luna max 独立审阅。以下只记录已实际完成的范围；平台和最终 CI 待办不计为成功。

## 当前状态（第十三轮 Android CI 后）

`e721f6a0e8b2196eb1a72b720b44096b525f0c38` 的四组桌面/Web CI 全部通过，run `42173100529`。Android run `42173100508` / job `127745263134` 的独立外部主机流程全部13组通过，包含真实界面、后台锁库、签名审计、独立 TOTP/PyKeePass 与完整输出隐私扫描；原生 instrumentation 执行了2项，其中1项在 edit-notes/save-field 阶段因实际键盘仍可见而失败。不能把外部流程通过当作原生两项全部通过。

同轮完整 google_apis 镜像确认安全锁屏能力存在，受控 PIN 设置成功，随后应用快捷解锁启用被拒绝，尚未出现可信 OS 凭据窗口。旧日志没有细分失败阶段，因此不能断言唯一根因。已依据 Android15 固定版本系统源码修复“认证之前发送 GCM AAD”的独立缺陷，见 [认证说明](../mobile/android/AUTHENTICATION.md)。主代理独立重新执行19项 JVM 策略测试、16项认证工具测试，通过；APK 构建通过，Luna 复核无认证排序阻塞。真正 OS 认证成功仍待下一轮原生 CI。

原生点击测试正在修复迟到 IME：最多一次 owned-window hide、观察真实隐藏状态、按当前 viewport 滚动并只执行一次点击；Luna 要求空 insets 和截止时间越界都拒绝通过。这个修复不修改产品生命周期或放宽业务断言。

iOS 当前模拟器缺少所要求的完整文件保护，产品继续拒绝。单独的能力拒绝测试已实际通过，完整正向流程没有通过。真机专用入口已经实现；用户确认暂时没有 iPhone 真机和签名环境，故不把这项外部限制写作已完成或不断重复请求设备。

团队协议和服务进程验收已经通过，但完整团队用户入口尚未实现；下一批设计见 [团队客户端产品设计](team-client-product-design.md)。PR #37 保持草稿，不能因桌面/Web 四组通过而忽略原生运行失败。

## 第七轮及此前的证据

团队真实 TLS、多设备权限、撤销、并发、回滚与未知提交对账，以及生产服务命令的独立 PTY/TLS 验收已通过。`22204ec7e024b1a0686a5df2d901e99f24ca60af` 的 Linux、Windows、macOS 桌面和 Web 四组 CI 全部通过。Windows ACL 已在原生 Windows CI 执行，不能再仅称为交叉编译。

Android 在 `d6eec7d` 的第七轮 CI 中通过完整基础链路：两项必须执行的实际应用 UID/JNI/原生界面测试，以及独立 ADB 的建库、Secret Key 确认、手工和生成登录、精确修订编辑、独立 HMAC TOTP、搜索、后台及主动锁定、错误双因素拒绝、重开、设备数据库复制、CLI 精确签名审计、PyKeePass 字段核对/错误导出密码拒绝，和完整控制器/logcat canary 扫描。原始私有记录 `team-mobile-pr37-seventh-android.log`。

第五、六轮的 KDBX 阶段失败由工具解析虚拟环境 Python 符号链接造成。保留配置的解释器路径后，真实 venv 回归通过；主代理独立本地复跑移动核心金库→PTY CLI→PyKeePass，记录 `android-peer-repro-is7ld0mb/android-host-ui-hihtz2s_`，预期密码/OTP 篡改均拒绝。此本地复验没有 ADB；第七轮才是修正后的完整设备链路证据。

iOS 实际 Apple SDK 编译已通过，运行仍在 Go 建库之前的 VaultFiles.protect 失败，typed/raw 读取兼容修复不足以解决。`4fb702e` 的实际前置诊断确认：目录和文件、typed 和 raw 两种 FileManager 设置均返回成功，但保护属性前后都缺失；备份排除写入、刷新后回读和枚举正常。原始私有记录 `team-mobile-pr37-sixth-ios.log`，只发布固定元数据。`81970aa` 改用 Apple 推荐的 NSURL 文件保护接口，实际第八轮 CI 的设置仍返回成功，但刷新后的 URL 保护等级始终为较弱类型，原始私有记录 `team-mobile-pr37-eighth-ios.log`。这确认当前模拟器未提供所要求的完整保护；产品继续严格拒绝，不增加模拟器豁免。完整原生用例和 UI/输出隐私检查需要具备该能力的真机环境；用户已确认暂无真机和签名环境，真机入口已准备，尚未验收成功。

Android 系统凭据认证工具已实现成功、取消、密钥属性和重装失效检查，Luna 复核、15项 JVM 与9项工具测试、APK 编译通过；首次实际系统认证轮停在模拟器 PIN 配置阶段，尚未进入应用认证，已定位 ATD 镜像缺少安全锁屏能力；iOS 真实系统认证和两平台真机生物识别仍未验收。PR #37 保持草稿，当前未满足精确 head 全 CI、最终独立审阅与验收后的合并条件。后文保留各历史候选的失败与修复证据，不把早期通过结果自动延伸到后续代码。

所用 API35 google_atd 镜像的实际 vendor permissions XML 明确删除 `android.software.secure_lock_screen`；主代理独立解析44项 feature，确认该项缺失，提取文件 SHA256 `adf6e6a182c6552955a6cff6b3e7ec42333f6ccad2f02d0ab0c24887483f7d06`。Android 15 LockSettingsShellCommand 源码在此能力缺失时直接拒绝 verify/set-pin。CI 改用完整 google_apis 镜像，认证仍是必须通过的关卡；工具补充固定子阶段、能力布尔值和安全错误分类，14项认证工具及4项原生包装测试通过。此处是精确镜像和系统源码证据，完整镜像的实际认证结果仍待新 CI，不把旧基础 UI 通过算作系统认证通过。

## 团队同步的失败先行与独立验收

`team-sync-history-red.log` 是实际行为失败：旧目录 Read 在同一真实 fixture 上成功，尚未实现的 ExportHistory 返回拒绝。随后目录整包检查通过。外部工具保留旧 main CLI 不存在 `team-sync read` 的 feature-absence 记录，但新交付使用独立服务命令与客户端库，不能将该旧 CLI 命令称为新增产品入口。

Sol 外部验收使用独立 TLS 服务、多个客户端进程、owner/publisher/sequencer 与独立设备密钥，以及真实 bbolt、age、KDBX。私有 oracle 不调用 vault.OpenItems，独立验签 proposal/receipt/snapshot、解开 age 并读取 KDBX。工具首轮因零 VerifiedState.Checkpoint 仍计算散列发现产品错误并修复；另一轮因捕获 wrapper 缺少 ResponseController.Unwrap 导致严格 deadline 被拒，修正工具以保留真实 socket deadline。失败记录保留，不把失败轮计为成功。

候选 core1 固定清单 `/tmp/locklark-validation/team-sync-core-candidate1.sha256`，SHA256 `62148b82105c7209b91d5c43f0e2d7f36cdb0c4d76e62e3fe4163ed1dcdfc083`。主代理独立核对源码，固定外部工具清单 `team-sync-parent-tools-v1.sha256`，独立构建 `/tmp/locklark-validation/team-sync-parent-candidate1`，运行：

```sh
GOTOOLCHAIN=go1.27.3 /tmp/locklark-tools/go/bin/go build -o /tmp/locklark-validation/team-sync-parent-candidate1 ./scripts/team_sync_fixture
python3 scripts/team_sync_acceptance.py --fixture-bin /tmp/locklark-validation/team-sync-parent-candidate1
```

主代理完整流程 exit0，日志 `team-sync-parent-candidate1.log`，私有目录 `team-sync-v1xivquy`；前后产品和工具清单均一致。12组覆盖真实 TLS/身份与 owner 边界、设备入网/reader 可读但不可写、writer 更新与精确父 CAS、新 nonce 下旧响应/密文篡改/错误 pins/错误 TLS 主机/客户端检查点失败、超15秒完整响应拒绝、排序端独立检查点阻止真实旧数据库回滚（包括只持 Genesis 的新客户端）、并发单赢家、丢回执的未知与精确 proposal 对账、服务端提交后检查点失败不确认成功及后代恢复、设备/整成员撤销后网络和新密文解密拒绝、owner 读取冻结历史、完整控制器/网络正文 canary 与 nonce 检查。Sol 的独立完整轮另存 `team-sync-5dqfwjoh`，不是主代理的同一轮。

主代理再独立扫描最外层重定向输出、所有子进程 stdout/stderr 与完整捕获请求/响应：除条目值外还检查全部合成设备、owner/publisher/sequencer 私钥的原始、Base64、hex、JSON、URL 编码，共343个文件、99种模式、零命中，记录 `team-sync-parent-extra-privacy.json`。私有 oracle/配置文件有意保存合成因素，不上传仓库。

## 移动核心与平台进展

移动门面复用真实个人库，会话、双因素、生成、精确修订编辑和披露均不是 fake 仓库。最初 API 缺失导致编译失败，只算 compile red；后续实际行为失败包括锁定已胜出但旧最终检查仍交出复制值、字段 handle 在 Take 前预读并记秘密意图、Clear 等待阻塞的 Take，以及拒绝一般字段编辑后审计校验器不认识对应 native-refused。均保存具体失败并修复：最终短授权与 RequestLock 同锁仲裁，字段在 Take 内新事务读取，Clear 即时取消并异步清理，审计允许的动作仍是固定六种字段。

Luna 独立运行移动字段延迟披露/另一会话旧修订拒绝、Clear 与交付竞争、锁定与交付先后、OTP 时限与审计等定向测试，5.406s通过；这是当时的定向结果，随后复核又发现 OTP 最终授权和排队操作的边界，见下文；原生 UI 迟到回调仍必须核对自身前台/选择代次。Sol 的移动及新增原生编辑定向 race 通过（core69.996s、personal16.383s）。一次更宽的 mobile/core+整个personal race 因旧浏览器 OTP 1秒控制窗口与测试负载发生到期拒绝，并在默认10分钟时限内仍运行 PBKDF 而超时；该轮没有完成，不计为全包 race 成功。原完整输出在工具会话70635，私有文件 `personal-race-failure-excerpt.log` 只有明确标注的摘录，不能冒充完整日志。随后完整 personal normal 回归在20分钟时限内通过（369.975s，`personal-normal-final.log`），不能据此把失败的宽范围race补记为成功。

第一轮移动核心冻结并绑定，AAR SHA256 `b1f336c36c25a839f40354327e60213ce48c6265c2a5a680e04ca0b5685dfefe`，88项实际平台传递源码/嵌入资源及构建工具清单在构建前后完全一致，产物保留 `/tmp/locklark-tools/mobile/core-final/`。

Android 已安装固定 JDK/SDK/NDK 并以真实 AAR 编译原生应用。软件 TCG 模拟器虽后来报告 boot_completed=1，但安装时 package 服务不存在，未进入应用，不计 UI 通过。iOS 纯 Swift 逻辑从实际 runtime red 修复后通过；第一轮 macOS CI 的真实 XCFramework 绑定、XcodeGen 和纯逻辑均通过，随后模拟器型号与 runtime 不兼容，尚未进入应用 SDK 编译/XCTest。所有 runtime 日志私有保存，CI 只输出固定分类，禁止上传含因素/正文的日志、截图或 xcresult。生成物的源码清单需包括实际平台传递依赖和 go:embed 输入，不能用整个仍在变化的工作树清单冒充冻结构建。

## 尚未关闭

服务命令隐藏终端验收已关闭，见后文；当前剩余为移动运行与系统认证、冻结后的最终审阅、精确提交 CI 和正常 PR 合并。完整团队邀请/草稿与冲突 UI、移动团队配对、原生系统填充、Passkey、远程审批、附件/历史和系统钥匙真机验收仍是持续范围；本记录不宣称整个团队或移动产品完成。

## 提前草稿 CI

全仓编译探针 `go test ./... -run '^$' -timeout=5m` 通过（不计作测试运行），当前 main 核对仍为 `9d8d574`。准备草稿 PR 以获得 Linux 无法提供的真实 Apple SDK/模拟器，以及有硬件加速的 Android CI；这早于完整平台验收和最终审阅。所有待办在最终精确提交通过前均保留，不据草稿编译认定可合并。

## 第二轮复核与独立服务命令验收

Luna 复核和确定性测试发现：OTP 原生交付后到门面最终授权之间的同周期回拨未再次校验；外露 From 仍为周期起点；旧解锁/修改可在等待串行锁时越过 RequestLock 使用新会话；Lock 等待期间被另一解锁超越后可能返回未锁定。旧行为五项实际失败记录在 `mobile-otp-grant-red.log` 和 `mobile-queued-lifecycle-red.log`。修复为复制原 OTPBounds 并在最终短授权再次 Check、From 使用最新成功授权时间、进入队列前捕获会话代次并在获取工作锁后复核、Lock 持工作锁后二次失效。当前五项通过（2.944s），核心整包 normal 通过（10.212s），最终 race/绑定和两端运行仍待完成。第一轮 AAR 现在是历史候选，不能代表这些新增修复。

两端工作队列还须在真正开始 Go/系统操作前检查线程安全的取消凭证，避免切后台之后才开始旧解锁；所有拒绝路径仍清理输入因素。Android 旧策略的阻塞工作队列测试实际失败，修复后 JVM 策略测试通过；两端集成和最终平台验收仍在继续。

主代理对冻结的生产 `locklark-team-sync` 命令做独立 PTY+TLS 验收，完整通过：prompt 可见时 ECHO/ICANON 已关闭、立即粘贴合法 seed 无回显、服务就绪前恢复原终端状态、真实 pinned owner 通过生产 TLS 服务读取、错误 seed/短输入/Ctrl-C 拒绝、等待输入时 SIGTERM/SIGHUP 恢复终端、无控制终端与 argv seed 拒绝、完整输出私钥 canary 零命中。私有证据 `team-cli-parent-y52x80gm/result.json`，独立构建二进制 SHA256 `155d15a686f4c600e73d57db12f4e56a4ce0c6dafc116a000fdf834d63ddc3f4`；23项产品/依赖清单 `team-sync-cli-core-candidate1.sha256` 前后通过，清单 SHA256 `e557d5c03d6b8fafd72467cd26e2b3c747c61afd510ced69f1a1127c20df9b1e`。Luna 独立复核当前 CLI 无剩余阻塞，并重跑完整终端恢复测试通过。

全仓正常回归使用 Go1.27.3、Bun1.4.4、PyKeePass4.2.0，`go test -p 1 -count=1 ./... -timeout=20m` 35个包状态通过，日志 `team-mobile-full-go.log`。该轮核心编译早于第二轮修复，不冒充最终冻结源码的全仓结果。草稿 PR [#37](https://github.com/jihuayu/locklark/pull/37) 在 `0094325` 的 Linux、Windows、macOS 桌面和 Web 四组 CI 通过；Android 构建通过但运行验收在 complete-test-count 失败，iOS 在模拟器选择失败。两项移动 CI 失败都须修复后在新精确提交重跑，未满足合并条件。

## 原生排队调用与核心第三轮绑定

主代理进一步指出“原生前置检查通过→切后台 RequestLock→旧闭包才调用 Go”的窗口。三项旧行为实际失败：后台创建仍生成数据库、旧解锁采用新代次、旧编辑使用新会话。`mobile-captured-view-red.log` 保留这些失败。核心现在由共享状态和不可续新的绑定视图组成：UI 入队前调用 CaptureOperation，工作闭包只用该视图；核心取得串行锁后仍检查绑定代次，旧视图不能重新捕获新代次。生命周期继续使用基础 Vault。界面还须等待排队锁清理完成，再接受新的用户操作，避免合法新请求被旧清理再次撤销。

主代理独立运行9项 OTP/排队/绑定视图测试各两次，逐项 RUN 记录在 `mobile-core-parent-v3-focused.log`（9.534s），另对锁清理期间新视图测试两次（1.359s，`mobile-core-parent-v3-cleanup.log`）。Luna 最初两条带末尾 `$` 的表达式漏选了名称带后缀的新视图测试，已明确撤回该覆盖声明；随后使用正确前缀并逐项核对，5项 Capture/FreshCapture 及10项合并定向测试均通过。核心完整 normal 11.034s、完整 race 109.560s，通过；全仓 vet 与模块校验通过。

第三轮固定 AAR 在 `/tmp/locklark-tools/mobile/core-final-v3/`，SHA256 `edc91ce26a07a83d381be8e2428a404bec1ce6224e8dca177324bae6ef859593`。清单 SHA256 `0c2eaffab9a9e12d1570613feec3acbe53f50fabd3a1322fc6c2aaa59976ca76`，88项传递输入及工具前后完全一致。第一轮和第二轮绑定及其日志保留为历史证据。

PR #37 第二轮 `4f35ec5` 的四组既有 CI 再次通过；Android 实际运行在 create 阶段180秒条件等待失败（固定诊断 AssertionError，非进程崩溃）；iOS 真实应用 SDK 编译无报错、模拟器开始测试，但运行报告3条失败记录，旧安全摘要未提供用例标识，不能据此推断3个不同根因。后续迭代增加固定用例/源码行诊断；Android 两套独立流程即使一套失败也执行另一套，任一失败仍拒绝通过。

Android 外部主机工具11项测试通过，Luna独立审阅并运行；实际 UI、签名审计和 PyKeePass 核对仍等待可运行模拟器。iOS UI 工具新增独立 HMAC-SHA1 OTP 比对、测试 runner 私有因素清单，以及在成功/失败两条路径扫描完整 runtime 和 xcresult 导出；主代理独立运行10项隐私/完整性测试与5项诊断隐私测试均通过，真实 SDK/工具兼容性仍待下一 CI。二进制附件只做字节扫描，不声称对截图像素 OCR；原始材料不上传。

## 原生平台兼容性定位

第三轮 `8c56540` 的四组既有 CI 全部通过。Android 两套独立实际 UI 流程都在创建阶段失败：准确因素输入已核对，应用报告操作拒绝而非点击不到或等待时间不足。iOS 的三条失败定位为两个 VaultFiles.protect 调用（均早于 Go 建库）和后续 UI 输入不可用。失败轮均不计为验收成功。

Android 本地原生诊断确认 shell UID 的同目录硬链接返回 EACCES；同时核对 AOSP app_neverallows.te 明确禁止所有 untrusted app 建立硬链接。旧个人库发布使用 os.Link，与 Android 应用策略不兼容。修复仅更换 Android 路径为内核 renameat2(RENAME_NOREPLACE)：仍先 fsync/关闭完整临时文件、原子拒绝覆盖、再 fsync 目录，内核/文件系统不支持时失败，不使用覆盖式 rename 或空占位回退。四项回归覆盖已有目标不变、并发恰好一个完整赢家、目录同步失败保留完整结果、ENOSYS 无回退；同一 Go 测试二进制已在真实 Android 模拟器内核上以 shell UID 执行通过。主代理独立跑四项 race 各三次（1.071s），Luna独立测试及 Android 交叉编译通过。shell UID 结果不冒充应用 UID/JNI 或完整 UI 验收；旧 AAR 的实际应用 UID 失败验证与新绑定的应用流程仍在继续。app_process 诊断没有完成 JNI 阶段，不计成功。

iOS Foundation 保护值的公开接口允许 NSString/String；直接 as? FileProtectionType 不能覆盖该表示。初步兼容修复严格接受 typed complete 或完全相同的 rawValue，仍拒绝缺失、较弱类型和近似字符串，无模拟器豁免。Luna 使用已安装 Linux Swift6.4.2 独立跑30项纯逻辑测试通过，其中包含三项表示形式测试。此测试不证明实际失败由字符串表示造成；后续原生诊断实际读到属性缺失，见当前状态，不能把该兼容修复当作已关闭平台问题。

主代理还发现 Android AtomicFile 首次 startWrite 写入的是 .new，而旧代码 chmod 最终路径会因不存在失败。现在先 fchmod 实际文件描述符至0600，写完后核对提交文件权限和大小；应用测试验证真实首次写入和复读。显示期限同时核对原墙钟范围与不延长的单调预算，系统时间变化广播保留为额外保护。Luna 独立运行10项 Android 策略测试通过；新平台组件运行证据仍待收齐。

Android 发布兼容性修复后的第四轮 AAR：`f306122940008c1e81bc45f91112fff32771d036d5120328fd08cf7196a3cd8f`，保留于 `/tmp/locklark-tools/mobile/core-final-v4/`。清单 SHA256 `45556f2cfce45630a6e956c115a49e048424187c6e28af1d5ba01c4eb93b99a7`；主代理独立核对89项实际输入与产物散列，零不一致。该绑定包含 Android 专用发布路径；第三轮绑定继续保留，用于实际应用 UID 的旧行为对照。
