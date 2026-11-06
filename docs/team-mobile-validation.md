# 团队同步与原生移动端验收

基线 main `9d8d57475f3fb904fc9fe4bedc0c1e6b4ce07535`，工作分支 `codex/team-mobile-sync`。主代理负责[架构](team-mobile-design.md)及独立验收，Sol xhigh 分工实现与工具，Luna max 独立审阅。以下只记录已实际完成的范围；平台和最终 CI 待办不计为成功。

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

服务命令隐藏终端与平台权限验收、冻结后的最终审阅、完整 Go/移动构建与模拟器、精确提交 CI 和正常 PR 合并仍须继续。完整团队邀请/草稿与冲突 UI、移动团队配对、原生系统填充、Passkey、远程审批、附件/历史和系统钥匙真机验收仍是持续范围；本记录不宣称整个团队或移动产品完成。

## 提前草稿 CI

全仓编译探针 `go test ./... -run '^$' -timeout=5m` 通过（不计作测试运行），当前 main 核对仍为 `9d8d574`。准备草稿 PR 以获得 Linux 无法提供的真实 Apple SDK/模拟器，以及有硬件加速的 Android CI；这早于完整平台验收和最终审阅。所有待办在最终精确提交通过前均保留，不据草稿编译认定可合并。

## 第二轮复核与独立服务命令验收

Luna 复核和确定性测试发现：OTP 原生交付后到门面最终授权之间的同周期回拨未再次校验；外露 From 仍为周期起点；旧解锁/修改可在等待串行锁时越过 RequestLock 使用新会话；Lock 等待期间被另一解锁超越后可能返回未锁定。旧行为五项实际失败记录在 `mobile-otp-grant-red.log` 和 `mobile-queued-lifecycle-red.log`。修复为复制原 OTPBounds 并在最终短授权再次 Check、From 使用最新成功授权时间、进入队列前捕获会话代次并在获取工作锁后复核、Lock 持工作锁后二次失效。当前五项通过（2.944s），核心整包 normal 通过（10.212s），最终 race/绑定和两端运行仍待完成。第一轮 AAR 现在是历史候选，不能代表这些新增修复。

两端工作队列还须在真正开始 Go/系统操作前检查线程安全的取消凭证，避免切后台之后才开始旧解锁；所有拒绝路径仍清理输入因素。Android 旧策略的阻塞工作队列测试实际失败，修复后 JVM 策略测试通过；两端集成和最终平台验收仍在继续。

主代理对冻结的生产 `locklark-team-sync` 命令做独立 PTY+TLS 验收，完整通过：prompt 可见时 ECHO/ICANON 已关闭、立即粘贴合法 seed 无回显、服务就绪前恢复原终端状态、真实 pinned owner 通过生产 TLS 服务读取、错误 seed/短输入/Ctrl-C 拒绝、等待输入时 SIGTERM/SIGHUP 恢复终端、无控制终端与 argv seed 拒绝、完整输出私钥 canary 零命中。私有证据 `team-cli-parent-y52x80gm/result.json`，独立构建二进制 SHA256 `155d15a686f4c600e73d57db12f4e56a4ce0c6dafc116a000fdf834d63ddc3f4`；23项产品/依赖清单 `team-sync-cli-core-candidate1.sha256` 前后通过，清单 SHA256 `e557d5c03d6b8fafd72467cd26e2b3c747c61afd510ced69f1a1127c20df9b1e`。Luna 独立复核当前 CLI 无剩余阻塞，并重跑完整终端恢复测试通过。

全仓正常回归使用 Go1.27.3、Bun1.4.4、PyKeePass4.2.0，`go test -p 1 -count=1 ./... -timeout=20m` 35个包状态通过，日志 `team-mobile-full-go.log`。该轮核心编译早于第二轮修复，不冒充最终冻结源码的全仓结果。草稿 PR [#37](https://github.com/jihuayu/locklark/pull/37) 在 `0094325` 的 Linux、Windows、macOS 桌面和 Web 四组 CI 通过；Android 构建通过但运行验收在 complete-test-count 失败，iOS 在模拟器选择失败。两项移动 CI 失败都须修复后在新精确提交重跑，未满足合并条件。
