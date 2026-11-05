# MyGo 日常密码生成与 TOTP：架构约定

基线 main `c9d4a5d284ddc15aa58953896e9b5773873bb1e6`，分支 `codex/desktop-daily-tools`。前一浏览器保存/更新 [PR #27](https://github.com/jihuayu/locklark/pull/27) 经 Luna/max、主代理独立两浏览器验收及精确 head `8d63fd6` 的四项 CI（run `42089993817`）合入。本批仍由主代理设计/验收、Sol xhigh 实现、Luna max review；设计草案已经预审，本文不是实现完成声明。

## 用户流程

新建登录增加可选网站，一次事务保存网站和登录字段。用户可输入密码保存，也可选择“生成强密码并保存”；不以 Add 后 Edit URL 拼接。沿用密码核心的默认24字符、62字母数字字符表，长度22–256且必须通过最低128位组合熵校验。本批不改变历史Profile或加入符号预设。生成值直接保存，只返回ID/修订/公开策略；查看和复制仍是随后独立授权动作，不自动披露。

已有登录提供“重新生成本地密码”，先进入独立确认视图，展示固定目标标题、网站、状态、ID及修订；明确只修改本地金库，不会替用户修改网站密码。确认时使用进入确认页的revision，过时目标拒绝，保留其他字段。活动和归档登录允许，回收站拒绝，与既有CLI保持一致。成功收据与列表刷新分开：刷新失败不能将已保存说成未保存，更不能自动重新生成。

唯一“新建登录”入口放在搜索工具栏，移除原详情底部同名按钮；OTP/重新生成放在详情上部，确认页单独呈现。保留现有Scroll容器适配小窗口，不让常用操作被新增编辑内容挤到页面底部。切换到新建也适用OTP/本程序剪贴板和待交付清理规则。

确认页网站通过窄ReviewNativeLogin只读认证接口取得，仅返回固定ID/修订及title/URL/state元数据；不改变全局Row或浏览器DTO，不返回完整Item或秘密字段。确认视图显示外部字符串时保留控制字符转义。此元数据预览不增加另一条mutation，实际生成仍再次在事务内核验目标。

登录详情提供“显示验证码”和“复制验证码”；未配置OTP时明确拒绝。每次有效显式操作产生一条意图后计算本次码，不自动持续取码；到期须用户重新操作。显示最长15秒，剪贴板最长30秒，均不能跨过该码原始有效窗口。切换条目/页面、观察到修订变化、锁库/锁屏/睡眠/关闭时清除显示与本程序仍拥有的剪贴板。仍提示系统剪贴板历史无法由本程序保证擦除。本批原生生成和取码不通过Next.js或扩展传值，种子/otpauth URI/密码/验证码不进入普通Agent输出或日志；既有独立浏览器批准填充协议不因此改变。

已显式授权显示的字段/验证码应可被正常辅助技术读取。使用有名称的可访问Group包裹实际静态Text子节点，不给Text本身覆盖Label导致读屏只读到标签。两个独立组名为“已授权显示的字段”和“已授权显示的验证码”；仅显示有效期间存在，隐藏/到期/锁库移除整组。外部有限验收reader只能在匹配进程窗口的这两唯一组内读取静态子文本，不读解锁/编辑输入，不输出原值；这是正常无障碍语义，不是产品测试接口。

## 原生事务与取消

抽取中性 MutationGate，可以保留 BrowserSaveGate 兼容别名/包装，不能改变已验收的浏览器行为。Session只允许一个已注册的mutation；注册、RequestLock和写入前仲裁共用短锁，不在短锁下等待磁盘或管道。新原生手工新建、生成、重新生成及OTP意图使用窄API，不暴露任意命令入口。手工字段的可变缓冲由入口接管并在所有路径清理；不可变string/系统复制无法据此宣称物理擦除。

保留 `item.generate`、`item.regenerate.password` 和公开Profile历史契约；不借用 `item.browser.*` 审计。事务内认证slot/snapshot/history，校验字段/URL/容量或目标revision/state及策略后再调用CSPRNG，首次持久变更前争gate。成功与已认证业务拒绝都原子审计；取消先赢则包括拒绝审计在内均不写。提交赢只表示开始持久化尝试；commit/close错误或收据丢失为unknown，不能误报明确未保存。`executeActive` 的晚active检查不能把unknown降成locked。

UI必须在启动worker前持有无秘密operation token/gate。Lock先Cancel再判断CommitWon；已提交但尚未dispatch的结果仍保留unknown提示，不能因worker释放Session注册或普通run丢弃晚回调而漏报。只有UI接纳已知收据/拒绝后才ack清token。同一App实例内unknown跨锁库保留，不自动重试；进程退出后未另建持久receipt日志，不承诺重启仍显示上一提示，重新打开只核实库内容。

旧桌面编辑/lifecycle尚未全部迁到同一仲裁，本批不隐含宣称已经统一，后续另列。当前范围的新生成/手工新建必须获得完整语义，不能为了兼容旧API而降低。

## TOTP 意图、复验与单次交付

独立 `item.desktop.show.otp-code` / `item.desktop.copy.otp-code` 动作，与旧CLI动作并存。不可直接加到默认取username的 `readValueAction`；store、journal/history/Event.verify及备份恢复单列固定动作/result/base-revision规则，意图不改变条目修订，不含码或种子。

分三个窄阶段：

1. PrepareOTP在worker认证并持久化show/copy意图，事务和DB close成功后采样计算一次码，立即Clear OTP配置。返回私有NativeOTP cap，仅持码bytes、精确ID/revision、窗口、wall样本和monotonic截止，不含seed/config。
2. AuthorizeOTP/ConsumeOTP在worker只读复验当前slot/snapshot签名、完整history、精确ID/revision、login类型和活动/归档状态，再关闭DB。消费prepared cap并产生短时NativeOTPDelivery；失败清cap，保留原意图，不自动重新Prepare。必须通过第二Session在两阶段之间修改OTP/URL/password或移入回收站的拒绝测试。不得调用会追加item.list审计的List；提取既有私有认证逻辑共用，不复制削减验证的解析器。
3. DeliverOTP只在UI线程执行，无磁盘I/O：核对会话锁/代次、当前页面和选中ID/revision、单次归属和双时钟，然后同步回调显示/复制。回调不重入Session；worker不读取可变UI字段。cap转移后旧cap不能重放，两个阶段合计最多8个pending，lock/cancel/expiry/drop清可变码。

最后时钟核验之后，交付grant必须与RequestLock在同一saveMu短锁下仲裁，确认lockRequested/cancelled/idle及单次状态后标记开始；不得在短锁内调用可能再次加同一锁的active/lock流程，也不跨UI callback持短锁。锁先赢时零交付；grant先赢后锁无法撤回已经开始的本次披露。callback panic不吞掉，但锁作用域须保证先Unlock cap再运行外层clear，不能因清理再次锁同一mutex而死锁；panic也清码/注册并释放Session锁。

只读认证快照是最后授权观察点，其后外部提交与GUI显示不保证物理原子，已显示码也无法撤回。不持跨进程DB锁等待UI，不以TTL代替持久库复验。prepared cap最长10秒，最后复验到UI交付最长2秒，同时受原码窗口约束；过期固定拒绝，重取需要用户再次操作。

每次Prepare/复验/交付核对wall时钟不早于前次样本且位于 `[from,until)`；同时使用保留monotonic信息的期限。显示和剪贴板分别保存窗口与最近wall样本，任意回拨、窗口或monotonic到期即清。OTP专属展示状态保留窗口约束；定时器只清理，不逐秒取码/写审计，不自动下一期。

## v4 剪贴板所有权设计（待实现验收）

v3的“读当前内容并比较hash”清理在真实Linux GUI中阻塞了Lock的帧提交；独立显示进程仍可复现，不能靠测试预读消除此缺陷。v4替换为窄原生适配 `Write([]byte) → opaque Lease,error`、`ClearOwned(Lease) → Cleared/Superseded/Unavailable`，不提供读取外部剪贴板内容的API。MyGo继续负责UI，不修改其模块缓存。所有权凭证不含原值，每次新写入独立建lease，即使文本相同也不能被旧timer清除。写失败不能显示复制成功。若系统已接收文本但后续凭证确认失败，必须证明自有数据已撤销/被替换，或返回可清理的opaque lease及“结果未确认”；不能丢清理资格、宣称确定未复制或自动重试。

锁库入口先取消mutation、请求Session锁定并撤销UI会话/代次及曝光状态，再撤销自有provider和系统所有权；完整Session清理仍放worker。清理不等待别的应用提供文本。操作系统或显示服务器本身失去响应不在实时保证内。暂时不可用时仅保留一个opaque待清lease，每秒重试元数据清理；新写入期间旧期限保持有效，返回后若本次验证码已过期，必须区分仍在的旧metadata与真正重入的新复制，不能因旧metadata存在而丢掉本次部分写入的清理资格。不积累秘密队列，不自动重试披露。新成功写入替代旧lease；失败状态不能显示“已清理”。provider失效时清可变缓冲，但不能承诺OS历史或框架不可变副本被物理擦除。

正常新复制直接由Write替换旧provider，不先撤销系统selection，以免制造迟到SelectionClear。写入前复核UI代次、曝光代次、精确目标及剪贴板新写入代次；OTP另复核原始双时钟bounds，不能续期。新写入失败才条件清理旧lease，并保留不可用时的清理资格。清理和锁库不伪装为新复制；只有真正的新写入递增ownership代次。已排队旧timer或迟到回调不得清掉或重新写回后来的复制内容。

Linux/X11保留GTK provider处理Unicode和大值协议，每次写入使用唯一GObject token。成功后只在token一致且 `gdk_selection_owner_get_for_display` 映射到本display的真实本地GdkWindow时绑定owner XID，不能认领foreign所有权。清理先失效旧provider，再在极短 `XGrabServer` 临界区内核对真实当前XID，匹配才撤销selection，所有路径保证ungrab/flush；临界区不执行GTK、回调、时间查询或文本请求，解除后不再调用无条件GTK Clear。主代理和Luna核对GTK 3.24.38完整调用链：每次set_contents均更新GDK OwnerInfo的NextRequest序号，SelectionClear在转为GTK事件前按窗口及序号过滤；旧事件不会清掉后来的新provider。因此不新增自定义事件filter或等待callback的写入屏障，仍须真实快速重写验收。非X11暂明确拒绝安全复制，保留显示功能；Wayland仍列待完成，不用hash/read降级冒称支持。

Windows以自有message-only HWND持有eager UTF16文本和固定私有格式的随机nonce。写入与所有权捕获在同一次 `OpenClipboard` 内完成；清理同样在系统锁内核对自有HWND和精确lease/nonce后才清空。不读取foreign文本，忙时立即返回不可用；成功写入以nonce为凭证，不把同owner添加格式造成的序号变化当作新owner。部分写入尚无nonce且序号变动时保留未知清理状态，不宣称确定被替换。不为每次复制注册全局格式名。需要验证内存分配/转交失败、同值新copy及锁争用。

macOS以 `declareTypes:owner:` 返回的原始changeCount绑定lease，提供文本后仍须确认原count有效，不能把后来读取的foreign count认领为自己的lease。清理仅比较元数据，不调用 `dataForType`。公开pasteboard API的比较与清除不是跨进程原子操作，因此保留同时发生新复制时的竞态边界，不宣称CAS保证。

## 实现与独立验收

先保存核心契约和真实MyGo缺入口的失败证据，再实现并覆盖：原子新建URL、精确修订和状态、其他字段保留、RNG/commit/close故障、cancel/lock/dispatch竞态、审计及恢复重读；OTP两阶段持久复验、单次cap/串用/上限、窗口/回拨/monotonic、锁/改选/drop；值/种子/码的格式化和日志扫描。

真实GUI使用私有DBus、隔离X11显示和合成加密库，通过AT-SPI标签/XTest输入，无产品审批开关。生成后在外部进程私下验证长度/字符表、真实显示或剪贴板；OTP与独立Python HMAC比较，仅输出固定阶段/布尔结果。含密码或码的显示阶段不截图；允许截图无秘密生成确认视图。验证到期清空、锁定清空及后来用户复制内容不被清除。Linux CI增加同样原生验收；Windows/macOS继续真实构建和相应测试，不代替Hello/Touch ID/Secret Service真机验证。

复用原生外部工具时一并处理Luna前批非阻塞维护项：AT-SPI snapshot已ref窗口后遇query异常，也释放所有已保留引用，补纯工具测试。不得因此扩大产品权限或改变真实点击方式。

本批完成后继续完整迁移、桌面其余日常功能、团队远端同步、移动/Safari/Passkey和签名发布等既定范围；不将这一切片视为全部1Password能力完成。
