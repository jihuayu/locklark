# 浏览器逐次原生批准的验证码填充

基线 main `4f37d8ccd9499b6a3e292709e7d567747a8ada7a`，分支 `codex/browser-native-otp`。前批桌面 [PR #28](https://github.com/jihuayu/locklark/pull/28) 已经主代理独立GUI、Luna/max及精确head `85b400ff328525572fdc98d9855b011613b9b2bd` 的四项 [CI 42120014509](https://github.com/jihuayu/locklark/actions/runs/42120014509) 合入。主代理负责架构、功能设计及验收，Sol xhigh实现，Luna max独立审阅。本文记录本批实现契约，实际验收与合并状态见 [验收记录](browser-otp-validation.md)。

## 用户流程与边界

用户在当前HTTPS网站打开扩展，选择活动登录，显式点击“填充验证码”。独立MyGo窗口显示网站、条目及固定修订供批准；只有原生批准及最后页面复核完成后才读配置并生成码。沿用既有原生解锁/配对，种子、otpauth URI和码不进入Next.js、普通Agent、popup展示或持久日志。不后台自动取码，不自动提交表单，不在窗口过期后自动重取下一期。

仅支持顶层页面中唯一、可见、可写的 `input[autocomplete=one-time-code]`，必须属于明确同源form，其action及所有关联submitter均同源。分格、多框、iframe、隐藏/只读字段、歧义或来源变化明确拒绝。原documentId、活动window/tab和canonical HTTPS origin在探测及赋值前复核。登录必须active且revision精确；无配置/无效配置由原生固定拒绝。不宣称覆盖Safari、移动填充、Passkey或所有复杂站点。

## 独立wire契约

保留v1严格键集、大小边界和重放防护；新OTP与已有fill/save互斥，不能复用保存或普通字段的审计/取消用途。每个被接受的逻辑请求只领取一次终态回复；非法重放不得重新准备、授权或发送码。

同一连接内重复消息ID静默忽略，不再为该ID追加error终态，也不重新执行、取消或关闭连接；跨消息类型复用ID也不能绕过。全部消息仍计入128条总预算，畸形协议或预算耗尽仍关闭。这同时保留既有保存契约：旧commit/cancel的重复消息不能借断连撤销新待办。正常客户端的每个新动作使用新ID。

| 请求 | 必需元数据 | 成功响应 |
| --- | --- | --- |
| `otp`（原ID O） | capability、window_id、origin、tab_id、document_id、item_id、revision | 原生批准后 `otp-ready`，ID为O，64位hex随机nonce，无值 |
| `otp-ack`（新ID A） | capability、request_id=O、nonce | `otp-fill`，ID为A，只含独立code字段 |
| `cancel-otp`（新ID C） | capability、request_id=O | 依取消仲裁为cancelled、unknown或固定refused |

O禁止payload/request_id/nonce；A/C不得重带任意context或字段值，C禁止nonce。目标/HMAC始终绑定O的完整context，ack不能重绑定。code只允许受信配置支持的6或8位ASCII数字；其他响应禁止code，OTP响应禁止username/password/candidates。DTO格式化、错误和非值消息不暴露码；只有最终授权的专用编码路径可序列化它。

扩展的pending OTP必须独立于通用RPC promise map。otp-ready是O消息的唯一终态响应，但不是整个OTP操作的终态；control继续等待A/C。O收到otp-ready后仍保留原请求ID、页面context及操作代次，导航、断连、锁库或超时才能定向取消O。旧cancel/cancel-save不得命中OTP；会话锁定及连接失效仍撤销本连接全部待办。初始原生批准等待有界，challenge仅3秒，nonce一次消费。

## 原生意图、取消与交付

增加独立动作 `item.browser.fill.otp-code`，用独立用途HMAC绑定window/origin/tab/document/request/item/revision/profileVersion。事务认证slot、snapshot、完整history及active/login/精确修订/来源，意图成功提交且Close成功后才计算一次码，立即清OTP配置。失败不发送值；意图不证明交付或网站接受。

O进入pending即创建无值 `BrowserOTPControl`。`PrepareBrowserOTP(target,intentGate,control)` 在读取配置/准备码之前原子登记原control，早到Cancel必须阻止慢worker继续准备；`AuthorizeBrowserOTP(prepared)` 继承它，完整只读认证当前历史、快照、active/login/id/revision/origin并成功Close。磁盘阶段的码holder始终登记且可取消，不能先取走码再做阻塞复验。

`GrantBrowserOTP(delivery)`只能使用已经绑定的control；writer先取得有界串行输出槽，再与RequestLock/取消在短锁内仲裁，复核原窗口/会话/单次状态后转移writer独占可变缓冲。不能临到Grant才新建send gate，也不能替换被取消的control。intent CommitWon与output grant分开；前者不是“值已送出”。所有Session/Connection/control短锁均不跨磁盘、writer等待或pipe I/O，等待槽时不在holder之外预先复制JSON/string码。所有终态清理可变缓冲，不承诺框架/OS不可变副本的物理擦除。

OTP holder沿用全Session有界上限和桌面已建立的时钟/清理契约，保持用途隔离与单次消费。类型、格式化、跨Session/跨用途、重复/并发交付均须负测。历史认证动作规则、备份/恢复重读和拒绝审计必须兼容现有可信历史，不能通过减少验证实现复用。

## 取消与回复竞速

“otp-ready已发”指短状态锁内已领取其发送权，不代表pipe已经写完。实际写入在锁外。

- challenge发送权未领取，Cancel先赢：O固定error/refused，C cancelled；之后不得再发O的challenge。
- O已领取challenge发送权、A未登记时Cancel先赢：不再为O另发回复，C cancelled。无值challenge可能随后到达；control已撤销，迟到A只能固定refused，不能重开Prepare。
- A已登记而output grant尚未赢时Cancel先赢：A固定error/refused，C cancelled；worker迟到结果不得再发A的值或第二个终态。意图可能已记录，不声称没有审计。
- output grant先赢：不得报告确定cancelled。A最多一个获准的值回复；无法确认的写入/断线由本地状态与连接结果表示unknown，不能追加第二个A unknown帧。C只可unknown。

自动验证拒绝、自然过期或无grant自然完成的操作收到迟到C，固定not-pending/refused；原生明确点击“拒绝填充验证码”属于用户显式撤销，可记为已取消，迟到C可返回cancelled。已取消、已自然终止、已grant的retired状态分开且有界，旧请求不得影响新操作。输出/取消回复丢失均不自动重发。回复终态的领取和实际writer I/O分开，不能持连接锁等待输出。

扩展本地另外记录是否已发送ACK、是否已经调用页面注入。已经开始注入时，取消不能撤回浏览器可能完成的赋值，即使主机返回cancelled，也不能声称页面未填。ACK后没有确定拒绝或取消的断线、超时、锁定保留“验证码填充结果未确认”；清理连接、重新配对本身不消除此结果。用户仍可主动开始新的O并重新原生批准，迟到取消回执仍更新旧OTP的未确认事实，但只有取消视图仍属于原操作且没有新的fill/save/OTP待办时才更新展示状态，不能覆盖新保存或填充的进度。不自动重发，也不为此增加永久阻断或额外审批步骤。

## 页面期限与最终输出

固定浏览器预算B=1500ms，从ack前的最终同document探测开始。isolated world返回本页timeOrigin、performance.now和Date.now，无输入值；background另记自身单调起点。静态赋值函数核原timeOrigin及本页probeNow+B，background以自己的t0+B约束ack→reply→inject；收到码不能重开预算，不能比较不同context的performance坐标。Date.now只能提供额外拒绝（回拨或超过原wall预算），绝不续期；这也覆盖单调钟暂停而墙钟前进的恢复情形。OS/浏览器调度不是硬实时保证。

host在实际取码时要求原码窗口剩余至少B+100ms，最终grant再核双时钟和短cap；不足则明确拒绝，不等待下一期。慢磁盘、管道或注入只消耗已有预算。原生授权快照与随后网页状态并非物理原子；显式批准的网页本身能观察被填入的码。

建议单个静态 `otpDocument` 函数用probe/fill两个固定模式，共用唯一目标/form来源策略，防止两份校验漂移。probe不返回输入内容；fill只收固定origin、码及原probe期限，紧邻赋值前再次检查，不接受任意selector/脚本。值只在background短期局部变量及本次注入参数中存在，不发送到popup、storage、console或页面桥。

writer输出期限取1秒、原OTP窗口及cap单调剩余的最小值。生产RunBrowser的整个Writer（含握手、错误及旧fill/save帧）注入不可返回的fatal callback（固定exit74），防止其他帧永久占用OTP需要的输出槽；watchdog到期先标terminal，直接退出该host，不等Close、不取状态锁、不打印值或重试。只调用out.Close不足以打断继承的blocking stdout；普通桌面/注册CLI不使用该fatal工厂。os.Exit不运行defer，不能宣称defer已擦除，进程退出也不是硬实时。

## 失败先行与独立验收

先保留新协议/core/DOM缺失的red，再验证成功、严格键集/值隔离、用途HMAC、旧修订/来源/状态、nonce和消息ID重放、取消/锁/慢worker、事务/Close故障、双时钟与短窗口、输出槽及grant/pipe边界。测试一端真正不读stdout的子进程，子必须由自己的watchdog以74退出，父context仅失败兜底；helper仅在_test程序，不增加产品跳过授权入口。

真实Chrome/Firefox：受控HTTPS单框页面→扩展→MyGo批准→独立Python HMAC核码和审计重开；拒绝/导航/旧document/iframe/歧义/表单来源变动/原窗口耗尽均无值。controller、浏览器/host日志、诊断和故障输出完整canary扫描；旧fill/save及Next.js回归保留。主代理独立两引擎验收、Luna review、精确head CI均通过后再合入。

文件分工：Sol implementation拥有personal/core、browserhost/Writer及原生批准UI和对应Go测试；Sol CI拥有extension JS/Node tests、外部DOM/真实浏览器工具、fixtures和CI。共享wire契约由本文约束；跨域修改先协调，不覆盖彼此文件。主代理拥有本文、验收记录、README/progress及独立验收/PR合并。
