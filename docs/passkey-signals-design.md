# WebAuthn 信号与本地原生确认

#39 的 Signal APIs 增量。主代理设计原生确认、原子修改和不披露结果的边界，外部 DeepSeek workers 实现扩展、personal/native 与独立复核。依据 W3C WebAuthn Level 3 的 signalUnknownCredential、signalAllAcceptedCredentials、signalCurrentUserDetails；authenticator 可忽略提示或先要求用户同意。

## 网页结果与本地修改分离

仅包装浏览器已经实现的三个静态方法，缺失方法保持缺失，不虚报 getClientCapabilities。先以原 this/原参数调用浏览器，再返回同一个原始 Promise；原成功值、同步异常和拒绝不变。同步捕获有界 RP 参数，只有浏览器原调用 fulfilled 后才发提示；本地能力/查库/用户确认/写盘均不延迟或改变该 Promise。不存在账户列表、凭据存在性、处理数量或提交结果回传页面。

MAIN 提示仅含 source/id/options，都是 RP 自己提供的数据；isolated 检查同窗口、同 origin、顶层安全可见文档、精确字段和大小后 fire-and-forget 给 background，不发页面回执。background 从真实 sender 和重新捕获的活动 tab/document/origin 构造 native 上下文；要求已有连接、当前 capability、passkey-signal-v1 和启用使用 Passkey，异步检查后再验证 epoch/能力/设置。弹窗、外部扩展或调用者自带 origin/selectors 不可调用；不占用或覆盖填充/OTP/Passkey/条件式槽位。

## Native 接受与原生审阅

passkey-signal 的 options 是严格的 kind + 对应标准字段；最多 32 KiB，accepted IDs 最多 64，credential ID 为 canonical base64url 的 1–1024 字节，user ID 为 1–64 字节，名字受 UTF-8 大小/控制字符约束。RP 使用实际 origin 与同一 full PSL 规则，禁止 sibling/private-suffix 越权。

先发送精确 passkey-signal-accepted {v,id,type}，再异步只读查库；已有原生操作时接受后忽略，不抢占。ACK 不等于本地已提交，也不返回存在性。审阅不追加审计、不改快照、不续 idle、不登记 MutationGate；每连接最多一个、期限不超过两分钟及现有 capability。超过 50 个受影响账户时整个建议忽略，不截断部分删除。

只匹配 active login 的 RP/credential ID 或精确 RP/user ID。unknown 提议移除该 CID；accepted 仅提议移除该用户未在接受列表中的 CID；user 仅提议更新该用户已有凭据的 Name/DisplayName。stored userHandle、原记录、私钥不进入 DTO。native 显示网站/RP、账户及更名或移除影响，必须由用户确认；信号本身不授予 UV。技术修订/完整 ID 不占据普通确认界面。

## 原子修改与取消

只在用户确认后登记单一 mutation slot；一次认证 bbolt 事务内重新核对全部被审阅的 item/revision/活动状态/RP/CID/UserID 和信号语义。特别是 accepted 的明确保留 CID 不能被伪造 proposal 移除。任一行过时则整批不改。只清 Passkey 或重写 Record.Name/DisplayName；保留登录字段、其他私密字段、CID/UserID/私钥和存储格式。新分配的原记录副本及含私钥的 JSON 在加密使用后清零。

每个变更在同一事务内 seal/appendLinked，维护正确 tip/修订链，新的已知 action item.passkey.signal 支持完整历史和尾部回放；HMAC 绑定原信号/审阅 selectors，审计不存原参数。移除在 commit decision 赢后保守推进 session Passkey revocation epoch，使其他连接排队签名失效。

gate 以 atomic.Pointer 发布，锁定/拒绝/期限可立即取消；登记前后均复查取消，数据库等待后取消先赢不得写。原生工作中也有不受 App.busy 准入阻拦的取消入口，不承诺追回已提交修改。提交先赢后撤销或关闭失败只在 native 呈现 UNKNOWN，网页永远不收到第二个结果帧。锁库/换 Session/关闭/期限清除过时 proposal。

## 验证范围

Go 真实持久化契约、Node VM 桥接契约、软件签名 RP 验证与真实浏览器原生确认分别列证。全部 50/51 边界使用真实有效条目，不修改生产限制；不新增只供测试的产品钩子。支持的浏览器实际原 API 能力决定包装范围，Firefox 缺失的方法不能冒充支持。此增量不代表跨设备凭据同步、硬件 UV 或完整独立密码审计。
