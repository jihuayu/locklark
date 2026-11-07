# 条件式 Passkey 账户选择

对应 issue #39 的条件式建议子项。主代理负责协议和授权边界，外部 DeepSeek workers 分别实现 native/personal、扩展端及独立只读复核；真实浏览器由主代理独立验收。此增量不代表完整参考产品对照或整个 #39 完成。

## 请求与选择

网页调用标准 `navigator.credentials.get({mediation: "conditional", publicKey, signal})`。MAIN 与 isolated 的限时能力握手只返回布尔值；必须忽略 MAIN 自己收到的查询回声。老 host/关闭设置回退浏览器自己的实现。保留原生 `isConditionalMediationAvailable` 与 `getClientCapabilities` 的结果，并合并本扩展确实支持的 conditionalGet。条件请求忽略 RP timeout，等待显式选择、AbortSignal、页面离开或扩展断连/锁定。普通非条件式调用保持原有期限。

isolated 只在可见、可写、非密码、非忽略的 `autocomplete` 含 `webauthn` 输入框获得真实焦点时展示 closed-shadow 账户面板。账户列表不进入 MAIN 消息或普通页面 DOM。焦点离开、异步查询落后、页面不可见、导航、取消、断连和锁库均不能让旧面板复活。网站可以请求建议，不能替用户选择账户或直接批准 native 操作。

background 从实际 runtime sender 取得 origin/tab/document，不信任页面传入的上下文。每个 document 只有一个有界 intent，总量上限 64；固定保存原始 challenge/options，单个 options 上限 32 KiB。账户点击必须属于当前请求列出的 item/revision/credential 三元组；仅在 native 明确报告截断时允许打开完整 native 选择器。选择后才发送 `passkey-get`，收窄 allowCredentials 并把 item_id/revision 成对固定。native 审阅及确认再次核对该条目和修订，不能换成另一账户。

## 只读 native 列表

能力名 `passkey-conditional-v1`。`passkey-list` 只接受 v/id/type/capability/origin/tab_id/document_id/options；不接受修改字段或选择器。personal 在认证的只读 bbolt 事务内解析记录并按同一 RP、allowCredentials、活动状态规则投影，返回后清理记录。该查询不占 MutationGate、不创建原生批准、不追加审计、不改快照、不刷新 idle。

`passkey-candidates` 精确包含 v/id/type/passkeys/truncated；每行仅有 item_id/revision/title/credential_id/rp_id/user_name/display_name。无私钥、原始记录、userHandle、密码或因素。最多 50 行；序列化整帧须小于 native 输出上限，超限只删除完整行并报告 truncated。writer 获得槽位后重新检查 capability、Session 身份和 generation；失效候选不能排队穿透锁库。

## 批准及验证

选择后沿用既有 native 独立批准界面和因素验证。需要 UV 时必须为本次操作重新验证主密码与 Secret Key；旧的库解锁不自动算 UV。候选列表不能授予签名权。签名回包受 Session、请求、期限和 Passkey 撤销 epoch 的共同约束，管理删除后排队结果仍须拒绝。此批没有声称接入 Windows Hello / Touch ID，也没有改变现有持久存储格式。

## 可复现验证与边界

Go 契约检查 metadata-only、真正只读、RP/状态/allowlist、排序、严格 DTO、整帧边界和固定账户批准；Node VM 检查 MAIN/isolated 生命周期、能力回声、可信选择及 background 上下文。它们是组件契约，不算真实浏览器旅程。

真实 Chromium/Edge 与 Firefox 脚本调用标准网页 API，使用真实输入焦点/点击以及 native UI 因素输入；检查不提前批准、忽略 timeout、取消、closed-shadow/MAIN 隔离、原库快照不变、所选账户签名、导航和断连。Node crypto 验证 RP hash、origin/challenge、UP/UV 和签名；可选独立 @simplewebauthn/server 校验。自动脚本不向产品增加测试消息或绕过批准接口。每次实际运行的范围与失败修复均写入验收记录。

其他提供者验收仅在 CDP 测试会话配置软件 CTAP2/USB 验证器，通过标准 cross-platform create 和真实“使用其他验证器”点击运行原生 get；不修改产品消息，不读取验证器私钥。RP 独立核对签名并检查本地库快照未变，finally 清除虚拟验证器。它提供共存与回退证据，不提供真实硬件或跨设备同步证据。
