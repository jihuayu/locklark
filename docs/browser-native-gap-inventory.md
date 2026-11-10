# 浏览器缺口盘点：需要新原生能力或权限的项

日期：2026-11-10。本文件盘点[1Password beta 对照](browser-1password-beta-parity.md)中“未同步”的项，按**是否可行、需要什么权限或原生能力、风险在哪**给出结论，供决定下一批范围。结论基于当前代码，不代替产品决定；标“可行”不等于已经实现或验收。

## 当前基线

- 扩展权限：`activeTab`、`scripting`、`nativeMessaging`、`storage`，Chromium 另加 `contextMenus`；`host_permissions` 为 `https://*/*`。
- 原生能力（`internal/browserhost/types_v2.go`）：`shared-session-v1`、`quick-fill-v1`、`passkey-v1`、`passkey-management-v1`、`passkey-conditional-v1`、`passkey-signal-v1`、`multiple-passkeys-v1`、`generate-v1`、`stage-save-v1`、`popup-vault-v1`、`profile-fill-v1`、`checkout-frames-v1`、`watchtower-v1`、`attachments-v1`、`cli-broker-v1`；原生剪贴板租约按平台条件出现。
- 已可复用的写入路径：`item-save`（创建/整条编辑，支持 `otp`、`sections`、`urls`、`favorite`、`clear_fields`）、`item-state`（archive/unarchive/trash/untrash/favorite）、`stage-save`（新登录/改密）、`attachment-*`、`profile-fill`、`passkey-*`。
- 原生批准的既有界面：填充、敏感字段（身份/银行卡/跨源结账）、保存、Passkey、Signal、逐次系统验证、验证码；新增需要批准的写入要同时改 `Connection.Snapshot`、桌面视图和协议。

## 不需要新权限或新原生能力的项

| 项 | 参考行为 | 现状与需要做的事 | 可行性 | 风险/决策点 |
| --- | --- | --- | --- | --- |
| 两步验证二维码捕获 | `autosave-qr-code-detected` | **本轮已实现**：`BarcodeDetector` 本地解码 + 文档绑定的 worker 捕获 + 仅 `otp` 的 `item-save`。见[验收](browser-otp-qr-capture-validation.md) | 已做 | Chromium 系以外不可用 |
| 条目归档/取消归档 | Archive 与 Trash 分开 | 原生 `item-state` 已支持 `archive/unarchive`，后台 `setItemState` 已接好；弹窗只有“移至废纸篓”，缺归档按钮与筛选 | S | 复用现有状态机，无新协议 |
| “添加网站并填充” | `Add website and autofill` | 原生 `item-save` 可更新 `urls`；需要新的确认 UI 和“只加到当前 origin”的策略 | M | 与“精确来源”模型冲突时要显式确认，不能静默扩域 |
| Open & Fill 落点猜测 | `b5x-sie-sign-in-urls` | 可在内容脚本里做同源 `/login`、`/signin` 等启发式；不需要 `webNavigation` | M | 误跳转与重定向循环；应只对已保存的主页 URL 尝试一次 |
| 内联菜单自动聚焦 | Autofocus sign-in prompts | 现有面板已支持键盘，改为打开后聚焦首项 | S | 抢焦点会打断输入；只在显式触发时做 |
| 富图标（同源 favicon） | Show app and website icons | 用页面 `link[rel=icon]` 或同源 `/favicon.ico` 缓存到 `storage.local`；无网络下载到第三方 | M | 图标缓存大小、隐私说明、离线策略；参考的 1Password CDN 方案不可照搬 |
| 诊断/健康报告 | Extension Health Status / diagnostics | 汇总能力、权限、连接、最近错误，生成 JSON 供用户保存 | S/M | 保存文件需要 `downloads` 或用 Blob 锚点；不能含条目、种子、令牌 |

## 需要新增浏览器权限

| 项 | 需要权限 | 最小实现 | 可行性 | 风险/决策点 |
| --- | --- | --- | --- | --- |
| 空闲/睡眠自动锁定 | `idle`（+ 可选 `alarms`） | 监听 `idle.onStateChanged`，`locked` 时调用现有 `lock` 路由 | S | 新增权限需要重新过发布/身份检查；阈值要可配 |
| 系统通知 | `notifications` | 保存/锁定/二维码保存后发系统通知 | S/M | 权限与骚扰控制；参考还有“通知已移动”的引导 |
| 冲突密码管理器检测 | `management` | 枚举扩展并提示禁用其他密码管理器 | S | 权限很重，收益有限，建议不做 |
| 剪贴板读取 | `clipboardRead` | 一般不需要；现有原生租约已覆盖复制 | — | 不建议引入 |

## 需要新增原生能力或协议

| 项 | 需要的原生改动 | 可行性 | 风险/决策点 |
| --- | --- | --- | --- |
| 密码历史 | 已落地元数据读取与恢复；明文查看仍只在桌面端 | 已实现 | 旧密码长期留存是既有原生存量，本轮未改变保留期 |
| “Sign in with” 保存 | 已落地提供商展示识别；真正的 OAuth 绑定与跨步骤保存未做 | 部分实现 | 需要第三方协议与产品定义 |
| 开发者 API 凭据保存 | 原生已有 `api_credential` 类别；需要站点规则集和识别 UI | M | 站点规则维护成本高，误报会污染库 |
| SSH 密钥填充/Agent | 原生已有 `ssh` 类别与 typed SSH 导入；Agent 是独立进程与权限模型 | L | 与浏览器填充不是同一能力，先做 Agent 更合理 |
| Masked Email / 虚拟卡 | 第三方 OAuth 与服务端集成（Fastmail、Privacy、Brex） | L | 法务、账号与离线模式冲突；不建议做 |
| 企业集成（Kolide/Trelica/Apono/特权访问） | 企业服务端策略、设备信任链、目录同步 | L | 超出个人/小团队产品范围 |
| Agentic autofill / local MCP | 扩展内 MCP 服务或本地代理 + 原生逐次批准 | L | 与“Agent 申请具体操作”的产品线可结合，但要单独设计 |
| 通用登录合并提示 | 现有内联菜单已是统一入口；差异主要是文案与排序 | S | 收益是观感，不是新能力 |

## 本轮已落地（2026-11-10）

| 项 | 落地内容 | 状态 |
| --- | --- | --- |
| 条目归档/取消归档 | 弹窗“已归档”筛选（worker 校验后传原生 `state`）+ 详情页归档/取消归档 | 已实现，Node 测试 |
| 添加网站并填充 | 详情页把当前 HTTPS origin 追加到条目 URLs（仅 URLs 的 `item-save`），随后填充 | 已实现，Node 测试；真实站点未验证 |
| 内联菜单聚焦 | 显式打开命令渲染后聚焦首个操作；聚焦触发的菜单不抢焦点 | 已实现 |
| 同源富图标 | 仅当前站点请求 `/favicon.ico`，其他来源不发请求、不接第三方图标 CDN | 已实现 |
| 诊断/健康报告 | 选项页导出 JSON：版本、连接、能力名、非敏感设置、计数；无条目/URL/值 | 已实现，Node 测试 |
| Open & Fill 落点 | 在已保存 URL 中优先选择看起来像登录页的路径 | 已实现 |
| 空闲自动锁定 | 新 `idle` 权限；设置 0/1/5/15/30/60 分钟，默认关闭；触发原生 lock | 已实现，Node 测试 |
| 系统通知 | 新 `notifications` 权限；默认关闭；仅保存成功与空闲锁定 | 已实现 |
| 密码历史 | 新原生能力 `history-v1`：`item-history` 只回元数据，`item-restore-history` 按索引恢复并复核 revision | 已实现，Node + Go 测试；未在真实会话验证 |
| Sign in with | 只做提供商**展示**识别（固定主机名白名单）；无 OAuth、不改变保存内容 | 部分实现，见[验证](browser-history-and-provider-validation.md) |

因此下面的“建议顺序”现在只剩后续批次（密码历史、Sign in with 等）。

## 建议顺序

1. **S 级、无新权限**：归档 UI、Open & Fill 落点、内联菜单聚焦、诊断报告。
2. **S 级、加权限**：空闲自动锁定（安全收益最高）、系统通知。
3. **M 级、加协议**：添加网站并填充、富图标、密码历史。
4. **L 级/不建议**：Sign in with、API 凭据、SSH Agent、Masked Email/虚拟卡、企业集成、agentic autofill。

## 与“复刻自动填充、Passkey、银行卡填充”的关系

这三类主流程在当前代码里已有实现（内联菜单、保存/更新、TOTP、身份/银行卡、结算 iframe、Passkey 创建/断言/条件式/管理），本轮没有发现缺失的主体流程；剩余差异集中在字段覆盖、站点兼容和上面这些外围能力。若要按参考逐项验收，仍需要固定参考版本和真实浏览器组合，不能用本盘点代替。
