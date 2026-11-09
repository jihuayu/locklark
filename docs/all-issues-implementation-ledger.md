# 遗留 issues 实现台账

更新：2026-11-09（北京时间）。已合并主线为 `42a2a7c`，包含 PR #71 多通行密钥和 PR #72 剪贴板；#63、#66 也已关闭。PR #74、#75、#76、#77 的开发与组合验证继续推进，未把分支代码或本地通过写成已合并。主要实现由 DeepSeek 完成，主代理负责架构、冲突整合和实际验收，Luna 提供定向复核。

| Issue | 已有实现与证据 | 尚未完成 |
| --- | --- | --- |
| #50 | 系统解锁与拒绝/撤销防护实现 | 真实 Hello/Touch ID 设备的新鲜验证及迟到负测 |
| #51 | Windows UIAutomation/macOS Accessibility 外部输入驱动 | 实际平台完整浏览器/原生流程 |
| #52 | PR #74：一次性加密迁移、完整因素新鲜性、原子导入；真实双金库 PTY 和 RP 签名验证通过 | 当前 head 的平台 CI、两台物理设备及 provider 共存证据 |
| #53 | PR #73 已合并：可复现 unsigned 产物、来源与签名验证预检 | 商店 owner、实际签名、干净安装和同身份升级 |
| #54 | 具体安全发现已修复并经过 race/定向复核 | 独立审计方及最终整改复核，LLM 复核不替代正式审计 |
| #55 | Safari 宿主、传输与生命周期防护；实际 macOS Swift/Xcode 检查已有通过证据 | 签名身份和实际 Safari 完整生命周期验收 |
| #56（已关闭） | PR #71 已合并；真实 Edge/Firefox 多凭据选择、编辑、删除和签名旅程通过 | 无本轮开发遗留；见多凭据验收文档 |
| #57 | PR #75：65 项证据映射；真实 Edge action popup/options 9 项审计零违规/未完成 | 固定参考安装对照、真实读屏、OS 缩放与高对比度 |
| #58 | skill 内嵌凭据已清理，运行配置使用私有权限 | Locklark 引用实际配置、所有者轮换/撤销旧凭据及最终复核 |
| #59 | PR #72 已合并；真实 Linux Edge/Firefox 共享桌面剪贴板完整旅程通过；实际 Windows/macOS native smoke 通过 | 完整共享浏览器旅程的 Windows/macOS 及独立 Chrome 安装证据；macOS 明确手动清理 |
| #63（已关闭） | PR #62、#68 已合并；typed CLI、附件、rich 1PUX、SSH 私有文件导入及真实终端负测通过 | 无本轮开发遗留 |
| #64 | PR #77：v2 broker、原生审批、同终端精确范围 lease；真实 Linux 完整审批/复用/锁后撤销通过 | 当前 Windows runtime CI；macOS 精确字节固定尚不支持，显式 unpinned 走本地完整因素 one-shot |
| #65 | PR #76：真实 Edge 同站跨源 child fill、物理拒绝、跨站/opaque sandbox/审批期间导航拒绝通过 | 当前平台 CI、其他浏览器/平台证据 |
| #66（已关闭） | PR #67 已合并；默认离线，显式 NETWORK 同意后 HIBP 检查 | 无本轮开发遗留 |
| #69 | PR #70 已合并，正向保护失败保持 CI 失败 | 支持保护能力的环境或签名真机完成 iOS 正向文件保护验收 |

## 本轮组合验证

组合分支已同时包含剪贴板、CLI、结算、迁移和证据映射。broker 回调工厂同时保留 v2 CLI 和原生剪贴板，未恢复旧 CLI v1；严格请求解码同时保留凭据 revision、copy ticket 与 checkout context；各生命周期注册表同时保留。

- 438 项 Node 检查全部通过，包含扩展及结算/无障碍驱动检查。
- 真实 Linux CLI/PTY：独立进程共享真实终端，one-shot 每次审批、显式 lease 复用、变参/变终端再审批与拒绝、锁后实际 CLI 拒绝且无因素回退，全部通过。绝对五分钟期限由 timer/race 检查覆盖，本次未等待完整五分钟。
- 真实 Edge 共享桌面剪贴板：关闭弹窗后可粘贴，外部所有者经过 TTL 仍保留且零外部 payload 请求，锁定清理自有值，隐藏后迟到准备取消，全部通过。
- 真实 Edge 结算：仅获批 child 收到卡片字段，顶层/PIN 空白、不提交；物理拒绝、跨站、opaque sandbox 和等待审批时导航均不写值。
- 59 项 CLI 工具检查通过（58 项桌面驱动与 1 项可移植包导入）；Windows unittest discovery 不再提前导入 POSIX fcntl。Windows/Darwin 个人模块交叉编译通过，交叉编译不算实际 Windows 运行。
- OTP 显式取消语义检查使用自有时间/计时器，连续 3 次 race 验证通过（50.468 秒）；仍要求一秒内取消、立即清零和不交付，生产时限与真实过期检查不变。
- 组合 Go race 检查仍在运行；最终平台 CI 与合并回执尚待确认。

## E2E 计数边界

历史完整 E2E 报告为 215 项：183 PASS、32 PENDING、0 FAIL。该历史数字不代表本轮组合重跑。本轮新增的真实旅程和定向测试在上方单列；438 个 Node 检查不与 215 个 E2E 混加，也不把模拟、交叉编译、LLM 复核计作真机或独立审计。PR #74–#77 的 CI 状态以各自当前 head 为准。

验收入口见 [剪贴板](browser-clipboard-ownership-validation.md)、[结算](browser-checkout-validation.md)、[无障碍](browser-accessibility-validation.md)、[CLI 包装](cli-wrappers.md)、[迁移](passkey-transfer-cli.md)。
