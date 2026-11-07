# 条件式 Passkey 验收

日期：2026-11-07。对应 #39 的条件式账户建议与高级请求回退子项；主代理设计、外部 DeepSeek workers 实现，独立 worker 只读复核，主代理执行真实浏览器。协议及授权边界见[设计](conditional-passkey-design.md)。

## 实现与复核

- native metadata-only 列表、精确 item/revision 固定、无列表审批/审计/idle 续期、最多 50 行及整帧限制已实现。实际只读状态凭据从 bbolt 直接读取比较，未用会追加审计的 List/Audit 充当观察器。
- MAIN 只公开布尔支持能力和标准 WebAuthn 结果；账户列表只进入 isolated closed shadow。同源 postMessage 会回送 MAIN 自己的能力查询，必须等到 boolean 回复；真实 Chromium 初跑发现并修复，VM 回声回归能复现旧逻辑失败。
- 只读复核发现能力握手期间 abort 可迟到复活；已将取消监听前移并清理 waiter/timer，补可用/不可用回复、pagehide、fallback 微任务及 listener 释放测试，旧顺序 mutation 下回归失败。
- 主代理发现开放 Shadow DOM 的 input 被 document.activeElement 重定向到 host；改为只遍历开放 root 的 activeElement，覆盖已聚焦、新聚焦、查询期间换焦点和 closed-root 不可遍历。
- 后续复核提示选择可能覆盖正在等待的普通批准；主代理确认另有 await current 后 intent 被替换/取消的问题。选择前后均重验 intent 对象、pageID/context/epoch/capability/support 以及三个空闲槽位；回包再查批准对象。四组受控延迟/并发回归在旧逻辑 mutation 下全部失败，修复后通过；未声称 OTP pending 分支已有专门动态子例。
- RS256/EdDSA-only create、enterprise/未知 attestation、超过 native 32 个算法参数的请求，以及已有 PRF/largeBlob/其他扩展/cross-platform 请求继续交给浏览器。混合列表含 ES256 且符合限制时仍可使用 Locklark。未虚构 PRF、largeBlob、新算法或相关来源支持。

两个只读外部复核均明确区分检查过的代码与未读部分；后一个补读 background/core 及 sender/原 options/选择成员关系。静态复核不算实际执行，也不等同完整独立密码审计。native writer 在 Session/generation 变化后拒绝帧；Handle 错误会关闭 standalone/共享连接并触发扩展断连清理，并非悄悄留下无期限响应。

## 已执行的组件契约

- backend worker：browserhost 全包 47.896 秒，personal 全包 219.647 秒；主代理独立 focused 非 race 通过，独立 conditional/suggestion race：browserhost 11.785 秒、personal 27.625 秒。personal/vault 私钥不复制到候选 DTO。
- 在起始 main 41e31f7 上，最终本地 Node 全量 243/243 通过、0 fail/skipped；主代理日志 /workspace/issue-completion-tasks/conditional-node-frozen-prebase.log。接入 main 2fc96e7 并保留 PR #46 的 7 个 fill 回归后，主代理全量 250/250 通过、0 fail/skipped（conditional-node-rebased.log）。
- 主代理定向 E2E F2 Tier 2：9/9 通过，其中新增 T2_F2_08、T2_F2_09 实际执行 Go/Node 组件契约并要求非零且足够数量；日志 conditional-e2e-focused.log、JSON conditional-e2e-focused.json。组件契约没有冒充真实 browser→native 旅程。
- go vet personal/browserhost/desktop、修改脚本 node --check、git diff --check 通过。

## 真实浏览器执行记录

脚本使用标准网页 API、物理输入点击和真实 native UI 因素输入；不增加产品测试消息。观察快照摘要，验证 RP hash、origin、challenge、精确账户 ID、UP/UV 与 ECDSA 签名；配置独立 verifier 时还执行 @simplewebauthn/server，未配置的运行不声称该第三方验证已执行。

- Chromium 单独条件式旅程通过（conditional-chromium-4.log）；之后完整组合旅程通过（conditional-chromium-combined.log）：弹窗创建/编辑/附件/显式清空、填充/保存/更新/OTP、条件式建议的无提前批准/忽略 timeout/取消/签名/导航/断连、独立 Passkey 管理和重连。
- Firefox 单独 Passkey+条件式（含断连）通过（conditional-firefox-2.log）。初跑的 BiDi 驱动把 Promise 直接 JSON.stringify 成 {}，已改成先 await 再序列化；这是验收驱动修复。
- Firefox 完整组合初次及诊断重跑在进入条件式 fixture 时失败。此前 OTP 流程留下 split-field 页面，基本 Passkey API 仍可运行，却没有条件式步骤需要的 #username。已让条件式 helper 通过真实导航显式进入受控 /passkey 登录页面，能力检查有界等待并仅输出布尔诊断。修复后的 Firefox 完整组合（conditional-firefox-combined-3.log）已通过全部填充/保存/更新/OTP、条件式与管理/重连；能力实际首次即 true。失败记录保留，不用早期单独成功替代组合运行。
- 独立 Edge 完整组合（conditional-edge-combined.log）通过全部上述范围和新增其他提供者共存：CDP CTAP2/USB 软件验证器通过原生浏览器 cross-platform 创建，普通 get 在实际点击“使用其他验证器”后由该验证器签名，Node crypto 独立核对 RP/来源/challenge/账户/UP/UV/签名，原库快照及相关元数据/历史不变。未读取虚拟验证器私钥；该软件验证器明确不代表硬件安全密钥或 Hello。未配置第三方 verifier 的本地运行不声称它已执行。
- 驱动 Python 测试及 Firefox Passkey 测试通过；E2E adapter 工具 46 项通过（31.545 秒），conditional-e2e-adapter-unit.log。

详细日志均位于 /workspace/issue-completion-tasks；包含 vault/因素的私有 fixture 不作为发布物或诊断附件。

## 最终集成门槛与剩余范围

Chromium、Firefox CI 都启用条件式和管理旅程；Chromium 还启用其他提供者的软件验证器旅程，配置已有独立 WebAuthn verifier。必须最终精确 head 的 android/ios/desktop-macos/web/Go Ubuntu/Go Windows 六项成功后正常合并。最终 head、run、合并收据和全量 E2E 数量在结果稳定后补录。

#39 仍分别追踪实际 Windows/macOS 浏览器及 Hello/Touch ID 硬件行为、Signal APIs、其他提供者/跨设备、公开站点兼容 fixture 和分发验收。此批不关闭整个 epic，不把软件/模拟器或 Linux 运行写成真机 UV，也不把受控 RP 当实际生产网站登录。

## 新主线最终本地收据

接入 main 2fc96e7 后，扩展全量 250/250；统一 E2E 重新构建后为 210 项：174 PASS、36 PENDING_FEATURE、0 FAIL，用时 135.545 秒。分类为 functional 149/130/19、capability_probe 45/28/17、component_contract 16/16/0（依次 total/pass/pending），不把能力探测或 pending 写成完整场景。机器 JSON 为 /workspace/issue-completion-tasks/conditional-e2e-final.json。命令包含 /workspace/toolchains/x11/usr/bin 与正确 Go PATH，并清除外层 DISPLAY/WAYLAND_DISPLAY/DBUS_SESSION_BUS_ADDRESS，让 harness 为每个 GUI 探测创建自己的会话。

本地首次统一运行漏带 X11 工具 PATH，得到 169 PASS、40 pending、1 FAIL；原生 host 无显示会话而无法启动。该失败保留在 conditional-e2e-without-x11.log/json，没有改测试断言或当成缺失产品功能。纠正环境后的上述完整运行才是本批证据。最终六项 CI 及合并收据见对应 PR；#39 仍开放。
