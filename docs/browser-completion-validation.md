# 浏览器完成增量与最终验收

日期：2026-11-07；开发起点为已合并 main 9cbc34cfe487d9a226a12a63c1cd35ed707fa11c。PR #47 已关闭历史验证性能 #35；PR #48 的最终 head b2905ffcbc3598eeb372b665bafd3e85b91a0d67 六项 CI 成功，09:16:47 UTC 正常 squash 合入此基线，合并树等于验证树。当前仅 #39 开放。本文件记录下一批的本地证据，最终提交及远端合并回执以对应 PR 为准，不沿用 #48 的绿色结果。

## 本批实现

- [Signal APIs](passkey-signals-design.md)：仅包装已有标准方法，保持浏览器原 Promise；原生只读审阅、owner 确认、全部条目精确修订的一次事务、独立审计动作及立即取消。具体组件和真实交互见[Signal 验收](passkey-signals-validation.md)。
- [逐次系统验证](passkey-system-verification-design.md)：Windows/macOS 通过每次新鲜系统保护 capsule 释放进行 Passkey 验证；普通解锁或已有会话不能充当本次 UV。OS 等待不持 Session/Connection 锁，返回后重验原请求/期限/修订/撤销。Linux 保持完整因素路径；fake adapter 通过不代表 Hello/Touch ID 真机通过。
- 相关来源 RP 提示及非规范/非本域 RP 请求交给浏览器，原 options 不变，由浏览器处理相关来源规则与错误。Locklark 不自行下载 .well-known，不宣称实现所有高级扩展。
- [未签名发布准备](browser-release-preparation.md)：固定 11 个文件白名单、确定性 ZIP/公开 SHA 回执、身份/权限/CSP/frame/world 校验与输出路径防护；CI 上传未签名 artifact。商店身份、签名、真实安装和升级仍需单独完成。
- 代表性公共站点输入兼容性：2026-11-07 09:31:07 UTC 实际读取 GitHub /login 与 webauthn.io 的公开非隐藏输入属性，保留精简自建 fixture 与 provenance.json。未保存整页、动态 token、值或品牌素材。真实三浏览器执行当前 core.probe/capture/fill，检查用户名/密码映射、隐藏诱饵不改、无意外提交。三项日志 public-site-{chromium,firefox,edge}.log 均通过；这是受控 HTTPS DOM 组件验收，不能冒充真实站点账户登录或完整原生连接旅程。

## 主代理实际验证

| 检查 | 结果 | 证据与边界 |
| --- | --- | --- |
| 扩展 Node 全量 | 293 pass，0 fail/skip | browser-completion-node-frozen.log |
| 统一 E2E | 212 总计，176 pass，36 pending，0 fail；170.332 秒 | browser-completion-e2e-final.json/log；未用 strict 模式隐藏已有 pending |
| 功能层 | 149 总计，130 pass，19 pending | 与探针、组件分开统计 |
| 能力探针 | 45 总计，28 pass，17 pending | 通过不等于产品操作完成 |
| 组件契约 | 18 总计，18 pass | 新增 T2_F2_10 Signal 与 T2_F2_11 系统 UV，实际执行 Go/Node；fake UV 不等于硬件验证 |
| Go vet | 全仓通过 | browser-completion-vet.log |
| Signal native race | 通过，46.567 秒 | passkey-signal-final-native-race.log |
| 系统 UV race | browserhost/personal/osunlock 均通过，45.177/60.212/1.013 秒 | passkey-os-independent-race.log；fake adapter |
| 驱动 Python 回归 | 82 项通过 | passkey-signal-driver-unit.log |
| 未签名打包回归 | 8 项通过，0.285 秒 | browser-completion-package-frozen.log |
| Chromium 完整原生组合 | 通过 | browser-completion-chromium-full.log；含 popup/附件/清空、填充/保存/更新/OTP、条件式、其他软件验证器、Signal、Passkey 管理/重连与独立 RP 验证 |
| 独立 Edge 完整原生组合 | 通过 | browser-completion-edge-full.log；同上；软件 CTAP2/USB 共存不是硬件安全密钥 |
| Firefox 完整原生组合 | 通过 | browser-completion-firefox-full.log；完整填充/保存/更新/OTP、Passkey 创建/签名/取消/回退、条件式和管理/重连；配置独立 RP verifier，缺失 Signal 方法不虚报支持 |

脚本实际使用固定 native 构建和独立 @simplewebauthn/server 14.0.3。所有私有合成 fixture 与因素保留在私有运行目录，公共日志仅输出阶段和断言。首轮 Signal GUI、筛选适配器失败及修复见专项验收，没有删除失败证据或将旧 head CI 挪作最终结果。

## 可重复的未签名产物

用本批冻结扩展源码分别在 release-a、release-b 两个输出目录生成，两个目录逐字节一致。公开回执和 ZIP 位于 /workspace/signal-validation-1/release-a，产物不含 vault、身份、因素、私钥或 harness 配置。

| 文件 | 字节 | SHA-256 |
| --- | --- | --- |
| locklark-browser-extension-chromium-unsigned.zip | 578152 | 1cc031ef3b7da68f3625080390660bec2b5e82fe28bb0260aab8f649dd32023b |
| locklark-browser-extension-firefox-unsigned.zip | 577844 | d0237c6fc3c87576a6401c559fbdb81ca695ead89f3a36c752d16bb1bbe0adf1 |

本地运行仅证明 Linux 未签名准备与可重复性。不能据此声称商店签名、商店身份衔接或 Windows 上执行打包工具已经验证。

## 仍开放的 #39 范围

真实 Windows/macOS 浏览器+native 组合及 Hello/Touch ID 每次提示/拒绝/锁库；凭据跨设备同步、导入导出和实际其他硬件提供者互操作；商店身份/签名/安装/升级；完整独立安全审计。Safari、同条目多凭据、更多真实站点及固定参考版本逐项 1:1 对照继续保留在[65 项清单](browser-parity-checklist.md)。这些条件不能由 Linux GUI、交叉编译、软件验证器或 fake adapter 替代。

只有本批最终精确 head 的 android、ios、desktop-macos、web、go (ubuntu-latest)、go (windows-latest) 全部 COMPLETED/SUCCESS 且 PR CLEAN 后才正常合并；macOS Objective-C helper 必须由实际 macOS CI 编译。无 admin 或绕过检查。
