# 扩展与本机原生应用的连接交互

日期：2026-11-10。范围是浏览器扩展与本机已安装的 Locklark 原生宿主/桌面端之间的**运行时交互**：连接失败的解释、重新连接、请求桌面解锁、状态与安装指引。不包含扩展安装、原生宿主注册自动化或原生审批窗口的内部界面。

## 背景

扩展通过固定宿主名 `org.locklark.browser` 连接原生宿主。宿主由桌面端二进制提供：

- 桌面端正在运行时，宿主把 stdio 中继到桌面端的 broker；
- broker 不可用时，宿主会启动一个独立的 Locklark 确认窗口。

因此“原生应用没装/没开/版本旧/被浏览器拒绝”在扩展侧表现为不同的失败：`connectNative` 抛错、端口在配对前退出、`hello` 超时，或配对成功但能力集合缺少新版能力。此前这些情况都只落到一句泛化的“连接失败/已断开”。

## 失败分类与交互

native state 由 worker 维护，并随 `state` 与 `diagnostics` 暴露（字段 `hostState`、`hostOutdated`）：

| `hostState` | 触发 | 弹窗行为 | 选项页行为 |
| --- | --- | --- | --- |
| `missing` | `connectNative` 报 host not found | 指引卡：未找到原生宿主；显示注册命令、复制命令、重新连接 | 状态“未找到原生宿主” |
| `forbidden` | 浏览器拒绝宿主注册 | 指引卡：重新运行注册命令并检查清单路径；可复制命令 | 状态“浏览器拒绝了原生宿主” |
| `exited` | 端口在配对前退出 | 指引卡：宿主已退出；重新连接/在 Locklark 中解锁 | 状态“原生宿主已退出” |
| `timeout` | `hello` 等待 65 秒超时 | 指引卡：等待桌面解锁；在 Locklark 中解锁/重新连接 | 状态“等待桌面解锁超时” |
| `outdated` | 配对成功但能力包含 `shared-session-v1` 且缺少 `popup-vault-v1` | 指引卡：升级桌面端后重新连接 | 状态“原生宿主版本过旧” |
| `error` | 其他连接异常 | 指引卡：确认 Locklark 正在运行；可请求解锁 | 状态“无法连接原生宿主” |

连接按钮在出现 host state 时改文案为“重新连接本地金库”。成功配对后清空 host state。

## 请求桌面解锁

`native-unlock` 由弹窗或选项页触发：

1. 已有端口（即使 `hello` 还在等待）时，发送 `unlock-request`；
2. 宿主收到后调用桌面 broker 的“聚焦解锁”回调；broker 不可用时独立窗口本身就是确认界面；
3. 回复一个窄的 `status` 帧（`desktop_connected`、`unlocked`、`vault_locked`、`capabilities` 等）；
4. 扩展只更新提示文案，不因为收到 `status` 就获得任何 capability，也不能借此跳过解锁或批准。

没有端口时，`native-unlock` 会先发起一次 `connect()`，返回“正在启动 Locklark”。

这套请求在配对前是允许的：`unlock-request` 的 wire 校验只要求 capability 为空或是合法 token，回复形状也由 `core.validResponse` 限定了固定键集。

## 安装/注册指引

原生宿主注册是 OS 级操作，扩展不能也不应该代做。指引卡给出当前浏览器的命令模板：

```sh
locklark-browser-register --browser chromium --host /path/to/locklark-browser-chromium
```

Firefox 用 `--browser firefox` 与对应二进制；Safari 不显示该命令，因为其注册走容器 App 与扩展设置，而不是 NativeMessagingHosts 清单。

## 诊断

`diagnostics` 的 `connection` 增加 `state`，与已有的 `connected`、`quick_fill`、`capabilities`、`status` 一起供选项页“原生连接”区块显示。选项页提供刷新、连接/重新连接、在 Locklark 中解锁三个动作，并只显示能力名，不读取条目。

## 测试

| 层 | 覆盖 |
| --- | --- |
| worker（`test/background.test.js`） | 缺失宿主 → `hostState=missing` 与指引文案；旧宿主 → `outdated`/`hostOutdated`；`native-unlock` 发出 `unlock-request` 并以 `status` 回复 |
| core（`test/core.test.js`） | `status` 帧的白名单键集；未知键与错误 `v` 拒绝 |
| UI（`test/popup_vault.test.js`） | 弹窗指引 ID、命令模板、`renderNativeGuidance`；选项页原生连接区块 |
| 原生（`internal/browserhost/native_unlock_test.go`） | 配对前 `unlock-request` 返回 `status`，且未配对宿主不声称桌面会话 |

实际执行：扩展 `node --test test/*.test.js` **449 项通过**；Go 该用例通过（`CGO_ENABLED=0`）；Chromium/Firefox/Safari 构建与未签名打包校验通过。

## 限制与未覆盖

- 没有宿主机版本号；`outdated` 只能靠能力集合启发式判断，不能精确比较版本。
- 注册命令里的宿主路径是占位符；扩展无法发现用户机器上的实际安装路径。
- 没有在真实桌面端上验证“聚焦解锁”窗口是否被带到前台，也没有验证独立确认窗口的可见性。
- 没有自动重连或后台轮询：连接仍然由用户动作触发，避免每次打开弹窗都拉起原生窗口。
- 原生审批窗口、生物识别提示和桌面主题不在扩展交互范围内。
