# 浏览器两步验证二维码捕获与保存

日期：2026-11-10。本文件记录在 Locklark 浏览器扩展中实现“检测页面上的两步验证二维码、经用户确认后保存到已有登录”的设计、信任边界和实际测试结果。它对应 1Password 的 `autosave-qr-code-detected` / `autosave-2fa-*` 行为；参考实现来源与字节锚点见[1Password beta 对照](browser-1password-beta-parity.md)。

## 参考行为

参考扩展在登录检测中监听二维码，识别 `otpauth://` 配置后提示保存，并把种子写入条目。本次不复制它的实现，只按可复核的静态证据复刻用户可见流程：检测 → 展示 issuer/account → 用户确认 → 写入。

## 用户流程

1. 页面出现二维码时，内容脚本使用浏览器 `BarcodeDetector` 在本地解码；不解码的图像会被直接跳过。
2. 解码结果必须是合法的 `otpauth://totp` 配置（见下节），否则忽略。
3. 扩展向 worker 发送 `inline-otp-capture`；worker 校验配置、核对当前文档，并读取该来源的 login 候选。页面只收到 issuer/account 展示文本和条目标题。
4. 页面在二维码附近显示关闭 Shadow DOM 面板“保存两步验证”，列出可保存到的已有登录。
5. 点击条目后，worker 用该文档的候选修订构造一次 `item-save` 编辑：只写 `otp`，标题沿用候选标题；原生端重新解析配置、重新读取整条条目并推进签名修订。
6. 成功后面板关闭并提示“已保存两步验证”；失败时面板保留并显示“保存失败，请重试”。

没有匹配登录时不写入，只提示“未找到此网站的登录，请先保存登录再添加两步验证”。不自动创建登录条目：原生创建 login 需要密码，二维码里没有密码。

## 安全边界

| 关注点 | 处理 |
| --- | --- |
| 种子是否进入页面 | 不解码结果不回传页面；面板只显示 `issuer · account`，不包含 secret。内容脚本解码后把原文发给 worker，worker 只回元数据。 |
| 是否自动保存 | 不会。必须由用户在内联面板点击具体条目。 |
| 种子存活时间 | worker 内存中的捕获记录 2 分钟过期，最多 8 条；锁库、断连、保存成功都清除。剪贴板、存储、日志、弹窗均不写入。 |
| 目标条目 | 只能选择 worker 在该文档上观察到的 login 候选；调用方不能指定任意条目。修订在保存时由原生端复核。 |
| 跨文档重放 | 捕获绑定 origin、tab、document；其他文档不能消费。一次捕获只能保存一次。 |
| 权限 | 不新增任何浏览器权限：`BarcodeDetector` 是页面 API，解码在本地完成。 |
| 网络 | 无网络请求；不下载图标、不上传图像。 |
| 原生协议 | 不新增协议消息或原生能力。写入复用现有 `item-save` 的 OTP 变更路径（`v2ItemFromMutation` 已校验并支持 `otp`）。 |
| 无效配置 | 以下均拒绝：HOTP、未知参数、重复参数、非 Base32 或过短/过长种子、digits 非 6/8、period 越界、算法非 SHA1/256/512、标签含控制字符/斜杠、label 与 issuer 冲突、带 fragment 或空白。 |

## 页面扫描的约束

- 只在 `BarcodeDetector` 存在且支持 `qr_code` 时启用；当前 Chromium 系可用，Firefox/Safari 不支持时整个功能静默关闭。
- 只扫描 `img`/`canvas`，边长 96–1024 像素、当前可见、每个元素只解码一次；每页最多 24 次解码。
- 只在看起来与账号安全相关的页面扫描：URL 含 `2fa|mfa|two-factor|authenticator|totp|otp|setup|security`，或页面文本含两步验证/扫描二维码字样。
- 页面存在其他内联面板时让位，不叠加 UI。
- 页面使用 `MutationObserver` 触发的重扫有 1.5 秒防抖。

## 测试

| 层 | 文件 | 覆盖 |
| --- | --- | --- |
| 解析 | `browser-extension/test/core.test.js` | 合法 URI 的 label/issuer/digits/period/algorithm、默认值、小写 Base32、issuer 单参数、HOTP/未知参数/重复参数/过短种子/越界/控制字符/斜杠/冲突 issuer/空白全部拒绝，返回值不含 secret |
| 内容脚本 | `browser-extension/test/otp_capture.test.js` | 检测后显示面板且面板不含种子、保存发送正确的 captureId/itemId、忽略后不再提示、非 TOTP 二维码忽略、设置关闭、无匹配登录不写、保存失败保留面板 |
| worker | `browser-extension/test/background.test.js` | 捕获只返回元数据、跨文档/非候选条目拒绝、保存发出只含 title/category/otp 的 `item-save`、捕获单次使用、未连接与非法配置拒绝 |
| 原生契约 | `internal/browserhost/otp_capture_save_test.go` | 仅 OTP 的整条变更保留用户名/密码/标题/URL、保留自定义区段与字段并推进修订；非法配置拒绝且不写入；旧修订拒绝覆盖 |

本批实际执行：扩展 `node --test test/*.test.js` 427 项全部通过（本功能新增 10 项）；Go `CGO_ENABLED=0 go test ./internal/browserhost -run 'TestItemSaveOTP|TestItemSaveRefusesInvalidOTP' -count=1` 四项通过。完整 `internal/browserhost` 包在本机因 `broker_test.go` 的本地 IPC 环境失败，与本次改动无关；本机默认 cgo 链接因 CommandLineTools SDK 报 `unknown architecture arm64e` 失败，因此 Go 断言使用 `CGO_ENABLED=0` 运行，CI 仍需在正常工具链上复跑。

## 限制与未覆盖

- 没有在真实浏览器、真实站点或真实原生连接上运行；以上只是 Node DOM 与 Go 单测。
- Chromium 系以外没有解码能力；Firefox 的 `BarcodeDetector` 缺失时功能不可见，这是有意降级，不是“平台已支持”。
- 只处理页面上可见的 `img`/`canvas`；视频帧、动态重绘画布更新、跨域图片（检测抛错）不会重试。
- 同一元素只解码一次；二维码刷新为同一元素的新图像时不会再次提示。
- 只保存到已存在的 login；不会创建新条目，也不会把种子写进注释或自定义字段。
- 面板显示 `issuer · account` 文本来自二维码本身，可能为任意字符串（已限制长度与控制字符）；用户需要自行判断是否可信。
- 未实现参考的“自动扫描并添加”默认开关组合、通知、遥测或“保存到新条目”流程。
- 原生端的 `item-save` 是既有的扩展编辑通道；本功能没有增加按次原生批准窗口。这是与参考“页面内确认”一致的取舍，不等于新增了原生授权语义。

## 复跑

```sh
cd browser-extension
node --test test/core.test.js
node --test test/otp_capture.test.js
node --test test/background.test.js
node --test test/*.test.js

cd ..
GOMODCACHE=$PWD/.tmp/gomodcache GOCACHE=$PWD/.tmp/gocache GOFLAGS=-mod=mod GOSUMDB=off CGO_ENABLED=0 \
  go test ./internal/browserhost -run 'TestItemSaveOTP|TestItemSaveRefusesInvalidOTP' -count=1
```
