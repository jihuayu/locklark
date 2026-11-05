# 浏览器原生配对与登录填充验收

基线 main `dcc52d04cd8bcf5e17e8d9e2aedd98c92056bacb`，分支 `codex/browser-native-fill`。用户指定：主代理设计架构、功能并验收；Sol（xhigh）完成具体实现；Luna（max）独立 review。[架构与验收约定](browser-native-design.md) 区分实际原生 UI、扩展来源断言和同 OS 用户信任边界。

## 实现范围

Chromium 扩展由实际用户 action/快捷键开启，固定扩展 ID，通过 Native Messaging 启动独立 MyGo 窗口。窗口持有自己的个人金库会话，使用既有完整因素及系统解锁接口；原生批准连接后才能读取当前网站候选，每次用户名/密码填充仍须原生批准。Next.js 管理页不接收金库字段。连接、来源/标签页/文档/条目/修订、短期一次请求以及认证事务的审计意图共同限制交付。

Chrome/Edge 使用 Chromium 宿主；Firefox 有独立启动身份、注册及扩展构建。真实 Firefox 157 临时扩展实验已验证 `executeScript` 返回标准 UUID `documentId`，按 `documentIds` 注入成功，同源导航后旧 ID 被浏览器拒绝（`Invalid documentId`），证据见 `/tmp/locklark-validation/firefox-document-binding/report.json`。该 API 自 Firefox 153 起提供，缺失身份的负测只是模拟不支持的 API，不代表新版 Firefox 不支持。Firefox 的完整 native 填充/UI 链路仍需另验；不引入较弱的来源匹配回退。Chromium 的测试结果不能替代 Edge、Firefox、Safari 或手机验收。签名发布、自动更新和商店分发仍待完成。

## 失败先行及回归

日志保存在执行环境 `/tmp/locklark-validation/`：`browser-red-session.log`、`browser-red-host.log`、`browser-red-connection.log` 分别记录缺失会话 API、协议模块和连接到期行为的失败。`browser-red-worker-late.log` 复现锁库提示被迟到回调覆盖及旧请求清除新候选；实现加入代次/请求身份约束后，扩展测试通过。

已完成个人金库精确来源、修订/状态、一次消费、提交回滚/关闭失败、到期/锁定、旧历史复验；宿主帧长度、重复 JSON 字段、固定启动身份、配对/确认前无值、请求重放、慢管道/断管和原生锁定竞态；扩展来源规范、精确 popup sender、导航后旧响应及缺失文档身份拒绝。`browser-race-final.log` 的 host/desktop/personal 定向竞态通过；`browser-go-all.log` 记录启用真实 Bun 和 PyKeePass 的全量 Go 测试通过。后续独立审阅修复仍需相应回归，不能把早期测试当作最终 head 的结论。

## 主代理独立实际链路

在 Linux Xorg dummy 显示服务器上运行真实 MyGo 进程、Chrome for Testing 156 和已安装开发扩展。`scripts/browser_native_acceptance.mjs` 生成独立合成金库及受控 HTTPS 页面，只信任此次临时证书的 SPKI；通过实际 `Ctrl+Shift+Y` 用户 action 获得 `activeTab`，浏览器读取真实 host manifest 并启动宿主。

`scripts/browser_native_x11.py` 使用系统 XTest 操作窗口：输入完整合成解锁因素、确认连接、批准或拒绝填充、锁库。实际 popup 以本机测试 CDP 连接并发送鼠标输入，不伪造扩展消息或宿主响应。产品中没有跳过解锁/配对/批准的测试入口。

首次完整验收发现锁库提示被异步失败覆盖，保留失败日志并修复；随后 `browser-native-e2e.log` 已通过：批准前字段为空、批准后两字段与合成值一致、未自动提交、原生拒绝后无值、文档导航后旧请求不填新页面、锁库停止匹配/交付且提示锁定、浏览器控制台不含合成秘密。合成证据目录 `/tmp/locklark-browser-acceptance-vTSzqm`，原生确认截图 `native-confirm.png`；合成因素目录不上传、不提交。真实 DOM 测试还覆盖隐藏/disabled/readonly/歧义字段、跨来源表单 action/base 与 iframe 拒绝，见 `browser-dom.log`。

复跑命令（路径按本机调整）：

```sh
DISPLAY=:91 \
LOCKLARK_TEST_PLAYWRIGHT=/workspace/locklark/web/node_modules/playwright \
LOCKLARK_GO=/tmp/locklark-tools/go/bin/go \
LOCKLARK_BROWSER_HOST=/tmp/locklark-tools/locklark-browser-chromium \
node scripts/browser_native_acceptance.mjs
```

## 独立 review 与待验收

Luna 的架构预审及最终实现复审已完成，未发现剩余阻塞项。安装路径/权限与原子发布、无关标签导航、配对前锁定通知、取消授权顺序、候选 JSON 编码预算、外置提交按钮、值后浏览器 API 无界等待与迟到状态覆盖均已修复并有回归。独立运行宿主测试、14 项扩展测试及 Windows 测试交叉编译通过；最后新增一项过期参数测试并格式化后，Sol 的 15 项 Node 测试及真实 DOM 再次通过。主代理在最终二进制上重新运行完整真实 GUI，`browser-native-e2e-final.log` 通过，合成证据目录 `/tmp/locklark-browser-acceptance-bSULDZ`。精确 PR head 远端 CI 尚待完成。已开始写管道/注入的字段无法撤回，失败或回执丢失只表示交付未知；不自动重试或声称网站接收成功。

Windows Hello/TPM、macOS Touch ID 与 Linux Secret Service 的真实系统验证仍保留桌面硬件验收项；本次完整因素 UI 流程不是生物识别硬件验证。保存/更新、TOTP/Passkey、完整类别迁移、团队邀请/远端同步、Safari及移动系统填充继续推进，不由本切片关闭。
