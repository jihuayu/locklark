# 浏览器密码历史与身份提供商标识

日期：2026-11-10。本文件记录浏览器扩展新增的两项能力：只投影元数据的密码历史与恢复，以及对常见身份提供商的**仅展示**识别。前者新增原生能力 `history-v1`，后者不新增权限、协议或存储。

## 密码历史

原生存量：`internal/personal` 在密码、用户名、备注或隐藏字段变化时自动追加历史（`autoHistory`），最多保留 20 条；桌面端已有恢复动作 `item.history.restore`。浏览器侧此前既读不到也恢复不了。

本轮新增：

| 请求 | 字段 | 响应 |
| --- | --- | --- |
| `item-history` | `capability`、`item_id`、`revision` | `item-history`：`item_id`、`revision`、`entries[]` |
| `item-restore-history` | `capability`、`item_id`、`revision`、`history_index` | `item-saved`：`item_id`、新 `revision` |

`entries` 只含 `index`、`timestamp`、`action`、`title`、`username`、`has_password`。旧密码、隐藏字段快照和区段永不序列化；worker 端再次按白名单重建条目，即使宿主未来误发值也会被丢弃。恢复走已有的原生 `RestoreHistory` 与 `MutationGate`，精确 revision 由会话重新校验，旧 revision 会被拒绝；恢复本身会再写入一条历史，因此可以反向恢复。

弹窗详情页新增“历史版本”区：按需读取，列出时间、变更类型、是否含密码，逐条“恢复”并二次确认。能力未广播（`history-v1` 缺失）时整块隐藏。

限制：

- 浏览器端不能查看旧密码明文；需要在桌面应用查看。
- 每条最多 20 条历史，和原生保留策略一致；更早的记录不可恢复。
- 恢复是整条恢复（密码、用户名、备注、隐藏字段），不是单字段恢复；这是原生动作的既有语义。
- 没有在真实浏览器或真实桌面会话中执行恢复；只有 Node 与 Go 单测。

## 身份提供商标识

`core.identityProviderFor(origin)` 对固定主机名列表返回展示名（Google、Microsoft、Apple、GitHub、Okta），主机名必须精确匹配或以点分隔后缀匹配，`accounts.google.com.evil.test`、`evil-accounts.google.com.test`、`accounts.google.com@evil.test` 都不会命中。

识别只用于页面保存横幅上的一句说明：“检测到 X 账号登录；这里仍只保存普通登录，不接入第三方 OAuth。”它不改变标题、URL、用户名或任何保存字段，也不触发额外请求。

限制：

- 没有 OAuth/OpenID Connect 集成，没有 provider 账号绑定或“Sign in with”按钮注入；参考实现的这类能力依赖第三方协议与产品协议，本轮不做。
- 列表外的提供商不显示提示；提示不是安全信号，用户仍需核对地址栏。

## 测试

| 层 | 文件 | 覆盖 |
| --- | --- | --- |
| 原生 | `internal/browserhost/history_test.go` | 历史投影不含密码/区段、恢复旧密码并推进 revision、旧 revision 与越界索引拒绝、wire 拒绝错配字段 |
| worker | `browser-extension/test/background.test.js` | 历史响应二次投影会丢弃宿主多发的密码字段、未广播能力时拒绝、恢复索引透传与越界拒绝 |
| 展示 | `browser-extension/test/core.test.js` | 提供商精确匹配与仿冒域名拒绝 |
| 界面 | `browser-extension/test/popup_vault.test.js` | 历史区块与恢复入口存在，worker 有投影函数 |

实际执行：扩展 `node --test test/*.test.js` 439 项通过；`CGO_ENABLED=0 go test ./internal/browserhost -run 'TestItemHistory|TestItemRestoreHistory'` 通过。

## 复跑

```sh
cd browser-extension
node --test test/core.test.js
node --test test/background.test.js
node --test test/*.test.js

cd ..
GOMODCACHE=$PWD/.tmp/gomodcache GOCACHE=$PWD/.tmp/gocache GOFLAGS=-mod=mod GOSUMDB=off CGO_ENABLED=0 \
  go test ./internal/browserhost -run 'TestItemHistory|TestItemRestoreHistory' -count=1
```
