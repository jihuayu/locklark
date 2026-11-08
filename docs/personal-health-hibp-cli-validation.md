# CLI 显式 HIBP 检查（issue #66）

从 `codex/cli-hibp-opt-in` 实现 `personal health --file PATH --hibp true`。没有该字面选项时，CLI 仍走原有 `personal.Health` 路径：一次认证的 `vault.health.local` 事务，输出原有 `HealthReceipt`（`status=checked-local`、报告、摘要、事件），不创建 `desktop.unlock`、`vault.health.watchtower` 或 `vault.health.hibp`，也不实例化联网客户端。

## 选项与同意顺序

- 仅接受完整的 `--hibp true`。`false`、`TRUE`、`1`、重复 `--hibp`、未知选项或其他值都返回固定 usage 拒绝，不回退到隐式布尔解析。
- 选项在正常主密码、Secret Key 提示之前完成解析；不存在 desktop 设置、环境变量、home 配置或 GUI 推送的隐式 opt-in。
- 解锁因素输入后、任何联网前，CLI 输出固定隐私提示，并要求隐藏输入 `NETWORK`。错误、缺失或终端取消都返回固定 `HIBP network check cancelled`；此时不调用 `UnlockSession`，因此没有解锁/体检网络意图事务，也没有请求。
- 同意后使用完整主密码加 Secret Key 调用既有 `personal.UnlockSession`，不使用 quick unlock。会话解锁与 `WatchtowerContext` 检查均使用既有认证事务。

## 网络与隐私边界

- 只对活动登录条目的非空密码计算 SHA-1，并只把大写 5 位十六进制前缀发送到固定 `https://api.pwnedpasswords.com/range/`。不发送明文、完整哈希、后缀、标题、用户名或来源；请求设置 `Add-Padding: true`，不带 Cookie、Referer、Origin 或 Authorization。
- CLI 不提供端点、代理或时限的命令行覆盖，也不从偏好设置或环境变量隐式启用查询；`Session` 持有的生产 `HIBPClient` 是唯一传输。测试只用包内 fake 或合成本地 TLS 客户端，不导出测试用网络客户端。
- 前缀与来源 IP 仍会暴露给 HIBP，可能被关联；提示明确说明这一点，并且取消不会联网。
- 固定错误不包装 provider URL、响应体、前缀或后缀。

## 事务、取消与超时

- `personal.Session.WatchtowerContext(ctx, site, includeHIBP)` 保留既有三阶段：本地报告、联网前意图审计、请求后的认证最终报告；旧 `Watchtower` 仍以 `context.Background()` 调用它。
- `ctx` 为 nil 或已取消时在任何事务前固定拒绝。本地报告后、意图审计前、意图提交后联网前、以及 lookup 返回后最终报告前都检查取消/截止时间。取消失败不产生 `hibp_checked=true` 的最终报告；`lockRequested` 阻止迟到的最终报告。
- `LookupCandidates` 在每个前缀前和每次传输返回后检查 `ctx`，即使 fake 传输忽略取消也不会返回部分或看似干净的计数；拒绝固定为 `ErrHIBP`。
- CLI 为整个多前缀检查设置 30 秒上限，既有客户端保留每请求 10 秒超时。SIGINT/SIGTERM/SIGHUP 仍由现有 CLI 处理器恢复终端并退出；30 秒上下文是网络路径的附加上限。
- 网络失败（超时、不可用、provider 错误）由最终报告如实表示：`hibp_checked=false`、`hibp_error=unavailable`，不会报告为“已检查且干净”。上下文取消/截止或锁请求则返回固定错误而不是干净报告。

## CLI 输出投影

成功检查只输出 CLI 安全投影：

```json
{"status":"checked-hibp","hibp_checked":true,"checked":2,"skipped":0,"findings":[{"id":"…","revision":"…","flags":["vulnerable"],"breach_count":42}]}
```

`hibp_error` 仅在 `unavailable` 时出现；不可用时 `status=hibp-unavailable`。投影丢弃原生 `watchtower.Report` 的标题、来源、URL、强度细节、站点发现和任何明文/哈希材料；`hibp_error` 另外白名单为固定值。默认离线体检输出不变。

## 验证

实际执行的自动测试：

- `go test ./internal/watchtower/ -count=1`
- `go test ./internal/watchtower/ -race -count=1`
- `go test ./internal/personal/ -run 'HIBP|Watchtower|LookupCandidates' -count=1`
- `go test ./cmd/locklark/ -run 'PersonalHealthHIBP|PersonalHIBPConsent|PersonalHIBPProjection|HealthNeedsTerminal' -count=1`
- `go vet ./internal/watchtower/ ./internal/personal/`
- `go test -run '^$' ./internal/browserhost ./internal/desktop`（编译既有 `Watchtower` 调用方）

覆盖：默认离线零外部调用、旧 `Watchtower` API 保持、nil/预取消上下文固定拒绝且零调用零事务、取消中的 fake 传输被前后守卫截断且不产生最终报告、锁请求阻止迟到最终报告、同一取消上下文重放不再次联网、前缀仅 5 位且审计不含密码/完整哈希/前缀/后缀、CLI 严格选项与错误同意不触碰库、投影不泄漏原生标题/来源/provider 错误。

主代理独立 race 检查通过：`go test -race ./internal/personal ./internal/watchtower ./cmd/locklark -run 'Watchtower|HIBP|Health' -count=1`，三个包分别 57.157、1.189、1.023 秒。实际 PTY 已执行默认离线体检、错误 NETWORK 同意后不增加联网意图、空库显式同意完整路径（checked=0）。私有合成夹具已删除，回执 `health-cli-pty-receipt.json`。

未执行的外部检查：真实非空密码的外部 HIBP 请求及其 IP/端点行为、信号下的实际终端恢复。本轮未使用用户真实库或真实密码发起外部查询；合成本地 TLS 传输用于客户端隐私/失败测试。
