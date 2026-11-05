# 人工确认的 GitHub 实时查询

从 main `c8c38e4`（PR #18 经 Luna/max 与双平台 CI 合并）接通 `personal github-pull`。原录制网关流程仍固定 `recorded-response/v1`；本入口使用新的个人库审计动作和现场人工确认，不能拿旧的录制批准切换到真实网络。

```text
locklark personal github-pull --file owner.ll --id ITEM_ID --revision REV --repository-id NUMERIC_REPO_ID --owner OWNER --repository NAME --number PR_NUMBER --api-ip PUBLIC_IPV4
```

选定登录的 password 字段应存放本人准备的 GitHub token；建议使用只授予目标仓库 PR 读取的凭据。命令不会向 GitHub 验证 token 的完整授权范围，也不会把一般 token 变成上游强制限仓库的委托；宿主本身仅执行固定仓库/PR 的 GET。repo ID 是稳定的数字身份，owner/name 是 API 路径；须从可信独立来源核实，不能从插件或中继直接抄来授予权限。

与现有 HTTPS 适配器一致，`--api-ip` 必须是本人独立确认的公网 IPv4，不能是主机名、私网或保留地址。不自动 DNS 发现，不读代理环境；TLS 始终验证 `api.github.com`，地址变化需重新确认调用参数。没有自定义 URL、请求头、根证书或跳过证书校验选项。TLS 使用当前系统信任根，系统信任库/本机管理员属于已有客户端信任边界。

隐藏终端输入主密码、Secret Key 后，界面显示稳定条目 ID/修订、目标仓库路径/数字 ID、PR 和 API 地址，说明字段将作为 GitHub token 发给 GitHub；输入 `CALL` 仅确认此次查询。函数 `LivePull` 本身不提供交互，只有经可信入口确认的调用方可调用。MCP 没有因此新增原值工具或网络批准权限。

## 审计和网络顺序

个人事务验证解锁、快照和历史，核对精确条目修订及回收站状态，读取 password 字段后写入 `item.invoke.github-pull` 的 `intent` 事件。目标使用独立 HKDF 目的派生的 HMAC 绑定 `github-https/v1`、仓库三元组、PR 与固定地址；事件签名另绑定条目/修订/session。目标文本和 token 不写普通回执或解密后的审计 JSON。显式选定归档条目沿用既有人工披露规则，回收站条目拒绝。

事务提交并成功关闭数据库后才调用 `gateway.NewPullReader(...).ReadApproved`。适配器校验 token 形状，再做一次固定 HTTPS GET，不跟随重定向、不用 cookie/代理、不在应用层重试。响应必须匹配固定数字仓库 ID 和 PR number，只投影 number/state/merged_at，并拒绝原 token 回显；错误统一脱敏。stdout 成功回执含 `result-received`、session、intent、target_digest 及这三个结果字段，不含 token、用户名或条目标题。取消、错误因素、旧修订、回收站、提交回滚和关闭失败不调用网络。

**持久记录仍是执行意图，不是执行结果。** `result-received` 只表示本进程收到并验证了响应；没有持久结果收据或跨重启恢复成功结果的接口。失败返回固定“intent recorded, request may have reached upstream”，崩溃后只能认定结果未知。用户再次确认会产生新意图和新 GET，不复用旧批准、不自动重试。未实现远程移动审批、通知、长期机器授权、独立执行部署或远端结果日志。

## 验证

失败先行 `/tmp/locklark-validation/live-pull-red.log`：缺少新请求、入口和事务选项。`TestLivePull*` 用真实个人库验证成功执行前可从另一句柄读到已提交意图、修订不变、目标/库隔离绑定、secret 清理、回滚/关闭失败/取消、错误因素/冲突/回收站拒绝、上游错误脱敏，以及含新意图的备份恢复。成功流程的上游是测试替身；既有 `gateway.TestFixedOriginTLSAndHostname` 另实跑受控 TLS、主机名和响应投影。不能把两层测试称为真实 GitHub 账号端到端成功。

`scripts/live_pull_acceptance.py` 实跑 PTY/Windows ConPTY 的隐藏因素、取消/错误因素、精确目标显示及意图持久化。使用五字节合成 token，生产适配器在发网前拒绝；CI 不依赖外部 token，也不接触真实账号。真实 GitHub 只读仓库 token、权限收窄与完整在线调用仍待独立验收。

命令：带 PyKeePass/Bun 的 `go test -count=1 ./...`；`go test -race ./internal/personal ./internal/gateway -run 'TestLivePull|TestFixedOriginTLSAndHostname|TestInjection' -count=1`；`go vet ./...`；`python3 scripts/live_pull_acceptance.py BINARY`；`git diff --check`。最终 Luna/max 复核、精确 head 与双平台 CI 以本批 PR 为准。
