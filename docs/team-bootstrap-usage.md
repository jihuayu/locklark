# 系统保护的团队初始化

当前入口完成单 owner、独立 publisher 和首设备的空库创建及首次同步。角色私钥由系统密钥服务保护；公开初始化文件只含公钥、签名证明与加密快照。团队邀请、条目编辑/披露、管理界面和密钥轮换仍未实现。

服务端和 owner 端各自使用本机配置及系统密钥库。所有路径参数必须是绝对路径，父目录须可信；新输出拒绝覆盖已有文件。两端通过独立可信渠道交换公开材料和指纹。指纹格式为 `SHA256:` 加 Ed25519 公钥字节的 SHA-256 十六进制值，准备命令的回执会显示它。

| 步骤 | 命令与参数 |
| --- | --- |
| 服务端准备身份 | `locklark-team-sync prepare-identity --profile P --public-out D` |
| owner 核对服务身份并创建配置 | `locklark team create --profile O --anchor A --service D --expect-sequencer-fingerprint FP --pins-out T` |
| owner 导出原初始化材料 | `locklark team export-initial --profile O --out I` |
| 服务端核对 owner 并初始化 | `locklark-team-sync initialize --profile P --service D --trusted-pins T --expect-owner-fingerprint FP --artifact I --directory B --anchor S` |
| 服务端启动 TLS | `locklark-team-sync serve-profile --profile P --service D --trusted-pins T --listen ADDR --certificate CERT --tls-key KEY` |
| owner 首次同步并解密验证 | `locklark team fetch-initial --profile O --endpoint HTTPS_URL [--ca CA_FILE]` |

表中的字母是需替换的路径或值，不是默认文件名。`P/O` 是双方各自的私有配置，`A/S` 是彼此独立的检查点，`B` 是服务目录。`D/T/I` 分别是服务公开身份、owner 导出的可信 pins 和初始化材料。初始化不能从 `I` 自动接受信任根。

两次信任确认均要求真实控制终端：先独立核对预期指纹，再按提示输入完整的 `TRUST SHA256:…`。没有跳过确认或忽略 TLS 校验的选项。TLS 私钥文件须保持私有权限；角色私钥没有 argv、环境变量或普通文件回退。`--listen` 使用端口 `0` 时，启动回执返回实际监听地址。

准备和导出成功时的 `pending` 不表示团队已可用。owner 首次完成 TLS、签名历史、解密与检查点持久化后，才返回 `active`。

## 查询与恢复

双方分别使用 `locklark team status --profile O` 和 `locklark-team-sync status --profile P` 查询本地记录；这些状态未经新的系统认证或远端校验。status 可用 `--pins-out` 或 `--public-out` 重新导出同一份公开信息，新输出仍拒绝覆盖。

`reconcile-protection --profile …` 仅加载并核验原系统记录。服务端 `reconcile-initialize` 使用与原 initialize 完全相同的参数，只对账原操作。重复 export-initial 只返回与系统保护摘要匹配的原材料。

退出码为：`0` 当前步骤完成、`1` 拒绝、`2` 参数错误、`3` 结果未知、`4` 与原操作冲突。结果未知时保留原配置和检查点，不删除后重试。已认领但原材料丢失、无法确认最终保护，或服务已绑定但目录缺失，可能无法在原配置内自动恢复。恢复旧公开配置不能获得重新签名、改绑团队或重建检查点的许可。

## 已完成的验收

Sol 实现、Luna max 审阅；主代理独立重建合并后的两个产品命令与验收夹具，真实双端流程 13/13 通过。双方使用独立的 D-Bus、Secret Service 和私有目录，实际运行上述 CLI、独立 TLS 根、设备签名及 age/KDBX 解密。验收还覆盖错误信任与 TLS、重启、丢失写入确认、公开配置回滚、缺失检查点/目录、原材料不重签、257 个运行文件的已知 canary 扫描与所属进程清理。构建产物的预期哈希在执行前后保持一致。

相关 Go 测试、核心 race、全仓 vet 和 10 项工具测试通过。Windows/macOS bootstrap 目前只有交叉编译证据，尚无真实系统认证成功证据；Linux 已解锁 Secret Service 不等同于逐次生物识别。扫描不声称覆盖未导出的随机内部私钥。设计与保守恢复边界见 [bootstrap 设计](team-bootstrap-design.md)。
