# 个人 CLI 的认证 1PUX 预检

基线为 PR #7 合并后的 main `cff9aaf84f83fa94a92b2c3e3e60c32b3fa75084`，分支 `codex/personal-onepux-inspection`。最终 head、Luna/max 复核和 Ubuntu/Windows CI 链接见 PR 正文。

## 可用入口和事务边界

`personal inspect-1pux --file owner.ll --source export.1pux` 要求交互 stdin/stderr、隐藏双因素和 `SCAN` 确认。先验证个人库因素、快照、全部审计及恢复历史，之后才调用源文件 reader；错误因素和损坏账本不会访问源路径。源路径不进入提示、错误、审计或 JSON 回执。

源文件以只读方式打开，针对打开的句柄验证普通文件和大小，再限读 MaxArchive+1（当前 32 MiB+1）。检查初始大小和读后长度，拒绝增长越界。Stat/Read/Close/非普通文件失败统一固定 source-error，ZIP/JSON 核心的 invalid/unsupported/limit 保留固定分类。原始缓冲返回时清除；不保证 Go 字符串副本、操作系统缓存或原明文导出文件被擦除。

在同一 bbolt Update 内完成检查与 `migration.inspect.1pux` 事件：成功只保存报告的 SHA-256 摘要，失败只保存固定类别。事件无源路径、源文件摘要、字段值、条目 ID 或修订。成功摘要对 `json.Marshal(report)` 的精确 UTF-8 字节计算，不含尾随换行；它绑定报告，不证明源文件内容、出处或迁移许可。不同归档可能产生相同报告摘要。

提交并关闭数据库后才返回 `status: inspected-unmapped`、session、event、report_digest 和报告。MappingVerified 始终 false，条目始终未映射；不会导入、改写源文件、解压落盘或给 MCP 增加读取工具。进程在提交前崩溃没有完成事件，也没有报告；不承诺每次文件系统访问之前已持久化意图。提交后输出失败只说明检查已完成，不证明人收到报告。

检查期间持有写事务；现有字节/节点/对象限制约束处理量，但没有对网络文件系统或存储停顿提供时间上限。Unix 沿用 nonblocking 打开再验证句柄，覆盖 FIFO/链接/设备拒绝；非 Unix 沿用打开前 Stat、打开后句柄校验，Windows 原生 CI 验证常规流程，不声称防住任意并发替换成平台特殊设备的竞态。

## 审计兼容和故障路径

ReportDigest 仅允许出现在该动作的成功事件，并须为规范 SHA-256；拒绝事件和其他动作携摘要均无效。旧事件省略新增字段，保持原签名序列化；新动作会使旧读取器明确拒绝。备份恢复保留成功摘要与拒绝历史，且不更改库条目。

接入时发现共享 command 原先忽略 db.Close 错误。新增 commandWithClose 在正常执行但关闭失败时清空结果，清除暂存字段/OTP，并返回固定“操作可能已提交”错误；既有执行错误保持原类别。不会因关闭错误撤销已经提交的事件，也不返回成功报告或字段值。

## 验证

失败先行：新增 `TestInspection*` 在缺失产品接口和事件字段时编译失败（`/tmp/locklark-validation/inspection-red.log`）。实现后测试真实加密库报告摘要/事件关联、源文件不变、备份恢复历史；错误因素/损坏账本零 reader 调用；完整事务后注入回滚零报告/零事件；源 Stat/Read/Close、增长、初始超限、目录和 Linux idle FIFO/链接/设备；数据库 close 失败零结果；签名事件的摘要/动作/结果串用拒绝。

真实 PTY/ConPTY 覆盖确认/取消、错误因素、正常预检、非法归档/目录拒绝、无值报告、源文件不变以及旧读取器拒绝。Python 独立对 JSON 报告和签名事件计算摘要核对回执；测试不打印转录或源密码。源码共用路径另运行既有个人/披露/生成/OTP/引用/MCP 验收、全仓 Go/Bun/PyKeePass、定向 race、vet/模块、终端驱动测试和 macOS arm64 编译；最终证据以 PR 为准。

此入口仍不执行通用导入。后续需明确支持的类别/字段/历史/附件语义、可逆迁出和真实 1Password 对照，再开放实际写入；桌面、系统解锁、浏览器、移动端、团队同步和外部密码评审仍单独保留。
